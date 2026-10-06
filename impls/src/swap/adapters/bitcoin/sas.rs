// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Key-only Bitcoin funding for SAS

use super::{invalid, types as btc};
use crate::libwallet::Error;
use btc::hex::{DisplayHex, FromHex};
use btc::key::TapTweak;
use btc::secp256k1::{ecdsa::Signature, Keypair, Message, Scalar, Secp256k1, SecretKey};
use btc::sighash::{Prevouts, SighashCache};
use btc::{Address, Amount, Network, OutPoint, PublicKey, Transaction, TxIn, TxOut};

/// Both public shares must have a verified proof of possession before funding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
	/// Seller's refund secret and buyer's success secret, in that order
	pub keys: [PublicKey; 2],
	/// Locked Bitcoin amount
	pub amount: Amount,
}

impl Contract {
	/// Derive a Taproot key path with no script or timelock branch
	pub fn address(&self, network: Network) -> Result<Address, Error> {
		let public = self.public()?;
		let address = Address::p2tr(
			&Secp256k1::new(),
			public.x_only_public_key().0,
			None,
			network,
		);
		if self.amount < address.script_pubkey().minimal_non_dust() {
			return Err(invalid("SAS funding dust"));
		}
		Ok(address)
	}

	fn public(&self) -> Result<btc::secp256k1::PublicKey, Error> {
		if self.keys[0] == self.keys[1]
			|| self.keys.iter().any(|key| !key.compressed)
			|| self.amount == Amount::ZERO
			|| self.amount > Amount::MAX_MONEY
		{
			return Err(invalid("SAS contract"));
		}
		self.keys[0]
			.inner
			.combine(&self.keys[1].inner)
			.map_err(|_| invalid("SAS key sum"))
	}

	/// Locate the unique agreed output
	pub fn output(&self, tx: &Transaction, network: Network) -> Result<OutPoint, Error> {
		let expected = TxOut {
			value: self.amount,
			script_pubkey: self.address(network)?.script_pubkey(),
		};
		let mut outputs = tx
			.output
			.iter()
			.enumerate()
			.filter(|(_, out)| **out == expected);
		let (vout, _) = outputs
			.next()
			.ok_or_else(|| invalid("SAS funding output"))?;
		if outputs.next().is_some() {
			return Err(invalid("duplicate SAS output"));
		}
		Ok(OutPoint::new(tx.compute_txid(), vout as u32))
	}

	/// Check both shares before accepting ownership
	pub fn recover(&self, local: &SecretKey, peer: &SecretKey) -> Result<SecretKey, Error> {
		let secp = Secp256k1::new();
		let public = [
			PublicKey::new(local.public_key(&secp)),
			PublicKey::new(peer.public_key(&secp)),
		];
		if public != self.keys && [public[1], public[0]] != self.keys {
			return Err(invalid("SAS secret mismatch"));
		}
		let scalar =
			Scalar::from_be_bytes(peer.secret_bytes()).map_err(|_| invalid("SAS secret"))?;
		let key = (*local)
			.add_tweak(&scalar)
			.map_err(|_| invalid("SAS secret sum"))?;
		if key.public_key(&secp) != self.public()? {
			return Err(invalid("SAS key mismatch"));
		}
		Ok(key)
	}

	/// Spend owned coins later; this is not part of swap completion
	pub fn spend(
		&self,
		funding: &Transaction,
		network: Network,
		destination: &Address,
		fee: Amount,
		key: &SecretKey,
	) -> Result<Transaction, Error> {
		let point = self.output(funding, network)?;
		self.spend_output(funding, point.vout, network, destination, fee, key)
	}

	/// Recover a specific contract output after key recovery, including extra deposits.
	/// This does not select or change the payment agreed for a swap.
	pub fn spend_output(
		&self,
		funding: &Transaction,
		vout: u32,
		network: Network,
		destination: &Address,
		fee: Amount,
		key: &SecretKey,
	) -> Result<Transaction, Error> {
		let output = funding
			.output
			.get(vout as usize)
			.ok_or_else(|| invalid("SAS output index"))?;
		if output.script_pubkey != self.address(network)?.script_pubkey()
			|| output.value > Amount::MAX_MONEY
		{
			return Err(invalid("SAS recovery output"));
		}
		let secp = Secp256k1::new();
		if key.public_key(&secp) != self.public()? {
			return Err(invalid("SAS signing key"));
		}
		let value = output
			.value
			.checked_sub(fee)
			.ok_or_else(|| invalid("fee exceeds amount"))?;
		let script_pubkey = destination.script_pubkey();
		if fee == Amount::ZERO || value < script_pubkey.minimal_non_dust() {
			return Err(invalid("invalid fee or dust output"));
		}
		let point = OutPoint::new(funding.compute_txid(), vout);
		let mut tx = Transaction {
			version: btc::transaction::Version::TWO,
			lock_time: btc::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: point,
				script_sig: btc::ScriptBuf::new(),
				sequence: btc::Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: btc::Witness::new(),
			}],
			output: vec![TxOut {
				value,
				script_pubkey,
			}],
		};
		let prevouts = [funding.output[point.vout as usize].clone()];
		let hash = SighashCache::new(&tx)
			.taproot_key_spend_signature_hash(
				0,
				&Prevouts::All(&prevouts),
				btc::TapSighashType::Default,
			)
			.map_err(|_| invalid("SAS sighash"))?;
		let pair = Keypair::from_secret_key(&secp, key)
			.tap_tweak(&secp, None)
			.to_keypair();
		let sig = secp.sign_schnorr_no_aux_rand(&Message::from(hash), &pair);
		tx.input[0].witness.push(sig.as_ref());
		Ok(tx)
	}
}

/// Bind possession of a share to the complete negotiation transcript
pub fn prove(key: &SecretKey, digest: [u8; 32]) -> String {
	Secp256k1::new()
		.sign_ecdsa(&Message::from_digest(digest), key)
		.serialize_compact()
		.to_lower_hex_string()
}

/// Reject rogue-key registration and proofs from another negotiation
pub fn verify(key: PublicKey, digest: [u8; 32], proof: &str) -> Result<(), Error> {
	let bytes = Vec::<u8>::from_hex(proof).map_err(|_| invalid("SAS proof encoding"))?;
	let sig = Signature::from_compact(&bytes).map_err(|_| invalid("SAS proof"))?;
	Secp256k1::new()
		.verify_ecdsa(&Message::from_digest(digest), &sig, &key.inner)
		.map_err(|_| invalid("SAS proof mismatch"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn funding() {
		let secp = Secp256k1::new();
		let keys = [1, 2].map(|n| SecretKey::from_slice(&[n; 32]).unwrap());
		let contract = Contract {
			keys: keys.map(|key| PublicKey::new(key.public_key(&secp))),
			amount: Amount::from_sat(100_000),
		};
		let address = contract.address(Network::Regtest).unwrap();
		let mut tx = Transaction {
			version: btc::transaction::Version::TWO,
			lock_time: btc::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: contract.amount,
				script_pubkey: address.script_pubkey(),
			}],
		};
		assert_eq!(contract.output(&tx, Network::Regtest).unwrap().vout, 0);
		for amount in [99_999, 100_001] {
			tx.output[0].value = Amount::from_sat(amount);
			assert!(contract.output(&tx, Network::Regtest).is_err());
		}
		tx.output[0].value = contract.amount;
		tx.output.push(tx.output[0].clone());
		assert!(contract.output(&tx, Network::Regtest).is_err());
		tx.output.pop();
		let key = contract.recover(&keys[0], &keys[1]).unwrap();
		for key in &keys {
			assert!(contract
				.spend(&tx, Network::Regtest, &address, Amount::from_sat(1000), key)
				.is_err());
		}
		for fee in [0, 99_999, 100_001] {
			assert!(contract
				.spend(&tx, Network::Regtest, &address, Amount::from_sat(fee), &key)
				.is_err());
		}
		let payout = contract
			.spend(
				&tx,
				Network::Regtest,
				&address,
				Amount::from_sat(1000),
				&key,
			)
			.unwrap();
		assert_eq!(payout.output[0].value.to_sat(), 99_000);
		assert_eq!(payout.input[0].previous_output.txid, tx.compute_txid());
		// Recovery names an exact outpoint and uses its actual value, including
		// duplicate and differently sized deposits. Negotiation remains strict.
		tx.output.push(tx.output[0].clone());
		tx.output[1].value = Amount::from_sat(120_000);
		let recovered = contract
			.spend_output(
				&tx,
				1,
				Network::Regtest,
				&address,
				Amount::from_sat(1000),
				&key,
			)
			.unwrap();
		assert_eq!(recovered.input[0].previous_output.vout, 1);
		assert_eq!(recovered.output[0].value.to_sat(), 119_000);
		assert!(contract
			.spend_output(
				&tx,
				2,
				Network::Regtest,
				&address,
				Amount::from_sat(1000),
				&key
			)
			.is_err());
		tx.output[1].script_pubkey = btc::ScriptBuf::new();
		assert!(contract
			.spend_output(
				&tx,
				1,
				Network::Regtest,
				&address,
				Amount::from_sat(1000),
				&key
			)
			.is_err());
		tx.output[0].script_pubkey = btc::ScriptBuf::new();
		assert!(contract.output(&tx, Network::Regtest).is_err());
	}

	#[test]
	fn rogue_key() {
		let secp = Secp256k1::new();
		let honest = SecretKey::from_slice(&[1; 32]).unwrap().public_key(&secp);
		let attacker = SecretKey::from_slice(&[2; 32]).unwrap();
		let rogue = attacker
			.public_key(&secp)
			.combine(&honest.negate(&secp))
			.unwrap();
		assert_eq!(honest.combine(&rogue).unwrap(), attacker.public_key(&secp));
		assert!(verify(PublicKey::new(rogue), [1; 32], &prove(&attacker, [1; 32])).is_err());
	}

	#[test]
	fn possession() {
		let secp = Secp256k1::new();
		let keys = [1, 2].map(|n| SecretKey::from_slice(&[n; 32]).unwrap());
		let public = keys.map(|k| PublicKey::new(k.public_key(&secp)));
		let c = Contract {
			keys: public,
			amount: Amount::from_sat(100_000),
		};
		let proof = prove(&keys[0], [1; 32]);
		verify(public[0], [1; 32], &proof).unwrap();
		assert!(verify(public[1], [1; 32], &proof).is_err());
		assert!(verify(public[0], [2; 32], &proof).is_err());
		assert!(c.recover(&keys[0], &keys[0]).is_err());
		assert_eq!(
			c.recover(&keys[0], &keys[1]).unwrap(),
			c.recover(&keys[1], &keys[0]).unwrap()
		);
		assert!(c
			.address(Network::Regtest)
			.unwrap()
			.script_pubkey()
			.is_p2tr());
	}
}
