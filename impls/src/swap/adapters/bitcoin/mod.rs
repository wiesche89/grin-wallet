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

//! Bitcoin contracts for the Grin adaptor-key swap protocol

use crate::libwallet::Error;

pub use ::bitcoin as types;

mod rpc;
use ::bitcoin::absolute::LockTime;
use ::bitcoin::opcodes::all::*;
use ::bitcoin::script::Builder;
use ::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use ::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use ::bitcoin::{
	transaction, Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction,
	TxIn, TxOut, Witness,
};
pub use rpc::{Core, Funding};

fn invalid(message: &str) -> Error {
	Error::GenericError(format!("bitcoin swap: {message}"))
}

/// A claim needs both the Grin seller's key and the recovered Grin key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contract {
	claim: PublicKey,
	adaptor: PublicKey,
	refund: PublicKey,
	height: u32,
	amount: Amount,
}

impl Contract {
	/// Bind the keys, refund height and amount before either party funds
	pub fn new(
		claim: PublicKey,
		adaptor: PublicKey,
		refund: PublicKey,
		height: u32,
		amount: Amount,
	) -> Result<Self, Error> {
		let contract = Self {
			claim,
			adaptor,
			refund,
			height,
			amount,
		};
		contract.validate()?;
		Ok(contract)
	}

	fn validate(&self) -> Result<(), Error> {
		if !self.claim.compressed
			|| !self.adaptor.compressed
			|| !self.refund.compressed
			|| self.claim == self.adaptor
			|| self.claim == self.refund
			|| self.adaptor == self.refund
			|| self.height == 0
			|| self.height >= 500_000_000
			|| self.amount == Amount::ZERO
			|| self.amount > Amount::MAX_MONEY
		{
			return Err(invalid("invalid contract"));
		}
		Ok(())
	}

	/// P2WSH witness script; all keys use compressed secp256k1 encoding
	pub fn script(&self) -> Result<ScriptBuf, Error> {
		self.validate()?;
		Ok(Builder::new()
			.push_opcode(OP_IF)
			.push_int(2)
			.push_key(&self.claim)
			.push_key(&self.adaptor)
			.push_int(2)
			.push_opcode(OP_CHECKMULTISIG)
			.push_opcode(OP_ELSE)
			.push_int(self.height as i64)
			.push_opcode(OP_CLTV)
			.push_opcode(OP_DROP)
			.push_key(&self.refund)
			.push_opcode(OP_CHECKSIG)
			.push_opcode(OP_ENDIF)
			.into_script())
	}

	/// Funding address on the selected Bitcoin network
	pub fn address(&self, network: Network) -> Result<Address, Error> {
		Ok(Address::p2wsh(&self.script()?, network))
	}

	/// Find the exact contract output; duplicate matching outputs are ambiguous
	pub fn output(&self, funding: &Transaction) -> Result<OutPoint, Error> {
		let script = self.script()?.to_p2wsh();
		let mut outputs = funding
			.output
			.iter()
			.enumerate()
			.filter(|(_, o)| o.script_pubkey == script && o.value == self.amount);
		let (vout, _) = outputs
			.next()
			.ok_or_else(|| invalid("funding output missing"))?;
		if outputs.next().is_some() {
			return Err(invalid("duplicate funding output"));
		}
		Ok(OutPoint::new(funding.compute_txid(), vout as u32))
	}

	/// Sign a claim using the key recovered from the confirmed Grin kernel
	pub fn claim(
		&self,
		funding: &Transaction,
		destination: &Address,
		fee: Amount,
		key: &SecretKey,
		recovered: &SecretKey,
	) -> Result<Transaction, Error> {
		self.check_key(key, self.claim)?;
		self.check_key(recovered, self.adaptor)?;
		let mut tx = self.spend(funding, destination, fee, false)?;
		let first = self.sign(&tx, key)?;
		let second = self.sign(&tx, recovered)?;
		tx.input[0].witness = Witness::from_slice(&[
			Vec::new(),
			first,
			second,
			vec![1],
			self.script()?.into_bytes(),
		]);
		Ok(tx)
	}

	/// Sign and save the refund before publishing the funding transaction
	pub fn refund(
		&self,
		funding: &Transaction,
		destination: &Address,
		fee: Amount,
		key: &SecretKey,
	) -> Result<Transaction, Error> {
		self.check_key(key, self.refund)?;
		let mut tx = self.spend(funding, destination, fee, true)?;
		let signature = self.sign(&tx, key)?;
		tx.input[0].witness =
			Witness::from_slice(&[signature, Vec::new(), self.script()?.into_bytes()]);
		Ok(tx)
	}

	fn check_key(&self, key: &SecretKey, expected: PublicKey) -> Result<(), Error> {
		if PublicKey::new(key.public_key(&Secp256k1::new())) != expected {
			return Err(invalid("key does not match contract"));
		}
		Ok(())
	}

	fn spend(
		&self,
		funding: &Transaction,
		destination: &Address,
		fee: Amount,
		refund: bool,
	) -> Result<Transaction, Error> {
		let value = self
			.amount
			.checked_sub(fee)
			.ok_or_else(|| invalid("fee exceeds amount"))?;
		let script_pubkey = destination.script_pubkey();
		if fee == Amount::ZERO || value < script_pubkey.minimal_non_dust() {
			return Err(invalid("invalid fee or dust output"));
		}
		Ok(Transaction {
			version: transaction::Version::TWO,
			lock_time: if refund {
				LockTime::from_height(self.height).map_err(|_| invalid("refund height"))?
			} else {
				LockTime::ZERO
			},
			input: vec![TxIn {
				previous_output: self.output(funding)?,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value,
				script_pubkey,
			}],
		})
	}

	fn sign(&self, tx: &Transaction, key: &SecretKey) -> Result<Vec<u8>, Error> {
		let sighash_type = EcdsaSighashType::All;
		let hash = SighashCache::new(tx)
			.p2wsh_signature_hash(0, &self.script()?, self.amount, sighash_type)
			.map_err(|_| invalid("signature hash"))?;
		let signature = Secp256k1::new().sign_ecdsa(&Message::from(hash), key);
		Ok(::bitcoin::ecdsa::Signature {
			signature,
			sighash_type,
		}
		.to_vec())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn setup() -> (Contract, Transaction, Address, [SecretKey; 3]) {
		let secp = Secp256k1::new();
		let keys = [1, 2, 3].map(|n| SecretKey::from_slice(&[n; 32]).unwrap());
		let pubs = keys.map(|k| PublicKey::new(k.public_key(&secp)));
		let c = Contract::new(pubs[0], pubs[1], pubs[2], 200, Amount::from_sat(100_000)).unwrap();
		let tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: c.amount,
				script_pubkey: c.script().unwrap().to_p2wsh(),
			}],
		};
		let address = Address::p2wpkh(
			&::bitcoin::CompressedPublicKey(pubs[0].inner),
			Network::Regtest,
		);
		(c, tx, address, keys)
	}

	#[test]
	fn spends() {
		let (c, funding, address, keys) = setup();
		let fee = Amount::from_sat(1000);
		let claim = c
			.claim(&funding, &address, fee, &keys[0], &keys[1])
			.unwrap();
		let refund = c.refund(&funding, &address, fee, &keys[2]).unwrap();
		assert_eq!(
			claim.input[0].previous_output,
			refund.input[0].previous_output
		);
		assert_eq!(claim.output[0].value, Amount::from_sat(99_000));
		assert_eq!(refund.lock_time.to_consensus_u32(), 200);
		assert_eq!(claim.input[0].witness.len(), 5);
		assert_eq!(refund.input[0].witness.len(), 3);
		for (tx, witness_index, key) in [
			(&claim, 1, keys[0]),
			(&claim, 2, keys[1]),
			(&refund, 0, keys[2]),
		] {
			let sig = ::bitcoin::ecdsa::Signature::from_slice(&tx.input[0].witness[witness_index])
				.unwrap();
			let hash = SighashCache::new(tx)
				.p2wsh_signature_hash(0, &c.script().unwrap(), c.amount, sig.sighash_type)
				.unwrap();
			Secp256k1::new()
				.verify_ecdsa(
					&Message::from(hash),
					&sig.signature,
					&key.public_key(&Secp256k1::new()),
				)
				.unwrap();
		}
	}

	#[test]
	fn rejects_mismatches() {
		let (c, mut funding, address, keys) = setup();
		let fee = Amount::from_sat(1000);
		assert!(c
			.claim(&funding, &address, fee, &keys[0], &keys[2])
			.is_err());
		assert!(c.refund(&funding, &address, fee, &keys[0]).is_err());
		assert!(c.refund(&funding, &address, c.amount, &keys[2]).is_err());
		funding.output[0].value = Amount::from_sat(90_000);
		assert!(c.output(&funding).is_err());
		funding.output[0].value = c.amount;
		funding.output.push(funding.output[0].clone());
		assert!(c.output(&funding).is_err());
	}
}
