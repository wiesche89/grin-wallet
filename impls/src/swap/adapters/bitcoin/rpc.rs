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

use super::{invalid, Contract};
use crate::client_utils::RUNTIME;
use crate::libwallet::{swap::TxState, Error};
use ::bitcoin::consensus::{deserialize, encode::serialize_hex};
use ::bitcoin::hex::FromHex;
use ::bitcoin::secp256k1::SecretKey;
use ::bitcoin::{Address, Amount, Network, Transaction, Txid};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Locally configured Bitcoin Core wallet. Credentials are read for each request
pub struct Core {
	url: reqwest::Url,
	cookie: PathBuf,
	network: Network,
	client: reqwest::Client,
}

/// A signed funding transaction and its signed refund, saved together before broadcast
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Funding {
	/// Signed contract funding transaction
	pub tx: Transaction,
	/// Fully signed timelocked refund
	pub refund: Transaction,
}

impl Core {
	/// Connect to a loopback Core RPC endpoint, including its `/wallet/...` path
	pub fn new(url: &str, cookie: PathBuf, network: Network) -> Result<Self, Error> {
		let url = reqwest::Url::parse(url).map_err(|_| invalid("RPC URL"))?;
		let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
		let local = IpAddr::from_str(host).map_or(false, |ip| ip.is_loopback());
		if !local
			|| url.scheme() != "http"
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(invalid(
				"RPC must use a loopback HTTP address and cookie authentication",
			));
		}
		let client = reqwest::Client::builder()
			.no_proxy()
			.redirect(reqwest::redirect::Policy::none())
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|_| invalid("RPC client"))?;
		let core = Self {
			url,
			cookie,
			network,
			client,
		};
		let info = core.call("getblockchaininfo", json!([]))?;
		let chain = match network {
			Network::Bitcoin => "main",
			Network::Testnet => "test",
			Network::Testnet4 => "testnet4",
			Network::Signet => "signet",
			Network::Regtest => "regtest",
		};
		if info["chain"].as_str() != Some(chain) {
			return Err(invalid("RPC network mismatch"));
		}
		Ok(core)
	}

	fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
		self.request(method, params)
			.map_err(|code| invalid(&format!("RPC {method} failed ({code})")))
	}

	fn request(&self, method: &str, params: Value) -> Result<Value, i64> {
		let cookie = std::fs::read_to_string(&self.cookie).map_err(|_| -1000)?;
		let (user, password) = cookie.trim().split_once(':').ok_or(-1000)?;
		let body =
			serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
				.map_err(|_| -1001)?;
		let result: Value = RUNTIME.block_on(async {
			let response = self
				.client
				.post(self.url.clone())
				.basic_auth(user, Some(password))
				.header("Content-Type", "application/json")
				.body(body)
				.send()
				.await
				.map_err(|_| -1002)?;
			let bytes = response.bytes().await.map_err(|_| -1002)?;
			serde_json::from_slice(&bytes).map_err(|_| -1003)
		})?;
		if !result["error"].is_null() {
			return Err(result["error"]["code"].as_i64().unwrap_or(-1003));
		}
		if result["id"] != 1 || result.get("result").is_none() {
			return Err(-1003);
		}
		Ok(result["result"].clone())
	}

	/// Active tip; refuse to make decisions while Core is still synchronizing
	pub fn tip(&self) -> Result<(u64, String), Error> {
		let info = self.call("getblockchaininfo", json!([]))?;
		if info["initialblockdownload"].as_bool() != Some(false) {
			return Err(invalid("Bitcoin Core is still synchronizing"));
		}
		Ok((
			info["blocks"]
				.as_u64()
				.ok_or_else(|| invalid("block height"))?,
			info["bestblockhash"]
				.as_str()
				.ok_or_else(|| invalid("block hash"))?
				.to_owned(),
		))
	}

	/// Current active-chain height
	pub fn height(&self) -> Result<u64, Error> {
		Ok(self.tip()?.0)
	}

	/// Obtain a wallet-owned destination on the configured network
	pub fn address(&self) -> Result<Address, Error> {
		let result = self.call("getnewaddress", json!(["grin-swap", "bech32"]))?;
		Address::from_str(result.as_str().ok_or_else(|| invalid("address"))?)
			.map_err(|_| invalid("address"))?
			.require_network(self.network)
			.map_err(|_| invalid("address network"))
	}

	/// Prepare funding and refund without broadcasting. The Core wallet must be unlocked
	pub fn prepare(
		&self,
		contract: &Contract,
		destination: &Address,
		refund_key: &SecretKey,
		fee_rate: u64,
		max_fee: Amount,
		refund_fee: Amount,
	) -> Result<Funding, Error> {
		if fee_rate == 0 || fee_rate > 1000 || refund_fee > max_fee || max_fee == Amount::ZERO {
			return Err(invalid("fee policy"));
		}
		if self.height()? >= contract.height as u64 {
			return Err(invalid("refund already mature"));
		}
		let outputs =
			json!([{contract.address(self.network)?.to_string(): contract.amount.to_btc()}]);
		let psbt = self.call(
			"walletcreatefundedpsbt",
			json!([[], outputs, 0,
			{"fee_rate": fee_rate, "replaceable": false, "lockUnspents": false}, true]),
		)?;
		let fee = amount(&psbt["fee"])?;
		if fee > max_fee {
			return Err(invalid("funding fee exceeds limit"));
		}
		let signed = self.call("walletprocesspsbt", json!([psbt["psbt"], true, "ALL"]))?;
		let final_tx = self.call("finalizepsbt", json!([signed["psbt"]]))?;
		if final_tx["complete"] != true {
			return Err(invalid("funding is not fully signed"));
		}
		let tx = decode(&final_tx["hex"])?;
		// Only native SegWit inputs: the pre-signed refund must have a stable funding txid
		for input in &tx.input {
			let prev = self.call(
				"gettxout",
				json!([input.previous_output.txid, input.previous_output.vout, true]),
			)?;
			let kind = prev["scriptPubKey"]["type"].as_str().unwrap_or("");
			if !input.script_sig.is_empty()
				|| input.witness.is_empty()
				|| !matches!(
					kind,
					"witness_v0_keyhash" | "witness_v0_scripthash" | "witness_v1_taproot"
				) {
				return Err(invalid("funding requires native SegWit inputs"));
			}
		}
		let refund = contract.refund(&tx, destination, refund_fee, refund_key)?;
		Ok(Funding { tx, refund })
	}

	/// Validate the agreed output against the current UTXO set, including mempool spends
	pub fn output(
		&self,
		contract: &Contract,
		funding: &Transaction,
	) -> Result<(TxState, bool), Error> {
		let point = contract.output(funding)?;
		let utxo = self.call("gettxout", json!([point.txid, point.vout, true]))?;
		if utxo.is_null() {
			return Ok((TxState::Absent, false));
		}
		if amount(&utxo["value"])? != contract.amount
			|| utxo["scriptPubKey"]["hex"].as_str()
				!= Some(&contract.script()?.to_p2wsh().to_hex_string())
		{
			return Err(invalid("funding output mismatch"));
		}
		let confirmations = utxo["confirmations"]
			.as_u64()
			.ok_or_else(|| invalid("confirmations"))?;
		Ok((
			if confirmations == 0 {
				TxState::Pending
			} else {
				TxState::Confirmed(confirmations)
			},
			true,
		))
	}

	/// Observe a local wallet transaction. Unknown and conflicted transactions stay distinct
	pub fn status(&self, txid: Txid) -> Result<TxState, Error> {
		match self.request("gettransaction", json!([txid])) {
			Ok(tx) => match tx["confirmations"].as_i64() {
				Some(n) if n < 0 => Ok(TxState::Conflicted),
				Some(0) => match self.request("getmempoolentry", json!([txid])) {
					Ok(_) => Ok(TxState::Pending),
					Err(-5) => Ok(TxState::Absent),
					Err(code) => Err(invalid(&format!("mempool lookup failed ({code})"))),
				},
				Some(n) => Ok(TxState::Confirmed(n as u64)),
				None => Err(invalid("transaction status")),
			},
			Err(-5) => Ok(TxState::Absent),
			Err(code) => Err(invalid(&format!("transaction lookup failed ({code})"))),
		}
	}

	/// Check relay and replacement rules before persisting a fee increase
	pub fn accept(&self, tx: &Transaction) -> Result<(), Error> {
		let result = self.call("testmempoolaccept", json!([[serialize_hex(tx)]]))?;
		if result[0]["allowed"] != true {
			return Err(invalid("replacement rejected by mempool policy"));
		}
		Ok(())
	}

	/// Broadcast an already saved transaction; rebroadcasting an included transaction is harmless
	pub fn publish(&self, tx: &Transaction) -> Result<(), Error> {
		match self.request("sendrawtransaction", json!([serialize_hex(tx)])) {
			Ok(id) if id.as_str() == Some(&tx.compute_txid().to_string()) => Ok(()),
			Err(-27) => Ok(()),
			_ => Err(invalid("transaction broadcast failed")),
		}
	}
}

fn amount(value: &Value) -> Result<Amount, Error> {
	Amount::from_btc(value.as_f64().ok_or_else(|| invalid("amount"))?)
		.map_err(|_| invalid("amount"))
}

fn decode(value: &Value) -> Result<Transaction, Error> {
	let hex = value
		.as_str()
		.ok_or_else(|| invalid("transaction encoding"))?;
	let bytes = Vec::<u8>::from_hex(hex).map_err(|_| invalid("transaction encoding"))?;
	deserialize(&bytes).map_err(|_| invalid("transaction encoding"))
}

#[cfg(test)]
mod tests {
	use super::*;
	use ::bitcoin::secp256k1::Secp256k1;
	use ::bitcoin::PublicKey;

	#[test]
	#[ignore = "requires GRIN_SWAP_RPC and GRIN_SWAP_COOKIE for an isolated funded regtest wallet"]
	fn regtest_spends() {
		let url = std::env::var("GRIN_SWAP_RPC").unwrap();
		let cookie = std::env::var("GRIN_SWAP_COOKIE").unwrap();
		let core = Core::new(&url, cookie.into(), Network::Regtest).unwrap();
		let keys = [1, 2, 3].map(|n| SecretKey::from_slice(&[n; 32]).unwrap());
		let pubs = keys.map(|key| PublicKey::new(key.public_key(&Secp256k1::new())));
		let destination = core.address().unwrap();
		let fee = Amount::from_sat(1000);
		for refund in [false, true] {
			let height = core.height().unwrap() as u32 + 4;
			let contract =
				Contract::new(pubs[0], pubs[1], pubs[2], height, Amount::from_sat(100_000))
					.unwrap();
			let funding = core
				.prepare(
					&contract,
					&destination,
					&keys[2],
					2,
					Amount::from_sat(5000),
					fee,
				)
				.unwrap();
			core.publish(&funding.tx).unwrap();
			assert_eq!(
				core.output(&contract, &funding.tx).unwrap(),
				(TxState::Pending, true)
			);
			let early = core
				.call(
					"testmempoolaccept",
					json!([[serialize_hex(&funding.refund)]]),
				)
				.unwrap();
			assert_eq!(early[0]["allowed"], false);
			let blocks = core
				.call("generatetoaddress", json!([1, destination.to_string()]))
				.unwrap();
			assert_eq!(
				core.output(&contract, &funding.tx).unwrap(),
				(TxState::Confirmed(1), true)
			);
			core.call("invalidateblock", json!([blocks[0]])).unwrap();
			assert_eq!(
				core.output(&contract, &funding.tx).unwrap(),
				(TxState::Pending, true)
			);
			core.call("reconsiderblock", json!([blocks[0]])).unwrap();
			let spend = if refund {
				core.call("generatetoaddress", json!([4, destination.to_string()]))
					.unwrap();
				funding.refund
			} else {
				contract
					.claim(&funding.tx, &destination, fee, &keys[0], &keys[1])
					.unwrap()
			};
			let accepted = core
				.call("testmempoolaccept", json!([[serialize_hex(&spend)]]))
				.unwrap();
			assert_eq!(accepted[0]["allowed"], true, "{accepted}");
			core.publish(&spend).unwrap();
			assert!(!core.output(&contract, &funding.tx).unwrap().1);
			core.call("generatetoaddress", json!([1, destination.to_string()]))
				.unwrap();
			assert_eq!(
				core.status(spend.compute_txid()).unwrap(),
				TxState::Confirmed(1)
			);
			core.publish(&spend).unwrap();
		}
	}
}
