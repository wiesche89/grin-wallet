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

//! Testnet access through a trusted HTTPS explorer
//!
//! Inclusion proofs are checked locally; chain selection and unspent status
//! still depend on the server, so this is not a fully validating Bitcoin node

use super::invalid;
use crate::{
	client_utils::block_on,
	libwallet::{swap::TxState, Error},
};
use ::bitcoin::{
	blockdata::constants::genesis_block,
	consensus::{deserialize, encode::serialize_hex, Params},
	hex::FromHex,
	Address, Amount, BlockHash, MerkleBlock, Network, OutPoint, Transaction, TxOut, Txid,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{str::FromStr, time::Duration};

#[derive(Clone)]
pub struct Esplora {
	url: reqwest::Url,
	network: Network,
	client: reqwest::Client,
}

fn http_client(proxy: Option<&str>) -> Result<reqwest::Client, Error> {
	let mut client = reqwest::Client::builder()
		.no_proxy()
		.redirect(reqwest::redirect::Policy::none())
		.timeout(Duration::from_secs(10));
	if let Some(proxy) = proxy {
		let url = reqwest::Url::parse(proxy).map_err(|_| invalid("proxy URL"))?;
		if !matches!(url.scheme(), "http" | "https" | "socks5h") || url.host_str().is_none() {
			return Err(invalid("use an HTTP, HTTPS or socks5h proxy URL"));
		}
		client = client.proxy(reqwest::Proxy::all(proxy).map_err(|_| invalid("proxy URL"))?);
	}
	client.build().map_err(|_| invalid("HTTP client"))
}

impl Esplora {
	pub fn new(url: &str, network: Network) -> Result<Self, Error> {
		Self::with_proxy(url, network, None)
	}
	pub fn with_proxy(url: &str, network: Network, proxy: Option<&str>) -> Result<Self, Error> {
		if !matches!(
			network,
			Network::Testnet | Network::Testnet4 | Network::Signet
		) {
			return Err(invalid("remote access is limited to Bitcoin test networks"));
		}
		let mut url = reqwest::Url::parse(url).map_err(|_| invalid("server URL"))?;
		if url.scheme() != "https"
			|| url.host_str().is_none()
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(invalid("remote server requires HTTPS without credentials"));
		}
		if !url.path().ends_with('/') {
			url.set_path(&format!("{}/", url.path()));
		}
		let node = Self {
			url,
			network,
			client: http_client(proxy)?,
		};
		if node.block(0)? != genesis_block(network).block_hash() {
			return Err(invalid("server network mismatch"));
		}
		Ok(node)
	}

	fn request(&self, path: &str, body: Option<String>) -> Result<Option<Vec<u8>>, Error> {
		let url = self.url.join(path).map_err(|_| invalid("request path"))?;
		block_on(async {
			let request = match body {
				Some(body) => self
					.client
					.post(url)
					.header("Content-Type", "text/plain")
					.body(body),
				None => self.client.get(url),
			};
			let mut response = request
				.send()
				.await
				.map_err(|_| invalid("remote server unavailable"))?;
			if response.status() == reqwest::StatusCode::NOT_FOUND {
				return Ok(None);
			}
			if !response.status().is_success() {
				return Err(invalid(&format!(
					"remote server returned {}",
					response.status()
				)));
			}
			let mut bytes = Vec::new();
			while let Some(chunk) = response
				.chunk()
				.await
				.map_err(|_| invalid("remote response"))?
			{
				if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
					return Err(invalid("remote response too large"));
				}
				bytes.extend_from_slice(&chunk);
			}
			Ok(Some(bytes))
		})
	}
	fn text(&self, path: &str) -> Result<String, Error> {
		String::from_utf8(
			self.request(path, None)?
				.ok_or_else(|| invalid("remote data missing"))?,
		)
		.map(|s| s.trim().to_owned())
		.map_err(|_| invalid("remote text"))
	}
	fn json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
		serde_json::from_slice(
			&self
				.request(path, None)?
				.ok_or_else(|| invalid("remote data missing"))?,
		)
		.map_err(|_| invalid("remote JSON"))
	}
	fn block(&self, height: u64) -> Result<BlockHash, Error> {
		BlockHash::from_str(&self.text(&format!("block-height/{height}"))?)
			.map_err(|_| invalid("block hash"))
	}
	pub fn tip(&self) -> Result<(u64, String), Error> {
		let height = self
			.text("blocks/tip/height")?
			.parse::<u64>()
			.map_err(|_| invalid("block height"))?;
		Ok((height, self.block(height)?.to_string()))
	}
	fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
		self.find_transaction(txid)?
			.ok_or_else(|| invalid("transaction missing"))
	}
	fn find_transaction(&self, txid: Txid) -> Result<Option<Transaction>, Error> {
		let Some(bytes) = self.request(&format!("tx/{txid}/raw"), None)? else {
			return Ok(None);
		};
		let tx: Transaction = deserialize(&bytes).map_err(|_| invalid("transaction encoding"))?;
		if tx.compute_txid() != txid {
			return Err(invalid("transaction id mismatch"));
		}
		Ok(Some(tx))
	}
	pub fn payment(&self, address: &Address, amount: Amount) -> Result<Option<Transaction>, Error> {
		let outputs: Vec<Value> = self.json(&format!("address/{address}/utxo"))?;
		let mut payment = None;
		for output in outputs {
			let value = output["value"]
				.as_u64()
				.ok_or_else(|| invalid("output amount"))?;
			if value != amount.to_sat() {
				continue;
			}
			if payment.is_some() {
				return Err(invalid("multiple swap payments"));
			}
			let txid = Txid::from_str(
				output["txid"]
					.as_str()
					.ok_or_else(|| invalid("transaction id"))?,
			)
			.map_err(|_| invalid("transaction id"))?;
			let vout = output["vout"]
				.as_u64()
				.and_then(|v| usize::try_from(v).ok())
				.ok_or_else(|| invalid("output index"))?;
			let tx = self.transaction(txid)?;
			let expected = TxOut {
				value: amount,
				script_pubkey: address.script_pubkey(),
			};
			if tx.output.get(vout) != Some(&expected) {
				return Err(invalid("payment output mismatch"));
			}
			payment = Some(tx);
		}
		Ok(payment)
	}
	pub fn status(&self, txid: Txid) -> Result<TxState, Error> {
		let Some(bytes) = self.request(&format!("tx/{txid}/status"), None)? else {
			return Ok(TxState::Absent);
		};
		let status: Value =
			serde_json::from_slice(&bytes).map_err(|_| invalid("transaction status"))?;
		match status["confirmed"].as_bool() {
			Some(false) => Ok(TxState::Pending),
			Some(true) => {
				let height = status["block_height"]
					.as_u64()
					.ok_or_else(|| invalid("transaction height"))?;
				let hash = BlockHash::from_str(
					status["block_hash"]
						.as_str()
						.ok_or_else(|| invalid("transaction block"))?,
				)
				.map_err(|_| invalid("transaction block"))?;
				if self.block(height)? != hash {
					return Err(invalid("transaction is not in the active chain"));
				}
				let bytes =
					Vec::<u8>::from_hex(&self.text(&format!("tx/{txid}/merkleblock-proof"))?)
						.map_err(|_| invalid("inclusion proof encoding"))?;
				verify(&bytes, txid, hash, self.network)?;
				let tip = self.tip()?.0;
				let confirmations = tip
					.checked_sub(height)
					.and_then(|n| n.checked_add(1))
					.ok_or_else(|| invalid("transaction above chain tip"))?;
				if self.block(height)? != hash {
					return Err(invalid("chain changed; retry"));
				}
				Ok(TxState::Confirmed(confirmations))
			}
			None => Err(invalid("transaction status")),
		}
	}
	pub fn unspent(&self, point: &OutPoint, expected: &TxOut) -> Result<(TxState, bool), Error> {
		let Some(tx) = self.find_transaction(point.txid)? else {
			return Ok((TxState::Absent, false));
		};
		if tx.output.get(point.vout as usize) != Some(expected) {
			return Err(invalid("funding output mismatch"));
		}
		let output: Value = self.json(&format!("tx/{}/outspend/{}", point.txid, point.vout))?;
		match output["spent"].as_bool() {
			Some(true) => Ok((TxState::Absent, false)),
			Some(false) => {
				let status = self.status(point.txid)?;
				if status == TxState::Absent {
					return Err(invalid("funding disappeared; retry"));
				}
				Ok((status, true))
			}
			None => Err(invalid("output status")),
		}
	}
	pub fn publish(&self, tx: &Transaction) -> Result<(), Error> {
		let txid = tx.compute_txid();
		let result = self.request("tx", Some(serialize_hex(tx)));
		if let Ok(Some(bytes)) = &result {
			if std::str::from_utf8(bytes).ok().map(str::trim) == Some(txid.to_string().as_str()) {
				return Ok(());
			}
		}
		if matches!(self.status(txid)?, TxState::Pending | TxState::Confirmed(_)) {
			return Ok(());
		}
		Err(invalid("transaction broadcast failed"))
	}
}

fn verify(bytes: &[u8], txid: Txid, hash: BlockHash, network: Network) -> Result<(), Error> {
	let proof: MerkleBlock = deserialize(bytes).map_err(|_| invalid("inclusion proof"))?;
	if proof.header.block_hash() != hash
		|| proof.header.target() > Params::new(network).max_attainable_target
	{
		return Err(invalid("inclusion block mismatch"));
	}
	proof
		.header
		.validate_pow(proof.header.target())
		.map_err(|_| invalid("block proof of work"))?;
	let mut matches = Vec::new();
	proof
		.extract_matches(&mut matches, &mut Vec::new())
		.map_err(|_| invalid("invalid inclusion proof"))?;
	if matches.iter().filter(|id| **id == txid).count() != 1 {
		return Err(invalid("transaction not included"));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn proxy() {
		use std::{
			io::{Read, Write},
			net::TcpListener,
			thread,
		};
		assert!(http_client(Some("socks5://127.0.0.1:9050")).is_err());
		assert!(http_client(Some("invalid")).is_err());
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let address = format!("http://{}", listener.local_addr().unwrap());
		let server = thread::spawn(move || {
			let deadline = std::time::Instant::now() + Duration::from_secs(5);
			let mut socket = loop {
				match listener.accept() {
					Ok((socket, _)) => break socket,
					Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
						assert!(std::time::Instant::now() < deadline, "proxy was bypassed");
						thread::sleep(Duration::from_millis(10));
					}
					Err(e) => panic!("{e}"),
				}
			};
			socket
				.set_read_timeout(Some(Duration::from_secs(2)))
				.unwrap();
			let mut request = Vec::new();
			while !request.ends_with(b"\r\n\r\n") {
				let mut byte = [0];
				socket.read_exact(&mut byte).unwrap();
				request.push(byte[0]);
				assert!(request.len() < 4096);
			}
			socket
				.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				.unwrap();
			String::from_utf8(request).unwrap()
		});
		let client = http_client(Some(&address)).unwrap();
		assert!(
			block_on(async { client.get("https://bitcoin.invalid/api").send().await }).is_err()
		);
		assert!(server
			.join()
			.unwrap()
			.starts_with("CONNECT bitcoin.invalid:443 HTTP/1.1"));
	}

	#[test]
	fn proof() {
		let block = genesis_block(Network::Testnet4);
		let txid = block.txdata[0].compute_txid();
		let proof = MerkleBlock::from_block_with_predicate(&block, |id| *id == txid);
		let bytes = ::bitcoin::consensus::serialize(&proof);
		assert!(verify(&bytes, txid, block.block_hash(), Network::Testnet4).is_ok());
		let wrong = genesis_block(Network::Signet).block_hash();
		assert!(verify(&bytes, txid, wrong, Network::Testnet4).is_err());
		let mut changed = bytes.clone();
		changed[36] ^= 1;
		assert!(verify(&changed, txid, block.block_hash(), Network::Testnet4).is_err());
		assert!(verify(&bytes[..40], txid, block.block_hash(), Network::Testnet4).is_err());
		let other = Txid::from_str(&"01".repeat(32)).unwrap();
		assert!(verify(&bytes, other, block.block_hash(), Network::Testnet4).is_err());
	}
	#[test]
	fn failures() {
		use std::{
			io::{Read, Write},
			net::TcpListener,
			thread,
		};
		for (code, body, funding, expected) in [
			(200, "{\"confirmed\":false}", false, Some(TxState::Pending)),
			(404, "missing", false, Some(TxState::Absent)),
			(503, "unavailable", false, None),
			(200, "{}", false, None),
			(404, "missing", true, Some(TxState::Absent)),
			(503, "unavailable", true, None),
		] {
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let url = format!("http://{}/", listener.local_addr().unwrap());
			let server = thread::spawn(move || {
				let (mut socket, _) = listener.accept().unwrap();
				socket.read(&mut [0; 4096]).unwrap();
				write!(
					socket,
					"HTTP/1.1 {code} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
					body.len()
				)
				.unwrap();
			});
			let node = Esplora {
				url: url.parse().unwrap(),
				network: Network::Testnet4,
				client: reqwest::Client::new(),
			};
			let txid = Txid::from_str(&"01".repeat(32)).unwrap();
			if funding {
				let output = genesis_block(Network::Testnet4).txdata[0].output[0].clone();
				assert_eq!(
					node.unspent(&OutPoint::new(txid, 0), &output).ok(),
					expected.map(|state| (state, false))
				);
			} else {
				assert_eq!(node.status(txid).ok(), expected);
			}
			server.join().unwrap();
		}
	}
	#[test]
	fn endpoints() {
		for url in [
			"http://example.com/api",
			"https://user:secret@example.com/api",
			"https://example.com/api?key=secret",
		] {
			assert!(Esplora::new(url, Network::Testnet4).is_err());
		}
		assert!(Esplora::new("https://example.com/api", Network::Bitcoin).is_err());
	}
	#[test]
	#[ignore = "queries the public Bitcoin testnet4 API"]
	fn live() {
		let node = Esplora::new("https://mempool.space/testnet4/api", Network::Testnet4).unwrap();
		assert!(node.tip().unwrap().0 > 0);
		let id = Txid::from_str("423a60955d1a3cc4dc4ea2a7b73407912a674e20867a413d7c653f4d3e083b59")
			.unwrap();
		assert_eq!(node.transaction(id).unwrap().compute_txid(), id);
		assert!(matches!(node.status(id).unwrap(), TxState::Confirmed(_)));
		let id = Txid::from_str("fdc638cf41de2538ab0dca3dc7ec88e6ec9c61f9c8265cc5ad77b55243097ae0")
			.unwrap();
		let tx = node.transaction(id).unwrap();
		let (vout, output) = tx
			.output
			.iter()
			.enumerate()
			.find(|(_, o)| o.value.to_sat() == 100_000 && o.script_pubkey.is_p2tr())
			.unwrap();
		let address = Address::from_script(&output.script_pubkey, Network::Testnet4).unwrap();
		assert_eq!(
			node.payment(&address, output.value)
				.unwrap()
				.unwrap()
				.compute_txid(),
			id
		);
		let (status, unspent) = node
			.unspent(&OutPoint::new(id, vout as u32), output)
			.unwrap();
		assert!(unspent && matches!(status, TxState::Confirmed(_)));
	}
}
