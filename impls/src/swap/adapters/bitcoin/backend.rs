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

//! Bitcoin access used by the succinct swap coordinator

use super::{esplora::Esplora, invalid, Core};
use crate::libwallet::{swap::TxState, Error};
use ::bitcoin::{Address, Amount, Network, OutPoint, Transaction, TxOut, Txid};
use std::path::PathBuf;

/// Local validation or trusted remote testnet access
pub enum Node {
	Core(Core),
	Remote(Esplora),
}

impl Node {
	/// HTTPS selects the public explorer interface; local RPC keeps cookie authentication
	pub fn new(url: &str, cookie: PathBuf, network: Network) -> Result<Self, Error> {
		Self::with_proxy(url, cookie, network, None)
	}
	pub fn with_proxy(
		url: &str,
		cookie: PathBuf,
		network: Network,
		proxy: Option<&str>,
	) -> Result<Self, Error> {
		if url.starts_with("https://") {
			Ok(Self::Remote(Esplora::with_proxy(url, network, proxy)?))
		} else {
			if proxy.is_some() {
				return Err(invalid(
					"a proxy is only supported for remote Bitcoin access",
				));
			}
			Ok(Self::Core(Core::new(url, cookie, network)?))
		}
	}
	pub fn remote(&self) -> bool {
		matches!(self, Self::Remote(_))
	}
	pub fn tip(&self) -> Result<(u64, String), Error> {
		match self {
			Self::Core(n) => n.tip(),
			Self::Remote(n) => n.tip(),
		}
	}
	pub fn watch(&self, address: &Address) -> Result<(), Error> {
		match self {
			Self::Core(n) => n.watch(address),
			Self::Remote(_) => Ok(()),
		}
	}
	pub fn payment(&self, address: &Address, amount: Amount) -> Result<Option<Transaction>, Error> {
		match self {
			Self::Core(n) => n.payment(address, amount),
			Self::Remote(n) => n.payment(address, amount),
		}
	}
	pub fn unspent(&self, point: &OutPoint, expected: &TxOut) -> Result<(TxState, bool), Error> {
		match self {
			Self::Core(n) => n.unspent(point, expected),
			Self::Remote(n) => n.unspent(point, expected),
		}
	}
	pub fn status(&self, txid: Txid) -> Result<TxState, Error> {
		match self {
			Self::Core(n) => n.status(txid),
			Self::Remote(n) => n.status(txid),
		}
	}
	pub fn publish(&self, tx: &Transaction) -> Result<(), Error> {
		match self {
			Self::Core(n) => n.publish(tx),
			Self::Remote(n) => n.publish(tx),
		}
	}
	pub fn accept(&self, tx: &Transaction) -> Result<(), Error> {
		match self {
			Self::Core(n) => n.accept(tx),
			Self::Remote(_) => Err(invalid("fee replacement requires local Core")),
		}
	}
	pub fn address(&self) -> Result<Address, Error> {
		match self {
			Self::Core(n) => n.address(),
			Self::Remote(_) => Err(invalid("provide a Bitcoin receiving address")),
		}
	}
	pub fn fund(
		&self,
		address: &Address,
		amount: Amount,
		rate: u64,
		fee: Amount,
	) -> Result<Transaction, Error> {
		match self {
			Self::Core(n) => n.fund(address, amount, rate, fee),
			Self::Remote(_) => Err(invalid("pay from your Bitcoin wallet")),
		}
	}
}
