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

//! Resumable preparation over the existing owner and foreign rounds

mod grouped;

use super::sas::{Offer, Request};

use crate::libwallet::swap::{sas::Terms, Role};
use crate::libwallet::{Error, InitTxArgs, Slate, VersionedSlate};
use crate::util::secp::SecretKey;
use crate::{ForeignRpc, OwnerRpc, Token};
use easy_jsonrpc_mw::Handler;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::str::FromStr;
use uuid::Uuid;

fn version<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
	let value = <u8 as serde::Deserialize>::deserialize(deserializer)?;
	if value != 2 {
		return Err(serde::de::Error::custom(
			"unsupported swap preparation version",
		));
	}
	Ok(value)
}

/// Public terms shown before accepting an offer
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
	/// Shared Grin output in nanogrins
	pub grin: u64,
	/// Bitcoin satoshis
	pub bitcoin: u64,
	/// Fee of each shared Grin spend
	pub fee: u64,
	/// Grin deadlines and confirmation policy
	pub terms: Terms,
	/// Grin chain
	pub chain: String,
	/// Bitcoin network
	pub network: String,
}

impl Proposal {
	/// Validate the total Grin input and exact Bitcoin payment
	pub fn validate_amounts(grin: u64, bitcoin: u64, fee: u64) -> Result<(), Error> {
		if fee != crate::core::libtx::tx_fee(1, 1, 1)
			|| grin <= fee.checked_mul(2).ok_or_else(|| invalid("amount"))?
			|| bitcoin <= 10_000
		{
			return Err(invalid("offer amounts"));
		}
		Ok(())
	}

	/// Reject invalid amounts and incompatible chains before signing
	pub fn validate(&self) -> Result<(), Error> {
		self.terms.validate()?;
		Self::validate_amounts(self.grin, self.bitcoin, self.fee)?;
		if self.chain != format!("{:?}", crate::core::global::get_chain_type()) {
			return Err(invalid("offer terms"));
		}
		Ok(())
	}
}

/// Public round data; completed seller funding and refund signatures stay local
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Message {
	/// Wire version
	pub version: u8,
	/// Negotiation identifier
	pub id: Uuid,
	/// Round number
	pub round: u8,
	/// Agreed terms
	pub proposal: Proposal,
	/// Public slates for this round
	pub slates: BTreeMap<String, String>,
	/// Transcript proof, when available
	pub proof: Option<String>,
}

/// Private preparation state; persist inside the wallet's protected storage
#[derive(Clone, Serialize, Deserialize)]
pub struct Preparation {
	#[serde(deserialize_with = "version")]
	version: u8,
	/// Negotiation identifier
	pub id: Uuid,
	/// Local side
	pub role: Role,
	/// Approved terms
	pub proposal: Proposal,
	/// Local payout address
	pub address: String,
	/// SAS identifier after preparation
	pub swap: Option<Uuid>,
	/// Preparation is complete
	pub ready: bool,
	/// Last outgoing public message
	pub outgoing: Option<Message>,
	next: u8,
	incoming: Option<Message>,
	slates: BTreeMap<String, String>,
	saved: BTreeMap<String, Value>,
	pending: Option<String>,
}

fn invalid(message: &str) -> Error {
	Error::GenericError(format!("swap preparation: {message}"))
}
fn encode<T: Serialize>(value: &T) -> Result<String, Error> {
	serde_json::to_string(value).map_err(|e| invalid(&e.to_string()))
}
fn decode<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
	serde_json::from_value(value).map_err(|e| invalid(&e.to_string()))
}

/// Local API access; no owner credentials are exchanged with the peer
pub struct Driver<'a> {
	/// Local owner API
	pub owner: &'a (dyn OwnerRpc + 'static),
	/// Local foreign API
	pub foreign: &'a (dyn ForeignRpc + 'static),
	/// Open wallet mask
	pub mask: Option<&'a SecretKey>,
}

impl Driver<'_> {
	fn call<T: DeserializeOwned>(
		&self,
		foreign: bool,
		method: &str,
		mut params: Value,
	) -> Result<T, Error> {
		let response = if foreign {
			self.foreign
				.handle_request(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
		} else {
			params["token"] = serde_json::to_value(Token {
				keychain_mask: self.mask.cloned(),
			})
			.map_err(|e| invalid(&e.to_string()))?;
			self.owner
				.handle_request(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
		}
		.as_option()
		.ok_or_else(|| invalid("missing API response"))?;
		if let Some(error) = response
			.get("error")
			.or_else(|| response["result"].get("Err"))
		{
			return Err(invalid(&error.to_string()));
		}
		decode(response["result"]["Ok"].clone())
	}

	fn sas(&self, request: Request) -> Result<super::Reply, Error> {
		self.call(
			false,
			"swap",
			json!({"request":super::Request::Sas { request }}),
		)
	}
}

impl Preparation {
	/// Reserve the proposal before constructing any transaction
	pub fn new(proposal: Proposal, address: String) -> Result<Self, Error> {
		proposal.validate()?;
		use crate::impls::swap::adapters::bitcoin::types::{Address, Network};
		let network = Network::from_str(&proposal.network).map_err(|_| invalid("network"))?;
		Address::from_str(&address)
			.map_err(|_| invalid("payout address"))?
			.require_network(network)
			.map_err(|_| invalid("payout network"))?;
		Ok(Self {
			version: 2,
			id: Uuid::new_v4(),
			role: Role::SellGrin,
			proposal,
			address,
			swap: None,
			ready: false,
			outgoing: None,
			next: 1,
			incoming: None,
			slates: BTreeMap::new(),
			saved: BTreeMap::new(),
			pending: None,
		})
	}

	/// Accept the initial public offer after the user has reviewed its terms
	pub fn accept(message: &Message, address: String) -> Result<Self, Error> {
		message.proposal.validate()?;
		if message.version != 2 || message.round != 0 || message.slates.len() != 4 {
			return Err(invalid("initial message"));
		}
		let fund = Slate::deserialize_upgrade(
			message
				.slates
				.get("fund")
				.ok_or_else(|| invalid("funding"))?,
		)?;
		if fund.amount != message.proposal.grin {
			return Err(invalid("funding amount"));
		}
		let mut state = Self::new(message.proposal.clone(), address)?;
		state.version = message.version;
		state.id = message.id;
		state.role = Role::BuyGrin;
		state.next = 0;
		Ok(state)
	}

	/// Local graph metadata for the wallet ledger
	pub fn record(&self) -> crate::libwallet::swap::records::Record {
		crate::libwallet::swap::records::Record {
			role: self.role,
			slates: self.slates.clone(),
		}
	}

	fn track(&self, api: &Driver) -> Result<(), Error> {
		if self.slates.contains_key("fund") {
			let _: super::Reply = api.call(
				false,
				"swap",
				json!({
					"request": super::Request::Track { record: self.record() }
				}),
			)?;
		}
		Ok(())
	}

	fn slate(&self, name: &str) -> Result<Slate, Error> {
		Slate::deserialize_upgrade(
			self.slates
				.get(name)
				.ok_or_else(|| invalid("missing round"))?,
		)
	}

	fn args(
		&self,
		amount: u64,
		parent: Option<&str>,
		height: Option<u64>,
		shared: bool,
	) -> Result<InitTxArgs, Error> {
		Ok(InitTxArgs {
			amount,
			minimum_confirmations: if parent.is_some() {
				0
			} else {
				self.proposal.terms.confirmations
			},
			selection_strategy_is_use_all: false,
			is_multisig: Some(shared),
			multisig_path: parent
				.map(|p| {
					self.slate(p)
						.map(|s| s.create_multisig_id().to_bip_32_string())
				})
				.transpose()?,
			refund_height: height,
			late_lock: Some(height.is_some() && !shared),
			..Default::default()
		})
	}

	fn call<T: Serialize + DeserializeOwned>(
		&mut self,
		api: &Driver,
		round: u8,
		key: &str,
		foreign: bool,
		method: &str,
		params: Value,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<T, Error> {
		let key = format!("{round}-{key}");
		if let Some(value) = self.saved.get(&key) {
			return decode(value.clone());
		}
		if self.pending.is_some() {
			return Err(invalid(
				"interrupted preparation; review pending wallet transactions before restarting",
			));
		}
		self.pending = Some(key.clone());
		save(self)?;
		let result: T = api.call(foreign, method, params)?;
		self.saved.insert(
			key,
			serde_json::to_value(&result).map_err(|e| invalid(&e.to_string()))?,
		);
		self.pending = None;
		save(self)?;
		Ok(result)
	}

	fn round(
		&mut self,
		api: &Driver,
		round: u8,
		name: &str,
		foreign: bool,
		method: &str,
		params: Value,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		let slate: VersionedSlate = self.call(api, round, name, foreign, method, params, save)?;
		self.slates
			.insert(name.into(), encode(&Slate::from(slate))?);
		save(self)
	}

	fn lock(
		&mut self,
		api: &Driver,
		round: u8,
		name: &str,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		self.call(
			api,
			round,
			&format!("lock-{name}"),
			false,
			"tx_lock_outputs",
			json!({"slate":self.slate(name)?}),
			save,
		)
	}

	fn publish(&mut self, round: u8, names: &[&str], proof: Option<String>) -> Result<(), Error> {
		let slates = names
			.iter()
			.map(|name| {
				Ok((
					name.to_string(),
					self.slates
						.get(*name)
						.ok_or_else(|| invalid("outgoing round"))?
						.clone(),
				))
			})
			.collect::<Result<_, Error>>()?;
		self.outgoing = Some(Message {
			version: self.version,
			id: self.id,
			round,
			proposal: self.proposal.clone(),
			slates,
			proof,
		});
		self.next = round + 1;
		Ok(())
	}

	/// Build the first funding round and save it before export
	pub fn start(
		&mut self,
		api: &Driver,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		if self.role != Role::SellGrin || self.incoming.is_some() {
			return Err(invalid("already started"));
		}
		if self.outgoing.is_some() {
			return self.track(api);
		}
		self.round(
			api,
			0,
			"fund",
			false,
			"init_send_tx",
			json!({"args": self.args(self.proposal.grin,None,None,true)?}),
			save,
		)?;
		self.lock(api, 0, "fund", save)?;
		self.start_grouped(api, save)?;
		self.track(api)
	}

	/// Continue only the agreed next round; identical retransmissions return saved output
	pub fn receive(
		&mut self,
		api: &Driver,
		message: Message,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		if self.incoming.as_ref() == Some(&message) {
			return self.track(api);
		}
		if self.ready
			|| message.version != self.version
			|| message.id != self.id
			|| message.proposal != self.proposal
			|| message.round != self.next
		{
			return Err(invalid("unexpected message"));
		}
		self.receive_grouped(api, message, save)?;
		self.track(api)
	}

	fn build_offer(&self) -> Result<Offer, Error> {
		let get = |name: &str| {
			self.slates
				.get(name)
				.cloned()
				.ok_or_else(|| invalid("incomplete graph"))
		};
		Ok(Offer {
			terms: self.proposal.terms,
			amount: self.proposal.bitcoin,
			fee_rate: 2,
			max_fee: 5000,
			funding: get("fund")?,
			revoke: get("revoke")?,
			refund: get("refund")?,
			timeout: get("timeout")?,
			success: get("success")?,
		})
	}

	fn offer(&mut self, api: &Driver) -> Result<Option<String>, Error> {
		let offer = self.build_offer()?;
		let reply = api.sas(Request::Planned {
			role: self.role,
			offer,
		})?;
		api.sas(Request::External {
			id: reply.id,
			address: self.address.clone(),
		})?;
		self.swap = Some(reply.id);
		Ok(reply.proof)
	}

	/// Next expected public round
	pub fn next_round(&self) -> u8 {
		self.next
	}

	/// Cancel a complete local preparation before funding
	pub fn cancel(&self, api: &Driver) -> Result<(), Error> {
		if self.pending.is_some() {
			return Err(invalid(
				"interrupted preparation; review pending wallet transactions",
			));
		}
		if self.slates.contains_key("fund") {
			let _: super::Reply = api.call(
				false,
				"swap",
				json!({
					"request": super::Request::CancelPreparation { record: self.record() }
				}),
			)?;
		}
		Ok(())
	}
}
