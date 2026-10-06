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

//! Three-transaction SAS execution over the existing wallet rounds

use super::bitcoin::{encode, grin_status, point, Publish};
use super::Reply;
use crate::core::core::{transaction::Weighting, CommitWrapper, Transaction};
use crate::impls::swap::adapters::bitcoin::{
	sas::{self, Contract},
	types as btc, Node as Core,
};
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::api_impl::owner;
use crate::libwallet::swap::{
	sas::{Flow, GrinView, Terms, View},
	Action, Role, TxState,
};
use crate::libwallet::{
	Error, NodeClient, OutputData, Slate, SlateState, WalletBackend, WalletLCProvider,
};
use crate::util::{
	from_hex,
	secp::{pedersen::Commitment, SecretKey},
	ToHex,
};
use crate::Owner;
use btc::consensus::{deserialize, encode::serialize_hex};
use btc::hashes::{sha256, Hash};
use btc::hex::FromHex;
use btc::secp256k1::SecretKey as BitcoinKey;
use std::str::FromStr;
use uuid::Uuid;

mod execution;
mod observe;
mod payout;
mod prepare;

use execution::{act, step};
use observe::{discover_payment, observe, observe_grin, GrinObservation};
use prepare::prepare;
pub use prepare::{plan_digest, prove_plan};

/// Payment instructions for an external Bitcoin wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
	/// Swap address
	pub address: String,
	/// Exact output amount in satoshis, excluding fees
	pub amount: u64,
	/// Bitcoin network
	pub network: String,
	/// Last Grin height at which funding may begin
	pub expires: u64,
}

/// Chain observations and the public Bitcoin funding reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
	/// Observations used to choose the next action
	pub status: View,
	/// Contract address, also available before payment
	pub address: String,
	/// Bitcoin network
	pub network: String,
	/// Funding transaction when detected
	pub txid: Option<String>,
	/// Observed Grin kernel excesses by transaction role
	#[serde(default)]
	pub kernels: std::collections::BTreeMap<String, String>,
}

/// Bitcoin payout status and fee limits for monitoring and replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payout {
	/// Fresh transaction observation, before any rebroadcast.
	pub status: TxState,
	/// Absolute fee of the saved payout in satoshis.
	pub fee: u64,
	/// Agreed maximum fee in satoshis.
	pub max_fee: u64,
	/// Backend can preflight a replacement before saving it.
	pub can_replace: bool,
}

/// Local graph; never exchange the completed refund
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
	/// Grin deadlines and both confirmation policies
	pub terms: Terms,
	/// Bitcoin satoshis
	pub amount: u64,
	/// Bitcoin funding fee rate in sat/vB
	pub fee_rate: u64,
	/// Maximum Bitcoin fee in satoshis
	pub max_fee: u64,
	/// Local funding M4; the buyer keeps its incomplete M4 until funding confirms
	pub funding: String,
	/// Fully signed shared-to-shared M4
	pub revoke: String,
	/// Refund A3, which still hides the seller's secret
	pub refund: String,
	/// Fully signed timeout A4 using an unrelated adaptor secret
	pub timeout: String,
	/// Success A2, which still requires the seller's signature
	pub success: String,
}

/// Operations transported through the existing owner swap endpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
	/// Read a saved signing response without repeating the operation
	Replay {
		/// Atomic round (2–4), or the Multisig2 processing round (5)
		round: u8,
		/// Exact original request
		slate: String,
	},
	/// Build a local contribution for grouped preparation
	Draft {
		/// Local operation
		op: String,
		/// Local slate with its saved context
		slate: String,
	},
	/// Prove the plan before the last rangeproof contribution arrives
	Plan {
		/// Local side
		role: Role,
		/// Planned graph
		offer: Offer,
		/// Timeout outputs received from the peer
		outputs: Vec<Commitment>,
	},
	/// Validate a completed graph using the experimental plan-bound proof
	Planned {
		/// Local side
		role: Role,
		/// Completed local graph
		offer: Offer,
	},
	/// Use an external Bitcoin wallet and fix the local payout address before funding
	External {
		/// Funding slate UUID
		id: Uuid,
		/// Local Bitcoin payout address
		address: String,
	},
	/// Validate the entire graph and return a transcript-bound proof
	Offer {
		/// Local side
		role: Role,
		/// Negotiated graph
		offer: Offer,
	},
	/// Verify the peer's proof before allowing funding
	Prepare {
		/// Funding slate UUID
		id: Uuid,
		/// Proof from the opposite side
		proof: String,
	},
	/// Receive Bitcoin funding or Grin Success A3
	Receive {
		/// Funding slate UUID
		id: Uuid,
		/// Signed Bitcoin transaction
		funding: Option<String>,
		/// Success A3
		success: Option<String>,
	},
	/// Recover one explicitly identified additional Bitcoin output after key recovery.
	Recover {
		/// Funding slate UUID
		id: Uuid,
		/// Raw signed transaction containing the output
		funding: String,
		/// Output index; never inferred from a server's ordering
		vout: u32,
		/// Absolute fee within the agreed maximum
		fee: u64,
	},

	/// Observe both chains and advance one step
	Step {
		/// Funding slate UUID
		id: Uuid,
	},
	/// Stop funding and signature release; retain recovery state
	Abort {
		/// Funding slate UUID
		id: Uuid,
	},
	/// Read local state
	Status {
		/// Funding slate UUID
		id: Uuid,
	},
	/// Spend owned Bitcoin at the agreed sat/vB rate, reusing any saved payout
	WithdrawAuto {
		/// Funding slate UUID
		id: Uuid,
	},
	/// Spend owned Bitcoin or raise its pending withdrawal fee
	Withdraw {
		/// Funding slate UUID
		id: Uuid,
		/// Absolute fee within the agreed limit
		fee: u64,
	},
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
	#[serde(skip)]
	grin: Option<GrinView>,
	#[serde(skip)]
	funding_recovery: bool,
	#[serde(default = "published_before_tracking")]
	grin_posted: bool,
	#[serde(skip)]
	chain: Option<Chain>,
	#[serde(skip)]
	payout: Option<Payout>,
	version: u8,
	flow: Flow,
	offer: Offer,
	digest: [u8; 32],
	proof: String,
	peer: Option<String>,
	network: btc::Network,
	contract: Contract,
	key: Identifier,
	shared: Commitment,
	revoked: Commitment,
	refund: Option<String>,
	released: Option<String>,
	funding: Option<btc::Transaction>,
	withdrawal: Option<btc::Transaction>,
	withdrawal_fee: Option<u64>,
	#[serde(default)]
	recoveries: std::collections::BTreeMap<String, btc::Transaction>,
	#[serde(default)]
	destination: Option<String>,
	action: Action,
}

fn invalid(message: &str) -> Error {
	Error::GenericError(format!("sas: {message}"))
}
fn decode(json: &str) -> Result<Slate, Error> {
	Slate::deserialize_upgrade(json)
}
fn index(role: Role) -> usize {
	if role == Role::SellGrin {
		0
	} else {
		1
	}
}
fn reply(id: Uuid, state: &State) -> Reply {
	Reply {
		grin: state.grin,
		funding_recovery: state.funding_recovery,
		chain: state.chain.clone(),
		payout: state.payout.clone(),
		withdrawal: state
			.withdrawal
			.as_ref()
			.map(|tx| tx.compute_txid().to_string()),
		payment: if state.destination.is_some()
			&& state.flow.role == Role::BuyGrin
			&& state.action == Action::FundOther
			&& !state.flow.aborted
			&& state.funding.is_none()
		{
			state
				.contract
				.address(state.network)
				.ok()
				.map(|address| Payment {
					address: address.to_string(),
					amount: state.offer.amount,
					network: state.network.to_string(),
					expires: state.flow.terms.revoke - state.flow.terms.margin - 1,
				})
		} else {
			None
		},
		id,
		proof: Some(state.proof.clone()),
		key: state.contract.keys[index(state.flow.role)].to_string(),
		action: state.action,
		funding: state.funding.as_ref().map(serialize_hex),
		main: state.released.clone(),
	}
}
fn shared<C: NodeClient, K: Keychain>(
	w: &WalletBackend<C, K>,
	id: &Identifier,
) -> Result<OutputData, Error> {
	w.iter()?
		.find(|o| o.is_multisig && &o.key_id == id)
		.ok_or_else(|| invalid("missing shared output"))
}
fn commitment(output: &OutputData) -> Result<Commitment, Error> {
	let bytes = from_hex(
		output
			.commit
			.as_deref()
			.ok_or_else(|| invalid("missing commitment"))?,
	)
	.map_err(|_| invalid("commitment"))?;
	if bytes.len() != 33 {
		return Err(invalid("commitment length"));
	}
	Ok(Commitment::from_vec(bytes))
}
fn local_key<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	role: Role,
	offer: &Offer,
) -> Result<BitcoinKey, Error> {
	let slate = decode(if role == Role::SellGrin {
		&offer.refund
	} else {
		&offer.success
	})?;
	let id = w.get_used_atomic_id(&slate.id)?;
	let secret = w.get_atomic_secret(mask, &id)?;
	BitcoinKey::from_slice(&secret.0).map_err(|_| invalid("local secret"))
}

impl<L, C, K> Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Run one succinct swap operation without exposing private key material
	pub fn sas(&self, mask: Option<&SecretKey>, request: Request) -> Result<Reply, Error> {
		let mut lock = self.wallet_inst.lock();
		let w = lock.lc_provider()?.wallet_inst()?;
		w.keychain(mask)?;
		if let Request::Status { id } | Request::Abort { id } = request {
			let mut state: State = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
			if !matches!(state.version, 1 | 2) {
				return Err(invalid("state version"));
			}
			if matches!(request, Request::Abort { .. }) {
				state.flow.aborted = true;
				w.save_swap(mask, &id, &state)?;
			}
			return Ok(reply(id, &state));
		}
		if let Request::Draft { slate, .. } | Request::Replay { slate, .. } = &request {
			let slate = decode(slate)?;
			let result = match &request {
				Request::Draft { op, .. } => Some(super::draft::edit(w, mask, op, &slate)?),
				Request::Replay { round, .. } => w.begin_round(mask, &slate, *round)?,
				_ => unreachable!(),
			};
			return Ok(Reply {
				main: result.as_ref().map(encode).transpose()?,
				..Reply::new(slate.id, Action::Wait)
			});
		}
		let mut observation = None;
		let recovery = if let Request::Step { id } = request {
			let state: State = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
			if !matches!(state.version, 1 | 2) {
				return Err(invalid("state version"));
			}
			let grin = observe_grin(w, mask, &state)?;
			let action =
				if state.flow.owned && state.destination.is_some() && state.funding.is_none() {
					// The key can be recovered offline before an external payment is known.
					// Observe Bitcoin before reporting that this swap is finished.
					None
				} else {
					state.flow.recovery(grin.0)?
				};
			observation = Some(grin);
			action.map(|action| (action, state.network))
		} else {
			None
		};
		let (core, network) = match recovery {
			Some((_, network)) => (None, network),
			None => {
				let (core, network) =
					super::node(self.config_path(), self.bitcoin_config.as_ref())?;
				(Some(core), network)
			}
		};
		let bitcoin = || {
			core.as_ref()
				.ok_or_else(|| invalid("Bitcoin observation required"))
		};
		if let Request::Plan {
			role,
			offer,
			outputs,
		} = &request
		{
			super::test_network(network)?;
			let id = decode(&offer.funding)?.id;
			return Ok(Reply {
				proof: Some(prove_plan(w, mask, *role, offer, network, outputs)?),
				..Reply::new(id, Action::Wait)
			});
		}

		let planned = matches!(&request, Request::Planned { .. });
		if let Request::Offer { role, offer } | Request::Planned { role, offer } = request {
			let funding = decode(&offer.funding)?;
			if w.swap_aborted(&funding.id)? {
				return Err(invalid("preparation was cancelled"));
			}
			if let Some(state) = w.load_swap::<State>(&funding.id)? {
				if state.version != if planned { 2 } else { 1 } || state.network != network {
					return Err(invalid("state version or network changed"));
				}
				if state.flow.role != role || state.offer != offer {
					return Err(invalid("offer changed"));
				}
				return Ok(reply(funding.id, &state));
			}
			super::test_network(network)?;
			let state = prepare(w, mask, role, offer, network, planned)?;
			let slates = [
				("fund", &state.offer.funding),
				("revoke", &state.offer.revoke),
				("success", &state.offer.success),
				("refund", &state.offer.refund),
				("timeout", &state.offer.timeout),
			]
			.iter()
			.map(|(name, slate)| (name.to_string(), (*slate).clone()))
			.collect();
			w.register_swap(
				mask,
				&crate::libwallet::swap::records::Record { role, slates },
			)?;
			w.bind_swap(mask, &funding.id, &funding.id)?;
			w.save_swap(mask, &funding.id, &state)?;
			return Ok(reply(funding.id, &state));
		}
		let id = match &request {
			Request::Prepare { id, .. }
			| Request::External { id, .. }
			| Request::Receive { id, .. }
			| Request::Step { id }
			| Request::Abort { id }
			| Request::Status { id }
			| Request::Recover { id, .. }
			| Request::Withdraw { id, .. }
			| Request::WithdrawAuto { id } => *id,
			Request::Offer { .. }
			| Request::Planned { .. }
			| Request::Replay { .. }
			| Request::Draft { .. }
			| Request::Plan { .. } => unreachable!(),
		};
		let mut state: State = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
		state.grin = observation.as_ref().map(|grin| grin.0);
		if w.swap_aborted(&id)? {
			state.flow.aborted = true;
		}
		if !matches!(state.version, 1 | 2) || state.network != network {
			return Err(invalid("state version or network changed"));
		}
		let stepping = matches!(request, Request::Step { .. });
		let mut publish = None;
		match request {
			Request::External { address, .. } => {
				let address = btc::Address::from_str(&address)
					.map_err(|_| invalid("payout address"))?
					.require_network(network)
					.map_err(|_| invalid("payout network"))?;
				let address = address.to_string();
				if let Some(saved) = &state.destination {
					if saved != &address {
						return Err(invalid("payout address changed"));
					}
				} else {
					if state.flow.prepared || state.funding.is_some() {
						return Err(invalid("payment mode already agreed"));
					}
					bitcoin()?.watch(&state.contract.address(network)?)?;
					state.destination = Some(address);
				}
			}
			Request::Prepare { proof, .. } => {
				if bitcoin()?.remote() && state.destination.is_none() {
					return Err(invalid("configure external Bitcoin payment first"));
				}
				sas::verify(
					state.contract.keys[1 - index(state.flow.role)],
					state.digest,
					&proof,
				)?;
				if let Some(saved) = &state.peer {
					if saved != &proof {
						return Err(invalid("peer proof changed"));
					}
				}
				state.peer = Some(proof);
				state.flow.prepared = true;
			}
			Request::Receive {
				funding, success, ..
			} => {
				if !state.flow.prepared {
					return Err(invalid("not prepared"));
				}
				if let Some(hex) = funding {
					if state.flow.role != Role::SellGrin {
						return Err(invalid("unexpected funding"));
					}
					let bytes =
						Vec::<u8>::from_hex(&hex).map_err(|_| invalid("funding encoding"))?;
					let tx: btc::Transaction =
						deserialize(&bytes).map_err(|_| invalid("funding encoding"))?;
					state.contract.output(&tx, network)?;
					if state.funding.as_ref().map_or(false, |saved| saved != &tx) {
						return Err(invalid("funding changed"));
					}
					state.funding = Some(tx);
				}
				if let Some(json) = success {
					if state.flow.role != Role::BuyGrin {
						return Err(invalid("unexpected success"));
					}
					let signed = decode(&json)?;
					let original = decode(&state.offer.success)?;
					if signed.tx_or_err()?.outputs() != original.tx_or_err()?.outputs() {
						return Err(invalid("success outputs changed"));
					}
					let output = shared(w, &decode(&state.offer.funding)?.create_multisig_id())?;
					let mut context = w.get_private_context(mask, original.id.as_bytes())?;
					context.input_ids = vec![(output.key_id, output.mmr_index, output.value)];
					signed.check_atomic(&original, state.shared, &w.keychain(mask)?, &context)?;
					let encoded = encode(&signed)?;
					if state
						.released
						.as_ref()
						.map_or(false, |saved| saved != &encoded)
					{
						return Err(invalid("success changed"));
					}
					state.released = Some(encoded);
					state.flow.released = true;
				}
			}
			Request::Abort { .. } => state.flow.aborted = true,
			Request::Step { .. } => {
				publish = if let Some((action, _)) = recovery {
					// No Bitcoin observation was made; do not expose stale payment instructions
					state.chain = None;
					act(w, mask, None, &mut state, action)?
				} else {
					step(w, mask, bitcoin()?, &mut state, observation)?
				};
			}
			Request::Recover { .. } => {
				let core = bitcoin()?;
				let (response, transaction) = payout::recover(w, mask, core, &mut state, request)?;
				drop(lock);
				if let Some(tx) = transaction {
					core.publish(&tx)?;
				}
				return Ok(response);
			}

			Request::Withdraw { .. } | Request::WithdrawAuto { .. } => {
				publish = payout::withdraw(w, mask, bitcoin()?, &mut state, request)?;
				if state.funding_recovery {
					w.save_swap(mask, &id, &state)?;
					return Ok(reply(id, &state));
				}
			}
			Request::Status { .. }
			| Request::Offer { .. }
			| Request::Planned { .. }
			| Request::Replay { .. }
			| Request::Draft { .. }
			| Request::Plan { .. } => {
				unreachable!()
			}
		}
		w.save_swap(mask, &id, &state)?;
		let response = reply(id, &state);
		let unused = if stepping {
			match state.action {
				Action::Complete => vec![
					&state.offer.revoke,
					&state.offer.refund,
					&state.offer.timeout,
				],
				Action::Refunded => vec![&state.offer.success, &state.offer.timeout],
				Action::TimedOut => vec![&state.offer.success, &state.offer.refund],
				_ => Vec::new(),
			}
		} else {
			Vec::new()
		};
		let unused = unused
			.into_iter()
			.map(|s| decode(s).map(|s| s.id))
			.collect::<Result<Vec<_>, _>>()?;
		let node = w.w2n_client().clone();
		drop(lock);
		match publish {
			Some(Publish::Grin(tx)) => node.post_tx(&tx, false)?,
			Some(Publish::Bitcoin(tx)) => bitcoin()?.publish(&tx)?,
			None => (),
		}
		self.cancel_pending(mask, &unused)?;
		Ok(response)
	}
}

fn published_before_tracking() -> bool {
	true
}

pub(super) fn check_preparation<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	id: Uuid,
) -> Result<(), Error> {
	if let Some(state) = w.load_swap::<State>(&id)? {
		if state.grin_posted
			|| state.flow.released
			|| state.flow.claimed
			|| state.flow.refund_sent
			|| state.funding.is_some()
			|| (state.flow.role == Role::BuyGrin && state.flow.prepared)
		{
			return Err(invalid("funding may be published; use swap recovery"));
		}
	}
	Ok(())
}
