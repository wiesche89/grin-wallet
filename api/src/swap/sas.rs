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
	sas::{Flow, Terms, View},
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

fn withdrawal_fee(vsize: usize, rate: u64, limit: u64) -> Result<u64, Error> {
	let fee = (vsize as u64)
		.checked_mul(rate)
		.ok_or_else(|| invalid("withdrawal fee overflow"))?;
	if fee == 0 || fee > limit {
		return Err(invalid("withdrawal fee exceeds limit"));
	}
	Ok(fee)
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
	#[serde(default = "published_before_tracking")]
	grin_posted: bool,
	#[serde(skip)]
	chain: Option<Chain>,
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
		chain: state.chain.clone(),
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
fn input(tx: &Transaction, expected: Commitment) -> Result<(), Error> {
	let inputs: Vec<CommitWrapper> = tx.inputs().into();
	if inputs.len() != 1
		|| inputs[0].commitment() != expected
		|| tx.outputs().len() != 1
		|| tx.kernels().len() != 1
	{
		return Err(invalid("transaction graph changed"));
	}
	Ok(())
}
fn locked(slate: &Slate, height: u64) -> Result<(), Error> {
	if slate.kernel_features != 2
		|| slate
			.kernel_features_args
			.as_ref()
			.map(|args| args.lock_height)
			!= Some(height)
	{
		return Err(invalid("lock height changed"));
	}
	if matches!(slate.state, SlateState::Multisig4 | SlateState::Atomic4) {
		let kernel = slate
			.tx_or_err()?
			.kernels()
			.first()
			.ok_or_else(|| invalid("missing kernel"))?;
		if kernel.features
			!= (crate::core::core::KernelFeatures::HeightLocked {
				fee: slate.fee_fields,
				lock_height: height,
			}) {
			return Err(invalid("kernel terms changed"));
		}
	}
	Ok(())
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

/// Bind the public graph before its signatures and rangeproofs are complete
/// Timeout outputs must come from the peer's draft and match the completed graph
pub fn plan_digest(
	offer: &Offer,
	network: btc::Network,
	timeout: &[Commitment],
) -> Result<[u8; 32], Error> {
	let mut graph = Vec::new();
	for encoded in [
		&offer.funding,
		&offer.revoke,
		&offer.refund,
		&offer.timeout,
		&offer.success,
	] {
		let mut slate = decode(encoded)?;
		if slate.participant_data.len() != 2 || slate.num_participants != 2 {
			return Err(invalid("incomplete plan"));
		}
		// Success outputs are already fixed in A2; other edges follow shared output IDs
		let outputs = if encoded == &offer.success {
			slate
				.tx_or_err()?
				.outputs()
				.iter()
				.map(|o| o.commitment())
				.collect::<Vec<_>>()
		} else {
			Vec::new()
		};
		if encoded == &offer.timeout {
			// A4 clears the amount; the parent value and fee fix the payout
			slate.amount = 0;
		}
		slate.tx = None;
		slate.offset = crate::keychain::BlindingFactor::zero();
		slate.state = SlateState::Standard1;
		for p in &mut slate.participant_data {
			p.part_sig = None;
			p.tau_one = None;
			p.tau_two = None;
			p.tau_x = None;
		}
		let secp = crate::util::secp::Secp256k1::new();
		slate
			.participant_data
			.sort_by_key(|p| p.public_nonce.serialize_vec(&secp, true));
		graph.push(serde_json::json!({"slate":slate,"outputs":outputs}));
	}
	let bytes = serde_json::to_vec(&serde_json::json!({
		"domain":"grin-sas/plan/1", "grin":format!("{:?}",crate::core::global::get_chain_type()),
		"bitcoin":network, "terms":offer.terms, "amount":offer.amount,
		"fee_rate":offer.fee_rate, "max_fee":offer.max_fee, "graph":graph, "timeout":timeout
	}))
	.map_err(|e| invalid(&e.to_string()))?;
	Ok(sha256::Hash::hash(&bytes).to_byte_array())
}

/// Prove local key possession without approving or funding the unfinished graph
pub fn prove_plan<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	role: Role,
	offer: &Offer,
	network: btc::Network,
	timeout: &[Commitment],
) -> Result<String, Error> {
	offer.terms.validate()?;
	let key = local_key(w, mask, role, offer)?;
	let expected = point(&decode(if role == Role::SellGrin {
		&offer.refund
	} else {
		&offer.success
	})?)?;
	if btc::PublicKey::new(key.public_key(&btc::secp256k1::Secp256k1::new())) != expected {
		return Err(invalid("local plan key changed"));
	}
	Ok(sas::prove(&key, plan_digest(offer, network, timeout)?))
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
		if let Request::Status { id } = request {
			let state: State = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
			if !matches!(state.version, 1 | 2) {
				return Err(invalid("state version"));
			}
			return Ok(reply(id, &state));
		}
		if let Request::Draft { op, slate } = &request {
			let slate = super::draft::edit(w, mask, op, &decode(slate)?)?;
			return Ok(Reply {
				chain: None,
				withdrawal: None,
				id: slate.id,
				action: Action::Wait,
				key: String::new(),
				proof: None,
				payment: None,
				funding: None,
				main: Some(encode(&slate)?),
			});
		}
		let (core, network) = super::node(self.config_path(), self.bitcoin_config.as_ref())?;
		if let Request::Plan {
			role,
			offer,
			outputs,
		} = &request
		{
			return Ok(Reply {
				chain: None,
				withdrawal: None,
				id: decode(&offer.funding)?.id,
				action: Action::Wait,
				key: String::new(),
				payment: None,
				funding: None,
				main: None,
				proof: Some(prove_plan(w, mask, *role, offer, network, outputs)?),
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
			| Request::Withdraw { id, .. }
			| Request::WithdrawAuto { id } => *id,
			Request::Offer { .. }
			| Request::Planned { .. }
			| Request::Draft { .. }
			| Request::Plan { .. } => unreachable!(),
		};
		let mut state: State = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
		if w.swap_aborted(&id)? {
			state.flow.aborted = true;
		}
		if !matches!(state.version, 1 | 2) || state.network != network {
			return Err(invalid("state version or network changed"));
		}
		let stepping = matches!(request, Request::Step { .. });
		let automatic = matches!(request, Request::WithdrawAuto { .. });
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
					core.watch(&state.contract.address(network)?)?;
					state.destination = Some(address);
				}
			}
			Request::Prepare { proof, .. } => {
				if core.remote() && state.destination.is_none() {
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
			Request::Step { .. } => publish = step(w, mask, &core, &mut state)?,
			Request::Withdraw { .. } | Request::WithdrawAuto { .. } => {
				let fee = match request {
					Request::Withdraw { fee, .. } => fee,
					_ => match &state.withdrawal {
						Some(_) => state
							.withdrawal_fee
							.ok_or_else(|| invalid("missing withdrawal fee"))?,
						None => 1,
					},
				};
				if !state.flow.owned || fee == 0 || fee > state.offer.max_fee {
					return Err(invalid("withdrawal policy"));
				}
				let tx = match &state.withdrawal {
					Some(tx) if state.withdrawal_fee == Some(fee) => tx.clone(),
					_ => {
						let view = observe(w, mask, &core, &state)?;
						if !matches!(state.flow.next(view)?, Action::Complete | Action::Refunded)
							|| (state.withdrawal.is_none() && !view.bitcoin_unspent)
						{
							return Err(invalid("coins are not settled"));
						}
						let destination = match &state.withdrawal {
							Some(previous) => {
								if fee
									<= state
										.withdrawal_fee
										.ok_or_else(|| invalid("missing withdrawal fee"))?
									|| matches!(
										core.status(previous.compute_txid())?,
										TxState::Confirmed(_)
									) {
									return Err(invalid("withdrawal cannot be replaced"));
								}
								btc::Address::from_script(
									&previous.output[0].script_pubkey,
									network,
								)
								.map_err(|_| invalid("withdrawal destination"))?
							}
							None => match &state.destination {
								Some(address) => btc::Address::from_str(address)
									.map_err(|_| invalid("payout address"))?
									.require_network(network)
									.map_err(|_| invalid("payout network"))?,
								None => core.address()?,
							},
						};
						let key = w.get_recovered_atomic_secret(mask, &state.key)?;
						let key =
							BitcoinKey::from_slice(&key.0).map_err(|_| invalid("owned key"))?;
						let funding = state
							.funding
							.as_ref()
							.ok_or_else(|| invalid("missing funding"))?;
						let spend = |fee| {
							state.contract.spend(
								funding,
								network,
								&destination,
								btc::Amount::from_sat(fee),
								&key,
							)
						};
						let mut tx = spend(fee)?;
						if automatic && state.withdrawal.is_none() {
							let fee = withdrawal_fee(
								tx.vsize(),
								state.offer.fee_rate,
								state.offer.max_fee,
							)?;
							tx = spend(fee)?;
						}
						if state.withdrawal.is_some() {
							core.accept(&tx)?;
						}
						tx
					}
				};
				state.withdrawal = Some(tx.clone());
				state.withdrawal_fee =
					Some(state.contract.amount.to_sat() - tx.output[0].value.to_sat());
				publish = Some(Publish::Bitcoin(tx));
			}
			Request::Status { .. }
			| Request::Offer { .. }
			| Request::Planned { .. }
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
			Some(Publish::Bitcoin(tx)) => core.publish(&tx)?,
			None => (),
		}
		self.cancel_pending(mask, &unused)?;
		Ok(response)
	}
}

fn prepare<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	role: Role,
	offer: Offer,
	network: btc::Network,
	planned: bool,
) -> Result<State, Error> {
	offer.terms.validate()?;
	if !offer.terms.open(w.w2n_client().get_chain_tip()?.0) {
		return Err(invalid("offer expired"));
	}
	if offer.amount <= offer.max_fee
		|| offer.max_fee == 0
		|| offer.fee_rate == 0
		|| offer.fee_rate > 1000
	{
		return Err(invalid("amount or fees"));
	}
	let fund = decode(&offer.funding)?;
	let revoke = decode(&offer.revoke)?;
	let refund = decode(&offer.refund)?;
	let timeout = decode(&offer.timeout)?;
	let success = decode(&offer.success)?;
	let slates = [&fund, &revoke, &refund, &timeout, &success];
	if fund.state != SlateState::Multisig4
		|| revoke.state != SlateState::Multisig4
		|| refund.state != SlateState::Atomic3
		|| timeout.state != SlateState::Atomic4
		|| success.state != SlateState::Atomic2
		|| success.kernel_features != 0
		|| slates.iter().any(|s| {
			s.ttl_cutoff_height != 0 || s.num_participants != 2 || s.participant_data.len() != 2
		}) {
		return Err(invalid("unexpected graph rounds"));
	}
	for (i, slate) in slates.iter().enumerate() {
		if slates[i + 1..].iter().any(|other| other.id == slate.id) {
			return Err(invalid("duplicate graph UUID"));
		}
	}
	let funded = shared(w, &fund.create_multisig_id())?;
	let revoked = shared(w, &revoke.create_multisig_id())?;
	let shared = commitment(&funded)?;
	let revoked_commit = commitment(&revoked)?;
	if !fund
		.tx_or_err()?
		.outputs()
		.iter()
		.any(|o| o.commitment() == shared)
		|| revoke.multisig_key_id.as_ref() != Some(&funded.key_id)
		|| success.multisig_key_id.as_ref() != Some(&funded.key_id)
		|| refund.multisig_key_id.as_ref() != Some(&revoked.key_id)
		|| timeout.multisig_key_id.as_ref() != Some(&revoked.key_id)
		|| success.amount.checked_add(success.fee_fields.fee()) != Some(funded.value)
		|| revoke.amount.checked_add(revoke.fee_fields.fee()) != Some(funded.value)
		|| refund.amount.checked_add(refund.fee_fields.fee()) != Some(revoked.value)
		|| timeout.amount != 0
		|| timeout.fee_fields.fee() >= revoked.value
	{
		return Err(invalid("graph amount or shared output"));
	}
	input(revoke.tx_or_err()?, shared)?;
	input(timeout.tx_or_err()?, revoked_commit)?;
	if revoke.tx_or_err()?.outputs()[0].commitment() != revoked_commit {
		return Err(invalid("revoke output"));
	}
	locked(&revoke, offer.terms.revoke)?;
	locked(&refund, offer.terms.refund)?;
	locked(&timeout, offer.terms.timeout)?;
	revoke.tx_or_err()?.validate(Weighting::AsTransaction)?;
	timeout.tx_or_err()?.validate(Weighting::AsTransaction)?;
	let contract = Contract {
		keys: [point(&refund)?, point(&success)?],
		amount: btc::Amount::from_sat(offer.amount),
	};
	contract.address(network)?;
	if contract.keys.contains(&point(&timeout)?) {
		return Err(invalid("timeout must not reveal a swap secret"));
	}
	let local = local_key(w, mask, role, &offer)?;
	if btc::PublicKey::new(local.public_key(&btc::secp256k1::Secp256k1::new()))
		!= contract.keys[index(role)]
	{
		return Err(invalid("local key changed"));
	}
	let ready = if role == Role::SellGrin {
		fund.tx_or_err()?.validate(Weighting::AsTransaction)?;
		if w.get_stored_tx(&fund.id.to_string())?.as_ref() != Some(fund.tx_or_err()?)
			|| w.get_stored_tx(&revoke.id.to_string())?.as_ref() != Some(revoke.tx_or_err()?)
		{
			return Err(invalid("funding and revoke must be local"));
		}
		let previous = w
			.atomic_round(&success.id, 1)?
			.ok_or_else(|| invalid("missing success offer"))?;
		success.check_offer(&previous)?;
		let context = w.get_private_context(mask, success.id.as_bytes())?;
		success.verify_adaptor(&w.keychain(mask)?, &context)?;
		Some(encode(&owner::finalize_atomic_swap(w, mask, &refund)?)?)
	} else {
		let previous = w
			.atomic_round(&success.id, 2)?
			.ok_or_else(|| invalid("missing success round"))?;
		let sent = w
			.atomic_round(&refund.id, 3)?
			.ok_or_else(|| invalid("missing refund round"))?;
		if encode(&previous)? != encode(&success)?
			|| encode(&sent)? != encode(&refund)?
			|| w.get_stored_tx(&timeout.id.to_string())?.as_ref() != Some(timeout.tx_or_err()?)
		{
			return Err(invalid("local graph changed"));
		}
		None
	};
	let digest = if planned {
		let outputs = timeout
			.tx_or_err()?
			.outputs()
			.iter()
			.map(|o| o.commitment())
			.collect::<Vec<_>>();
		plan_digest(&offer, network, &outputs)?
	} else {
		let digest = serde_json::to_vec(&serde_json::json!({
		"domain":"grin-sas/1", "grin": format!("{:?}", crate::core::global::get_chain_type()),
		"bitcoin":network, "id":fund.id, "fund":shared.0.to_hex(), "fee":fund.fee_fields,
		"kernel": fund.calc_excess(w.keychain(mask)?.secp())?.0.to_hex(),
		"terms":offer.terms,"amount":offer.amount,"fee_rate":offer.fee_rate,"max_fee":offer.max_fee,
		"revoke":encode(&revoke)?,"refund":encode(&refund)?,"timeout":encode(&timeout)?,"success":encode(&success)?
	})).map_err(|e| invalid(&e.to_string()))?;
		sha256::Hash::hash(&digest).to_byte_array()
	};
	let proof = sas::prove(&local, digest);
	let key = w.next_atomic_id(mask)?;
	Ok(State {
		grin_posted: false,
		chain: None,
		version: if planned { 2 } else { 1 },
		flow: Flow {
			role,
			terms: offer.terms,
			prepared: false,
			released: false,
			claimed: false,
			refund_sent: false,
			aborted: false,
			owned: false,
		},
		offer,
		digest,
		proof,
		peer: None,
		network,
		contract,
		key,
		shared,
		revoked: revoked_commit,
		refund: ready,
		released: None,
		funding: None,
		withdrawal: None,
		withdrawal_fee: None,
		destination: None,
		action: Action::Wait,
	})
}

fn observe<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &State,
) -> Result<View, Error> {
	let fund = decode(&state.offer.funding)?;
	let claim = decode(&state.offer.success)?;
	let rev = decode(&state.offer.revoke)?;
	let back = decode(&state.offer.refund)?;
	let expiry = decode(&state.offer.timeout)?;
	let (height, hash) = w.w2n_client().get_chain_tip()?;
	let btc_tip = core.tip()?;
	let funding = grin_status(w, mask, &fund, height)?;
	let success = grin_status(w, mask, &claim, height)?;
	let revoke = grin_status(w, mask, &rev, height)?;
	let refund = grin_status(w, mask, &back, height)?;
	let timeout = grin_status(w, mask, &expiry, height)?;
	let outputs = w
		.w2n_client()
		.get_outputs_from_node(vec![state.shared, state.revoked])?;
	let (bitcoin, bitcoin_unspent) = match &state.funding {
		Some(tx) => {
			let point = state.contract.output(tx, state.network)?;
			core.unspent(&point, &tx.output[point.vout as usize])?
		}
		None => (TxState::Absent, false),
	};
	if w.w2n_client().get_chain_tip()? != (height, hash) || core.tip()? != btc_tip {
		return Err(invalid("chain tip changed; retry"));
	}
	Ok(View {
		height,
		funding,
		success,
		revoke,
		refund,
		timeout,
		funded: outputs.contains_key(&state.shared),
		revoked: outputs.contains_key(&state.revoked),
		bitcoin,
		bitcoin_started: state.funding.is_some(),
		bitcoin_unspent,
	})
}

fn step<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut State,
) -> Result<Option<Publish>, Error> {
	if state.destination.is_some() && state.flow.prepared && !state.flow.owned {
		let unspent = match &state.funding {
			Some(tx) => {
				let point = state.contract.output(tx, state.network)?;
				core.unspent(&point, &tx.output[point.vout as usize])?.1
			}
			None => false,
		};
		if state.funding.is_none() || (!unspent && !state.flow.released && !state.flow.claimed) {
			if let Some(tx) = core.payment(
				&state.contract.address(state.network)?,
				state.contract.amount,
			)? {
				state.contract.output(&tx, state.network)?;
				state.funding = Some(tx);
			}
		}
	}
	let view = observe(w, mask, core, state)?;
	let mut kernels = std::collections::BTreeMap::new();
	for (name, status, json) in [
		("funding", view.funding, &state.offer.funding),
		("success", view.success, &state.offer.success),
		("revoke", view.revoke, &state.offer.revoke),
		("refund", view.refund, &state.offer.refund),
		("timeout", view.timeout, &state.offer.timeout),
	] {
		if matches!(status, TxState::Confirmed(_)) {
			let excess = decode(json)?.calc_excess(w.keychain(mask)?.secp())?;
			kernels.insert(name.into(), excess.0.to_hex());
		}
	}
	state.chain = Some(Chain {
		kernels,
		status: view,
		address: state.contract.address(state.network)?.to_string(),
		network: state.network.to_string(),
		txid: state
			.funding
			.as_ref()
			.map(|tx| tx.compute_txid().to_string()),
	});
	let action = state.flow.next(view)?;
	state.action = action;
	Ok(match action {
		Action::FundGrin => {
			state.grin_posted = true;
			Some(Publish::Grin(
				decode(&state.offer.funding)?.tx_or_err()?.clone(),
			))
		}
		Action::FundOther => {
			if state.destination.is_some() {
				return Ok(None);
			}
			if state.funding.is_none() {
				state.funding = Some(core.fund(
					&state.contract.address(state.network)?,
					state.contract.amount,
					state.offer.fee_rate,
					btc::Amount::from_sat(state.offer.max_fee),
				)?);
			}
			if !state.flow.terms.open(w.w2n_client().get_chain_tip()?.0) {
				return Err(invalid("funding deadline passed"));
			}
			Some(Publish::Bitcoin(
				state
					.funding
					.clone()
					.ok_or_else(|| invalid("missing funding"))?,
			))
		}
		Action::Release => {
			let signed = owner::countersign_atomic_swap(w, &decode(&state.offer.success)?, mask)?;
			state.released = Some(encode(&signed)?);
			state.flow.released = true;
			None
		}
		Action::ClaimGrin => {
			let signed = owner::finalize_atomic_swap(
				w,
				mask,
				&decode(
					state
						.released
						.as_deref()
						.ok_or_else(|| invalid("missing release"))?,
				)?,
			)?;
			state.flow.claimed = true;
			Some(Publish::Grin(signed.tx_or_err()?.clone()))
		}
		Action::RevokeGrin => Some(Publish::Grin(
			decode(&state.offer.revoke)?.tx_or_err()?.clone(),
		)),
		Action::RefundGrin => {
			let tx = decode(
				state
					.refund
					.as_deref()
					.ok_or_else(|| invalid("missing refund"))?,
			)?
			.tx_or_err()?
			.clone();
			state.flow.refund_sent = true;
			Some(Publish::Grin(tx))
		}
		Action::TimeoutGrin => Some(Publish::Grin(
			decode(&state.offer.timeout)?.tx_or_err()?.clone(),
		)),
		Action::OwnBitcoin => {
			let slate = decode(if state.flow.role == Role::SellGrin {
				state
					.released
					.as_deref()
					.ok_or_else(|| invalid("missing success signature"))?
			} else {
				&state.offer.refund
			})?;
			let excess = slate.calc_excess(w.keychain(mask)?.secp())?;
			let (kernel, _, _) = w
				.w2n_client()
				.get_kernel(&excess, None, None)?
				.ok_or_else(|| invalid("kernel disappeared"))?;
			let peer = crate::libwallet::recover_atomic_secret(w, mask, &slate, &kernel)?;
			let peer = BitcoinKey::from_slice(&peer.0).map_err(|_| invalid("recovered secret"))?;
			let local = local_key(w, mask, state.flow.role, &state.offer)?;
			let key = state.contract.recover(&local, &peer)?;
			let key = SecretKey::from_slice(w.keychain(mask)?.secp(), &key.secret_bytes())?;
			let mut batch = w.batch(mask)?;
			batch.save_recovered_atomic_secret(&state.key, &key)?;
			batch.commit()?;
			state.flow.owned = true;
			state.action = if state.flow.role == Role::SellGrin {
				Action::Complete
			} else {
				Action::Refunded
			};
			None
		}
		_ => None,
	})
}

#[cfg(test)]
mod fee_tests {
	use super::*;
	#[test]
	fn fees() {
		assert_eq!(withdrawal_fee(111, 2, 5000).unwrap(), 222);
		assert!(withdrawal_fee(111, 2, 221).is_err());
		assert!(withdrawal_fee(111, 0, 5000).is_err());
		assert!(withdrawal_fee(111, u64::MAX, u64::MAX).is_err());
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
