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

//! Persisted owner-side swap execution. Negotiation uses the existing atomic slates

use crate::core::core::{transaction::Weighting, CommitWrapper, KernelFeatures};
use crate::impls::swap::adapters::bitcoin::{types as btc, Contract, Core};
use crate::keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::libwallet::api_impl::owner;
use crate::libwallet::swap::{Action, Flow, Role, TxState, View};
use crate::libwallet::{Error, NodeClient, Slate, SlateState, WalletBackend, WalletLCProvider};
use crate::util::from_hex;
use crate::util::secp::{key::PublicKey, pedersen::Commitment, SecretKey};
use crate::Owner;
use btc::consensus::{deserialize, encode::serialize_hex};
use btc::hex::FromHex;
use std::str::FromStr;
use uuid::Uuid;

use super::{Reply, Request};

#[derive(Clone, Serialize, Deserialize)]
struct Swap {
	version: u8,
	flow: Flow,
	key: Identifier,
	network: btc::Network,
	destination: String,
	amount: u64,
	fee_rate: u64,
	fee: u64,
	max_fee: u64,
	contract: Option<Contract>,
	peer: Option<String>,
	funding: Option<String>,
	refund: Option<String>,
	main: Option<String>,
	released: Option<String>,
	shared: Option<Commitment>,
	btc_funding: Option<btc::Transaction>,
	btc_refund: Option<btc::Transaction>,
	btc_claim: Option<btc::Transaction>,
	#[serde(default)]
	replacements: Vec<btc::Transaction>,
	last_action: Action,
}

pub(super) enum Publish {
	Grin(crate::core::core::Transaction),
	Bitcoin(btc::Transaction),
}

impl Swap {
	fn destination(&self) -> Result<btc::Address, Error> {
		btc::Address::from_str(&self.destination)
			.map_err(|_| invalid("destination"))?
			.require_network(self.network)
			.map_err(|_| invalid("destination network"))
	}
}

fn invalid(message: &str) -> Error {
	Error::GenericError(format!("swap: {message}"))
}
pub(super) fn encode(slate: &Slate) -> Result<String, Error> {
	serde_json::to_string(slate).map_err(|e| invalid(&e.to_string()))
}
fn slate(value: &Option<String>) -> Result<Slate, Error> {
	Slate::deserialize_upgrade(value.as_deref().ok_or_else(|| invalid("missing slate"))?)
}
fn secret<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	id: &Identifier,
) -> Result<btc::secp256k1::SecretKey, Error> {
	let key = w
		.keychain(mask)?
		.derive_key(0, id, SwitchCommitmentType::Regular)?;
	btc::secp256k1::SecretKey::from_slice(&key.0).map_err(|_| invalid("signing key"))
}
fn public(key: &btc::secp256k1::SecretKey) -> btc::PublicKey {
	btc::PublicKey::new(key.public_key(&btc::secp256k1::Secp256k1::new()))
}
pub(super) fn point(main: &Slate) -> Result<btc::PublicKey, Error> {
	let mut keys = main
		.participant_data
		.iter()
		.filter_map(|p| p.public_atomic.as_ref());
	let key = keys.next().ok_or_else(|| invalid("missing adaptor key"))?;
	if keys.next().is_some() {
		return Err(invalid("ambiguous adaptor key"));
	}
	let secp = crate::util::secp::Secp256k1::new();
	btc::PublicKey::from_slice(&key.serialize_vec(&secp, true)).map_err(|_| invalid("adaptor key"))
}

impl<L, C, K> Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Run one persisted swap operation using the locally configured Bitcoin backend
	pub fn swap(&self, mask: Option<&SecretKey>, request: Request) -> Result<Reply, Error> {
		if let Request::CancelPreparation { record } = request {
			return self.cancel_preparation(mask, &record);
		}
		if let Request::Track { record } = request {
			return self.track_swap(mask, &record);
		}
		if let Request::Sas { request } = request {
			return self.sas(mask, request);
		}
		if let Request::Status { id } = &request {
			let mut lock = self.wallet_inst.lock();
			let w = lock.lc_provider()?.wallet_inst()?;
			w.keychain(mask)?;
			let state: Swap = w.load_swap(id)?.ok_or_else(|| invalid("unknown swap"))?;
			if state.version != 1 {
				return Err(invalid("unsupported swap version"));
			}
			return reply(w, mask, *id, &state);
		}

		let mut lock = self.wallet_inst.lock();
		let w = lock.lc_provider()?.wallet_inst()?;
		w.keychain(mask)?;
		let (core, network) = super::core(self.config_path())?;
		if let Request::Start {
			role,
			policy,
			amount,
			fee_rate,
			fee,
			max_fee,
		} = request
		{
			policy.validate(w.w2n_client().get_chain_tip()?.0, core.height()?)?;
			if amount > btc::Amount::MAX_MONEY.to_sat()
				|| amount <= fee
				|| fee == 0 || fee > max_fee
				|| max_fee >= amount
				|| fee_rate == 0
				|| fee_rate > 1000
				|| policy.other.refund >= 500_000_000
				|| policy.grin.block_seconds != 60
				|| policy.other.block_seconds != 600
			{
				return Err(invalid("invalid amounts, fees or deadlines"));
			}
			let id = Uuid::new_v4();
			let key = w.next_atomic_id(mask)?;
			let state = Swap {
				version: 1,
				flow: Flow {
					role,
					policy,
					prepared: false,
					released: false,
					claimed: false,
				},
				key,
				network,
				destination: core.address()?.to_string(),
				amount,
				fee_rate,
				fee,
				max_fee,
				contract: None,
				peer: None,
				funding: None,
				refund: None,
				main: None,
				released: None,
				shared: None,
				btc_funding: None,
				btc_refund: None,
				btc_claim: None,
				replacements: Vec::new(),
				last_action: Action::Wait,
			};
			w.save_swap(mask, &id, &state)?;
			return reply(w, mask, id, &state);
		}
		let id = match &request {
			Request::Prepare { id, .. }
			| Request::Receive { id, .. }
			| Request::Bump { id, .. }
			| Request::Step { id }
			| Request::Status { id } => *id,
			Request::Start { .. }
			| Request::Sas { .. }
			| Request::Track { .. }
			| Request::CancelPreparation { .. } => unreachable!(),
		};
		let mut state: Swap = w.load_swap(&id)?.ok_or_else(|| invalid("unknown swap"))?;
		if state.version != 1 || state.network != network {
			return Err(invalid("swap version or network changed"));
		}
		let mut publish = None;
		let stepping = matches!(&request, Request::Step { .. });
		match request {
			Request::Prepare {
				peer_key,
				funding,
				refund,
				main,
				..
			} => {
				if state.flow.prepared {
					if state.peer.as_deref() != Some(&peer_key)
						|| state.funding.as_deref()
							!= Some(&encode(&Slate::deserialize_upgrade(&funding)?)?)
						|| state.refund.as_deref()
							!= Some(&encode(&Slate::deserialize_upgrade(&refund)?)?)
						|| state.main.as_deref()
							!= Some(&encode(&Slate::deserialize_upgrade(&main)?)?)
					{
						return Err(invalid("prepared swap changed"));
					}
					return reply(w, mask, id, &state);
				}
				state
					.flow
					.policy
					.validate(w.w2n_client().get_chain_tip()?.0, core.height()?)?;
				let funding = Slate::deserialize_upgrade(&funding)?;
				let refund = Slate::deserialize_upgrade(&refund)?;
				let main = Slate::deserialize_upgrade(&main)?;
				prepare(w, mask, &mut state, &funding, &refund, &main, &peer_key)?;
				w.bind_swap(mask, &funding.id, &id)?;
				state.peer = Some(peer_key);
			}
			Request::Receive { funding, main, .. } => {
				if !state.flow.prepared {
					return Err(invalid("swap is not prepared"));
				}
				if let Some(hex) = funding {
					if state.flow.role != Role::SellGrin {
						return Err(invalid("unexpected Bitcoin funding"));
					}
					let bytes =
						Vec::<u8>::from_hex(&hex).map_err(|_| invalid("funding encoding"))?;
					let tx: btc::Transaction =
						deserialize(&bytes).map_err(|_| invalid("funding encoding"))?;
					state
						.contract
						.as_ref()
						.ok_or_else(|| invalid("missing contract"))?
						.output(&tx)?;
					if let Some(saved) = &state.btc_funding {
						if saved != &tx {
							return Err(invalid("funding changed"));
						}
					}
					state.btc_funding = Some(tx);
				}
				if let Some(json) = main {
					if state.flow.role != Role::BuyGrin {
						return Err(invalid("unexpected Grin signature"));
					}
					let signed = Slate::deserialize_upgrade(&json)?;
					let original = slate(&state.main)?;
					if signed.tx_or_err()?.outputs() != original.tx_or_err()?.outputs() {
						return Err(invalid("main outputs changed"));
					}
					let mut context = w.get_private_context(mask, signed.id.as_bytes())?;
					let output = w
						.iter()?
						.find(|o| {
							o.is_multisig && Some(&o.key_id) == original.multisig_key_id.as_ref()
						})
						.ok_or_else(|| invalid("missing shared output"))?;
					context.input_ids = vec![(output.key_id, output.mmr_index, output.value)];
					signed.check_atomic(
						&original,
						state
							.shared
							.ok_or_else(|| invalid("missing shared output"))?,
						&w.keychain(mask)?,
						&context,
					)?;
					if let Some(saved) = &state.released {
						if saved != &encode(&signed)? {
							return Err(invalid("signature changed"));
						}
					}
					state.released = Some(encode(&signed)?);
					state.flow.released = true;
				}
			}
			Request::Step { .. } => publish = step(w, mask, &core, &mut state)?,
			Request::Bump { fee, .. } => publish = Some(bump(w, mask, &core, &mut state, fee)?),
			Request::Status { .. } => return reply(w, mask, id, &state),
			Request::Start { .. }
			| Request::Sas { .. }
			| Request::Track { .. }
			| Request::CancelPreparation { .. } => unreachable!(),
		}
		w.save_swap(mask, &id, &state)?;
		let reply = reply(w, mask, id, &state)?;
		let cancel = if stepping {
			match state.last_action {
				Action::Complete => Some(slate(&state.refund)?.id),
				Action::Refunded => Some(slate(&state.main)?.id),
				_ => None,
			}
		} else {
			None
		};
		let client = w.w2n_client().clone();
		drop(lock);
		match publish {
			Some(Publish::Grin(tx)) => client.post_tx(&tx, false)?,
			Some(Publish::Bitcoin(tx)) => core.publish(&tx)?,
			None => (),
		}
		if let Some(id) = cancel {
			self.cancel_pending(mask, &[id])?;
		}
		Ok(reply)
	}
}

fn reply<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	id: Uuid,
	state: &Swap,
) -> Result<Reply, Error> {
	Ok(Reply {
		chain: None,
		withdrawal: None,
		payment: None,
		proof: None,
		id,
		key: public(&secret(w, mask, &state.key)?).to_string(),
		action: state.last_action,
		funding: state.btc_funding.as_ref().map(serialize_hex),
		main: state.released.clone(),
	})
}

fn prepare<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	state: &mut Swap,
	funding: &Slate,
	refund: &Slate,
	main: &Slate,
	peer: &str,
) -> Result<(), Error> {
	if funding.state != SlateState::Multisig4
		|| refund.state != SlateState::Atomic4
		|| main.state != SlateState::Atomic2
		|| main.kernel_features != 0
		|| main.ttl_cutoff_height != 0
		|| refund.ttl_cutoff_height != 0
		|| funding.ttl_cutoff_height != 0
		|| main.num_participants != 2
		|| main.participant_data.len() != 2
	{
		return Err(invalid(
			"expected M4 funding, A4 refund and A2 main without TTL",
		));
	}
	funding.tx_or_err()?.validate(Weighting::AsTransaction)?;
	refund.tx_or_err()?.validate(Weighting::AsTransaction)?;
	let shared_id = funding.create_multisig_id();
	if refund.multisig_key_id.as_ref() != Some(&shared_id)
		|| main.multisig_key_id.as_ref() != Some(&shared_id)
	{
		return Err(invalid("shared output mismatch"));
	}
	let output = w
		.iter()?
		.find(|o| o.is_multisig && o.key_id == shared_id)
		.ok_or_else(|| invalid("shared output is not in this wallet"))?;
	let bytes = from_hex(
		output
			.commit
			.as_deref()
			.ok_or_else(|| invalid("missing shared commitment"))?,
	)
	.map_err(|_| invalid("shared commitment"))?;
	if bytes.len() != 33 {
		return Err(invalid("shared commitment length"));
	}
	let commit = Commitment::from_vec(bytes);
	if !funding
		.tx_or_err()?
		.outputs()
		.iter()
		.any(|o| o.commitment() == commit)
		|| main.amount.checked_add(main.fee_fields.fee()) != Some(output.value)
	{
		return Err(invalid("main must spend the full shared output"));
	}
	let refund_tx = refund.tx_or_err()?;
	let inputs: Vec<CommitWrapper> = refund_tx.inputs().into();
	if inputs.len() != 1
		|| inputs[0].commitment() != commit
		|| refund_tx.kernels().len() != 1
		|| refund_tx.outputs().len() != 1
		|| !matches!(refund_tx.kernels()[0].features, KernelFeatures::HeightLocked { lock_height, .. }
			if lock_height == state.flow.policy.grin.refund)
	{
		return Err(invalid("invalid Grin refund"));
	}
	let context = w.get_private_context(mask, main.id.as_bytes())?;
	let keychain = w.keychain(mask)?;
	main.find_participant_data_index(keychain.secp(), &context)?;
	if state.flow.role == Role::SellGrin {
		let offer = w
			.atomic_round(&main.id, 1)?
			.ok_or_else(|| invalid("missing sender round"))?;
		main.check_offer(&offer)?;
		main.verify_adaptor(&keychain, &context)?;
		if w.get_stored_tx(&refund.id.to_string())?.as_ref() != Some(refund_tx)
			|| w.get_stored_tx(&funding.id.to_string())?.as_ref() != Some(funding.tx_or_err()?)
		{
			return Err(invalid("funding and refund must be finalized locally"));
		}
	} else {
		let saved = w
			.atomic_round(&main.id, 2)?
			.ok_or_else(|| invalid("missing receiver round"))?;
		if encode(main)? != encode(&saved)? {
			return Err(invalid("receiver round changed"));
		}
		let atomic = context
			.sec_atomic
			.as_ref()
			.ok_or_else(|| invalid("missing local adaptor key"))?;
		let expected = PublicKey::from_secret_key(keychain.secp(), atomic)?;
		let expected = btc::PublicKey::from_slice(&expected.serialize_vec(keychain.secp(), true))
			.map_err(|_| invalid("adaptor key"))?;
		if expected != point(main)? {
			return Err(invalid("main adaptor key changed"));
		}
	}
	let local = public(&secret(w, mask, &state.key)?);
	let peer = btc::PublicKey::from_str(peer).map_err(|_| invalid("peer key"))?;
	let (claim, refund_key) = if state.flow.role == Role::SellGrin {
		(local, peer)
	} else {
		(peer, local)
	};
	state.contract = Some(Contract::new(
		claim,
		point(main)?,
		refund_key,
		state.flow.policy.other.refund as u32,
		btc::Amount::from_sat(state.amount),
	)?);
	state.funding = Some(encode(funding)?);
	state.refund = Some(encode(refund)?);
	state.main = Some(encode(main)?);
	state.shared = Some(commit);
	state.flow.prepared = true;
	Ok(())
}

pub(super) fn grin_status<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	slate: &Slate,
	height: u64,
) -> Result<TxState, Error> {
	let lock_height = if slate.kernel_features == 2 {
		Some(
			slate
				.kernel_features_args
				.as_ref()
				.ok_or_else(|| invalid("missing lock height"))?
				.lock_height,
		)
	} else {
		None
	};
	if lock_height.is_some_and(|lock| lock > height) {
		return Ok(TxState::Absent);
	}
	let mut created = None;
	for tx in w.tx_log_iter()? {
		let tx = tx?;
		if tx.tx_slate_id == Some(slate.id) {
			if let Some(h) = tx.kernel_lookup_min_height {
				created = Some(created.map_or(h, |previous: u64| previous.min(h)));
			}
		}
	}
	let min_height = created.into_iter().chain(lock_height).max();
	let excess = slate.calc_excess(w.keychain(mask)?.secp())?;
	Ok(
		match w
			.w2n_client()
			.get_kernel(&excess, min_height, Some(height))?
		{
			Some((kernel, h, _)) if h <= height => {
				kernel.verify()?;
				TxState::Confirmed(height - h + 1)
			}
			Some(_) => return Err(invalid("Grin tip changed during lookup")),
			None => TxState::Absent,
		},
	)
}

fn step<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut Swap,
) -> Result<Option<Publish>, Error> {
	if !state.flow.prepared {
		return Err(invalid("swap is not prepared"));
	}
	let funding = slate(&state.funding)?;
	let refund = slate(&state.refund)?;
	let main = if state.flow.released {
		slate(&state.released)?
	} else {
		slate(&state.main)?
	};
	let contract = state
		.contract
		.clone()
		.ok_or_else(|| invalid("missing contract"))?;
	let (height, hash) = w.w2n_client().get_chain_tip()?;
	let shared = state
		.shared
		.ok_or_else(|| invalid("missing shared output"))?;
	let grin = View {
		height,
		funding: grin_status(w, mask, &funding, height)?,
		claim: if state.flow.released {
			grin_status(w, mask, &main, height)?
		} else {
			TxState::Absent
		},
		refund: grin_status(w, mask, &refund, height)?,
		unspent: w
			.w2n_client()
			.get_outputs_from_node(vec![shared])?
			.contains_key(&shared),
	};
	let (other_height, other_hash) = core.tip()?;
	let (other_funding, unspent) = match &state.btc_funding {
		Some(tx) => core.output(&contract, tx)?,
		None => (TxState::Absent, false),
	};
	let other = View {
		height: other_height,
		funding: other_funding,
		unspent,
		claim: status(
			core,
			state.btc_claim.as_ref(),
			if state.flow.role == Role::SellGrin {
				&state.replacements
			} else {
				&[]
			},
		)?,
		refund: status(
			core,
			state.btc_refund.as_ref(),
			if state.flow.role == Role::BuyGrin {
				&state.replacements
			} else {
				&[]
			},
		)?,
	};
	if w.w2n_client().get_chain_tip()? != (height, hash)
		|| core.tip()? != (other_height, other_hash)
	{
		return Err(invalid("chain tip changed; retry"));
	}
	let mut action = state.flow.next(grin, other)?;
	// A saved replacement can be retried while its predecessor still spends the funding
	if action == Action::Wait && !state.replacements.is_empty() {
		if state.flow.role == Role::SellGrin && other.claim == TxState::Pending {
			action = Action::ClaimOther;
		} else if state.flow.role == Role::BuyGrin
			&& other.refund == TxState::Pending
			&& other.height >= state.flow.policy.other.refund
		{
			action = Action::RefundOther;
		}
	}
	state.last_action = action;
	let publish = match action {
		Action::FundGrin => Some(Publish::Grin(funding.tx_or_err()?.clone())),
		Action::FundOther => {
			if state.btc_funding.is_none() {
				let destination = state.destination()?;
				let prepared = core.prepare(
					&contract,
					&destination,
					&secret(w, mask, &state.key)?,
					state.fee_rate,
					btc::Amount::from_sat(state.max_fee),
					btc::Amount::from_sat(state.fee),
				)?;
				state.btc_funding = Some(prepared.tx);
				state.btc_refund = Some(prepared.refund);
			}
			state
				.flow
				.policy
				.validate(w.w2n_client().get_chain_tip()?.0, core.height()?)?;
			Some(Publish::Bitcoin(
				state
					.btc_funding
					.clone()
					.ok_or_else(|| invalid("missing Bitcoin funding"))?,
			))
		}
		Action::Release => {
			let signed = owner::countersign_atomic_swap(w, &main, mask)?;
			state.released = Some(encode(&signed)?);
			state.flow.released = true;
			None
		}
		Action::ClaimGrin => {
			let signed = owner::finalize_atomic_swap(w, mask, &main)?;
			state.flow.claimed = true;
			Some(Publish::Grin(signed.tx_or_err()?.clone()))
		}
		Action::ClaimOther => {
			if state.btc_claim.is_none() {
				state.btc_claim = Some(claim(w, mask, state)?);
			}
			state.flow.claimed = true;
			Some(Publish::Bitcoin(
				state
					.btc_claim
					.clone()
					.ok_or_else(|| invalid("missing claim"))?,
			))
		}
		Action::RefundGrin => Some(Publish::Grin(refund.tx_or_err()?.clone())),
		Action::RefundOther => Some(Publish::Bitcoin(
			state
				.btc_refund
				.clone()
				.ok_or_else(|| invalid("missing Bitcoin refund"))?,
		)),
		_ => None,
	};
	Ok(publish)
}

fn status(
	core: &Core,
	tx: Option<&btc::Transaction>,
	previous: &[btc::Transaction],
) -> Result<TxState, Error> {
	let mut result = TxState::Absent;
	for tx in tx.into_iter().chain(previous.iter()) {
		match core.status(tx.compute_txid())? {
			confirmed @ TxState::Confirmed(_) => return Ok(confirmed),
			TxState::Pending => result = TxState::Pending,
			TxState::Conflicted if result == TxState::Absent => result = TxState::Conflicted,
			_ => (),
		}
	}
	Ok(result)
}

fn claim<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	state: &Swap,
) -> Result<btc::Transaction, Error> {
	let main = slate(&state.released)?;
	let atomic_id = w.get_used_atomic_id(&main.id)?;
	let recovered = match w.find_recovered_atomic_secret(mask, &atomic_id)? {
		Some(key) => key,
		None => {
			let excess = main.calc_excess(w.keychain(mask)?.secp())?;
			let (kernel, _, _) = w
				.w2n_client()
				.get_kernel(&excess, None, None)?
				.ok_or_else(|| invalid("main kernel disappeared"))?;
			crate::libwallet::recover_atomic_secret(w, mask, &main, &kernel)?
		}
	};
	let recovered = btc::secp256k1::SecretKey::from_slice(&recovered.0)
		.map_err(|_| invalid("recovered key"))?;
	state
		.contract
		.as_ref()
		.ok_or_else(|| invalid("missing contract"))?
		.claim(
			state
				.btc_funding
				.as_ref()
				.ok_or_else(|| invalid("missing Bitcoin funding"))?,
			&state.destination()?,
			btc::Amount::from_sat(state.fee),
			&secret(w, mask, &state.key)?,
			&recovered,
		)
}

fn bump<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut Swap,
	fee: u64,
) -> Result<Publish, Error> {
	if fee < state.fee || fee > state.max_fee {
		return Err(invalid("fee increase exceeds policy"));
	}
	let old = match state.flow.role {
		Role::SellGrin => state.btc_claim.as_ref(),
		Role::BuyGrin => state.btc_refund.as_ref(),
	}
	.ok_or_else(|| invalid("no Bitcoin spend to replace"))?
	.clone();
	if matches!(
		status(core, Some(&old), &state.replacements)?,
		TxState::Confirmed(_) | TxState::Conflicted
	) {
		return Err(invalid("Bitcoin spend is confirmed or conflicted"));
	}
	if state.flow.role == Role::BuyGrin && core.height()? < state.flow.policy.other.refund {
		return Err(invalid("refund is not mature"));
	}
	if fee == state.fee {
		return Ok(Publish::Bitcoin(old));
	}
	state.fee = fee;
	let replacement = match state.flow.role {
		Role::SellGrin => claim(w, mask, state)?,
		Role::BuyGrin => state
			.contract
			.as_ref()
			.ok_or_else(|| invalid("missing contract"))?
			.refund(
				state
					.btc_funding
					.as_ref()
					.ok_or_else(|| invalid("missing Bitcoin funding"))?,
				&state.destination()?,
				btc::Amount::from_sat(fee),
				&secret(w, mask, &state.key)?,
			)?,
	};
	core.accept(&replacement)?;
	state.replacements.push(old);
	match state.flow.role {
		Role::SellGrin => {
			state.btc_claim = Some(replacement.clone());
			state.last_action = Action::ClaimOther;
		}
		Role::BuyGrin => {
			state.btc_refund = Some(replacement.clone());
			state.last_action = Action::RefundOther;
		}
	}
	Ok(Publish::Bitcoin(replacement))
}
