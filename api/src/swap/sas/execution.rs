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

//! Swap state transitions and Grin actions.

use super::*;

pub(super) fn step<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut State,
	grin: Option<GrinObservation>,
) -> Result<Option<Publish>, Error> {
	discover_payment(core, state)?;
	let view = observe(w, mask, core, state, grin)?;
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
	act(w, mask, Some(core), state, action)
}

pub(super) fn act<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: Option<&Core>,
	state: &mut State,
	action: Action,
) -> Result<Option<Publish>, Error> {
	state.action = action;
	Ok(match action {
		Action::FundGrin => {
			state.grin_posted = true;
			Some(Publish::Grin(
				decode(&state.offer.funding)?.tx_or_err()?.clone(),
			))
		}
		Action::FundOther => {
			let core = core.ok_or_else(|| invalid("Bitcoin observation required"))?;
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
			state.action = if state.destination.is_some() && state.funding.is_none() {
				Action::OwnBitcoin
			} else if state.flow.role == Role::SellGrin {
				Action::Complete
			} else {
				Action::Refunded
			};
			None
		}
		_ => None,
	})
}
