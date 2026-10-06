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

//! Fresh chain observations and funding discovery.

use super::*;

pub(super) type GrinObservation = (GrinView, (u64, String));

fn with_pending(
	status: TxState,
	excess: Commitment,
	pool: &[crate::core::core::TxKernel],
) -> TxState {
	if status == TxState::Absent
		&& pool
			.iter()
			.any(|k| k.excess == excess && k.verify().is_ok())
	{
		TxState::Pending
	} else {
		status
	}
}

pub(super) fn observe_grin<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	state: &State,
) -> Result<GrinObservation, Error> {
	let fund = decode(&state.offer.funding)?;
	let claim = decode(&state.offer.success)?;
	let rev = decode(&state.offer.revoke)?;
	let back = decode(&state.offer.refund)?;
	let expiry = decode(&state.offer.timeout)?;
	let (height, hash) = w.w2n_client().get_chain_tip()?;
	// Public-pool information is advisory. An unavailable query or a stem-only
	// transaction must not prevent recovery or be treated as a confirmed spend.
	let pending = w
		.w2n_client()
		.get_unconfirmed_kernels()
		.ok()
		.flatten()
		.unwrap_or_default();
	let mut status = |slate: &Slate| -> Result<TxState, Error> {
		let confirmed = grin_status(w, mask, slate, height)?;
		let excess = slate.calc_excess(w.keychain(mask)?.secp())?;
		Ok(with_pending(confirmed, excess, &pending))
	};
	let funding = status(&fund)?;
	let success = status(&claim)?;
	let revoke = status(&rev)?;
	let refund = status(&back)?;
	let timeout = status(&expiry)?;
	let outputs = w
		.w2n_client()
		.get_outputs_from_node(vec![state.shared, state.revoked])?;
	if w.w2n_client().get_chain_tip()? != (height, hash.clone()) {
		return Err(invalid("chain tip changed; retry"));
	}
	Ok((
		GrinView {
			height,
			funding,
			success,
			revoke,
			refund,
			timeout,
			funded: outputs.contains_key(&state.shared),
			revoked: outputs.contains_key(&state.revoked),
		},
		(height, hash),
	))
}

pub(super) fn observe<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &State,
	grin: Option<GrinObservation>,
) -> Result<View, Error> {
	let (grin, tip) = match grin {
		Some(grin) => grin,
		None => observe_grin(w, mask, state)?,
	};
	let btc_tip = core.tip()?;
	let (bitcoin, bitcoin_unspent) = match &state.funding {
		Some(tx) => {
			let point = state.contract.output(tx, state.network)?;
			core.unspent(&point, &tx.output[point.vout as usize])?
		}
		None => (TxState::Absent, false),
	};
	if w.w2n_client().get_chain_tip()? != tip || core.tip()? != btc_tip {
		return Err(invalid("chain tip changed; retry"));
	}
	Ok(View {
		height: grin.height,
		funding: grin.funding,
		success: grin.success,
		revoke: grin.revoke,
		refund: grin.refund,
		timeout: grin.timeout,
		funded: grin.funded,
		revoked: grin.revoked,
		bitcoin,
		bitcoin_started: state.funding.is_some(),
		bitcoin_unspent,
	})
}

pub(super) fn discover_payment(core: &Core, state: &mut State) -> Result<(), Error> {
	// Once recorded, a payment is a binding, not a replaceable search result.
	// Eviction, reorgs or a second deposit must not silently change it.
	// Explicit recovery has its own journal; never adopt one of its inputs.
	if state.destination.is_some()
		&& state.flow.prepared
		&& state.funding.is_none()
		&& state.recoveries.is_empty()
	{
		if let Some(tx) = core.payment(
			&state.contract.address(state.network)?,
			state.contract.amount,
		)? {
			state.contract.output(&tx, state.network)?;
			state.funding = Some(tx);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn public_pool_is_advisory() {
		use crate::core::core::KernelFeatures;
		use crate::core::libtx::{build, ProofBuilder};
		use crate::keychain::ExtKeychain;
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let tx = build::transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[
				build::input(5, ExtKeychain::derive_key_id(1, 1, 0, 0, 0)),
				build::output(3, ExtKeychain::derive_key_id(1, 2, 0, 0, 0)),
			],
			&keychain,
			&ProofBuilder::new(&keychain),
		)
		.unwrap();
		let kernel = tx.kernels()[0];
		let excess = kernel.excess;
		assert_eq!(
			with_pending(TxState::Absent, excess, &[kernel]),
			TxState::Pending
		);
		assert_eq!(
			with_pending(TxState::Confirmed(2), excess, &[kernel]),
			TxState::Confirmed(2)
		);
		assert_eq!(with_pending(TxState::Absent, excess, &[]), TxState::Absent);
		let mut invalid = kernel;
		invalid.features = KernelFeatures::Plain { fee: 3.into() };
		assert_eq!(
			with_pending(TxState::Absent, excess, &[invalid]),
			TxState::Absent
		);
		assert_eq!(
			with_pending(TxState::Absent, Commitment([0; 33]), &[kernel]),
			TxState::Absent
		);
	}
}
