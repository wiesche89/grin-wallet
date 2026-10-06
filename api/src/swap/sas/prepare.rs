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

//! Graph validation and preparation.

use super::*;

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
	offer.terms.validate_offer()?;
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

pub(super) fn prepare<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	role: Role,
	offer: Offer,
	network: btc::Network,
	planned: bool,
) -> Result<State, Error> {
	offer.terms.validate_offer()?;
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
		grin: None,
		funding_recovery: false,
		grin_posted: false,
		chain: None,
		payout: None,
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
		recoveries: Default::default(),
		destination: None,
		action: Action::Wait,
	})
}
