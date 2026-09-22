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

//! Local operations for grouped swap preparation

use crate::keychain::Keychain;
use crate::libwallet::{Error, NodeClient, Slate};
use crate::util::secp::{pedersen::Commitment, SecretKey};
fn invalid(message: &str) -> Error {
	Error::GenericError(format!("swap draft: {message}"))
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Operation {
	Reserve,
	Outputs,
	Sign,
	Finish,
	Store,
}

impl Operation {
	pub(super) fn name(self) -> &'static str {
		match self {
			Self::Reserve => "reserve",
			Self::Outputs => "outputs",
			Self::Sign => "sign",
			Self::Finish => "finish",
			Self::Store => "store",
		}
	}

	fn parse(name: &str) -> Result<Self, Error> {
		match name {
			"reserve" => Ok(Self::Reserve),
			"outputs" => Ok(Self::Outputs),
			"sign" => Ok(Self::Sign),
			"finish" => Ok(Self::Finish),
			"store" => Ok(Self::Store),
			_ => Err(invalid("draft operation")),
		}
	}

	fn round(self) -> u64 {
		match self {
			Self::Reserve => 0,
			Self::Outputs => 1,
			Self::Sign => 2,
			Self::Finish => 3,
			Self::Store => 4,
		}
	}
}

pub fn edit<C: NodeClient, K: Keychain>(
	w: &mut crate::libwallet::WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	op: &str,
	slate: &Slate,
) -> Result<Slate, Error> {
	let op = Operation::parse(op)?;
	let round = op.round();
	if let Some(saved) = w.draft_round(mask, slate, round, None)? {
		return Ok(saved);
	}
	let result = apply(w, mask, op, slate)?;
	w.draft_round(mask, slate, round, Some(&result))?;
	Ok(result)
}

fn apply<C: NodeClient, K: Keychain>(
	w: &mut crate::libwallet::WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	op: Operation,
	slate: &Slate,
) -> Result<Slate, crate::libwallet::Error> {
	use crate::core::core::{transaction::Weighting, Output, OutputFeatures};
	use crate::core::libtx::{build, proof};
	use crate::keychain::SwitchCommitmentType;
	let mut sl = slate.clone();
	let keychain = w.keychain(mask)?;
	let mut context = w.get_private_context(mask, sl.id.as_bytes())?;
	if op == Operation::Reserve {
		w.reserve_shared(mask, slate)?;
		return Ok(sl);
	}
	if op == Operation::Outputs {
		sl.tx = Some(Slate::empty_transaction());
		let parts = context
			.output_ids
			.iter()
			.map(|(id, _, value)| build::output(*value, id.clone()))
			.collect();
		sl.add_transaction_elements(&keychain, &proof::ProofBuilder::new(&keychain), parts)?;
		return Ok(sl);
	}
	if context.parent_key_id != w.parent_key_id() {
		return Err(invalid("account"));
	}
	if sl.num_participants != 2
		|| sl.participant_data.len() != 2
		|| sl.amount != context.amount
		|| Some(sl.fee_fields) != context.fee
	{
		return Err(invalid("recovery terms"));
	}
	let (key, nonce) = context.get_public_keys(keychain.secp());
	if !sl
		.participant_data
		.iter()
		.any(|p| p.public_nonce == nonce && p.public_blind_excess == key)
	{
		return Err(invalid("local participant"));
	}
	if sl.kernel_features != 2 {
		return Err(invalid("recovery height"));
	}
	if sl.multisig_key_id.is_none() {
		return Err(invalid("shared input"));
	}
	match op {
		Operation::Sign => {
			if sl.state != crate::libwallet::SlateState::Multisig3 {
				return Err(invalid("recovery round"));
			}
			context
				.output_ids
				.push((sl.create_multisig_id(), None, sl.amount));
			sl.adjust_offset(&keychain, &context)?;
			let mut parts = Vec::new();
			for (id, _, value) in &context.input_ids {
				let output = w
					.iter()?
					.find(|o| o.key_id == *id)
					.ok_or_else(|| invalid("recovery input"))?;
				let commit = Commitment::from_vec(
					crate::util::from_hex(
						output
							.commit
							.as_ref()
							.ok_or_else(|| invalid("input commitment"))?,
					)
					.map_err(|e| invalid(&e.to_string()))?,
				);
				parts.push(build::multisig_input(*value, id.clone(), commit));
			}
			sl.add_transaction_elements(&keychain, &proof::ProofBuilder::new(&keychain), parts)?;
			sl.tx_or_err_mut()?.offset = sl.offset.clone();
			sl.fill_round_2(&keychain, &context.sec_key, &context.sec_nonce)?;
		}
		Operation::Finish => {
			if sl.state != crate::libwallet::SlateState::Multisig4 {
				return Err(invalid("recovery round"));
			}
			let (_, nonce) = context.get_public_keys(keychain.secp());
			let other = sl
				.participant_data
				.iter()
				.find(|p| p.public_nonce != nonce)
				.ok_or_else(|| invalid("peer nonce"))?;
			let common = context.create_common_nonce(keychain.secp(), &other.public_nonce)?;
			let commit = keychain.secp().commit_sum(
				sl.participant_data
					.iter()
					.map(|p| p.part_commit.ok_or_else(|| invalid("peer commitment")))
					.collect::<Result<Vec<_>, _>>()?,
				vec![],
			)?;
			// presign_tx has already saved the sum of both tau_x shares
			let rangeproof = proof::create_multisig(
				&keychain,
				&proof::ProofBuilder::new(&keychain),
				sl.amount,
				&sl.create_multisig_id(),
				SwitchCommitmentType::Regular,
				&common,
				context.tau_x.as_mut(),
				context.tau_one.as_mut(),
				context.tau_two.as_mut(),
				&[commit],
				0,
				None,
			)?
			.ok_or_else(|| invalid("rangeproof"))?;
			let output = Output::new(OutputFeatures::Plain, commit, rangeproof);
			output.verify_proof()?;
			sl.tx_or_err_mut()?.body.outputs = vec![output];
			sl.tx_or_err_mut()?.offset = sl.offset.clone();
			sl.fill_round_2(&keychain, &context.sec_key, &context.sec_nonce)?;
			sl.finalize(&keychain)?;
		}
		Operation::Store => {
			sl.tx_or_err()?.validate(Weighting::AsTransaction)?;
			w.store_tx(&sl.id.to_string(), sl.tx_or_err()?)?;
		}
		_ => return Err(invalid("draft operation")),
	}
	Ok(sl)
}
