// Copyright 2021 The Grin Developers
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

//! Generic implementation of owner API functions

use strum::IntoEnumIterator;

use super::owner::tx_lock_outputs;
use crate::api_impl::owner::finalize_atomic_swap;
use crate::api_impl::owner::{check_ttl, post_tx};
use crate::api_impl::types::update_tx_slate_state;
use crate::backend::WalletBackend;
use crate::grin_core::core::FeeFields;
use crate::grin_keychain::{Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::ToHex;
use crate::internal::{selection, tx, updater};
use crate::slate_versions::SlateVersion;
use crate::{
	address, BlockFees, CbData, Error, NodeClient, Slate, SlateState, TxLogEntryType, VersionInfo,
};

const FOREIGN_API_VERSION: u16 = 2;

/// Return the version info
pub fn check_version() -> VersionInfo {
	VersionInfo {
		foreign_api_version: FOREIGN_API_VERSION,
		supported_slate_versions: SlateVersion::iter().collect(),
	}
}

/// Build a coinbase transaction
pub fn build_coinbase<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	C: NodeClient,
	K: Keychain,
{
	updater::build_coinbase(w, keychain_mask, block_fees, test_mode)
}

/// Receive a tx as recipient
pub fn receive_tx<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest_acct_name: Option<&str>,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut ret_slate = slate.clone();
	if !matches!(
		ret_slate.state,
		SlateState::Standard1 | SlateState::Multisig1
	) {
		return Err(Error::SlateState);
	}
	check_ttl(w, &ret_slate)?;
	let parent_key_id = match dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		w,
		None,
		Some(ret_slate.id),
		None,
		Some(&parent_key_id),
		use_test_rng,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(Error::TransactionAlreadyReceived(ret_slate.id.to_string()));
		}
	}

	ret_slate.tx = Some(Slate::empty_transaction());

	let height = w.last_confirmed_height_for_parent(&parent_key_id)?;
	let keychain = w.keychain(keychain_mask)?;

	let context = tx::add_output_to_slate(
		w,
		keychain_mask,
		&mut ret_slate,
		height,
		&parent_key_id,
		false,
		use_test_rng,
	)?;

	let is_multisig = slate.is_multisig();

	if !is_multisig {
		// Add our contribution to the offset
		ret_slate.adjust_offset(&keychain, &context)?;
	}

	let excess = ret_slate.calc_excess(keychain.secp())?;

	if let Some(ref mut p) = ret_slate.payment_proof {
		let sig = tx::create_payment_proof_signature(
			ret_slate.amount,
			&excess,
			p.sender_address,
			address::address_from_derivation_path(&keychain, &parent_key_id, 0)?,
		)?;

		p.receiver_signature = Some(sig);
	}

	if ret_slate.is_multisig() {
		ret_slate.state = SlateState::Multisig2;
	} else {
		ret_slate.amount = 0;
		ret_slate.fee_fields = FeeFields::zero();
		ret_slate.remove_other_sigdata(&keychain, &context.sec_nonce, &context.sec_key)?;
		ret_slate.state = SlateState::Standard2;
	}

	update_tx_slate_state(w, keychain_mask, &parent_key_id, &ret_slate)?;
	Ok(ret_slate)
}

/// Receive an atomic tx as recipient
pub fn receive_atomic_tx<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	dest_acct_name: Option<&str>,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut ret_slate = slate.clone();
	check_ttl(w, &ret_slate)?;
	let parent_key_id = match dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		w,
		None,
		Some(ret_slate.id),
		None,
		Some(&parent_key_id),
		use_test_rng,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(Error::TransactionAlreadyReceived(ret_slate.id.to_string()).into());
		}
	}

	ret_slate.tx = Some(Slate::empty_transaction());

	let height = w.last_confirmed_height()?;
	let keychain = w.keychain(keychain_mask)?;

	let is_height_lock = ret_slate.kernel_features == 2;
	// derive atomic nonce from the slate's `atomic_id`
	let (atomic_id, atomic_secret) = {
		let atomic_id = w.next_atomic_id(keychain_mask)?;
		let atomic =
			keychain.derive_key(ret_slate.amount, &atomic_id, SwitchCommitmentType::Regular)?;

		let pub_atomic = PublicKey::from_secret_key(keychain.secp(), &atomic)?;

		debug!(
			"Your public atomic nonce: {}",
			pub_atomic
				.serialize_vec(keychain.secp(), true)
				.as_ref()
				.to_hex()
		);
		debug!("Use this key to lock funds on the other chain.\n");

		(atomic_id, Some(atomic))
	};

	let min_confirmations = if use_test_rng { 0 } else { 10 };
	let (input_ids, output_ids) = if is_height_lock {
		// add input(s) and change output to slate
		let ctx = tx::add_inputs_to_atomic_slate(
			w,
			keychain_mask,
			&mut ret_slate,
			height,
			min_confirmations,
			500,  // max_outputs
			1,    // num_change_outputs
			true, // selection_strategy_is_use_all
			&parent_key_id,
			atomic_secret.clone(),
			use_test_rng,
		)?;

		(ctx.input_ids, ctx.output_ids)
	} else {
		(vec![], vec![])
	};

	let mut context = tx::add_output_to_atomic_slate(
		w,
		keychain_mask,
		&mut ret_slate,
		height,
		&parent_key_id,
		atomic_secret,
		use_test_rng,
	)?;

	{
		let atomic_idx = Slate::atomic_id_to_int(&atomic_id)?;
		let mut batch = w.batch(keychain_mask)?;
		batch.save_used_atomic_index(&ret_slate.id, atomic_idx)?;
		batch.commit()?;
	}

	context.fee = Some(ret_slate.fee_fields.clone());

	if is_height_lock {
		ret_slate.compact()?;
		context.input_ids = input_ids;
		context.output_ids.extend_from_slice(&output_ids);
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(ret_slate.id.as_bytes(), &context)?;
		batch.commit()?;
	}

	ret_slate.state = SlateState::Atomic2;

	Ok(ret_slate)
}

/// Receive a tx that this wallet has issued
pub fn finalize_tx<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	post_automatically: bool,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut sl = slate.clone();
	let mut context = w.get_private_context(keychain_mask, sl.id.as_bytes())?;
	check_ttl(w, &sl)?;
	if sl.state == SlateState::Invoice2 {
		// Add our contribution to the offset
		sl.adjust_offset(&w.keychain(keychain_mask)?, &context)?;

		let mut temp_ctx = context.clone();
		temp_ctx.sec_key = context.initial_sec_key.clone();
		temp_ctx.sec_nonce = context.initial_sec_nonce.clone();
		selection::repopulate_tx(w, keychain_mask, &mut sl, &temp_ctx, false)?;

		tx::complete_tx(w, keychain_mask, &mut sl, &context)?;
		tx::update_stored_tx(w, keychain_mask, &context, &mut sl, true)?;
		{
			let mut batch = w.batch(keychain_mask)?;
			batch.delete_private_context(sl.id.as_bytes())?;
			batch.commit()?;
		}
		sl.state = SlateState::Invoice3;
		sl.amount = 0;

		let parent_key_id = w.parent_key_id();
		update_tx_slate_state(w, keychain_mask, &parent_key_id, &sl)?;
	} else if sl.state == SlateState::Standard2 {
		let keychain = w.keychain(keychain_mask)?;
		let parent_key_id = w.parent_key_id();

		if let Some(args) = context.late_lock_args.take() {
			// Transaction was late locked, select inputs+change now
			// and insert into original context

			let current_height = w.w2n_client().get_chain_tip()?.0;
			let mut temp_sl = tx::new_tx_slate(
				w,
				context.amount,
				crate::TxFlow::Standard,
				2,
				false,
				args.ttl_blocks,
			)?;
			let temp_context = selection::build_send_tx(
				w,
				&keychain,
				keychain_mask,
				&mut temp_sl,
				current_height,
				args.minimum_confirmations,
				args.max_outputs as usize,
				args.num_change_outputs as usize,
				args.selection_strategy_is_use_all,
				Some(context.fee.map(|f| f.fee()).unwrap_or(0)),
				parent_key_id.clone(),
				None,
				false,
				true,
				false,
			)?;

			// Add inputs and outputs to original context
			context.input_ids = temp_context.input_ids;
			context.output_ids = temp_context.output_ids;

			// Store the updated context
			{
				let mut batch = w.batch(keychain_mask)?;
				batch.save_private_context(sl.id.as_bytes(), &context)?;
				batch.commit()?;
			}

			// Now do the actual locking
			tx_lock_outputs(w, keychain_mask, &sl)?;
		}

		// Add our contribution to the offset
		sl.adjust_offset(&keychain, &context)?;

		selection::repopulate_tx(w, keychain_mask, &mut sl, &context, true)?;

		tx::complete_tx(w, keychain_mask, &mut sl, &context)?;
		tx::verify_slate_payment_proof(w, keychain_mask, &parent_key_id, &context, &sl)?;
		tx::update_stored_tx(w, keychain_mask, &context, &sl, false)?;
		{
			let mut batch = w.batch(keychain_mask)?;
			batch.delete_private_context(sl.id.as_bytes())?;
			batch.commit()?;
		}
		sl.state = SlateState::Standard3;
		sl.amount = 0;

		update_tx_slate_state(w, keychain_mask, &parent_key_id, &sl)?;
	} else if sl.state == SlateState::Multisig3 {
		let tau_x =
			selection::finalize_multisig_bulletproof(w, keychain_mask, &mut sl, &mut context)?;
		let k = w.keychain(keychain_mask)?;
		let (_, pub_nonce) = context.get_public_keys(k.secp());
		{
			let part_data = sl
				.participant_data
				.iter_mut()
				.find(|d| d.public_nonce == pub_nonce)
				.ok_or(Error::from(Error::GenericError(
					"missing local participant data".into(),
				)))?;
			part_data.tau_x = tau_x;
		}

		sl.adjust_offset(&k, &context)?;

		debug!(
			"multisig ID path: {}",
			slate.create_multisig_id().to_bip_32_string()
		);
		debug!("Use with commands spending this multisig output");

		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(sl.id.as_bytes().as_ref(), &context)?;
		batch.commit()?;
	} else if sl.state == SlateState::Atomic3 {
		sl = finalize_atomic_swap(w, keychain_mask, slate)?;
	} else {
		return Err(Error::SlateState);
	}
	if post_automatically {
		post_tx(w.w2n_client(), sl.tx_or_err()?, true)?;
	}
	Ok(sl)
}
