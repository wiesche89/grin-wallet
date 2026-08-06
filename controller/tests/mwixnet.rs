// Copyright 2024 The Grin Developers
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

//! Test a wallet sending to self, then creation of comsig request
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use grin_core::core::FeeFields;
use grin_keychain::{Keychain, SwitchCommitmentType};
use grin_util as util;
use grin_util::secp::key::SecretKey;
use grin_util::ToHex;
use std::path::PathBuf;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{
	mwixnet::{
		ComSignature, MixnetReqCreationParams, MwixnetServerPublicKey, RouteSwapReq, SwapReq,
		WalletMwixnetRequest, WalletMwixnetRequestStatus, MAX_MWIXNET_HOPS,
	},
	InitTxArgs, OutputStatus, TxLogEntryType,
};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn mwixnet_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			api.create_account_path(m, "mining")?;
			api.create_account_path(m, "listener")?;
			Ok(())
		},
	)?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			// send to send
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount: reward * 2,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let mut slate = api.init_send_tx(m, args)?;
			api.tx_lock_outputs(m, &slate)?;
			// Send directly to self
			wallet::controller::foreign_single_use(
				wallet1.clone(),
				PathBuf::from(test_dir),
				mask1_i.clone(),
				|api| {
					slate = api.receive_tx(&slate, Some("listener"), None)?;
					Ok(())
				},
			)?;
			slate = api.finalize_tx(m, &slate)?;
			api.post_tx(m, &slate, false)?; // mines a block
			bh += 1;
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward - reward * 2);
			Ok(())
		},
	)?;

	// Check total in 'listener' account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, 2 * reward);
			Ok(())
		},
	)?;

	// Recipient wallet creates a mwixnet request from the last output
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let secp_locked = util::static_secp_instance();
			let secp = secp_locked.lock();
			let server_pubkey_str_1 =
				"97444ae673bb92c713c1a2f7b8882ffbfc1c67401a280a775dce1a8651584332";
			let server_pubkey_str_2 =
				"0c9414341f2140ed34a5a12a6479bf5a6404820d001ab81d9d3e8cc38f049b4e";
			let server_pubkey_str_3 =
				"b58ece97d60e71bb7e53218400b0d67bfe6a3cb7d3b4a67a44f8fb7c525cbca5";
			let server_key_1 =
				SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_1).unwrap())
					.unwrap();
			let server_key_2 =
				SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_2).unwrap())
					.unwrap();
			let server_key_3 =
				SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_3).unwrap())
					.unwrap();
			let params = MixnetReqCreationParams {
				server_keys: vec![
					MwixnetServerPublicKey::from_secret(&server_key_1),
					MwixnetServerPublicKey::from_secret(&server_key_2),
					MwixnetServerPublicKey::from_secret(&server_key_3),
				],
				fee_per_hop: 10_000_000,
			};
			let outputs = api.retrieve_outputs(mask1, false, false, None)?;
			// get last output
			let last_output = outputs.1[outputs.1.len() - 1].clone();

			let empty_params = MixnetReqCreationParams {
				server_keys: vec![],
				fee_per_hop: params.fee_per_hop,
			};
			assert!(api
				.create_mwixnet_req(m, &empty_params, &last_output.commit, true)
				.is_err());

			let too_many_params = MixnetReqCreationParams {
				server_keys: vec![params.server_keys[0]; MAX_MWIXNET_HOPS + 1],
				fee_per_hop: params.fee_per_hop,
			};
			assert!(api
				.create_mwixnet_req(m, &too_many_params, &last_output.commit, true)
				.is_err());

			let oversized_fee_params = MixnetReqCreationParams {
				server_keys: params.server_keys[..2].to_vec(),
				fee_per_hop: 1 << 39,
			};
			assert_eq!(
				api.create_mwixnet_req(m, &oversized_fee_params, &last_output.commit, true)
					.unwrap_err(),
				libwallet::Error::Fee("mwixnet total fee exceeds FeeFields limit".to_string())
			);

			let creation = api.create_mwixnet_req(m, &params, &last_output.commit, true)?;
			let creation_tx_id = creation.tx_id.unwrap();
			let peeled = creation
				.request
				.onion()
				.peel_layer(&server_key_1)
				.map_err(|e| libwallet::Error::GenericError(e.to_string()))?;
			assert_eq!(peeled.payload.fee, FeeFields::try_from(params.fee_per_hop)?);

			println!("MWIXNET REQ: {:?}", creation.request);

			// Check the input lock and expected output are tracked together.
			let outputs = api.retrieve_outputs(mask1, false, false, None)?;
			let input = outputs
				.1
				.iter()
				.find(|o| o.commit == last_output.commit)
				.unwrap();
			assert_eq!(input.output.status, OutputStatus::Locked);
			let expected_amount =
				last_output.output.value - params.fee_per_hop * params.server_keys.len() as u64;
			let expected_output = outputs
				.1
				.iter()
				.find(|o| {
					o.output.status == OutputStatus::Unconfirmed
						&& o.output.value == expected_amount
				})
				.unwrap();
			assert_eq!(
				input.output.tx_log_entry,
				expected_output.output.tx_log_entry
			);

			let txs = api.retrieve_txs(m, false, None, None, None)?.1;
			let tx = txs.last().unwrap();
			assert_eq!(creation_tx_id, tx.id);
			assert_eq!(tx.tx_type, TxLogEntryType::TxSent);
			assert_eq!(tx.amount_debited, last_output.output.value);
			assert_eq!(tx.amount_credited, expected_amount);
			assert_eq!(tx.num_inputs, 1);
			assert_eq!(tx.num_outputs, 1);
			assert_eq!(
				tx.fee,
				Some(FeeFields::try_from(
					params.fee_per_hop * params.server_keys.len() as u64
				)?)
			);

			// A timed-out route request remains queryable and is retried byte-for-byte.
			let legacy = match &creation.request {
				SwapReq::Legacy(request) => request,
				SwapReq::Route(_) => panic!("expected legacy MWixnet request"),
			};
			let wallet_request_id = libwallet::mwixnet_protocol::Hash([7; 32]);
			let mut route_request = RouteSwapReq {
				version: libwallet::mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
				msg_type: libwallet::mwixnet_protocol::MwixnetType::SwapReq,
				wallet_request_id,
				route_id: libwallet::mwixnet_protocol::Hash([8; 32]),
				manifest_sequence: 1,
				expires_at_height: bh + 60,
				onion: legacy.onion.clone(),
				onion_hash: RouteSwapReq::onion_hash(&legacy.onion),
				comsig: legacy.comsig.clone(),
			};
			{
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				let input_blind = {
					let keychain = w.keychain(m)?;
					keychain.derive_key(
						last_output.output.value,
						&last_output.output.key_id,
						SwitchCommitmentType::Regular,
					)?
				};
				route_request.comsig = ComSignature::sign(
					last_output.output.value,
					&input_blind,
					&route_request.hash().0.to_vec(),
					false,
				)
				.map_err(|e| libwallet::Error::Signature(e.to_string()))?;
				route_request
					.validate()
					.map_err(libwallet::Error::GenericError)?;
				let mut batch = w.batch_no_mask()?;
				batch.save_mwixnet_request(&WalletMwixnetRequest {
					request: route_request.clone(),
					tx_id: Some(creation_tx_id),
					input_commitment: last_output.commit.to_hex(),
					swap_onion_address: libwallet::mwixnet_protocol::OnionAddress([9; 32]),
					status: WalletMwixnetRequestStatus::Accepted,
					reclaim_max_fee: 1_000_000_000,
					confirmation_depth: 10,
					kernel_excess: None,
					cancel_request: None,
					cancel_ack: None,
					reclaim_tx: None,
					reclaim_tx_id: None,
					conflict_observed_height: None,
				})?;
				batch.commit()?;
			}

			let requests = api.get_mwixnet_requests(Some(wallet_request_id))?;
			assert_eq!(requests.len(), 1);
			assert_eq!(requests[0].status, WalletMwixnetRequestStatus::Accepted);
			assert_eq!(requests[0].swap_req_hash, route_request.hash());
			let persisted_request = {
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				w.mwixnet_requests()?
					.into_iter()
					.find(|request| request.request.wallet_request_id == wallet_request_id)
					.unwrap()
					.request
			};
			assert_eq!(
				serde_json::to_vec(&persisted_request).unwrap(),
				serde_json::to_vec(&route_request).unwrap()
			);
			{
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				libwallet::api_impl::owner::update_mwixnet_recovery(w, m, bh)?;
				let request = w
					.mwixnet_requests()?
					.into_iter()
					.find(|request| request.request.wallet_request_id == wallet_request_id)
					.unwrap();
				assert_eq!(request.status, WalletMwixnetRequestStatus::Accepted);
				assert!(request.reclaim_tx.is_none());
			}

			// One unreclaimable request must not abort recovery for the wallet.
			let unreclaimable_request_id = libwallet::mwixnet_protocol::Hash([6; 32]);
			{
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				let mut request = route_request.clone();
				request.wallet_request_id = unreclaimable_request_id;
				request.expires_at_height = bh;
				let input_blind = w.keychain(m)?.derive_key(
					last_output.output.value,
					&last_output.output.key_id,
					SwitchCommitmentType::Regular,
				)?;
				request.comsig = ComSignature::sign(
					last_output.output.value,
					&input_blind,
					&request.hash().0.to_vec(),
					false,
				)
				.map_err(|e| libwallet::Error::Signature(e.to_string()))?;
				let mut batch = w.batch_no_mask()?;
				batch.save_mwixnet_request(&WalletMwixnetRequest {
					request,
					tx_id: Some(creation_tx_id),
					input_commitment: last_output.commit.to_hex(),
					swap_onion_address: libwallet::mwixnet_protocol::OnionAddress([9; 32]),
					status: WalletMwixnetRequestStatus::Expired,
					reclaim_max_fee: 0,
					confirmation_depth: 10,
					kernel_excess: None,
					cancel_request: None,
					cancel_ack: None,
					reclaim_tx: None,
					reclaim_tx_id: None,
					conflict_observed_height: None,
				})?;
				batch.commit()?;
				libwallet::api_impl::owner::update_mwixnet_recovery(w, m, bh)?;
				let request = w
					.mwixnet_requests()?
					.into_iter()
					.find(|request| request.request.wallet_request_id == unreclaimable_request_id)
					.unwrap();
				assert!(request.reclaim_tx.is_none());
			}
			let outputs = api.retrieve_outputs(mask1, false, false, None)?;
			assert_eq!(
				outputs
					.1
					.iter()
					.find(|output| output.commit == last_output.commit)
					.unwrap()
					.output
					.status,
				OutputStatus::Locked
			);

			// Repeating cancel after a timeout returns the persisted request unchanged.
			let first_cancel = {
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				libwallet::api_impl::owner::create_mwixnet_cancel_req(
					w,
					m,
					wallet_request_id,
					false,
				)?
			};
			let second_cancel = {
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				libwallet::api_impl::owner::create_mwixnet_cancel_req(
					w,
					m,
					wallet_request_id,
					false,
				)?
			};
			assert_eq!(
				serde_json::to_vec(&first_cancel).unwrap(),
				serde_json::to_vec(&second_cancel).unwrap()
			);

			for status in [
				WalletMwixnetRequestStatus::Batched,
				WalletMwixnetRequestStatus::Posted,
			] {
				{
					let mut wallet_lock = api.wallet_inst.lock();
					let w = wallet_lock.lc_provider()?.wallet_inst()?;
					let mut request = w
						.mwixnet_requests()?
						.into_iter()
						.find(|request| request.request.wallet_request_id == wallet_request_id)
						.unwrap();
					request.status = status;
					request.cancel_request = None;
					let mut batch = w.batch_no_mask()?;
					batch.save_mwixnet_request(&request)?;
					batch.commit()?;
				}
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				assert!(libwallet::api_impl::owner::create_mwixnet_cancel_req(
					w,
					m,
					wallet_request_id,
					false,
				)
				.is_err());
			}

			assert!(api
				.create_mwixnet_req(m, &params, &last_output.commit, false)
				.is_err());

			Ok(())
		},
	)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn mwixnet_comsig_test() {
	let test_dir = "test_output/mwixnet";
	setup(test_dir);
	if let Err(e) = mwixnet_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
