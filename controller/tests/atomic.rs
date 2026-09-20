// Copyright 2021 The Grin Developers
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

//! Test wallets performing an atomic swap
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use easy_jsonrpc_mw::Handler;
use grin_core as core;
use grin_keychain::{Keychain, SwitchCommitmentType};
use grin_wallet_libwallet as libwallet;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, Slate, SlateState, TxFlow};
use std::path::PathBuf;
use std::{sync::atomic::Ordering, thread, time::Duration};

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn rpc<T: serde::de::DeserializeOwned>(
	api: &(dyn grin_wallet_api::OwnerRpc + 'static),
	mask: Option<&grin_util::secp::SecretKey>,
	method: &str,
	mut params: serde_json::Value,
) -> Result<T, libwallet::Error> {
	params["token"] = serde_json::to_value(grin_wallet_api::Token {
		keychain_mask: mask.cloned(),
	})
	.unwrap();
	let response = api
		.handle_request(serde_json::json!({
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params
		}))
		.as_option()
		.expect("RPC response");
	assert!(response.get("error").is_none(), "{response}");
	assert!(response["result"].get("Err").is_none(), "{response}");
	serde_json::from_value(response["result"]["Ok"].clone())
		.map_err(|e| libwallet::Error::GenericError(e.to_string()))
}

fn foreign(
	api: &(dyn grin_wallet_api::ForeignRpc + 'static),
	method: &str,
	params: serde_json::Value,
) -> Slate {
	let response = api
		.handle_request(serde_json::json!({
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params
		}))
		.as_option()
		.unwrap();
	assert!(response.get("error").is_none(), "{response}");
	assert!(response["result"].get("Err").is_none(), "{response}");
	let wire: libwallet::VersionedSlate =
		serde_json::from_value(response["result"]["Ok"].clone()).unwrap();
	Slate::from(wire)
}

fn swap(
	api: &(dyn grin_wallet_api::OwnerRpc + 'static),
	mask: Option<&grin_util::secp::SecretKey>,
	request: grin_wallet_api::swap::Request,
) -> Result<grin_wallet_api::swap::Reply, libwallet::Error> {
	rpc(api, mask, "swap", serde_json::json!({"request": request}))
}

/// atomic swap impl
fn atomic_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

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
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

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
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			Ok(())
		},
	)?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 1 inititates the main atomic swap transaction
			let args = InitTxArgs {
				amount: 5012500000,
				is_multisig: Some(true),
				..Default::default()
			};
			slate = api.init_send_tx(m, args)?;
			api.tx_lock_outputs(m, &slate)?;
			let (_, outputs) = api.retrieve_outputs(m, false, false, None)?;
			let change = outputs
				.iter()
				.filter(|o| o.output.status == libwallet::OutputStatus::Unconfirmed)
				.collect::<Vec<_>>();
			assert!(!change.is_empty());
			assert!(change.iter().all(|o| !o.output.is_multisig));
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig1);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_tx(&slate, None, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig2);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.process_multisig_tx(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig3);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.finalize_tx(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 1 inititates the main atomic swap transaction
			let args = InitTxArgs {
				amount: 5000000000,
				minimum_confirmations: 0,
				multisig_path: Some(slate.create_multisig_id().to_bip_32_string()),
				..Default::default()
			};
			slate = api.init_atomic_swap(m, args)?;
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_atomic_tx(&slate, None, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic2);

	// Get the receiver's atomic secret created in `receive_atomic_tx`
	// This is one of the keys locking the multisig transaction on the other chain
	// Only revealed if the refund transaction is fully signed + posted
	let atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		let secret = w.get_atomic_secret(mask2, &atomic_id)?;
		assert_ne!(
			secret,
			w.keychain(mask2)?.derive_key(
				slate.amount,
				&atomic_id,
				SwitchCommitmentType::Regular
			)?
		);
		secret
	};

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// wallet 1 creates the first partial signature on the atomic swap
			slate = api.countersign_atomic_swap(&slate, m, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(w, mask1, &slate, &tx.kernels()[0])?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

/// atomic swap refund impl
fn atomic_refund_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

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
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

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
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			Ok(())
		},
	)?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 1 inititates the main atomic swap transaction
			let args = InitTxArgs {
				amount: 5012500000,
				is_multisig: Some(true),
				..Default::default()
			};
			slate = api.init_send_tx(m, args)?;
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig1);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_tx(&slate, None, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig2);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.process_multisig_tx(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig3);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.finalize_tx(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);

	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	wallet::controller::owner_single_use(
		wallet2.clone(),
		mask2.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 2 inititates the refund atomic swap transaction
			let args = InitTxArgs {
				amount: 5000000000,
				late_lock: Some(true),
				minimum_confirmations: 0,
				multisig_path: Some(slate.create_multisig_id().to_bip_32_string()),
				..Default::default()
			};
			slate = api.init_atomic_swap(m, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(
		wallet1.clone(),
		PathBuf::from(test_dir),
		mask1_i.clone(),
		|api| {
			api.doctest_mode = true;
			slate = api.receive_atomic_tx(&slate, None, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic2);

	// Get the sender's atomic secret created in `receive_atomic_tx`
	// This is one of the keys locking the multisig transaction on the other chain
	// Only revealed if the refund transaction is fully signed + posted
	let atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		w.get_atomic_secret(mask1, &atomic_id)?
	};

	wallet::controller::owner_single_use(
		wallet2.clone(),
		mask2.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// wallet 1 creates the first partial signature on the atomic swap
			slate = api.countersign_atomic_swap(&slate, m, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			api.tx_lock_outputs(m, &slate)?;
			let wire: libwallet::VersionedSlate = rpc(
				api,
				m,
				"finalize_atomic_swap",
				serde_json::json!({"slate": slate}),
			)?;
			slate = Slate::from(wire);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic4);
	let restored = Slate::deserialize_upgrade(&serde_json::to_string(&slate).unwrap()).unwrap();
	assert_eq!(
		slate.tx_or_err()?.kernels(),
		restored.tx_or_err()?.kernels()
	);
	restored.tx_or_err()?.kernels()[0].verify().unwrap();

	let rec_atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(w, mask2, &slate, &tx.kernels()[0])?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

/// atomic swap end-to-end impl
fn atomic_end_to_end_tx_impl(
	test_dir: &'static str,
	cross_chain: Option<bool>,
) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

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
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

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
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			Ok(())
		},
	)?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 1 inititates the main atomic swap transaction
			let args = InitTxArgs {
				amount: 5012500000,
				is_multisig: Some(true),
				..Default::default()
			};
			slate = Slate::from(rpc::<libwallet::VersionedSlate>(
				api,
				m,
				"init_send_tx",
				serde_json::json!({"args": args}),
			)?);
			rpc::<()>(
				api,
				m,
				"tx_lock_outputs",
				serde_json::json!({"slate": slate}),
			)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig1);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = foreign(
				api,
				"receive_tx",
				serde_json::json!({"slate": slate, "dest_acct_name": null, "dest": null}),
			);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig2);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = Slate::from(rpc::<libwallet::VersionedSlate>(
				api,
				m,
				"process_multisig_tx",
				serde_json::json!({"slate": slate}),
			)?);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig3);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = foreign(api, "presign_tx", serde_json::json!({"slate": slate}));
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			slate = Slate::from(rpc::<libwallet::VersionedSlate>(
				api,
				m,
				"finalize_tx",
				serde_json::json!({"slate": slate}),
			)?);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Multisig4);
	assert!(slate
		.tx_or_err()?
		.outputs()
		.iter()
		.all(|output| output.features() == core::core::OutputFeatures::Plain));
	let funding = slate.clone();

	let multisig_path = slate.create_multisig_id().to_bip_32_string();
	wallet::controller::owner_single_use(
		wallet2.clone(),
		mask2.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 2 inititates the refund atomic swap transaction
			let args = InitTxArgs {
				amount: 5000000000,
				late_lock: Some(true),
				refund_height: Some(bh + 30),
				multisig_path: Some(multisig_path.clone()),
				..Default::default()
			};
			slate = Slate::from(rpc::<libwallet::VersionedSlate>(
				api,
				m,
				"init_atomic_swap",
				serde_json::json!({"args": args}),
			)?);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(
		wallet1.clone(),
		PathBuf::from(test_dir),
		mask1_i.clone(),
		|api| {
			api.doctest_mode = false;
			slate = foreign(
				api,
				"receive_atomic_tx",
				serde_json::json!({"slate": slate, "dest_acct_name": null, "dest": null}),
			);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic2);

	wallet::controller::owner_single_use(
		wallet2.clone(),
		mask2.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// wallet 1 creates the first partial signature on the atomic swap
			slate = Slate::from(rpc::<libwallet::VersionedSlate>(
				api,
				m,
				"countersign_atomic_swap",
				serde_json::json!({"slate": slate, "r_addr": null}),
			)?);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic3);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let wire: libwallet::VersionedSlate = rpc(
				api,
				m,
				"finalize_atomic_swap",
				serde_json::json!({"slate": slate}),
			)?;
			slate = Slate::from(wire);
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic4);
	assert_eq!(
		slate.kernel_features_args.as_ref().unwrap().lock_height,
		bh + 30
	);
	slate.tx_or_err()?.kernels()[0].verify()?;
	assert_eq!(chain.head().unwrap().height, bh);
	if let Some(abort) = cross_chain {
		use grin_wallet_api::{swap::Request, Owner};
		use grin_wallet_config::types::BitcoinConfig;
		use grin_wallet_config::{GlobalWalletConfig, GlobalWalletConfigMembers, WalletConfig};
		use libwallet::swap::{Action, Deadline, Policy, Role};
		let rpc = std::env::var("GRIN_SWAP_RPC").expect("isolated regtest RPC URL");
		let cookie = PathBuf::from(std::env::var("GRIN_SWAP_COOKIE").unwrap());
		let bitcoin = impls::swap::adapters::bitcoin::Core::new(
			&rpc,
			cookie.clone(),
			impls::swap::adapters::bitcoin::types::Network::Regtest,
		)?;
		let mine = |blocks: u64| {
			let output = std::process::Command::new(std::env::var("GRIN_SWAP_CLI").unwrap())
				.arg(format!(
					"-datadir={}",
					std::env::var("GRIN_SWAP_DATADIR").unwrap()
				))
				.arg("-regtest")
				.arg(format!(
					"-rpcport={}",
					std::env::var("GRIN_SWAP_PORT").unwrap()
				))
				.args(["-rpcwallet=swap", "-generate", &blocks.to_string()])
				.output()
				.unwrap();
			assert!(
				output.status.success(),
				"{}",
				String::from_utf8_lossy(&output.stderr)
			);
		};
		let path = PathBuf::from(test_dir).join("swap.toml");
		let mut config = GlobalWalletConfig {
			config_file_path: path.clone(),
			members: GlobalWalletConfigMembers {
				config_file_version: Some(2),
				wallet: WalletConfig {
					bitcoin: Some(BitcoinConfig {
						url: rpc,
						cookie,
						network: "regtest".into(),
					}),
					..Default::default()
				},
				tor: None,
				logging: None,
			},
		};
		std::fs::write(&path, config.ser_config()?).unwrap();
		let a = Owner::new(wallet1.clone(), None, path.clone());
		let b = Owner::new(wallet2.clone(), None, path.clone());
		let policy = Policy {
			grin: Deadline {
				refund: bh + 30,
				confirmations: 1,
				claim_blocks: 5,
				block_seconds: 60,
			},
			other: Deadline {
				refund: bitcoin.height()? + 12,
				confirmations: 2,
				claim_blocks: 2,
				block_seconds: 600,
			},
		};
		let start = |role| Request::Start {
			role,
			policy,
			amount: 100_000,
			fee_rate: 2,
			fee: 1000,
			max_fee: 5000,
		};
		let a_info = swap(&a, mask1, start(Role::SellGrin))?;
		let b_info = swap(&b, mask2, start(Role::BuyGrin))?;
		let mut main = a.init_atomic_swap(
			mask1,
			InitTxArgs {
				amount: 5_000_000_000,
				minimum_confirmations: 0,
				multisig_path: Some(multisig_path),
				..Default::default()
			},
		)?;
		a.tx_lock_outputs(mask1, &main)?;
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			path.clone(),
			mask2_i.clone(),
			|api| {
				let request = main.clone();
				let receive = || {
					foreign(
						api,
						"receive_atomic_tx",
						serde_json::json!({
							"slate": request, "dest_acct_name": null, "dest": null
						}),
					)
				};
				main = receive();
				let replay = receive();
				assert_eq!(
					serde_json::to_string(&main).unwrap(),
					serde_json::to_string(&replay).unwrap()
				);
				let mut changed = request;
				changed.amount += 1;
				assert!(api.receive_atomic_tx(&changed, None, None).is_err());
				Ok(())
			},
		)?;
		let prepare = |id, peer_key| Request::Prepare {
			id,
			peer_key,
			funding: serde_json::to_string(&funding).unwrap(),
			refund: serde_json::to_string(&slate).unwrap(),
			main: serde_json::to_string(&main).unwrap(),
		};
		let a_prepare = prepare(a_info.id, b_info.key.clone());
		swap(&a, mask1, a_prepare.clone())?;
		swap(&a, mask1, a_prepare)?;
		let duplicate = swap(&a, mask1, start(Role::SellGrin))?;
		assert!(a
			.swap(mask1, prepare(duplicate.id, b_info.key.clone()))
			.is_err());
		swap(&b, mask2, prepare(b_info.id, a_info.key.clone()))?;
		assert_eq!(
			swap(&b, mask2, Request::Step { id: b_info.id })?.action,
			Action::Wait
		);
		assert_eq!(
			swap(&a, mask1, Request::Step { id: a_info.id })?.action,
			Action::FundGrin
		);
		assert_eq!(
			swap(&a, mask1, Request::Step { id: a_info.id })?.action,
			Action::Wait
		);
		let btc_funding = swap(&b, mask2, Request::Step { id: b_info.id })?;
		assert_eq!(btc_funding.action, Action::FundOther);
		swap(
			&a,
			mask1,
			Request::Receive {
				id: a_info.id,
				funding: btc_funding.funding,
				main: None,
			},
		)?;
		assert_eq!(
			swap(&a, mask1, Request::Step { id: a_info.id })?.action,
			Action::Wait
		);
		mine(1);
		assert_eq!(
			swap(&a, mask1, Request::Step { id: a_info.id })?.action,
			Action::Wait
		);
		mine(1);
		if abort {
			let blocks = policy.grin.refund - chain.head().unwrap().height;
			test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				mask1,
				blocks as usize,
				false,
			)?;
			assert_eq!(
				swap(&a, mask1, Request::Step { id: a_info.id })?.action,
				Action::RefundGrin
			);
			assert_eq!(
				swap(&a, mask1, Request::Step { id: a_info.id })?.action,
				Action::Refunded
			);
			mine(policy.other.refund - bitcoin.height()?);
			assert_eq!(
				swap(&b, mask2, Request::Step { id: b_info.id })?.action,
				Action::RefundOther
			);
			mine(2);
			assert_eq!(
				swap(&b, mask2, Request::Step { id: b_info.id })?.action,
				Action::Refunded
			);
		} else {
			let released = swap(&a, mask1, Request::Step { id: a_info.id })?;
			assert_eq!(released.action, Action::Release);
			let resumed = Owner::new(wallet1.clone(), None, path.clone());
			assert_eq!(
				swap(&resumed, mask1, Request::Status { id: a_info.id })?.main,
				released.main
			);
			swap(
				&b,
				mask2,
				Request::Receive {
					id: b_info.id,
					funding: None,
					main: released.main,
				},
			)?;
			assert_eq!(
				swap(&b, mask2, Request::Step { id: b_info.id })?.action,
				Action::ClaimGrin
			);
			assert_eq!(
				swap(&b, mask2, Request::Step { id: b_info.id })?.action,
				Action::Complete
			);
			assert_eq!(
				swap(&resumed, mask1, Request::Step { id: a_info.id })?.action,
				Action::ClaimOther
			);
			mine(2);
			assert_eq!(
				swap(&resumed, mask1, Request::Step { id: a_info.id })?.action,
				Action::Complete
			);
		}
		let cancelled = if abort { main.id } else { slate.id };
		for (index, (api, mask)) in [(&a, mask1), (&b, mask2)].into_iter().enumerate() {
			let (_, entries) = api.retrieve_txs(mask, false, None, Some(cancelled), None)?;
			// A refund initiator may not have a transaction log entry yet
			if abort || index == 0 {
				assert_eq!(entries.len(), 1, "wallet {index}");
			}
			assert!(entries.iter().all(|entry| matches!(
				entry.tx_type,
				libwallet::TxLogEntryType::TxSentCancelled
					| libwallet::TxLogEntryType::TxReceivedCancelled
			)));
		}
		let terminal = if abort {
			Action::Refunded
		} else {
			Action::Complete
		};
		assert_eq!(
			swap(&a, mask1, Request::Step { id: a_info.id })?.action,
			terminal
		);
		assert_eq!(
			swap(&b, mask2, Request::Step { id: b_info.id })?.action,
			terminal
		);
		stopper.store(false, Ordering::Relaxed);
		thread::sleep(Duration::from_millis(200));
		return Ok(());
	}

	// Funding is released only after the refund is complete
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			api.post_tx(m, &funding, false)?;
			Ok(())
		},
	)?;
	wallet::controller::owner_single_use(
		wallet2.clone(),
		mask2,
		PathBuf::from(test_dir),
		|api, m| {
			let (refreshed, outputs) = api.retrieve_outputs(m, false, true, None)?;
			assert!(refreshed);
			let shared = outputs.iter().find(|o| o.output.is_multisig).unwrap();
			let commit = shared.commit;
			assert_eq!(shared.output.status, libwallet::OutputStatus::Unspent);
			api.scan(m, Some(1), false)?;
			let (_, outputs) = api.retrieve_outputs(m, false, false, None)?;
			assert!(outputs
				.iter()
				.any(|o| o.commit == commit && o.output.is_multisig));
			// This wallet only owns a shared output, which requires cooperation
			let result = api.init_send_tx(
				m,
				InitTxArgs {
					amount: 1_000_000,
					minimum_confirmations: 1,
					..Default::default()
				},
			);
			assert!(matches!(
				result,
				Err(libwallet::Error::NotEnoughFunds { .. })
			));
			Ok(())
		},
	)?;

	test_framework::award_blocks_to_wallet(&chain, wallet2.clone(), mask2, 10, false)?;

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			// Wallet 1 inititates the main atomic swap transaction
			let args = InitTxArgs {
				amount: 500000000,
				minimum_confirmations: 0,
				multisig_path: Some(multisig_path),
				..Default::default()
			};
			slate = api.init_atomic_swap(m, args)?;
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_atomic_tx(&slate, None, None)?;
			Ok(())
		},
	)?;

	// Create atomic secret, this is created during the refund transaction
	// This is one of the keys locking the multisig transaction on the other chain
	let atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		w.get_atomic_secret(mask2, &atomic_id)?
	};

	assert_eq!(slate.state, SlateState::Atomic2);

	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1.clone(),
		PathBuf::from(test_dir),
		|api, m| {
			// wallet 1 creates the first partial signature on the atomic swap
			slate = api.countersign_atomic_swap(&slate, m, None)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(w, mask1, &slate, &tx.kernels()[0])?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			api.post_tx(m, &slate, false)?;
			api.recover_atomic_secret(m, &slate)?;
			api.recover_atomic_secret(m, &slate)?;
			Ok(())
		},
	)?;
	{
		wallet_inst!(wallet1, w);
		let id = w.get_used_atomic_id(&slate.id)?;
		assert_eq!(w.get_recovered_atomic_secret(mask1, &id)?, atomic_secret);
		assert!(w.get_private_context(mask1, slate.id.as_bytes()).is_err());
	}

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_atomic_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_tx";
	setup(test_dir);
	atomic_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_atomic_refund_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_refund_tx";
	setup(test_dir);
	atomic_refund_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_atomic_end_to_end_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_end_to_end_tx";
	setup(test_dir);
	atomic_end_to_end_tx_impl(test_dir, None)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
#[ignore = "requires an isolated funded Bitcoin regtest wallet and GRIN_SWAP_* settings"]
fn swap_claim() -> Result<(), libwallet::Error> {
	let dir = "test_output/cross_chain_claim";
	setup(dir);
	atomic_end_to_end_tx_impl(dir, Some(false))?;
	clean_output_dir(dir);
	Ok(())
}

#[test]
#[ignore = "requires an isolated funded Bitcoin regtest wallet and GRIN_SWAP_* settings"]
fn swap_refund() -> Result<(), libwallet::Error> {
	let dir = "test_output/cross_chain_refund";
	setup(dir);
	atomic_end_to_end_tx_impl(dir, Some(true))?;
	clean_output_dir(dir);
	Ok(())
}
