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

//! Exercise the SAS graph with two wallets and Bitcoin Core regtest

extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_core as core;
use grin_keychain::Keychain;
use grin_util::secp::SecretKey;
use grin_wallet_api::{
	swap::{
		self,
		sas::{Offer, Request},
	},
	Foreign, ForeignRpc, Owner, OwnerRpc,
};
use grin_wallet_config::{
	types::BitcoinConfig, GlobalWalletConfig, GlobalWalletConfigMembers, WalletConfig,
};
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{
	swap::{sas::Terms, Action, Role},
	InitTxArgs, NodeClient, Slate, VersionedSlate,
};
use std::{path::PathBuf, sync::atomic::Ordering, thread};

#[macro_use]
mod common;
#[path = "common/swap.rs"]
mod wire;
use wire::{foreign, rpc};
#[path = "common/graph.rs"]
mod graph;

fn slate(
	api: &(dyn OwnerRpc + 'static),
	mask: Option<&SecretKey>,
	method: &str,
	params: serde_json::Value,
) -> Result<Slate, libwallet::Error> {
	Ok(Slate::from(rpc::<VersionedSlate>(
		api, mask, method, params,
	)?))
}
fn multisig(
	a: &(dyn OwnerRpc + 'static),
	mask: Option<&SecretKey>,
	b: &(dyn OwnerRpc + 'static),
	bm: Option<&SecretKey>,
	fb: &(dyn ForeignRpc + 'static),
	args: InitTxArgs,
) -> Result<(Slate, Slate), libwallet::Error> {
	let start = slate(a, mask, "init_send_tx", serde_json::json!({"args":args}))?;
	rpc::<()>(
		a,
		mask,
		"tx_lock_outputs",
		serde_json::json!({"slate":start}),
	)?;
	let received = foreign(
		fb,
		"receive_tx",
		serde_json::json!({"slate":start,"dest_acct_name":null,"dest":null}),
	);
	let processed = slate(
		a,
		mask,
		"process_multisig_tx",
		serde_json::json!({"slate":received}),
	)?;
	let partial = slate(b, bm, "presign_tx", serde_json::json!({"slate":processed}))?;
	let full = slate(a, mask, "finalize_tx", serde_json::json!({"slate":partial}))?;
	Ok((full, partial))
}
fn atomic(
	a: &(dyn OwnerRpc + 'static),
	mask: Option<&SecretKey>,
	b: &(dyn ForeignRpc + 'static),
	args: InitTxArgs,
) -> Result<Slate, libwallet::Error> {
	let start = slate(
		a,
		mask,
		"init_atomic_swap",
		serde_json::json!({"args":args}),
	)?;
	let received = foreign(
		b,
		"receive_atomic_tx",
		serde_json::json!({"slate":start,"dest_acct_name":null,"dest":null}),
	);
	slate(
		a,
		mask,
		"countersign_atomic_swap",
		serde_json::json!({"slate":received,"r_addr":null}),
	)
}
fn sas(
	api: &(dyn OwnerRpc + 'static),
	mask: Option<&SecretKey>,
	request: Request,
) -> Result<swap::Reply, libwallet::Error> {
	wire::swap(api, mask, swap::Request::Sas { request })
}
use common::bitcoin;

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
	Claim,
	Refund,
	Timeout,
}

#[derive(Clone, Copy, PartialEq)]
enum Funding {
	Core,
	External,
	Grouped,
	Duplicate,
	Replaced,
}

fn run(dir: &'static str, outcome: Outcome, funding: Funding) -> Result<(), libwallet::Error> {
	let negotiated = matches!(
		funding,
		Funding::Grouped | Funding::Duplicate | Funding::Replaced
	);
	let external = funding != Funding::Core;
	common::clean_output_dir(dir);
	common::setup(dir);
	let mut proxy = common::create_wallet_proxy(dir);
	let chain = proxy.chain.clone();
	let running = proxy.running.clone();
	create_wallet_and_add!(client1, wallet1, mask1, dir, "wallet1", None, &mut proxy, true);
	create_wallet_and_add!(client2, wallet2, mask2, dir, "wallet2", None, &mut proxy, true);
	let worker = thread::spawn(move || proxy.run().unwrap());
	let am = mask1.as_ref();
	let bm = mask2.as_ref();
	test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), am, 10, false)?;
	let path = PathBuf::from(dir).join("swap.toml");
	let mut config = GlobalWalletConfig {
		config_file_path: path.clone(),
		members: GlobalWalletConfigMembers {
			config_file_version: Some(2),
			wallet: WalletConfig {
				bitcoin: Some(BitcoinConfig {
					proxy: None,
					url: std::env::var("GRIN_SWAP_RPC").unwrap(),
					cookie: std::env::var("GRIN_SWAP_COOKIE").unwrap().into(),
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
	let mut offline = config.members.wallet.bitcoin.clone().unwrap();
	offline.url = "http://127.0.0.1:1".into();
	offline.cookie = PathBuf::from(dir).join("missing.cookie");
	let offline_a =
		Owner::new(wallet1.clone(), None, path.clone()).with_bitcoin_config(offline.clone());
	let offline_b = Owner::new(wallet2.clone(), None, path.clone()).with_bitcoin_config(offline);
	let fa = Foreign::new(wallet1.clone(), path.clone(), mask1.clone(), None, false);
	let fb = Foreign::new(wallet2.clone(), path.clone(), mask2.clone(), None, false);
	a.retrieve_summary_info(am, true, 1)?;
	let terms = Terms {
		revoke: 40,
		refund: 64,
		timeout: 88,
		confirmations: 2,
		bitcoin_confirmations: 2,
		margin: 12,
	};
	let fee = core::libtx::tx_fee(1, 1, 1);
	let value = 5_012_500_000;
	let (id, revoke, refund, timeout, destination) = if negotiated {
		let address = bitcoin(&["getnewaddress"]).as_str().unwrap().to_owned();
		let result = graph::prepare(&a, am, &fa, &b, bm, &fb, value, fee, terms, &address)?;
		(result.0, result.1, result.2, result.3, Some(address))
	} else {
		let (fund, partial) = multisig(
			&a,
			am,
			&b,
			bm,
			&fb,
			InitTxArgs {
				amount: value,
				is_multisig: Some(true),
				..Default::default()
			},
		)?;
		assert!(partial
			.tx_or_err()?
			.validate(core::core::transaction::Weighting::AsTransaction)
			.is_err());
		let id = fund.id;
		let main_start = a.init_atomic_swap(
			am,
			InitTxArgs {
				amount: value - fee,
				minimum_confirmations: 0,
				multisig_path: Some(fund.create_multisig_id().to_bip_32_string()),
				..Default::default()
			},
		)?;
		let (revoke, _) = multisig(
			&a,
			am,
			&b,
			bm,
			&fb,
			InitTxArgs {
				amount: value - fee,
				minimum_confirmations: 0,
				is_multisig: Some(true),
				multisig_path: Some(fund.create_multisig_id().to_bip_32_string()),
				refund_height: Some(terms.revoke),
				..Default::default()
			},
		)?;
		let refund = atomic(
			&b,
			bm,
			&fa,
			InitTxArgs {
				amount: value - 2 * fee,
				minimum_confirmations: 0,
				multisig_path: Some(revoke.create_multisig_id().to_bip_32_string()),
				late_lock: Some(true),
				refund_height: Some(terms.refund),
				..Default::default()
			},
		)?;
		let timeout = atomic(
			&a,
			am,
			&fb,
			InitTxArgs {
				amount: value - 2 * fee,
				minimum_confirmations: 0,
				multisig_path: Some(revoke.create_multisig_id().to_bip_32_string()),
				late_lock: Some(true),
				refund_height: Some(terms.timeout),
				..Default::default()
			},
		)?;
		let timeout = b.finalize_atomic_swap(bm, &timeout)?;
		a.tx_lock_outputs(am, &main_start)?;
		let success = foreign(
			&fb,
			"receive_atomic_tx",
			serde_json::json!({"slate":main_start,"dest_acct_name":null,"dest":null}),
		);
		let encode = |slate: &Slate| serde_json::to_string(slate).unwrap();
		let offer = Offer {
			terms,
			amount: 100_000,
			fee_rate: 2,
			max_fee: 5000,
			funding: encode(&fund),
			revoke: encode(&revoke),
			refund: encode(&refund),
			timeout: encode(&timeout),
			success: encode(&success),
		};
		let mut changed = offer.clone();
		changed.terms.refund += 1;
		assert!(a
			.sas(
				am,
				Request::Offer {
					role: Role::SellGrin,
					offer: changed
				}
			)
			.is_err());
		let ai = sas(
			&a,
			am,
			Request::Offer {
				role: Role::SellGrin,
				offer: offer.clone(),
			},
		)?;
		let mut buyer = offer;
		buyer.funding = encode(&partial);
		let bi = sas(
			&b,
			bm,
			Request::Offer {
				role: Role::BuyGrin,
				offer: buyer,
			},
		)?;
		assert!(a
			.sas(
				am,
				Request::Prepare {
					id,
					proof: ai.proof.clone().unwrap()
				}
			)
			.is_err());
		assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::Wait);
		let destination = if external {
			let address = bitcoin(&["getnewaddress"]).as_str().unwrap().to_owned();
			for (owner, mask) in [(&a, am), (&b, bm)] {
				let reply = sas(
					owner,
					mask,
					Request::External {
						id,
						address: address.clone(),
					},
				)?;
				assert!(reply.payment.is_none());
			}
			Some(address)
		} else {
			None
		};
		sas(
			&a,
			am,
			Request::Prepare {
				id,
				proof: bi.proof.unwrap(),
			},
		)?;
		sas(
			&b,
			bm,
			Request::Prepare {
				id,
				proof: ai.proof.unwrap(),
			},
		)?;

		(id, revoke, refund, timeout, destination)
	};
	assert_eq!(chain.head().unwrap().height, 10);
	assert!(offline_a.sas(am, Request::Step { id }).is_err());
	for (owner, mask) in [(&a, am), (&b, bm)] {
		assert!(owner.sas(mask, Request::WithdrawAuto { id }).is_err());
	}
	assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::FundGrin);
	assert_eq!(sas(&b, bm, Request::Step { id })?.action, Action::Wait);
	test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), am, 1, false)?;
	let funded = sas(&b, bm, Request::Step { id })?;
	assert_eq!(funded.action, Action::FundOther);
	if external {
		assert!(funded.funding.is_none());
		let payment = funded.payment.as_ref().unwrap();
		assert_eq!(payment.amount, 100_000);
		assert_eq!(payment.network, "regtest");
		bitcoin(&[
			"-named",
			"sendtoaddress",
			&format!("address={}", payment.address),
			"amount=0.001",
			"fee_rate=2",
		]);
		if !negotiated {
			// Reopen the owner API before discovering the external payment
			let reopened = Owner::new(wallet2.clone(), None, path.clone());
			let mut seen = false;
			for _ in 0..50 {
				if sas(&reopened, bm, Request::Step { id })?.funding.is_some() {
					seen = true;
					break;
				}
				thread::sleep(std::time::Duration::from_millis(100));
			}
			assert!(seen);
		}

		assert!(a
			.sas(
				am,
				Request::External {
					id,
					address: bitcoin(&["getnewaddress"]).as_str().unwrap().to_owned()
				}
			)
			.is_err());
	}
	sas(
		&a,
		am,
		Request::Receive {
			id,
			funding: funded.funding.clone(),
			success: None,
		},
	)?;
	assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::Wait);
	let mut duplicates = Vec::new();
	if matches!(funding, Funding::Duplicate | Funding::Replaced) {
		let original = sas(&a, am, Request::Status { id })?.funding.unwrap();
		if funding == Funding::Replaced {
			assert_eq!(
				sas(&b, bm, Request::Step { id })?.funding,
				Some(original.clone())
			);
		}
		let original_id = bitcoin(&["decoderawtransaction", &original])["txid"]
			.as_str()
			.unwrap()
			.to_owned();
		let replacement_id = bitcoin(&["bumpfee", &original_id, r#"{"fee_rate":4}"#])["txid"]
			.as_str()
			.unwrap()
			.to_owned();
		let replacement = bitcoin(&["gettransaction", &replacement_id])["hex"]
			.as_str()
			.unwrap()
			.to_owned();
		// An RBF replacement paying the same address must not silently rebind
		// the seller, even before signature release. Recovery remains available.
		assert_eq!(
			sas(&a, am, Request::Step { id })?.funding,
			Some(original.clone())
		);
		assert!(a
			.sas(
				am,
				Request::Receive {
					id,
					funding: Some(replacement.clone()),
					success: None
				}
			)
			.is_err());
		let address = &funded.payment.as_ref().unwrap().address;
		let txid = bitcoin(&["sendtoaddress", address, "0.001"]);
		let extra = bitcoin(&["gettransaction", txid.as_str().unwrap()])["hex"]
			.as_str()
			.unwrap()
			.to_owned();
		assert_eq!(
			sas(&a, am, Request::Step { id })?.funding,
			Some(original.clone())
		);
		if funding == Funding::Duplicate {
			assert!(b.sas(bm, Request::Step { id }).is_err());
		} else {
			assert_eq!(sas(&b, bm, Request::Step { id })?.funding, Some(original));
		}
		duplicates = vec![replacement, extra];
	}
	bitcoin(&["-generate", "2"]);
	if outcome == Outcome::Claim {
		let tip = bitcoin(&["getbestblockhash"]);
		bitcoin(&["invalidateblock", tip.as_str().unwrap()]);
		let waiting = sas(&a, am, Request::Step { id })?;
		assert_eq!(waiting.action, Action::Wait);
		assert!(waiting.main.is_none());
		bitcoin(&["reconsiderblock", tip.as_str().unwrap()]);
	}
	match outcome {
		Outcome::Claim => {
			assert!(offline_a.sas(am, Request::Step { id }).is_err());
			assert!(sas(&a, am, Request::Status { id })?.main.is_none());
			let released = sas(&a, am, Request::Step { id })?;
			assert_eq!(released.action, Action::Release);
			let original = Slate::deserialize_upgrade(released.main.as_ref().unwrap())?;
			let before = serde_json::to_value(sas(&b, bm, Request::Status { id })?).unwrap();
			for mutation in 0..4 {
				let mut changed = original.clone();
				match mutation {
					0 => changed.id = uuid::Uuid::new_v4(),
					1 => changed.amount += 1,
					2 => changed.participant_data[1] = changed.participant_data[0].clone(),
					_ => changed.kernel_features = 2,
				}
				assert!(b
					.sas(
						bm,
						Request::Receive {
							id,
							funding: None,
							success: Some(serde_json::to_string(&changed).unwrap()),
						}
					)
					.is_err());
				assert_eq!(
					before,
					serde_json::to_value(sas(&b, bm, Request::Status { id })?).unwrap()
				);
			}
			sas(
				&b,
				bm,
				Request::Receive {
					id,
					funding: None,
					success: released.main,
				},
			)?;
			let tip = bitcoin(&["getbestblockhash"]);
			assert!(offline_b.sas(bm, Request::Step { id }).is_err());
			bitcoin(&["invalidateblock", tip.as_str().unwrap()]);
			assert_eq!(sas(&b, bm, Request::Step { id })?.action, Action::Wait);
			bitcoin(&["reconsiderblock", tip.as_str().unwrap()]);
			assert_eq!(sas(&b, bm, Request::Step { id })?.action, Action::ClaimGrin);
			test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), am, 1, false)?;
			assert_eq!(
				sas(&offline_a, am, Request::Step { id })?.action,
				Action::Complete
			);
			assert_eq!(sas(&b, bm, Request::Step { id })?.action, Action::Complete);
			for (owner, mask) in [(&a, am), (&b, bm)] {
				let (_, txs) = owner.retrieve_txs(mask, true, None, None, None)?;
				for slate in [&revoke, &refund, &timeout] {
					assert!(txs
						.iter()
						.filter(|tx| tx.tx_slate_id == Some(slate.id))
						.all(|tx| matches!(
							tx.tx_type,
							libwallet::TxLogEntryType::TxSentCancelled
								| libwallet::TxLogEntryType::TxReceivedCancelled
						)));
				}
			}
			for slate in [&revoke, &refund, &timeout] {
				wallet_inst!(wallet1, w);
				let excess = slate.calc_excess(w.keychain(am)?.secp())?;
				assert!(w.w2n_client().get_kernel(&excess, None, None)?.is_none());
			}
			let new_mask = {
				let mut lock = wallet1.lock();
				let lc = lock.lc_provider()?;
				lc.close_wallet(None)?;
				lc.open_wallet(None, "".into(), true, false)?
			};
			let resumed = Owner::new(wallet1.clone(), None, path.clone());
			let rm = new_mask.as_ref();
			assert_eq!(
				sas(&resumed, rm, Request::Status { id })?.action,
				Action::Complete
			);
			assert!(resumed
				.sas(rm, Request::Withdraw { id, fee: 5001 })
				.is_err());
			let sent = sas(&resumed, rm, Request::Withdraw { id, fee: 1000 })?;
			assert_eq!(
				sent.payout.as_ref().unwrap().status,
				libwallet::swap::TxState::Absent
			);
			let pending = sas(&resumed, rm, Request::WithdrawAuto { id })?;
			assert_eq!(pending.withdrawal, sent.withdrawal);
			assert_eq!(
				pending.payout.as_ref().unwrap().status,
				libwallet::swap::TxState::Pending
			);
			sas(&resumed, rm, Request::Withdraw { id, fee: 2000 })?;
			bitcoin(&["-generate", "2"]);
			let confirmed = sas(&resumed, rm, Request::WithdrawAuto { id })?;
			assert!(confirmed.payout.as_ref().unwrap().status.confirmed(2));
			if let Some(address) = &destination {
				let received = bitcoin(&["getreceivedbyaddress", address, "1", "true"]);
				assert_eq!(received.as_f64(), Some(0.00098));
			}
			assert!(resumed
				.sas(rm, Request::Withdraw { id, fee: 3000 })
				.is_err());
			if negotiated {
				let address = &funded.payment.as_ref().unwrap().address;
				let original = sas(&resumed, rm, Request::Status { id })?.funding;
				let mut extras = Vec::new();
				for amount in ["0.001", "0.00123"] {
					let txid = bitcoin(&["sendtoaddress", address, amount]);
					let raw = bitcoin(&["gettransaction", txid.as_str().unwrap()])["hex"]
						.as_str()
						.unwrap()
						.to_owned();
					let decoded = bitcoin(&["decoderawtransaction", &raw]);
					let vout = decoded["vout"]
						.as_array()
						.unwrap()
						.iter()
						.find(|out| out["scriptPubKey"]["address"] == *address)
						.unwrap()["n"]
						.as_u64()
						.unwrap() as u32;
					extras.push((raw, vout));
				}
				bitcoin(&["-generate", "2"]);
				for (funding, vout) in extras {
					let recover = |fee| Request::Recover {
						id,
						funding: funding.clone(),
						vout,
						fee,
					};
					assert!(b.sas(bm, recover(1000)).is_err());
					assert!(resumed.sas(rm, recover(5001)).is_err());
					let first = sas(&resumed, rm, recover(1000))?;
					// Reload the journal through a new owner instance and retry.
					let reopened = Owner::new(wallet1.clone(), None, path.clone());
					let repeated = sas(&reopened, rm, recover(1000))?;
					assert_eq!(first.withdrawal, repeated.withdrawal);
					assert_eq!(
						repeated.payout.unwrap().status,
						libwallet::swap::TxState::Pending
					);
					assert!(reopened.sas(rm, recover(999)).is_err());
					let bumped = sas(&reopened, rm, recover(2000))?;
					assert_ne!(bumped.withdrawal, first.withdrawal);
					bitcoin(&["-generate", "2"]);
					assert!(sas(&reopened, rm, recover(2000))?
						.payout
						.unwrap()
						.status
						.confirmed(2));
					assert!(reopened.sas(rm, recover(3000)).is_err());
				}
				let unchanged = sas(&resumed, rm, Request::Status { id })?;
				assert_eq!(unchanged.funding, original);
				assert_eq!(unchanged.withdrawal, confirmed.withdrawal);
			}
		}
		Outcome::Refund | Outcome::Timeout => {
			sas(&offline_a, am, Request::Abort { id })?;
			assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::Wait);
			let count = terms.revoke - chain.head().unwrap().height;
			test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				am,
				count as usize,
				false,
			)?;
			assert_eq!(
				sas(&offline_b, bm, Request::Step { id })?.action,
				Action::RevokeGrin
			);
			assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::Wait);
			test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				am,
				terms.confirmations as usize,
				false,
			)?;
			let waiting = sas(&offline_a, am, Request::Step { id })?;
			assert_eq!(waiting.action, Action::Wait);
			assert!(waiting.chain.is_none());
			assert!(waiting.grin.unwrap().revoke.confirmed(terms.confirmations));
			let target = if outcome == Outcome::Refund {
				// First refund at the old cutoff must still be published.
				terms.timeout - terms.margin
			} else {
				terms.timeout
			};
			let count = target - chain.head().unwrap().height;
			test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				am,
				count as usize,
				false,
			)?;
			if outcome == Outcome::Refund {
				assert_eq!(
					sas(&offline_a, am, Request::Step { id })?.action,
					Action::RefundGrin
				);
				test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), am, 1, false)?;
				assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::Refunded);
				let recovered = sas(&offline_b, bm, Request::Step { id })?;
				assert_eq!(
					recovered.action,
					if recovered.funding.is_none() {
						Action::OwnBitcoin
					} else {
						Action::Refunded
					}
				);
				// The grouped buyer has not observed its external payment yet. Its
				// offline key recovery must still allow the subsequent withdrawal.
				if matches!(funding, Funding::Duplicate | Funding::Replaced) {
					let bound = recovered.funding.clone();
					if funding == Funding::Duplicate {
						assert!(bound.is_none());
						assert!(b.sas(bm, Request::WithdrawAuto { id }).is_err());
					} else {
						assert!(bound.is_some());
						for _ in 0..2 {
							let reply = sas(&b, bm, Request::WithdrawAuto { id })?;
							assert!(reply.funding_recovery);
							assert_eq!(reply.action, Action::Refunded);
							let mut lock = wallet2.lock();
							let w = lock.lc_provider()?.wallet_inst()?;
							let saved = w.load_swap::<serde_json::Value>(&id)?.unwrap();
							assert_eq!(
								saved["action"],
								serde_json::to_value(reply.action).unwrap()
							);
							assert!(!saved["funding"].is_null());
							assert!(reply.withdrawal.is_none() && reply.payout.is_none());
						}
					}
					for raw in duplicates {
						let decoded = bitcoin(&["decoderawtransaction", &raw]);
						let address = &funded.payment.as_ref().unwrap().address;
						let vout = decoded["vout"]
							.as_array()
							.unwrap()
							.iter()
							.find(|out| out["scriptPubKey"]["address"] == *address)
							.unwrap()["n"]
							.as_u64()
							.unwrap() as u32;
						let request = Request::Recover {
							id,
							funding: raw,
							vout,
							fee: 1000,
						};
						let sent = sas(&b, bm, request.clone())?;
						assert!(sent.withdrawal.is_some());
						assert_eq!(sas(&b, bm, Request::Step { id })?.funding, bound);
						assert_eq!(sas(&b, bm, request.clone())?.withdrawal, sent.withdrawal);
						bitcoin(&["-generate", "2"]);
						assert!(sas(&b, bm, request)?.payout.unwrap().status.confirmed(2));
					}
				} else {
					let payout = sas(&b, bm, Request::WithdrawAuto { id })?;
					let repeated = sas(&b, bm, Request::WithdrawAuto { id })?;
					assert!(payout.withdrawal.is_some());
					assert_eq!(payout.withdrawal, repeated.withdrawal);
					bitcoin(&["-generate", "2"]);
				}
			} else {
				// Simulate a seller withholding its refund: an honest seller would now
				// keep attempting RefundGrin instead of giving up before timeout.
				assert_eq!(
					sas(&offline_b, bm, Request::Step { id })?.action,
					Action::TimeoutGrin
				);
				test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), am, 1, false)?;
				assert_eq!(sas(&a, am, Request::Step { id })?.action, Action::TimedOut);
				assert_eq!(sas(&b, bm, Request::Step { id })?.action, Action::TimedOut);
				assert!(b.sas(bm, Request::Withdraw { id, fee: 1000 }).is_err());
			}
		}
	}
	running.store(false, Ordering::Relaxed);
	worker.join().unwrap();
	Ok(())
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn claim() -> Result<(), libwallet::Error> {
	run("test_output/sas_claim", Outcome::Claim, Funding::Core)
}
#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn refund() -> Result<(), libwallet::Error> {
	run("test_output/sas_refund", Outcome::Refund, Funding::Core)
}
#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn timeout() -> Result<(), libwallet::Error> {
	run("test_output/sas_timeout", Outcome::Timeout, Funding::Core)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn payment() -> Result<(), libwallet::Error> {
	run("test_output/sas_payment", Outcome::Claim, Funding::External)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn payment_refund() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_payment_refund",
		Outcome::Refund,
		Funding::External,
	)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn payment_timeout() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_payment_timeout",
		Outcome::Timeout,
		Funding::External,
	)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn grouped_claim() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_grouped_claim",
		Outcome::Claim,
		Funding::Grouped,
	)
}
#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn grouped_refund() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_grouped_refund",
		Outcome::Refund,
		Funding::Grouped,
	)
}
#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn grouped_timeout() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_grouped_timeout",
		Outcome::Timeout,
		Funding::Grouped,
	)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn duplicate_refund() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_duplicate_refund",
		Outcome::Refund,
		Funding::Duplicate,
	)
}

#[test]
#[ignore = "requires an isolated funded Bitcoin Core regtest wallet"]
fn replaced_refund() -> Result<(), libwallet::Error> {
	run(
		"test_output/sas_replaced_refund",
		Outcome::Refund,
		Funding::Replaced,
	)
}
