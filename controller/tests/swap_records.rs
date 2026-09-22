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

use grin_keychain::{ExtKeychain, Keychain};
use grin_wallet_impls::HTTPNodeClient;
use grin_wallet_libwallet::{
	self as wallet,
	swap::{
		records::{Record, TxKind},
		Role,
	},
	OutputData, OutputStatus, SlateState, TxLogEntry, TxLogEntryType, WalletBackend,
};
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

#[test]
fn ledger() -> Result<(), wallet::Error> {
	grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
	let root = std::env::temp_dir().join(format!("wallet-records-{}", Uuid::new_v4()));
	let client = HTTPNodeClient::new("http://127.0.0.1:1", None, Duration::from_secs(1))?;
	let mut w = WalletBackend::<_, ExtKeychain>::new(root.to_str().unwrap(), client)?;
	w.set_keychain(ExtKeychain::from_seed(&[42; 32], true)?, false, true)?;
	let parent = w.parent_key_id();
	let fund = Uuid::new_v4();
	let refund = Uuid::new_v4();
	let mut slates = BTreeMap::new();
	slates.insert("fund".into(), serde_json::json!({"id": fund}).to_string());
	slates.insert(
		"refund".into(),
		serde_json::json!({"id": refund}).to_string(),
	);
	let record = Record {
		role: Role::SellGrin,
		slates,
	};
	let mut tx = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceived, 0);
	tx.tx_slate_id = Some(refund);
	tx.tx_slate_state = Some(SlateState::Atomic2);
	tx.amount_credited = 1_000_000_000;
	let out = OutputData {
		root_key_id: parent.clone(),
		key_id: ExtKeychain::derive_key_id(3, 0, 0, 1, 0),
		n_child: 1,
		commit: None,
		mmr_index: None,
		value: 1_000_000_000,
		status: OutputStatus::Unconfirmed,
		height: 1,
		lock_height: 0,
		is_coinbase: false,
		is_multisig: false,
		tx_log_entry: Some(0),
	};
	{
		let mut batch = w.batch(None)?;
		batch.save_tx_log_entry(tx, &parent)?;
		batch.save(out)?;
		batch.commit()?;
	}
	assert_eq!(
		wallet::retrieve_info(&mut w, &parent, 2)?.amount_awaiting_finalization,
		1_000_000_000
	);
	assert_eq!(w.register_swap(None, &record)?, fund);
	assert_eq!(w.register_swap(None, &record)?, fund);
	let tx = w.tx_log_iter()?.next().unwrap()?;
	assert_eq!(tx.swap.as_ref().unwrap().kind, TxKind::Recovery);
	assert!(wallet::swap::records::check_edit(&tx).is_err());
	assert!(w.batch(None)?.delete_tx_log_entry(0, &parent).is_err());
	assert_eq!(
		wallet::retrieve_info(&mut w, &parent, 2)?.amount_awaiting_finalization,
		0
	);
	assert_eq!(wallet::retrieve_info(&mut w, &parent, 0)?.total, 0);
	assert!(wallet::cancel_swap_tx(&mut w, None, &parent, refund, Uuid::new_v4()).is_err());
	let mut changed = record.clone();
	changed.role = Role::BuyGrin;
	assert!(w.register_swap(None, &changed).is_err());
	assert_eq!(w.tx_log_iter()?.next().unwrap()?.swap, tx.swap);
	wallet::cancel_swap_tx(&mut w, None, &parent, refund, fund)?;
	assert_eq!(
		w.tx_log_iter()?.next().unwrap()?.tx_type,
		TxLogEntryType::TxReceivedCancelled
	);
	assert!(w.batch(None)?.delete_tx_log_entry(0, &parent).is_err());
	assert!(!w.swap_aborted(&fund)?);
	w.abort_swap(None, &fund)?;
	drop(w);
	let client = HTTPNodeClient::new("http://127.0.0.1:1", None, Duration::from_secs(1))?;
	let mut w = WalletBackend::<_, ExtKeychain>::new(root.to_str().unwrap(), client)?;
	w.set_keychain(ExtKeychain::from_seed(&[42; 32], true)?, false, true)?;
	assert!(w.swap_aborted(&fund)?);
	let tx = w.tx_log_iter()?.next().unwrap()?;
	assert_eq!(tx.swap.as_ref().unwrap().kind, TxKind::Recovery);
	let mut future = TxLogEntry::new(parent.clone(), TxLogEntryType::TxSent, 1);
	future.tx_slate_id = Some(fund);
	future.tx_slate_state = Some(SlateState::Multisig1);
	{
		let mut batch = w.batch(None)?;
		batch.save_tx_log_entry(future, &parent)?;
		let ordinary = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceived, 2);
		batch.save_tx_log_entry(ordinary, &parent)?;
		batch.delete_tx_log_entry(2, &parent)?;
		batch.commit()?;
	}
	let future = w
		.tx_log_iter()?
		.collect::<Result<Vec<_>, _>>()?
		.into_iter()
		.find(|t| t.id == 1)
		.unwrap();
	assert_eq!(future.swap.as_ref().unwrap().kind, TxKind::Deposit);
	assert!(w.batch(None)?.delete_tx_log_entry(1, &parent).is_err());
	drop(w);
	std::fs::remove_dir_all(root).unwrap();
	Ok(())
}
