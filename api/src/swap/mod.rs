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

//! Owner swap requests and replies

use crate::libwallet::swap::{Action, Policy, Role};
use uuid::Uuid;

mod bitcoin;
mod draft;
/// Preparation over existing wallet rounds
pub mod negotiation;
/// Public swap Slatepacks
pub mod pack;
mod records;
/// Succinct swap requests
pub mod sas;

/// Owner commands. Transaction strings contain ordinary slate JSON or Bitcoin hex
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
	/// Register local graph entries in the wallet ledger
	Track {
		/// Local graph entries
		record: crate::libwallet::swap::records::Record,
	},
	/// Cancel an unpublished preparation as a whole
	CancelPreparation {
		/// Local graph entries
		record: crate::libwallet::swap::records::Record,
	},
	/// Execute the succinct protocol
	Sas {
		/// Protocol operation
		request: sas::Request,
	},
	/// Reserve a local signing key and agree on explicit fees and deadlines
	Start {
		/// Local side
		role: Role,
		/// Chain deadlines
		policy: Policy,
		/// Bitcoin amount in satoshis
		amount: u64,
		/// Funding fee rate in sat/vB
		fee_rate: u64,
		/// Claim/refund fee in satoshis
		fee: u64,
		/// Maximum fee per transaction in satoshis
		max_fee: u64,
	},
	/// Bind negotiated slates and the counterparty's Bitcoin public key
	Prepare {
		/// Local swap ID
		id: Uuid,
		/// Counterparty claim/refund key
		peer_key: String,
		/// Fully signed multisig funding slate
		funding: String,
		/// Fully signed Grin refund slate
		refund: String,
		/// Main transaction at round A2
		main: String,
	},
	/// Receive a funding transaction or the sender's main signature
	Receive {
		/// Local swap ID
		id: Uuid,
		/// Bitcoin funding hex, for the Grin seller
		funding: Option<String>,
		/// Grin A3 slate, for the Grin buyer
		main: Option<String>,
	},
	/// Recheck both chains and perform at most one safe action
	Step {
		/// Local swap ID
		id: Uuid,
	},
	/// Raise the fee of a local Bitcoin claim or refund within the agreed limit
	Bump {
		/// Local swap ID
		id: Uuid,
		/// New absolute fee in satoshis
		fee: u64,
	},
	/// Read the saved state without broadcasting
	Status {
		/// Local swap ID
		id: Uuid,
	},
}

/// Public state and messages that may be sent to the counterparty
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
	/// Fresh Grin-only observation, also available during Bitcoin-free recovery.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub grin: Option<crate::libwallet::swap::sas::GrinView>,
	/// The agreed Bitcoin input cannot fund a first payout; explicit recovery is needed.
	#[serde(default)]
	pub funding_recovery: bool,
	/// Fresh chain observations from the last successful step
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain: Option<sas::Chain>,
	/// Published Bitcoin payout transaction
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub withdrawal: Option<String>,
	/// Fresh payout observation; absent when Bitcoin has not been queried.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub payout: Option<sas::Payout>,
	/// External Bitcoin payment, available only when funding is allowed
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub payment: Option<sas::Payment>,
	/// Proof of possession for succinct swap preparation
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proof: Option<String>,
	/// Local swap ID
	pub id: Uuid,
	/// Public claim/refund key to exchange before preparation
	pub key: String,
	/// Result of the last step
	pub action: Action,
	/// Prepared Bitcoin funding, if available
	pub funding: Option<String>,
	/// Released A3 slate; identical across retries
	pub main: Option<String>,
}

impl Reply {
	fn new(id: Uuid, action: Action) -> Self {
		Self {
			grin: None,
			funding_recovery: false,
			chain: None,
			withdrawal: None,
			payout: None,
			payment: None,
			proof: None,
			id,
			key: String::new(),
			action,
			funding: None,
			main: None,
		}
	}
}

// New swaps are experimental. Recovery of already stored swaps stays available.
fn test_network(
	network: crate::impls::swap::adapters::bitcoin::types::Network,
) -> Result<(), crate::libwallet::Error> {
	if network == crate::impls::swap::adapters::bitcoin::types::Network::Bitcoin
		|| crate::core::global::get_chain_type() == crate::core::global::ChainTypes::Mainnet
	{
		return Err(crate::libwallet::Error::GenericError(
			"New swaps are only supported on test networks".into(),
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::global::{set_local_chain_type, ChainTypes};
	use crate::impls::swap::adapters::bitcoin::types::Network;
	#[test]
	fn new_swaps_require_test_networks() {
		set_local_chain_type(ChainTypes::Testnet);
		assert!(test_network(Network::Bitcoin).is_err());
		assert!(test_network(Network::Testnet4).is_ok());
		set_local_chain_type(ChainTypes::Mainnet);
		assert!(test_network(Network::Testnet4).is_err());
		set_local_chain_type(ChainTypes::AutomatedTesting);
		assert!(test_network(Network::Regtest).is_ok());
	}
}

fn settings(
	path: std::path::PathBuf,
) -> Result<
	(
		crate::config::types::BitcoinConfig,
		crate::impls::swap::adapters::bitcoin::types::Network,
	),
	crate::libwallet::Error,
> {
	use crate::impls::swap::adapters::bitcoin::types::Network;
	use std::str::FromStr;
	let config = crate::config::config::reload_global_config(&path)
		.map_err(|e| crate::libwallet::Error::GenericError(e.to_string()))?
		.members
		.wallet
		.bitcoin
		.ok_or_else(|| {
			crate::libwallet::Error::GenericError("Bitcoin backend is not configured".into())
		})?;
	let network = Network::from_str(&config.network)
		.map_err(|_| crate::libwallet::Error::GenericError("Bitcoin network".into()))?;
	Ok((config, network))
}

fn core(
	path: std::path::PathBuf,
) -> Result<
	(
		crate::impls::swap::adapters::bitcoin::Core,
		crate::impls::swap::adapters::bitcoin::types::Network,
	),
	crate::libwallet::Error,
> {
	let (config, network) = settings(path)?;
	Ok((
		crate::impls::swap::adapters::bitcoin::Core::new(&config.url, config.cookie, network)?,
		network,
	))
}

fn node(
	path: std::path::PathBuf,
	explicit: Option<&crate::config::types::BitcoinConfig>,
) -> Result<
	(
		crate::impls::swap::adapters::bitcoin::Node,
		crate::impls::swap::adapters::bitcoin::types::Network,
	),
	crate::libwallet::Error,
> {
	let (config, network) = match explicit {
		Some(config) => {
			use std::str::FromStr;
			let network =
				crate::impls::swap::adapters::bitcoin::types::Network::from_str(&config.network)
					.map_err(|_| crate::libwallet::Error::GenericError("Bitcoin network".into()))?;
			(config.clone(), network)
		}
		None => settings(path)?,
	};
	Ok((
		crate::impls::swap::adapters::bitcoin::Node::with_proxy(
			&config.url,
			config.cookie,
			network,
			config.proxy.as_deref(),
		)?,
		network,
	))
}

impl<L, C, K> crate::Owner<L, C, K>
where
	L: crate::libwallet::WalletLCProvider<'static, C, K> + 'static,
	C: crate::libwallet::NodeClient + 'static,
	K: crate::keychain::Keychain + 'static,
{
	fn cancel_pending(
		&self,
		mask: Option<&crate::util::secp::SecretKey>,
		ids: &[Uuid],
	) -> Result<(), crate::libwallet::Error> {
		use crate::libwallet::{retrieve_txs, TxLogEntryType};
		let mut lock = self.wallet_inst.lock();
		let w = lock.lc_provider()?.wallet_inst()?;
		let parent = w.parent_key_id();
		let mut pending = Vec::new();
		for id in ids {
			if let Some(tx) = retrieve_txs(w, None, Some(*id), None, Some(&parent), false)?
				.into_iter()
				.find(|tx| {
					!tx.confirmed
						&& matches!(
							tx.tx_type,
							TxLogEntryType::TxSent
								| TxLogEntryType::TxReceived
								| TxLogEntryType::TxReverted
						)
				}) {
				pending.push((*id, tx.swap.map(|s| s.id)));
			}
		}
		drop(lock);
		for (id, swap) in pending {
			if let Some(swap) = swap {
				crate::libwallet::api_impl::owner::cancel_swap_tx(
					self.wallet_inst.clone(),
					mask,
					id,
					swap,
				)?;
			} else {
				self.cancel_tx(mask, None, Some(id))?;
			}
		}
		Ok(())
	}
}
