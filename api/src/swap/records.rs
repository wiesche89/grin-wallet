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

use super::Reply;
use crate::{
	keychain::Keychain,
	libwallet::{
		swap::{records::Record, Action},
		Error, NodeClient, WalletLCProvider,
	},
	util::secp::SecretKey,
	Owner,
};

impl<L, C, K> Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub(super) fn cancel_preparation(
		&self,
		mask: Option<&SecretKey>,
		record: &Record,
	) -> Result<Reply, Error> {
		let response = self.track_swap(mask, record)?;
		let id = response.id;
		let (fresh, _) = self.retrieve_txs(mask, true, None, None, None)?;
		if !fresh {
			return Err(Error::GenericError("Grin node is unavailable".into()));
		}
		let ids = {
			let mut lock = self.wallet_inst.lock();
			let w = lock.lc_provider()?.wallet_inst()?;
			super::sas::check_preparation(w, id)?;
			let parent = w.parent_key_id();
			let txs = w.tx_log_iter()?.collect::<Result<Vec<_>, _>>()?;
			let txs = txs
				.into_iter()
				.filter(|tx| {
					tx.parent_key_id == parent && tx.swap.as_ref().map(|s| s.id) == Some(id)
				})
				.collect::<Vec<_>>();
			if txs.iter().any(|tx| tx.confirmed) {
				return Err(Error::GenericError(
					"Swap funding is confirmed; use swap recovery".into(),
				));
			}
			w.abort_swap(mask, &id)?;
			txs.into_iter()
				.filter_map(|tx| tx.tx_slate_id)
				.collect::<Vec<_>>()
		};
		self.cancel_pending(mask, &ids)?;
		Ok(response)
	}

	pub(super) fn track_swap(
		&self,
		mask: Option<&SecretKey>,
		record: &Record,
	) -> Result<Reply, Error> {
		let mut lock = self.wallet_inst.lock();
		let w = lock.lc_provider()?.wallet_inst()?;
		w.keychain(mask)?;
		let id = w.register_swap(mask, record)?;
		Ok(Reply {
			id,
			action: Action::Wait,
			chain: None,
			withdrawal: None,
			payment: None,
			proof: None,
			key: String::new(),
			funding: None,
			main: None,
		})
	}
}
