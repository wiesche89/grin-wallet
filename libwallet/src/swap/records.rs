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

use super::Role;
use crate::{Error, TxLogEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Economic purpose of a swap transaction
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxKind {
	/// Funding the shared output
	Deposit,
	/// Successful exchange
	Transfer,
	/// Local recovery payment
	Recovery,
	/// An intermediate step without a personal payment
	Internal,
}

/// Persistent ownership of a swap transaction
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInfo {
	/// Funding slate identifier
	pub id: Uuid,
	/// Purpose in the local account
	pub kind: TxKind,
}

/// Local graph used to register existing and future transaction entries
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
	/// Local side of the exchange
	pub role: Role,
	/// Named public slates from preparation
	pub slates: BTreeMap<String, String>,
}

impl Record {
	/// Resolve graph identifiers without exposing private preparation state
	pub fn entries(&self) -> Result<(Uuid, Vec<(Uuid, TxInfo)>), Error> {
		#[derive(Deserialize)]
		struct Id {
			id: Uuid,
		}
		let mut ids = BTreeMap::new();
		for name in ["fund", "revoke", "success", "refund", "timeout"] {
			if let Some(slate) = self.slates.get(name) {
				let tx: Id =
					serde_json::from_str(slate).map_err(|e| Error::GenericError(e.to_string()))?;
				if ids.values().any(|id| *id == tx.id) {
					return Err(Error::GenericError("duplicate swap transaction".into()));
				}
				ids.insert(name, tx.id);
			}
		}
		let id = *ids
			.get("fund")
			.ok_or_else(|| Error::GenericError("missing swap funding".into()))?;
		let entries = ids
			.into_iter()
			.map(|(name, slate)| {
				let kind = match name {
					"fund" => TxKind::Deposit,
					"success" => TxKind::Transfer,
					"refund" if self.role == Role::SellGrin => TxKind::Recovery,
					"timeout" if self.role == Role::BuyGrin => TxKind::Recovery,
					_ => TxKind::Internal,
				};
				(slate, TxInfo { id, kind })
			})
			.collect();
		Ok((id, entries))
	}
}

/// Normal transaction actions cannot alter swap bookkeeping
pub fn check_edit(tx: &TxLogEntry) -> Result<(), Error> {
	if tx.swap.is_some() {
		return Err(Error::GenericError(
			"Manage this transaction through the swap".into(),
		));
	}
	Ok(())
}
