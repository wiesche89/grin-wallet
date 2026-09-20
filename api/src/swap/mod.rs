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

/// Owner commands. Transaction strings contain ordinary slate JSON or Bitcoin hex
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
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
	/// Read the saved state without broadcasting
	Status {
		/// Local swap ID
		id: Uuid,
	},
}

/// Public state and messages that may be sent to the counterparty
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
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
