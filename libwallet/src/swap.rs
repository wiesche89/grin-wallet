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

//! Shared swap policy. Chain adapters verify contracts and supply fresh observations

use crate::Error;

/// Swap transaction bookkeeping
pub mod records;
/// Succinct swaps with a Grin revoke branch
pub mod sas;
/// Preparation timing policy
pub mod timing;

/// Local side of the trade
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
	/// Pay Grin and claim the other asset with the recovered key
	SellGrin,
	/// Lock the other asset and receive Grin
	BuyGrin,
}

/// Confirmation and timeout policy for one chain
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deadline {
	/// Absolute refund height
	pub refund: u64,
	/// Required confirmations
	pub confirmations: u64,
	/// Blocks reserved for a claim, including confirmation time
	pub claim_blocks: u64,
	/// Expected block interval, used only when checking the initial timeout ordering
	pub block_seconds: u64,
}

impl Deadline {
	fn validate(self, height: u64) -> Result<(), Error> {
		if self.confirmations == 0
			|| self.claim_blocks < self.confirmations
			|| self.block_seconds == 0
			|| !self.open(height)
		{
			return Err(Error::GenericError("invalid swap deadline".into()));
		}
		Ok(())
	}

	fn open(self, height: u64) -> bool {
		height
			.checked_add(self.claim_blocks)
			.map_or(false, |h| h < self.refund)
	}

	fn remaining(self, height: u64) -> Option<u64> {
		self.refund
			.checked_sub(height)?
			.checked_mul(self.block_seconds)
	}
}

/// Both deadlines are checked again before funding or releasing a signature
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
	/// Grin deadline; it expires first
	pub grin: Deadline,
	/// Counter-chain deadline, leaving time to recover and claim
	pub other: Deadline,
}

impl Policy {
	/// Reject reversed, expired or overflowing deadlines
	pub fn validate(self, grin_height: u64, other_height: u64) -> Result<(), Error> {
		self.grin.validate(grin_height)?;
		self.other.validate(other_height)?;
		let valid = (|| {
			let grin = self.grin.remaining(grin_height)?;
			let other = self.other.remaining(other_height)?;
			let margin = self
				.other
				.claim_blocks
				.checked_mul(self.other.block_seconds)?;
			Some(other > grin.checked_add(margin)?)
		})();
		if valid != Some(true) {
			return Err(Error::GenericError(
				"counter-chain refund is too early".into(),
			));
		}
		Ok(())
	}
}

/// Current chain status, never a cached confirmation count
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxState {
	/// Not in the active chain or mempool
	Absent,
	/// Accepted but not confirmed
	Pending,
	/// Confirmations on the active chain
	Confirmed(u64),
	/// A conflicting spend is known
	Conflicted,
}

impl TxState {
	fn confirmed(self, required: u64) -> bool {
		matches!(self, Self::Confirmed(n) if n >= required && required > 0)
	}
}

/// An adapter must validate the funding output before reporting it as unspent
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
	/// Active chain height
	pub height: u64,
	/// Contract funding transaction
	pub funding: TxState,
	/// Successful contract spend
	pub claim: TxState,
	/// Timelocked refund
	pub refund: TxState,
	/// Exact agreed output exists and remains unspent
	pub unspent: bool,
}

/// One retryable operation. Signed transactions must be saved before publication
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
	/// Await a message, confirmations or the refund height
	Wait,
	/// Publish the saved Grin funding transaction
	FundGrin,
	/// Publish the saved counter-chain funding transaction
	FundOther,
	/// Countersign Grin only after checking both fundings
	Release,
	/// Finalize and publish the Grin claim
	ClaimGrin,
	/// Recover the key and publish the counter-chain claim
	ClaimOther,
	/// Publish the prepared Grin refund
	RefundGrin,
	/// Publish the prepared counter-chain refund
	RefundOther,
	/// Publish the Grin revocation transaction
	RevokeGrin,
	/// Publish the Grin timeout transaction
	TimeoutGrin,
	/// Store the recovered Bitcoin signing key without spending the funding
	OwnBitcoin,
	/// The timeout branch won
	TimedOut,
	/// The local claim has enough confirmations
	Complete,
	/// The local refund has enough confirmations
	Refunded,
}

/// Persisted facts; chain confirmations are deliberately not persisted here
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flow {
	/// Local trading role
	pub role: Role,
	/// Agreed confirmation and timeout policy
	pub policy: Policy,
	/// Both local funding and its fully signed refund have been verified and saved
	pub prepared: bool,
	/// The sender's Grin signature was saved or received. Never clear on a reorg
	pub released: bool,
	/// Our claim was signed and saved. It may already be public
	pub claimed: bool,
}

impl Flow {
	/// Choose an action using a fresh, fully checked snapshot from both chains
	pub fn next(&self, grin: View, other: View) -> Result<Action, Error> {
		use Action::*;
		if [self.policy.grin, self.policy.other].iter().any(|p| {
			p.confirmations == 0 || p.claim_blocks < p.confirmations || p.block_seconds == 0
		}) {
			return Err(Error::GenericError("invalid swap policy".into()));
		}
		let (local, deadline) = match self.role {
			Role::SellGrin => (other, self.policy.other),
			Role::BuyGrin => (grin, self.policy.grin),
		};
		if local.claim.confirmed(deadline.confirmations) {
			return Ok(Complete);
		}
		let (refund, confirmations) = match self.role {
			Role::SellGrin => (grin.refund, self.policy.grin.confirmations),
			Role::BuyGrin => (other.refund, self.policy.other.confirmations),
		};
		if refund.confirmed(confirmations) {
			return Ok(Refunded);
		}
		if !self.prepared {
			return Ok(Wait);
		}
		let grin_ready = grin.unspent && grin.funding.confirmed(self.policy.grin.confirmations);
		let other_ready = other.unspent && other.funding.confirmed(self.policy.other.confirmations);
		let open = self.policy.validate(grin.height, other.height).is_ok();
		Ok(match self.role {
			Role::SellGrin => {
				if (self.claimed
					|| self.released && grin.claim.confirmed(self.policy.grin.confirmations))
					&& other.unspent
				{
					ClaimOther
				} else if grin.unspent && grin.height >= self.policy.grin.refund {
					RefundGrin
				} else if !self.released && open && grin_ready && other_ready {
					Release
				} else if !self.released
					&& open && grin.funding == TxState::Absent
					&& grin.claim == TxState::Absent
					&& grin.refund == TxState::Absent
					&& other.funding == TxState::Absent
				{
					FundGrin
				} else {
					Wait
				}
			}
			Role::BuyGrin => {
				if other.unspent && other.height >= self.policy.other.refund {
					RefundOther
				} else if self.claimed && grin.unspent {
					ClaimGrin
				} else if self.claimed
					&& grin.funding == TxState::Absent
					&& grin.claim == TxState::Absent
					&& grin.refund == TxState::Absent
				{
					FundGrin
				} else if self.released && open && grin_ready && other_ready {
					ClaimGrin
				} else if !self.released
					&& open && grin_ready
					&& other.funding == TxState::Absent
					&& other.claim == TxState::Absent
					&& other.refund == TxState::Absent
				{
					FundOther
				} else {
					Wait
				}
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn setup() -> (Flow, View, View) {
		let policy = Policy {
			grin: Deadline {
				refund: 200,
				confirmations: 3,
				claim_blocks: 10,
				block_seconds: 60,
			},
			other: Deadline {
				refund: 50,
				confirmations: 2,
				claim_blocks: 5,
				block_seconds: 600,
			},
		};
		let grin = View {
			height: 100,
			funding: TxState::Confirmed(3),
			claim: TxState::Absent,
			refund: TxState::Absent,
			unspent: true,
		};
		let other = View {
			height: 20,
			funding: TxState::Confirmed(2),
			..grin
		};
		(
			Flow {
				role: Role::SellGrin,
				policy,
				prepared: true,
				released: false,
				claimed: false,
			},
			grin,
			other,
		)
	}

	#[test]
	fn funding_confirmations() {
		let (mut flow, mut grin, mut other) = setup();
		assert_eq!(flow.next(grin, other).unwrap(), Action::Release);
		other.funding = TxState::Confirmed(1);
		assert_eq!(flow.next(grin, other).unwrap(), Action::Wait);
		other.funding = TxState::Confirmed(2);
		grin.unspent = false;
		assert_eq!(flow.next(grin, other).unwrap(), Action::Wait);
		grin.unspent = true;
		flow.prepared = false;
		assert_eq!(flow.next(grin, other).unwrap(), Action::Wait);
	}

	#[test]
	fn funding_reorg() {
		let (mut flow, grin, mut other) = setup();
		other.funding = TxState::Pending;
		assert_eq!(flow.next(grin, other).unwrap(), Action::Wait);
		flow.released = true;
		let restored: Flow = serde_json::from_str(&serde_json::to_string(&flow).unwrap()).unwrap();
		assert!(restored.released);
		assert_eq!(restored.next(grin, other).unwrap(), Action::Wait);
	}

	#[test]
	fn claim_reorg() {
		let (mut flow, mut grin, mut other) = setup();
		flow.released = true;
		flow.claimed = true;
		// A revealed key remains usable even if the source kernel is reorganized out
		assert_eq!(flow.next(grin, other).unwrap(), Action::ClaimOther);
		flow.role = Role::BuyGrin;
		other.unspent = false;
		other.funding = TxState::Absent;
		assert_eq!(flow.next(grin, other).unwrap(), Action::ClaimGrin);
		grin.unspent = false;
		grin.funding = TxState::Absent;
		assert_eq!(flow.next(grin, other).unwrap(), Action::FundGrin);
	}

	#[test]
	fn deadlines_and_refunds() {
		let (mut flow, mut grin, mut other) = setup();
		grin.height = 190;
		assert_eq!(flow.next(grin, other).unwrap(), Action::Wait);
		grin.height = 200;
		assert_eq!(flow.next(grin, other).unwrap(), Action::RefundGrin);
		flow.role = Role::BuyGrin;
		other.height = 50;
		assert_eq!(flow.next(grin, other).unwrap(), Action::RefundOther);
		other.unspent = false;
		other.refund = TxState::Confirmed(2);
		assert_eq!(flow.next(grin, other).unwrap(), Action::Refunded);
		flow.policy.other.refund = u64::MAX;
		assert!(flow.policy.validate(100, 20).is_err());
	}
}
