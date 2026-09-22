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

//! Three-transaction SAS with absolute Grin deadlines

use super::{Action, Role, TxState};
use crate::Error;

/// All spending deadlines belong to the Grin chain
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Terms {
	/// Earliest revoke height
	pub revoke: u64,
	/// Earliest refund height
	pub refund: u64,
	/// Earliest timeout height
	pub timeout: u64,
	/// Grin confirmations before releasing a dependent secret
	pub confirmations: u64,
	/// Bitcoin funding confirmations
	pub bitcoin_confirmations: u64,
	/// Reserved Grin blocks for confirmation and intervention
	pub margin: u64,
}

impl Terms {
	/// Check ordering and leave room for each independent confirmation
	pub fn validate(self) -> Result<(), Error> {
		if self.confirmations == 0
			|| self.bitcoin_confirmations == 0
			|| self.margin < self.confirmations
			|| !self.before(self.revoke, self.refund)
			|| !self.before(self.refund, self.timeout)
		{
			return Err(Error::GenericError("invalid SAS deadlines".into()));
		}
		Ok(())
	}

	fn before(self, height: u64, deadline: u64) -> bool {
		height
			.checked_add(self.margin)
			.map_or(false, |h| h < deadline)
	}

	/// There must still be time to settle Success before Revoke becomes available
	pub fn open(self, height: u64) -> bool {
		self.validate().is_ok() && self.before(height, self.revoke)
	}
}

/// A fresh observation of the agreed transaction graph
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct View {
	/// Current Grin height
	pub height: u64,
	/// Funding kernel
	pub funding: TxState,
	/// Success kernel
	pub success: TxState,
	/// Revoke kernel
	pub revoke: TxState,
	/// Refund kernel
	pub refund: TxState,
	/// Timeout kernel
	pub timeout: TxState,
	/// The funding output remains unspent
	pub funded: bool,
	/// The revoke output remains unspent
	pub revoked: bool,
	/// Bitcoin funding status
	pub bitcoin: TxState,
	/// A Bitcoin funding transaction has been recorded
	pub bitcoin_started: bool,
	/// The Bitcoin output remains unspent
	pub bitcoin_unspent: bool,
}

/// Durable facts; confirmations are always read again from the chains
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow {
	/// Local side
	pub role: Role,
	/// Agreed deadlines
	pub terms: Terms,
	/// Graph and both proofs of possession have been checked
	pub prepared: bool,
	/// Success was signed or received
	pub released: bool,
	/// Our completed Success transaction is persisted
	pub claimed: bool,
	/// Refund was committed for publication, so its secret must be considered public
	pub refund_sent: bool,
	/// A local abort is irreversible
	pub aborted: bool,
	/// Both Bitcoin shares are stored locally
	pub owned: bool,
}

impl Flow {
	/// Choose one action without assuming any mempool ordering
	pub fn next(&self, view: View) -> Result<Action, Error> {
		use Action::*;
		self.terms.validate()?;
		if !self.prepared {
			return Ok(Wait);
		}
		let confirmed = |tx: TxState| tx.confirmed(self.terms.confirmations);
		if confirmed(view.timeout) {
			return Ok(TimedOut);
		}
		if confirmed(view.success) {
			if !view.bitcoin_started {
				return Ok(Wait);
			}
			return Ok(match self.role {
				Role::BuyGrin => Complete,
				Role::SellGrin if self.owned => Complete,
				Role::SellGrin => OwnBitcoin,
			});
		}
		if confirmed(view.refund) {
			return Ok(match self.role {
				Role::SellGrin => Refunded,
				Role::BuyGrin if self.owned => Refunded,
				Role::BuyGrin if !view.bitcoin_started => Refunded,
				Role::BuyGrin => OwnBitcoin,
			});
		}
		if self.owned {
			return Ok(Wait);
		}
		if self.claimed && view.funded && !confirmed(view.revoke) {
			return Ok(ClaimGrin);
		}
		if self.refund_sent && view.revoked && confirmed(view.revoke) {
			return Ok(RefundGrin);
		}
		let open = !self.aborted && self.terms.open(view.height);
		let funded = view.funded && confirmed(view.funding);
		let bitcoin =
			view.bitcoin_unspent && view.bitcoin.confirmed(self.terms.bitcoin_confirmations);
		if confirmed(view.revoke) && view.revoked {
			return Ok(match self.role {
				Role::SellGrin
					if view.height >= self.terms.refund
						&& self.terms.before(view.height, self.terms.timeout) =>
				{
					RefundGrin
				}
				Role::BuyGrin if view.height >= self.terms.timeout => TimeoutGrin,
				_ => Wait,
			});
		}
		if view.funded && view.height >= self.terms.revoke {
			return Ok(RevokeGrin);
		}
		Ok(match self.role {
			Role::SellGrin if open && !self.released && funded && bitcoin => Release,
			Role::SellGrin
				if open
					&& view.funding == TxState::Absent
					&& view.revoke == TxState::Absent
					&& view.success == TxState::Absent =>
			{
				FundGrin
			}
			Role::BuyGrin if open && self.released && funded && bitcoin => ClaimGrin,
			Role::BuyGrin
				if open && !self.released && funded && view.bitcoin == TxState::Absent =>
			{
				FundOther
			}
			_ => Wait,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn setup(role: Role) -> (Flow, View) {
		(
			Flow {
				role,
				terms: Terms {
					revoke: 100,
					refund: 120,
					timeout: 140,
					confirmations: 3,
					bitcoin_confirmations: 2,
					margin: 5,
				},
				prepared: true,
				released: true,
				claimed: false,
				refund_sent: false,
				aborted: false,
				owned: false,
			},
			View {
				height: 80,
				funding: TxState::Confirmed(3),
				success: TxState::Absent,
				revoke: TxState::Absent,
				refund: TxState::Absent,
				timeout: TxState::Absent,
				funded: true,
				revoked: false,
				bitcoin: TxState::Confirmed(2),
				bitcoin_started: true,
				bitcoin_unspent: true,
			},
		)
	}

	#[test]
	fn revoke_first() {
		let (mut flow, mut v) = setup(Role::SellGrin);
		v.height = 120;
		assert_eq!(flow.next(v).unwrap(), Action::RevokeGrin);
		v.funded = false;
		v.revoked = true;
		for confirmations in 0..3 {
			v.revoke = TxState::Confirmed(confirmations);
			assert_eq!(flow.next(v).unwrap(), Action::Wait);
		}
		v.revoke = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::RefundGrin);
		v.height = 135;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		flow.refund_sent = true;
		assert_eq!(flow.next(v).unwrap(), Action::RefundGrin);
	}

	#[test]
	fn reorg() {
		let (mut flow, mut v) = setup(Role::SellGrin);
		v.success = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::OwnBitcoin);
		flow.owned = true;
		assert_eq!(flow.next(v).unwrap(), Action::Complete);
		v.success = TxState::Absent;
		v.height = 120;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		assert!(flow.owned && flow.released);
	}

	#[test]
	fn timeout() {
		let (flow, mut v) = setup(Role::BuyGrin);
		v.height = 140;
		v.funded = false;
		v.revoked = true;
		v.revoke = TxState::Confirmed(2);
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		v.revoke = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::TimeoutGrin);
		v.timeout = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::TimedOut);
	}

	#[test]
	fn funding() {
		let (mut flow, mut v) = setup(Role::SellGrin);
		flow.released = false;
		flow.prepared = false;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		flow.prepared = true;
		v.bitcoin = TxState::Confirmed(1);
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		v.bitcoin = TxState::Confirmed(2);
		v.funding = TxState::Confirmed(2);
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		v.funding = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::Release);
		v.bitcoin_unspent = false;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
	}

	#[test]
	fn abort() {
		let (mut flow, mut v) = setup(Role::SellGrin);
		flow.released = false;
		flow.aborted = true;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		v.height = 100;
		assert_eq!(flow.next(v).unwrap(), Action::RevokeGrin);
		v.funded = false;
		v.revoked = true;
		v.height = 130;
		v.revoke = TxState::Pending;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		v.revoke = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::RefundGrin);
		v.height = 135;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
	}

	#[test]
	fn retry() {
		let (mut flow, mut v) = setup(Role::BuyGrin);
		v.height = 100;
		assert_eq!(flow.next(v).unwrap(), Action::RevokeGrin);
		flow.claimed = true;
		assert_eq!(flow.next(v).unwrap(), Action::ClaimGrin);
		v.funded = false;
		v.revoked = true;
		v.revoke = TxState::Confirmed(3);
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
	}

	#[test]
	fn deadlines() {
		let (mut flow, mut v) = setup(Role::SellGrin);
		flow.released = false;
		assert_eq!(flow.next(v).unwrap(), Action::Release);
		v.height = 95;
		assert_eq!(flow.next(v).unwrap(), Action::Wait);
		flow.terms.timeout = u64::MAX;
		flow.terms.refund = u64::MAX - 2;
		assert!(flow.terms.validate().is_err());
	}
}
