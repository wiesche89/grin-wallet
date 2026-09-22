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

use super::sas::Terms;
use crate::Error;
use serde::{Deserialize, Serialize};

/// Relative deadlines and confirmation policy for new swaps
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timing {
	/// Blocks until revocation
	pub revoke: u64,
	/// Blocks until seller recovery
	pub refund: u64,
	/// Blocks until buyer recovery
	pub timeout: u64,
	/// Required Grin confirmations
	pub confirmations: u64,
	/// Required Bitcoin confirmations
	pub bitcoin_confirmations: u64,
	/// Safety margin in Grin blocks
	pub margin: u64,
}

impl Default for Timing {
	fn default() -> Self {
		Self {
			revoke: 1440,
			refund: 1560,
			timeout: 1680,
			confirmations: 2,
			bitcoin_confirmations: 2,
			margin: 30,
		}
	}
}

impl Timing {
	/// Validate relative deadlines
	pub fn validate(self) -> Result<(), Error> {
		self.terms(0).map(|_| ())
	}

	/// Resolve deadlines against the current Grin height
	pub fn terms(self, height: u64) -> Result<Terms, Error> {
		let add = |offset| {
			height
				.checked_add(offset)
				.ok_or_else(|| Error::GenericError("Height overflow".into()))
		};
		let terms = Terms {
			revoke: add(self.revoke)?,
			refund: add(self.refund)?,
			timeout: add(self.timeout)?,
			confirmations: self.confirmations,
			bitcoin_confirmations: self.bitcoin_confirmations,
			margin: self.margin,
		};
		terms.validate()?;
		if !terms.open(height) {
			return Err(Error::GenericError(
				"Leave more blocks than the safety margin before recovery and between deadlines"
					.into(),
			));
		}
		Ok(terms)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn deadlines() {
		let terms = Timing::default().terms(100).unwrap();
		assert_eq!(
			(terms.revoke, terms.refund, terms.timeout),
			(1540, 1660, 1780)
		);
		let terms = Timing {
			revoke: 100,
			refund: 200,
			timeout: 300,
			..Timing::default()
		}
		.terms(500)
		.unwrap();
		assert_eq!((terms.revoke, terms.refund, terms.timeout), (600, 700, 800));
		assert!(terms.open(569));
		assert!(!terms.open(570));
		for timing in [
			Timing {
				revoke: 30,
				refund: 200,
				timeout: 300,
				..Timing::default()
			},
			Timing {
				revoke: 100,
				refund: 130,
				timeout: 300,
				..Timing::default()
			},
			Timing {
				revoke: 100,
				refund: 200,
				timeout: 230,
				..Timing::default()
			},
			Timing {
				revoke: 100,
				refund: 90,
				timeout: 300,
				..Timing::default()
			},
		] {
			assert!(timing.terms(0).is_err());
		}
		assert!(Timing::default().terms(u64::MAX - 1500).is_err());
		let custom = Timing {
			confirmations: 4,
			bitcoin_confirmations: 3,
			margin: 40,
			..Timing::default()
		};
		let terms = custom.terms(100).unwrap();
		assert_eq!(
			(
				terms.confirmations,
				terms.bitcoin_confirmations,
				terms.margin
			),
			(4, 3, 40)
		);
		assert!(Timing {
			confirmations: 0,
			..custom
		}
		.validate()
		.is_err());
		assert!(Timing {
			bitcoin_confirmations: 0,
			..custom
		}
		.validate()
		.is_err());
		assert!(Timing {
			margin: 3,
			..custom
		}
		.validate()
		.is_err());
		let old: Timing =
			serde_json::from_str(r#"{"revoke":1440,"refund":1560,"timeout":1680}"#).unwrap();
		assert_eq!(old, Timing::default());
		let restored: Timing = serde_json::from_str("{}").unwrap();
		assert_eq!(restored, Timing::default());
	}
}
