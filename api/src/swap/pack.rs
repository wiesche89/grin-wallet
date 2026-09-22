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

//! Slatepack envelopes for public SAS messages

use super::negotiation::Message;
use crate::libwallet::{Error, Slatepack, SlatepackArmor, SlatepackBin};
use uuid::Uuid;

const PREFIX: &[u8] = b"grin-sas/1\0";
const LIMIT: usize = 4 * 1024 * 1024;

/// Public data exchanged by the two swap participants
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Packet {
	/// Negotiation round
	Round {
		/// Validated negotiation data
		message: Message,
	},
	/// Released success transaction
	Release {
		/// Negotiation identifier
		id: Uuid,
		/// Released Grin transaction
		success: String,
	},
}

fn invalid() -> Error {
	Error::GenericError("Invalid swap Slatepack".into())
}

impl Packet {
	/// Encode public data in an unencrypted Slatepack
	pub fn encode(&self) -> Result<String, Error> {
		let mut pack = Slatepack::default();
		pack.payload = PREFIX.to_vec();
		pack.payload
			.extend(serde_json::to_vec(self).map_err(|_| invalid())?);
		if pack.payload.len() > LIMIT / 2 {
			return Err(invalid());
		}
		SlatepackArmor::encode(&pack)
	}

	/// Decode a versioned swap payload without accepting ordinary transaction slates
	pub fn decode(text: &str) -> Result<Self, Error> {
		let text = text.trim();
		if text.len() > LIMIT {
			return Err(invalid());
		}
		let bytes = SlatepackArmor::decode(text.as_bytes())?;
		let mut reader = std::io::Cursor::new(&bytes);
		let pack: SlatepackBin = crate::core::ser::deserialize(
			&mut reader,
			crate::core::ser::ProtocolVersion(
				crate::libwallet::slate_versions::CURRENT_SLATE_VERSION as u32,
			),
			crate::core::ser::DeserializationMode::default(),
		)
		.map_err(|_| invalid())?;
		if reader.position() as usize != bytes.len() {
			return Err(invalid());
		}
		let pack = pack.0;
		if pack.mode != 0 || pack.slatepack.major != 1 || pack.slatepack.minor != 0 {
			return Err(invalid());
		}
		let payload = pack.payload.strip_prefix(PREFIX).ok_or_else(invalid)?;
		serde_json::from_slice(payload).map_err(|_| invalid())
	}

	/// Inspect an initial offer before accepting it
	pub fn offer(text: &str) -> Result<Message, Error> {
		match Self::decode(text)? {
			Self::Round { message } if message.version == 2 && message.round == 0 => {
				message.proposal.validate()?;
				Ok(message)
			}
			_ => Err(invalid()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn envelope() {
		crate::core::global::set_local_chain_type(crate::core::global::ChainTypes::Testnet);
		let packet = Packet::Release {
			id: Uuid::new_v4(),
			success: "public transaction".into(),
		};
		let encoded = packet.encode().unwrap();
		assert_eq!(Packet::decode(&format!("  {encoded}\n")).unwrap(), packet);
		assert!(Packet::offer(&encoded).is_err());
		let ordinary = SlatepackArmor::encode(&Slatepack::default()).unwrap();
		assert!(Packet::decode(&ordinary).is_err());
		assert!(Packet::decode("BEGINSLATEPACK. broken").is_err());
		let mut future = Slatepack::default();
		future.payload = b"grin-sas/2\0{}".to_vec();
		assert!(Packet::decode(&SlatepackArmor::encode(&future).unwrap()).is_err());
		assert!(Packet::decode(&"x".repeat(LIMIT + 1)).is_err());
	}
}
