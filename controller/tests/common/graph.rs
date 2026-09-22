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

//! Exercise the production preparation through four real Slatepacks

use super::*;
use grin_wallet_api::swap::{
	negotiation::{Driver, Preparation, Proposal},
	pack::Packet,
};
use uuid::Uuid;

pub fn prepare(
	a: &(dyn OwnerRpc + 'static),
	am: Option<&SecretKey>,
	fa: &(dyn ForeignRpc + 'static),
	b: &(dyn OwnerRpc + 'static),
	bm: Option<&SecretKey>,
	fb: &(dyn ForeignRpc + 'static),
	value: u64,
	fee: u64,
	terms: Terms,
	address: &str,
) -> Result<(Uuid, Slate, Slate, Slate), libwallet::Error> {
	let da = Driver {
		owner: a,
		foreign: fa,
		mask: am,
	};
	let db = Driver {
		owner: b,
		foreign: fb,
		mask: bm,
	};
	let mut seller = Preparation::new(
		Proposal {
			grin: value,
			bitcoin: 100_000,
			fee,
			terms,
			chain: format!("{:?}", core::global::get_chain_type()),
			network: "regtest".into(),
		},
		address.into(),
	)?;
	let mut old = serde_json::to_value(&seller).unwrap();
	old["version"] = serde_json::json!(1);
	assert!(serde_json::from_value::<Preparation>(old.clone()).is_err());
	old.as_object_mut().unwrap().remove("version");
	assert!(serde_json::from_value::<Preparation>(old).is_err());
	let mut checkpoint = |state: &Preparation| {
		let restored: Preparation =
			serde_json::from_slice(&serde_json::to_vec(state).unwrap()).unwrap();
		assert_eq!(state.next_round(), restored.next_round());
		Ok(())
	};
	seller.start(&da, &mut checkpoint)?;
	let record = seller.record();
	let funding = Slate::deserialize_upgrade(&record.slates["fund"])?;
	assert!(a
		.cancel_tx(
			grin_wallet_api::Token {
				keychain_mask: am.cloned()
			},
			None,
			Some(funding.id)
		)
		.is_err());
	for _ in 0..2 {
		seller.cancel(&da)?;
	}
	seller = Preparation::new(seller.proposal.clone(), address.into())?;
	seller.start(&da, &mut checkpoint)?;
	let mut old_offer = seller.outgoing.clone().unwrap();
	old_offer.version = 1;
	assert!(Preparation::accept(&old_offer, address.into()).is_err());
	assert!(Packet::offer(&Packet::Round { message: old_offer }.encode()?).is_err());

	let token = || grin_wallet_api::Token {
		keychain_mask: am.cloned(),
	};
	let (_, outputs) = a.retrieve_outputs(token(), true, false, None)?;
	for name in ["fund", "revoke"] {
		let slate = Slate::deserialize_upgrade(&seller.outgoing.as_ref().unwrap().slates[name])?;
		assert!(
			outputs
				.iter()
				.all(|o| o.output.key_id != slate.create_multisig_id()),
			"draft must not appear as a wallet output"
		);
	}

	let mut buyer = Preparation::accept(seller.outgoing.as_ref().unwrap(), address.into())?;
	let mut sizes = Vec::new();
	for round in 0..4 {
		let (sender, receiver, driver) = if round % 2 == 0 {
			(&seller, &mut buyer, &db)
		} else {
			(&buyer, &mut seller, &da)
		};
		let packet = Packet::Round {
			message: sender.outgoing.clone().unwrap(),
		};
		let encoded = packet.encode()?;
		sizes.push(encoded.len());
		let message = match Packet::decode(&encoded)? {
			Packet::Round { message } => message,
			_ => unreachable!(),
		};
		assert_eq!(message.version, 2);
		assert_eq!(message.round, round);
		for mutation in 0..4 {
			let mut changed = message.clone();
			match mutation {
				0 => changed.version = 99,
				1 => changed.id = Uuid::new_v4(),
				2 => changed.round += 1,
				_ => changed.proposal.bitcoin += 1,
			}
			assert!(receiver.receive(driver, changed, &mut checkpoint).is_err());
		}
		for name in ["fund", "refund", "success"] {
			if let Some(encoded) = message.slates.get(name) {
				let slate = Slate::deserialize_upgrade(encoded)?;
				if name == "fund" {
					assert!(slate.participant_data.iter().any(|p| p.part_sig.is_none()));
				}
				if name == "refund" {
					assert_ne!(slate.state, libwallet::SlateState::Atomic4);
				}
				if name == "success" {
					assert!(matches!(
						slate.state,
						libwallet::SlateState::Atomic1 | libwallet::SlateState::Atomic2
					));
				}
			}
		}
		receiver.receive(driver, message.clone(), &mut checkpoint)?;
		*receiver = serde_json::from_slice(&serde_json::to_vec(receiver).unwrap()).unwrap();
		if round == 1 {
			let state = serde_json::to_value(&receiver).unwrap();
			let original: VersionedSlate =
				serde_json::from_value(state["saved"]["1-revoke"].clone()).unwrap();
			let mut slate = Slate::from(original);
			let request = |slate: &Slate| swap::Request::Sas {
				request: Request::Draft {
					op: "sign".into(),
					slate: serde_json::to_string(slate).unwrap(),
				},
			};
			let cached = a.swap(token(), request(&slate))?;
			assert_eq!(
				cached.main.as_ref(),
				receiver.outgoing.as_ref().unwrap().slates.get("revoke")
			);
			slate.amount += 1;
			assert!(
				a.swap(token(), request(&slate)).is_err(),
				"a signing nonce must not be reused for a changed request"
			);
		}

		receiver.receive(driver, message.clone(), &mut checkpoint)?;
		let mut changed = message;
		changed.proof = Some("changed".into());
		assert!(receiver.receive(driver, changed, &mut checkpoint).is_err());
	}
	assert_eq!(sizes.len(), 4);
	assert!(seller.ready && buyer.ready);
	assert_eq!(seller.swap, buyer.swap);
	assert!(seller.outgoing.is_none());
	eprintln!("GROUPED messages={} bytes={:?}", sizes.len(), sizes);
	let private = serde_json::to_value(&seller).unwrap();
	let get = |name: &str| Slate::deserialize_upgrade(private["slates"][name].as_str().unwrap());
	Ok((
		seller.swap.unwrap(),
		get("revoke")?,
		get("refund")?,
		get("timeout")?,
	))
}
