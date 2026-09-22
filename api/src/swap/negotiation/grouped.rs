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

//! Four preparation messages over the existing signing rounds

use super::*;
use crate::swap::draft::Operation;
use crate::util::secp::pedersen::Commitment;

impl Preparation {
	fn draft(
		&mut self,
		api: &Driver,
		round: u8,
		name: &str,
		op: Operation,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		let reply: super::super::Reply = self.call(
			api,
			round,
			&format!("{}-{name}", op.name()),
			false,
			"swap",
			json!({"request":super::super::Request::Sas {
				request: Request::Draft { op: op.name().into(), slate: encode(&self.slate(name)?)? }
			}}),
			save,
		)?;
		if op == Operation::Outputs {
			let slate =
				Slate::deserialize_upgrade(&reply.main.ok_or_else(|| invalid("draft response"))?)?;
			let outputs: Vec<_> = slate
				.tx_or_err()?
				.outputs()
				.iter()
				.map(|o| o.commitment())
				.collect();
			self.slates.insert("outputs".into(), encode(&outputs)?);
		} else {
			self.slates.insert(
				name.into(),
				reply.main.ok_or_else(|| invalid("draft response"))?,
			);
		}
		save(self)
	}

	pub(super) fn start_grouped(
		&mut self,
		api: &Driver,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		let p = self.proposal.clone();
		self.draft(api, 0, "fund", Operation::Reserve, save)?;
		self.round(
			api,
			0,
			"success",
			false,
			"init_atomic_swap",
			json!({"args":self.args(p.grin-p.fee,Some("fund"),None,false)?}),
			save,
		)?;
		self.round(
			api,
			0,
			"revoke",
			false,
			"init_send_tx",
			json!({"args":self.args(p.grin-p.fee,Some("fund"),Some(p.terms.revoke),true)?}),
			save,
		)?;
		self.draft(api, 0, "revoke", Operation::Reserve, save)?;
		self.round(
			api,
			0,
			"timeout",
			false,
			"init_atomic_swap",
			json!({"args":self.args(p.grin-2*p.fee,Some("revoke"),Some(p.terms.timeout),false)?}),
			save,
		)?;
		self.publish(0, &["fund", "revoke", "success", "timeout"], None)?;
		save(self)
	}

	pub(super) fn receive_grouped(
		&mut self,
		api: &Driver,
		message: Message,
		save: &mut impl FnMut(&Self) -> Result<(), Error>,
	) -> Result<(), Error> {
		let r = message.round;
		let names: &[&str] = match r {
			0 => &["fund", "revoke", "success", "timeout"],
			1 => &["fund", "revoke", "success", "timeout", "refund", "outputs"],
			2 | 3 => &["fund", "revoke", "refund", "timeout"],
			_ => return Err(invalid("round")),
		};
		if message.slates.len() != names.len()
			|| names.iter().any(|n| !message.slates.contains_key(*n))
			|| (r >= 2) != message.proof.is_some()
		{
			return Err(invalid("round contents"));
		}
		for (name, slate) in &message.slates {
			self.slates.insert(name.clone(), slate.clone());
		}
		let p = self.proposal.clone();
		let rx = |slate: Slate| json!({"slate":slate,"dest_acct_name":null,"dest":null});
		match r {
			0 => {
				for name in ["fund", "revoke", "success", "timeout"] {
					let method = if name == "fund" || name == "revoke" {
						"receive_tx"
					} else {
						"receive_atomic_tx"
					};
					self.round(api, r, name, true, method, rx(self.slate(name)?), save)?;
				}
				self.draft(api, r, "timeout", Operation::Outputs, save)?;
				self.round(
					api,
					r,
					"refund",
					false,
					"init_atomic_swap",
					json!({"args":self.args(p.grin-2*p.fee,Some("revoke"),Some(p.terms.refund),false)?}),
					save,
				)?;
				self.publish(1, names_for_reply(), None)?;
			}
			1 => {
				for name in ["fund", "revoke"] {
					self.round(
						api,
						r,
						name,
						false,
						"process_multisig_tx",
						json!({"slate":self.slate(name)?}),
						save,
					)?;
				}
				self.lock(api, r, "revoke", save)?;
				self.round(
					api,
					r,
					"refund",
					true,
					"receive_atomic_tx",
					rx(self.slate("refund")?),
					save,
				)?;
				self.round(
					api,
					r,
					"timeout",
					false,
					"countersign_atomic_swap",
					json!({"slate":self.slate("timeout")?,"r_addr":null}),
					save,
				)?;
				self.draft(api, r, "revoke", Operation::Sign, save)?;
				let outputs: Vec<Commitment> = serde_json::from_str(&self.slates["outputs"])
					.map_err(|e| invalid(&e.to_string()))?;
				let offer = self.build_offer()?;
				let proof = api
					.sas(Request::Plan {
						role: self.role,
						offer,
						outputs,
					})?
					.proof;
				self.publish(2, &["fund", "revoke", "refund", "timeout"], proof)?;
			}
			2 => {
				for name in ["fund", "revoke"] {
					self.round(
						api,
						r,
						name,
						true,
						"presign_tx",
						json!({"slate":self.slate(name)?}),
						save,
					)?;
				}
				self.draft(api, r, "revoke", Operation::Finish, save)?;
				self.round(
					api,
					r,
					"refund",
					false,
					"countersign_atomic_swap",
					json!({"slate":self.slate("refund")?,"r_addr":null}),
					save,
				)?;
				self.round(
					api,
					r,
					"timeout",
					false,
					"finalize_atomic_swap",
					json!({"slate":self.slate("timeout")?}),
					save,
				)?;
				let proof = self.offer(api)?;
				api.sas(Request::Prepare {
					id: self.swap.ok_or_else(|| invalid("swap id"))?,
					proof: message.proof.clone().ok_or_else(|| invalid("peer proof"))?,
				})?;
				self.ready = true;
				self.publish(3, &["fund", "revoke", "refund", "timeout"], proof)?;
			}
			3 => {
				self.round(
					api,
					r,
					"fund",
					false,
					"finalize_tx",
					json!({"slate":self.slate("fund")?}),
					save,
				)?;
				self.draft(api, r, "revoke", Operation::Store, save)?;
				self.lock(api, r, "success", save)?;
				self.offer(api)?;
				api.sas(Request::Prepare {
					id: self.swap.ok_or_else(|| invalid("swap id"))?,
					proof: message.proof.clone().ok_or_else(|| invalid("peer proof"))?,
				})?;
				self.ready = true;
				self.outgoing = None;
				self.next = 4;
			}
			_ => unreachable!(),
		}
		self.incoming = Some(message);
		save(self)
	}
}

fn names_for_reply() -> &'static [&'static str] {
	&["fund", "revoke", "success", "timeout", "refund", "outputs"]
}
