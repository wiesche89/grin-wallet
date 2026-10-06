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

//! Bitcoin withdrawal and explicit output recovery.

use super::*;

fn withdrawal_fee(vsize: usize, rate: u64, limit: u64) -> Result<u64, Error> {
	let fee = (vsize as u64)
		.checked_mul(rate)
		.ok_or_else(|| invalid("withdrawal fee overflow"))?;
	if fee == 0 || fee > limit {
		return Err(invalid("withdrawal fee exceeds limit"));
	}
	Ok(fee)
}

pub(super) fn recover<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut State,
	request: Request,
) -> Result<(Reply, Option<btc::Transaction>), Error> {
	let Request::Recover {
		id,
		funding,
		vout,
		fee,
	} = request
	else {
		unreachable!()
	};
	let network = state.network;
	if !state.flow.owned || fee == 0 || fee > state.offer.max_fee {
		return Err(invalid("recovery policy"));
	}
	let grin = observe_grin(w, mask, state)?;
	if !match state.flow.role {
		Role::SellGrin => grin.0.success.confirmed(state.flow.terms.confirmations),
		Role::BuyGrin => grin.0.refund.confirmed(state.flow.terms.confirmations),
	} {
		return Err(invalid("Grin settlement is not confirmed"));
	}
	let bytes = Vec::<u8>::from_hex(&funding).map_err(|_| invalid("funding encoding"))?;
	let funding: btc::Transaction = deserialize(&bytes).map_err(|_| invalid("funding encoding"))?;
	let point = btc::OutPoint::new(funding.compute_txid(), vout);
	// The normal payout owns its own journal and fee replacement policy.
	if state
		.funding
		.as_ref()
		.map(|tx| state.contract.output(tx, network))
		.transpose()?
		.as_ref()
		== Some(&point)
	{
		return Err(invalid("use Withdraw for the agreed funding output"));
	}
	let saved = state.recoveries.get(&point.to_string());
	let destination = match saved {
		Some(tx) => btc::Address::from_script(&tx.output[0].script_pubkey, network)
			.map_err(|_| invalid("recovery destination"))?,
		None => match &state.destination {
			Some(address) => btc::Address::from_str(address)
				.map_err(|_| invalid("payout address"))?
				.require_network(network)
				.map_err(|_| invalid("payout network"))?,
			None => core.address()?,
		},
	};
	let key = w.get_recovered_atomic_secret(mask, &state.key)?;
	let key = BitcoinKey::from_slice(&key.0).map_err(|_| invalid("owned key"))?;
	let tx = state.contract.spend_output(
		&funding,
		vout,
		network,
		&destination,
		btc::Amount::from_sat(fee),
		&key,
	)?;
	if let Some(previous) = saved {
		if previous != &tx {
			if tx.output[0].value >= previous.output[0].value
				|| matches!(core.status(previous.compute_txid())?, TxState::Confirmed(_))
			{
				return Err(invalid("recovery cannot be replaced"));
			}
			core.accept(&tx)?;
		}
	} else {
		let (status, unspent) = core.unspent(&point, &funding.output[vout as usize])?;
		if !unspent || !status.confirmed(state.flow.terms.bitcoin_confirmations) {
			return Err(invalid("recovery output is not settled"));
		}
	}
	core.watch(&destination)?;
	let status = core.status(tx.compute_txid())?;
	if status == TxState::Conflicted {
		return Err(invalid("recovery conflicts with another transaction"));
	}
	state.recoveries.insert(point.to_string(), tx.clone());
	w.save_swap(mask, &id, state)?;
	let mut response = reply(id, state);
	response.withdrawal = Some(tx.compute_txid().to_string());
	response.payout = Some(Payout {
		status,
		fee,
		max_fee: state.offer.max_fee,
		can_replace: !core.remote(),
	});
	Ok((
		response,
		if status == TxState::Absent {
			Some(tx)
		} else {
			None
		},
	))
}

pub(super) fn withdraw<C: NodeClient, K: Keychain>(
	w: &mut WalletBackend<C, K>,
	mask: Option<&SecretKey>,
	core: &Core,
	state: &mut State,
	request: Request,
) -> Result<Option<Publish>, Error> {
	let automatic = matches!(request, Request::WithdrawAuto { .. });
	let network = state.network;
	let mut publish = None;
	let fee = match request {
		Request::Withdraw { fee, .. } => fee,
		_ => match &state.withdrawal {
			Some(_) => state
				.withdrawal_fee
				.ok_or_else(|| invalid("missing withdrawal fee"))?,
			None => 1,
		},
	};
	if !state.flow.owned || fee == 0 || fee > state.offer.max_fee {
		return Err(invalid("withdrawal policy"));
	}
	let tx = match &state.withdrawal {
		Some(tx) if state.withdrawal_fee == Some(fee) => tx.clone(),
		_ => {
			discover_payment(core, state)?;
			let view = observe(w, mask, core, state, None)?;
			let action = state.flow.next(view)?;
			if !matches!(action, Action::Complete | Action::Refunded) {
				return Err(invalid("coins are not settled"));
			}
			state.action = action;
			if state.withdrawal.is_none() && !view.bitcoin_unspent {
				state.funding_recovery = true;
				return Ok(None);
			}
			let destination = match &state.withdrawal {
				Some(previous) => {
					if fee
						<= state
							.withdrawal_fee
							.ok_or_else(|| invalid("missing withdrawal fee"))?
						|| matches!(core.status(previous.compute_txid())?, TxState::Confirmed(_))
					{
						return Err(invalid("withdrawal cannot be replaced"));
					}
					btc::Address::from_script(&previous.output[0].script_pubkey, network)
						.map_err(|_| invalid("withdrawal destination"))?
				}
				None => match &state.destination {
					Some(address) => btc::Address::from_str(address)
						.map_err(|_| invalid("payout address"))?
						.require_network(network)
						.map_err(|_| invalid("payout network"))?,
					None => core.address()?,
				},
			};
			// Register the external payout before broadcast so Core can monitor it
			// without a transaction index or access to the recipient's wallet.
			core.watch(&destination)?;
			let key = w.get_recovered_atomic_secret(mask, &state.key)?;
			let key = BitcoinKey::from_slice(&key.0).map_err(|_| invalid("owned key"))?;
			let funding = state
				.funding
				.as_ref()
				.ok_or_else(|| invalid("missing funding"))?;
			let spend = |fee| {
				state.contract.spend(
					funding,
					network,
					&destination,
					btc::Amount::from_sat(fee),
					&key,
				)
			};
			let mut tx = spend(fee)?;
			if automatic && state.withdrawal.is_none() {
				let fee = withdrawal_fee(tx.vsize(), state.offer.fee_rate, state.offer.max_fee)?;
				tx = spend(fee)?;
			}
			if state.withdrawal.is_some() {
				core.accept(&tx)?;
			}
			tx
		}
	};
	let status = core.status(tx.compute_txid())?;
	if status == TxState::Conflicted {
		return Err(invalid("withdrawal conflicts with another transaction"));
	}
	state.payout = Some(Payout {
		status,
		fee: state.contract.amount.to_sat() - tx.output[0].value.to_sat(),
		max_fee: state.offer.max_fee,
		can_replace: !core.remote(),
	});
	state.withdrawal = Some(tx.clone());
	state.withdrawal_fee = Some(state.contract.amount.to_sat() - tx.output[0].value.to_sat());
	if status == TxState::Absent {
		publish = Some(Publish::Bitcoin(tx));
	}
	Ok(publish)
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn fees() {
		assert_eq!(withdrawal_fee(111, 2, 5000).unwrap(), 222);
		assert!(withdrawal_fee(111, 2, 221).is_err());
		assert!(withdrawal_fee(111, 0, 5000).is_err());
		assert!(withdrawal_fee(111, u64::MAX, u64::MAX).is_err());
	}
}
