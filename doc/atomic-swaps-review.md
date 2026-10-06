# Atomic swaps: recovery and compatibility

The `atomic_swaps` branch implements the Grin–Bitcoin SAS transaction graph.
New offers require test networks on both chains. Recovery of existing stored
swaps remains available with their original deadlines.

## Signing and persistence

Swap finalization requires the authenticated owner API. Multisig clients must
call owner `presign_tx`; foreign `finalize_tx` and `presign_tx` accept ordinary
transactions only. The CLI and grouped negotiation use the owner endpoint.

Atomic rounds and Multisig2 processing store the exact request and response.
Replaying the same request returns the saved response; changed requests are
rejected. Multisig2's response, context and output are committed together.
A completed legacy multisig context without a journal cannot be signed again.
Interrupted preparation resumes only when a response is available in the journal;
otherwise it requires guarded cancellation and a new offer.

Atomic secrets in private transaction contexts use the wallet's existing
key-derived masking scheme. Legacy plaintext contexts are upgraded on an
authenticated read. Back up the wallet database and swap session files: the seed
alone does not restore randomly generated swap keys.

## Confirmations and recovery

New offers require at least two confirmations per chain, a safety margin of six
Grin confirmation intervals, and two margins between recovery deadlines. Grim
also checks incoming offers against its local policy and displays the offered
heights. These minimums do not guarantee protection against reorganizations.

Grin recovery and Bitcoin key recovery can proceed while Bitcoin is offline.
Bitcoin payout still requires a connection. Public Grin pool kernels are
advisory pending observations; only chain confirmations authorize settlement.
Failed pool queries do not block recovery, and stem transactions remain private.

Payout replies contain fresh confirmation status and fee limits. Grim monitors
payouts, retries absent transactions and rechecks confirmations before archiving.
Local Bitcoin Core supports fee replacement after mempool preflight. The remote
backend does not support replacement preflight and remains a trusted service.
External payout addresses are registered in Core's descriptor watch wallet.

Send the exact Bitcoin amount once and pay transaction fees separately. Funding
is bound to the first recorded transaction; an RBF replacement does not silently
change that binding. Extra deposits and replaced funding may require explicit
recovery after Grin settlement.

## Protocol limits

The Bitcoin contract has no independent refund timelock. Grin Success reveals
the buyer's share to the seller; Grin Refund reveals the seller's share to the
buyer. Grin Timeout pays the buyer but reveals neither swap key. If the seller
withholds its refund, Timeout therefore compensates the buyer in Grin rather
than unlocking Bitcoin. Both parties must monitor their recovery windows.

Esplora observations do not independently validate the Bitcoin header chain or
prove that an output remains unspent. Mainnet rejection does not remove that
trust assumption. See [remaining protocol work](atomic-swaps-protocol-next.md)
for changes that would require a new protocol version and further review.

## Explicit recovery of extra Bitcoin outputs


The owner API accepts a SAS request of this form (inside the existing `swap`
request envelope):

```json
{
  "action": "recover",
  "id": "<funding-slate-uuid>",
  "funding": "<raw-signed-bitcoin-transaction-hex>",
  "vout": 1,
  "fee": 1000
}
```

This is a manual recovery operation, not a new GUI payment mode. `vout` is the
zero-based Bitcoin output index; `fee` is an absolute satoshi fee bounded by the
swap's maximum. The destination stays the configured payout address, or a local
Core wallet address saved in the first recovery transaction.

The wallet requires the matching confirmed Grin outcome (seller Success or
buyer Refund), the locally recovered key and a confirmed, unspent output to the
exact contract script. It uses the selected output's actual amount. It rejects
the canonical payment here: use the existing Withdraw operation for that output.
When no payment was recorded because discovery was ambiguous, each explicitly
specified output can be recovered through this endpoint after the Grin Refund.
Timeout does not provide the Bitcoin key and does not enable this operation.

Repeat the same request to observe confirmation or retry a saved broadcast.
The response's `withdrawal` and `payout` describe this recovery transaction;
normal Status/GRIM still describe the original swap payout. With local Core,
increase the absolute fee to replace an unconfirmed recovery; lowering the fee
or replacing a confirmed recovery is rejected. Recovery transactions have a
separate persistent journal and do not overwrite the original funding/payout.

## Running the regression tests

From the wallet repository:

```sh
cargo test --offline --workspace --lib --no-fail-fast -- --test-threads=1
cargo test --offline -p grin_wallet_controller --test atomic --test swap_records --test transaction --test invoice --test slatepack -- --test-threads=1
cargo test --offline --test cmd_line_atomic -- --test-threads=1
```

The ignored SAS and cross-chain Atomic tests require a separate, funded Bitcoin
Core regtest wallet named `swap`. Set `GRIN_SWAP_CLI`, `GRIN_SWAP_DATADIR`,
`GRIN_SWAP_PORT`, `GRIN_SWAP_RPC` (including `/wallet/swap`) and
`GRIN_SWAP_COOKIE` for that instance, then run:

```sh
cargo test --offline -p grin_wallet_controller --test sas --test atomic -- --ignored --test-threads=1
cargo test --offline -p grin_wallet_impls --lib swap::adapters::bitcoin::rpc::tests::regtest_spends -- --ignored --exact --test-threads=1
```

Run these suites sequentially: they mine and invalidate blocks on the configured
regtest chain. In Grim, use the same isolated environment:

```sh
cargo test --offline --lib swaps -- --include-ignored --skip wallet::swaps::storage::tests::crash_child --test-threads=1
```

The storage test starts `crash_child` itself. These tests cover selected restart,
replay, payout, refund, timeout and confirmation-loss paths. They do not replace
an independent protocol review or a complete funded GUI test.
