# Remaining atomic-swap work

Design considerations for changes beyond the current single-payment protocol.

## Timeout: distinguish recovery from punishment

The current code implements the three-transaction SAS path: Grin is the
chain with deadlines; Bitcoin is locked to the sum of the refund and success
keys. A confirmed Grin Success reveals the buyer's share to the seller. A
confirmed Grin Refund reveals the seller's share to the buyer. Grin Timeout
pays the buyer and deliberately does neither.

The `grouped_timeout`, `payment_timeout` and `timeout` regtests cover a
withheld seller refund: the buyer gets Grin and cannot withdraw Bitcoin.
Returning the original Bitcoin as well would require a different protocol.

Unsafe shortcuts:

- Revealing the seller's Bitcoin share in Timeout would let the buyer take
  both the Grin timeout output and Bitcoin. Do not remove the independent-secret
  check in `prepare`.
- Merely adding a Bitcoin refund deadline would allow Bitcoin refund after
  Grin Success if the seller has not swept Bitcoin yet. Key ownership would
  stop being final settlement; timely on-chain payout would become mandatory.
- A fresh local state flag cannot invalidate a fully signed transaction already
  held by the other party.

For a new independent-refund protocol, specify and test before enabling it:

1. Which Grin outputs pay whom after each abort, especially after Revoke;
   a buyer Bitcoin refund must not coexist with a spendable buyer Grin path.
2. Confirmation and intervention windows across both chains, including stalled
   chains, fee spikes, delayed Revoke inclusion, and transactions mined together.
3. A precise last safe Grin-claim point before Bitcoin refund becomes spendable;
   UI deadlines alone cannot disable an already signed Grin transaction.
4. Funding outpoints and all refund transactions bound before funds are exposed.
5. A new negotiated version with separate parsing and state transitions. Old
   key-only swaps retain their existing recovery paths and must not be migrated
   by reinterpreting their stored addresses or secrets.

## Multiple Bitcoin outputs

Today both backends and the contract reject ambiguous matching payments. This
is safe rejection, but a duplicate deposit can disrupt progress. Extra funds
now have an explicit post-settlement recovery operation.

Automatic multi-output support would need both agreement and recovery:

- An explicit `(txid, vout, amount, script)` binding acknowledged by both parties
  before Success is released, persisted across restart and retransmission.
- No implicit replacement of this binding after release, claim or key recovery.
- Validation against the raw transaction and fresh unspent/confirmation data;
  server ordering must never choose the parties' agreement.
- Separate enumeration and withdrawal of additional contract outputs after key
  recovery, with visible totals and fee bounds. This must not silently turn a
  single-output swap into a different negotiated amount.
- Tests for duplicates in one transaction and across transactions, opposite
  discovery order, replacement, disappearance, restart and later extra deposits.

Automatic multi-output agreement would be a message/state change as well as a
Bitcoin-adapter change. It is not necessary for the retained single-payment SAS
protocol. The minimal implementation keeps ambiguous discovery rejected, freezes
an existing binding, and provides explicit post-settlement recovery of each
additional output through the owner API. See [recovery instructions](atomic-swaps-review.md#explicit-recovery-of-extra-bitcoin-outputs).
No automatic multi-output agreement or GUI selection has been added.

## Observation and test coverage

The public Grin mempool is available through `get_unconfirmed_transactions`.
The wallet now uses its kernels as advisory Pending information. Chain
confirmation remains authoritative; a missing entry does not prove a conflict.
Stem transactions remain private. A failed optional pool query must not block
Grin recovery. A complete Conflicted classification would need stronger evidence
of the actual competing spend, not simply an absent output or pool entry.

Remote Esplora remains a trusted backend. Header-chain validation alone would
not establish that an output remains unspent. Use the existing local Core mode
when independent Bitcoin validation is required; do not rename the remote
adapter as a validating light client.

GRIM's session writer is now tested with child processes killed after writing,
after file sync, after rename and after directory sync. The committed session
remains a complete old or new state and subsequent writes succeed. This checks
process interruption, not power-loss behavior of the underlying hardware.

Remaining verification work includes termination across wallet-DB/session commit
boundaries, real Grin-pool eviction and stem/fluff transitions, deep
reorgs, GUI automation, and an independent cryptographic review. Existing
simulated save interruptions and restart tests are useful but do not cover
all these cases.
