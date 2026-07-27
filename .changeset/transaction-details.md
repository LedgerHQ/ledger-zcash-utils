---
"@ledgerhq/zcash-utils": minor
---

Add `transactionDetails`, which fetches transactions by txid and reads from each what only the raw bytes hold: the fee it actually paid, and the addresses its shielded outputs paid.

Both answers require the whole transaction, so one fetch serves both. A fee derived from the transparent bundle alone — all an explorer can do — counts value entering a shielded pool as fee and cannot account for value leaving one. Shielded payees are encrypted and recoverable only by the account that created the outputs, through the outgoing viewing key the transaction was built with; pass `ufvk` to recover them.

Requests are pipelined over a single gRPC channel and answered in order. A transaction that cannot be fetched, parsed, or fully priced yields a `null` fee and no payees rather than an approximation.

Orchard-family and Sapling notes now also carry the address they pay (`recipient`), which for a note we sent is the payee rather than one of our own addresses.
