---
"@ledgerhq/zcash-utils": patch
---

Compute Ironwood witnesses from the server's `GetSubtreeRoots` instead of deriving shard roots locally, and fix a shard-0 scan that could hang on either pool.

Ironwood sends previously rescanned the pool's whole history on every spend and recomputed each completed shard root from scratch, because the deployed indexer rejected `GetSubtreeRoots` for Ironwood. It now serves it, so both pools take the same route: the cost is the spend's own shard footprint rather than the pool's lifetime, and the leaf ceiling that would have failed every shielded send as the pool grew is gone. Measured on mainnet against real shard-0 notes, witness computation drops from roughly 26s to 11s, and no longer degrades as the pool fills.

Also fixes a latent hang affecting Orchard as well as Ironwood: the scan for a note in commitment-tree shard 0 started at block 1, and since both pools begin millions of blocks after genesis, `GetBlockRange` — which has no per-request timeout — streamed most of the chain instead of failing. The scan now starts at the pool's first leaf.
