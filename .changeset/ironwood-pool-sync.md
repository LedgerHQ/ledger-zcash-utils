---
"@ledgerhq/zcash-utils": minor
---

Sync the Ironwood (NU6.3) shielded pool in parallel to Orchard. Detect, trial-decrypt, and fully decrypt Ironwood notes (ZIP 2005 `0x03` note plaintext) from the Ironwood bundle of V6 transactions, expose them via a new `ironwoodNotes` array on `ShieldedTransaction` and a per-note `pool` discriminator, derive their position from the Ironwood commitment-tree-size counter, track spends against the Ironwood nullifier set, and compute ShardTree witnesses for the Ironwood tree. Existing Orchard/Sapling sync and the Orchard send path are unchanged. Bumps the Zcash crates to NU6.3-aware versions (orchard 0.15, zcash_primitives 0.29, zcash_protocol 0.10, and the wallet-side crates from crates.io release candidates: `zcash_client_backend 0.24.0-rc.1`, `pczt 0.8.0-rc.1`).
