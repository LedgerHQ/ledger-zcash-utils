---
"@ledgerhq/zcash-utils": minor
---

Add `ironwoodSignatures` to `FinalizeTransactionParams` to support finalizing V6 Ironwood PCZTs. `FinalizeInputs` now accepts per-spend Ironwood `spendAuthSig` bytes injected via `apply_ironwood_signature`. Crate dependencies bumped to `pczt 0.9.2`, `zcash_primitives 0.30`, `zcash_transparent 0.10`, `zcash_keys 0.16`, and `zcash_client_backend 0.24.0-rc.7`.
