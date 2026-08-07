---
"@ledgerhq/zcash-utils": minor
---

Add an optional `ironwoodSignatures` field to `FinalizeTransactionParams` to support finalizing V6 Ironwood PCZTs, and widen `finalizeTransaction` to return a V5 (ZIP-225) or V6 (ZIP-230) transaction depending on the input PCZT's shielded bundle. `FinalizeInputs` now accepts per-spend Ironwood `spendAuthSig` bytes injected via `apply_ironwood_signature`.

The new field is optional, so existing callers that pass only `orchardSignatures` and `transparentSignatures` keep working unchanged — hence a minor rather than a major bump. Each signature list is length-checked against the PCZT's unsigned actions for its pool, so supplying signatures for a pool the PCZT does not spend fails closed.

Crate dependencies bumped to `pczt 0.9.2`, `zcash_primitives 0.30`, `zcash_transparent 0.10`, `zcash_keys 0.16`, and `zcash_client_backend 0.24.0-rc.7`.
