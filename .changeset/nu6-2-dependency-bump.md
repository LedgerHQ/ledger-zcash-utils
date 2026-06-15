---
"@ledgerhq/zcash-utils": patch
---

Update Zcash crates to NU6.2-aware versions (orchard 0.14, zcash_primitives 0.28, zcash_protocol 0.9, and transitive deps). Restores correct branch-id resolution and shielded-transaction parsing for blocks at or above the NU6.2 activation height (mainnet 3,364,600).
