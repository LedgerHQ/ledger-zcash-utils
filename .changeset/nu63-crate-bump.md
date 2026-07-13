---
"@ledgerhq/zcash-utils": patch
---

Bump the librustzcash crate set to NU6.3-aware versions (zcash_protocol 0.10, zcash_primitives 0.29, and the compatible zcash_keys/zcash_address/zcash_transparent/orchard set, plus zcash_client_backend and pczt release candidates). This corrects `BranchId::for_height`, which resolves `Nu6_3` at mainnet height 3,428,143, so transactions parse and build correctly after NU6.3 activation. No public API change.
