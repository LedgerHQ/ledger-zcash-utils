---
"@ledgerhq/zcash-utils": patch
---

Keep the transparent and Orchard send paths working past NU6.3. Three things change under `build_transaction` at that activation even though the code did not: the builder derives V6 from the consensus branch, which the PCZT v1 device contract cannot encode, so the V5 format is now pinned explicitly; an Orchard bundle becomes `orchard_v3` in that epoch and only proves against the NU6.3 circuit generation, so the proving and verifying keys are selected from the branch instead of being fixed to the NU6.2 generation; and the Orchard pool disables cross-address transfers, so retained value is added through the builder's change API, which is what makes z→t build again.

Also fetch an anchor from the commitment-tree frontier alone. A shielded bundle with outputs but no real spend needs an anchor and no witness, and the frontier determines the root, so shielding no longer streams every completed shard root — and no longer depends on the server serving that pool's `GetSubtreeRoots`, which Ironwood does not yet.
