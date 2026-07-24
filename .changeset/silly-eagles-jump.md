---
"@ledgerhq/zcash-utils": minor
---

Add `buildIronwoodTransaction` for the Ironwood (NU6.3) shielded pool: builds, proves, and serializes an unsigned V6 PCZT carrying an Ironwood bundle (spends and/or outputs), reusing the existing Orchard V5 crafting lifecycle against the updated Action circuit. Ironwood outputs use the `0x03` quantum-recoverable note plaintext, the emitted PCZT is redacted and serialized in the v2 wire format (required for any V6 transaction), and a dedicated non-zero-anchor check rejects an all-zero Ironwood commitment-tree root before it can be silently embedded. Anchor/witness resolution reuses the existing Ironwood sync path (`fetchIronwoodAnchor` / Ironwood witness computation). The shipped Orchard V5 send flow (`buildTransaction`) is unchanged. Like the V5 builder, this is device-coupled (not exposed via the CLI) and depends on release-candidate wallet-side crates (`pczt`, `zcash_client_backend`) pending stable NU6.3 releases.
