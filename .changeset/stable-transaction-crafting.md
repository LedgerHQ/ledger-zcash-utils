---
"@ledgerhq/zcash-utils": major
---

First stable release (1.0.0): end-to-end shielded transaction crafting.

Since 0.3.1 the addon grew from a scan-only library into a full Orchard send pipeline:

- V5 PCZT transaction builder supporting Orchard send flows and mixed
  transparent + Orchard inputs, with bip32 derivation stamped on the change
  output and every transparent input
- `buildTransaction`, `finalizeTransaction`, and `broadcastTransaction` to
  build, finalize, and submit a shielded transaction
- `parsePczt(pcztHex)` to decode canonical PCZT bytes into a structured
  `PcztTransaction` consumed by `@ledgerhq/device-signer-kit-zcash`
- On-demand Orchard ShardTree witness computation at craft time
- `findBlockHeight(grpcUrl, timestamp)` binary search over block timestamps
- NU6.2-aware crate versions for correct branch-id resolution and shielded
  parsing at/above the NU6.2 activation height
