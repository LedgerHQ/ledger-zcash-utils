---
"@ledgerhq/zcash-utils": minor
---

Add `"regtest"` as a valid `network` value for `buildTransaction`/`buildIronwoodTransaction`. A fresh regtest chain's tip height never reaches the real mainnet/testnet NU5/NU6.3 activation heights, so both builders previously rejected every send against a local node. `network: "regtest"` now resolves to a `LocalNetwork` whose Overwinter-through-Canopy upgrades activate at height 1 and NU5/NU6/NU6.1/NU6.2/NU6.3 at height 2, matching the canonical zebra/zaino/librustzcash regtest defaults.

A regtest build now stamps derivation paths with mainnet's coin type (133), not regtest's own SLIP-44 value (1, shared with testnet) — this crate's key-derivation surface always derives regtest keys under the mainnet convention, so stamping the SLIP-44 value produced a path no caller actually derives from.

Known limitation: the PCZT's own `global.coin_type` header field (set independently by the `pczt` crate's `Creator` role from the network's type, with no accessor this crate can override afterwards) still carries regtest's SLIP-44 value (1), inconsistent with the mainnet coin type stamped into the derivation paths above. This has no effect on this crate's own device-free signing surface, which never reads that field; it would matter only to a real device, which is out of scope for regtest support.
