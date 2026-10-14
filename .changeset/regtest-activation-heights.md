---
"@ledgerhq/zcash-utils": minor
---

`buildTransaction` and `buildIronwoodTransaction` take an optional `regtestActivationHeights` for a regtest node whose activation schedule differs from the canonical one. The builder then selects the branch id that node enforces and caps the expiry below the upgrade it has scheduled. The field is refused with mainnet or testnet.
