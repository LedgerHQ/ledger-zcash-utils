---
"@ledgerhq/zcash-utils": minor
---

Apply ZIP 2009's ZIP-317 marginal fee: `buildTransaction` and `buildIronwoodTransaction` accept a fee computed at 1,000 zatoshis per logical action on mainnet from height 3,590,000 and on test networks, and keep 5,000 on mainnet below that height. A fee computed at 5,000 is still accepted past the switch.
