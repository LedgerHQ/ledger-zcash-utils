---
"@ledgerhq/zcash-utils": patch
---

The error returned by `buildTransaction` and `buildIronwoodTransaction` for a fee that does not satisfy ZIP-317 reads `craft error: fee …` once, instead of repeating the `craft error:` prefix.
