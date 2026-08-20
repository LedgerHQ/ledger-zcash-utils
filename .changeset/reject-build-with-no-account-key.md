---
"@ledgerhq/zcash-utils": patch
---

Refuse a build that supplies no account key at all, at the entry point. Calling
`buildTransaction` with neither `ufvk` nor `transparentAccountPubkey` already
failed, but a few calls deep and as whichever of change derivation or transparent
input verification the flow happened to reach first. It now fails up front, before
any work, with one message naming both fields.

The two remain independently optional because the struct they cross into JS
cannot express "exactly one of" — napi has no encoding for a data-carrying enum —
so the invariant is documented on `BuildTransactionParams`, and therefore in
`index.d.ts`, where a caller reads it.
