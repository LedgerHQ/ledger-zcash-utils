---
"@ledgerhq/zcash-utils": patch
---

Document the whole published API in the README, which had drifted to covering three of the eleven exports. Everything the send path is made of — `buildTransaction`, `buildIronwoodTransaction`, `parsePczt`, `finalizeTransaction`, `broadcastTransaction` — plus `findBlockHeight`, `transactionDetails` and `orchardAddressFromUfvk` were absent, as were the note fields that make a note spendable (`nullifier`, `rho`, `rseed`, `cmx`, `position`, `recipient`, `isSpent`), `knownNullifiers` / `spentKnownNullifiers`, and `transparentOut` / `hasTransparentInputs`.

The README now walks the send round trip through the device rather than listing functions, and states the two encoding conventions a caller has to get right: zatoshis are JS numbers on the scanning path but decimal strings on the crafting path, and txids come in display order everywhere except `TransparentInputJs.txid`, which is internal order. Its install step names the Artifactory registry the package actually publishes to.
