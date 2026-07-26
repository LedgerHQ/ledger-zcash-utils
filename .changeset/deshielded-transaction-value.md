---
"@ledgerhq/zcash-utils": minor
---

Report the transparent bundle of a scanned transaction on `ShieldedTransaction`, via two new fields: `transparentOut` (sum of the transparent outputs, in zatoshis) and `hasTransparentInputs`.

A shielded→transparent send leaves no decrypted output a wallet can attribute to a counterparty: the value exits through the transparent bundle and only the change comes back, marked `internal`. Consumers therefore saw such a send as a self-transfer moving nothing. The scanner already deserializes the full transaction to compute the fee, so it can report these two facts directly instead of having each consumer re-parse the raw hex. `hasTransparentInputs` is needed alongside the amount: once transparent inputs are present, the transparent outputs may be paid by those inputs rather than out of the shielded pools, and the bundle alone cannot tell the two apart.
