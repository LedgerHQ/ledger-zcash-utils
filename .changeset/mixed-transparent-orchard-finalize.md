---
"@ledgerhq/zcash-utils": minor
---

Support transparent inputs in `finalizeTransaction`, enabling the mixed transparent+Orchard send flow end-to-end. Finalize now stamps each transparent input's `hash160_preimage` so device signatures can be injected and `script_sig`s assembled.
