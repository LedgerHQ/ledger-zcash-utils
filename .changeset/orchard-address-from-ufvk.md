---
"@ledgerhq/zcash-utils": minor
---

Add `orchardAddressFromUfvk` — derives the Orchard-only unified address from an encoded UFVK string. Returns the same address the Ledger device shows on the Receive screen (matches `GetShieldedAddress` INS 0x51). Also renames `DerivedKeys.unifiedAddress` to `multiReceiverUnifiedAddress` to distinguish it from the Orchard-only address.
