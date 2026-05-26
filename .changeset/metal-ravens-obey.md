---
"@ledgerhq/zcash-utils": minor
---

Add spending fields to ShieldedNote (nullifier, rseed, cmx, position, recipient, is_spent) to support shielded transaction crafting via PCZT. Position is derived from CompactBlock chain_metadata, is_spent is computed by nullifier matching across the scanned range.

