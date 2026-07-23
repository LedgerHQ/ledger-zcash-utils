---
"@ledgerhq/zcash-utils": patch
---

Route surplus change to the pool that funds it: an Orchard change output only when the transaction has Orchard spends (z→z, z→t), a transparent change output when there are none (t→t, t→z). For t→z this keeps the change transparent instead of migrating the whole balance into the shielded pool — only the sent amount is shielded.
