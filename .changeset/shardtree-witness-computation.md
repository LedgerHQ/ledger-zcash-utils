---
"@ledgerhq/zcash-utils": minor
---

Add on-demand Orchard ShardTree witness computation.

Public surface:
- `zcash_crypto::tree::{build_witnesses, WitnessInputs, WitnessOutput, ShardLeaves}`
- `zcash_sync::witness::{compute_witnesses, WitnessRequest, NoteRef}`

Witness data is fetched and assembled on demand at craft time. No tree state
is persisted between calls.
