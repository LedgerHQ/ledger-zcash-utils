---
"@ledgerhq/zcash-utils": minor
---

Transactions now target the next block (tip + 1) instead of anchor + 40, keep the builder's expiry, and cap it below the next network upgrade. A craft whose capped expiry would leave fewer than 3 blocks is refused with `expiry too close to activation`. An explicit `anchorHeight` above the chain tip is rejected, and the chain tip is now queried even when `anchorHeight` is given.
