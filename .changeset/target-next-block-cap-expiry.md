---
"@ledgerhq/zcash-utils": minor
---

Transactions now target the next block (tip + 1) instead of anchor + 40, keep the builder's expiry, and cap it below the next network upgrade known to the bundled consensus parameters (none is pending on mainnet or testnet with this release; NU7 is covered once its heights ship). A craft whose capped expiry would leave fewer than 8 blocks (zcashd's 3-block expiring-soon rule plus 5 blocks for signing on the device) is refused with an error containing `expiry too close to activation`. An explicit `anchorHeight` above the chain tip is rejected, and the chain tip is now queried even when `anchorHeight` is given.
