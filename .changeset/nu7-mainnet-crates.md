---
"@ledgerhq/zcash-utils": minor
---

Move the Zcash crates from their NU7 pre-releases to the stable releases that set the NU7 mainnet activation height (3543405). A mainnet transaction whose target block is past that height is built under the ZIP 259 branch id (`0x77190AD9`), and the expiry cap now sees NU7 ahead on mainnet. From NU7 activation the builder's default expiry is 120 blocks after the target instead of 40, the same duration at 25-second blocks. The PCZT encoding is unchanged.
