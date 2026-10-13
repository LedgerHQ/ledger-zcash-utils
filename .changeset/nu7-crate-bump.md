---
"@ledgerhq/zcash-utils": minor
---

Move the Zcash crates to their NU7 pre-releases. A transaction whose target block is past NU7 activation is built under the ZIP 259 branch id (`0x77190AD9`), and the expiry cap now sees NU7 ahead on testnet. These releases carry no NU7 mainnet activation height yet, so mainnet transactions keep the NU6.3 branch id until a release that sets it is pinned. The PCZT encoding is unchanged.
