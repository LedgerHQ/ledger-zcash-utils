---
"@ledgerhq/zcash-utils": patch
---

Add a test-only NAPI signing surface (`testDeriveKeys`, `testSignPczt`) so the `ledger-live` coin-tester can derive keys and sign a PCZT's Orchard actions, Ironwood (V6) actions, and transparent inputs from a seed, acting as a device stand-in in CI. Never call this from production wallet code.
