---
"@ledgerhq/zcash-utils": patch
---

Correct the two security claims the test-only signer surface invalidated. The README opened with "spending key material never enters this layer" and stated that key derivation is deliberately not exported — both untrue once `testDeriveKeys` and `testSignPczt` shipped, since each takes a mnemonic and derives spending-key material in process. The claims now describe the production surface, which is still device-only, and name the exception rather than contradicting it.

Document that surface where a consumer will meet it. It is published rather than gated behind a build flag, because the test harness needing it installs the same npm package as production code, so the `test` prefix and a warning are the only guardrail there is — a reader who finds these exports in `index.d.ts` with no explanation is the case worth avoiding. The README now carries a section stating what they are for, what they must never be used for, and that they accept only `"mainnet"` and `"testnet"`: a regtest chain passes `"mainnet"`, because this surface derives regtest keys under the mainnet convention even though the builders take `"regtest"` as a network of its own.

Both new exports also gained the `# Errors` documentation every other export carries, and the README now states that `network` accepts `"regtest"` on the builders at all.
