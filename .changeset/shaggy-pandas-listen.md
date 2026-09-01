---
"@ledgerhq/zcash-utils": patch
---

Move `zcash_client_backend` to its `0.24.0` stable release. The exact pin on `0.24.0-rc.7` carried a comment instructing exactly this once the stable release existed; it was published on 2026-08-19 and the pin had not followed. Nothing in the dependency tree is a release candidate any more, and the full workspace suite passes on the stable release.

Retire the claims that pin had left behind, three of which were false rather than merely stale. `buildIronwoodTransaction` was documented — in the shipped `index.d.ts`, so every consumer read it — as "dry-run pending the NU6.3 wallet-side crates stabilizing (`pczt`, `zcash_client_backend` are release candidates)". `pczt` was never a release candidate: it is pinned exactly at `0.9.3`, a stable release, because it defines the byte stream the firmware parses. And the crafting path is not a dry run: it is implemented, and its witness computation is tested offline against a real Ironwood anchor captured from a public testnet node. The README now says what the support is actually tested against instead.

Fix the two things the README got wrong about the package itself. It told readers to route the `@ledgerhq` scope to an internal registry, when the package is published on the public npm registry and `npm install` works unconfigured with no `.npmrc` entry at all. It also declared its license with a trailing editorial flourish rather than naming it plainly.

Replace the Ledger staging gRPC endpoint used as the example value throughout the public surface — `index.d.ts`, the CLI's `--grpc-url` help, `docs/ffi-node.md`, the runnable examples — with the public `https://testnet.zec.rocks:443`. The former host does not resolve outside Ledger's network, so every published example was unusable by anyone outside it. Ledger's own nodes remain the defaults in the integration tests, which are Ledger's to run.
