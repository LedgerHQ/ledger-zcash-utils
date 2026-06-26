# Architecture

## Overview

This repository is a Cargo workspace that provides Zcash cryptographic operations
across multiple targets: Node.js/Electron (napi-rs) and a standalone CLI.

## Crate dependency graph

```
zcash-crypto   (pure logic, no FFI, no network I/O)
    │
    └── zcash-sync          (async sync engine — tonic + tokio)
            │
            ├── zcash-ffi-node   (Node.js/Electron — napi-rs cdylib)
            └── zcash-cli        (CLI binary — clap)
```

## Crates

### `zcash-crypto` — the core

Pure Rust cryptographic operations. No FFI, no network I/O. Compiles for all
targets including iOS and Android.

Modules:
- `keys`: BIP-39 → ZIP-32 → UFVK + xpub key derivation
- `decrypt`: Compact block trial decryption and full transaction decryption
- `network`: Zcash network name parsing
- `error`: Unified `Error` enum (thiserror)

This is the only crate subject to the ≥90% test coverage requirement.

### `zcash-sync` — network layer

Async sync client for lightwalletd / Zaino. Converts proto `CompactTx` types
to `zcash-crypto`'s plain data types before calling trial/full decryption.

Depended on by `zcash-ffi-node` and `zcash-cli` for all gRPC operations.

### `zcash-ffi-node` — Node.js/Electron binding

Thin napi-rs `cdylib` wrapper. Exports to JavaScript:
- `startSync(params)` — starts an async block range scan; returns a `TransactionStream`
- `getChainTip(grpcUrl)` — chain tip query
- `TransactionStream` class — async iterator (`next()`) + statistics (`stats()`)

### `zcash-cli` — CLI binary

`clap`-based binary with three subcommands:
- `derive` — key derivation
- `tip` — query chain tip height
- `sync` — block range scan with JSON or human output

## Design decisions

**Why split `zcash-crypto` and `zcash-sync`?**
Keeping tonic/tokio out of `zcash-crypto` ensures the core logic crate compiles
cleanly for every target without heavy networking dependencies. `zcash-sync`
adds gRPC transport on top of it. Both consumer crates (`zcash-ffi-node`, `zcash-cli`)
use `zcash-sync` for network I/O and `zcash-crypto` for pure logic.

**Why define custom compact tx types instead of using proto types?**
`zcash_client_backend`'s proto types require the `lightwalletd-tonic` feature
which pulls in tonic (gRPC framework) and tokio. Defining our own
`CompactTransaction` / `CompactSaplingOutput` / `CompactOrchardAction` types
in `zcash-crypto` keeps it free of these heavy dependencies.

## Adding a new feature

Example: adding an "craft Orchard transaction" function.

1. Implement the logic in `zcash-crypto/src/` (new module, e.g. `craft.rs`).
2. Export it from `zcash-crypto/src/lib.rs`.
3. Add a NAPI wrapper in `zcash-ffi-node/src/lib.rs`.
4. Add a CLI subcommand in `zcash-cli/src/main.rs` — unless the feature is
   device-coupled (see exception below), in which case justify the omission here.
5. Write tests in `zcash-crypto` (inline or in `tests/`).
6. Update `docs/` as needed.

The CLI is a developer/debugging surface for self-contained operations (key
derivation, chain queries, block scanning). It is not required for every
feature. A feature may skip step 4 when a standalone CLI invocation cannot
produce a useful result on its own — document the reason inline as below.

**Exception: the V5 PCZT builder (`craft`, `build_transaction`).**
The PCZT builder is intentionally not exposed via the CLI. It is device-coupled:
it requires a `seed_fingerprint` read from the Ledger device and produces a PCZT
whose sole purpose is to be APDU-streamed to and signed by that device. The CLI
cannot sign, so a CLI invocation would only yield an unsignable artifact.
Its per-spend inputs (`rho`/`rseed`/`cmx`/`position`/`nullifier`) and per-UTXO
pubkeys are produced by a prior `sync` run, not hand-entered. The builder is
therefore reachable only through `zcash-ffi-node`, its sole consumer.
