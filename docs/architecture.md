# Architecture

## Overview

This repository is a Cargo workspace that provides Zcash cryptographic operations
across multiple targets: Node.js/Electron (napi-rs), Android (UniFFI/Kotlin),
iOS (UniFFI/Swift), and a standalone CLI.

## Crate dependency graph

```
zcash-crypto   (pure logic, no FFI, no network I/O)
    │
    └── zcash-grpc          (async gRPC engine — tonic + tokio)
            │
            ├── zcash-ffi-node   (Node.js/Electron — napi-rs cdylib)
            ├── zcash-ffi-mobile (Android + iOS — UniFFI cdylib/staticlib)
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

### `zcash-grpc` — network layer

Async gRPC client for lightwalletd / Zaino. Converts proto `CompactTx` types
to `zcash-crypto`'s plain data types before calling trial/full decryption.

Depended on by `zcash-ffi-mobile`, `zcash-ffi-node`, and `zcash-cli` for all
gRPC operations.

### `zcash-ffi-node` — Node.js/Electron binding

Thin napi-rs `cdylib` wrapper. Exports three async functions to JavaScript:
- `deriveKeys(params)` — key derivation
- `syncShielded(params)` — block range scan
- `getChainTip(grpcUrl)` — chain tip query

### `zcash-ffi-mobile` — Android + iOS binding

UniFFI `cdylib` (Android JNI) + `staticlib` (iOS XCFramework). Depends on
`zcash-crypto` and `zcash-grpc` (tokio runtime is created internally via
`Runtime::block_on` — the calling thread blocks for the duration of the sync).

The interface is defined in `src/zcash.udl` (UDL approach chosen over proc
macros to keep `zcash-crypto` free of UniFFI dependencies and to make the
interface contract explicit and independently versioned).

Exposed functions: `deriveZcashKeys`, `deriveZcashKeysWithOptions`,
`prepareIvksFromUfvk`, `trialDecryptCompactTxs`, `fullDecryptTransaction`,
`syncShielded`, `getChainTip`.

### `zcash-cli` — CLI binary

`clap`-based binary with three subcommands:
- `derive` — key derivation
- `tip` — query chain tip height
- `sync` — block range scan with JSON or human output

## Design decisions

**Why split `zcash-crypto` and `zcash-grpc`?**
Keeping tonic/tokio out of `zcash-crypto` ensures the core logic crate compiles
cleanly for every target without heavy networking dependencies. `zcash-grpc`
adds gRPC on top of it. All three consumer crates (`zcash-ffi-node`,
`zcash-ffi-mobile`, `zcash-cli`) use `zcash-grpc` for network I/O and
`zcash-crypto` for pure logic.

**Why UDL for UniFFI instead of proc macros?**
Proc macros (`#[uniffi::export]`) would require annotating `zcash-crypto`
directly, introducing a UniFFI dependency into the core logic crate. The UDL
approach keeps `zcash-crypto` dependency-free of FFI concerns, and provides
an explicit, reviewable interface contract for Android/iOS consumers.

**Why define custom compact tx types instead of using proto types?**
`zcash_client_backend`'s proto types require the `lightwalletd-tonic` feature
which pulls in tonic (gRPC framework) and tokio. Defining our own
`CompactTransaction` / `CompactSaplingOutput` / `CompactOrchardAction` types
in `zcash-crypto` keeps it free of these heavy dependencies for mobile.

## Adding a new feature

Example: adding an "craft Orchard transaction" function.

1. Implement the logic in `zcash-crypto/src/` (new module, e.g. `craft.rs`).
2. Export it from `zcash-crypto/src/lib.rs`.
3. Add a NAPI wrapper in `zcash-ffi-node/src/lib.rs`.
4. Add a UDL entry in `zcash-ffi-mobile/src/zcash.udl` and implement it in
   `zcash-ffi-mobile/src/lib.rs`.
5. Add a CLI subcommand in `zcash-cli/src/main.rs`.
6. Write tests in `zcash-crypto` (inline or in `tests/`).
7. Update `docs/` as needed.
