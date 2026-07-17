# @ledgerhq/zcash-utils

## 1.0.2

### Patch Changes

- Fix find block height low boundary block number

# @ledgerhq/zcash-utils

## 1.0.1

### Patch Changes

- Recompute target height

# @ledgerhq/zcash-utils

## 1.0.0

### Major Changes

- NAPI function for parsePCZT

# @ledgerhq/zcash-utils

## 0.1.2

### Patch Changes

- Rework npm package README to document the Node.js NAPI API instead of the Rust workspace. Move workspace/development documentation to CONTRIBUTING.md.

## 0.1.1

### Patch Changes

- Expose `TransactionStream.cancel()` to abort a background scan immediately. Buffered transactions already sent by Rust remain consumable via `next()`.

## 0.1.0

### Initial Release

First public release of the Node.js (NAPI) addon for Zcash shielded transaction scanning.

- `startSync(params)` — scans a compact block range for shielded transactions using trial decryption entirely in Rust
- `getChainTip(grpcUrl)` — queries current chain tip height from a gRPC endpoint
- `TransactionStream` — async iterator over matched and fully-decrypted shielded transactions (`next()`, `stats()`)
- Pre-built `.node` binaries for macOS (arm64, x64), Linux (x64, arm64), and Windows (x64, arm64)
- Orchard-only mode (`orchardOnly: true`) for Ledger wallets
