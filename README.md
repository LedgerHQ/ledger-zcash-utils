# @ledgerhq/zcash-utils

Rust workspace for Zcash cryptographic operations. Provides key derivation,
shielded transaction decryption, and compact block scanning across multiple
runtime targets.

## Build targets

| Target | Script | Output |
|--------|--------|--------|
| Node.js / Electron | `./scripts/build-napi.sh` | `index.*.node` |
| Android | `./scripts/build-android.sh` | `dist/android/` |
| iOS | `./scripts/build-ios.sh` | `dist/ios/ZcashFFI.xcframework` |
| macOS CLI (universal) | `./scripts/build-cli-macos.sh` | `dist/ledger-zcash-cli-macos-universal` |
| Linux CLI (static) | `./scripts/build-cli-linux.sh` | `dist/ledger-zcash-cli-linux-x86_64` |

See [`docs/build-targets.md`](docs/build-targets.md) for prerequisites and details.

## Crate structure

```
zcash-crypto     Pure cryptographic logic (key derivation, trial/full decryption)
zcash-grpc       Async gRPC sync engine (lightwalletd / Zaino)
zcash-ffi-node   Node.js / Electron native addon (napi-rs)
zcash-ffi-mobile Android + iOS bindings (UniFFI)
zcash-cli        CLI binary (ledger-zcash-cli)
```

See [`docs/architecture.md`](docs/architecture.md) for the dependency graph and
design decisions.

## CLI usage

```bash
# Key derivation
ledger-zcash-cli derive --mnemonic "abandon abandon ... about" --format json

# Query chain tip
ledger-zcash-cli tip --grpc-url https://testnet.zec.rocks:443

# Scan a block range
ledger-zcash-cli sync \
    --grpc-url https://testnet.zec.rocks:443 \
    --viewing-key uviewtest1... \
    --start-height 280000 \
    --end-height 285000 \
    --network testnet \
    --format json
```

### `derive` options

```
--mnemonic <WORDS>      BIP-39 mnemonic (reads from stdin if omitted)
--account <N>           ZIP-32 account index [default: 0]
--xpub-path <PATH>      BIP-32 xpub path [default: m/44'/133'/{account}']
--network mainnet|testnet [default: mainnet]
--no-sapling            Exclude Sapling FVK from UFVK
--format human|json     [default: human]
```

## Development

```bash
# Run all logic tests
cargo test --package zcash-crypto

# Run CLI integration tests
cargo test --package zcash-cli

# Coverage (requires cargo install cargo-llvm-cov)
./scripts/coverage.sh

# Type-check everything
cargo check --workspace
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — workspace design
- [`docs/key-derivation.md`](docs/key-derivation.md) — BIP-39 → UFVK pipeline
- [`docs/block-sync.md`](docs/block-sync.md) — gRPC trial + full decryption
- [`docs/ffi-node.md`](docs/ffi-node.md) — Node.js/Electron integration
- [`docs/ffi-mobile.md`](docs/ffi-mobile.md) — Android/iOS UniFFI integration
- [`docs/build-targets.md`](docs/build-targets.md) — build scripts reference

## Release

Versioning is managed with [Changesets](https://github.com/changesets/action). Every merge to `main` triggers the CI workflow, which:

1. Builds all artifacts in parallel on their respective platforms
2. Either opens/updates a **"Version Packages"** PR if changesets are pending
3. Or publishes immediately if the "Version Packages" PR has already been merged

### Publishing a new version

```bash
# 1. Describe the change (patch / minor / major)
pnpm changeset

# 2. Commit the generated .changeset file and push
git add .changeset/
git commit -m "chore: add changeset"
git push

# 3. Merge the PR → CI automatically opens a "Version Packages" PR
# 4. Merge the "Version Packages" PR → CI publishes
```

### Artifacts produced per release

| Artifact | Distribution | Platforms |
|----------|-------------|-----------|
| `@ledgerhq/zcash-utils` | npm | All (bundled `.node` files) |
| `ledger-zcash-cli-macos-universal` | GitHub Release | macOS arm64 + x64 |
| `ledger-zcash-cli-linux-x86_64` | GitHub Release | Linux x64 (static musl) |

The `.node` binaries are built in a CI matrix for each OS/architecture target, collected in the publish job, and included in the npm package via the `files` field. The `index.js` NAPI-RS loader looks for a local `.node` file first, then falls back to a separate `@ledgerhq/zcash-utils-{platform}` package if needed.

CLI binaries are attached to the tagged GitHub Release (`v{version}`) and are not part of the npm package.

### Required secrets

| Secret | Purpose |
|--------|---------|
| `NPM_TOKEN` | npm authentication for `pnpm publish` |
| `GITHUB_TOKEN` | Automatically provided by GitHub Actions |

## License

MIT OR Apache-2.0
