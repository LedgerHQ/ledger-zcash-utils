# @ledgerhq/zcash-utils

Rust workspace for Zcash cryptographic operations. Provides key derivation, shielded transaction decryption, and compact block scanning across multiple runtime targets.

## Build targets

| Target                | Script                         | Output                                  |
| --------------------- | ------------------------------ | --------------------------------------- |
| Node.js / Electron    | `./scripts/build-napi.sh`      | `index.*.node`                          |
| macOS CLI (universal) | `./scripts/build-cli-macos.sh` | `dist/ledger-zcash-cli-macos-universal` |
| Linux CLI (static)    | `./scripts/build-cli-linux.sh` | `dist/ledger-zcash-cli-linux-x86_64`    |

See [`docs/build-targets.md`](docs/build-targets.md) for prerequisites and details.

## Crate structure

```
zcash-crypto     Pure cryptographic logic (key derivation, trial/full decryption)
zcash-sync       Async sync engine (lightwalletd / Zaino)
zcash-ffi-node   Node.js / Electron native addon (napi-rs)
zcash-cli        CLI binary (ledger-zcash-cli)
```

See [`docs/architecture.md`](docs/architecture.md) for the dependency graph and design decisions.

## CLI usage

```bash
# Key derivation
ledger-zcash-cli derive --mnemonic "abandon abandon ... about" --format json

# Query chain tip
ledger-zcash-cli tip --grpc-url https://zaino-zec-testnet.nodes.stg.ledger-test.com/

# Scan a block range
ledger-zcash-cli sync \
    --grpc-url https://zaino-zec-testnet.nodes.stg.ledger-test.com/ \
    --viewing-key uviewtest1... \
    --start-height 280000 \
    --end-height 285000 \
    --network testnet \
    --format json
```

`derive` prints the UFVK, the multi-receiver unified address, the transparent xpub, and per-pool (Sapling + Orchard) FVK/IVK/OVK. No spending key material is ever exposed.

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

# Check markdown formatting (CI runs this too)
pnpm format:check
```

`pnpm format` rewrites the markdown in place. `.prettierrc` holds the style, `.prettierignore` the exclusions.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — workspace design
- [`docs/key-derivation.md`](docs/key-derivation.md) — BIP-39 → UFVK pipeline
- [`docs/block-sync.md`](docs/block-sync.md) — gRPC trial + full decryption
- [`docs/ffi-node.md`](docs/ffi-node.md) — Node.js/Electron integration
- [`docs/build-targets.md`](docs/build-targets.md) — build scripts reference

## Contributing workflow

Branch off `main`. Names are lowercase and hyphen-separated, prefixed with the same type word the commits will use; when the work has a JIRA ticket, its number follows that prefix:

```
feat/live-35017-transaction-details    # with a ticket
fix/zero-anchor                        # without
release/2.2.0                          # version bump
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) — `type(scope): subject`. No CI check validates the format: it holds by review, so match the surrounding history (`git log --oneline`) when in doubt.

`type` is one of `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, or `release` for a version bump. `scope` is optional and names either a crate (`zcash-crypto`, `zcash-sync`, `zcash-ffi-node`, `zcash-cli`) or the area touched (`craft`, `broadcast`, `ironwood`, `ci`, `deps`). The subject is lowercase and imperative with no trailing period, and the body carries why the change is needed and what it implies — the reasoning a diff cannot show, which most non-trivial commits here do have.

```
fix(craft): reject a build with no account key up front
feat: surface the Ironwood bundle from parsePczt
release: 2.2.0
```

Commits must be signed; a branch ruleset on `main` rejects unsigned ones. Do not work around it by disabling signing.

Open the pull request against `main` — it needs one approval to merge, and an extra one if it contains changes GitHub cannot attribute to an identified author. Title it like a commit subject; the JIRA key may be appended in brackets (`feat(craft): … [LIVE-36260]`) but is not required. A user-visible change also needs a changeset (see [Release](#release)).

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

| Artifact                           | Distribution       | Platforms                   |
| ---------------------------------- | ------------------ | --------------------------- |
| `@ledgerhq/zcash-utils`            | Ledger JFrog (npm) | All (bundled `.node` files) |
| `ledger-zcash-cli-macos-universal` | GitHub Release     | macOS arm64 + x64           |
| `ledger-zcash-cli-linux-x86_64`    | GitHub Release     | Linux x64 (static musl)     |

The `.node` binaries are built in a CI matrix for each OS/architecture target, collected in the publish job, and included in the npm package via the `files` field. The `index.js` NAPI-RS loader looks for a local `.node` file first, then falls back to a separate `@ledgerhq/zcash-utils-{platform}` package if needed.

The npm package is published to the internal Ledger JFrog Artifactory registry. The CI authenticates via OIDC (`LedgerHQ/actions-security/actions/jfrog-login`) and configures `.npmrc` to route `@ledgerhq` scoped packages to the Artifactory URL.

CLI binaries are attached to the tagged GitHub Release (`v{version}`) and are not part of the npm package.

### Required secrets and variables

| Secret / Variable              | Purpose                                             |
| ------------------------------ | --------------------------------------------------- |
| `GITHUB_TOKEN`                 | Automatically provided by GitHub Actions            |
| `vars.ARTIFACTORY_PUBLISH_URL` | JFrog Artifactory registry URL (without `https://`) |

## License

MIT OR Apache-2.0
