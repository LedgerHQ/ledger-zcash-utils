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

Versioning is managed with [Changesets](https://changesets.dev) v3, which needs Node.js `^22.11 || ^24 || >=26` locally. A release needs nothing but changesets: no hand-edited version, no manual tag.

### Publishing a new version

1. Each pull request carrying a user-visible change commits its changeset (`pnpm changeset`, see [Contributing workflow](#contributing-workflow)).
2. When it merges, the **Publish Release** workflow (`.github/workflows/publish-release.yml`) opens or updates a pull request titled **"release: version packages"**. It consumes the pending changesets: it bumps `package.json` and writes `CHANGELOG.md`. Further merges keep updating it.
3. Merging that pull request is the release. The workflow then:
   1. builds the `.node` binaries and the CLI binaries in parallel on their platforms;
   2. packs the package once (`changeset pack`);
   3. attests that exact tarball (SLSA provenance) with `LedgerHQ/actions-security`'s `attest-for-npmsjs-com`. The attestation is bound to the tarball bytes, which is why packing and publishing are separate steps;
   4. publishes that same tarball (`changeset publish --from-pack-dir`), pushes the `v{version}` tag, creates the GitHub Release and attaches the CLI binaries to it.

On each push to `main`, the workflow first selects a mode: `version` when changesets are pending, `publish` when `package.json` holds a version the registry does not have, and nothing otherwise. A re-run, or a manual run from the Actions tab, is therefore harmless: a version already on the registry is neither packed nor published again.

The bot's commits go through the GitHub API, so they are signed, and its pull request is reviewed and merged like any other. This requires the repository setting **Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"** to stay enabled. Because that pull request is opened with the workflow's own token, the build-and-test workflow does not run on it.

The publish job runs on `public-ledgerhq-shared-medium`. That runner is GitHub-hosted, which the attestation requires, and it can reach the IP-restricted JFrog registry. Do not move the job to a self-hosted runner.

### Artifacts produced per release

| Artifact                           | Distribution        | Platforms                   |
| ---------------------------------- | ------------------- | --------------------------- |
| `@ledgerhq/zcash-utils`            | Public npm registry | All (bundled `.node` files) |
| `ledger-zcash-cli-macos-universal` | GitHub Release      | macOS arm64 + x64           |
| `ledger-zcash-cli-linux-x86_64`    | GitHub Release      | Linux x64 (static musl)     |

The `.node` binaries are built in a CI matrix for each OS/architecture target, collected in the publish job, and included in the npm package via the `files` field. The `index.js` NAPI-RS loader looks for a local `.node` file first, then falls back to a separate `@ledgerhq/zcash-utils-{platform}` package if needed.

The package is published to Ledger's JFrog registry, which relays it to the **public npm registry** together with its attestation, so consumers need no registry configuration. The publish job authenticates through Ledger's release infrastructure via OIDC rather than a long-lived token, which is why no npm credential appears among the secrets below.

CLI binaries are attached to the tagged GitHub Release (`v{version}`) and are not part of the npm package.

### Required secrets and variables

| Secret / Variable              | Purpose                                                    |
| ------------------------------ | ---------------------------------------------------------- |
| `GITHUB_TOKEN`                 | Automatically provided by GitHub Actions                   |
| `vars.ARTIFACTORY_PUBLISH_URL` | Registry host the publish step targets, without `https://` |

## License

[Apache-2.0](LICENSE.md). Declared once in `[workspace.package]` of the root `Cargo.toml`, which the crates inherit, and mirrored in `package.json` for the npm package.
