# ledger-zcash-utils

Rust utilities for Zcash key management, used in Ledger Live integration testing.

## Crates

| Crate                                          | Description                                             |
| ---------------------------------------------- | ------------------------------------------------------- |
| [`zcash-key-derive`](crates/zcash-key-derive/) | Derive UFVK and all viewing keys from a BIP-39 mnemonic |

---

## `zcash-key-derive`

Derives all Zcash viewing keys for a given account from a BIP-39 mnemonic:

- **UFVK** — Unified Full Viewing Key (ZIP-316, Bech32m)
- **xpub** — Transparent extended public key (BIP-32, Base58Check)
- **Sapling** — FVK / IVK / OVK (hex, external scope)
- **Orchard** — FVK / IVK / OVK (hex, external scope)

No spending key material is exposed.
Pass `--no-sapling` to omit the Sapling FVK from the generated UFVK while still deriving Sapling pool keys separately.

### Usage

```
zcash-key-derive [OPTIONS]

Options:
  --mnemonic <WORDS>      BIP-39 mnemonic phrase (reads from stdin if omitted)
  --account <N>           ZIP-32 account index [default: 0]
  --xpub-path <PATH>      BIP-32 path for transparent xpub [default: m/44'/133'/{account}']
  --network <NET>         mainnet | testnet [default: mainnet]
  --no-sapling            Exclude the Sapling FVK from the generated UFVK
  --format <FMT>          human | json [default: human]
  -h, --help
```

### Examples

```bash
# Derive keys for account 0, mainnet, human-readable output
zcash-key-derive --mnemonic "abandon abandon ... about"

# JSON output for account 1
zcash-key-derive --mnemonic "..." --account 1 --format json

# Testnet with custom transparent derivation path
zcash-key-derive --mnemonic "..." --network testnet --xpub-path "m/44'/133'/5'"

# Build a UFVK without the Sapling component
zcash-key-derive --mnemonic "..." --no-sapling

# Pipe mnemonic from a file
cat mnemonic.txt | zcash-key-derive --network testnet --format json
```

### Output (human format)

```
ufvk      : uview1...
xpub      : xpub6...
xpub path : m/44'/133'/0'
  sapling:
    fvk : <256 hex chars>
    ivk : <64 hex chars>
    ovk : <64 hex chars>
  orchard:
    fvk : <192 hex chars>
    ivk : <128 hex chars>
    ovk : <64 hex chars>
```

---

## Building

### macOS (universal binary — arm64 + x86_64)

Requires Rust toolchain (`rustup`) and Xcode command line tools. If Rust is not installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then build:

```bash
./scripts/build-macos.sh
# Binary: dist/zcash-key-derive-macos-universal
```

The output is a [universal binary](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary) that runs natively on both Apple Silicon (M1/M2/M3) and Intel Macs.

### Linux (via Docker)

Requires Docker. Produces a static `x86_64-unknown-linux-musl` binary:

```bash
./scripts/build-linux.sh
# Binary: dist/zcash-key-derive-linux-x86_64
```

---

## Development

```bash
# Run tests
cargo test

# Run tests with coverage (requires cargo-llvm-cov)
cargo llvm-cov --summary-only

# Run the binary directly
cargo run --bin zcash-key-derive -- --mnemonic "..." --format json
```

---

## License

MIT
