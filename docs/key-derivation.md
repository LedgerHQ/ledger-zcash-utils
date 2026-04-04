# Key Derivation

## Overview

`zcash-crypto::keys` derives all Zcash viewing keys for a given account from
a BIP-39 mnemonic. No spending key material is returned.

## Derivation pipeline

```
BIP-39 mnemonic (12 or 24 words)
        │
        ▼ Mnemonic::parse() + to_seed("")
    512-byte seed
        │
        ├─── ZIP-32 path ──────────────────────────────────────────────────────►
        │     UnifiedSpendingKey::from_seed(network, seed, account_id)
        │         └─► to_unified_full_viewing_key()
        │                 ├─► ufvk_obj.encode(network) → UFVK (Bech32m)
        │                 ├─► ufvk_obj.sapling() → SaplingDFVK → fvk / ivk / ovk (hex)
        │                 └─► ufvk_obj.orchard() → OrchardFVK → fvk / ivk / ovk (hex)
        │
        └─── BIP-32 path ──────────────────────────────────────────────────────►
              Xpriv::new_master(network, seed)
              .derive_priv(path)    path = m/44'/133'/{account}'
              Xpub::from_priv(...)  → xpub (Base58Check)
```

## Key formats

| Key | Format | Size | Reveals |
|-----|--------|------|---------|
| UFVK | Bech32m (`uview1` / `uviewtest1`) | ~300 chars | all transactions (in + out) |
| xpub | Base58Check (`xpub` / `tpub`) | 111 chars | transparent addresses |
| Sapling FVK | hex | 256 hex chars (128 bytes) | all Sapling txs |
| Sapling IVK | hex | 64 hex chars (32 bytes) | incoming Sapling only |
| Sapling OVK | hex | 64 hex chars (32 bytes) | outgoing Sapling only |
| Orchard FVK | hex | 192 hex chars (96 bytes) | all Orchard txs |
| Orchard IVK | hex | 128 hex chars (64 bytes) | incoming Orchard only |
| Orchard OVK | hex | 64 hex chars (32 bytes) | outgoing Orchard only |

## UFVK composition (ZIP-316)

The UFVK bundles multiple pool FVKs in a single Bech32m string. By default it
includes: transparent (P2PKH), Sapling, and Orchard. Sapling can be excluded
via `DeriveOptions { include_sapling_in_ufvk: false }` (e.g. for wallets that
have migrated fully to Orchard).

## Known test vector

```
mnemonic : "abandon abandon ... about" (standard BIP-39 test vector)
account  : 0
network  : mainnet
→ ufvk   : uview1...
→ xpub   : xpub...
→ xpub_path : m/44'/133'/0'
```

Alice testnet account (used in integration tests):
```
mnemonic : "wish puppy smile loan doll ..."
account  : 0
network  : testnet
→ ufvk   : uviewtest1eacc7lytmvgp0s...
→ xpub   : tpubDDpDzVtfYFxaQ2nz9...
```

## API

```rust
// Simple: uses DeriveOptions::default() (Sapling included in UFVK)
pub fn derive_keys(
    mnemonic: &str,
    account: u32,
    network: ZcashNetwork,
    xpub_path: Option<&str>,
) -> Result<DerivedKeys, Error>;

// Advanced: full control over UFVK composition
pub fn derive_keys_with_options(
    mnemonic: &str,
    account: u32,
    network: ZcashNetwork,
    xpub_path: Option<&str>,
    options: DeriveOptions,
) -> Result<DerivedKeys, Error>;
```
