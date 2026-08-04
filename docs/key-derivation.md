# Key Derivation

## Overview

`zcash-crypto::keys` derives all Zcash viewing keys — and the default
receiving address — for a given account from a BIP-39 mnemonic. No spending
key material is returned.

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
        │                 ├─► ufvk_obj.orchard() → OrchardFVK → fvk / ivk / ovk (hex)
        │                 └─► ufvk_obj.default_address(AllAvailableKeys) → multi-receiver unified address (Bech32m)
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
| Multi-receiver unified address | Bech32m (`u1` / `utest1`) | ~120 chars | nothing (public, all receivers) |
| Orchard-only unified address | Bech32m (`u1` / `utest1`) | ~106 chars | nothing (public, Orchard receiver only) |
| xpub | Base58Check (`xpub` / `tpub`) | 111 chars | transparent addresses |
| Sapling FVK | hex | 256 hex chars (128 bytes) | all Sapling txs |
| Sapling IVK | hex | 64 hex chars (32 bytes) | incoming Sapling only |
| Sapling OVK | hex | 64 hex chars (32 bytes) | outgoing Sapling only |
| Orchard FVK | hex | 192 hex chars (96 bytes) | all Orchard txs |
| Orchard IVK | hex | 128 hex chars (64 bytes) | incoming Orchard only |
| Orchard OVK | hex | 64 hex chars (32 bytes) | outgoing Orchard only |

## Unified addresses — two distinct variants

There are two different unified addresses produced by this library. They have
different receiver sets and are **not interchangeable**.

### `DerivedKeys::multi_receiver_unified_address` (derive_keys output)

Derived via `UnifiedAddress::default_address(AllAvailableKeys)` — includes
every receiver the UFVK can produce (Orchard + Sapling, or Orchard + Sapling +
transparent depending on the UFVK composition). Around 120 chars (`u1…`).
It is independent of `DeriveOptions.include_sapling_in_ufvk`, which only
controls what's bundled into the encoded UFVK *string*, not the in-memory
viewing key object. **This address is NOT what the Ledger device shows on the
Receive screen** — the device derives an Orchard-only address.

### `orchard_address_from_ufvk(ufvk_str)` (standalone function)

Takes an encoded UFVK string (`uview1…`) and returns an Orchard-only unified
address — a `UnifiedAddress` with only an Orchard receiver, no Sapling, no
transparent. Around 106 chars (`u1…`). This matches exactly what the Zcash
Ledger app derives internally when `GetShieldedAddress` is called (INS 0x51),
so it is the correct address to display on the Receive screen and to verify
against the device.

Use this function when you need to show the user their shielded receive address
without having the device connected.

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
→ ufvk    : uview1...
→ address : u1...
→ xpub    : xpub...
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

// Derive the Orchard-only unified address from a persisted UFVK string.
// Returns the same address the Ledger device shows on the Receive screen.
// Errors: InvalidUfvk (bad encoding), NoOrchardReceiver (no Orchard component),
//         or UnsupportedNetwork (regtest UFVKs are rejected).
pub fn orchard_address_from_ufvk(ufvk_str: &str) -> Result<String, Error>;
```

NAPI (Node.js) exposure:
```ts
// From @ledgerhq/zcash-utils
orchardAddressFromUfvk(ufvk: string): string
```
