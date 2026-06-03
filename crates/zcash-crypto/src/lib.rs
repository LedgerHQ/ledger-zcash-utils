//! # zcash-crypto
//!
//! Pure Zcash cryptographic operations with no FFI and no network I/O.
//! This crate is the shared foundation used by `zcash-ffi-node` and the CLI (`zcash-cli`).
//!
//! ## Modules
//!
//! - [`keys`]: BIP-39 mnemonic → UFVK + xpub key derivation (ZIP-32 / BIP-32 / BIP-44)
//! - [`decrypt`]: Compact block trial decryption and full transaction decryption
//! - [`network`]: Zcash network name parsing utilities
//! - [`error`]: Unified error type for all operations in this crate
//! - [`tree`]: On-demand Orchard ShardTree assembly and Merkle witness extraction

pub mod decrypt;
pub mod error;
pub mod keys;
pub mod network;
pub mod tree;
