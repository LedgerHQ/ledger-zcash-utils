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
//! - [`craft`]: Build, prove, and serialize a PCZT for the Orchard send flows
//! - [`finalize`]: Inject device signatures into a PCZT and extract the final signed V5 transaction
//! - [`parse`]: Parse canonical PCZT bytes into a structured, device-signer-ready form

pub mod craft;
pub mod decrypt;
pub mod error;
pub mod finalize;
pub mod keys;
pub mod network;
pub mod parse;
pub mod tree;
