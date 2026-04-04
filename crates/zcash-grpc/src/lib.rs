//! # zcash-grpc
//!
//! Async gRPC sync engine that connects to a lightwalletd/Zaino node,
//! streams compact blocks, and decrypts transactions matching a given UFVK.
//!
//! This crate is the only crate in the workspace that depends on `tonic` and
//! `tokio`. It is **not** a dependency of `zcash-ffi-mobile` — mobile targets
//! manage their own network transport and call `zcash-crypto` directly.
//!
//! ## Modules
//!
//! - [`client`]: gRPC channel management and low-level RPC helpers
//! - [`sync`]: High-level block range scanning and transaction decryption

pub mod client;
pub mod sync;
