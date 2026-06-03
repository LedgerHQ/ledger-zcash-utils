//! # zcash-sync
//!
//! Async sync engine that connects to a lightwalletd/Zaino node,
//! streams compact blocks, and decrypts transactions matching a given UFVK.
//!
//! This crate is the only crate in the workspace that depends on `tonic` and
//! `tokio`.
//!
//! ## Modules
//!
//! - [`client`]: gRPC channel management and low-level RPC helpers
//! - [`sync`]: High-level block range scanning and transaction decryption
//! - [`witness`]: On-demand Orchard Merkle witness computation (async orchestrator)

pub mod client;
pub mod sync;
pub mod witness;
