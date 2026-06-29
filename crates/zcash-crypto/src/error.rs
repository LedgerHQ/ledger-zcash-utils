use thiserror::Error;

/// Unified error type for all `zcash-crypto` operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid BIP-39 mnemonic phrase.
    #[error("invalid mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),

    /// Key derivation failed (ZIP-32, BIP-44, or UFVK assembly).
    #[error("key derivation failed: {0}")]
    Derivation(String),

    /// BIP-32 path parsing or key derivation error.
    #[error("BIP-32 error: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// Cryptographic operation failed (UFVK parsing, transaction decryption, etc.)
    #[error("decrypt error: {0}")]
    Decrypt(String),

    // ── Witness / ShardTree errors ──
    /// Error produced by the underlying ShardTree store or query logic.
    #[error("shardtree error: {0}")]
    ShardTree(String),

    /// A 32-byte shard root hash does not represent a valid Pallas base-field element.
    #[error("invalid shard root for shard {shard_index}")]
    InvalidShardRoot { shard_index: u32 },

    /// A 32-byte cmx value does not represent a valid Pallas base-field element.
    #[error("invalid leaf bytes at position {position}")]
    InvalidLeaf { position: u64 },

    /// Failed to decode the Orchard commitment-tree frontier from its serialized form.
    #[error("orchard frontier decode failed: {0}")]
    FrontierDecode(String),

    /// The legacy CommitmentTree bytes were decoded but could not be converted to a Frontier
    /// (empty tree — no commitments yet is handled separately; this fires only on malformed data).
    #[error("orchard frontier is incomplete (legacy tree could not be converted)")]
    FrontierIncomplete,

    /// The ShardTree has no checkpoint corresponding to the requested anchor height.
    #[error("no checkpoint found for anchor height {anchor_height}")]
    NoCheckpointForAnchor { anchor_height: u32 },

    /// The computed Merkle-path root does not match the expected anchor.
    #[error("witness root mismatch at position {position}: expected {expected:?}, got {got:?}")]
    WitnessMismatch {
        position: u64,
        expected: [u8; 32],
        got: [u8; 32],
    },

    /// Transaction crafting failed (invalid note components, builder error,
    /// PCZT role error, proof generation failure, or insufficient funds).
    #[error("craft error: {0}")]
    Craft(String),

    /// Transaction finalization failed: PCZT parse/role error, signature
    /// rejected during injection, proof verification failure, or serialization error.
    #[error("finalize error: {0}")]
    Finalize(String),
}

impl Error {
    /// Converts a `ShardTreeError<E>` (generic store-error param) into the `ShardTree` variant
    /// by formatting via `Debug`. This avoids propagating the generic type parameter up the call
    /// stack while still capturing the full error description.
    pub(crate) fn shardtree<E: std::fmt::Debug>(e: shardtree::error::ShardTreeError<E>) -> Self {
        Self::ShardTree(format!("{e:?}"))
    }

    /// Converts an `io::Error` from frontier decoding into the `FrontierDecode` variant.
    pub(crate) fn frontier_decode(e: std::io::Error) -> Self {
        Self::FrontierDecode(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_error_display() {
        let e = Error::Derivation("something went wrong".to_string());
        assert_eq!(e.to_string(), "key derivation failed: something went wrong");
    }

    #[test]
    fn test_decrypt_error_display() {
        let e = Error::Decrypt("bad ciphertext".to_string());
        assert_eq!(e.to_string(), "decrypt error: bad ciphertext");
    }

    #[test]
    fn test_shard_tree_error_display() {
        let e = Error::ShardTree("store error".to_string());
        assert_eq!(e.to_string(), "shardtree error: store error");
    }

    #[test]
    fn test_invalid_shard_root_display() {
        let e = Error::InvalidShardRoot { shard_index: 42 };
        assert_eq!(e.to_string(), "invalid shard root for shard 42");
    }

    #[test]
    fn test_invalid_leaf_display() {
        let e = Error::InvalidLeaf { position: 99 };
        assert_eq!(e.to_string(), "invalid leaf bytes at position 99");
    }

    #[test]
    fn test_frontier_decode_display() {
        let e = Error::FrontierDecode("bad bytes".to_string());
        assert_eq!(e.to_string(), "orchard frontier decode failed: bad bytes");
    }

    #[test]
    fn test_frontier_incomplete_display() {
        let e = Error::FrontierIncomplete;
        assert_eq!(
            e.to_string(),
            "orchard frontier is incomplete (legacy tree could not be converted)"
        );
    }

    #[test]
    fn test_no_checkpoint_display() {
        let e = Error::NoCheckpointForAnchor {
            anchor_height: 1000,
        };
        assert_eq!(e.to_string(), "no checkpoint found for anchor height 1000");
    }

    #[test]
    fn test_craft_error_display() {
        let e = Error::Craft("bad anchor".into());
        assert_eq!(e.to_string(), "craft error: bad anchor");
    }

    #[test]
    fn test_finalize_error_display() {
        let e = Error::Finalize("PCZT parse failed".into());
        assert_eq!(e.to_string(), "finalize error: PCZT parse failed");
    }

    #[test]
    fn test_witness_mismatch_display() {
        let e = Error::WitnessMismatch {
            position: 5,
            expected: [0u8; 32],
            got: [1u8; 32],
        };
        let s = e.to_string();
        assert!(s.contains("witness root mismatch at position 5"));
    }

    #[test]
    fn test_frontier_decode_constructor() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let e = Error::frontier_decode(io_err);
        assert!(e.to_string().contains("orchard frontier decode failed"));
    }
}
