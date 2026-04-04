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
}
