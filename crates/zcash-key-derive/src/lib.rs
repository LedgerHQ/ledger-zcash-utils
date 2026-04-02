mod error;
pub use error::Error;

use bip39::Mnemonic;
use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    NetworkKind,
};
use orchard::keys::{FullViewingKey as OrchardFvk, Scope as OrchardScope};
use sapling_crypto::zip32::DiversifiableFullViewingKey as SaplingDfvk;
use zcash_address::unified::{Container, Encoding, Fvk, Ufvk};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network as ZcashConsensusNetwork;
use zip32::{AccountId, Scope};

/// Which Zcash network to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZcashNetwork {
    Mainnet,
    Testnet,
}

/// Viewing keys for a single shielded pool (Sapling or Orchard), hex-encoded.
///
/// All keys use **external scope** (receiving / payment-facing side).
/// Internal scope (change addresses) is omitted — not needed for watch-only use.
#[derive(Debug, Clone)]
pub struct PoolViewingKeys {
    /// Full Viewing Key — reveals all transactions (in + out).
    pub fvk: String,
    /// Incoming Viewing Key — reveals only incoming transactions.
    pub ivk: String,
    /// Outgoing Viewing Key — reveals only outgoing transactions.
    pub ovk: String,
}

/// All keys derived from a BIP-39 mnemonic for a given Zcash account.
#[derive(Debug, Clone)]
pub struct DerivedKeys {
    /// Bech32m Unified Full Viewing Key (HRP "uview1" / "uviewtest1").
    /// Bundles transparent + Orchard FVKs, and Sapling by default, per ZIP-316.
    pub ufvk: String,
    /// BIP-32 transparent extended public key (Base58Check).
    pub xpub: String,
    /// BIP-32 path used for xpub derivation.
    pub xpub_path: String,
    /// Sapling pool viewing keys (None if not available for this account).
    pub sapling: Option<PoolViewingKeys>,
    /// Orchard pool viewing keys (None if not available for this account).
    pub orchard: Option<PoolViewingKeys>,
}

/// Options that control UFVK composition during key derivation.
#[derive(Debug, Clone, Copy)]
pub struct DeriveOptions {
    /// Whether to include the Sapling FVK inside the generated UFVK.
    pub include_sapling_in_ufvk: bool,
}

impl Default for DeriveOptions {
    fn default() -> Self {
        Self {
            include_sapling_in_ufvk: true,
        }
    }
}

fn extract_sapling(dfvk: &SaplingDfvk) -> PoolViewingKeys {
    // FVK: 128 bytes (ak || nk || ovk || dk)
    let fvk = hex::encode(dfvk.to_bytes());
    // IVK (external scope): 32-byte jubjub scalar
    let ivk = hex::encode(dfvk.to_ivk(Scope::External).to_repr());
    // OVK (external scope): 32-byte raw key
    let ovk = hex::encode(dfvk.to_ovk(Scope::External).0);
    PoolViewingKeys { fvk, ivk, ovk }
}

fn extract_orchard(fvk: &OrchardFvk) -> PoolViewingKeys {
    // FVK: 96 bytes
    let fvk_hex = hex::encode(fvk.to_bytes());
    // IVK (external scope): 64 bytes
    let ivk = hex::encode(fvk.to_ivk(OrchardScope::External).to_bytes());
    // OVK (external scope): 32 bytes
    let ovk = hex::encode(fvk.to_ovk(OrchardScope::External).as_ref());
    PoolViewingKeys {
        fvk: fvk_hex,
        ivk,
        ovk,
    }
}

/// Derive all viewing keys from a BIP-39 mnemonic.
///
/// - `account`: ZIP-32 account index — controls UFVK and default xpub path.
/// - `xpub_path`: optional explicit BIP-32 path for the transparent xpub.
///   Defaults to `m/44'/133'/{account}'`.
///
/// # Security
/// No spending key material is returned. The UFVK and per-pool FVKs reveal
/// the full transaction history of the account. Share IVK for incoming-only
/// visibility, OVK for proving outgoing payments.
pub fn derive_keys(
    mnemonic: &str,
    account: u32,
    network: ZcashNetwork,
    xpub_path: Option<&str>,
) -> Result<DerivedKeys, Error> {
    derive_keys_with_options(
        mnemonic,
        account,
        network,
        xpub_path,
        DeriveOptions::default(),
    )
}

/// Derive all viewing keys from a BIP-39 mnemonic with UFVK composition options.
pub fn derive_keys_with_options(
    mnemonic: &str,
    account: u32,
    network: ZcashNetwork,
    xpub_path: Option<&str>,
    options: DeriveOptions,
) -> Result<DerivedKeys, Error> {
    let mnemonic = Mnemonic::parse(mnemonic)?;
    let seed = mnemonic.to_seed("");

    let (zcash_net, btc_network_kind) = match network {
        ZcashNetwork::Mainnet => (ZcashConsensusNetwork::MainNetwork, NetworkKind::Main),
        ZcashNetwork::Testnet => (ZcashConsensusNetwork::TestNetwork, NetworkKind::Test),
    };

    // --- UFVK via ZIP-32 ---
    let account_id = AccountId::try_from(account)
        .map_err(|_| Error::Derivation(format!("account index {account} exceeds ZIP-32 range")))?;
    let usk = UnifiedSpendingKey::from_seed(&zcash_net, &seed, account_id)
        .map_err(|e| Error::Derivation(format!("{e:?}")))?;
    let ufvk_obj = usk.to_unified_full_viewing_key();
    let ufvk = if options.include_sapling_in_ufvk {
        ufvk_obj.encode(&zcash_net)
    } else {
        let (ufvk_net, ufvk_container) = Ufvk::decode(&ufvk_obj.encode(&zcash_net))
            .map_err(|e| Error::Derivation(format!("failed to parse generated UFVK: {e}")))?;
        let filtered_items = ufvk_container
            .items_as_parsed()
            .iter()
            .filter(|item| !matches!(item, Fvk::Sapling(_)))
            .cloned()
            .collect();
        Ufvk::try_from_items(filtered_items)
            .map(|ufvk| ufvk.encode(&ufvk_net))
            .map_err(|e| {
                Error::Derivation(format!("failed to rebuild UFVK without sapling: {e}"))
            })?
    };

    // --- Pool-specific viewing keys ---
    let sapling = ufvk_obj.sapling().map(extract_sapling);
    let orchard = ufvk_obj.orchard().map(extract_orchard);

    // --- Transparent xpub via BIP-32 ---
    let resolved_path = match xpub_path {
        Some(p) => p.to_string(),
        None => format!("m/44'/133'/{account}'"),
    };
    let path: DerivationPath = resolved_path.parse().map_err(|e: bitcoin::bip32::Error| {
        Error::Derivation(format!("invalid path '{resolved_path}': {e}"))
    })?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let root = Xpriv::new_master(btc_network_kind, &seed)?;
    let account_xprv = root.derive_priv(&secp, &path)?;
    let xpub = Xpub::from_priv(&secp, &account_xprv).to_string();

    Ok(DerivedKeys {
        ufvk,
        xpub,
        xpub_path: resolved_path,
        sapling,
        orchard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const ALICE_MNEMONIC: &str =
        "wish puppy smile loan doll curve hole maze file ginger hair nose key relax knife witness cannon grab despair throw review deal slush frame";

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let result = derive_keys(
            "not a valid bip39 mnemonic phrase",
            0,
            ZcashNetwork::Mainnet,
            None,
        );
        assert!(matches!(result, Err(Error::Mnemonic(_))));
    }

    #[test]
    fn test_invalid_path_rejected() {
        let result = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, Some("not/a/path"));
        assert!(matches!(result, Err(Error::Derivation(_))));
    }

    #[test]
    fn test_mainnet_key_prefixes() {
        let keys = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        assert!(keys.ufvk.starts_with("uview1"), "got: {}", keys.ufvk);
        assert!(keys.xpub.starts_with("xpub"), "got: {}", keys.xpub);
        assert_eq!(keys.xpub_path, "m/44'/133'/0'");
    }

    #[test]
    fn test_testnet_key_prefixes() {
        let keys = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Testnet, None).unwrap();
        assert!(keys.ufvk.starts_with("uviewtest1"), "got: {}", keys.ufvk);
        assert!(keys.xpub.starts_with("tpub"), "got: {}", keys.xpub);
    }

    #[test]
    fn test_pool_keys_present() {
        let keys = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let sapling = keys
            .sapling
            .as_ref()
            .expect("sapling keys should be present");
        let orchard = keys
            .orchard
            .as_ref()
            .expect("orchard keys should be present");
        // Sapling: fvk=128B, ivk=32B, ovk=32B
        assert_eq!(
            sapling.fvk.len(),
            256,
            "sapling fvk should be 128 bytes hex"
        );
        assert_eq!(sapling.ivk.len(), 64, "sapling ivk should be 32 bytes hex");
        assert_eq!(sapling.ovk.len(), 64, "sapling ovk should be 32 bytes hex");
        // Orchard: fvk=96B, ivk=64B, ovk=32B
        assert_eq!(orchard.fvk.len(), 192, "orchard fvk should be 96 bytes hex");
        assert_eq!(orchard.ivk.len(), 128, "orchard ivk should be 64 bytes hex");
        assert_eq!(orchard.ovk.len(), 64, "orchard ovk should be 32 bytes hex");
    }

    #[test]
    fn test_pool_keys_differ_across_accounts() {
        let k0 = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let k1 = derive_keys(KNOWN_MNEMONIC, 1, ZcashNetwork::Mainnet, None).unwrap();
        let s0 = k0.sapling.as_ref().unwrap();
        let s1 = k1.sapling.as_ref().unwrap();
        assert_ne!(s0.fvk, s1.fvk);
        assert_ne!(s0.ivk, s1.ivk);
    }

    #[test]
    fn test_pool_keys_deterministic() {
        let ka = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let kb = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        assert_eq!(
            ka.sapling.as_ref().unwrap().fvk,
            kb.sapling.as_ref().unwrap().fvk
        );
        assert_eq!(
            ka.orchard.as_ref().unwrap().ivk,
            kb.orchard.as_ref().unwrap().ivk
        );
    }

    #[test]
    fn test_alice_testnet_known_vectors() {
        let keys = derive_keys(ALICE_MNEMONIC, 0, ZcashNetwork::Testnet, None).unwrap();
        assert_eq!(
            keys.ufvk,
            "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr",
        );
        assert_eq!(
            keys.xpub,
            "tpubDDpDzVtfYFxaQ2nz9EpgviZ2wwezS1oFBDVDNUdZsmmACrgt3rnqxxLeq6JSi4w3pnmFaSVMGbpcH2oard5QfY8RpNK3qPXqAKfwRhShZFA",
        );
        // Pool keys should be present and non-empty
        assert!(keys.sapling.is_some());
        assert!(keys.orchard.is_some());
    }

    #[test]
    fn test_explicit_path_overrides_account() {
        let default = derive_keys(KNOWN_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let custom = derive_keys(
            KNOWN_MNEMONIC,
            0,
            ZcashNetwork::Mainnet,
            Some("m/44'/133'/5'"),
        )
        .unwrap();
        assert_eq!(default.ufvk, custom.ufvk);
        assert_ne!(default.xpub, custom.xpub);
        assert_eq!(custom.xpub_path, "m/44'/133'/5'");
    }

    #[test]
    fn test_ufvk_can_exclude_sapling_component() {
        let keys = derive_keys_with_options(
            KNOWN_MNEMONIC,
            0,
            ZcashNetwork::Mainnet,
            None,
            DeriveOptions {
                include_sapling_in_ufvk: false,
            },
        )
        .unwrap();

        let (_, ufvk) = Ufvk::decode(&keys.ufvk).unwrap();
        let items = ufvk.items();

        assert!(items.iter().any(|item| matches!(item, Fvk::Orchard(_))));
        assert!(items.iter().any(|item| matches!(item, Fvk::P2pkh(_))));
        assert!(!items.iter().any(|item| matches!(item, Fvk::Sapling(_))));
        assert!(
            keys.sapling.is_some(),
            "sapling pool keys should still be derived"
        );
    }
}
