//! TEST-ONLY signing surface — never call from production wallet code.
//!
//! Holds and derives Orchard/transparent spending-key material directly from a
//! seed so that `ledger-live`'s coin-tester can act as a device stand-in in CI,
//! where no physical Ledger is available to sign against. Every function here
//! is compiled unconditionally into the crate (no `#[cfg(test)]`, no Cargo
//! feature) because the coin-tester calls it as an ordinary NAPI export at
//! runtime — segregation from production code is by module/function naming
//! and this warning, not by conditional compilation. The production host must
//! stay watch-only; never call anything in this module from a production
//! code path, and never add a spending-key parameter to a production export.

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::NetworkKind;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pczt::{
    roles::{signer::Signer as PcztSigner, updater::Updater},
    Pczt,
};
use secp256k1::{Message, Secp256k1};
use zcash_protocol::consensus::{Network as ZcashConsensusNetwork, NetworkConstants};
use zip32::AccountId;

use crate::error::Error;
use crate::keys::ZcashNetwork;

/// Derives the account UFVK and transparent xpub the test-only `test_derive_keys`
/// NAPI export returns. A thin, default-options wrapper over
/// [`crate::keys::derive_keys`], kept here (rather than inlined in
/// `zcash-ffi-node`, which is `test = false`) purely so the mapping is
/// unit-testable.
pub fn derive_ufvk_and_xpub(
    mnemonic: &str,
    account: u32,
    network: ZcashNetwork,
) -> Result<(String, String), Error> {
    let keys = crate::keys::derive_keys(mnemonic, account, network, None)?;
    Ok((keys.ufvk, keys.xpub))
}

/// Derives the ZIP-32 Orchard spending key for `(mnemonic, network, account)` —
/// the same underlying primitive `derive_keys_with_options` uses internally for
/// its UFVK's Orchard component (`zcash_keys::keys::UnifiedSpendingKey::from_seed`,
/// which calls `orchard::keys::SpendingKey::from_zip32_seed` with the same
/// seed/coin_type/account). Deriving here directly (instead of re-deriving
/// independently) guarantees the signer's `ask` always matches the UFVK this
/// same mnemonic/account produces.
pub fn derive_orchard_spending_key(
    mnemonic: &str,
    network: ZcashNetwork,
    account: u32,
) -> Result<SpendingKey, Error> {
    let seed = Mnemonic::parse(mnemonic)?.to_seed("");

    let consensus_network = match network {
        ZcashNetwork::Mainnet => ZcashConsensusNetwork::MainNetwork,
        ZcashNetwork::Testnet => ZcashConsensusNetwork::TestNetwork,
    };
    let coin_type = consensus_network.coin_type();

    let account_id = AccountId::try_from(account)
        .map_err(|_| Error::Derivation(format!("account index {account} exceeds ZIP-32 range")))?;

    SpendingKey::from_zip32_seed(&seed, coin_type, account_id)
        .map_err(|e| Error::Derivation(format!("Orchard spending key derivation failed: {e:?}")))
}

/// Derives the ZIP-32 Orchard spend-authorizing key (`ask`) for
/// `(mnemonic, network, account)` — the same key [`sign_pczt_orchard_actions`]
/// consumes. A thin conversion wrapper over [`derive_orchard_spending_key`],
/// kept here so the NAPI layer (`zcash-ffi-node`, which stays a thin
/// declarative binding layer) never needs to name an `orchard` crate type
/// directly.
pub fn derive_orchard_ask(
    mnemonic: &str,
    network: ZcashNetwork,
    account: u32,
) -> Result<SpendAuthorizingKey, Error> {
    let sk = derive_orchard_spending_key(mnemonic, network, account)?;
    Ok(SpendAuthorizingKey::from(&sk))
}

/// Converts a BIP-39 mnemonic into its raw seed bytes (empty passphrase), for
/// [`sign_pczt_transparent_inputs`]'s `seed` parameter. A thin wrapper over
/// `bip39::Mnemonic::parse`, kept here so the NAPI layer never needs `bip39`
/// as a direct dependency.
pub fn mnemonic_to_seed(mnemonic: &str) -> Result<Vec<u8>, Error> {
    Ok(Mnemonic::parse(mnemonic)?.to_seed("").to_vec())
}

/// One 64-byte RedPallas `spendAuthSig` per unsigned Orchard action, in
/// PCZT-action order. Empty `Vec` (not an error) when the PCZT carries no
/// Orchard bundle (e.g. a t→t PCZT).
///
/// Uses `pczt::roles::signer::Signer::sign_orchard` exactly as the private
/// `finalize.rs` test helper (`sign_unsigned_actions`) this is promoted from —
/// that call hardcodes `OsRng` upstream (pczt 0.9.3), so repeated calls with
/// the same `ask`/PCZT produce different, equally-valid signatures. That is
/// expected, not a bug: do not assert byte-identical signatures across calls.
///
/// # Errors
///
/// Returns [`Error::Finalize`] if the PCZT is malformed or any signing step
/// fails.
pub fn sign_pczt_orchard_actions(
    pczt_bytes: &[u8],
    ask: &SpendAuthorizingKey,
) -> Result<Vec<[u8; 64]>, Error> {
    let pczt = Pczt::parse(pczt_bytes)
        .map_err(|e| Error::Finalize(format!("PCZT parse failed: {e:?}")))?;

    // Real (unsigned) Orchard action indices, in order. Mirrors
    // `finalize::finalize_transaction`'s own identification of real spends.
    let unsigned_indices: Vec<usize> = pczt
        .orchard()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect();

    let mut signer =
        PcztSigner::new(pczt).map_err(|e| Error::Finalize(format!("Signer::new: {e:?}")))?;
    for idx in &unsigned_indices {
        signer
            .sign_orchard(*idx, ask)
            .map_err(|e| Error::Finalize(format!("sign_orchard(action {idx}): {e:?}")))?;
    }
    let signed_pczt = signer.finish();

    unsigned_indices
        .iter()
        .map(|idx| {
            signed_pczt.orchard().actions()[*idx]
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    Error::Finalize(format!("action {idx}: spend_auth_sig missing after signing"))
                })
        })
        .collect()
}

/// One 64-byte RedPallas `spendAuthSig` per unsigned Ironwood action, in
/// PCZT-action order. Empty `Vec` (not an error) when the PCZT carries no
/// Ironwood bundle (e.g. a V5/Orchard or transparent-only PCZT).
///
/// Mirrors [`sign_pczt_orchard_actions`] exactly, operating on
/// `pczt.ironwood()` / `Signer::sign_ironwood` instead of `.orchard()` /
/// `sign_orchard` — same `ask` type, same RedPallas math, same `OsRng`
/// caveat (do not assert byte-identical signatures across calls). Promoted
/// from `finalize.rs`'s private test helper `sign_unsigned_ironwood_actions`.
///
/// # Errors
///
/// Returns [`Error::Finalize`] if the PCZT is malformed or any signing step
/// fails.
pub fn sign_pczt_ironwood_actions(
    pczt_bytes: &[u8],
    ask: &SpendAuthorizingKey,
) -> Result<Vec<[u8; 64]>, Error> {
    let pczt = Pczt::parse(pczt_bytes)
        .map_err(|e| Error::Finalize(format!("PCZT parse failed: {e:?}")))?;

    // Real (unsigned) Ironwood action indices, in order. Mirrors
    // `finalize::finalize_transaction`'s own identification of real spends.
    let unsigned_indices: Vec<usize> = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect();

    let mut signer =
        PcztSigner::new(pczt).map_err(|e| Error::Finalize(format!("Signer::new: {e:?}")))?;
    for idx in &unsigned_indices {
        signer
            .sign_ironwood(*idx, ask)
            .map_err(|e| Error::Finalize(format!("sign_ironwood(action {idx}): {e:?}")))?;
    }
    let signed_pczt = signer.finish();

    unsigned_indices
        .iter()
        .map(|idx| {
            signed_pczt.ironwood().actions()[*idx]
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    Error::Finalize(format!("action {idx}: spend_auth_sig missing after signing"))
                })
        })
        .collect()
}

/// Extracts the single `bip32_derivation` path attached to a transparent
/// input, as raw ZIP-32/BIP-44 child indices (the hardened flag folded into
/// the u32, the same encoding `bitcoin::bip32::ChildNumber::from(u32)`
/// decodes). A signable transparent input carries exactly one entry — the
/// same precondition `craft::stamp_transparent_derivations` establishes when
/// building the PCZT and `parse::single_derivation` re-checks when parsing it.
///
/// Takes the fully-typed `zcash_transparent::pczt::Input` (reachable only
/// through the `Updater`/`Verifier` roles, not the crate's raw serialization
/// form `pczt::transparent::Input`, which has no `bip32_derivation` getter —
/// see the caller for how this is reached).
fn transparent_input_bip32_path(
    input: &zcash_transparent::pczt::Input,
) -> Result<DerivationPath, Error> {
    let derivations = input.bip32_derivation();
    match derivations.len() {
        1 => {
            let deriv = derivations.values().next().expect("len == 1");
            let child_numbers: Vec<ChildNumber> = deriv
                .derivation_path()
                .iter()
                .copied()
                .map(u32::from)
                .map(ChildNumber::from)
                .collect();
            Ok(DerivationPath::from(child_numbers))
        }
        n => Err(Error::Finalize(format!(
            "transparent input expected exactly 1 bip32_derivation entry, found {n}"
        ))),
    }
}

/// One DER-encoded secp256k1 signature per transparent input, in input order.
/// Empty `Vec` (not an error) when the PCZT carries no transparent inputs
/// (e.g. a pure z→z PCZT).
///
/// For each transparent input: reads its own `bip32_derivation` path from the
/// parsed PCZT, derives the leaf secp256k1 secret key via
/// `Xpriv::new_master(seed).derive_priv(&secp, &path)` (the same `Xpriv` /
/// `derive_priv` calls `keys::derive_keys_with_options` already makes for the
/// account-level xpub, carried one level deeper per-input), computes the
/// sighash via `Signer::transparent_sighash(index)`, and signs it with
/// `secp.sign_ecdsa` — matching the promoted `finalize.rs` test helper
/// (`valid_transparent_der_signature`)'s approach exactly. The resulting
/// signature structurally verifies against the pubkey derived at the input's
/// own `bip32_derivation` path, because the key IS derived from that path
/// rather than supplied separately.
///
/// # Errors
///
/// Returns [`Error::Finalize`] if the PCZT is malformed, a transparent input's
/// `bip32_derivation` is absent or ambiguous, or a signing step fails.
/// Returns [`Error::Bip32`] if the seed or the derivation path is invalid.
pub fn sign_pczt_transparent_inputs(
    pczt_bytes: &[u8],
    seed: &[u8],
    network: ZcashNetwork,
) -> Result<Vec<Vec<u8>>, Error> {
    let pczt = Pczt::parse(pczt_bytes)
        .map_err(|e| Error::Finalize(format!("PCZT parse failed: {e:?}")))?;

    let n_inputs = pczt.transparent().inputs().len();
    if n_inputs == 0 {
        return Ok(Vec::new());
    }

    let network_kind = match network {
        ZcashNetwork::Mainnet => NetworkKind::Main,
        ZcashNetwork::Testnet => NetworkKind::Test,
    };
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(network_kind, seed)?;

    // Read every input's `bip32_derivation` path via the `Updater` role
    // (read-only use: the closure mutates nothing before `.finish()`). This is
    // the only way to reach the fully-typed `zcash_transparent::pczt::Input`
    // and its `bip32_derivation()` getter — the crate's own raw serialization
    // form (what `pczt.transparent().inputs()` returns directly) exposes no
    // such getter. Mirrors `finalize::stamp_transparent_hash160_preimages`'s
    // use of the same role, and its pattern of capturing a domain error in an
    // outer slot because the closure's error type has no domain variant.
    let mut paths: Vec<DerivationPath> = Vec::with_capacity(n_inputs);
    let mut path_error: Option<Error> = None;
    let pczt = Updater::new(pczt)
        .update_transparent_with(|updater| {
            for input in updater.bundle().inputs() {
                match transparent_input_bip32_path(input) {
                    Ok(path) => paths.push(path),
                    Err(e) => {
                        path_error = Some(e);
                        return Ok(());
                    }
                }
            }
            Ok(())
        })
        .map_err(|e| Error::Finalize(format!("PCZT Updater (read bip32 derivation): {e:?}")))?
        .finish();
    if let Some(e) = path_error {
        return Err(e);
    }

    // Derive every input's leaf secret key before constructing the Signer,
    // which takes ownership of the PCZT.
    let secret_keys: Vec<secp256k1::SecretKey> = paths
        .iter()
        .map(|path| root.derive_priv(&secp, path).map(|leaf| leaf.private_key))
        .collect::<Result<_, _>>()?;

    let signer =
        PcztSigner::new(pczt).map_err(|e| Error::Finalize(format!("Signer::new: {e:?}")))?;

    secret_keys
        .iter()
        .enumerate()
        .map(|(index, sk)| {
            let sighash = signer
                .transparent_sighash(index)
                .map_err(|e| Error::Finalize(format!("transparent_sighash({index}): {e:?}")))?;
            let sig = secp.sign_ecdsa(&Message::from_digest(sighash), sk);
            Ok(sig.serialize_der().to_vec())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::craft::{
        build_transaction, BuildInputs, Destination, OrchardSpendInput, OutputRequest,
        TransparentInput,
    };
    use crate::finalize::{finalize_transaction, FinalizeInputs};
    use incrementalmerkletree::{Marking, Retention};
    use orchard::{
        keys::Scope,
        note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
        tree::MerkleHashOrchard,
        value::NoteValue,
    };
    use shardtree::{store::memory::MemoryShardStore, ShardTree};

    // ── helpers ──────────────────────────────────────────────────────────────

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_orchard_sk() -> SpendingKey {
        derive_orchard_spending_key(TEST_MNEMONIC, ZcashNetwork::Mainnet, 0)
            .expect("test_orchard_sk: derivation must succeed")
    }

    fn make_fvk() -> orchard::keys::FullViewingKey {
        orchard::keys::FullViewingKey::from(&test_orchard_sk())
    }

    fn make_ask() -> SpendAuthorizingKey {
        SpendAuthorizingKey::from(&test_orchard_sk())
    }

    fn nu5_height() -> u32 {
        1_687_105 // mainnet NU5 activation + 1
    }

    /// Mirrors `finalize.rs`'s `nu6_3_height` helper: read from
    /// `zcash_protocol`'s network parameters rather than hardcoded, so it
    /// tracks the crate rather than needing a manual edit if the height ever
    /// moves.
    fn nu6_3_height() -> u32 {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};
        let height = ZcashConsensusNetwork::MainNetwork
            .activation_height(NetworkUpgrade::Nu6_3)
            .expect("mainnet must define an NU6.3 activation height");
        u32::from(height) + 1
    }

    /// Build a one-leaf ShardTree containing `cmx`, returning `(anchor_bytes, path)`.
    fn synthetic_anchor_and_path(
        leaf: MerkleHashOrchard,
    ) -> (
        [u8; 32],
        incrementalmerkletree::MerklePath<MerkleHashOrchard, 32>,
    ) {
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let mp = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();
        (root.to_bytes(), mp)
    }

    /// Standard 25-byte P2PKH `scriptPubKey` paying to `hash`.
    fn make_p2pkh_script(hash: [u8; 20]) -> Vec<u8> {
        let mut s = Vec::with_capacity(25);
        s.push(0x76); // OP_DUP
        s.push(0xa9); // OP_HASH160
        s.push(0x14); // push 20 bytes
        s.extend_from_slice(&hash);
        s.push(0x88); // OP_EQUALVERIFY
        s.push(0xac); // OP_CHECKSIG
        s
    }

    /// HASH160 (RIPEMD160 ∘ SHA256) of a compressed pubkey.
    fn pubkey_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
        use bitcoin::hashes::{hash160, Hash};
        hash160::Hash::hash(pubkey).to_byte_array()
    }

    /// Build a proven PCZT (pure Orchard) with a single real spend. Returns the
    /// canonical PCZT bytes.
    fn build_orchard_pczt() -> Vec<u8> {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);

        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let spend_value: u64 = 20_000;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .into_option()
        .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let ovk = Some(fvk.to_ovk(Scope::External));

        let inputs = BuildInputs {
            network: zcash_protocol::consensus::Network::MainNetwork,
            target_height: nu5_height(),
            orchard_fvk: Some(fvk),
            ovk,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: spend_value - 10_000,
                memo: None,
            }],
        };
        build_transaction(inputs)
            .expect("build_orchard_pczt: build must succeed")
            .pczt_bytes
    }

    /// Build a proven Ironwood-only (V6) PCZT with a single real spend.
    /// Mirrors `finalize.rs`'s private `build_ironwood_pczt` test helper,
    /// using `craft::build_ironwood_transaction` instead of `build_transaction`.
    fn build_ironwood_pczt() -> Vec<u8> {
        use crate::craft::{
            build_ironwood_transaction, IronwoodBuildInputs, IronwoodDestination,
            IronwoodOutputRequest, IronwoodSpendInput,
        };

        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::External));

        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let fee: u64 = 10_000;
        let spend_value: u64 = 20_000;
        let out_value: u64 = spend_value - fee;

        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        let inputs = IronwoodBuildInputs {
            network: zcash_protocol::consensus::Network::MainNetwork,
            target_height: nu6_3_height(),
            ironwood_fvk: Some(fvk),
            ovk,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![IronwoodSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        };
        build_ironwood_transaction(inputs)
            .expect("build_ironwood_pczt: build must succeed")
            .pczt_bytes
    }

    /// Build a proven, pure-transparent (t→t) PCZT with no Orchard bundle at all.
    fn build_transparent_only_pczt() -> Vec<u8> {
        use bitcoin::hashes::{hash160, Hash};
        use secp256k1::{PublicKey, SecretKey};
        use zcash_transparent::address::TransparentAddress;

        let secp = Secp256k1::new();
        let t_sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let t_pubkey = PublicKey::from_secret_key(&secp, &t_sk).serialize();
        let in_value: u64 = 20_000;
        let fee: u64 = 10_000;
        let out_value = in_value - fee;

        let inputs = BuildInputs {
            network: zcash_protocol::consensus::Network::MainNetwork,
            target_height: nu5_height(),
            orchard_fvk: None,
            ovk: None,
            change_address: None,
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![TransparentInput {
                pubkey: t_pubkey,
                txid: [0x09u8; 32],
                vout: 0,
                script_pubkey: make_p2pkh_script(pubkey_hash160(&t_pubkey)),
                value: in_value,
                derivation_scope: 0,
                derivation_address_index: 0,
            }],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(TransparentAddress::PublicKeyHash(
                    hash160::Hash::hash(&[0x22u8; 33]).to_byte_array(),
                )),
                value: out_value,
                memo: None,
            }],
        };

        build_transaction(inputs)
            .expect("build_transparent_only_pczt: build must succeed")
            .pczt_bytes
    }

    /// Build a proven mixed PCZT (one real Orchard spend + one transparent
    /// P2PKH input controlled by a key derived from `TEST_MNEMONIC` at
    /// `m/44'/133'/0'/0/{address_index}` → one Orchard output). Returns the
    /// PCZT bytes and the transparent leaf secret key, so the test can verify
    /// the resulting signature independently of `sign_pczt_transparent_inputs`.
    fn build_mixed_pczt(address_index: u32) -> (Vec<u8>, secp256k1::SecretKey) {
        let secp = Secp256k1::new();
        let seed = Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("");
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(133).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(address_index).unwrap(),
        ]);
        let root = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
        let leaf = root.derive_priv(&secp, &path).unwrap();
        let t_sk = leaf.private_key;
        let t_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &t_sk).serialize();

        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);

        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let spend_value: u64 = 20_000;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .into_option()
        .unwrap();
        let leaf_hash = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, merkle_path) = synthetic_anchor_and_path(leaf_hash);
        let ovk = Some(fvk.to_ovk(Scope::External));

        let transparent_value: u64 = 15_000;
        let fee = 15_000u64;
        let out_value = 10_000u64;

        let inputs = BuildInputs {
            network: zcash_protocol::consensus::Network::MainNetwork,
            target_height: nu5_height(),
            orchard_fvk: Some(fvk.clone()),
            ovk,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path,
            }],
            transparent_inputs: vec![TransparentInput {
                pubkey: t_pubkey,
                txid: [0x09u8; 32],
                vout: 0,
                script_pubkey: make_p2pkh_script(pubkey_hash160(&t_pubkey)),
                value: transparent_value,
                derivation_scope: 0,
                derivation_address_index: address_index,
            }],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let pczt_bytes = build_transaction(inputs)
            .expect("build_mixed_pczt: build must succeed")
            .pczt_bytes;
        (pczt_bytes, t_sk)
    }

    // ── derive_ufvk_and_xpub ───────────────────────────────────────────────────

    /// The test-only derivation wrapper produces the same UFVK and xpub,
    /// byte-for-byte, as `keys::derive_keys` itself — `derive_keys`'s own tests
    /// already prove `derive_keys` is deterministic, so this only needs to
    /// prove the wrapper introduces no divergence (wrong param order, wrong
    /// network mapping, or an unintended xpub path).
    #[test]
    fn test_derive_keys_ufvk_matches_derive_keys() {
        let (ufvk, xpub) =
            derive_ufvk_and_xpub(TEST_MNEMONIC, 0, ZcashNetwork::Mainnet).unwrap();
        let reference = crate::keys::derive_keys(TEST_MNEMONIC, 0, ZcashNetwork::Mainnet, None)
            .expect("reference derive_keys must succeed");
        assert_eq!(ufvk, reference.ufvk, "UFVK must match derive_keys exactly");
        assert_eq!(xpub, reference.xpub, "xpub must match derive_keys exactly");
    }

    // ── derive_orchard_ask / mnemonic_to_seed ─────────────────────────────────

    #[test]
    fn test_derive_orchard_ask_matches_spending_key() {
        let ask = derive_orchard_ask(TEST_MNEMONIC, ZcashNetwork::Mainnet, 0)
            .expect("derive_orchard_ask must succeed");
        let expected_ask = SpendAuthorizingKey::from(&test_orchard_sk());
        assert_eq!(
            orchard::keys::SpendValidatingKey::from(&ask),
            orchard::keys::SpendValidatingKey::from(&expected_ask),
            "derive_orchard_ask must match the ask derived directly from the spending key"
        );
    }

    #[test]
    fn test_mnemonic_to_seed_matches_direct_parse() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC).expect("mnemonic_to_seed must succeed");
        let expected = Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("");
        assert_eq!(seed, expected);
    }

    #[test]
    fn test_mnemonic_to_seed_rejects_invalid_mnemonic() {
        let err = mnemonic_to_seed("not a valid bip39 mnemonic phrase").unwrap_err();
        assert!(matches!(err, Error::Mnemonic(_)));
    }

    // ── sign_pczt_orchard_actions ──────────────────────────────────────────────

    #[test]
    fn sign_pczt_orchard_actions_returns_empty_for_no_orchard_bundle() {
        let pczt_bytes = build_transparent_only_pczt();
        let ask = make_ask();
        let sigs = sign_pczt_orchard_actions(&pczt_bytes, &ask)
            .expect("signing a transparent-only PCZT for Orchard actions must not error");
        assert!(
            sigs.is_empty(),
            "a t→t PCZT has no Orchard bundle, so the signature list must be empty"
        );
    }

    #[test]
    fn sign_pczt_orchard_actions_produces_valid_signature_accepted_by_finalize() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();
        let orchard_signatures = sign_pczt_orchard_actions(&pczt_bytes, &ask)
            .expect("signing the pure-Orchard PCZT must succeed");
        assert_eq!(
            orchard_signatures.len(),
            1,
            "the fixture has exactly one real (unsigned) Orchard spend"
        );

        let out = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures,
            ironwood_signatures: vec![],
            transparent_signatures: vec![],
        })
        .expect("finalize must accept the signature produced by sign_pczt_orchard_actions");

        assert!(!out.tx_bytes.is_empty(), "tx_bytes must be non-empty");
        assert_eq!(out.txid.len(), 32, "txid must be 32 bytes");
    }

    /// `sign_orchard` hardcodes `OsRng` upstream (pczt 0.9.3): two independent
    /// signing calls over the same PCZT/ask produce different, but both
    /// independently valid, signatures. This is expected device-like behavior,
    /// not a bug — do not "fix" this into a byte-identity expectation.
    #[test]
    fn sign_pczt_orchard_actions_is_valid_but_not_byte_identical_across_calls() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();

        let sigs_a = sign_pczt_orchard_actions(&pczt_bytes, &ask)
            .expect("first signing call must succeed");
        let sigs_b = sign_pczt_orchard_actions(&pczt_bytes, &ask)
            .expect("second signing call must succeed");

        assert_eq!(sigs_a.len(), 1);
        assert_eq!(sigs_b.len(), 1);
        assert_ne!(
            sigs_a, sigs_b,
            "OsRng-based signing must not be byte-identical across independent calls"
        );

        for sigs in [sigs_a, sigs_b] {
            let out = finalize_transaction(FinalizeInputs {
                pczt_bytes: pczt_bytes.clone(),
                orchard_signatures: sigs,
                ironwood_signatures: vec![],
                transparent_signatures: vec![],
            })
            .expect("each independently produced signature must verify and finalize");
            assert!(!out.tx_bytes.is_empty());
        }
    }

    // ── sign_pczt_ironwood_actions ─────────────────────────────────────────────

    #[test]
    fn sign_pczt_ironwood_actions_returns_empty_for_no_ironwood_bundle() {
        let ask = make_ask();

        let orchard_pczt_bytes = build_orchard_pczt();
        let sigs = sign_pczt_ironwood_actions(&orchard_pczt_bytes, &ask)
            .expect("signing a V5/Orchard PCZT for Ironwood actions must not error");
        assert!(
            sigs.is_empty(),
            "a V5/Orchard PCZT has no Ironwood bundle, so the signature list must be empty"
        );

        let transparent_pczt_bytes = build_transparent_only_pczt();
        let sigs = sign_pczt_ironwood_actions(&transparent_pczt_bytes, &ask)
            .expect("signing a transparent-only PCZT for Ironwood actions must not error");
        assert!(
            sigs.is_empty(),
            "a t→t PCZT has no Ironwood bundle, so the signature list must be empty"
        );
    }

    #[test]
    fn sign_pczt_ironwood_actions_produces_valid_signature_accepted_by_finalize() {
        let pczt_bytes = build_ironwood_pczt();
        let ask = make_ask();
        let ironwood_signatures = sign_pczt_ironwood_actions(&pczt_bytes, &ask)
            .expect("signing the pure-Ironwood PCZT must succeed");
        assert_eq!(
            ironwood_signatures.len(),
            1,
            "the fixture has exactly one real (unsigned) Ironwood spend"
        );

        let out = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures: vec![],
            ironwood_signatures,
            transparent_signatures: vec![],
        })
        .expect("finalize must accept the signature produced by sign_pczt_ironwood_actions");

        assert!(!out.tx_bytes.is_empty(), "tx_bytes must be non-empty");
        assert_eq!(out.txid.len(), 32, "txid must be 32 bytes");

        // Round-trip through `Transaction::read` on the V6 branch, and confirm
        // the tx actually carries an Ironwood bundle — the same version marker
        // `finalize.rs`'s own `ironwood_only_finalize_produces_valid_v6_tx` checks.
        let tx = zcash_primitives::transaction::Transaction::read(
            &out.tx_bytes[..],
            zcash_protocol::consensus::BranchId::Nu6_3,
        )
        .expect("Transaction::read must succeed on V6 tx bytes");
        assert_eq!(
            *tx.txid().as_ref(),
            out.txid,
            "txid from read must match finalize output"
        );
        assert!(
            tx.ironwood_bundle().is_some(),
            "V6 tx must carry an Ironwood bundle"
        );
    }

    // ── sign_pczt_transparent_inputs ───────────────────────────────────────────

    #[test]
    fn sign_pczt_transparent_inputs_returns_empty_for_no_transparent_inputs() {
        let pczt_bytes = build_orchard_pczt();
        let seed = Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("");
        let sigs = sign_pczt_transparent_inputs(&pczt_bytes, &seed, ZcashNetwork::Mainnet)
            .expect("signing a pure-Orchard PCZT for transparent inputs must not error");
        assert!(
            sigs.is_empty(),
            "a z→z PCZT has no transparent inputs, so the signature list must be empty"
        );
    }

    #[test]
    fn sign_pczt_transparent_inputs_signature_verifies_against_derived_pubkey() {
        let address_index = 3;
        let (pczt_bytes, t_sk) = build_mixed_pczt(address_index);
        let seed = Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("");

        let sigs = sign_pczt_transparent_inputs(&pczt_bytes, &seed, ZcashNetwork::Mainnet)
            .expect("signing the mixed PCZT's transparent input must succeed");
        assert_eq!(sigs.len(), 1, "the fixture has exactly one transparent input");

        // Independently re-derive the expected pubkey and sighash, then verify
        // the produced DER signature against them — exercising both the
        // derivation and the verification, not just one.
        let secp = Secp256k1::new();
        let expected_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &t_sk);

        let pczt = Pczt::parse(&pczt_bytes).unwrap();
        let signer = PcztSigner::new(pczt).unwrap();
        let sighash = signer.transparent_sighash(0).unwrap();
        let msg = Message::from_digest(sighash);

        let der_sig = secp256k1::ecdsa::Signature::from_der(&sigs[0])
            .expect("produced signature must be valid DER");
        secp.verify_ecdsa(&msg, &der_sig, &expected_pubkey)
            .expect("signature must verify against the pubkey derived at the input's own path");
    }
}
