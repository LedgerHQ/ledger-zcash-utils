//! Inject device signatures into a PCZT and extract the final signed V5 transaction.
//!
//! Consumes the canonical PCZT bytes produced by `craft::build_transaction`
//! (`pczt::Pczt::serialize()`), which has already been run through the
//! Creator → IoFinalizer → Prover roles. The IoFinalizer self-signed every
//! dummy Orchard action, so only the *real* spend actions (those whose
//! `spend_auth_sig` is `None`) need a device-provided RedPallas signature.
//!
//! Pipeline:
//!   1. `Pczt::parse(bytes)`.
//!   2. Identify the unsigned Orchard action indices (real spends).
//!      2b. If there are transparent inputs, stamp each input's `hash160_preimage`
//!      with its controlling pubkey (taken from the `bip32_derivation` the craft
//!      step recorded). `append_transparent_signature` and `SpendFinalizer` need
//!      that pubkey to verify the device signature and rebuild the `script_sig`;
//!      the builder leaves the map empty and the device never supplies it.
//!   3. `Signer::new(pczt)`; for each unsigned action i, in order, apply the
//!      i-th device `spendAuthSig` via `apply_orchard_signature(i, sig)`
//!      (verifies against the action's `rk`, fails closed on a bad signature).
//!   4. For each transparent input i, `append_transparent_signature(i, der_sig)`.
//!   5. `signer.finish()`.
//!   6. If there are transparent inputs: `SpendFinalizer::finalize_spends()`.
//!   7. `TransactionExtractor::new(pczt).with_orchard(verifying_key()).extract()`
//!      — applies the Orchard binding signature host-side and verifies the proof.
//!   8. Serialize the V5 `Transaction` (ZIP-225) and compute the txid.

use std::sync::OnceLock;

use orchard::{
    circuit::{OrchardCircuitVersion, VerifyingKey},
    primitives::redpallas,
};
use pczt::{
    roles::{
        signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
        updater::Updater,
    },
    Pczt,
};

use crate::error::Error;

/// Inputs to [`finalize_transaction`].
pub struct FinalizeInputs {
    /// Canonical PCZT bytes from `build_transaction` (`PCZT` magic + version + postcard).
    pub pczt_bytes: Vec<u8>,
    /// One 64-byte RedPallas `spendAuthSig` per real (device-signed) Orchard spend,
    /// in PCZT-action order over the unsigned actions.
    pub orchard_signatures: Vec<[u8; 64]>,
    /// One DER-encoded secp256k1 signature per transparent input, in input order.
    /// Empty for pure-Orchard transactions.
    pub transparent_signatures: Vec<Vec<u8>>,
}

/// Output of [`finalize_transaction`].
#[derive(Debug)]
pub struct FinalizeOutput {
    /// The fully-signed transaction serialized per ZIP-225 (V5).
    pub tx_bytes: Vec<u8>,
    /// Transaction ID (BLAKE2b-256), 32 bytes, in internal **little-endian**
    /// order (as returned by `Transaction::txid()`). The FFI layer reverses this
    /// to big-endian display order to match the sync path / LL operation hash.
    pub txid: [u8; 32],
}

/// Process-global Orchard verifying key. First build is multi-second; cached
/// thereafter. Mirrors the `ProvingKey` cache in `craft.rs`.
fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
}

/// Inject device signatures into a proven PCZT and extract the final V5 transaction.
///
/// # Errors
///
/// Returns [`Error::Finalize`] if the PCZT is malformed, any signature is rejected,
/// the Orchard proof verification fails, or serialization fails.
pub fn finalize_transaction(inputs: FinalizeInputs) -> Result<FinalizeOutput, Error> {
    // 1. Parse PCZT.
    let pczt = Pczt::parse(&inputs.pczt_bytes)
        .map_err(|e| Error::Finalize(format!("PCZT parse failed: {e:?}")))?;

    // 2. Real (unsigned) Orchard action indices, in order.
    //    The IoFinalizer self-signs dummy actions at build time via each action's
    //    `dummy_sk`, so their `spend_auth_sig` is Some. Real device spends are left
    //    unsigned (None) and are the ones CUSTOM-04 fills in.
    let unsigned: Vec<usize> = pczt
        .orchard()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect();

    // Validate: one device sig per unsigned action, one transparent sig per input.
    if inputs.orchard_signatures.len() != unsigned.len() {
        return Err(Error::Finalize(format!(
            "Orchard signature count {} != unsigned action count {}",
            inputs.orchard_signatures.len(),
            unsigned.len()
        )));
    }
    let n_transparent = pczt.transparent().inputs().len();
    if inputs.transparent_signatures.len() != n_transparent {
        return Err(Error::Finalize(format!(
            "transparent signature count {} != transparent input count {}",
            inputs.transparent_signatures.len(),
            n_transparent
        )));
    }

    // 2b. Stamp each transparent input's `hash160_preimage` with its controlling
    //     pubkey so the host can verify the device signature and rebuild the
    //     `script_sig` in steps 4 + 6. Gated on `n_transparent > 0` so pure-Orchard
    //     PCZTs (which have no transparent bundle) skip the transparent Updater.
    let pczt = if n_transparent > 0 {
        stamp_transparent_hash160_preimages(pczt)?
    } else {
        pczt
    };

    // 3. Inject Orchard spend-auth signatures.
    //    `apply_orchard_signature` verifies each sig against the action's `rk`
    //    (orchard-0.14.0/src/pczt/signer.rs:43-54) and rejects invalid ones, so
    //    a mis-ordered or wrong signature fails closed rather than producing an
    //    invalid transaction.
    let mut signer =
        Signer::new(pczt).map_err(|e| Error::Finalize(format!("Signer::new: {e:?}")))?;
    for (action_idx, sig_bytes) in unsigned.iter().zip(inputs.orchard_signatures.iter()) {
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(*sig_bytes);
        signer
            .apply_orchard_signature(*action_idx, sig)
            .map_err(|e| {
                Error::Finalize(format!(
                    "apply_orchard_signature(action {action_idx}): {e:?}"
                ))
            })?;
    }

    // 4. Inject transparent input signatures (DER). The helper normalizes the
    //    Ledger y-parity header bit and strips an optional trailing sighash-type byte.
    for (idx, der) in inputs.transparent_signatures.iter().enumerate() {
        let sig = parse_transparent_der(der)?;
        signer
            .append_transparent_signature(idx, sig)
            .map_err(|e| Error::Finalize(format!("append_transparent_signature({idx}): {e:?}")))?;
    }

    // 5 + 6. Finish signer; finalize transparent spends if present.
    //        `SpendFinalizer::finalize_spends` builds `script_sig`s from the
    //        partial signatures appended in step 4. Gated on `n_transparent > 0`
    //        so we don't run it unnecessarily on pure-Orchard PCZTs.
    let pczt = signer.finish();
    let pczt = if n_transparent > 0 {
        SpendFinalizer::new(pczt)
            .finalize_spends()
            .map_err(|e| Error::Finalize(format!("SpendFinalizer: {e:?}")))?
    } else {
        pczt
    };

    // 7. Extract the final transaction.
    //    `TransactionExtractor::extract` applies the Orchard binding signature
    //    host-side (pczt-0.7.0/src/roles/tx_extractor/mod.rs:103-110) and
    //    verifies the Halo 2 proof. The VerifyingKey OnceLock means only the
    //    first call pays the multi-second build cost.
    let tx = TransactionExtractor::new(pczt)
        .with_orchard(verifying_key())
        .extract()
        .map_err(|e| Error::Finalize(format!("TransactionExtractor: {e:?}")))?;

    // 8. Serialize (ZIP-225 V5) + compute txid.
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| Error::Finalize(format!("tx serialize: {e}")))?;
    let txid: [u8; 32] = *tx.txid().as_ref();

    Ok(FinalizeOutput { tx_bytes, txid })
}

/// Stamp the `hash160_preimages` map of every transparent input with its
/// controlling pubkey.
///
/// For a P2PKH input the `script_pubkey` only commits to `HASH160(pubkey)`, not
/// the pubkey itself. To inject the device's signature
/// (`Signer::append_transparent_signature`) the host must recover that pubkey so
/// it can (1) verify the ECDSA signature against it and (2) have
/// `SpendFinalizer::finalize_spends` assemble the `<sig> <pubkey>` `script_sig`.
/// The transparent input PCZT field that carries it (`hash160_preimages`) is left
/// empty by `Builder::build_for_pczt`, and the Ledger device never returns it, so
/// finalize populates it here from the pubkey the craft step recorded as the key
/// of each input's `bip32_derivation` (the device signing-path metadata).
///
/// # Precondition
///
/// Every transparent input must carry at least one `bip32_derivation` entry. The
/// device parser is expected to reject a transparent input without one, but that
/// is a property of the firmware, not something the PCZT type system enforces: an
/// input with an empty `bip32_derivation` map would silently stamp no preimage
/// here, and the failure would only surface much later — and far less clearly — as
/// a missing-preimage error inside `SpendFinalizer::finalize_spends`. We therefore
/// fail closed up front with an explicit [`Error::Finalize`] naming the offending
/// input rather than letting a confusing downstream error escape.
///
/// This is pure signer metadata: like `bip32_derivation`, it does not affect the
/// txid or the sighash, so adding it to the already-proven PCZT is sound. Stamping
/// every candidate pubkey is safe because `set_hash160_preimage` keys each entry
/// by `HASH160(pubkey)`, so the lookup in `append_signature` resolves to the entry
/// whose hash matches the input's `script_pubkey`.
fn stamp_transparent_hash160_preimages(pczt: Pczt) -> Result<Pczt, Error> {
    // The `update_transparent_with` closure can only surface `UpdaterError`, which
    // has no variant for our domain-specific precondition. Capture any violation in
    // an outer slot and convert it to `Error::Finalize` once the borrow ends.
    let mut precondition_error: Option<Error> = None;

    let updated = Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            // Collect each input's candidate pubkeys (its `bip32_derivation` keys)
            // before mutating, to avoid overlapping immutable/mutable borrows of
            // the bundle.
            let input_pubkeys: Vec<Vec<[u8; 33]>> = updater
                .bundle()
                .inputs()
                .iter()
                .map(|input| input.bip32_derivation().keys().copied().collect())
                .collect();

            // Precondition: an input without any `bip32_derivation` entry would be
            // stamped with no preimage, yielding a confusing downstream
            // `SpendFinalizer` error. Fail closed here with a clear message instead.
            if let Some(index) = input_pubkeys.iter().position(Vec::is_empty) {
                precondition_error = Some(Error::Finalize(format!(
                    "transparent input {index} has no bip32_derivation; cannot stamp \
                     hash160 preimage (the controlling pubkey is unknown)"
                )));
                return Ok(());
            }

            for (index, pubkeys) in input_pubkeys.into_iter().enumerate() {
                updater.update_input_with(index, |mut input| {
                    for pubkey in pubkeys {
                        input.set_hash160_preimage(pubkey.to_vec());
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| {
            Error::Finalize(format!("PCZT Updater (transparent hash160 preimage): {e:?}"))
        })?;

    if let Some(err) = precondition_error {
        return Err(err);
    }

    Ok(updated.finish())
}

/// Parse a Ledger-produced transparent ECDSA signature into a libsecp256k1
/// `Signature`.
///
/// The device emits this signature from the dedicated PCZT transparent-signing
/// handler `handler_pczt_sign_transparent`
/// (`app-zcash:src/handlers/pczt.rs:202`, verified against app-zcash v3.6.0 on
/// `develop` — the PCZT-enabled build this middleware targets). That handler
/// delegates to `append_signature` (`sign_tx.rs:371-399`) with
/// `deterministic_sign = true`, which signs the signature digest with the Ledger
/// SDK secp256k1 ECDSA (`p.deterministic_sign`, returning a DER/ASN.1-encoded
/// signature), then applies two device-specific quirks before returning the
/// APDU payload:
///
///   - it ORs the y-parity bit into the DER sequence header byte when the `y`
///     coordinate is odd (`if info != 0 { sig[0] |= 0x01; }`, sign_tx.rs:390-392), and
///   - it appends a trailing 1-byte `sighash_type` (`comm.append(&[sighash_type])`,
///     sign_tx.rs:397).
///
/// Two Ledger-specific normalizations are therefore applied before calling
/// `from_der`:
///
/// 1. **DER header-bit normalization** (`0x31 → 0x30`): reset the y-parity bit
///    the device ORs into the DER sequence header byte, restoring the canonical
///    ASN.1 `0x30 SEQUENCE` tag.
///
/// 2. **Trailing sighash-type byte removal**: strip the 1-byte `sighash_type`
///    appended after the DER signature (the PCZT signer / spend-finalizer
///    re-derive the sighash type themselves). Detect it by comparing the buffer
///    length with the ASN.1 total length (header byte + 1 length byte + content
///    length): if the buffer is exactly 1 byte longer than the DER-declared
///    total length, strip the trailing byte.
///
/// # KNOWN RISK / TODO: firmware-source-verified, device-bytes-unverified
///
/// Both normalizations match the `app-zcash` firmware *source* for the PCZT
/// transparent path (verified against app-zcash v3.6.0 on `develop`:
/// `handler_pczt_sign_transparent`, pczt.rs:202 → `append_signature`,
/// sign_tx.rs:371-399):
///
/// - The `0x31 → 0x30` header-bit reset matches `if info != 0 { sig[0] |= 0x01; }`
///   (sign_tx.rs:390-392): the device only sets the bit when the `y` coordinate is
///   odd, so an even-`y` signature arrives canonical (`0x30`) and this branch is a
///   harmless no-op.
/// - The trailing-byte strip matches `comm.append(&[sighash_type])` (sign_tx.rs:397):
///   exactly one `sighash_type` byte is appended after the DER signature.
///
/// One residual gap remains, so this is *not* fully validated: the shape has not
/// been confirmed against bytes a *physical device* actually returns. The
/// mixed-path test (`mixed_transparent_and_orchard_finalize_produces_valid_v5_tx`)
/// drives the pipeline with a *canonical* signature, so it exercises assembly but
/// makes no claim about the device wire shape. The `parse_transparent_der_*` unit
/// tests check these normalizations against the documented firmware *source*, but
/// only `golden_device_transparent_signature_validates_end_to_end` (scaffolded and
/// `#[ignore]`d until device bytes are captured) validates them against real
/// firmware output.
///
/// TODO(transparent): capture a real Ledger transparent signature over a PCZT
/// input to validate this path end-to-end against firmware rather than against
/// itself. The fixture test `golden_device_transparent_signature_validates_end_to_end`
/// (with its `golden_fixture` populate-point and capture procedure) is scaffolded
/// and `#[ignore]`d, waiting on those bytes. The normalizations fail closed
/// (`from_der` rejects a malformed buffer), so a wrong assumption surfaces as
/// `Error::Finalize` rather than a silently invalid transaction — but it has not
/// been exercised against a device.
fn parse_transparent_der(bytes: &[u8]) -> Result<secp256k1::ecdsa::Signature, Error> {
    if bytes.len() < 2 {
        return Err(Error::Finalize(format!(
            "transparent DER signature too short: {} bytes",
            bytes.len()
        )));
    }

    // Work on a mutable copy so we can normalize in place.
    let mut buf = bytes.to_vec();

    // Normalization 1: reset the Ledger y-parity header bit.
    // DER SEQUENCE tag is 0x30; the device ORs in 0x01 (only for odd y), yielding 0x31.
    //
    // Matches app-zcash firmware source (`if info != 0 { sig[0] |= 0x01; }`,
    // sign_tx.rs:390-392, v3.6.0 `develop`), but not yet validated against bytes
    // from a physical device. See the function doc's "KNOWN RISK / TODO" section.
    // Fails closed (a wrong assumption makes `from_der` below reject the buffer).
    if buf[0] == 0x31 {
        buf[0] = 0x30;
    }

    // Normalization 2: strip the trailing sighash-type byte if present.
    // ASN.1 total wire length = 1 (tag) + 1 (length byte) + content_length.
    // If the buffer is exactly 1 byte longer than that, the extra byte is the
    // sighash type appended by the device.
    //
    // This parses only the *short-form* DER length (single length byte, high bit
    // clear, value 0..=127). The device produces the signature via the Ledger SDK
    // secp256k1 ECDSA (`p.deterministic_sign`, app-zcash sign_tx.rs:382-387,
    // v3.6.0 `develop`, DER/ASN.1 output), whose buffer is bounded at 72 bytes
    // (`0x30` tag + len byte + at most 70 bytes of content: two 33-byte INTEGERs).
    // The DER content length is therefore always <= 70 < 128, so the length is
    // always short-form and `buf[1]` is the content length directly.
    // We still guard the high bit explicitly rather than rely on that bound
    // implicitly: if a long-form length byte (>= 0x80) ever shows up we skip the
    // strip and let `from_der` below reject/parse the buffer as-is (fail closed,
    // never silently truncate using a misread length).
    if buf.len() >= 2 && buf[1] < 0x80 {
        let content_len = buf[1] as usize;
        let declared_total = 2 + content_len; // tag + length-byte + content
        if buf.len() == declared_total + 1 {
            buf.truncate(declared_total);
        }
    }

    secp256k1::ecdsa::Signature::from_der(&buf)
        .map_err(|e| Error::Finalize(format!("transparent DER parse failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::craft::{
        build_transaction, BuildInputs, Destination, OrchardSpendInput, OutputRequest,
        TransparentInput,
    };
    use incrementalmerkletree::{Marking, Retention};
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
        tree::MerkleHashOrchard,
        value::NoteValue,
    };
    use pczt::roles::signer::Signer as PcztSigner;
    use shardtree::{store::memory::MemoryShardStore, ShardTree};
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;
    use zip32::AccountId;

    // ── helpers ──────────────────────────────────────────────────────────────────

    fn make_fvk() -> orchard::keys::FullViewingKey {
        let sk = SpendingKey::from_zip32_seed(&[1u8; 32], 133, AccountId::ZERO).unwrap();
        orchard::keys::FullViewingKey::from(&sk)
    }

    fn make_ask() -> orchard::keys::SpendAuthorizingKey {
        let sk = SpendingKey::from_zip32_seed(&[1u8; 32], 133, AccountId::ZERO).unwrap();
        orchard::keys::SpendAuthorizingKey::from(&sk)
    }

    fn nu5_height() -> u32 {
        1_687_105 // mainnet NU5 activation + 1
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

    /// Build a proven PCZT (pure Orchard) with a single real spend.
    ///
    /// Returns the canonical PCZT bytes so callers can derive the
    /// device signature for the real spend.
    fn build_orchard_pczt() -> Vec<u8> {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);

        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let spend_value: u64 = 20_000;
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed, NoteVersion::V2)
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

    /// Collect device signatures for all *unsigned* actions in a PCZT using
    /// the spend authorizing key (simulates what the Ledger device does).
    fn sign_unsigned_actions(
        pczt_bytes: &[u8],
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Vec<[u8; 64]> {
        let pczt = Pczt::parse(pczt_bytes).expect("sign_unsigned_actions: parse");
        let unsigned_indices: Vec<usize> = pczt
            .orchard()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
            .map(|(i, _)| i)
            .collect();

        let mut signer = PcztSigner::new(pczt).expect("sign_unsigned_actions: Signer::new");
        for idx in &unsigned_indices {
            signer
                .sign_orchard(*idx, ask)
                .expect("sign_unsigned_actions: sign_orchard");
        }
        let signed_pczt = signer.finish();

        // Extract the 64-byte signatures in unsigned-action order.
        unsigned_indices
            .iter()
            .map(|idx| {
                *signed_pczt.orchard().actions()[*idx]
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .expect("sign_unsigned_actions: spend_auth_sig must be Some after signing")
            })
            .collect()
    }

    /// Standard 25-byte P2PKH `scriptPubKey` paying to `hash`:
    /// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
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

    /// HASH160 (RIPEMD160 ∘ SHA256) of a compressed pubkey — the value a standard
    /// P2PKH `scriptPubKey` commits to.
    fn pubkey_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
        use bitcoin::hashes::{hash160, Hash};
        hash160::Hash::hash(pubkey).to_byte_array()
    }

    /// Build a proven mixed PCZT (one real Orchard spend + one transparent P2PKH
    /// input → one Orchard output, with Orchard change), returning the PCZT bytes
    /// and the secp256k1 secret key controlling the transparent input.
    ///
    /// Layout (so `finalize_transaction` exercises every mixed-path role):
    ///   - 1 real Orchard spend (value 20_000) → device `spendAuthSig` required.
    ///   - 1 transparent P2PKH input (value 15_000) → device DER signature required.
    ///   - 1 Orchard recipient output (value 10_000).
    ///   - Orchard change (10_000) is added automatically by the builder.
    ///     ZIP-317: orchard_actions = max(2, max(1 spend, 2 outputs)) = 2,
    ///     transparent_actions = max(1 in, 0 out) = 1 → fee = 5_000 × 3 = 15_000.
    fn build_mixed_pczt() -> (Vec<u8>, secp256k1::SecretKey) {
        use secp256k1::{PublicKey, Secp256k1, SecretKey};

        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let change = fvk.address_at(0u32, Scope::Internal);

        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let spend_value: u64 = 20_000;
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let ovk = Some(fvk.to_ovk(Scope::External));

        // Transparent input controlled by a known key so the test can sign it.
        let secp = Secp256k1::new();
        let t_sk = SecretKey::from_slice(&[0x07u8; 32]).unwrap();
        let t_pubkey = PublicKey::from_secret_key(&secp, &t_sk).serialize();
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
                merkle_path: path,
            }],
            transparent_inputs: vec![TransparentInput {
                pubkey: t_pubkey,
                txid: [0x09u8; 32],
                vout: 0,
                script_pubkey: make_p2pkh_script(pubkey_hash160(&t_pubkey)),
                value: transparent_value,
                derivation_scope: 0,
                derivation_address_index: 0,
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

    /// Produce a **canonical** DER signature over transparent input `index`'s
    /// sighash: compute the sighash via the PCZT `Signer`, sign it with `sk`, and
    /// return the standard libsecp256k1 DER encoding (`0x30` SEQUENCE header, no
    /// trailing sighash-type byte).
    ///
    /// Deliberately does NOT reproduce the Ledger wire quirks (the `0x31` y-parity
    /// header bit and the trailing `SIGHASH_ALL` byte). Fabricating exactly the
    /// shape `parse_transparent_der` strips would make the mixed test a closed loop
    /// that stays green even if real firmware emits a different shape — the very
    /// over-confidence this avoids. The quirk normalization is exercised in
    /// isolation by the `parse_transparent_der_*` unit tests, and validated against
    /// real device bytes by `golden_device_transparent_signature_validates_end_to_end`.
    /// This helper's sole job is to feed the finalize pipeline a valid signature.
    fn valid_transparent_der_signature(
        pczt_bytes: &[u8],
        index: usize,
        sk: &secp256k1::SecretKey,
    ) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};

        let pczt = Pczt::parse(pczt_bytes).expect("valid_transparent_der_signature: parse");
        let signer =
            PcztSigner::new(pczt).expect("valid_transparent_der_signature: Signer::new");
        let sighash = signer
            .transparent_sighash(index)
            .expect("valid_transparent_der_signature: transparent_sighash");

        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&Message::from_digest(sighash), sk);
        sig.serialize_der().to_vec()
    }

    // ── test 1: pure-Orchard finalize ─────────────────────────────────────────

    /// Build → device-sign → finalize yields well-formed tx_bytes and a 32-byte
    /// txid. `Transaction::read` round-trips successfully.
    #[test]
    fn pure_orchard_finalize_produces_valid_v5_tx() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();
        let orchard_signatures = sign_unsigned_actions(&pczt_bytes, &ask);

        let out = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures,
            transparent_signatures: vec![],
        })
        .expect("pure_orchard_finalize: finalize must succeed");

        assert!(!out.tx_bytes.is_empty(), "tx_bytes must be non-empty");
        // V5 transaction header: version=5 (LE u32) and version group id 0x26A7270A (LE).
        assert!(
            out.tx_bytes.len() > 8,
            "tx_bytes must be long enough to hold a V5 header"
        );
        assert_eq!(out.txid.len(), 32, "txid must be 32 bytes");

        // Round-trip: Transaction::read must succeed.
        let tx = Transaction::read(&out.tx_bytes[..], BranchId::Nu6)
            .expect("Transaction::read must succeed on V5 tx bytes");
        assert_eq!(
            *tx.txid().as_ref(),
            out.txid,
            "txid from read must match finalize output"
        );
    }

    // ── test 2: mixed transparent + Orchard finalize ──────────────────────────

    /// Full mixed-path finalize: build a PCZT with one real Orchard spend and one
    /// transparent P2PKH input, inject the device Orchard `spendAuthSig` and the
    /// device transparent DER signature, and run the complete finalize pipeline
    /// (preimage stamping → Signer → `SpendFinalizer` → `TransactionExtractor`).
    /// The result must be a well-formed V5 transaction that round-trips through
    /// `Transaction::read`, carries both bundles, and has a non-empty `script_sig`
    /// on its transparent input.
    ///
    /// SCOPE: this test validates the finalize *pipeline* — transparent signature
    /// injection → `SpendFinalizer` → `TransactionExtractor`, ending in a V5 tx
    /// that round-trips and carries both bundles with a populated `script_sig`. It
    /// is driven by a *canonical* signature from `valid_transparent_der_signature`
    /// and therefore makes no claim about the Ledger DER wire shape: that
    /// assumption is checked against firmware *source* by the `parse_transparent_der_*`
    /// unit tests and against real *device bytes* by
    /// `golden_device_transparent_signature_validates_end_to_end`.
    #[test]
    fn mixed_transparent_and_orchard_finalize_produces_valid_v5_tx() {
        let (pczt_bytes, t_sk) = build_mixed_pczt();
        let ask = make_ask();
        let orchard_signatures = sign_unsigned_actions(&pczt_bytes, &ask);
        assert_eq!(
            orchard_signatures.len(),
            1,
            "the mixed PCZT must have exactly one real (device-signed) Orchard spend"
        );
        let transparent_sig = valid_transparent_der_signature(&pczt_bytes, 0, &t_sk);

        let out = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures,
            transparent_signatures: vec![transparent_sig],
        })
        .expect("mixed finalize must succeed");

        assert!(!out.tx_bytes.is_empty(), "tx_bytes must be non-empty");
        assert_eq!(out.txid.len(), 32, "txid must be 32 bytes");

        // Round-trip and inspect: both pools present, transparent input signed.
        let tx = Transaction::read(&out.tx_bytes[..], BranchId::Nu6)
            .expect("Transaction::read must succeed on mixed V5 tx bytes");
        assert_eq!(
            *tx.txid().as_ref(),
            out.txid,
            "txid from read must match finalize output"
        );

        let transparent = tx
            .transparent_bundle()
            .expect("mixed tx must carry a transparent bundle");
        assert_eq!(transparent.vin.len(), 1, "exactly one transparent input");
        // A finalized P2PKH `script_sig` (`<sig> <pubkey>`) is ~107 bytes; an empty
        // script serializes to a single CompactSize `0x00` byte. `> 1` therefore
        // confirms the SpendFinalizer assembled a real `script_sig`.
        assert!(
            transparent.vin[0].script_sig().serialized_size() > 1,
            "transparent input must have a finalized (non-empty) script_sig"
        );
        assert!(
            tx.orchard_bundle().is_some(),
            "mixed tx must carry an Orchard bundle"
        );
    }

    // ── test 3: valid/invalid Orchard signature ────────────────────────────────

    /// A valid device `spendAuthSig` is accepted. A signature that fails `rk`
    /// verification returns `Error::Finalize`.
    #[test]
    fn valid_orchard_signature_accepted_invalid_rejected() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();
        let valid_sigs = sign_unsigned_actions(&pczt_bytes, &ask);

        // Valid signature: must succeed.
        let result = finalize_transaction(FinalizeInputs {
            pczt_bytes: pczt_bytes.clone(),
            orchard_signatures: valid_sigs,
            transparent_signatures: vec![],
        });
        assert!(
            result.is_ok(),
            "valid sig must succeed: {:?}",
            result.unwrap_err()
        );

        // Invalid signature (all-zero bytes — cannot be a valid RedPallas sig).
        // `apply_orchard_signature` verifies against `rk` and rejects it.
        let bad_sigs: Vec<[u8; 64]> = {
            let pczt = Pczt::parse(&pczt_bytes).unwrap();
            let n = pczt
                .orchard()
                .actions()
                .iter()
                .filter(|a| a.spend().spend_auth_sig().is_none())
                .count();
            vec![[0u8; 64]; n]
        };
        let err = finalize_transaction(FinalizeInputs {
            pczt_bytes: pczt_bytes.clone(),
            orchard_signatures: bad_sigs,
            transparent_signatures: vec![],
        })
        .unwrap_err();
        assert!(
            matches!(&err, Error::Finalize(s) if s.contains("apply_orchard_signature")),
            "invalid sig must produce Error::Finalize, got: {err}"
        );
    }

    // ── test 4: txid equals BLAKE2b-256 ──────────────────────────────────────

    /// The returned txid equals `tx.txid()` obtained by re-reading the bytes.
    #[test]
    fn txid_matches_transaction_read_txid() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();
        let sigs = sign_unsigned_actions(&pczt_bytes, &ask);

        let out = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures: sigs,
            transparent_signatures: vec![],
        })
        .unwrap();

        let tx = Transaction::read(&out.tx_bytes[..], BranchId::Nu6).unwrap();
        assert_eq!(
            *tx.txid().as_ref(),
            out.txid,
            "txid must match Transaction::read txid"
        );
    }

    // ── test 5: Orchard signature-count mismatch ──────────────────────────────

    /// Providing the wrong number of Orchard signatures returns `Error::Finalize`.
    #[test]
    fn orchard_signature_count_mismatch_returns_finalize_error() {
        let pczt_bytes = build_orchard_pczt();
        // Pass zero signatures when ≥1 real spend exists.
        let err = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures: vec![],
            transparent_signatures: vec![],
        })
        .unwrap_err();
        assert!(
            matches!(&err, Error::Finalize(s) if s.contains("Orchard signature count")),
            "mismatch must produce Error::Finalize, got: {err}"
        );
    }

    // ── test 6: transparent signature-count mismatch ──────────────────────────

    /// Providing the wrong number of transparent signatures returns `Error::Finalize`.
    #[test]
    fn transparent_signature_count_mismatch_returns_finalize_error() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();
        let sigs = sign_unsigned_actions(&pczt_bytes, &ask);
        // Pass one spurious transparent sig on a pure-Orchard PCZT.
        let err = finalize_transaction(FinalizeInputs {
            pczt_bytes,
            orchard_signatures: sigs,
            transparent_signatures: vec![vec![0u8; 1]],
        })
        .unwrap_err();
        assert!(
            matches!(&err, Error::Finalize(s) if s.contains("transparent signature count")),
            "mismatch must produce Error::Finalize, got: {err}"
        );
    }

    // ── test 7: malformed PCZT bytes ──────────────────────────────────────────

    /// Malformed PCZT bytes return `Error::Finalize` without panicking.
    #[test]
    fn malformed_pczt_returns_finalize_error_no_panic() {
        let junk = b"not a pczt at all".to_vec();
        let err = finalize_transaction(FinalizeInputs {
            pczt_bytes: junk,
            orchard_signatures: vec![],
            transparent_signatures: vec![],
        })
        .unwrap_err();
        assert!(
            matches!(&err, Error::Finalize(s) if s.contains("PCZT parse failed")),
            "malformed bytes must produce Error::Finalize, got: {err}"
        );
    }

    // ── test 8: VerifyingKey cache ────────────────────────────────────────────

    /// The second finalize call is markedly faster than the first because the
    /// VerifyingKey is cached in a process-global OnceLock. Timing thresholds:
    /// first call ≥ 1 s (building the key), second call < 1 s.
    ///
    /// Marked `#[ignore]` because it is a timing test — flaky in heavily loaded
    /// CI environments and slow (first call can take several seconds).
    #[test]
    #[ignore]
    fn verifying_key_cache_second_call_faster_than_first() {
        let pczt_bytes = build_orchard_pczt();
        let ask = make_ask();

        let t0 = std::time::Instant::now();
        let sigs1 = sign_unsigned_actions(&pczt_bytes, &ask);
        finalize_transaction(FinalizeInputs {
            pczt_bytes: pczt_bytes.clone(),
            orchard_signatures: sigs1,
            transparent_signatures: vec![],
        })
        .unwrap();
        let first_elapsed = t0.elapsed();

        let t1 = std::time::Instant::now();
        let sigs2 = sign_unsigned_actions(&pczt_bytes, &ask);
        finalize_transaction(FinalizeInputs {
            pczt_bytes: pczt_bytes.clone(),
            orchard_signatures: sigs2,
            transparent_signatures: vec![],
        })
        .unwrap();
        let second_elapsed = t1.elapsed();

        assert!(
            second_elapsed < first_elapsed,
            "second finalize ({second_elapsed:?}) must be faster than first ({first_elapsed:?})"
        );
        // Second call should be well under 1 s (key is already cached).
        assert!(
            second_elapsed.as_secs() < 1,
            "second finalize took {second_elapsed:?}; expected < 1 s with cached VK"
        );
    }

    // ── parse_transparent_der tests ───────────────────────────────────────────

    /// A standard DER signature (no Ledger modifications) round-trips correctly.
    #[test]
    fn parse_transparent_der_standard_signature() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x01u8; 32]).unwrap();
        let msg = Message::from_digest([0xabu8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let der = sig.serialize_der().to_vec();

        // Standard DER (0x30 header, no trailing byte): must parse cleanly.
        let parsed = parse_transparent_der(&der).expect("standard DER must parse");
        assert_eq!(parsed, sig, "parsed sig must equal original");
    }

    /// The Ledger header-bit mutation (`0x30 → 0x31`) is normalized to `0x30`.
    #[test]
    fn parse_transparent_der_normalizes_ledger_header_byte() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x02u8; 32]).unwrap();
        let msg = Message::from_digest([0xbcu8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let mut der = sig.serialize_der().to_vec();
        der[0] = 0x31; // simulate Ledger y-parity bit
        let parsed = parse_transparent_der(&der).expect("Ledger-mutated header must normalize");
        assert_eq!(parsed, sig, "normalized sig must equal original");
    }

    /// A trailing sighash-type byte is stripped when the ASN.1 length field
    /// indicates the buffer is 1 byte too long.
    #[test]
    fn parse_transparent_der_strips_trailing_sighash_type_byte() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x03u8; 32]).unwrap();
        let msg = Message::from_digest([0xcdu8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let mut der = sig.serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL appended by device
        let parsed = parse_transparent_der(&der).expect("sighash-type byte must be stripped");
        assert_eq!(parsed, sig, "parsed sig (stripped) must equal original");
    }

    /// Both normalizations together (Ledger header bit + trailing sighash byte).
    #[test]
    fn parse_transparent_der_both_normalizations() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x04u8; 32]).unwrap();
        let msg = Message::from_digest([0xdeu8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let mut der = sig.serialize_der().to_vec();
        der[0] = 0x31; // y-parity bit
        der.push(0x01); // SIGHASH_ALL
        let parsed = parse_transparent_der(&der).expect("both normalizations must succeed");
        assert_eq!(parsed, sig, "fully-normalized sig must equal original");
    }

    /// A too-short buffer returns `Error::Finalize` without panicking.
    #[test]
    fn parse_transparent_der_too_short_returns_finalize_error() {
        let err = parse_transparent_der(&[0x30]).unwrap_err();
        assert!(
            matches!(&err, Error::Finalize(s) if s.contains("too short")),
            "too-short buffer must produce Error::Finalize, got: {err}"
        );
    }

    // ── transparent-signature DER parsing (unit-level) ───────────────────────
    //
    // The full mixed transparent+Orchard finalize path (SpendFinalizer +
    // transparent bundle extraction) is now covered end-to-end by
    // `mixed_transparent_and_orchard_finalize_produces_valid_v5_tx` above. This
    // remaining case is a focused unit check that `parse_transparent_der`
    // normalizes a synthetic device-shaped DER signature (header bit + trailing
    // sighash byte) back to a canonical signature.
    #[test]
    fn transparent_der_parse_integrates_with_finalize_path() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x05u8; 32]).unwrap();
        let msg = Message::from_digest([0xefu8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut der = sig.serialize_der().to_vec();
        der[0] = 0x31; // Ledger header
        der.push(0x01); // sighash byte
                        // Both normalizations must produce the original signature.
        let parsed = parse_transparent_der(&der).unwrap();
        assert_eq!(parsed, sig);
    }

    // ── golden device-bytes fixture (open loop) ───────────────────────────────
    //
    // Closes the gap documented in `parse_transparent_der`'s "KNOWN RISK / TODO":
    // no other test validates the Ledger DER wire shape against real firmware. The
    // mixed test drives the pipeline with a canonical signature, and the
    // `parse_transparent_der_*` unit tests only check the normalizations against the
    // documented firmware *source*. This test instead feeds in **bytes a physical
    // Ledger actually returned** for a transparent PCZT input and proves, end-to-end,
    // that after normalization they are a valid ECDSA signature over the sighash
    // this crate computes — validating the DER-shape assumption against firmware
    // rather than against ourselves.
    //
    // ── How to capture the fixture ────────────────────────────────────────────
    //
    // On a host with a physical Ledger running the PCZT-enabled app-zcash build:
    //
    //   1. Build a transaction that has at least one transparent (P2PKH) input,
    //      e.g. via the `buildTransaction` NAPI export. Record the returned
    //      `pczt_hex` verbatim → `GOLDEN_PCZT_HEX`. (The sighash depends on the
    //      whole tx, so the PCZT here MUST be the exact one streamed to the
    //      device.)
    //   2. Stream that PCZT to the device and have it sign each transparent
    //      input. Capture the raw bytes the device returns for each input,
    //      exactly as they arrive in the APDU payload — i.e. *with* the Ledger
    //      quirks still applied (y-parity bit OR-ed into the DER header byte and
    //      the trailing 1-byte `sighash_type`; see `handler_pczt_sign_transparent`
    //      → `append_signature`, app-zcash pczt.rs:202 / sign_tx.rs:371-399,
    //      v3.6.0 `develop`). Do NOT pre-normalize them. Hex-encode →
    //      first element of each `GOLDEN_TRANSPARENT_INPUTS` tuple.
    //   3. Record the 33-byte compressed controlling pubkey for each input (the
    //      same value passed as `TransparentInputJs.pubkey` when building) →
    //      second element of each tuple. Inputs must be listed in PCZT input
    //      order.
    //
    // Then drop the captured bytes into `golden_fixture` below (return `Some(..)`)
    // and the assertions validate the path against real firmware output. A
    // `from_der` rejection means the PCZT firmware emits a different DER shape than
    // the documented assumption; a verification failure means the device signed a
    // different sighash (or the normalization corrupted the signature). Either way
    // the path fails closed.
    //
    // ── Blocking dependency (why this stays open) ─────────────────────────────
    //
    // This fixture cannot be captured today for a *structural* reason, not just
    // the funded-testnet prerequisite: there is no host-side path that streams a
    // PCZT to the device and returns the raw transparent DER signature. As of
    // device-sdk-ts `signer-zcash` v0.3.0, only the legacy transparent flow exists
    // (`SignTransactionTask`, "Zcash transparent signing only"); there is no PCZT
    // sign device-action, and `finalizeTransaction` has no consumer wired in
    // `coin-bitcoin/.../chain-adapters/zcash/`. Step 2 above ("stream that PCZT to
    // the device and capture the raw bytes") is therefore not yet implementable.
    //
    // DEPENDENCY: this test unblocks only once the DMK PCZT signing device-action
    // lands in device-sdk-ts `signer-zcash` (APDU-stream a PCZT, return the raw
    // transparent DER signature) and a consumer is wired into the coin-bitcoin
    // Zcash chain-adapter. Track that work as an explicit prerequisite for this
    // golden fixture.

    /// The captured golden fixture, or `None` until one exists.
    ///
    /// To enable the end-to-end test, return
    /// `Some((pczt_hex, &[(device_signature_hex, controlling_pubkey_hex), ..]))`
    /// where the inner tuples are in PCZT input order and `device_signature_hex`
    /// is the raw APDU payload (Ledger header bit + trailing sighash byte intact).
    /// See the capture procedure documented above this function.
    fn golden_fixture() -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
        None
    }

    #[test]
    #[ignore = "requires golden bytes captured from a physical Ledger; see the doc comment for the capture procedure"]
    fn golden_device_transparent_signature_validates_end_to_end() {
        let Some((pczt_hex, transparent_inputs)) = golden_fixture() else {
            eprintln!(
                "SKIP golden_device_transparent_signature_validates_end_to_end: no fixture \
                 captured yet. Populate `golden_fixture` — see the doc comment above this test \
                 for the capture procedure."
            );
            return;
        };

        use secp256k1::{Message, PublicKey, Secp256k1};

        let pczt_bytes = hex::decode(pczt_hex).expect("golden pczt_hex must be valid hex");
        let pczt = Pczt::parse(&pczt_bytes).expect("golden pczt_hex must parse as a PCZT");

        assert_eq!(
            pczt.transparent().inputs().len(),
            transparent_inputs.len(),
            "fixture transparent-input count must match the golden PCZT"
        );

        let signer = PcztSigner::new(pczt).expect("Signer::new on golden PCZT");
        let secp = Secp256k1::new();

        for (index, (sig_hex, pubkey_hex)) in transparent_inputs.iter().enumerate() {
            let raw = hex::decode(sig_hex)
                .unwrap_or_else(|e| panic!("transparent input {index} signature hex: {e}"));

            // (1) The device's raw bytes must satisfy parse_transparent_der's
            //     normalization assumptions. This is the exact fail-closed branch
            //     (`from_der` rejection) the closed-loop test cannot reach.
            let parsed = parse_transparent_der(&raw).unwrap_or_else(|e| {
                panic!(
                    "transparent input {index}: parse_transparent_der rejected the device bytes \
                     ({e}). The PCZT firmware DER shape does not match the documented \
                     (app-zcash v3.6.0 `develop`) assumption — update parse_transparent_der."
                )
            });

            // (2) End-to-end fidelity: the normalized signature must verify against
            //     the controlling pubkey over the sighash THIS crate computes.
            let sighash = signer
                .transparent_sighash(index)
                .unwrap_or_else(|e| panic!("transparent_sighash({index}): {e:?}"));
            let pubkey_bytes = hex::decode(pubkey_hex)
                .unwrap_or_else(|e| panic!("transparent input {index} pubkey hex: {e}"));
            let pubkey = PublicKey::from_slice(&pubkey_bytes)
                .unwrap_or_else(|e| panic!("transparent input {index} pubkey: {e}"));

            secp.verify_ecdsa(&Message::from_digest(sighash), &parsed, &pubkey)
                .unwrap_or_else(|e| {
                    panic!(
                        "transparent input {index}: the normalized device signature does NOT \
                         verify against the controlling pubkey over the computed sighash ({e}). \
                         The device signed a different sighash, or normalization corrupted the \
                         signature."
                    )
                });
        }
    }
}
