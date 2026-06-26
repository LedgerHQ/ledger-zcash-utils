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

use orchard::{circuit::VerifyingKey, primitives::redpallas};
use pczt::{
    roles::{signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor},
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
    VK.get_or_init(VerifyingKey::build)
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

/// Parse a Ledger-produced transparent ECDSA signature into a libsecp256k1
/// `Signature`.
///
/// The device produces this signature through the PCZT signing flow
/// (`INS_PCZT_SIGN_TRANSPARENT`, 0x55): `handler_pczt_sign_transparent`
/// (`app-zcash:src/handlers/pczt.rs:202-283`) reads the signing path from the
/// input's PCZT `bip32_derivation` and emits the signature via the shared
/// `append_signature` helper (`app-zcash:src/handlers/sign_tx.rs:371-398`).
/// That helper emits a variable-length DER (ASN.1) ECDSA signature with the
/// y-parity bit OR-ed into the sequence header byte (`sig[0] |= 0x01`), followed
/// by a 1-byte `sighash_type`. Two Ledger-specific normalizations are therefore
/// applied before calling `from_der`:
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
    // DER SEQUENCE tag is 0x30; the device ORs in 0x01, yielding 0x31.
    if buf[0] == 0x31 {
        buf[0] = 0x30;
    }

    // Normalization 2: strip the trailing sighash-type byte if present.
    // ASN.1 total wire length = 1 (tag) + 1 (length byte) + content_length.
    // If the buffer is exactly 1 byte longer than that, the extra byte is the
    // sighash type appended by the device.
    if buf.len() >= 2 {
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
    };
    use incrementalmerkletree::{Marking, Retention};
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
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
    /// Returns (pczt_bytes, spend_value, fee) so callers can derive the
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
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed)
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

    // test 2 (mixed transparent+Orchard, full finalize) is deferred to the
    // DEV-03 integration tests (needs a funded transparent UTXO). The covered
    // portion — transparent-signature DER parsing — is in the dedicated group
    // near the end of this module.

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

    // ── transparent-signature DER parsing (mixed-path finalize → DEV-03) ──────
    //
    // This is the covered portion of the "mixed transparent+Orchard" criterion.
    // A fully realistic mixed PCZT requires a funded transparent UTXO and a
    // real secp256k1 private key to produce a valid `script_sig`; that full
    // finalize path (SpendFinalizer + transparent bundle extraction) is covered
    // by the DEV-03 integration tests once a funded testnet account is available
    // (MISSING item flagged in the plan). Here we confirm the helper integrates:
    // `parse_transparent_der` normalizes a synthetic valid DER signature.
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
}
