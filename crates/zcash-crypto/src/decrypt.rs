use std::io::Cursor;
use std::sync::Arc;

use orchard::{
    keys::{PreparedIncomingViewingKey as PreparedOrchardIvk, Scope},
    note::{
        ExtractedNoteCommitment as OrchardExtractedNoteCommitment,
        Nullifier as OrchardNullifier,
    },
    note_encryption::{CompactAction, OrchardDomain},
};
use sapling_crypto::{
    note::ExtractedNoteCommitment as SaplingExtractedNoteCommitment,
    note_encryption::{
        CompactOutputDescription, PreparedIncomingViewingKey as PreparedSaplingIvk, SaplingDomain,
        Zip212Enforcement,
    },
};
use uuid::Uuid;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_client_backend::decrypt_transaction;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes, COMPACT_NOTE_SIZE};
use zcash_primitives::{
    consensus::{BlockHeight, BranchId},
    transaction::Transaction as ZcashTransaction,
};
use zcash_protocol::{consensus::Network, memo::MemoBytes, value::Zatoshis};

use crate::error::Error;

// ─── compact block data types ─────────────────────────────────────────────────
//
// These types represent compact block data as streamed by lightwalletd.
// They are intentionally decoupled from any proto/tonic dependency so this
// crate compiles for all targets including iOS and Android.
// The `zcash-grpc` crate converts proto `CompactTx` → `CompactTransaction` before
// calling `trial_decrypt_block`.

/// A compact Sapling output as found in a lightwalletd compact block.
#[derive(Debug, Clone)]
pub struct CompactSaplingOutput {
    /// Note commitment (32 bytes).
    pub cmu: Vec<u8>,
    /// Ephemeral public key (32 bytes).
    pub ephemeral_key: Vec<u8>,
    /// Compact note ciphertext ([`COMPACT_NOTE_SIZE`] = 52 bytes).
    pub ciphertext: Vec<u8>,
}

/// A compact Orchard action as found in a lightwalletd compact block.
#[derive(Debug, Clone)]
pub struct CompactOrchardAction {
    /// Note commitment (cmx, 32 bytes).
    pub cmx: Vec<u8>,
    /// Ephemeral public key (32 bytes).
    pub ephemeral_key: Vec<u8>,
    /// Compact note ciphertext ([`COMPACT_NOTE_SIZE`] = 52 bytes).
    pub ciphertext: Vec<u8>,
}

/// A compact transaction as streamed by lightwalletd, containing only what is
/// needed for trial decryption.
#[derive(Debug, Clone)]
pub struct CompactTransaction {
    /// Transaction ID in big-endian (display) hex order.
    pub txid: String,
    /// Sapling shielded outputs in this transaction.
    pub sapling_outputs: Vec<CompactSaplingOutput>,
    /// Orchard shielded actions in this transaction.
    pub orchard_actions: Vec<CompactOrchardAction>,
}

// ─── prepared IVKs ────────────────────────────────────────────────────────────

/// Pre-computed incoming viewing keys for both shielded pools, ready for
/// repeated trial decryption across many blocks.
///
/// Wrap in [`Arc`] when sharing across threads or UniFFI opaque handles.
pub struct PreparedIvks {
    pub sapling: Vec<(PreparedSaplingIvk, &'static str)>,
    pub orchard: Vec<(PreparedOrchardIvk, &'static str)>,
}

// ─── output types ─────────────────────────────────────────────────────────────

/// A single decrypted shielded note (Sapling or Orchard).
#[derive(Debug, Clone)]
pub struct DecryptedOutput {
    /// Value in zatoshis (1 ZEC = 100_000_000 zatoshis).
    pub amount: u64,
    /// Memo text decoded from the note's memo field (UTF-8, null-trimmed).
    pub memo: String,
    /// `"incoming"`, `"outgoing"`, or `"internal"`.
    pub transfer_type: String,
}

/// All decrypted outputs from a single transaction.
#[derive(Debug, Clone)]
pub struct DecryptedTx {
    pub sapling_outputs: Vec<DecryptedOutput>,
    pub orchard_outputs: Vec<DecryptedOutput>,
}

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Decode a [`MemoBytes`] to a UTF-8 string, stripping trailing null bytes.
pub(crate) fn decode_memo(memo: MemoBytes) -> String {
    let memo_bytes = memo.into_bytes();
    let memo_len = memo_bytes.iter().position(|&b| b == 0).unwrap_or(memo_bytes.len());
    if memo_len == 0 {
        return String::new();
    }
    String::from_utf8(memo_bytes[..memo_len].to_vec()).unwrap_or_default()
}

fn decode_transfer_type(t: zcash_client_backend::TransferType) -> String {
    match t {
        zcash_client_backend::TransferType::Incoming => "incoming".into(),
        zcash_client_backend::TransferType::Outgoing => "outgoing".into(),
        _ => "internal".into(),
    }
}

fn decode_note_value(z: Zatoshis) -> u64 {
    z.into_u64()
}

// ─── public API ───────────────────────────────────────────────────────────────

/// Parse a UFVK string and derive pre-computed IVKs for Sapling and Orchard
/// trial decryption.
///
/// The returned [`PreparedIvks`] should be created once and reused across
/// many calls to [`trial_decrypt_block`] for maximum performance.
///
/// # Errors
///
/// Returns [`Error::Decrypt`] if the UFVK string cannot be decoded or parsed.
pub fn prepare_ivks(viewing_key: &str) -> Result<PreparedIvks, Error> {
    let (_network, ufvk_str) = Ufvk::decode(viewing_key)
        .map_err(|e| Error::Decrypt(format!("UFVK decode failed: {:?}", e)))?;
    let ufvk = UnifiedFullViewingKey::parse(&ufvk_str)
        .map_err(|e| Error::Decrypt(format!("UFVK parse failed: {:?}", e)))?;

    let sapling = if let Some(dfvk) = ufvk.sapling() {
        vec![
            (PreparedSaplingIvk::new(&dfvk.to_ivk(zip32::Scope::External)), "incoming"),
            (PreparedSaplingIvk::new(&dfvk.to_ivk(zip32::Scope::Internal)), "internal"),
        ]
    } else {
        vec![]
    };

    let orchard = if let Some(fvk) = ufvk.orchard() {
        vec![
            (PreparedOrchardIvk::new(&fvk.to_ivk(Scope::External)), "incoming"),
            (PreparedOrchardIvk::new(&fvk.to_ivk(Scope::Internal)), "internal"),
        ]
    } else {
        vec![]
    };

    Ok(PreparedIvks { sapling, orchard })
}

/// Convenience wrapper: prepare IVKs and wrap in an [`Arc`] for shared ownership.
///
/// This is used by the UniFFI mobile binding's opaque `PreparedIvksHandle`.
pub fn prepare_ivks_arc(viewing_key: &str) -> Result<Arc<PreparedIvks>, Error> {
    prepare_ivks(viewing_key).map(Arc::new)
}

/// Trial-decrypt compact outputs/actions in a slice of compact transactions.
///
/// Returns the txids (big-endian hex) of transactions that match our IVKs.
///
/// This is the hot path in block scanning — allocates on the heap only when a
/// match is found. The function processes Sapling outputs first, then Orchard
/// actions, short-circuiting as soon as any match is detected per transaction.
pub fn trial_decrypt_block(txs: &[CompactTransaction], ivks: &PreparedIvks) -> Vec<String> {
    let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);
    let mut matched = Vec::new();

    for tx in txs {
        let mut found = false;

        // --- Sapling outputs ---
        'sapling: for output in &tx.sapling_outputs {
            let Ok(compact_output) = parse_compact_sapling_output(output) else {
                continue;
            };
            for (ivk, _) in &ivks.sapling {
                if try_compact_note_decryption(&sapling_domain, ivk, &compact_output).is_some() {
                    found = true;
                    break 'sapling;
                }
            }
        }

        // --- Orchard actions (only if not already matched via Sapling) ---
        if !found {
            'orchard: for action in &tx.orchard_actions {
                let Ok(compact_action) = parse_compact_orchard_action(action) else {
                    continue;
                };
                let orchard_domain = OrchardDomain::for_compact_action(&compact_action);
                for (ivk, _) in &ivks.orchard {
                    if try_compact_note_decryption(&orchard_domain, ivk, &compact_action).is_some()
                    {
                        found = true;
                        break 'orchard;
                    }
                }
            }
        }

        if found {
            matched.push(tx.txid.clone());
        }
    }

    matched
}

/// Full decryption of a raw transaction hex using the UFVK.
///
/// Decrypts all shielded outputs that belong to the given viewing key,
/// returning notes with amounts, memos, and transfer types
/// (`"incoming"` / `"outgoing"` / `"internal"`).
///
/// # Errors
///
/// Returns [`Error::Decrypt`] if the UFVK is invalid, the hex is malformed,
/// or the transaction cannot be parsed for the given block height.
pub fn full_decrypt_tx(
    tx_hex: &str,
    viewing_key: &str,
    height: u32,
    network: Network,
) -> Result<DecryptedTx, Error> {
    let (_network, ufvk_str) = Ufvk::decode(viewing_key)
        .map_err(|e| Error::Decrypt(format!("UFVK decode failed: {:?}", e)))?;
    let ufvk = UnifiedFullViewingKey::parse(&ufvk_str)
        .map_err(|e| Error::Decrypt(format!("UFVK parse failed: {:?}", e)))?;
    let account_id = Uuid::nil();

    let branch_id = BranchId::for_height(&network, BlockHeight::from(height));

    let tx_bytes = hex::decode(tx_hex)
        .map_err(|e| Error::Decrypt(format!("hex decode failed: {:?}", e)))?;
    let mut cursor = Cursor::new(tx_bytes);
    let tx = ZcashTransaction::read(&mut cursor, branch_id)
        .map_err(|e| Error::Decrypt(format!("TX parse failed: {:?}", e)))?;

    let decrypted = decrypt_transaction(
        &network,
        Some(BlockHeight::from(height)),
        None,
        &tx,
        &[(account_id, ufvk)].into_iter().collect(),
    );

    let sapling_outputs = decrypted
        .sapling_outputs()
        .iter()
        .map(|f| DecryptedOutput {
            amount: decode_note_value(f.note_value()),
            memo: decode_memo(f.memo().clone()),
            transfer_type: decode_transfer_type(f.transfer_type()),
        })
        .collect();

    let orchard_outputs = decrypted
        .orchard_outputs()
        .iter()
        .map(|f| DecryptedOutput {
            amount: decode_note_value(f.note_value()),
            memo: decode_memo(f.memo().clone()),
            transfer_type: decode_transfer_type(f.transfer_type()),
        })
        .collect();

    Ok(DecryptedTx { sapling_outputs, orchard_outputs })
}

// ─── compact type parsers ─────────────────────────────────────────────────────

/// Convert a [`CompactSaplingOutput`] to the crypto type used by trial decryption.
///
/// Returns an error if any field has an unexpected byte length.
pub(crate) fn parse_compact_sapling_output(
    output: &CompactSaplingOutput,
) -> Result<CompactOutputDescription, Error> {
    let cmu_bytes: [u8; 32] = output
        .cmu
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decrypt(format!("cmu must be 32 bytes, got {}", output.cmu.len())))?;
    let epk_bytes: [u8; 32] = output
        .ephemeral_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::Decrypt(format!(
                "ephemeral_key must be 32 bytes, got {}",
                output.ephemeral_key.len()
            ))
        })?;
    let ct_bytes: [u8; COMPACT_NOTE_SIZE] = output
        .ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::Decrypt(format!(
                "ciphertext must be {} bytes, got {}",
                COMPACT_NOTE_SIZE,
                output.ciphertext.len()
            ))
        })?;

    let cmu =
        Option::<SaplingExtractedNoteCommitment>::from(SaplingExtractedNoteCommitment::from_bytes(
            &cmu_bytes,
        ))
        .ok_or_else(|| Error::Decrypt("invalid cmu field element".into()))?;

    Ok(CompactOutputDescription {
        cmu,
        ephemeral_key: EphemeralKeyBytes(epk_bytes),
        enc_ciphertext: ct_bytes,
    })
}

/// Convert a [`CompactOrchardAction`] to the crypto type used by trial decryption.
///
/// Returns an error if any field has an unexpected byte length.
pub(crate) fn parse_compact_orchard_action(
    action: &CompactOrchardAction,
) -> Result<CompactAction, Error> {
    let cmx_bytes: [u8; 32] = action
        .cmx
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decrypt(format!("cmx must be 32 bytes, got {}", action.cmx.len())))?;
    let ek_bytes: [u8; 32] = action
        .ephemeral_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::Decrypt(format!(
                "ephemeral_key must be 32 bytes, got {}",
                action.ephemeral_key.len()
            ))
        })?;
    let ct_bytes: [u8; COMPACT_NOTE_SIZE] = action
        .ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::Decrypt(format!(
                "ciphertext must be {} bytes, got {}",
                COMPACT_NOTE_SIZE,
                action.ciphertext.len()
            ))
        })?;

    let cmx = Option::<OrchardExtractedNoteCommitment>::from(
        OrchardExtractedNoteCommitment::from_bytes(&cmx_bytes),
    )
    .ok_or_else(|| Error::Decrypt("invalid cmx commitment".into()))?;

    // Nullifier is not needed for trial decryption — use a zero placeholder.
    let nullifier = OrchardNullifier::from_bytes(&[0u8; 32]).unwrap();

    Ok(CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(ek_bytes),
        ct_bytes,
    ))
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Alice testnet UFVK — the known-good key used in integration test vectors.
    const ALICE_UFVK: &str = "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

    // ── prepare_ivks ──────────────────────────────────────────────────────────

    #[test]
    fn test_prepare_ivks_valid_ufvk_has_both_pools() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        // Expect 2 Sapling IVKs (external + internal) and 2 Orchard IVKs
        assert_eq!(ivks.sapling.len(), 2);
        assert_eq!(ivks.orchard.len(), 2);
        assert_eq!(ivks.sapling[0].1, "incoming");
        assert_eq!(ivks.sapling[1].1, "internal");
        assert_eq!(ivks.orchard[0].1, "incoming");
        assert_eq!(ivks.orchard[1].1, "internal");
    }

    #[test]
    fn test_prepare_ivks_invalid_ufvk() {
        let err = prepare_ivks("not_a_valid_ufvk").err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("UFVK decode failed"));
    }

    #[test]
    fn test_prepare_ivks_empty_string() {
        let err = prepare_ivks("").err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
    }

    #[test]
    fn test_prepare_ivks_arc_wraps_correctly() {
        let arc = prepare_ivks_arc(ALICE_UFVK).unwrap();
        assert_eq!(arc.sapling.len(), 2);
        assert_eq!(arc.orchard.len(), 2);
    }

    // ── trial_decrypt_block — no-match path ───────────────────────────────────

    #[test]
    fn test_trial_decrypt_block_empty_input() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let result = trial_decrypt_block(&[], &ivks);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_tx_with_no_outputs() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "deadbeef".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_invalid_sapling_cmu_skipped() {
        // A Sapling output with wrong cmu length is silently skipped (no panic).
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "aabbccdd".to_string(),
            sapling_outputs: vec![CompactSaplingOutput {
                cmu: vec![0u8; 16], // wrong: should be 32
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            orchard_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks);
        assert!(result.is_empty(), "invalid output should be skipped, not panic");
    }

    #[test]
    fn test_trial_decrypt_block_invalid_orchard_cmx_skipped() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "11223344".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![CompactOrchardAction {
                cmx: vec![0u8; 10], // wrong: should be 32
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
        };
        let result = trial_decrypt_block(&[tx], &ivks);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_all_zeros_sapling_no_match() {
        // Correct lengths but all-zero bytes: won't decrypt for any real key.
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "cafebabe".to_string(),
            sapling_outputs: vec![CompactSaplingOutput {
                cmu: vec![0u8; 32],
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            orchard_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_all_zeros_orchard_no_match() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "feedface".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![CompactOrchardAction {
                cmx: vec![0u8; 32],
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
        };
        let result = trial_decrypt_block(&[tx], &ivks);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_multiple_txs_none_match() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let txs: Vec<_> = (0..5)
            .map(|i| CompactTransaction {
                txid: format!("{:064x}", i),
                sapling_outputs: vec![CompactSaplingOutput {
                    cmu: vec![0u8; 32],
                    ephemeral_key: vec![0u8; 32],
                    ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
                }],
                orchard_actions: vec![],
            })
            .collect();
        let result = trial_decrypt_block(&txs, &ivks);
        assert!(result.is_empty());
    }

    // ── parse_compact_sapling_output ─────────────────────────────────────────

    #[test]
    fn test_parse_sapling_wrong_cmu_length() {
        let out = CompactSaplingOutput {
            cmu: vec![0u8; 16],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        let err = parse_compact_sapling_output(&out).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("cmu must be 32 bytes"));
    }

    #[test]
    fn test_parse_sapling_wrong_epk_length() {
        let out = CompactSaplingOutput {
            cmu: vec![0u8; 32],
            ephemeral_key: vec![0u8; 10],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        let err = parse_compact_sapling_output(&out).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("ephemeral_key must be 32 bytes"));
    }

    #[test]
    fn test_parse_sapling_wrong_ciphertext_length() {
        let out = CompactSaplingOutput {
            cmu: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 10],
        };
        let err = parse_compact_sapling_output(&out).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("ciphertext must be"));
    }

    // ── parse_compact_orchard_action ─────────────────────────────────────────

    #[test]
    fn test_parse_orchard_wrong_cmx_length() {
        let action = CompactOrchardAction {
            cmx: vec![0u8; 16],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        let err = parse_compact_orchard_action(&action).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("cmx must be 32 bytes"));
    }

    #[test]
    fn test_parse_orchard_wrong_epk_length() {
        let action = CompactOrchardAction {
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 5],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        let err = parse_compact_orchard_action(&action).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("ephemeral_key must be 32 bytes"));
    }

    #[test]
    fn test_parse_orchard_wrong_ciphertext_length() {
        let action = CompactOrchardAction {
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 3],
        };
        let err = parse_compact_orchard_action(&action).err().unwrap();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("ciphertext must be"));
    }

    // ── decode_memo ───────────────────────────────────────────────────────────

    #[test]
    fn test_decode_memo_empty() {
        let memo = MemoBytes::from_bytes(&[0u8; 512]).unwrap();
        assert_eq!(decode_memo(memo), "");
    }

    #[test]
    fn test_decode_memo_utf8_text() {
        let mut bytes = [0u8; 512];
        let text = b"Hello, Zcash!";
        bytes[..text.len()].copy_from_slice(text);
        let memo = MemoBytes::from_bytes(&bytes).unwrap();
        assert_eq!(decode_memo(memo), "Hello, Zcash!");
    }

    #[test]
    fn test_decode_memo_null_terminated() {
        let mut bytes = [0u8; 512];
        let text = b"abc";
        bytes[..3].copy_from_slice(text);
        // bytes[3] = 0 (null terminator)
        let memo = MemoBytes::from_bytes(&bytes).unwrap();
        assert_eq!(decode_memo(memo), "abc");
    }

    // ── full_decrypt_tx — error paths ─────────────────────────────────────────

    #[test]
    fn test_full_decrypt_tx_invalid_hex() {
        let err = full_decrypt_tx("not_hex!!", ALICE_UFVK, 1_900_000, Network::TestNetwork)
            .unwrap_err();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("hex decode failed"));
    }

    #[test]
    fn test_full_decrypt_tx_invalid_ufvk() {
        let err =
            full_decrypt_tx("deadbeef", "bad_ufvk", 1_900_000, Network::TestNetwork).unwrap_err();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("UFVK decode failed"));
    }

    #[test]
    fn test_full_decrypt_tx_invalid_tx_bytes() {
        // Valid hex but not a valid Zcash transaction
        let err = full_decrypt_tx(
            "deadbeefcafebabe",
            ALICE_UFVK,
            1_900_000,
            Network::TestNetwork,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Decrypt(_)));
        assert!(err.to_string().contains("TX parse failed"));
    }
}
