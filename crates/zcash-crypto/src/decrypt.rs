use std::io::Cursor;
use std::sync::Arc;

use rayon::prelude::*;

use orchard::{
    keys::{PreparedIncomingViewingKey as PreparedOrchardIvk, Scope},
    note::{
        ExtractedNoteCommitment as OrchardExtractedNoteCommitment,
        Nullifier as OrchardNullifier,
    },
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
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
use zcash_note_encryption::{batch, EphemeralKeyBytes, COMPACT_NOTE_SIZE};
use zcash_primitives::transaction::Transaction as ZcashTransaction;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
    ShieldedPool,
};

use crate::error::Error;

// ─── compact block data types ─────────────────────────────────────────────────
//
// These types represent compact block data as streamed by lightwalletd.
// They are intentionally decoupled from any proto/tonic dependency so this
// crate compiles for all targets including iOS and Android.
// The `zcash-sync` crate converts proto `CompactTx` → `CompactTransaction` before
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
    /// Spent nullifier (nf, 32 bytes). Used in Phase 4 to detect outgoing transactions
    /// by matching against nullifiers of previously received notes.
    pub nf: Vec<u8>,
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
    /// Ironwood (NU6.3) shielded actions in this transaction.
    ///
    /// Ironwood reuses the exact `OrchardAction` wire encoding (same 820 B/action
    /// shape as `orchard_actions`), so it is represented with the same
    /// [`CompactOrchardAction`] type — only the note-plaintext version decrypted
    /// from it differs (Ironwood = ZIP 2005 `0x03`, decrypted with the SAME
    /// Orchard incoming viewing keys as `orchard_actions`; no separate ivk).
    pub ironwood_actions: Vec<CompactOrchardAction>,
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
    /// The shielded pool this note belongs to (Sapling, Orchard, or Ironwood).
    ///
    /// Carried straight from upstream's `DecryptedOutput::value_pool()` — this
    /// crate does not invent its own pool enum. This is the field that lets a
    /// consumer distinguish an Ironwood note from an Orchard note; both use the
    /// same `orchard::Note` representation and the same spending-field shape.
    pub pool: ShieldedPool,
    /// Orchard/Ironwood nullifier for this note (32 bytes).
    /// `Some` for incoming/internal Orchard-family notes; `None` for Sapling or outgoing.
    /// Used by the sync engine to detect when received notes are later spent
    /// (outgoing transactions that would otherwise be invisible to trial decryption).
    pub nullifier: Option<[u8; 32]>,

    /// rho value for the note (32 bytes, Pallas base field).
    /// Equals nf_old from the same Action description (protocol spec section 4.7.3).
    /// Required together with rseed for `Note::from_parts` during spending.
    /// `Some` for Orchard incoming/internal; `None` for outgoing and all Sapling notes.
    pub rho: Option<[u8; 32]>,

    /// Random seed for the note (32 bytes). Needed to re-derive psi, rcm for spending.
    /// `Some` for Orchard incoming/internal; `None` for outgoing and all Sapling notes.
    pub rseed: Option<[u8; 32]>,

    /// Extracted note commitment (cmx, 32 bytes — Pallas base field u-coordinate).
    /// Required to locate the note in the commitment tree.
    /// `Some` for Orchard incoming/internal; `None` otherwise.
    pub cmx: Option<[u8; 32]>,

    /// Recipient address bytes (43 bytes: 11-byte diversifier `d` + 32-byte `pk_d`).
    /// Required to reconstruct the note for spending.
    /// `Some` for Orchard incoming/internal; `None` otherwise.
    pub recipient: Option<[u8; 43]>,

    /// 0-based action index within the Orchard bundle of the containing transaction.
    /// Used by the sync layer to compute the note's Merkle tree position.
    /// `Some` for Orchard incoming/internal; `None` otherwise.
    pub action_index: Option<u32>,
}

/// All decrypted outputs from a single transaction.
#[derive(Debug, Clone)]
pub struct DecryptedTx {
    pub sapling_outputs: Vec<DecryptedOutput>,
    pub orchard_outputs: Vec<DecryptedOutput>,
    /// Decrypted Ironwood (NU6.3) outputs. Additive and parallel to
    /// `orchard_outputs` — Ironwood is a second, separate Orchard-family pool
    /// with its own commitment tree and nullifier set (see `docs/architecture.md`).
    pub ironwood_outputs: Vec<DecryptedOutput>,
    /// Transaction fee in zatoshis (= valueBalanceSapling + valueBalanceOrchard + valueBalanceIronwood).
    /// Always ≥ 0 for valid fully-shielded transactions.
    pub fee_zatoshis: i64,
}

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Determine the correct [`Zip212Enforcement`] for Sapling trial decryption at
/// a given block height.
///
/// ZIP-212 (Heartwood) changed the Sapling note plaintext format.  Notes in
/// blocks below the activation height must be decrypted with `Off`; those at
/// or above use `On`.  A 32 256-block grace period immediately after activation
/// accepted both formats — we model that with `GracePeriod`.
///
/// Activation heights (inclusive):
/// - Mainnet : 903 800
/// - Testnet : 1 028 500
fn zip212_enforcement(network: &Network, height: u32) -> Zip212Enforcement {
    // Heartwood (ZIP-212) activation heights — hardcoded because
    // zcash_protocol::consensus::Network does not expose per-network upgrade
    // heights reliably via the Parameters trait in the versions we target.
    //
    // Source: https://zips.z.cash/zip-0212
    //   Mainnet : 903 800
    //   Testnet : 1 028 500
    let heartwood: u32 = match network {
        Network::MainNetwork => 903_800,
        Network::TestNetwork => 1_028_500,
    };
    // 32 256-block grace period: both pre- and post-ZIP-212 note plaintexts
    // are valid, so use GracePeriod to accept either format.
    if height >= heartwood {
        if height < heartwood + 32_256 {
            Zip212Enforcement::GracePeriod
        } else {
            Zip212Enforcement::On
        }
    } else {
        Zip212Enforcement::Off
    }
}

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
pub fn prepare_ivks_arc(viewing_key: &str) -> Result<Arc<PreparedIvks>, Error> {
    prepare_ivks(viewing_key).map(Arc::new)
}

/// Trial-decrypt compact outputs/actions in a slice of compact transactions.
///
/// Returns the txids (big-endian hex) of transactions that match our IVKs.
///
/// Strategy: split all outputs in the block into `rayon::current_num_threads()`
/// chunks, each processed with `batch::try_compact_note_decryption`. This
/// combines two optimisations:
/// - Batch API: each chunk uses one `batch_to_affine()` instead of N inversions.
/// - Rayon: chunks run in parallel across all available CPU cores.
pub fn trial_decrypt_block(
    txs: &[CompactTransaction],
    ivks: &PreparedIvks,
    height: u32,
    network: &Network,
) -> Vec<String> {
    let sapling_ivks: Vec<PreparedSaplingIvk> =
        ivks.sapling.iter().map(|(ivk, _)| ivk.clone()).collect();
    let orchard_ivks: Vec<PreparedOrchardIvk> =
        ivks.orchard.iter().map(|(ivk, _)| ivk.clone()).collect();

    // Compute the correct ZIP-212 enforcement for this block height once.
    let zip212 = zip212_enforcement(network, height);

    // ── Collect parsed outputs tagged with tx index ───────────────────────────
    let sapling_raw: Vec<(usize, CompactOutputDescription)> = txs
        .iter()
        .enumerate()
        .flat_map(|(tx_idx, tx)| {
            tx.sapling_outputs.iter().filter_map(move |o| {
                parse_compact_sapling_output(o).ok().map(|parsed| (tx_idx, parsed))
            })
        })
        .collect();

    {
        let total: usize = txs.iter().map(|tx| tx.sapling_outputs.len()).sum();
        let skipped = total - sapling_raw.len();
        if skipped > 0 {
            eprintln!(
                "WARN: trial_decrypt_block skipped {skipped} malformed Sapling output(s) at height {height}"
            );
        }
    }

    let orchard_raw: Vec<(usize, CompactAction)> = txs
        .iter()
        .enumerate()
        .flat_map(|(tx_idx, tx)| {
            tx.orchard_actions.iter().filter_map(move |a| {
                parse_compact_orchard_action(a).ok().map(|action| (tx_idx, action))
            })
        })
        .collect();

    {
        let total: usize = txs.iter().map(|tx| tx.orchard_actions.len()).sum();
        let skipped = total - orchard_raw.len();
        if skipped > 0 {
            eprintln!(
                "WARN: trial_decrypt_block skipped {skipped} malformed Orchard action(s) at height {height}"
            );
        }
    }

    // Ironwood actions reuse the exact CompactOrchardAction wire shape, so parsing
    // is identical to the Orchard path above. Only the domain type used for trial
    // decryption differs (IronwoodDomain vs OrchardDomain), and the ivks are the
    // SAME Orchard ivks (one ivk decrypts both pools).
    let ironwood_raw: Vec<(usize, CompactAction)> = txs
        .iter()
        .enumerate()
        .flat_map(|(tx_idx, tx)| {
            tx.ironwood_actions.iter().filter_map(move |a| {
                parse_compact_orchard_action(a).ok().map(|action| (tx_idx, action))
            })
        })
        .collect();

    {
        let total: usize = txs.iter().map(|tx| tx.ironwood_actions.len()).sum();
        let skipped = total - ironwood_raw.len();
        if skipped > 0 {
            eprintln!(
                "WARN: trial_decrypt_block skipped {skipped} malformed Ironwood action(s) at height {height}"
            );
        }
    }

    let n_threads = rayon::current_num_threads().max(1);

    // ── Parallel chunked batch Sapling ────────────────────────────────────────
    let sapling_matched: std::collections::HashSet<usize> = if sapling_raw.is_empty() {
        Default::default()
    } else {
        let chunk_size = (sapling_raw.len() / n_threads).max(1);
        sapling_raw
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let outputs: Vec<(SaplingDomain, CompactOutputDescription)> = chunk
                    .iter()
                    .map(|(_, o)| (SaplingDomain::new(zip212), o.clone()))
                    .collect();
                let results = batch::try_compact_note_decryption(&sapling_ivks, &outputs);
                chunk
                    .iter()
                    .zip(results)
                    .filter_map(|((idx, _), r)| r.map(|_| *idx))
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    // ── Parallel chunked batch Orchard ────────────────────────────────────────
    let orchard_matched: std::collections::HashSet<usize> = if orchard_raw.is_empty() {
        Default::default()
    } else {
        let chunk_size = (orchard_raw.len() / n_threads).max(1);
        orchard_raw
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let outputs: Vec<(OrchardDomain, CompactAction)> = chunk
                    .iter()
                    .map(|(_, a)| (OrchardDomain::for_compact_action(a), a.clone()))
                    .collect();
                let results = batch::try_compact_note_decryption(&orchard_ivks, &outputs);
                chunk
                    .iter()
                    .zip(results)
                    .filter_map(|((idx, _), r)| r.map(|_| *idx))
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    // ── Parallel chunked batch Ironwood (same ivks as Orchard) ───────────────
    let ironwood_matched: std::collections::HashSet<usize> = if ironwood_raw.is_empty() {
        Default::default()
    } else {
        let chunk_size = (ironwood_raw.len() / n_threads).max(1);
        ironwood_raw
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let outputs: Vec<(IronwoodDomain, CompactAction)> = chunk
                    .iter()
                    .map(|(_, a)| (IronwoodDomain::for_compact_action(a), a.clone()))
                    .collect();
                let results = batch::try_compact_note_decryption(&orchard_ivks, &outputs);
                chunk
                    .iter()
                    .zip(results)
                    .filter_map(|((idx, _), r)| r.map(|_| *idx))
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    txs.iter()
        .enumerate()
        .filter_map(|(i, tx)| {
            if sapling_matched.contains(&i)
                || orchard_matched.contains(&i)
                || ironwood_matched.contains(&i)
            {
                Some(tx.txid.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Full decryption of a raw transaction hex using a pre-parsed UFVK.
///
/// This is the hot-path variant used by `run_sync()` where the UFVK is
/// parsed once per sync and reused across all matched transactions.
pub fn full_decrypt_tx_with_ufvk(
    tx_hex: &str,
    ufvk: &UnifiedFullViewingKey,
    height: u32,
    network: Network,
) -> Result<DecryptedTx, Error> {
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
        &[(account_id, ufvk.clone())].into_iter().collect(),
    );

    let sapling_outputs = decrypted
        .sapling_outputs()
        .iter()
        .map(|f| DecryptedOutput {
            amount: decode_note_value(f.note_value()),
            memo: decode_memo(f.memo().clone()),
            transfer_type: decode_transfer_type(f.transfer_type()),
            pool: f.value_pool(),
            nullifier: None, // Sapling nullifier tracking not needed (Ledger is Orchard-only)
            rho: None,
            rseed: None,
            cmx: None,
            recipient: None,
            action_index: None,
        })
        .collect();

    let orchard_outputs = decrypted
        .orchard_outputs()
        .iter()
        .map(|f| map_orchard_family_output(f, ufvk))
        .collect();

    // Ironwood (NU6.3) is a second, separate Orchard-family pool. Its outputs are
    // Orchard-shaped (`orchard::Note`) and decrypted with the SAME Orchard ivks —
    // `map_orchard_family_output` is pool-agnostic and reads the real pool tag
    // (`f.value_pool()`) from upstream, so no separate mapping logic is needed here.
    let ironwood_outputs = decrypted
        .ironwood_outputs()
        .iter()
        .map(|f| map_orchard_family_output(f, ufvk))
        .collect();

    // Use TransactionData::fee_paid for an accurate protocol-level fee calculation.
    // For fully-shielded transactions this gives the exact fee. For transactions
    // with transparent inputs we don't have prevout values from compact blocks,
    // so get_prevout returns None and fee_paid returns Ok(None) → we fall back to 0.
    let fee_zatoshis = tx
        .into_data()
        .fee_paid(|_outpoint| -> Result<Option<Zatoshis>, BalanceError> { Ok(None) })
        .ok()
        .flatten()
        .map(|z| z.into_u64() as i64)
        .unwrap_or(0);

    Ok(DecryptedTx { sapling_outputs, orchard_outputs, ironwood_outputs, fee_zatoshis })
}

/// Maps one upstream Orchard-family decrypted output (Orchard OR Ironwood — both
/// are `orchard::Note` tagged with an `orchard::ValuePool`) to our [`DecryptedOutput`].
///
/// Shared by both `orchard_outputs()` and `ironwood_outputs()` mapping in
/// [`full_decrypt_tx_with_ufvk`]: the two pools use identical spending-field
/// extraction and the SAME Orchard full viewing key for the nullifier
/// (one ivk/fvk scope covers both pools). The real pool tag
/// (`f.value_pool()`) — not an assumption baked into the caller — determines
/// `pool` on the output.
fn map_orchard_family_output(
    f: &zcash_client_backend::DecryptedOutput<(orchard::Note, orchard::ValuePool), Uuid>,
    ufvk: &UnifiedFullViewingKey,
) -> DecryptedOutput {
    // Compute the nullifier for incoming/internal notes so the sync engine
    // can later detect when these notes are spent (Phase 4 outgoing-tx detection).
    // Outgoing notes do not generate a nullifier we need to track.
    let is_outgoing = matches!(
        f.transfer_type(),
        zcash_client_backend::TransferType::Outgoing
    );

    // `f.note()` now returns `&(orchard::Note, orchard::ValuePool)` — destructure
    // to get at the note; the pool element is intentionally unused here because
    // `f.value_pool()` (below) is the authoritative, upstream-computed pool tag.
    let (note, _) = f.note();

    let nullifier = if is_outgoing {
        None
    } else {
        ufvk.orchard().map(|fvk| note.nullifier(fvk).to_bytes())
    };

    // Extract spending fields for incoming/internal notes.
    // All fields are populated together: all or none.
    let (rho, rseed, cmx, recipient, action_index) = if is_outgoing {
        (None, None, None, None, None)
    } else {
        let rho_bytes: [u8; 32] = note.rho().to_bytes();
        let rseed_bytes: [u8; 32] = *note.rseed().as_bytes();

        let cmx_bytes: [u8; 32] = {
            let nc = note.commitment();
            OrchardExtractedNoteCommitment::from(nc).to_bytes()
        };

        // to_raw_address_bytes() returns [u8; 43]: 11-byte diversifier + 32-byte pk_d.
        let recipient_bytes: [u8; 43] = note.recipient().to_raw_address_bytes();

        // index() returns the 0-based action index within the containing bundle.
        // Cast to u32 is safe: action counts per transaction are always < 2^32.
        let idx: u32 = f.index() as u32;

        (Some(rho_bytes), Some(rseed_bytes), Some(cmx_bytes), Some(recipient_bytes), Some(idx))
    };

    DecryptedOutput {
        // `note.value()` (orchard::value::NoteValue) replaces the removed
        // `DecryptedOutput::note_value()` accessor, which is no longer implemented
        // for the `(Note, ValuePool)` tuple note type introduced by the bump.
        amount: note.value().inner(),
        memo: decode_memo(f.memo().clone()),
        transfer_type: decode_transfer_type(f.transfer_type()),
        pool: f.value_pool(),
        nullifier,
        rho,
        rseed,
        cmx,
        recipient,
        action_index,
    }
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
    full_decrypt_tx_with_ufvk(tx_hex, &ufvk, height, network)
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

    // Use the actual spent nullifier from the compact block.
    // Falls back to zero if the field is missing/malformed (trial decryption doesn't
    // use the nullifier, so this only affects Phase 4 outgoing-tx detection which
    // operates on raw bytes via CompactOrchardAction.nf directly).
    let nf_bytes: [u8; 32] = action.nf.as_slice().try_into().unwrap_or([0u8; 32]);
    let nullifier = OrchardNullifier::from_bytes(&nf_bytes)
        .into_option()
        .unwrap_or_else(|| OrchardNullifier::from_bytes(&[0u8; 32]).unwrap());

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

    // Test height safely above Heartwood on testnet (1_028_500) — ZIP-212 is On.
    const TEST_HEIGHT: u32 = 1_900_000;

    #[test]
    fn test_trial_decrypt_block_empty_input() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let result = trial_decrypt_block(&[], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_tx_with_no_outputs() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "deadbeef".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![],
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_invalid_sapling_cmu_skipped() {
        // A Sapling output with wrong cmu length is skipped with a WARN log (no panic).
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "aabbccdd".to_string(),
            sapling_outputs: vec![CompactSaplingOutput {
                cmu: vec![0u8; 16], // wrong: should be 32
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            orchard_actions: vec![],
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert!(result.is_empty(), "invalid output should be skipped, not panic");
    }

    #[test]
    fn test_trial_decrypt_block_invalid_orchard_cmx_skipped() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "11223344".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![CompactOrchardAction {
                nf: vec![0u8; 32],
                cmx: vec![0u8; 10], // wrong: should be 32
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
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
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_all_zeros_orchard_no_match() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "feedface".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![CompactOrchardAction {
                nf: vec![0u8; 32],
                cmx: vec![0u8; 32],
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
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
                ironwood_actions: vec![],
            })
            .collect();
        let result = trial_decrypt_block(&txs, &ivks, TEST_HEIGHT, &Network::TestNetwork);
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
            nf: vec![0u8; 32],
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
            nf: vec![0u8; 32],
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
            nf: vec![0u8; 32],
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

    // ── zip212_enforcement ────────────────────────────────────────────────────

    // Heartwood activation: mainnet 903_800, testnet 1_028_500
    // Grace period: [heartwood, heartwood + 32_256)
    // After grace: [heartwood + 32_256, ∞)

    #[test]
    fn test_zip212_mainnet_below_heartwood() {
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 903_799), Zip212Enforcement::Off);
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 0), Zip212Enforcement::Off);
    }

    #[test]
    fn test_zip212_mainnet_at_heartwood_is_grace_period() {
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 903_800), Zip212Enforcement::GracePeriod);
    }

    #[test]
    fn test_zip212_mainnet_within_grace_period() {
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 903_801), Zip212Enforcement::GracePeriod);
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 903_800 + 32_255), Zip212Enforcement::GracePeriod);
    }

    #[test]
    fn test_zip212_mainnet_after_grace_period() {
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 903_800 + 32_256), Zip212Enforcement::On);
        assert_eq!(zip212_enforcement(&Network::MainNetwork, 2_000_000), Zip212Enforcement::On);
    }

    #[test]
    fn test_zip212_testnet_below_heartwood() {
        assert_eq!(zip212_enforcement(&Network::TestNetwork, 1_028_499), Zip212Enforcement::Off);
    }

    #[test]
    fn test_zip212_testnet_at_heartwood_is_grace_period() {
        assert_eq!(zip212_enforcement(&Network::TestNetwork, 1_028_500), Zip212Enforcement::GracePeriod);
    }

    #[test]
    fn test_zip212_testnet_after_grace_period() {
        assert_eq!(zip212_enforcement(&Network::TestNetwork, 1_028_500 + 32_256), Zip212Enforcement::On);
    }

    // ── parse_compact_orchard_action — nf fallback ────────────────────────────

    #[test]
    fn test_parse_orchard_short_nf_falls_back_silently() {
        // nf with wrong length: parse_compact_orchard_action should NOT error —
        // it falls back to [0u8; 32]. Trial decryption doesn't use the nf field.
        let action = CompactOrchardAction {
            nf: vec![0u8; 5], // wrong length
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        // Should succeed (fallback to zero nf), not return an error
        assert!(parse_compact_orchard_action(&action).is_ok());
    }

    #[test]
    fn test_parse_orchard_empty_nf_falls_back_silently() {
        let action = CompactOrchardAction {
            nf: vec![], // empty
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
        };
        assert!(parse_compact_orchard_action(&action).is_ok());
    }

    // ── decode_memo — invalid UTF-8 ───────────────────────────────────────────

    #[test]
    fn test_decode_memo_invalid_utf8_returns_empty() {
        // 0xFF 0xFE are not valid UTF-8 — unwrap_or_default() should return "".
        let mut bytes = [0u8; 512];
        bytes[0] = 0xFF;
        bytes[1] = 0xFE;
        // bytes[2] stays 0 (null-terminator), so memo_len = 2, but the slice
        // [0xFF, 0xFE] is invalid UTF-8 → unwrap_or_default → "".
        let memo = MemoBytes::from_bytes(&bytes).unwrap();
        assert_eq!(decode_memo(memo), "");
    }

    // ── trial_decrypt_block — mainnet network ─────────────────────────────────

    #[test]
    fn test_trial_decrypt_block_mainnet_height_no_panic() {
        // Ensures the function runs correctly with mainnet network
        // (different ZIP-212 boundary than testnet).
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "aabbccdd".to_string(),
            sapling_outputs: vec![CompactSaplingOutput {
                cmu: vec![0u8; 32],
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            orchard_actions: vec![],
            ironwood_actions: vec![],
        };
        // Below mainnet Heartwood (903_800) — ZIP-212 Off
        let result = trial_decrypt_block(
            std::slice::from_ref(&tx),
            &ivks,
            500_000,
            &Network::MainNetwork,
        );
        assert!(result.is_empty());
        // Above mainnet Heartwood + grace — ZIP-212 On
        let result = trial_decrypt_block(&[tx], &ivks, 2_000_000, &Network::MainNetwork);
        assert!(result.is_empty());
    }

    #[test]
    fn test_trial_decrypt_block_only_returns_matching_txids() {
        // With random/zero data, no txids should match. The result must be a
        // strict subset of the input txids (never returns txids not in input).
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let txids = ["aaaa", "bbbb", "cccc"];
        let txs: Vec<_> = txids
            .iter()
            .map(|id| CompactTransaction {
                txid: id.to_string(),
                sapling_outputs: vec![CompactSaplingOutput {
                    cmu: vec![0u8; 32],
                    ephemeral_key: vec![0u8; 32],
                    ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
                }],
                orchard_actions: vec![CompactOrchardAction {
                    nf: vec![0u8; 32],
                    cmx: vec![0u8; 32],
                    ephemeral_key: vec![0u8; 32],
                    ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
                }],
                ironwood_actions: vec![],
            })
            .collect();
        let result = trial_decrypt_block(&txs, &ivks, TEST_HEIGHT, &Network::TestNetwork);
        // All returned txids must be from the input set
        let input_set: std::collections::HashSet<_> = txids.iter().copied().collect();
        for txid in &result {
            assert!(input_set.contains(txid.as_str()), "unexpected txid in result: {txid}");
        }
    }

    // ── DecryptedOutput new fields — unit tests ───────────────────────────────

    /// A `DecryptedOutput` with `transfer_type = "outgoing"` must have all
    /// spending fields set to `None`.  This mirrors what `full_decrypt_tx` does
    /// for outgoing Orchard notes.
    #[test]
    fn test_decrypt_output_new_fields_are_none_for_outgoing() {
        let output = DecryptedOutput {
            amount: 1_000,
            memo: String::new(),
            transfer_type: "outgoing".to_string(),
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            recipient: None,
            action_index: None,
            pool: ShieldedPool::Orchard,
        };
        assert_eq!(output.transfer_type, "outgoing");
        assert!(output.rseed.is_none(), "outgoing: rseed must be None");
        assert!(output.cmx.is_none(), "outgoing: cmx must be None");
        assert!(output.recipient.is_none(), "outgoing: recipient must be None");
        assert!(output.action_index.is_none(), "outgoing: action_index must be None");
    }

    /// Sapling outputs are always constructed with all spending fields set to
    /// `None` (Sapling uses a different spending mechanism; we never populate
    /// these for Sapling).
    #[test]
    fn test_decrypt_output_sapling_has_no_spending_fields() {
        // Simulate the Sapling mapping path by constructing DecryptedOutput
        // exactly as the sapling_outputs iterator does.
        let output = DecryptedOutput {
            amount: 5_000_000,
            memo: "sapling memo".to_string(),
            transfer_type: "incoming".to_string(),
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            recipient: None,
            action_index: None,
            pool: ShieldedPool::Sapling,
        };
        assert!(output.rseed.is_none(), "Sapling: rseed must be None");
        assert!(output.cmx.is_none(), "Sapling: cmx must be None");
        assert!(output.recipient.is_none(), "Sapling: recipient must be None");
        assert!(output.action_index.is_none(), "Sapling: action_index must be None");
    }

    /// Verify that incoming/internal `DecryptedOutput` values can carry spending
    /// fields with the correct byte lengths.  This test checks the structural
    /// contract without requiring a real decryption (which needs network / fixtures).
    #[test]
    fn test_decrypt_output_incoming_spending_fields_byte_lengths() {
        let rseed = [0xaau8; 32];
        let cmx = [0xbbu8; 32];
        let recipient = [0xccu8; 43];

        let output = DecryptedOutput {
            amount: 100_000_000,
            memo: String::new(),
            transfer_type: "incoming".to_string(),
            nullifier: Some([0u8; 32]),
            rho: Some([0xddu8; 32]),
            rseed: Some(rseed),
            cmx: Some(cmx),
            recipient: Some(recipient),
            action_index: Some(0),
            pool: ShieldedPool::Orchard,
        };

        let r = output.rseed.unwrap();
        assert_eq!(r.len(), 32, "rseed must be 32 bytes");

        let c = output.cmx.unwrap();
        assert_eq!(c.len(), 32, "cmx must be 32 bytes");

        let rec = output.recipient.unwrap();
        assert_eq!(rec.len(), 43, "recipient must be 43 bytes");

        assert_eq!(output.action_index.unwrap(), 0);
    }

    /// `action_index` distinguishes multiple actions within the same transaction.
    #[test]
    fn test_decrypt_output_action_index_values() {
        let make = |idx: u32| DecryptedOutput {
            amount: 1,
            memo: String::new(),
            transfer_type: "incoming".to_string(),
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            recipient: None,
            action_index: Some(idx),
            pool: ShieldedPool::Orchard,
        };
        assert_eq!(make(0).action_index, Some(0));
        assert_eq!(make(7).action_index, Some(7));
        assert_eq!(make(u32::MAX).action_index, Some(u32::MAX));
    }

    // ── BranchId::for_height — NU6.2 activation assertions ──────────────────

    #[test]
    fn test_branch_id_nu6_2_mainnet_at_activation() {
        // NU6.2 activates on mainnet at block 3,364,600.
        assert_eq!(
            BranchId::for_height(&Network::MainNetwork, BlockHeight::from(3_364_600_u32)),
            BranchId::Nu6_2,
            "height 3_364_600 must resolve to Nu6_2 on mainnet"
        );
    }

    #[test]
    fn test_branch_id_nu6_1_mainnet_one_below_activation() {
        // One block before NU6.2 activation must still be Nu6_1.
        assert_eq!(
            BranchId::for_height(&Network::MainNetwork, BlockHeight::from(3_364_599_u32)),
            BranchId::Nu6_1,
            "height 3_364_599 must resolve to Nu6_1 on mainnet"
        );
    }

    #[test]
    fn test_branch_id_nu6_2_testnet_at_activation() {
        // NU6.2 activates on testnet at block 4,052,000.
        assert_eq!(
            BranchId::for_height(&Network::TestNetwork, BlockHeight::from(4_052_000_u32)),
            BranchId::Nu6_2,
            "height 4_052_000 must resolve to Nu6_2 on testnet"
        );
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

    // ── Ironwood (NU6.3) — trial decryption ──────────────────────────────────
    //
    // Full end-to-end decryption of a real V6/Ironwood transaction (0x03 note
    // reconstruction against genuine on-chain data) cannot be exercised yet: no
    // NU6.3 transaction exists on any chain this dry-run can reach (no Ledger
    // Ironwood endpoint is reachable from this dry-run yet), so no
    // real fixture bytes exist to capture (mirroring `known_vectors.rs`, which
    // captures real mainnet/testnet V4/V5 bytes — none exist for V6 yet). The
    // trial-decrypt round-trip below instead constructs a *synthetic* Ironwood
    // action directly from the public `orchard` note-encryption API (the same
    // approach the `orchard` crate's own test suite uses internally), which
    // exercises genuine cryptography — real Note/RandomSeed/Rho values, a real
    // Ironwood-domain encryption, and the real `try_compact_note_decryption`
    // path — without needing chain data.

    /// Builds a synthetic, correctly-encrypted `CompactOrchardAction` for
    /// Alice's external Orchard address, encrypted under the Ironwood note
    /// plaintext version (`NoteVersion::V3`, ZIP 2005 lead byte `0x03`).
    ///
    /// Returns the compact action alongside the note's `rho` (== the `nf` byte
    /// value it derives from, since `Rho::from_nf_old` is the identity on the
    /// underlying field element) so callers can assert on `cmx` reconstruction.
    fn make_ironwood_compact_action() -> (CompactOrchardAction, [u8; 32]) {
        use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
        use orchard::note_encryption::IronwoodNoteEncryption;
        use orchard::value::NoteValue;
        use zcash_note_encryption::Domain;

        let (_network, ufvk_str) = Ufvk::decode(ALICE_UFVK).unwrap();
        let ufvk = UnifiedFullViewingKey::parse(&ufvk_str).unwrap();
        let fvk = ufvk.orchard().expect("Alice's UFVK carries an Orchard component");
        let recipient = fvk.address_at(0u32, Scope::External);

        // rho == nf_old's field element (Rho::from_nf_old(nf) is nf reinterpreted
        // as a Rho), so encoding the same 32 zero bytes for both keeps them equal.
        let rho_bytes = [0u8; 32];
        let rho = Rho::from_bytes(&rho_bytes).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xcdu8; 32], &rho).into_option().unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(1_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .expect("Note::from_parts must produce a canonical V3 note");

        let cmx_bytes: [u8; 32] =
            OrchardExtractedNoteCommitment::from(note.commitment()).to_bytes();

        let enc = IronwoodNoteEncryption::new(None, note, [0u8; 512]);
        let full_ciphertext = enc.encrypt_note_plaintext();
        let ephemeral_key = IronwoodDomain::epk_bytes(enc.epk());

        let action = CompactOrchardAction {
            nf: rho_bytes.to_vec(),
            cmx: cmx_bytes.to_vec(),
            ephemeral_key: ephemeral_key.0.to_vec(),
            ciphertext: full_ciphertext[..COMPACT_NOTE_SIZE].to_vec(),
        };
        (action, rho_bytes)
    }

    /// Verifies sync detects and fully-decrypts Ironwood notes
    /// from V6 Ironwood bundles (trial-decrypt half). An Ironwood action,
    /// correctly encrypted under a real Orchard ivk, must be found by
    /// `trial_decrypt_block` using the SAME ivk set `prepare_ivks` derives for
    /// Orchard — no separate Ironwood ivk is ever derived.
    #[test]
    fn ironwood_action_trial_decrypts_with_orchard_ivk_matches() {
        let (action, _rho_bytes) = make_ironwood_compact_action();
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "ironwood00".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![],
            ironwood_actions: vec![action],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert_eq!(
            result,
            vec!["ironwood00".to_string()],
            "a correctly-encrypted Ironwood action must be matched by trial_decrypt_block              using the same ivks prepared for Orchard"
        );
    }

    /// Regression: a transaction with only an (unmatched) Orchard action and a
    /// separate, empty `ironwood_actions` list is unaffected by the new field —
    /// no match is fabricated out of an empty Ironwood list.
    #[test]
    fn ironwood_actions_empty_does_not_affect_orchard_only_tx() {
        let ivks = prepare_ivks(ALICE_UFVK).unwrap();
        let tx = CompactTransaction {
            txid: "orchardonly".to_string(),
            sapling_outputs: vec![],
            orchard_actions: vec![CompactOrchardAction {
                nf: vec![0u8; 32],
                cmx: vec![0u8; 32],
                ephemeral_key: vec![0u8; 32],
                ciphertext: vec![0u8; COMPACT_NOTE_SIZE],
            }],
            ironwood_actions: vec![],
        };
        let result = trial_decrypt_block(&[tx], &ivks, TEST_HEIGHT, &Network::TestNetwork);
        assert!(result.is_empty(), "all-zero Orchard action must still not match");
    }

    // ── DecryptedOutput.pool / DecryptedTx.ironwood_outputs — structural ─────

    /// `DecryptedOutput.pool` carries the Ironwood tag distinctly from Orchard —
    /// this is the field the sync layer relies on to distinguish the two pools
    /// at the NAPI boundary.
    #[test]
    fn decrypted_output_pool_tags_ironwood_distinctly_from_orchard() {
        let orchard = DecryptedOutput {
            amount: 1,
            memo: String::new(),
            transfer_type: "incoming".to_string(),
            pool: ShieldedPool::Orchard,
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            recipient: None,
            action_index: None,
        };
        let ironwood = DecryptedOutput {
            pool: ShieldedPool::Ironwood,
            ..orchard.clone()
        };
        assert_eq!(orchard.pool, ShieldedPool::Orchard);
        assert_eq!(ironwood.pool, ShieldedPool::Ironwood);
        assert_ne!(orchard.pool, ironwood.pool);
    }

    /// `DecryptedTx.ironwood_outputs` is additive and independent from
    /// `orchard_outputs` — constructing one does not implicitly populate or
    /// alter the other (regression guard for the DecryptedTx field addition).
    #[test]
    fn decrypted_tx_ironwood_outputs_independent_of_orchard_outputs() {
        let ironwood_note = DecryptedOutput {
            amount: 42,
            memo: String::new(),
            transfer_type: "incoming".to_string(),
            pool: ShieldedPool::Ironwood,
            nullifier: Some([0u8; 32]),
            rho: Some([0u8; 32]),
            rseed: Some([0u8; 32]),
            cmx: Some([0u8; 32]),
            recipient: Some([0u8; 43]),
            action_index: Some(0),
        };
        let tx = DecryptedTx {
            sapling_outputs: vec![],
            orchard_outputs: vec![],
            ironwood_outputs: vec![ironwood_note],
            fee_zatoshis: 0,
        };
        assert!(tx.orchard_outputs.is_empty());
        assert_eq!(tx.ironwood_outputs.len(), 1);
        assert_eq!(tx.ironwood_outputs[0].pool, ShieldedPool::Ironwood);
    }
}
