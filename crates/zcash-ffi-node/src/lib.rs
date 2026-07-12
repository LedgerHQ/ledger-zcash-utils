use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use zcash_sync::sync::{
    run_sync, ShieldedTransaction as GrpcTx, SyncParams as GrpcSyncParams,
    SyncResult as GrpcSyncResult,
};

// ─── NAPI types ───────────────────────────────────────────────────────────────

/// Parameters for scanning a block range for shielded transactions.
///
/// The UFVK must be obtained from the Ledger device — never derive it from
/// a seed phrase directly in this layer.
#[napi(object)]
pub struct SyncParams {
    /// gRPC endpoint URL (e.g. `"https://zaino-zec-testnet.nodes.stg.ledger-test.com/"`).
    pub grpc_url: String,
    /// Unified Full Viewing Key (UFVK) for the account to scan.
    pub viewing_key: String,
    /// First block height to scan (inclusive).
    pub start_height: u32,
    /// Last block height to scan (inclusive).
    pub end_height: u32,
    /// `"mainnet"` or `"testnet"` (default: `"testnet"`).
    pub network: Option<String>,
    /// When `true`, Sapling outputs are stripped before trial decryption.
    /// Only Orchard actions are processed — eliminates all Sapling crypto work.
    /// Set to `true` for Ledger wallets (Orchard-only support).
    pub orchard_only: Option<bool>,
    /// Maximum retry attempts per range on transient errors (timeout, 503).
    /// The failing range is split in half on each retry. Defaults to 3.
    pub max_retries: Option<u32>,
    /// Emit per-phase timing diagnostics to stderr every 10 seconds.
    pub verbose: Option<bool>,
    /// Hex-encoded nullifiers of notes received in previous scans that are still
    /// unspent. Enables spent detection across incremental sync boundaries.
    pub known_nullifiers: Option<Vec<String>>,
}

/// A single shielded note found during decryption.
///
/// Shared between Orchard and Sapling. The spending fields (`nullifier`,
/// `rseed`, `cmx`, `position`, `recipient`) are Orchard-specific and `None`
/// for Sapling notes. A dedicated Sapling type is deferred until Sapling
/// spending is needed.
#[napi(object)]
pub struct ShieldedNote {
    /// Amount in zatoshis (f64 for JS Number compatibility).
    pub amount: f64,
    /// `"incoming"`, `"outgoing"`, or `"internal"`.
    pub transfer_type: String,
    /// Memo text decoded from the note.
    pub memo: String,
    /// `"sapling"`, `"orchard"`, or `"ironwood"` — the shielded pool this note
    /// belongs to. Additive field: existing consumers that ignore it are
    /// unaffected; new consumers use it to distinguish Orchard from Ironwood
    /// notes now that both appear in this shared `ShieldedNote` shape.
    pub pool: String,

    /// Orchard/Ironwood nullifier (64-char hex = 32 bytes). Used for spent detection and PCZT.
    pub nullifier: Option<String>,
    /// rho value (64-char hex = 32 bytes). Required with rseed for Note::from_parts.
    pub rho: Option<String>,
    /// Random seed (64-char hex = 32 bytes). Required for spending.
    pub rseed: Option<String>,
    /// Extracted note commitment cmx (64-char hex = 32 bytes). Required for Merkle witness.
    pub cmx: Option<String>,
    /// Leaf position in the Orchard commitment tree (decimal string).
    /// None when ChainMetadata is absent.
    /// String avoids f64 precision loss on u64 -> f64 -> u64 round-trips.
    pub position: Option<String>,
    /// Recipient bytes (86-char hex = 43 bytes: 11-byte d + 32-byte pk_d). For note reconstruction.
    pub recipient: Option<String>,
    /// True if this note was spent in a later block within the scanned range.
    pub is_spent: bool,
}

/// A matched and fully-decrypted shielded transaction.
#[napi(object)]
pub struct ShieldedTransaction {
    /// Transaction ID in big-endian (display) hex order.
    pub txid: String,
    /// Raw transaction bytes as a hex string.
    pub hex: String,
    /// Block height at which this transaction was confirmed.
    pub block_height: u32,
    /// Block hash in big-endian (display) hex order.
    pub block_hash: String,
    /// Block timestamp (Unix seconds).
    pub block_time: u32,
    /// Transaction fee in zatoshis (shielded bundles only).
    pub fee: f64,
    /// Decrypted Sapling notes belonging to this account.
    pub sapling_notes: Vec<ShieldedNote>,
    /// Decrypted Orchard notes belonging to this account.
    pub orchard_notes: Vec<ShieldedNote>,
    /// Decrypted Ironwood (NU6.3) notes belonging to this account. Additive
    /// field, parallel to `orchard_notes` — existing consumers that only read
    /// `orchardNotes`/`saplingNotes` are unaffected.
    pub ironwood_notes: Vec<ShieldedNote>,
}

/// Scan statistics returned once the stream is exhausted.
#[napi(object)]
#[derive(Debug)]
pub struct SyncStats {
    pub blocks_scanned: u32,
    pub elapsed_ms: f64,
    /// Hex-encoded nullifiers from `knownNullifiers` that were spent in the scanned range.
    /// JS uses this to mark previously-stored notes as spent.
    pub spent_known_nullifiers: Vec<String>,
}

// ─── stream ───────────────────────────────────────────────────────────────────

/// Async iterator over matched shielded transactions.
///
/// Usage (TypeScript):
/// ```ts
/// const stream = await startSync(params);
/// let tx: ShieldedTransaction | null;
/// while ((tx = await stream.next()) !== null) {
///   console.log(tx);
/// }
/// const stats = await stream.stats();
/// ```
#[napi]
pub struct TransactionStream {
    rx: mpsc::UnboundedReceiver<GrpcTx>,
    result_rx: Option<oneshot::Receiver<Result<GrpcSyncResult, String>>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

#[napi]
impl TransactionStream {
    /// Returns the next matched transaction, or `null` when the scan is complete.
    ///
    /// # Safety
    ///
    /// napi-rs requires `unsafe` for `&mut self` in async methods.
    /// This method is safe to call — it only mutates the internal channel receiver.
    #[napi]
    pub async unsafe fn next(&mut self) -> napi::Result<Option<ShieldedTransaction>> {
        Ok(self.rx.recv().await.map(grpc_tx_to_napi))
    }

    /// Cancels the background scan immediately.
    ///
    /// Aborts the tokio task running the sync engine. Any buffered transactions
    /// already sent by Rust are still consumable via `next()`, which will then
    /// return `null` once the buffer is drained. `stats()` will return an error
    /// after cancellation.
    #[napi]
    pub fn cancel(&mut self) {
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
        // Close the receiver so next() returns null once buffered items are drained.
        self.rx.close();
    }

    /// Returns scan statistics once the stream is exhausted (i.e. after `next()`
    /// returns `null`). Calling this before the stream is done will wait until
    /// the background sync task finishes.
    ///
    /// # Safety
    ///
    /// napi-rs requires `unsafe` for `&mut self` in async methods.
    #[napi]
    pub async unsafe fn stats(&mut self) -> napi::Result<SyncStats> {
        let rx = self
            .result_rx
            .take()
            .ok_or_else(|| napi::Error::from_reason("stats() called more than once"))?;

        let grpc_result = rx
            .await
            .map_err(|_| napi::Error::from_reason("sync task was dropped before completing"))?
            .map_err(napi::Error::from_reason)?;

        Ok(SyncStats {
            blocks_scanned: grpc_result.blocks_scanned,
            elapsed_ms: grpc_result.elapsed_ms as f64,
            spent_known_nullifiers: grpc_result.spent_known_nullifiers,
        })
    }
}

// ─── NAPI functions ───────────────────────────────────────────────────────────

/// Start scanning a range of compact blocks and return a transaction stream.
///
/// The scan runs in the background immediately. Call `stream.next()` to
/// consume transactions as they are found. Call `stream.stats()` after the
/// stream is exhausted to retrieve scan statistics.
///
/// Trial decryption runs entirely in Rust (no JS event loop blocking).
/// `GetTransaction` is called only for matched transactions.
#[napi]
pub async fn start_sync(params: SyncParams) -> napi::Result<TransactionStream> {
    let (tx_sender, tx_receiver) = mpsc::unbounded_channel::<GrpcTx>();
    let (result_sender, result_receiver) = oneshot::channel::<Result<GrpcSyncResult, String>>();

    let on_transaction = Arc::new(move |tx: GrpcTx| {
        // Ignore send errors: if the receiver was dropped the consumer
        // is no longer interested in results.
        let _ = tx_sender.send(tx);
    }) as Arc<dyn Fn(GrpcTx) + Send + Sync>;

    let grpc_params = GrpcSyncParams {
        grpc_url: params.grpc_url,
        viewing_key: params.viewing_key,
        start_height: params.start_height,
        end_height: params.end_height,
        network: params.network,
        verbose: params.verbose.unwrap_or(false),
        orchard_only: params.orchard_only.unwrap_or(false),
        max_retries: params.max_retries,
        on_block_done: None,
        on_transaction: Some(on_transaction),
        known_nullifiers: params.known_nullifiers.unwrap_or_default(),
    };

    let task_handle = tokio::spawn(async move {
        let result = run_sync(grpc_params).await.map_err(|e| e.to_string());
        // Ignore send errors: if the receiver was dropped stats are not needed.
        let _ = result_sender.send(result);
    });

    Ok(TransactionStream {
        rx: tx_receiver,
        result_rx: Some(result_receiver),
        task_handle: Some(task_handle),
    })
}

/// Returns the current chain tip height from the gRPC endpoint.
#[napi]
pub async fn get_chain_tip(grpc_url: String) -> napi::Result<u32> {
    zcash_sync::client::chain_tip(grpc_url)
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Find the block height closest to the given Unix timestamp via interpolation search.
///
/// Returns the height of the latest block whose timestamp is ≤ the target.
/// If the timestamp is before genesis, returns the genesis height.
/// If the timestamp is after the chain tip, returns the tip height.
#[napi]
pub async fn find_block_height(grpc_url: String, timestamp: u32) -> napi::Result<u32> {
    zcash_sync::client::find_block_height(grpc_url, timestamp)
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ─── V5 transaction builder (Orchard + transparent send) ─────────────────────

#[napi(object)]
pub struct OrchardSpendInputJs {
    /// 86-char hex (43 bytes: 11-byte diversifier + 32-byte pk_d).
    pub recipient: String,
    /// Decimal u64 (string to avoid f64 precision loss).
    pub value_zat: String,
    /// 64-char hex (32 bytes).
    pub rho: String,
    /// 64-char hex.
    pub rseed: String,
    /// 64-char hex.
    pub cmx: String,
    /// Decimal u64 leaf position in the Orchard commitment tree.
    pub position: String,
}

#[napi(object)]
pub struct OutputRequestJs {
    /// Destination address: t-addr (P2PKH/P2SH) or u-addr (Orchard receiver).
    /// Sapling z-addresses and TEX (ZIP-320) addresses are rejected.
    pub address: String,
    pub value_zat: String,
    pub memo: Option<String>,
}

/// One transparent (P2PKH) UTXO to spend.
#[napi(object)]
pub struct TransparentInputJs {
    /// 64-char hex (32 bytes) prevout txid in internal (little-endian) byte order.
    /// Ledger Live surfaces txids in display (big-endian) order; callers must
    /// reverse before passing.
    pub txid: String,
    /// Output index within the origin transaction.
    pub vout: u32,
    /// Hex-encoded raw scriptPubKey bytes (no CompactSize length prefix).
    /// Exposed to JS as `scriptPubKey` (canonical Bitcoin/Zcash casing) rather
    /// than napi's default `scriptPubkey` camelCasing of the Rust field name.
    #[napi(js_name = "scriptPubKey")]
    pub script_pubkey: String,
    /// UTXO value in zatoshis (decimal string to avoid f64 precision loss).
    pub value_zat: String,
    /// 66-char hex (33 bytes) compressed secp256k1 pubkey controlling the UTXO.
    pub pubkey: String,
    /// BIP-44 chain (scope) the controlling key lives on: `0` = external,
    /// `1` = internal (change). With `address_index` this identifies the UTXO's
    /// signing key under the account. It is verified against the UFVK (the
    /// derived pubkey must equal `pubkey`) and stamped into the PCZT as the
    /// input's `bip32_derivation`, which the Ledger device uses as the signing
    /// path (the PCZT sign APDU carries no path).
    pub derivation_scope: u32,
    /// Non-hardened BIP-44 address index of the controlling key (see
    /// `derivation_scope`).
    pub address_index: u32,
}

#[napi(object)]
pub struct BuildTransactionParams {
    pub grpc_url: String,
    pub ufvk: String,
    pub network: Option<String>,
    /// 64-char hex (32 bytes): ZIP-32 seed fingerprint of the wallet seed,
    /// read from the device. Stamped onto each real spend so the device can
    /// confirm the PCZT belongs to its seed before signing.
    pub seed_fingerprint: String,
    /// ZIP-32 account index the UFVK was derived at.
    pub account_index: u32,
    /// Caller-owned fee in zatoshis (decimal string to avoid f64 precision
    /// loss). Per FR-4 the fee is selected by ledger-live; this
    /// crate validates it against ZIP-317 and derives change from it rather
    /// than computing a fee itself.
    pub fee_zat: String,
    pub spends: Vec<OrchardSpendInputJs>,
    /// Transparent (P2PKH) UTXOs to spend. Empty for Private→* flows.
    pub transparent_inputs: Vec<TransparentInputJs>,
    pub outputs: Vec<OutputRequestJs>,
    pub anchor_height: Option<u32>,
}

#[napi(object)]
pub struct BuildTransactionResult {
    /// Hex-encoded canonical PCZT bytes (`PCZT` magic + u32 LE version +
    /// postcard payload). Ready for the device APDU streaming layer. Carries
    /// each real spend's ZIP-32 derivation path for on-device signing.
    pub pczt_hex: String,
    /// Decimal fee in zatoshis.
    pub fee_zat: String,
    /// Block height the Merkle paths were computed against.
    pub anchor_height: u32,
    /// Orchard action count after dummy padding.
    pub n_actions_orchard: u32,
    /// Transparent input count.
    pub n_transparent_inputs: u32,
    /// Transparent output count (including change).
    pub n_transparent_outputs: u32,
}

/// Build, prove, and serialize a PCZT for a send transaction.
///
/// Supports Orchard-source (Private→*) and transparent-source (Public→*)
/// flows. Halo 2 proof generation happens here for Orchard-bundle transactions
/// (~2-5 s first call, ~hundreds of ms thereafter thanks to the process-global
/// ProvingKey cache). Transparent-only transactions skip the Orchard prover.
///
/// Note: unlike `finalize_transaction` (purely CPU-bound, offloaded via
/// `spawn_blocking`), this is an async orchestrator that interleaves gRPC
/// witness fetches with the CPU-bound proving step, so it cannot be wrapped in a
/// single `spawn_blocking` call — the proving cost is borne inline.
#[napi]
pub async fn build_transaction(
    params: BuildTransactionParams,
) -> napi::Result<BuildTransactionResult> {
    let spends = params
        .spends
        .into_iter()
        .map(|s| {
            Ok(zcash_sync::craft::SpendInputDto {
                recipient_hex: s.recipient,
                value_zat: parse_u64(&s.value_zat, "value_zat")?,
                rho_hex: s.rho,
                rseed_hex: s.rseed,
                cmx_hex: s.cmx,
                position: parse_u64(&s.position, "position")?,
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let transparent_inputs = params
        .transparent_inputs
        .into_iter()
        .map(|t| {
            Ok(zcash_sync::craft::TransparentInputDto {
                txid_hex: t.txid,
                vout: t.vout,
                script_pubkey_hex: t.script_pubkey,
                value_zat: parse_u64(&t.value_zat, "value_zat")?,
                pubkey_hex: t.pubkey,
                derivation_scope: t.derivation_scope,
                address_index: t.address_index,
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let outputs = params
        .outputs
        .into_iter()
        .map(|o| {
            Ok(zcash_sync::craft::OutputRequestDto {
                address: o.address,
                value_zat: parse_u64(&o.value_zat, "value_zat")?,
                memo: o.memo,
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let req = zcash_sync::craft::CraftRequest {
        grpc_url: params.grpc_url,
        ufvk: params.ufvk,
        network: params.network,
        seed_fingerprint_hex: params.seed_fingerprint,
        account_index: params.account_index,
        fee_zat: parse_u64(&params.fee_zat, "fee_zat")?,
        anchor_height: params.anchor_height,
        spends,
        transparent_inputs,
        outputs,
    };

    let out = zcash_sync::craft::craft_transaction(req)
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(BuildTransactionResult {
        pczt_hex: hex::encode(&out.pczt_bytes),
        fee_zat: out.fee.to_string(),
        anchor_height: out.anchor_height,
        n_actions_orchard: out.n_actions_orchard,
        n_transparent_inputs: out.n_transparent_inputs,
        n_transparent_outputs: out.n_transparent_outputs,
    })
}

fn parse_u64(s: &str, field: &str) -> napi::Result<u64> {
    s.parse::<u64>()
        .map_err(|e| napi::Error::from_reason(format!("invalid {field}: {e}")))
}

// ─── Finalize + broadcast ─────────────────────────────────────────────────────

/// Parameters for finalizing a PCZT with device-provided signatures.
#[napi(object)]
pub struct FinalizeTransactionParams {
    /// Hex-encoded canonical PCZT bytes from `buildTransaction`.
    pub pczt: String,
    /// One 64-byte (128-hex-char) RedPallas `spendAuthSig` per real Orchard spend,
    /// in PCZT-action order over the unsigned actions.
    pub orchard_signatures: Vec<String>,
    /// One DER-hex secp256k1 signature per transparent input (empty for pure Orchard).
    pub transparent_signatures: Vec<String>,
}

/// Result of a successful `finalizeTransaction` call.
#[napi(object)]
#[derive(Debug)]
pub struct FinalizeTransactionResult {
    /// Hex-encoded signed V5 transaction bytes (ready for `broadcastTransaction`).
    pub tx_hex: String,
    /// 64-char hex transaction id, big-endian *display* order (matches the sync
    /// path's `ShieldedTransaction.txid` and the Ledger Live operation hash).
    pub txid: String,
}

/// Inject device signatures into a PCZT and extract the final signed V5 transaction.
///
/// Accepts the PCZT from `buildTransaction`, one 64-byte RedPallas signature per
/// real (unsigned) Orchard action, and one DER secp256k1 signature per transparent
/// input. The Orchard binding signature is computed host-side.
///
/// CPU-bound (Halo 2 proof verification runs here): the pure call is dispatched
/// to `tokio::task::spawn_blocking` so the async executor is not starved.
#[napi]
pub async fn finalize_transaction(
    params: FinalizeTransactionParams,
) -> napi::Result<FinalizeTransactionResult> {
    // Decode the PCZT hex.
    let pczt_bytes = hex::decode(&params.pczt)
        .map_err(|e| napi::Error::from_reason(format!("pczt hex decode: {e}")))?;

    // Decode each Orchard signature (128 hex chars → 64 bytes).
    let orchard_signatures: Vec<[u8; 64]> = params
        .orchard_signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let v = hex::decode(s).map_err(|e| {
                napi::Error::from_reason(format!("orchard_signatures[{i}] hex decode: {e}"))
            })?;
            v.try_into().map_err(|got: Vec<u8>| {
                napi::Error::from_reason(format!(
                    "orchard_signatures[{i}] must be 64 bytes (got {} bytes)",
                    got.len()
                ))
            })
        })
        .collect::<napi::Result<_>>()?;

    // Decode each transparent signature (DER hex → bytes).
    let transparent_signatures: Vec<Vec<u8>> = params
        .transparent_signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            hex::decode(s).map_err(|e| {
                napi::Error::from_reason(format!("transparent_signatures[{i}] hex decode: {e}"))
            })
        })
        .collect::<napi::Result<_>>()?;

    // Run the CPU-bound finalization in a blocking thread so the tokio executor
    // is not starved during proof verification (VerifyingKey build ~2-5 s first
    // call; cached thereafter via the OnceLock in finalize.rs).
    let result = tokio::task::spawn_blocking(move || {
        zcash_crypto::finalize::finalize_transaction(zcash_crypto::finalize::FinalizeInputs {
            pczt_bytes,
            orchard_signatures,
            transparent_signatures,
        })
    })
    .await
    .map_err(|e| {
        let kind = if e.is_cancelled() {
            "was cancelled"
        } else {
            "panicked"
        };
        napi::Error::from_reason(format!("finalization task {kind}: {e}"))
    })?
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    // `result.txid` is internal little-endian; surface it in big-endian display
    // order to match the sync path (`ShieldedTransaction.txid`) and the txid
    // Ledger Live records as the operation hash.
    let mut txid_be = result.txid;
    txid_be.reverse();

    Ok(FinalizeTransactionResult {
        tx_hex: hex::encode(&result.tx_bytes),
        txid: hex::encode(txid_be),
    })
}

/// Submit a signed transaction to a lightwalletd / Zaino endpoint.
///
/// Returns the txid (64-char hex, big-endian display order — matches the sync
/// path and the Ledger Live operation hash) on success (`errorCode == 0`).
/// Returns a descriptive error on a non-zero `errorCode` (carrying the server's
/// `errorMessage`) or on a gRPC transport failure.
#[napi]
pub async fn broadcast_transaction(grpc_url: String, tx_hex: String) -> napi::Result<String> {
    let tx_bytes = hex::decode(&tx_hex)
        .map_err(|e| napi::Error::from_reason(format!("tx_hex decode: {e}")))?;
    zcash_sync::client::broadcast_transaction(grpc_url, tx_bytes)
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ─── Parse PCZT (canonical bytes → structured device-signer input) ────────────

/// PCZT header (`common::Global`) fields.
#[napi(object)]
pub struct PcztGlobal {
    /// Transaction version (V5 = 5).
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    /// `null` encodes the absent optional lock time.
    pub fallback_lock_time: Option<u32>,
    pub expiry_height: u32,
    /// SLIP-44 coin type (133 mainnet, 1 testnet).
    pub coin_type: u32,
    pub tx_modifiable: u32,
}

/// A `bip32_derivation` entry for a transparent input/output.
#[napi(object)]
pub struct PcztBip32Derivation {
    /// Derivation path (no `m/` prefix, hardened indices suffixed with `'`).
    pub signing_path: String,
    /// Compressed secp256k1 public key, 33 bytes.
    pub pubkey: Uint8Array,
    /// ZIP-32 seed fingerprint, 32 bytes.
    pub seed_fingerprint: Uint8Array,
}

/// A single transparent input.
#[napi(object)]
pub struct PcztTransparentInput {
    /// Previous output txid, 32 bytes (internal byte order, as stored in the PCZT).
    pub prevout_txid: Uint8Array,
    pub prevout_index: u32,
    /// `null` encodes the absent optional sequence number (final `0xffffffff`).
    pub sequence: Option<u32>,
    /// Input value in zatoshis (decimal string to avoid f64 precision loss).
    pub value: String,
    #[napi(js_name = "scriptPubKey")]
    pub script_pubkey: Uint8Array,
    /// Sighash type (`SIGHASH_ALL` = `0x01`).
    pub sighash_type: u32,
    pub derivation: PcztBip32Derivation,
}

/// A single transparent output.
#[napi(object)]
pub struct PcztTransparentOutput {
    /// Output value in zatoshis (decimal string to avoid f64 precision loss).
    pub value: String,
    #[napi(js_name = "scriptPubKey")]
    pub script_pubkey: Uint8Array,
    /// Present (change output) or `null` (external recipient).
    pub derivation: Option<PcztBip32Derivation>,
}

/// A single Orchard action (spend + output halves), flattened for the device.
#[napi(object)]
pub struct PcztOrchardAction {
    /// Value commitment, 32 bytes.
    pub cv_net: Uint8Array,
    /// Spend nullifier, 32 bytes.
    pub nullifier: Uint8Array,
    /// Randomized verification key, 32 bytes.
    pub rk: Uint8Array,
    /// Raw Orchard address of the spent note, 43 bytes.
    pub spend_recipient: Uint8Array,
    /// Spent-note value in zatoshis (decimal string to avoid f64 precision loss).
    pub spend_value: String,
    /// Spend rho, 32 bytes.
    pub spend_rho: Uint8Array,
    /// Spend rseed, 32 bytes.
    pub spend_rseed: Uint8Array,
    /// Spend-authorization randomizer, 32 bytes.
    pub alpha: Uint8Array,
    /// ZIP-32 derivation path of the signing key.
    pub signing_path: String,
    /// ZIP-32 seed fingerprint, 32 bytes.
    pub seed_fingerprint: Uint8Array,
    /// Note commitment x-coordinate, 32 bytes.
    pub cmx: Uint8Array,
    /// Ephemeral key, 32 bytes.
    pub ephemeral_key: Uint8Array,
    pub enc_ciphertext: Uint8Array,
    pub out_ciphertext: Uint8Array,
    /// Raw Orchard address of the output note, 43 bytes.
    pub recipient: Uint8Array,
    /// Output-note value in zatoshis (decimal string to avoid f64 precision loss).
    pub value: String,
    /// Output rseed, 32 bytes.
    pub rseed: Uint8Array,
    /// Value commitment randomness, 32 bytes.
    pub rcv: Uint8Array,
}

/// The Orchard action bundle plus its trailer.
#[napi(object)]
pub struct PcztOrchardBundle {
    pub actions: Vec<PcztOrchardAction>,
    pub flags: u32,
    /// Net value balance in zatoshis (signed decimal string, lossless for i128).
    pub value_balance: String,
    /// Orchard commitment-tree anchor, 32 bytes.
    pub anchor: Uint8Array,
}

/// A fully structured PCZT ready for `DmkSignerZcash.signPcztTransaction`.
#[napi(object)]
pub struct PcztTransaction {
    pub global: PcztGlobal,
    pub transparent_inputs: Vec<PcztTransparentInput>,
    pub transparent_outputs: Vec<PcztTransparentOutput>,
    /// `null` when the transaction has no Orchard actions.
    pub orchard_bundle: Option<PcztOrchardBundle>,
}

/// Parse canonical PCZT bytes (hex, as returned by `buildTransaction`) into the
/// structured `PcztTransaction` object the Ledger device signer consumes.
///
/// The PCZT binary format (postcard) is not trivially parseable in TypeScript;
/// this decodes it in Rust and breaks out the transparent inputs/outputs and
/// each Orchard action field-by-field. Fails if the input is not a valid PCZT,
/// or if a field the device requires to sign is missing from it.
#[napi]
pub fn parse_pczt(pczt_hex: String) -> napi::Result<PcztTransaction> {
    let bytes = hex::decode(&pczt_hex)
        .map_err(|e| napi::Error::from_reason(format!("pczt hex decode: {e}")))?;
    let parsed = zcash_crypto::parse::parse_pczt(&bytes)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(parsed_pczt_to_napi(parsed))
}

fn bytes_to_napi(bytes: impl Into<Vec<u8>>) -> Uint8Array {
    Uint8Array::from(bytes.into())
}

fn derivation_to_napi(d: zcash_crypto::parse::ParsedBip32Derivation) -> PcztBip32Derivation {
    PcztBip32Derivation {
        signing_path: d.signing_path,
        pubkey: bytes_to_napi(d.pubkey.to_vec()),
        seed_fingerprint: bytes_to_napi(d.seed_fingerprint.to_vec()),
    }
}

fn orchard_action_to_napi(a: zcash_crypto::parse::ParsedOrchardAction) -> PcztOrchardAction {
    PcztOrchardAction {
        cv_net: bytes_to_napi(a.cv_net.to_vec()),
        nullifier: bytes_to_napi(a.nullifier.to_vec()),
        rk: bytes_to_napi(a.rk.to_vec()),
        spend_recipient: bytes_to_napi(a.spend_recipient.to_vec()),
        spend_value: a.spend_value.to_string(),
        spend_rho: bytes_to_napi(a.spend_rho.to_vec()),
        spend_rseed: bytes_to_napi(a.spend_rseed.to_vec()),
        alpha: bytes_to_napi(a.alpha.to_vec()),
        signing_path: a.signing_path,
        seed_fingerprint: bytes_to_napi(a.seed_fingerprint.to_vec()),
        cmx: bytes_to_napi(a.cmx.to_vec()),
        ephemeral_key: bytes_to_napi(a.ephemeral_key.to_vec()),
        enc_ciphertext: bytes_to_napi(a.enc_ciphertext),
        out_ciphertext: bytes_to_napi(a.out_ciphertext),
        recipient: bytes_to_napi(a.recipient.to_vec()),
        value: a.value.to_string(),
        rseed: bytes_to_napi(a.rseed.to_vec()),
        rcv: bytes_to_napi(a.rcv.to_vec()),
    }
}

fn parsed_pczt_to_napi(parsed: zcash_crypto::parse::ParsedPczt) -> PcztTransaction {
    let global = PcztGlobal {
        tx_version: parsed.global.tx_version,
        version_group_id: parsed.global.version_group_id,
        consensus_branch_id: parsed.global.consensus_branch_id,
        fallback_lock_time: parsed.global.fallback_lock_time,
        expiry_height: parsed.global.expiry_height,
        coin_type: parsed.global.coin_type,
        tx_modifiable: u32::from(parsed.global.tx_modifiable),
    };

    let transparent_inputs = parsed
        .transparent_inputs
        .into_iter()
        .map(|i| PcztTransparentInput {
            prevout_txid: bytes_to_napi(i.prevout_txid.to_vec()),
            prevout_index: i.prevout_index,
            sequence: i.sequence,
            value: i.value.to_string(),
            script_pubkey: bytes_to_napi(i.script_pubkey),
            sighash_type: u32::from(i.sighash_type),
            derivation: derivation_to_napi(i.derivation),
        })
        .collect();

    let transparent_outputs = parsed
        .transparent_outputs
        .into_iter()
        .map(|o| PcztTransparentOutput {
            value: o.value.to_string(),
            script_pubkey: bytes_to_napi(o.script_pubkey),
            derivation: o.derivation.map(derivation_to_napi),
        })
        .collect();

    let orchard_bundle = parsed.orchard_bundle.map(|b| PcztOrchardBundle {
        actions: b.actions.into_iter().map(orchard_action_to_napi).collect(),
        flags: u32::from(b.flags),
        value_balance: b.value_balance.to_string(),
        anchor: bytes_to_napi(b.anchor.to_vec()),
    });

    PcztTransaction {
        global,
        transparent_inputs,
        transparent_outputs,
        orchard_bundle,
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn grpc_tx_to_napi(tx: GrpcTx) -> ShieldedTransaction {
    ShieldedTransaction {
        txid: tx.txid,
        hex: tx.hex,
        block_height: tx.block_height,
        block_hash: tx.block_hash,
        block_time: tx.block_time,
        fee: tx.fee_zatoshis as f64,
        // Sapling notes: spending fields are always None (Orchard-only).
        // We hardcode None here rather than forwarding from the Rust struct
        // to make the Orchard-only intent explicit.
        sapling_notes: tx
            .sapling_notes
            .into_iter()
            .map(|n| ShieldedNote {
                amount: n.amount as f64,
                transfer_type: n.transfer_type,
                memo: n.memo,
                pool: n.pool,
                nullifier: None,
                rho: None,
                rseed: None,
                cmx: None,
                position: None,
                recipient: None,
                is_spent: false,
            })
            .collect(),
        orchard_notes: tx
            .orchard_notes
            .into_iter()
            .map(|n| ShieldedNote {
                amount: n.amount as f64,
                transfer_type: n.transfer_type,
                memo: n.memo,
                pool: n.pool,
                nullifier: n.nullifier,
                rho: n.rho,
                rseed: n.rseed,
                cmx: n.cmx,
                position: n.position.map(|p| p.to_string()),
                recipient: n.recipient,
                is_spent: n.is_spent,
            })
            .collect(),
        // Additive: same mapping shape as orchard_notes, sourced from the
        // separate ironwood_notes list zcash-sync populates.
        ironwood_notes: tx
            .ironwood_notes
            .into_iter()
            .map(|n| ShieldedNote {
                amount: n.amount as f64,
                transfer_type: n.transfer_type,
                memo: n.memo,
                pool: n.pool,
                nullifier: n.nullifier,
                rho: n.rho,
                rseed: n.rseed,
                cmx: n.cmx,
                position: n.position.map(|p| p.to_string()),
                recipient: n.recipient,
                is_spent: n.is_spent,
            })
            .collect(),
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_crypto::parse::{
        ParsedBip32Derivation, ParsedGlobal, ParsedOrchardAction, ParsedOrchardBundle, ParsedPczt,
        ParsedTransparentInput, ParsedTransparentOutput,
    };
    use zcash_sync::sync::{ShieldedNote as GrpcNote, ShieldedTransaction as GrpcTx};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_grpc_tx() -> GrpcTx {
        GrpcTx {
            txid: "aabbccdd".to_string(),
            hex: "deadbeef".to_string(),
            block_height: 2_000_000,
            block_hash: "cafecafe".to_string(),
            block_time: 1_700_000_000,
            fee_zatoshis: 10_000,
            sapling_notes: vec![],
            orchard_notes: vec![],
            ironwood_notes: vec![],
        }
    }

    fn make_grpc_note(amount: u64, transfer_type: &str, memo: &str) -> GrpcNote {
        GrpcNote {
            amount,
            transfer_type: transfer_type.to_string(),
            memo: memo.to_string(),
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            position: None,
            recipient: None,
            is_spent: false,
            pool: "orchard".to_string(),
        }
    }

    fn make_sync_params(viewing_key: &str) -> SyncParams {
        SyncParams {
            grpc_url: "https://127.0.0.1:1".to_string(),
            viewing_key: viewing_key.to_string(),
            start_height: 1_000_000,
            end_height: 1_000_010,
            network: Some("mainnet".to_string()),
            orchard_only: Some(false),
            max_retries: None,
            verbose: None,
            known_nullifiers: None,
        }
    }

    // ── grpc_tx_to_napi — scalar field conversion ─────────────────────────────

    #[test]
    fn grpc_tx_to_napi_preserves_scalar_fields() {
        let napi = grpc_tx_to_napi(make_grpc_tx());
        assert_eq!(napi.txid, "aabbccdd");
        assert_eq!(napi.hex, "deadbeef");
        assert_eq!(napi.block_height, 2_000_000);
        assert_eq!(napi.block_hash, "cafecafe");
        assert_eq!(napi.block_time, 1_700_000_000);
    }

    #[test]
    fn grpc_tx_to_napi_converts_fee_i64_to_f64() {
        let napi = grpc_tx_to_napi(GrpcTx {
            fee_zatoshis: 1_234_567,
            ..make_grpc_tx()
        });
        assert_eq!(napi.fee, 1_234_567.0_f64);
    }

    #[test]
    fn grpc_tx_to_napi_zero_fee() {
        let napi = grpc_tx_to_napi(GrpcTx {
            fee_zatoshis: 0,
            ..make_grpc_tx()
        });
        assert_eq!(napi.fee, 0.0_f64);
    }

    // ── grpc_tx_to_napi — notes conversion ───────────────────────────────────

    #[test]
    fn grpc_tx_to_napi_empty_notes_produce_empty_vecs() {
        let napi = grpc_tx_to_napi(make_grpc_tx());
        assert!(napi.sapling_notes.is_empty());
        assert!(napi.orchard_notes.is_empty());
    }

    #[test]
    fn grpc_tx_to_napi_converts_orchard_note_fields() {
        let grpc = GrpcTx {
            orchard_notes: vec![make_grpc_note(100_000_000, "incoming", "hello")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.orchard_notes.len(), 1);
        assert_eq!(napi.orchard_notes[0].amount, 100_000_000.0_f64);
        assert_eq!(napi.orchard_notes[0].transfer_type, "incoming");
        assert_eq!(napi.orchard_notes[0].memo, "hello");
        assert_eq!(napi.orchard_notes[0].pool, "orchard");
    }

    // ── grpc_tx_to_napi — Ironwood (additive, backward-compatible) ──────────

    /// Additive: `ironwoodNotes` is mapped with the exact same shape as
    /// `orchardNotes`, and its `pool` discriminator reads `"ironwood"` —
    /// letting NAPI consumers distinguish the two pools.
    #[test]
    fn grpc_tx_to_napi_converts_ironwood_note_fields() {
        let mut note = make_grpc_note(250_000_000, "internal", "ironwood memo");
        note.pool = "ironwood".to_string();
        let grpc = GrpcTx {
            ironwood_notes: vec![note],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.ironwood_notes.len(), 1);
        assert_eq!(napi.ironwood_notes[0].amount, 250_000_000.0_f64);
        assert_eq!(napi.ironwood_notes[0].transfer_type, "internal");
        assert_eq!(napi.ironwood_notes[0].memo, "ironwood memo");
        assert_eq!(napi.ironwood_notes[0].pool, "ironwood");
    }

    /// Backward-compatibility regression: a transaction with only Orchard notes
    /// produces an empty `ironwoodNotes` array; `orchardNotes`/`saplingNotes`
    /// mapping is unaffected by the additive field — existing consumers that
    /// only read those two arrays see no behavioral change.
    #[test]
    fn grpc_tx_to_napi_orchard_only_tx_has_empty_ironwood_notes() {
        let grpc = GrpcTx {
            orchard_notes: vec![make_grpc_note(1_000, "incoming", "")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert!(napi.ironwood_notes.is_empty());
        assert_eq!(napi.orchard_notes.len(), 1);
    }

    /// `pool` on a Sapling note forwards whatever the sync layer tagged it with
    /// (always `"sapling"` in production — see `zcash-sync`'s `pool_tag`), and
    /// is distinct from an Orchard/Ironwood note's tag on the same transaction.
    #[test]
    fn grpc_tx_to_napi_sapling_note_pool_is_distinguishable() {
        let mut sapling_note = make_grpc_note(1, "incoming", "");
        sapling_note.pool = "sapling".to_string();
        let grpc = GrpcTx {
            sapling_notes: vec![sapling_note],
            orchard_notes: vec![make_grpc_note(2, "incoming", "")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.sapling_notes[0].pool, "sapling");
        assert_eq!(napi.orchard_notes[0].pool, "orchard");
        assert_ne!(napi.sapling_notes[0].pool, napi.orchard_notes[0].pool);
    }

    #[test]
    fn grpc_tx_to_napi_converts_sapling_note_fields() {
        let grpc = GrpcTx {
            sapling_notes: vec![make_grpc_note(50_000_000, "outgoing", "payment")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.sapling_notes.len(), 1);
        assert_eq!(napi.sapling_notes[0].amount, 50_000_000.0_f64);
        assert_eq!(napi.sapling_notes[0].transfer_type, "outgoing");
        assert_eq!(napi.sapling_notes[0].memo, "payment");
    }

    #[test]
    fn grpc_tx_to_napi_preserves_note_order_and_count() {
        let grpc = GrpcTx {
            sapling_notes: vec![
                make_grpc_note(10_000_000, "incoming", ""),
                make_grpc_note(20_000_000, "outgoing", ""),
                make_grpc_note(30_000_000, "internal", ""),
            ],
            orchard_notes: vec![make_grpc_note(5_000_000, "incoming", "orchard")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.sapling_notes.len(), 3);
        assert_eq!(napi.sapling_notes[0].amount, 10_000_000.0_f64);
        assert_eq!(napi.sapling_notes[1].amount, 20_000_000.0_f64);
        assert_eq!(napi.sapling_notes[2].amount, 30_000_000.0_f64);
        assert_eq!(napi.orchard_notes.len(), 1);
    }

    #[test]
    fn grpc_tx_to_napi_note_with_empty_memo() {
        let grpc = GrpcTx {
            orchard_notes: vec![make_grpc_note(1_000, "incoming", "")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.orchard_notes[0].memo, "");
    }

    #[test]
    fn grpc_tx_to_napi_total_supply_amount_representable_as_f64() {
        // ZEC total supply ≈ 21M ZEC = 2.1e15 zatoshis, well within f64 precision.
        let grpc = GrpcTx {
            orchard_notes: vec![make_grpc_note(2_100_000_000_000_000, "incoming", "")],
            ..make_grpc_tx()
        };
        let napi = grpc_tx_to_napi(grpc);
        assert_eq!(napi.orchard_notes[0].amount, 2_100_000_000_000_000.0_f64);
    }

    // ── finalize_transaction / broadcast_transaction — error paths ───────────

    /// Malformed PCZT hex must return a NAPI error, not a panic.
    #[tokio::test]
    async fn finalize_transaction_malformed_pczt_hex_returns_napi_error() {
        let params = FinalizeTransactionParams {
            pczt: "not valid hex @@@@".to_string(),
            orchard_signatures: vec![],
            transparent_signatures: vec![],
        };
        let err = finalize_transaction(params).await.unwrap_err();
        assert!(
            !err.reason.is_empty(),
            "expected non-empty NAPI error reason"
        );
    }

    /// Valid hex that is not a PCZT must also return a NAPI error (not panic).
    #[tokio::test]
    async fn finalize_transaction_non_pczt_hex_returns_napi_error() {
        let params = FinalizeTransactionParams {
            pczt: hex::encode(b"definitely not a pczt"),
            orchard_signatures: vec![],
            transparent_signatures: vec![],
        };
        let err = finalize_transaction(params).await.unwrap_err();
        assert!(
            !err.reason.is_empty(),
            "expected non-empty NAPI error reason"
        );
    }

    /// Malformed URL must return a NAPI error from broadcast_transaction.
    #[tokio::test]
    async fn broadcast_transaction_malformed_url_returns_napi_error() {
        let err = broadcast_transaction("invalid gRPC URL".to_string(), hex::encode(b"fake tx"))
            .await
            .unwrap_err();
        assert!(
            !err.reason.is_empty(),
            "expected non-empty NAPI error reason"
        );
    }

    /// Malformed tx_hex (non-hex chars) must return a decode error.
    #[tokio::test]
    async fn broadcast_transaction_malformed_tx_hex_returns_napi_error() {
        let err = broadcast_transaction(
            "https://zaino-zec-testnet.nodes.stg.ledger-test.com/".to_string(),
            "not valid hex @@".to_string(),
        )
        .await
        .unwrap_err();
        assert!(
            err.reason.contains("tx_hex decode"),
            "expected tx_hex decode error, got: {}",
            err.reason
        );
    }

    // ── get_chain_tip — error paths ───────────────────────────────────────────

    #[tokio::test]
    async fn get_chain_tip_fails_on_refused_port() {
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let err = get_chain_tip(format!("https://127.0.0.1:{}", addr.port()))
            .await
            .unwrap_err();
        assert!(!err.reason.is_empty());
    }

    #[tokio::test]
    async fn get_chain_tip_fails_on_malformed_url() {
        let err = get_chain_tip("not_a_url".to_string()).await.unwrap_err();
        assert!(!err.reason.is_empty());
    }

    // ── start_sync API contract ───────────────────────────────────────────────

    /// `start_sync` must always return `Ok(stream)` immediately — it launches
    /// a background task and never blocks on the network.
    #[tokio::test]
    async fn start_sync_always_returns_ok_regardless_of_params() {
        let result = start_sync(make_sync_params("totally_invalid_ufvk")).await;
        assert!(
            result.is_ok(),
            "start_sync must return Ok(stream) immediately"
        );
    }

    /// An invalid UFVK causes the background sync to fail. The failure is
    /// invisible until `stats()` is called, which is where the error surfaces.
    #[tokio::test]
    async fn start_sync_invalid_ufvk_surfaces_error_via_stats() {
        let mut stream = start_sync(make_sync_params("bad_ufvk")).await.unwrap();
        // next() returns None immediately — no transactions on a failed sync.
        let tx = unsafe { stream.next().await }.unwrap();
        assert!(tx.is_none(), "expected no transactions from failed sync");
        // The error is reported through stats().
        let err = unsafe { stream.stats().await }.unwrap_err();
        assert!(!err.reason.is_empty(), "error reason must not be empty");
    }

    /// An invalid network string causes the same early-fail path.
    #[tokio::test]
    async fn start_sync_invalid_network_surfaces_error_via_stats() {
        let params = SyncParams {
            network: Some("notanetwork".to_string()),
            ..make_sync_params("bad_ufvk")
        };
        let mut stream = start_sync(params).await.unwrap();
        let tx = unsafe { stream.next().await }.unwrap();
        assert!(tx.is_none());
        let err = unsafe { stream.stats().await }.unwrap_err();
        assert!(!err.reason.is_empty());
    }

    /// Calling `stats()` a second time must return a clear error, not hang or panic.
    #[tokio::test]
    async fn stats_called_twice_returns_error_on_second_call() {
        let mut stream = start_sync(make_sync_params("bad_ufvk")).await.unwrap();
        // Drain the stream.
        while unsafe { stream.next().await }.unwrap().is_some() {}
        // First stats() call — may succeed or fail depending on sync result.
        let _ = unsafe { stream.stats().await };
        // Second stats() call must always return an explicit error.
        let err = unsafe { stream.stats().await }.unwrap_err();
        assert!(
            err.reason.contains("more than once"),
            "expected 'called more than once' error, got: {}",
            err.reason
        );
    }

    // ── grpc_tx_to_napi — new spending fields ─────────────────────────────────

    /// A note with all 6 spending fields populated must have them preserved after
    /// conversion through `grpc_tx_to_napi`.
    #[test]
    fn test_grpc_tx_to_napi_note_with_spending_fields() {
        let nullifier_hex = hex::encode([0xAAu8; 32]);
        let rseed_hex = hex::encode([0xBBu8; 32]);
        let cmx_hex = hex::encode([0xCCu8; 32]);
        let recipient_hex = hex::encode([0xDDu8; 43]);
        let position_u64: u64 = 42;

        let grpc = GrpcTx {
            orchard_notes: vec![GrpcNote {
                amount: 100_000_000,
                transfer_type: "incoming".to_string(),
                memo: "test".to_string(),
                nullifier: Some(nullifier_hex.clone()),
                rho: Some("dd".repeat(32)),
                rseed: Some(rseed_hex.clone()),
                cmx: Some(cmx_hex.clone()),
                position: Some(position_u64),
                recipient: Some(recipient_hex.clone()),
                is_spent: true,
                pool: "orchard".to_string(),
            }],
            ..make_grpc_tx()
        };

        let napi = grpc_tx_to_napi(grpc);
        let note = &napi.orchard_notes[0];

        assert_eq!(
            note.nullifier.as_deref(),
            Some(nullifier_hex.as_str()),
            "nullifier must be preserved"
        );
        assert_eq!(
            note.rseed.as_deref(),
            Some(rseed_hex.as_str()),
            "rseed must be preserved"
        );
        assert_eq!(
            note.cmx.as_deref(),
            Some(cmx_hex.as_str()),
            "cmx must be preserved"
        );
        assert_eq!(
            note.position.as_deref(),
            Some(position_u64.to_string().as_str()),
            "position must be decimal string"
        );
        assert_eq!(
            note.recipient.as_deref(),
            Some(recipient_hex.as_str()),
            "recipient must be preserved"
        );
        assert!(note.is_spent, "is_spent must be true");
    }

    /// An outgoing note with all spending fields `None`/`false` must produce a
    /// NAPI note where all those fields are `None`/`false`.
    #[test]
    fn test_grpc_tx_to_napi_outgoing_note_has_null_fields() {
        let grpc = GrpcTx {
            orchard_notes: vec![GrpcNote {
                amount: 50_000,
                transfer_type: "outgoing".to_string(),
                memo: String::new(),
                nullifier: None,
                rho: None,
                rseed: None,
                cmx: None,
                position: None,
                recipient: None,
                is_spent: false,
                pool: "orchard".to_string(),
            }],
            ..make_grpc_tx()
        };

        let napi = grpc_tx_to_napi(grpc);
        let note = &napi.orchard_notes[0];

        assert!(note.nullifier.is_none(), "outgoing: nullifier must be None");
        assert!(note.rseed.is_none(), "outgoing: rseed must be None");
        assert!(note.cmx.is_none(), "outgoing: cmx must be None");
        assert!(note.position.is_none(), "outgoing: position must be None");
        assert!(note.recipient.is_none(), "outgoing: recipient must be None");
        assert!(!note.is_spent, "outgoing: is_spent must be false");
    }

    // ── TransparentInputJs → TransparentInputDto mapping ─────────────────────

    /// value_zat = "50000" must map to exactly 50_000 u64.
    #[test]
    fn transparent_input_js_value_zat_parses_correctly() {
        let result = parse_u64("50000", "value_zat");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 50_000u64);
    }

    /// A non-numeric value_zat must yield a NAPI error via parse_u64.
    #[test]
    fn transparent_input_js_non_numeric_value_zat_errors() {
        let err = parse_u64("not_a_number", "value_zat").unwrap_err();
        assert!(
            err.reason.contains("invalid value_zat"),
            "got: {}",
            err.reason
        );
    }

    /// zero value_zat parses to 0.
    #[test]
    fn transparent_input_js_zero_value_zat_parses_correctly() {
        let result = parse_u64("0", "value_zat");
        assert_eq!(result.unwrap(), 0u64);
    }

    /// `position = 2_100_000_000u64` must convert to exactly `2_100_000_000.0f64`
    /// without precision loss (well within the safe integer range of f64).
    #[test]
    fn test_grpc_tx_to_napi_position_as_decimal_string() {
        let position_u64: u64 = 2_100_000_000;
        let grpc = GrpcTx {
            orchard_notes: vec![GrpcNote {
                amount: 1,
                transfer_type: "incoming".to_string(),
                memo: String::new(),
                nullifier: None,
                rho: None,
                rseed: None,
                cmx: None,
                position: Some(position_u64),
                recipient: None,
                is_spent: false,
                pool: "orchard".to_string(),
            }],
            ..make_grpc_tx()
        };

        let napi = grpc_tx_to_napi(grpc);
        let pos_str = napi.orchard_notes[0].position.as_deref().unwrap();
        assert_eq!(pos_str, "2100000000", "position must be decimal string");
        // Round-trip: string → u64 must give back the original value.
        assert_eq!(
            pos_str.parse::<u64>().unwrap(),
            position_u64,
            "string → u64 round-trip must be lossless"
        );
    }

    // ── parsed_pczt_to_napi — PCZT structure mapping ─────────────────────────
    //
    // The `parse_pczt` round-trip tests in `zcash_crypto::parse` stop at the Rust
    // `Parsed*` structs; they never traverse this NAPI mapping layer. These tests
    // mirror the `grpc_tx_to_napi_*` convention and guard the field-by-field copy
    // in `parsed_pczt_to_napi` / `orchard_action_to_napi` / `derivation_to_napi`
    // against mis-copied fields, value truncation, and `Option -> null` regressions.

    fn make_derivation() -> ParsedBip32Derivation {
        ParsedBip32Derivation {
            signing_path: "44'/133'/0'/0/0".to_string(),
            pubkey: [0x02u8; 33],
            seed_fingerprint: [0x11u8; 32],
        }
    }

    fn make_parsed_global() -> ParsedGlobal {
        ParsedGlobal {
            tx_version: 5,
            version_group_id: 0x26A7_270A,
            consensus_branch_id: 0xC2D6_D0B4,
            fallback_lock_time: Some(12_345),
            expiry_height: 2_000_100,
            coin_type: 133,
            tx_modifiable: 0b0000_0011,
        }
    }

    /// A fully-populated Orchard action. Every `[u8; N]` field uses a distinct
    /// fill byte so a mis-copy between fields (e.g. `nullifier` written from
    /// `rk`) is caught by the field-by-field assertions.
    fn make_parsed_orchard_action() -> ParsedOrchardAction {
        ParsedOrchardAction {
            cv_net: [0x01u8; 32],
            nullifier: [0x02u8; 32],
            rk: [0x03u8; 32],
            spend_recipient: [0x04u8; 43],
            spend_value: 111_111,
            spend_rho: [0x05u8; 32],
            spend_rseed: [0x06u8; 32],
            alpha: [0x07u8; 32],
            signing_path: "44'/133'/0'/0/7".to_string(),
            seed_fingerprint: [0x08u8; 32],
            cmx: [0x09u8; 32],
            ephemeral_key: [0x0au8; 32],
            enc_ciphertext: vec![0x0bu8; 580],
            out_ciphertext: vec![0x0cu8; 80],
            recipient: [0x0du8; 43],
            value: 222_222,
            rseed: [0x0eu8; 32],
            rcv: [0x0fu8; 32],
        }
    }

    /// A PCZT exercising every branch of the mapping: global with a lock time,
    /// one transparent input (with derivation), one change output (derivation
    /// present), and an Orchard bundle with one fully-populated action.
    fn make_parsed_pczt() -> ParsedPczt {
        ParsedPczt {
            global: make_parsed_global(),
            transparent_inputs: vec![ParsedTransparentInput {
                prevout_txid: [0x21u8; 32],
                prevout_index: 3,
                sequence: Some(0xffff_fffe),
                value: 500_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
                sighash_type: 1,
                derivation: make_derivation(),
            }],
            transparent_outputs: vec![ParsedTransparentOutput {
                value: 400_000,
                script_pubkey: vec![0xa9, 0x14],
                derivation: Some(make_derivation()),
            }],
            orchard_bundle: Some(ParsedOrchardBundle {
                actions: vec![make_parsed_orchard_action()],
                flags: 0b0000_0011,
                value_balance: -100_000,
                anchor: [0x31u8; 32],
            }),
        }
    }

    #[test]
    fn parsed_pczt_to_napi_maps_global_fields() {
        let napi = parsed_pczt_to_napi(make_parsed_pczt());
        assert_eq!(napi.global.tx_version, 5);
        assert_eq!(napi.global.version_group_id, 0x26A7_270A);
        assert_eq!(napi.global.consensus_branch_id, 0xC2D6_D0B4);
        assert_eq!(napi.global.fallback_lock_time, Some(12_345));
        assert_eq!(napi.global.expiry_height, 2_000_100);
        assert_eq!(napi.global.coin_type, 133);
        assert_eq!(napi.global.tx_modifiable, 0b0000_0011);
    }

    #[test]
    fn parsed_pczt_to_napi_global_none_lock_time_maps_to_null() {
        let mut parsed = make_parsed_pczt();
        parsed.global.fallback_lock_time = None;
        let napi = parsed_pczt_to_napi(parsed);
        assert!(
            napi.global.fallback_lock_time.is_none(),
            "absent lock time must map to null"
        );
    }

    #[test]
    fn parsed_pczt_to_napi_maps_transparent_input() {
        let napi = parsed_pczt_to_napi(make_parsed_pczt());
        assert_eq!(napi.transparent_inputs.len(), 1);
        let input = &napi.transparent_inputs[0];
        assert_eq!(input.prevout_txid.to_vec(), vec![0x21u8; 32]);
        assert_eq!(input.prevout_index, 3);
        assert_eq!(input.sequence, Some(0xffff_fffe));
        assert_eq!(input.value, "500000");
        // `script_pubkey` is surfaced to JS as `scriptPubKey` via
        // `#[napi(js_name)]`; the Rust value must pass through unchanged (the
        // js_name casing itself is asserted by the generated `index.d.ts`).
        assert_eq!(input.script_pubkey.to_vec(), vec![0x76u8, 0xa9, 0x14]);
        assert_eq!(input.sighash_type, 1);
        assert_eq!(input.derivation.signing_path, "44'/133'/0'/0/0");
        assert_eq!(input.derivation.pubkey.to_vec(), vec![0x02u8; 33]);
        assert_eq!(input.derivation.seed_fingerprint.to_vec(), vec![0x11u8; 32]);
    }

    #[test]
    fn parsed_pczt_to_napi_maps_transparent_output_with_derivation() {
        let napi = parsed_pczt_to_napi(make_parsed_pczt());
        assert_eq!(napi.transparent_outputs.len(), 1);
        let output = &napi.transparent_outputs[0];
        assert_eq!(output.value, "400000");
        assert_eq!(output.script_pubkey.to_vec(), vec![0xa9u8, 0x14]);
        let deriv = output
            .derivation
            .as_ref()
            .expect("change output derivation must be present");
        assert_eq!(deriv.signing_path, "44'/133'/0'/0/0");
        assert_eq!(deriv.seed_fingerprint.to_vec(), vec![0x11u8; 32]);
    }

    #[test]
    fn parsed_pczt_to_napi_transparent_output_none_derivation_maps_to_null() {
        let mut parsed = make_parsed_pczt();
        parsed.transparent_outputs[0].derivation = None;
        let napi = parsed_pczt_to_napi(parsed);
        assert!(
            napi.transparent_outputs[0].derivation.is_none(),
            "external-recipient output must map derivation None -> null"
        );
    }

    /// Every one of the ~17 Orchard-action fields must land in its own NAPI
    /// field. Distinct per-field fill bytes make a mis-copy detectable.
    #[test]
    fn parsed_pczt_to_napi_maps_all_orchard_action_fields() {
        let napi = parsed_pczt_to_napi(make_parsed_pczt());
        let bundle = napi
            .orchard_bundle
            .as_ref()
            .expect("orchard bundle must be present");
        assert_eq!(bundle.actions.len(), 1);
        let a = &bundle.actions[0];
        assert_eq!(a.cv_net.to_vec(), vec![0x01u8; 32], "cv_net");
        assert_eq!(a.nullifier.to_vec(), vec![0x02u8; 32], "nullifier");
        assert_eq!(a.rk.to_vec(), vec![0x03u8; 32], "rk");
        assert_eq!(
            a.spend_recipient.to_vec(),
            vec![0x04u8; 43],
            "spend_recipient"
        );
        assert_eq!(a.spend_value, "111111", "spend_value");
        assert_eq!(a.spend_rho.to_vec(), vec![0x05u8; 32], "spend_rho");
        assert_eq!(a.spend_rseed.to_vec(), vec![0x06u8; 32], "spend_rseed");
        assert_eq!(a.alpha.to_vec(), vec![0x07u8; 32], "alpha");
        assert_eq!(a.signing_path, "44'/133'/0'/0/7", "signing_path");
        assert_eq!(
            a.seed_fingerprint.to_vec(),
            vec![0x08u8; 32],
            "seed_fingerprint"
        );
        assert_eq!(a.cmx.to_vec(), vec![0x09u8; 32], "cmx");
        assert_eq!(a.ephemeral_key.to_vec(), vec![0x0au8; 32], "ephemeral_key");
        assert_eq!(
            a.enc_ciphertext.to_vec(),
            vec![0x0bu8; 580],
            "enc_ciphertext"
        );
        assert_eq!(a.out_ciphertext.to_vec(), vec![0x0cu8; 80], "out_ciphertext");
        assert_eq!(a.recipient.to_vec(), vec![0x0du8; 43], "recipient");
        assert_eq!(a.value, "222222", "value");
        assert_eq!(a.rseed.to_vec(), vec![0x0eu8; 32], "rseed");
        assert_eq!(a.rcv.to_vec(), vec![0x0fu8; 32], "rcv");
    }

    #[test]
    fn parsed_pczt_to_napi_maps_orchard_bundle_trailer() {
        let napi = parsed_pczt_to_napi(make_parsed_pczt());
        let bundle = napi
            .orchard_bundle
            .as_ref()
            .expect("orchard bundle must be present");
        assert_eq!(bundle.flags, 0b0000_0011);
        assert_eq!(
            bundle.value_balance, "-100000",
            "negative value_balance sign must be preserved"
        );
        assert_eq!(bundle.anchor.to_vec(), vec![0x31u8; 32]);
    }

    #[test]
    fn parsed_pczt_to_napi_no_orchard_bundle_maps_to_null() {
        let mut parsed = make_parsed_pczt();
        parsed.orchard_bundle = None;
        let napi = parsed_pczt_to_napi(parsed);
        assert!(
            napi.orchard_bundle.is_none(),
            "a transaction with no Orchard actions must map to null"
        );
    }

    /// Zatoshi values above f64's safe-integer range must survive the mapping
    /// intact — this is the reason these fields are decimal `String`, not `f64`.
    /// A silent narrowing to `f64` would corrupt `9_007_199_254_740_993` (2^53 + 1).
    #[test]
    fn parsed_pczt_to_napi_preserves_value_above_f64_safe_integer() {
        let big_value: u64 = 9_007_199_254_740_993;
        let mut parsed = make_parsed_pczt();
        parsed.orchard_bundle.as_mut().unwrap().actions[0].value = big_value;
        parsed.transparent_inputs[0].value = big_value;

        let napi = parsed_pczt_to_napi(parsed);
        assert_eq!(
            napi.orchard_bundle.unwrap().actions[0].value,
            big_value.to_string(),
            "orchard output value must not be truncated"
        );
        assert_eq!(
            napi.transparent_inputs[0].value,
            big_value.to_string(),
            "transparent input value must not be truncated"
        );
    }

    #[test]
    fn parsed_pczt_to_napi_preserves_action_order_and_count() {
        let mut a0 = make_parsed_orchard_action();
        a0.value = 1;
        let mut a1 = make_parsed_orchard_action();
        a1.value = 2;
        let mut a2 = make_parsed_orchard_action();
        a2.value = 3;

        let mut parsed = make_parsed_pczt();
        parsed.orchard_bundle.as_mut().unwrap().actions = vec![a0, a1, a2];

        let napi = parsed_pczt_to_napi(parsed);
        let bundle = napi.orchard_bundle.unwrap();
        assert_eq!(bundle.actions.len(), 3);
        assert_eq!(bundle.actions[0].value, "1");
        assert_eq!(bundle.actions[1].value, "2");
        assert_eq!(bundle.actions[2].value, "3");
    }
}
