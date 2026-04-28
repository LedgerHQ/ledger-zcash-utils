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
}

/// A single shielded note found during decryption.
#[napi(object)]
pub struct ShieldedNote {
    /// Amount in zatoshis (f64 for JS Number compatibility).
    pub amount: f64,
    /// `"incoming"`, `"outgoing"`, or `"internal"`.
    pub transfer_type: String,
    /// Memo text decoded from the note.
    pub memo: String,
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
}

/// Scan statistics returned once the stream is exhausted.
#[napi(object)]
#[derive(Debug)]
pub struct SyncStats {
    pub blocks_scanned: u32,
    pub elapsed_ms: f64,
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
    /// Safety: napi-rs requires `unsafe` for `&mut self` in async methods.
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
    /// Safety: napi-rs requires `unsafe` for `&mut self` in async methods.
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

// ─── helpers ──────────────────────────────────────────────────────────────────

fn grpc_tx_to_napi(tx: GrpcTx) -> ShieldedTransaction {
    ShieldedTransaction {
        txid: tx.txid,
        hex: tx.hex,
        block_height: tx.block_height,
        block_hash: tx.block_hash,
        block_time: tx.block_time,
        fee: tx.fee_zatoshis as f64,
        sapling_notes: tx
            .sapling_notes
            .into_iter()
            .map(|n| ShieldedNote {
                amount: n.amount as f64,
                transfer_type: n.transfer_type,
                memo: n.memo,
            })
            .collect(),
        orchard_notes: tx
            .orchard_notes
            .into_iter()
            .map(|n| ShieldedNote {
                amount: n.amount as f64,
                transfer_type: n.transfer_type,
                memo: n.memo,
            })
            .collect(),
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }

    fn make_grpc_note(amount: u64, transfer_type: &str, memo: &str) -> GrpcNote {
        GrpcNote {
            amount,
            transfer_type: transfer_type.to_string(),
            memo: memo.to_string(),
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
        let napi = grpc_tx_to_napi(GrpcTx { fee_zatoshis: 1_234_567, ..make_grpc_tx() });
        assert_eq!(napi.fee, 1_234_567.0_f64);
    }

    #[test]
    fn grpc_tx_to_napi_zero_fee() {
        let napi = grpc_tx_to_napi(GrpcTx { fee_zatoshis: 0, ..make_grpc_tx() });
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
        assert!(result.is_ok(), "start_sync must return Ok(stream) immediately");
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
}
