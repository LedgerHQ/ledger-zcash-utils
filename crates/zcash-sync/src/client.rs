use anyhow::{anyhow, Result};
use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    GetSubtreeRootsArg, RawTransaction, SendResponse, ShieldedProtocol, SubtreeRoot, TreeState,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

/// Timeout for establishing the TCP+TLS connection.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout applied to unary RPC calls (GetLatestBlock, GetTransaction, …).
/// Not applied to streaming RPCs (GetBlockRange) — those run until completion.
pub(crate) const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

/// Establish a gRPC channel to a lightwalletd / Zaino endpoint.
///
/// TLS is applied automatically for `https://` URLs. Plaintext is used for
/// `http://` URLs, which is intended for local proxy/test servers only.
///
/// No channel-level timeout is set — callers apply per-request timeouts via
/// `tonic::Request::set_timeout` so that streaming RPCs are not interrupted.
///
/// # Errors
///
/// Returns an error if the URL is invalid, the TLS handshake fails, or the
/// connection cannot be established within [`CONNECT_TIMEOUT`].
pub async fn connect(grpc_url: &str) -> Result<Channel> {
    let endpoint = tonic::transport::Channel::from_shared(grpc_url.to_owned())
        .map_err(|e| anyhow!("invalid gRPC URL: {}", e))?
        .connect_timeout(CONNECT_TIMEOUT);

    let channel = if grpc_url.starts_with("https://") {
        endpoint
            .tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
            .map_err(|e| anyhow!("TLS config failed: {}", e))?
            .connect()
            .await
    } else {
        endpoint.connect().await
    }
    .map_err(|e| anyhow!("gRPC connect failed: {}", e))?;

    Ok(channel)
}

/// Query the current chain tip height using an existing client.
pub(crate) async fn chain_tip_with_client(
    client: &mut CompactTxStreamerClient<Channel>,
) -> Result<u32> {
    let mut req = tonic::Request::new(ChainSpec {});
    req.set_timeout(UNARY_TIMEOUT);
    let latest = client
        .get_latest_block(req)
        .await
        .map_err(|e| anyhow!("GetLatestBlock failed: {}", e))?
        .into_inner();
    Ok(latest.height as u32)
}

/// Query the current chain tip height from a lightwalletd endpoint.
///
/// # Errors
///
/// Returns an error if the connection fails or the RPC call is rejected.
pub async fn chain_tip(grpc_url: String) -> Result<u32> {
    let channel = connect(&grpc_url).await?;
    let mut client = CompactTxStreamerClient::new(channel);
    chain_tip_with_client(&mut client).await
}

/// Fetch the timestamp of a single block by height (unary `GetBlock` RPC).
async fn get_block_time(
    client: &mut CompactTxStreamerClient<Channel>,
    height: u32,
) -> Result<u32> {
    let mut req = tonic::Request::new(BlockId {
        height: height as u64,
        hash: vec![],
    });
    req.set_timeout(UNARY_TIMEOUT);
    let block = client
        .get_block(req)
        .await
        .map_err(|e| anyhow!("GetBlock({}) failed: {}", height, e))?
        .into_inner();
    Ok(block.time)
}

/// When the search range is narrower than this, fetch all remaining blocks
/// in a single `GetBlockRange` streaming RPC instead of continuing one-by-one.
const RANGE_FETCH_THRESHOLD: u32 = 500;

/// Find the height of the latest block whose timestamp is ≤ `timestamp`.
///
/// Uses **interpolation search** (O(log log n) RPCs, ~3-4 iterations) to
/// narrow the range, then a single `GetBlockRange` streaming RPC to find
/// the exact block. Typically completes in ~6 RPCs total instead of ~23
/// with a naive binary search.
///
/// Returns a height clamped to `[1, tip]`.
///
/// # Errors
///
/// Returns an error if the connection fails or any RPC call is rejected.
pub async fn find_block_height(grpc_url: String, timestamp: u32) -> Result<u32> {
    let channel = connect(&grpc_url).await?;
    let mut client = CompactTxStreamerClient::new(channel);

    let tip = chain_tip_with_client(&mut client).await?;
    if tip == 0 {
        return Ok(0);
    }

    const ORCHARD_ACTIVATION_MAINNET: u32 = 1_687_104;
    let mut low: u32 = ORCHARD_ACTIVATION_MAINNET;
    let mut high: u32 = tip;

    // Fetch boundary timestamps (2 RPCs).
    let mut low_t = get_block_time(&mut client, low).await?;
    if timestamp <= low_t {
        return Ok(low);
    }
    let mut high_t = get_block_time(&mut client, high).await?;
    if timestamp >= high_t {
        return Ok(high);
    }

    // Phase 1: interpolation search — narrow the range to ≤ RANGE_FETCH_THRESHOLD.
    // Block timestamps are nearly linear (~75s/block), so interpolation
    // converges in ~3-4 iterations for 3M+ blocks.
    while high - low > RANGE_FETCH_THRESHOLD {
        let range_h = (high - low) as u64;
        let range_t = (high_t - low_t).max(1) as u64;
        let offset_t = (timestamp - low_t) as u64;
        let est = low + ((offset_t * range_h / range_t) as u32).clamp(1, (high - low) - 1);

        let est_t = get_block_time(&mut client, est).await?;

        if est_t < timestamp {
            low = est;
            low_t = est_t;
        } else {
            high = est;
            high_t = est_t;
        }
    }

    // Phase 2: stream remaining blocks in one GetBlockRange RPC.
    find_in_range(&mut client, low, high, timestamp).await
}

/// Fetch all blocks in `[low, high]` via a single streaming RPC and return
/// the height of the latest block whose timestamp is ≤ `timestamp`.
/// Falls back to `low` if no block in the range meets the condition.
async fn find_in_range(
    client: &mut CompactTxStreamerClient<Channel>,
    low: u32,
    high: u32,
    timestamp: u32,
) -> Result<u32> {
    let range = BlockRange {
        start: Some(BlockId { height: low as u64, hash: vec![] }),
        end: Some(BlockId { height: high as u64, hash: vec![] }),
        pool_types: vec![],
    };

    let mut stream = client
        .get_block_range(range)
        .await
        .map_err(|e| anyhow!("GetBlockRange({}-{}) failed: {}", low, high, e))?
        .into_inner();

    let mut candidate = low;
    while let Some(block) = stream
        .message()
        .await
        .map_err(|e| anyhow!("GetBlockRange stream error: {}", e))?
    {
        if block.time <= timestamp {
            candidate = block.height as u32;
        } else {
            break;
        }
    }

    Ok(candidate)
}

/// Fetch all completed Orchard shard roots starting at `start_index`.
///
/// `max_entries = 0` means "all". Streams via `GetSubtreeRoots` and collects
/// the full sequence — the cap layer is small and the stream is short-lived.
/// No per-request timeout is applied (matches `get_block_range` streaming usage).
pub(crate) async fn get_orchard_subtree_roots(
    client: &mut CompactTxStreamerClient<Channel>,
    start_index: u32,
) -> Result<Vec<SubtreeRoot>> {
    let req = tonic::Request::new(GetSubtreeRootsArg {
        start_index,
        shielded_protocol: ShieldedProtocol::Orchard as i32,
        max_entries: 0,
    });
    let mut stream = client
        .get_subtree_roots(req)
        .await
        .map_err(|e| anyhow!("GetSubtreeRoots failed: {}", e))?
        .into_inner();

    let mut out = Vec::new();
    while let Some(item) = stream
        .message()
        .await
        .map_err(|e| anyhow!("GetSubtreeRoots stream error: {}", e))?
    {
        out.push(item);
    }
    Ok(out)
}

/// Fetch the lightwalletd tree state at `height`.
pub(crate) async fn get_tree_state_at(
    client: &mut CompactTxStreamerClient<Channel>,
    height: u32,
) -> Result<TreeState> {
    let mut req = tonic::Request::new(BlockId { height: height as u64, hash: vec![] });
    req.set_timeout(UNARY_TIMEOUT);
    client
        .get_tree_state(req)
        .await
        .map(|r| r.into_inner())
        .map_err(|e| anyhow!("GetTreeState({}) failed: {}", height, e))
}

/// Broadcast a serialized transaction via the `SendTransaction` gRPC method.
///
/// Returns the txid (hex) on success (`error_code == 0`). On a non-zero
/// `error_code`, returns an error carrying the server's `error_message`.
///
/// The txid is recomputed from the V5 transaction bytes (which embed the
/// consensus branch ID in the stream, making the branch-id argument to
/// `Transaction::read` advisory for V5).
///
/// # Errors
///
/// Returns an error if the connection fails, the RPC is rejected, or the
/// endpoint reports a non-zero error code.
pub async fn broadcast_transaction(grpc_url: String, tx_bytes: Vec<u8>) -> Result<String> {
    let channel = connect(&grpc_url).await?;
    let mut client = CompactTxStreamerClient::new(channel);

    // Recompute the txid from the V5 bytes before moving them into the request.
    // For V5 transactions `Transaction::read` derives the txid from the stream
    // (the branch id argument is ignored for V5).
    let txid = txid_from_v5_bytes(&tx_bytes)?;

    let mut req = tonic::Request::new(RawTransaction {
        data: tx_bytes,
        height: 0,
    });
    req.set_timeout(UNARY_TIMEOUT);
    let resp = client
        .send_transaction(req)
        .await
        .map_err(|e| anyhow!("SendTransaction failed: {}", e))?
        .into_inner();

    // Pure mapping, unit-testable without a gRPC server (see tests below).
    interpret_send_response(resp)?;

    Ok(txid)
}

/// Map a `SendResponse` to success/failure. `error_code == 0` ⇒ accepted;
/// any non-zero code surfaces the server's `error_message`. Split out as a
/// pure function so the rejection path is unit-testable without a gRPC server.
fn interpret_send_response(resp: SendResponse) -> Result<()> {
    if resp.error_code != 0 {
        return Err(anyhow!(
            "SendTransaction rejected (code {}): {}",
            resp.error_code,
            resp.error_message
        ));
    }
    Ok(())
}

/// Compute the txid from a serialized V5 transaction, in big-endian (display)
/// hex order.
///
/// Rejects non-V5 bytes with a descriptive error before calling
/// `Transaction::read`, so callers cannot accidentally compute a txid from a
/// legacy transaction whose wire format differs from ZIP-225.
///
/// For V5 transactions the consensus branch ID is embedded in the stream, so
/// the `BranchId` argument to `Transaction::read` is not used. We pass
/// `BranchId::Nu6` as a safe placeholder.
///
/// Byte order: `Transaction::txid()` returns internal little-endian bytes; this
/// function reverses them to big-endian *display* order so the result matches
/// `ShieldedTransaction.txid` from the sync path (see `sync.rs`) and the txid
/// Ledger Live records as the operation hash. Keeping the two paths consistent
/// is required so a freshly-broadcast transaction reconciles with the same
/// transaction once it is discovered by sync.
fn txid_from_v5_bytes(tx_bytes: &[u8]) -> Result<String> {
    // Peek at the version header without consuming from the slice that
    // `Transaction::read` will use — use a separate cursor for the check.
    let version = TxVersion::read(std::io::Cursor::new(tx_bytes))
        .map_err(|e| anyhow!("txid_from_v5_bytes: version parse failed: {}", e))?;
    if !matches!(version, TxVersion::V5) {
        return Err(anyhow!(
            "txid_from_v5_bytes: expected V5 transaction, got {:?}",
            version
        ));
    }
    let tx = Transaction::read(tx_bytes, BranchId::Nu6)
        .map_err(|e| anyhow!("txid_from_v5_bytes: Transaction::read failed: {}", e))?;
    let mut txid_bytes: [u8; 32] = *tx.txid().as_ref();
    txid_bytes.reverse(); // internal little-endian -> big-endian display order
    Ok(hex::encode(txid_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_rejects_malformed_url() {
        let err = connect("definitely not a url !!!").await.unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    /// Verifies that `connect()` fails promptly with a clear error when the
    /// TCP port is not listening (ECONNREFUSED), instead of hanging.
    #[tokio::test]
    async fn connect_fails_fast_on_refused_port() {
        // Bind then immediately drop to get a port guaranteed to be closed.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let url = format!("https://127.0.0.1:{}", addr.port());

        let err = connect(&url).await.unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    /// Verifies that `connect()` does not hang indefinitely when a server
    /// accepts the TCP connection but never completes the TLS handshake.
    /// The connect timeout must fire within [`CONNECT_TIMEOUT`].
    #[tokio::test]
    async fn connect_times_out_when_server_stalls_after_tcp_accept() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Accept connections but never send a TLS ServerHello.
        tokio::spawn(async move {
            loop {
                if let Ok((_sock, _)) = listener.accept().await {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        });

        tokio::time::pause();

        let connect_fut = tokio::spawn(connect(
            format!("https://127.0.0.1:{port}").leak(),
        ));

        // Let the task start and register its timers, then advance past CONNECT_TIMEOUT.
        tokio::task::yield_now().await;
        tokio::time::advance(CONNECT_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        let err = connect_fut.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn find_block_height_fails_on_malformed_url() {
        let err = find_block_height("not a url".to_string(), 1_700_000_000)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn find_block_height_fails_on_refused_port() {
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let err =
            find_block_height(format!("https://127.0.0.1:{}", addr.port()), 1_700_000_000)
                .await
                .unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    // ── broadcast_transaction — error paths ──────────────────────────────────

    #[tokio::test]
    async fn broadcast_transaction_fails_on_malformed_url() {
        let err = broadcast_transaction("invalid gRPC URL".to_string(), vec![0u8; 4])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn broadcast_transaction_fails_fast_on_refused_port() {
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let err = broadcast_transaction(format!("https://127.0.0.1:{}", addr.port()), vec![0u8; 4])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    // ── broadcast_transaction — happy path (end-to-end, mock gRPC server) ─────
    //
    // `zcash_client_backend` only generates the CompactTxStreamer *client*, so
    // there is no server trait to implement. We hand-roll the smallest possible
    // gRPC server: a `tower` service that routes the single `SendTransaction`
    // path to a `UnaryService` returning a configured `SendResponse`, served over
    // plaintext h2 (matching the `http://` branch of `connect`). This exercises
    // the full success path: connect → SendTransaction → error_code == 0 →
    // recompute txid from the V5 bytes, which the error-path and pure-mapping
    // tests never cover.

    /// Minimal `CompactTxStreamer` mock that answers `SendTransaction` with a
    /// fixed `SendResponse` and rejects every other method as unimplemented.
    #[derive(Clone)]
    struct MockStreamer {
        response: SendResponse,
    }

    impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>> for MockStreamer {
        type Response = tonic::codegen::http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(
            &mut self,
            req: tonic::codegen::http::Request<tonic::body::Body>,
        ) -> Self::Future {
            let response = self.response.clone();
            Box::pin(async move {
                match req.uri().path() {
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction" => {
                        struct SendTxSvc(SendResponse);
                        impl tonic::server::UnaryService<RawTransaction> for SendTxSvc {
                            type Response = SendResponse;
                            type Future = std::pin::Pin<
                                Box<
                                    dyn std::future::Future<
                                            Output = Result<
                                                tonic::Response<SendResponse>,
                                                tonic::Status,
                                            >,
                                        > + Send,
                                >,
                            >;
                            fn call(
                                &mut self,
                                _request: tonic::Request<RawTransaction>,
                            ) -> Self::Future {
                                let resp = self.0.clone();
                                Box::pin(async move { Ok(tonic::Response::new(resp)) })
                            }
                        }

                        // ProstCodec<Encode, Decode>: we encode SendResponse and
                        // decode the inbound RawTransaction.
                        let codec =
                            tonic_prost::ProstCodec::<SendResponse, RawTransaction>::default();
                        let mut grpc = tonic::server::Grpc::new(codec);
                        Ok(grpc.unary(SendTxSvc(response), req).await)
                    }
                    _ => Ok(tonic::codegen::http::Response::new(
                        tonic::body::Body::default(),
                    )),
                }
            })
        }
    }

    #[tokio::test]
    async fn broadcast_transaction_returns_txid_on_accept() {
        let tx_bytes = hex::decode(TX_V5_HEX.trim()).expect("fixture must be valid hex");

        // Bind first so the OS backlog queues the client's connection even before
        // the server's accept loop starts — no startup sleep needed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let incoming = tonic::transport::server::TcpIncoming::from(listener);

        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .serve_with_incoming(
                    MockStreamer {
                        response: SendResponse {
                            error_code: 0,
                            error_message: String::new(),
                        },
                    },
                    incoming,
                )
                .await
        });

        let url = format!("http://127.0.0.1:{port}");
        let txid = broadcast_transaction(url, tx_bytes)
            .await
            .expect("error_code == 0 must yield a txid");

        // The returned txid must be the canonical big-endian display txid of the
        // V5 bytes we broadcast, identical to what the sync path / LL records.
        assert_eq!(
            txid, TX_V5_TXID_DISPLAY,
            "happy path must recompute the canonical txid from the V5 bytes"
        );

        server.abort();
    }

    // ── interpret_send_response — pure mapping tests ──────────────────────────

    #[test]
    fn interpret_send_response_ok_for_error_code_zero() {
        let resp = SendResponse {
            error_code: 0,
            error_message: String::new(),
        };
        assert!(
            interpret_send_response(resp).is_ok(),
            "error_code == 0 must return Ok"
        );
    }

    #[test]
    fn interpret_send_response_err_for_nonzero_error_code() {
        let resp = SendResponse {
            error_code: 1,
            error_message: "fee too low".to_string(),
        };
        let err = interpret_send_response(resp).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("code 1"),
            "error must contain 'code 1', got: {msg}"
        );
        assert!(
            msg.contains("fee too low"),
            "error must contain the error_message, got: {msg}"
        );
    }

    #[test]
    fn interpret_send_response_err_nonzero_preserves_message() {
        let resp = SendResponse {
            error_code: 42,
            error_message: "double spend detected".to_string(),
        };
        let err = interpret_send_response(resp).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("42"), "error must contain error_code");
        assert!(
            msg.contains("double spend detected"),
            "error must contain error_message"
        );
    }

    // ── txid_from_v5_bytes — direct tests ────────────────────────────────────
    //
    // Known vectors reused from `zcash-crypto/tests/fixtures` (same workspace).
    // The expected txids are the big-endian *display* form documented in
    // `zcash-crypto/tests/known_vectors.rs`.

    /// A real V5 transaction (header `05000080`).
    const TX_V5_HEX: &str =
        include_str!("../../zcash-crypto/tests/fixtures/tx_0b5baa0c_h3055417.hex");
    /// Its canonical (big-endian, display) txid.
    const TX_V5_TXID_DISPLAY: &str =
        "0b5baa0c01ea74f93effe5cc0566eaf086bf67329ff2923bc07a5d0e8859a65e";
    /// A real V4 transaction (header `04000080`) — used to exercise the V5 guard.
    const TX_V4_HEX: &str =
        include_str!("../../zcash-crypto/tests/fixtures/tx_c534920d_h954650_testnet.hex");

    #[test]
    fn txid_from_v5_bytes_computes_canonical_txid() {
        let bytes = hex::decode(TX_V5_HEX.trim()).expect("fixture must be valid hex");
        let got = txid_from_v5_bytes(&bytes).expect("V5 txid computation must succeed");
        assert_eq!(got.len(), 64, "txid hex must be 64 chars");
        // `txid_from_v5_bytes` returns big-endian display order, matching the
        // sync path (`ShieldedTransaction.txid`) and the LL operation hash.
        assert_eq!(
            got, TX_V5_TXID_DISPLAY,
            "txid must match the documented big-endian display txid"
        );
    }

    #[test]
    fn txid_from_v5_bytes_rejects_non_v5() {
        let bytes = hex::decode(TX_V4_HEX.trim()).expect("fixture must be valid hex");
        let err = txid_from_v5_bytes(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected V5 transaction"),
            "non-V5 input must be rejected by the version guard, got: {msg}"
        );
    }

    // ── algorithm mock tests ─────────────────────────────────────────────────
    //
    // The gRPC server trait is not exposed by zcash_client_backend, so we
    // mirror the interpolation + scan algorithm against a synthetic chain.
    // This acts as an executable spec: if the production logic changes, the
    // mirror must be updated too — any divergence is a review signal.

    fn mock_find_block_height(chain: &[(u32, u32)], timestamp: u32) -> u32 {
        let tip = chain.last().unwrap().0;
        if tip == 0 { return 0; }

        let get_time = |h: u32| -> u32 {
            chain.iter().find(|(height, _)| *height == h).unwrap().1
        };

        let (mut low, mut high) = (chain[0].0, tip);
        let (mut low_t, mut high_t) = (get_time(low), get_time(high));
        if timestamp <= low_t { return low; }
        if timestamp >= high_t { return high; }

        while high - low > RANGE_FETCH_THRESHOLD {
            let range_h = (high - low) as u64;
            let range_t = (high_t - low_t).max(1) as u64;
            let offset_t = (timestamp - low_t) as u64;
            let est = low + ((offset_t * range_h / range_t) as u32).clamp(1, (high - low) - 1);
            let est_t = get_time(est);
            if est_t < timestamp { low = est; low_t = est_t; }
            else { high = est; high_t = est_t; }
        }

        let mut candidate = low;
        for &(h, t) in chain {
            if h < low || h > high { continue; }
            if t <= timestamp { candidate = h; } else { break; }
        }
        candidate
    }

    fn make_chain(count: u32, genesis_ts: u32, interval: u32) -> Vec<(u32, u32)> {
        (1..=count).map(|h| (h, genesis_ts + h * interval)).collect()
    }

    #[test]
    fn mock_algo_returns_block_before_when_between_timestamps() {
        let chain = make_chain(10_000, 1_000_000, 75);
        let t_5000 = chain.iter().find(|(h, _)| *h == 5000).unwrap().1;
        let t_5001 = chain.iter().find(|(h, _)| *h == 5001).unwrap().1;
        let result = mock_find_block_height(&chain, (t_5000 + t_5001) / 2);
        assert_eq!(result, 5000, "should return latest block ≤ target");
    }

    #[test]
    fn mock_algo_matches_brute_force_across_range() {
        let chain = make_chain(5_000, 1_477_000_000, 75);
        let brute = |ts: u32| -> u32 {
            chain.iter().rev().find(|(_, t)| *t <= ts).map(|(h, _)| *h).unwrap_or(chain[0].0)
        };
        for &target in &[1_477_100_000u32, 1_477_200_000, 1_477_300_000, 1_477_375_000] {
            let result = mock_find_block_height(&chain, target);
            assert_eq!(result, brute(target), "mismatch for timestamp {target}");
        }
    }
}
