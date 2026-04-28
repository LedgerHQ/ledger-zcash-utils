use anyhow::{anyhow, Result};
use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
};

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

    let mut low: u32 = 1;
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
