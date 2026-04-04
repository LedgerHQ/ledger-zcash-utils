use anyhow::{anyhow, Result};
use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, ChainSpec,
};

/// Establish a TLS-secured gRPC channel to a lightwalletd / Zaino endpoint.
///
/// # Errors
///
/// Returns an error if the URL is invalid or the TLS handshake fails.
pub async fn connect(grpc_url: &str) -> Result<Channel> {
    tonic::transport::Channel::from_shared(grpc_url.to_owned())
        .map_err(|e| anyhow!("invalid gRPC URL: {}", e))?
        .tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
        .map_err(|e| anyhow!("TLS config failed: {}", e))?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .map_err(|e| anyhow!("gRPC connect failed: {}", e))
}

/// Query the current chain tip height from a lightwalletd endpoint.
///
/// # Errors
///
/// Returns an error if the connection fails or the RPC call is rejected.
pub async fn chain_tip(grpc_url: String) -> Result<u32> {
    let channel = connect(&grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);
    let latest = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|e| anyhow!("GetLatestBlock failed: {}", e))?
        .into_inner();
    Ok(latest.height as u32)
}
