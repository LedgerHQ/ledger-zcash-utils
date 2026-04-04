use anyhow::{anyhow, Result};
use tonic::transport::Channel;
use zcash_client_backend::proto::{
    compact_formats::{CompactOrchardAction as ProtoOrchardAction, CompactSaplingOutput as ProtoSaplingOutput},
    service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, TxFilter,
    },
};
use zcash_crypto::decrypt::{
    self, CompactOrchardAction, CompactSaplingOutput, CompactTransaction, DecryptedOutput,
};
use zcash_crypto::network::parse_network;

use crate::client::connect;

// ─── public types ─────────────────────────────────────────────────────────────

/// Parameters for a shielded block range sync.
pub struct SyncParams {
    /// gRPC endpoint URL (e.g. `"https://testnet.zec.rocks:443"`).
    pub grpc_url: String,
    /// Unified Full Viewing Key (UFVK) for the account to scan.
    pub viewing_key: String,
    /// First block height to scan (inclusive).
    pub start_height: u32,
    /// Last block height to scan (inclusive).
    pub end_height: u32,
    /// `"mainnet"` or `"testnet"` (defaults to `"testnet"` if `None`).
    pub network: Option<String>,
}

/// A single shielded note found during decryption.
#[derive(Debug, Clone)]
pub struct ShieldedNote {
    /// Value in zatoshis.
    pub amount: u64,
    /// `"incoming"`, `"outgoing"`, or `"internal"`.
    pub transfer_type: String,
    /// Memo text (UTF-8, null-trimmed).
    pub memo: String,
}

/// A matched and fully-decrypted shielded transaction.
#[derive(Debug, Clone)]
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
    /// Decrypted Sapling notes belonging to this account.
    pub sapling_notes: Vec<ShieldedNote>,
    /// Decrypted Orchard notes belonging to this account.
    pub orchard_notes: Vec<ShieldedNote>,
}

/// Result returned after scanning a block range.
#[derive(Debug)]
pub struct SyncResult {
    pub transactions: Vec<ShieldedTransaction>,
    pub blocks_scanned: u32,
    pub elapsed_ms: u64,
}

// ─── public API ───────────────────────────────────────────────────────────────

/// Scan a range of compact blocks for shielded transactions belonging to the
/// UFVK in `params`.
///
/// # Algorithm
///
/// 1. Parse the network and pre-compute IVKs from the UFVK (done once).
/// 2. Connect to the gRPC endpoint with TLS.
/// 3. Stream compact blocks via `GetBlockRange` (efficient single RPC).
/// 4. For each block: trial-decrypt compact outputs/actions to identify matching txids.
/// 5. For each matching txid: fetch the full transaction via `GetTransaction`.
/// 6. Full-decrypt the transaction to extract notes with memos and transfer types.
///
/// # Errors
///
/// Returns an error if the gRPC connection fails, UFVK is invalid, or the
/// block stream is interrupted.
pub async fn run_sync(params: SyncParams) -> Result<SyncResult> {
    let start = std::time::Instant::now();

    // 1. Resolve network and prepare IVKs once
    let network = parse_network(params.network.as_deref())
        .map_err(|e| anyhow!("{}", e))?;
    let ivks = decrypt::prepare_ivks(&params.viewing_key)
        .map_err(|e| anyhow!("{}", e))?;

    // 2. Connect to lightwalletd / Zaino with TLS
    let channel = connect(&params.grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);

    // 3. Stream compact blocks via GetBlockRange
    let range = BlockRange {
        start: Some(BlockId { height: params.start_height as u64, hash: vec![] }),
        end: Some(BlockId { height: params.end_height as u64, hash: vec![] }),
    };
    let mut stream = client
        .get_block_range(range)
        .await
        .map_err(|e| anyhow!("GetBlockRange failed: {}", e))?
        .into_inner();

    let mut blocks_scanned = 0u32;
    let mut all_transactions: Vec<ShieldedTransaction> = Vec::new();

    while let Some(block) = stream
        .message()
        .await
        .map_err(|e| anyhow!("stream error: {}", e))?
    {
        let block_hash = hex::encode(block.hash.iter().copied().rev().collect::<Vec<u8>>());

        // 4. Convert proto CompactTx → zcash-crypto CompactTransaction, then trial-decrypt
        let compact_txs: Vec<CompactTransaction> = block
            .vtx
            .iter()
            .map(|ctx| CompactTransaction {
                txid: hex::encode(ctx.hash.iter().copied().rev().collect::<Vec<u8>>()),
                sapling_outputs: ctx.outputs.iter().map(proto_sapling_to_compact).collect(),
                orchard_actions: ctx.actions.iter().map(proto_orchard_to_compact).collect(),
            })
            .collect();

        let matched_txids = decrypt::trial_decrypt_block(&compact_txs, &ivks);

        for txid_hex in matched_txids {
            // 5. GetTransaction — TxFilter.hash expects internal (little-endian) byte order
            let txid_bytes_le: Vec<u8> = hex::decode(&txid_hex)
                .map_err(|e| anyhow!("txid hex decode: {}", e))?
                .into_iter()
                .rev()
                .collect();

            let raw_tx = client
                .get_transaction(TxFilter {
                    block: Some(BlockId { height: block.height, hash: vec![] }),
                    index: 0,
                    hash: txid_bytes_le,
                })
                .await
                .map_err(|e| anyhow!("GetTransaction failed for {}: {}", txid_hex, e))?
                .into_inner();

            let tx_hex = hex::encode(&raw_tx.data);

            // 6. Full decryption → notes with memo + transfer_type
            // Pre-Overwinter transactions have an incompatible format; skip gracefully.
            let decrypted = match decrypt::full_decrypt_tx(
                &tx_hex,
                &params.viewing_key,
                block.height as u32,
                network,
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "WARN: full_decrypt_tx skipped {} at height {}: {}",
                        txid_hex, block.height, e
                    );
                    continue;
                }
            };

            all_transactions.push(ShieldedTransaction {
                txid: txid_hex,
                hex: tx_hex,
                block_height: block.height as u32,
                block_hash: block_hash.clone(),
                block_time: block.time,
                sapling_notes: decrypted
                    .sapling_outputs
                    .into_iter()
                    .map(to_shielded_note)
                    .collect(),
                orchard_notes: decrypted
                    .orchard_outputs
                    .into_iter()
                    .map(to_shielded_note)
                    .collect(),
            });
        }

        blocks_scanned += 1;
    }

    Ok(SyncResult {
        transactions: all_transactions,
        blocks_scanned,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ─── proto conversion helpers ─────────────────────────────────────────────────

/// Convert a proto `CompactSaplingOutput` to the zcash-crypto compact type.
fn proto_sapling_to_compact(p: &ProtoSaplingOutput) -> CompactSaplingOutput {
    CompactSaplingOutput {
        cmu: p.cmu.clone(),
        ephemeral_key: p.ephemeral_key.clone(),
        ciphertext: p.ciphertext.clone(),
    }
}

/// Convert a proto `CompactOrchardAction` to the zcash-crypto compact type.
fn proto_orchard_to_compact(p: &ProtoOrchardAction) -> CompactOrchardAction {
    CompactOrchardAction {
        cmx: p.cmx.clone(),
        ephemeral_key: p.ephemeral_key.clone(),
        ciphertext: p.ciphertext.clone(),
    }
}

/// Convert a [`DecryptedOutput`] from zcash-crypto to the gRPC layer's [`ShieldedNote`].
fn to_shielded_note(o: DecryptedOutput) -> ShieldedNote {
    ShieldedNote {
        amount: o.amount,
        transfer_type: o.transfer_type,
        memo: o.memo,
    }
}
