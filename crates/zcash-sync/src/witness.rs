//! Orchard witness orchestrator.
//!
//! Fetches cap roots, frontier, and shard cmx leaves from a lightwalletd /
//! Zaino endpoint, then delegates to `zcash_crypto::tree::build_witnesses`
//! for the pure tree assembly.

use anyhow::{anyhow, Result};
use tonic::transport::Channel;
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange},
};
use zcash_crypto::tree::{
    build_witnesses, frontier_leaf_count, ShardLeaves, WitnessInputs, WitnessOutput,
    ORCHARD_SHARD_HEIGHT,
};

use crate::client::{chain_tip_with_client, connect, get_orchard_subtree_roots, get_tree_state_at};

/// Default safety margin (in blocks) below the chain tip when the caller does
/// not pin a specific anchor height. Matches the zcashd / zecwallet default.
const DEFAULT_ANCHOR_DEPTH_BLOCKS: u32 = 10;

/// A note for which a witness is requested.
#[derive(Clone, Copy, Debug)]
pub struct NoteRef {
    /// Leaf index in the Orchard commitment tree (from `position` field of `ShieldedNote`).
    pub position: u64,
    /// 32-byte cmx (note commitment) for the leaf.
    pub cmx: [u8; 32],
}

/// Input parameters for [`compute_witnesses`].
pub struct WitnessRequest {
    /// gRPC endpoint URL (e.g. `https://zaino-zec-testnet.nodes.stg.ledger-test.com/`).
    pub grpc_url: String,
    /// Explicit anchor height. When `None`, falls back to `tip - anchor_depth_blocks`.
    pub anchor_height: Option<u32>,
    /// Safety margin used when `anchor_height` is `None`. Defaults to
    /// [`DEFAULT_ANCHOR_DEPTH_BLOCKS`] when `None`.
    pub anchor_depth_blocks: Option<u32>,
    /// Notes for which witnesses are requested.
    pub notes: Vec<NoteRef>,
}

/// Compute Merkle witnesses for every requested note against a single anchor.
///
/// # Errors
///
/// Returns an error if the notes list is empty, if the gRPC connection fails,
/// or if the pure witness assembly fails (e.g. anchor mismatch).
pub async fn compute_witnesses(req: WitnessRequest) -> Result<WitnessOutput> {
    if req.notes.is_empty() {
        return Err(anyhow!("compute_witnesses: notes list is empty"));
    }

    let channel = connect(&req.grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);

    // 1. Resolve anchor height.
    let anchor_height = match req.anchor_height {
        Some(h) => h,
        None => {
            let tip = chain_tip_with_client(&mut client).await?;
            let depth = req
                .anchor_depth_blocks
                .unwrap_or(DEFAULT_ANCHOR_DEPTH_BLOCKS);
            tip.saturating_sub(depth).max(1)
        }
    };

    // 2. Fetch tree state at the anchor (frontier + boundary metadata).
    let tree_state = get_tree_state_at(&mut client, anchor_height).await?;
    let frontier_bytes = hex::decode(&tree_state.orchard_tree)
        .map_err(|e| anyhow!("TreeState.orchard_tree hex decode failed: {}", e))?;

    // Total commitments at the anchor — used to bound the frontier shard and to
    // trim per-shard fetches by absolute position.
    let anchor_total_leaves =
        frontier_leaf_count(&frontier_bytes).map_err(|e| anyhow!("frontier leaf count: {}", e))?;

    // 3. Fetch every completed Orchard shard root.
    let subtree_roots = get_orchard_subtree_roots(&mut client, 0).await?;

    // 4. Determine which shards contain at least one requested note.
    let needed_shards: std::collections::BTreeSet<u32> = req
        .notes
        .iter()
        .map(|n| (n.position >> ORCHARD_SHARD_HEIGHT) as u32)
        .collect();

    // 5. For each needed shard, find its block-height range and fetch cmxs.
    let shard_leaves = fetch_shard_leaves(
        &mut client,
        &subtree_roots,
        anchor_height,
        anchor_total_leaves,
        &needed_shards,
    )
    .await?;

    // 6. Build cap_roots — completed shards only (frontier shard's root comes
    //    from the frontier itself, not from GetSubtreeRoots).
    let cap_roots: Vec<(u32, [u8; 32])> = subtree_roots
        .iter()
        .enumerate()
        .map(|(i, sr)| {
            let bytes: [u8; 32] = sr
                .root_hash
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("GetSubtreeRoots returned a root that is not 32 bytes"))?;
            Ok((i as u32, bytes))
        })
        .collect::<Result<Vec<_>>>()?;

    // 7. Hand off to the pure builder.
    let notes: Vec<(u64, [u8; 32])> = req.notes.iter().map(|n| (n.position, n.cmx)).collect();
    let inputs = WitnessInputs {
        cap_roots,
        frontier_bytes,
        anchor_height,
        shard_leaves,
        notes,
    };
    build_witnesses(&inputs).map_err(|e| anyhow!("build_witnesses: {}", e))
}

/// Fetch the cmx leaves for each needed shard, trimmed to that shard's exact
/// absolute-position range.
///
/// An Orchard shard boundary can fall in the middle of a block: the block that
/// *completes* shard `s` (its `completing_block_height`) may also contain the
/// first leaves of shard `s+1`. Naively scanning `(completing(s-1), completing(s)]`
/// therefore over- or under-counts at both ends. Instead we scan a block range
/// guaranteed to contain the whole shard — starting at the previous shard's
/// completing block (inclusive) — and slice out exactly the commitments whose
/// absolute positions fall in `[s * 2^16, (s+1) * 2^16)` (or `[s * 2^16, total)`
/// for the partial frontier shard). The slice offset is derived from the tree
/// size at the block just before the scan starts.
async fn fetch_shard_leaves(
    client: &mut CompactTxStreamerClient<Channel>,
    subtree_roots: &[zcash_client_backend::proto::service::SubtreeRoot],
    anchor_height: u32,
    anchor_total_leaves: u64,
    needed_shards: &std::collections::BTreeSet<u32>,
) -> Result<Vec<ShardLeaves>> {
    let mut out = Vec::with_capacity(needed_shards.len());
    let frontier_shard_index = subtree_roots.len() as u32;
    for &shard_idx in needed_shards {
        // Scan range: from the previous shard's completing block (inclusive) so
        // any of this shard's leaves that spilled into that block are captured.
        let start_height = if shard_idx == 0 {
            // Orchard activation is enforced server-side; clamp to 1.
            1u32
        } else {
            let prev = subtree_roots.get((shard_idx - 1) as usize).ok_or_else(|| {
                anyhow!(
                    "requested shard {} but only {} shards completed",
                    shard_idx,
                    subtree_roots.len()
                )
            })?;
            prev.completing_block_height as u32
        };
        let end_height = if shard_idx < frontier_shard_index {
            subtree_roots[shard_idx as usize].completing_block_height as u32
        } else {
            anchor_height
        };

        // Absolute position of the first commitment in `start_height` = number of
        // commitments present at the end of the preceding block.
        let base_offset = tree_size_at(client, start_height.saturating_sub(1)).await?;
        let raw = collect_orchard_cmxs(client, start_height, end_height).await?;

        let (lo, hi) = shard_leaf_bounds(
            shard_idx,
            frontier_shard_index,
            anchor_total_leaves,
            base_offset,
            raw.len(),
        )?;
        out.push(ShardLeaves {
            shard_index: shard_idx,
            cmxs: raw[lo..hi].to_vec(),
        });
    }
    Ok(out)
}

/// Number of Orchard commitments present at the end of block `height`
/// (0 for height 0 / pre-activation), derived from `GetTreeState`'s frontier.
async fn tree_size_at(client: &mut CompactTxStreamerClient<Channel>, height: u32) -> Result<u64> {
    if height == 0 {
        return Ok(0);
    }
    let ts = get_tree_state_at(client, height).await?;
    let bytes = hex::decode(&ts.orchard_tree)
        .map_err(|e| anyhow!("TreeState.orchard_tree hex decode at {}: {}", height, e))?;
    frontier_leaf_count(&bytes).map_err(|e| anyhow!("frontier leaf count at {}: {}", height, e))
}

/// Given commitments fetched starting at absolute position `base_offset`, return
/// the `[lo, hi)` sub-slice that corresponds to shard `shard_idx`.
fn shard_leaf_bounds(
    shard_idx: u32,
    frontier_shard_index: u32,
    anchor_total_leaves: u64,
    base_offset: u64,
    raw_len: usize,
) -> Result<(usize, usize)> {
    let shard_size = 1u64 << ORCHARD_SHARD_HEIGHT;
    let start_pos = u64::from(shard_idx) * shard_size;
    let end_pos = if shard_idx < frontier_shard_index {
        start_pos + shard_size
    } else {
        anchor_total_leaves
    };
    if base_offset > start_pos {
        return Err(anyhow!(
            "shard {}: scan base offset {} is past shard start {}",
            shard_idx,
            base_offset,
            start_pos
        ));
    }
    let lo = (start_pos - base_offset) as usize;
    let hi = (end_pos - base_offset) as usize;
    if lo > hi || hi > raw_len {
        return Err(anyhow!(
            "shard {}: leaf slice [{}, {}) out of range for {} fetched commitments",
            shard_idx,
            lo,
            hi,
            raw_len
        ));
    }
    Ok((lo, hi))
}

async fn collect_orchard_cmxs(
    client: &mut CompactTxStreamerClient<Channel>,
    start: u32,
    end: u32,
) -> Result<Vec<[u8; 32]>> {
    let range = BlockRange {
        start: Some(BlockId {
            height: start as u64,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: end as u64,
            hash: vec![],
        }),
    };
    let mut stream = client
        .get_block_range(range)
        .await
        .map_err(|e| anyhow!("GetBlockRange({}-{}) failed: {}", start, end, e))?
        .into_inner();

    let mut out = Vec::new();
    while let Some(block) = stream
        .message()
        .await
        .map_err(|e| anyhow!("GetBlockRange stream error: {}", e))?
    {
        push_block_cmxs(&block, &mut out)?;
    }
    Ok(out)
}

fn push_block_cmxs(block: &CompactBlock, out: &mut Vec<[u8; 32]>) -> Result<()> {
    for tx in &block.vtx {
        for action in &tx.actions {
            let bytes: [u8; 32] = action.cmx.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "cmx not 32 bytes (got {}) at block {}",
                    action.cmx.len(),
                    block.height,
                )
            })?;
            out.push(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::proto::{
        compact_formats::{CompactBlock, CompactOrchardAction, CompactTx},
        service::SubtreeRoot,
    };

    // ── 1. push_block_cmxs collects in tx/action order ────────────────────────

    #[test]
    fn push_block_cmxs_collects_in_order() {
        let block = CompactBlock {
            height: 100,
            vtx: vec![
                CompactTx {
                    actions: vec![
                        CompactOrchardAction {
                            cmx: vec![1u8; 32],
                            ..Default::default()
                        },
                        CompactOrchardAction {
                            cmx: vec![2u8; 32],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                CompactTx {
                    actions: vec![CompactOrchardAction {
                        cmx: vec![3u8; 32],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let mut out = Vec::new();
        push_block_cmxs(&block, &mut out).unwrap();

        assert_eq!(out.len(), 3);
        assert_eq!(out[0], [1u8; 32]);
        assert_eq!(out[1], [2u8; 32]);
        assert_eq!(out[2], [3u8; 32]);
    }

    // ── 2. push_block_cmxs rejects malformed cmx (length ≠ 32) ───────────────

    #[test]
    fn push_block_cmxs_rejects_malformed_cmx() {
        let block = CompactBlock {
            height: 42,
            vtx: vec![CompactTx {
                actions: vec![CompactOrchardAction {
                    cmx: vec![0u8; 16], // wrong length
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut out = Vec::new();
        let err = push_block_cmxs(&block, &mut out).unwrap_err();
        assert!(
            err.to_string().contains("cmx not 32 bytes"),
            "unexpected error: {err}"
        );
    }

    // ── shard_leaf_bounds: mid-block boundary trimming ────────────────────────

    const SHARD_SIZE: u64 = 1 << ORCHARD_SHARD_HEIGHT;

    #[test]
    fn shard_leaf_bounds_trims_frontier_shard_leading_spillover() {
        // Frontier shard = 2. Shard 1 completed mid-block, so 5 of shard 1's
        // leaves precede shard 2's first leaf within the boundary block we scan.
        // The scan fetched: 5 trailing shard-1 leaves + 31 shard-2 leaves.
        let base_offset = 2 * SHARD_SIZE - 5;
        let raw_len = 5 + 31;
        let total = 2 * SHARD_SIZE + 31;
        let (lo, hi) = shard_leaf_bounds(2, 2, total, base_offset, raw_len).unwrap();
        assert_eq!((lo, hi), (5, 36));
        assert_eq!(hi - lo, 31, "exactly the 31 frontier-shard leaves");
    }

    #[test]
    fn shard_leaf_bounds_trims_completed_shard_both_ends() {
        // Completed shard 1, scanned from shard 0's completing block. 3 shard-0
        // leaves precede; the scan also runs into shard 2 (7 spillover leaves).
        let base_offset = SHARD_SIZE - 3;
        let raw_len = (3 + SHARD_SIZE + 7) as usize;
        let total = 3 * SHARD_SIZE; // irrelevant for a completed shard
        let (lo, hi) = shard_leaf_bounds(1, 2, total, base_offset, raw_len).unwrap();
        assert_eq!(lo, 3, "skip the 3 leading shard-0 leaves");
        assert_eq!((hi - lo) as u64, SHARD_SIZE, "exactly one full shard");
        assert_eq!(hi as u64, 3 + SHARD_SIZE, "drop the trailing shard-2 spillover");
    }

    #[test]
    fn shard_leaf_bounds_shard_zero_no_offset() {
        let total = SHARD_SIZE + 10;
        let (lo, hi) = shard_leaf_bounds(0, 1, total, 0, (SHARD_SIZE + 10) as usize).unwrap();
        assert_eq!((lo as u64, hi as u64), (0, SHARD_SIZE));
    }

    #[test]
    fn shard_leaf_bounds_errors_when_fetch_too_short() {
        // Claim a frontier shard needs leaves up to `total`, but the fetch came
        // back short → must error rather than panic on the slice.
        let err = shard_leaf_bounds(2, 2, 2 * SHARD_SIZE + 31, 2 * SHARD_SIZE, 10).unwrap_err();
        assert!(err.to_string().contains("out of range"), "got: {err}");
    }

    // ── 5. compute_witnesses rejects empty notes list ─────────────────────────

    #[tokio::test]
    async fn compute_witnesses_rejects_empty_notes() {
        let req = WitnessRequest {
            grpc_url: "https://127.0.0.1:1".to_string(),
            anchor_height: Some(1),
            anchor_depth_blocks: None,
            notes: vec![],
        };
        let err = compute_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("notes list is empty"),
            "unexpected error: {err}"
        );
    }

    // ── 4. compute_witnesses on refused port ─────────────────────────────────

    #[tokio::test]
    async fn compute_witnesses_fails_on_refused_port() {
        // Bind then immediately drop to get a port guaranteed to be closed.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let req = WitnessRequest {
            grpc_url: format!("https://127.0.0.1:{}", addr.port()),
            anchor_height: Some(1),
            anchor_depth_blocks: None,
            notes: vec![NoteRef {
                position: 0,
                cmx: [0u8; 32],
            }],
        };
        let err = compute_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    // ── 3. compute_witnesses fails on malformed URL ───────────────────────────

    #[tokio::test]
    async fn compute_witnesses_fails_on_malformed_url() {
        let req = WitnessRequest {
            grpc_url: "definitely not a url !!!".to_string(),
            anchor_height: Some(1),
            anchor_depth_blocks: None,
            notes: vec![NoteRef {
                position: 0,
                cmx: [0u8; 32],
            }],
        };
        let err = compute_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    // ── SubtreeRoot with wrong root_hash length → error ───────────────────────

    #[test]
    fn subtree_root_non_32_bytes_raises_error() {
        // Simulate the cap_roots building step inline.
        let bad_root = SubtreeRoot {
            root_hash: vec![0u8; 16], // wrong length
            completing_block_hash: vec![],
            completing_block_height: 1,
        };
        let subtree_roots = [bad_root];
        let result: Result<Vec<(u32, [u8; 32])>> = subtree_roots
            .iter()
            .enumerate()
            .map(|(i, sr)| {
                let bytes: [u8; 32] =
                    sr.root_hash.as_slice().try_into().map_err(|_| {
                        anyhow!("GetSubtreeRoots returned a root that is not 32 bytes")
                    })?;
                Ok((i as u32, bytes))
            })
            .collect();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not 32 bytes"));
    }
}
