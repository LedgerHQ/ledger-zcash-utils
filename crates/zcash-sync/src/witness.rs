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
    build_witnesses, compute_shard_root, frontier_anchor, frontier_leaf_count, ShardLeaves,
    WitnessInputs, WitnessOutput, ORCHARD_SHARD_HEIGHT,
};

use crate::client::{
    chain_tip_with_client, connect, get_ironwood_subtree_roots, get_orchard_subtree_roots,
    get_tree_state_at,
};

/// Default safety margin (in blocks) below the chain tip when the caller does
/// not pin a specific anchor height. Matches the zcashd / zecwallet default.
const DEFAULT_ANCHOR_DEPTH_BLOCKS: u32 = 10;

/// Anchor height derived from the chain `tip` when no explicit height is
/// pinned: `tip - anchor_depth_blocks` (default [`DEFAULT_ANCHOR_DEPTH_BLOCKS`]),
/// clamped to a minimum of height 1.
fn anchor_height_from_tip(tip: u32, anchor_depth_blocks: Option<u32>) -> u32 {
    let depth = anchor_depth_blocks.unwrap_or(DEFAULT_ANCHOR_DEPTH_BLOCKS);
    tip.saturating_sub(depth).max(1)
}

/// Resolve the anchor height for a flow that does not otherwise contact the
/// witness orchestrator — the transparent-only Public→Public path, which builds
/// no Orchard bundle and therefore never calls [`compute_witnesses`] or
/// [`fetch_orchard_anchor`].
///
/// Returns an explicit `anchor_height` verbatim without any network I/O;
/// otherwise queries the chain tip and resolves `tip - anchor_depth_blocks`
/// (see [`resolve_from_tip`]). This keeps the transaction's target/expiry height
/// anchored to the live tip on the transparent path, matching the shielded
/// flows.
///
/// # Errors
///
/// Returns an error if resolution needs the tip and the gRPC connection or
/// `GetLatestBlock` call fails.
pub async fn resolve_anchor_height(
    grpc_url: &str,
    anchor_height: Option<u32>,
    anchor_depth_blocks: Option<u32>,
) -> Result<u32> {
    if let Some(h) = anchor_height {
        return Ok(h);
    }
    let channel = connect(grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);
    let tip = chain_tip_with_client(&mut client).await?;
    Ok(anchor_height_from_tip(tip, anchor_depth_blocks))
}

/// The shielded pool a witness/anchor is computed against. Orchard and Ironwood
/// share the exact same commitment-tree cryptography (Pallas/Sinsemilla,
/// `ShardTree<32,16>` — see `zcash_crypto::tree::build_witnesses`) — only the
/// gRPC pool selector (`GetSubtreeRoots`) and the `TreeState` field consulted
/// (`orchard_tree` vs `ironwood_tree`) differ between the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    Orchard,
    Ironwood,
}

impl Pool {
    /// Reads the pool's commitment-tree frontier hex string out of a `TreeState`.
    fn tree_state_hex(self, ts: &zcash_client_backend::proto::service::TreeState) -> &str {
        match self {
            Pool::Orchard => &ts.orchard_tree,
            Pool::Ironwood => &ts.ironwood_tree,
        }
    }
}

/// Fetch completed shard roots for `pool`, dispatching to the pool-specific
/// `GetSubtreeRoots` call.
async fn get_subtree_roots(
    client: &mut CompactTxStreamerClient<Channel>,
    pool: Pool,
    start_index: u32,
) -> Result<Vec<zcash_client_backend::proto::service::SubtreeRoot>> {
    match pool {
        Pool::Orchard => get_orchard_subtree_roots(client, start_index).await,
        Pool::Ironwood => get_ironwood_subtree_roots(client, start_index).await,
    }
}

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

/// Fetch the Orchard anchor (frontier root) at `anchor_height` without computing
/// any per-note witnesses.
///
/// Used for transparent-source flows (Public→Private) whose Orchard bundle has
/// outputs but no real spends — an anchor is still required for the dummy spends
/// the builder injects. Only `GetTreeState` is needed: the anchor is the root of
/// that frontier (see `zcash_crypto::tree::frontier_anchor`), and with no note to
/// witness there is no path to resolve and so no shard data to fetch.
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or if tree-state decoding fails.
pub async fn fetch_orchard_anchor(
    grpc_url: &str,
    anchor_height: Option<u32>,
    anchor_depth_blocks: Option<u32>,
) -> Result<WitnessOutput> {
    fetch_anchor_for_pool(Pool::Orchard, grpc_url, anchor_height, anchor_depth_blocks).await
}

/// Ironwood (NU6.3) sibling of [`fetch_orchard_anchor`]: fetches the Ironwood
/// anchor (frontier root) at `anchor_height` without computing any per-note
/// witnesses, reading the same `TreeState` message's `ironwood_tree` field.
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or if tree-state decoding fails.
pub async fn fetch_ironwood_anchor(
    grpc_url: &str,
    anchor_height: Option<u32>,
    anchor_depth_blocks: Option<u32>,
) -> Result<WitnessOutput> {
    fetch_anchor_for_pool(Pool::Ironwood, grpc_url, anchor_height, anchor_depth_blocks).await
}

/// Shared implementation behind [`fetch_orchard_anchor`] / [`fetch_ironwood_anchor`].
async fn fetch_anchor_for_pool(
    pool: Pool,
    grpc_url: &str,
    anchor_height: Option<u32>,
    anchor_depth_blocks: Option<u32>,
) -> Result<WitnessOutput> {
    let channel = connect(grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);

    // Resolve anchor height.
    let resolved_height = match anchor_height {
        Some(h) => h,
        None => {
            let tip = chain_tip_with_client(&mut client).await?;
            anchor_height_from_tip(tip, anchor_depth_blocks)
        }
    };

    // Fetch tree state at the anchor.
    let tree_state = get_tree_state_at(&mut client, resolved_height).await?;
    let frontier_bytes = hex::decode(pool.tree_state_hex(&tree_state))
        .map_err(|e| anyhow!("TreeState frontier hex decode failed: {}", e))?;

    // The frontier alone determines the root, so no shard data is fetched here.
    // That also keeps this path working against a server that does not serve the
    // pool's `GetSubtreeRoots` yet, which is the case for Ironwood on Zaino.
    let anchor = frontier_anchor(&frontier_bytes)
        .map_err(|e| anyhow!("frontier_anchor (anchor-only): {}", e))?;

    Ok(WitnessOutput {
        anchor,
        anchor_height: resolved_height,
        witnesses: vec![],
    })
}

/// Find the first block height at which `pool` has any commitment-tree leaves,
/// by binary-searching `GetTreeState` between block 1 and `anchor_height`.
///
/// The search returns the smallest height `h` at which the pool's frontier holds
/// at least one leaf. Emptiness is decided by [`tree_size_at`] (i.e. by
/// `frontier_leaf_count`), not by whether the server's hex field is an empty
/// string: a server is free to answer a pre-activation height with a *serialized
/// empty* frontier, which is non-empty as a string but still zero leaves. Reading
/// the leaf count keeps the predicate independent of that choice.
///
/// This is used by [`compute_ironwood_witnesses_from_blocks`] to bound the
/// `GetBlockRange` scan that collects all of the pool's cmx leaves.
///
/// # Errors
///
/// Returns an error if any `GetTreeState` call fails, or if the pool has no
/// leaves at or before `anchor_height` (which should not happen when the caller
/// already verified `anchor_total_leaves > 0`).
async fn find_pool_activation_height(
    client: &mut CompactTxStreamerClient<Channel>,
    pool: Pool,
    anchor_height: u32,
) -> Result<u32> {
    // Binary search: maintain invariant that pool has leaves at `high` and
    // does NOT have leaves strictly before `low`.
    let mut low = 1u32;
    let mut high = anchor_height;

    while low < high {
        let mid = low + (high - low) / 2;
        if tree_size_at(client, pool, mid).await? == 0 {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    // Guard: `low` must actually carry leaves.
    if tree_size_at(client, pool, low).await? == 0 {
        return Err(anyhow!(
            "find_pool_activation_height: pool {:?} has no leaves at or before anchor {}",
            pool,
            anchor_height
        ));
    }
    Ok(low)
}

/// Largest Ironwood pool this local strategy will process, in leaves.
///
/// This is the cost driver: the scan streams every leaf and reduces each completed
/// shard with ~2^17 Sinsemilla hashes, all inline in a user-facing send. 2^18 is
/// four completed shards — comfortably above the pool's present size (well under
/// one shard) and far below where the hashing stops being interactive.
///
/// Exceeding it is not a malfunction, it is the signal that this strategy has
/// outlived its purpose: switch back to `compute_witnesses_for_pool(Pool::Ironwood, …)`
/// once the server serves `GetSubtreeRoots` for Ironwood.
const MAX_IRONWOOD_LOCAL_LEAVES: u64 = 1 << 18;

/// Widest block range the local Ironwood scan will attempt.
///
/// Unlike [`MAX_IRONWOOD_LOCAL_LEAVES`] this is not a cost budget — it is a
/// sanity guard on [`find_pool_activation_height`]. If that probe ever resolves
/// far from the true activation height (worst case: down to genesis), the scan
/// would stream a large share of the chain through `GetBlockRange`, which carries
/// no per-request timeout. Failing fast with a legible error beats hanging.
///
/// Deliberately generous — it must not fire as the chain grows normally. At
/// Zcash's 75-second target spacing this is roughly 2.4 years of blocks after
/// NU6.3 activation, while the genuine pathology is off by ~4 million blocks.
const MAX_IRONWOOD_SCAN_BLOCKS: u32 = 1_000_000;

/// Reject a pool too large for the local strategy, before any block is fetched.
fn check_pool_size(anchor_total_leaves: u64) -> Result<()> {
    if anchor_total_leaves > MAX_IRONWOOD_LOCAL_LEAVES {
        return Err(anyhow!(
            "Ironwood pool holds {} leaves, past the {} this local shard-root \
             strategy supports; switch to GetSubtreeRoots for Ironwood",
            anchor_total_leaves,
            MAX_IRONWOOD_LOCAL_LEAVES
        ));
    }
    Ok(())
}

/// Reject an implausibly wide scan range before any block is fetched.
fn check_scan_width(activation_height: u32, anchor_height: u32) -> Result<()> {
    let width = anchor_height.saturating_sub(activation_height);
    if width > MAX_IRONWOOD_SCAN_BLOCKS {
        return Err(anyhow!(
            "Ironwood scan range {}..{} spans {} blocks (limit {}); the resolved \
             activation height is implausible — the server may report a non-empty \
             frontier for pre-activation heights",
            activation_height,
            anchor_height,
            width,
            MAX_IRONWOOD_SCAN_BLOCKS
        ));
    }
    Ok(())
}

/// Ironwood-specific witness computation that derives shard roots locally from
/// compact-block cmx leaves instead of calling `GetSubtreeRoots`.
///
/// # Strategy
///
/// 1. Resolve anchor height and fetch the Ironwood tree-state frontier to learn
///    `anchor_total_leaves` and the frontier bytes needed by [`build_witnesses`].
/// 2. Binary-search for the first block with any Ironwood leaves
///    ([`find_pool_activation_height`]) to bound the scan range.
/// 3. Stream **all** Ironwood cmx leaves from activation → anchor via
///    `GetBlockRange` (`collect_cmxs`).  The leaf count must match the
///    frontier; a mismatch surfaces an error rather than producing a silently
///    wrong witness.
/// 4. For each completed shard (leaf range `[i·2^16, (i+1)·2^16)`): call
///    [`compute_shard_root`] to get the 32-byte root hash that would normally
///    come from `GetSubtreeRoots`.
/// 5. For each shard that contains a requested note, slice the corresponding
///    leaves out of the full list and pass them as [`ShardLeaves`].
/// 6. Call [`build_witnesses`] with the locally-assembled inputs.
///
/// # Complexity
///
/// Fetches O(anchor_total_leaves) cmx bytes via `GetBlockRange` and performs
/// O(completed_shards × 65 536) Sinsemilla hash operations for step 4.  Both
/// costs are proportional to the Ironwood pool size, which is small while the
/// pool is young (NU6.3 is brand-new).  When Zaino deploys `GetSubtreeRoots`
/// support for Ironwood, callers should switch back to
/// `compute_witnesses_for_pool(Pool::Ironwood, …)`.
///
/// # Errors
///
/// Returns an error if the notes list is empty, if any gRPC call fails, if the
/// collected leaf count disagrees with the frontier, or if [`build_witnesses`]
/// reports an anchor/witness mismatch.
async fn compute_ironwood_witnesses_from_blocks(req: WitnessRequest) -> Result<WitnessOutput> {
    if req.notes.is_empty() {
        return Err(anyhow!("compute_ironwood_witnesses: notes list is empty"));
    }

    let channel = connect(&req.grpc_url).await?;
    let mut client: CompactTxStreamerClient<Channel> = CompactTxStreamerClient::new(channel);

    // 1. Resolve anchor height.
    let anchor_height = match req.anchor_height {
        Some(h) => h,
        None => {
            let tip = chain_tip_with_client(&mut client).await?;
            anchor_height_from_tip(tip, req.anchor_depth_blocks)
        }
    };

    // 2. Fetch Ironwood tree state at the anchor.
    let tree_state = get_tree_state_at(&mut client, anchor_height).await?;
    let frontier_bytes = hex::decode(Pool::Ironwood.tree_state_hex(&tree_state))
        .map_err(|e| anyhow!("Ironwood frontier hex decode failed: {}", e))?;

    let anchor_total_leaves = frontier_leaf_count(&frontier_bytes)
        .map_err(|e| anyhow!("Ironwood frontier leaf count: {}", e))?;

    if anchor_total_leaves == 0 {
        return Err(anyhow!(
            "compute_ironwood_witnesses: Ironwood pool has no leaves at anchor height {anchor_height}"
        ));
    }
    check_pool_size(anchor_total_leaves)?;

    // Reject a note that cannot exist in the tree at this anchor, before any
    // slicing: an out-of-range position would otherwise yield an empty
    // `ShardLeaves` and surface downstream as a confusing "witness not found".
    if let Some(bad) = req.notes.iter().find(|n| n.position >= anchor_total_leaves) {
        return Err(anyhow!(
            "compute_ironwood_witnesses: note position {} is at or past anchor_total_leaves {} \
             at anchor height {}",
            bad.position,
            anchor_total_leaves,
            anchor_height
        ));
    }

    // 3. Find the first block with any Ironwood leaves, then stream all cmxs.
    let activation_height =
        find_pool_activation_height(&mut client, Pool::Ironwood, anchor_height).await?;
    check_scan_width(activation_height, anchor_height)?;
    let all_cmxs = collect_cmxs(
        &mut client,
        Pool::Ironwood,
        activation_height,
        anchor_height,
    )
    .await?;

    if all_cmxs.len() as u64 != anchor_total_leaves {
        return Err(anyhow!(
            "compute_ironwood_witnesses: collected {} Ironwood cmxs but frontier reports {} \
             leaves at anchor height {} (activation height {})",
            all_cmxs.len(),
            anchor_total_leaves,
            anchor_height,
            activation_height,
        ));
    }

    // 4. Compute completed-shard roots locally (replaces GetSubtreeRoots).
    let shard_size = 1usize << ORCHARD_SHARD_HEIGHT;
    let num_complete_shards = (anchor_total_leaves as usize) / shard_size;

    let cap_roots: Vec<(u32, [u8; 32])> = (0..num_complete_shards)
        .map(|i| {
            let shard_cmxs = &all_cmxs[i * shard_size..(i + 1) * shard_size];
            let root = compute_shard_root(shard_cmxs)
                .map_err(|e| anyhow!("compute_shard_root(shard {}): {}", i, e))?;
            Ok((i as u32, root))
        })
        .collect::<Result<_>>()?;

    // 5. Build ShardLeaves for every shard that contains a requested note.
    let needed_shards: std::collections::BTreeSet<u32> = req
        .notes
        .iter()
        .map(|n| (n.position >> ORCHARD_SHARD_HEIGHT) as u32)
        .collect();

    let mut shard_leaves = Vec::with_capacity(needed_shards.len());
    for &shard_idx in &needed_shards {
        // `all_cmxs` begins at the pool's very first leaf — the leaf-count check
        // above proves `all_cmxs.len() == anchor_total_leaves` — so the scan base
        // offset is 0, and the frontier (partial) shard is `num_complete_shards`.
        let (lo, hi) = shard_leaf_bounds(
            shard_idx,
            num_complete_shards as u32,
            anchor_total_leaves,
            0,
            all_cmxs.len(),
        )?;
        shard_leaves.push(ShardLeaves {
            shard_index: shard_idx,
            cmxs: all_cmxs[lo..hi].to_vec(),
        });
    }

    // 6. Assemble and delegate to the pool-agnostic witness builder.
    let notes: Vec<(u64, [u8; 32])> = req.notes.iter().map(|n| (n.position, n.cmx)).collect();
    let inputs = WitnessInputs {
        cap_roots,
        frontier_bytes,
        anchor_height,
        shard_leaves,
        notes,
    };
    build_witnesses(&inputs).map_err(|e| anyhow!("build_witnesses (Ironwood local): {}", e))
}

/// Compute Merkle witnesses for every requested note against a single anchor.
///
/// # Errors
///
/// Returns an error if the notes list is empty, if the gRPC connection fails,
/// or if the pure witness assembly fails (e.g. anchor mismatch).
pub async fn compute_witnesses(req: WitnessRequest) -> Result<WitnessOutput> {
    compute_witnesses_for_pool(Pool::Orchard, req).await
}

/// Ironwood (NU6.3) sibling of [`compute_witnesses`]: computes Merkle witnesses
/// for notes in the Ironwood commitment tree, reusing the exact same ShardTree
/// assembly (`zcash_crypto::tree::build_witnesses` is pool-agnostic — spec
/// constraint "same cryptography as Orchard — reuse, do not reimplement").
///
/// Unlike the Orchard path, this function does **not** call `GetSubtreeRoots`
/// because the deployed Zaino server does not yet serve that RPC for the
/// Ironwood pool (it returns `INVALID_ARGUMENT: Invalid shielded protocol value`
/// for `ShieldedProtocol::Ironwood = 2`).  Instead, shard roots are derived
/// locally from the cmx leaves streamed via `GetBlockRange`, which is always
/// available.
///
/// See [`compute_ironwood_witnesses_from_blocks`] for the implementation.
///
/// # Errors
///
/// Returns an error if the notes list is empty, if the gRPC connection fails,
/// or if the pure witness assembly fails (e.g. anchor mismatch).
pub async fn compute_ironwood_witnesses(req: WitnessRequest) -> Result<WitnessOutput> {
    compute_ironwood_witnesses_from_blocks(req).await
}

/// Shared implementation behind [`compute_witnesses`] / [`compute_ironwood_witnesses`].
async fn compute_witnesses_for_pool(pool: Pool, req: WitnessRequest) -> Result<WitnessOutput> {
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
            anchor_height_from_tip(tip, req.anchor_depth_blocks)
        }
    };

    // 2. Fetch tree state at the anchor (frontier + boundary metadata).
    let tree_state = get_tree_state_at(&mut client, anchor_height).await?;
    let frontier_bytes = hex::decode(pool.tree_state_hex(&tree_state))
        .map_err(|e| anyhow!("TreeState frontier hex decode failed: {}", e))?;

    // Total commitments at the anchor — used to bound the frontier shard and to
    // trim per-shard fetches by absolute position.
    let anchor_total_leaves =
        frontier_leaf_count(&frontier_bytes).map_err(|e| anyhow!("frontier leaf count: {}", e))?;

    // 3. Fetch every completed shard root for this pool.
    let subtree_roots = get_subtree_roots(&mut client, pool, 0).await?;

    // 4. Determine which shards contain at least one requested note.
    let needed_shards: std::collections::BTreeSet<u32> = req
        .notes
        .iter()
        .map(|n| (n.position >> ORCHARD_SHARD_HEIGHT) as u32)
        .collect();

    // 5. For each needed shard, find its block-height range and fetch cmxs.
    let shard_leaves = fetch_shard_leaves(
        &mut client,
        pool,
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
    pool: Pool,
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
            // Pool activation is enforced server-side; clamp to 1.
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
        let base_offset = tree_size_at(client, pool, start_height.saturating_sub(1)).await?;
        let raw = collect_cmxs(client, pool, start_height, end_height).await?;

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

/// Number of commitments present at the end of block `height` for `pool`
/// (0 for height 0 / pre-activation), derived from `GetTreeState`'s frontier.
async fn tree_size_at(
    client: &mut CompactTxStreamerClient<Channel>,
    pool: Pool,
    height: u32,
) -> Result<u64> {
    if height == 0 {
        return Ok(0);
    }
    let ts = get_tree_state_at(client, height).await?;
    let bytes = hex::decode(pool.tree_state_hex(&ts))
        .map_err(|e| anyhow!("TreeState frontier hex decode at {}: {}", height, e))?;
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

async fn collect_cmxs(
    client: &mut CompactTxStreamerClient<Channel>,
    pool: Pool,
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
        pool_types: vec![],
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
        push_block_cmxs(&block, pool, &mut out)?;
    }
    Ok(out)
}

fn push_block_cmxs(block: &CompactBlock, pool: Pool, out: &mut Vec<[u8; 32]>) -> Result<()> {
    for tx in &block.vtx {
        let actions = match pool {
            Pool::Orchard => &tx.actions,
            Pool::Ironwood => &tx.ironwood_actions,
        };
        for action in actions {
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
        push_block_cmxs(&block, Pool::Orchard, &mut out).unwrap();

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
        let err = push_block_cmxs(&block, Pool::Orchard, &mut out).unwrap_err();
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
        assert_eq!(
            hi as u64,
            3 + SHARD_SIZE,
            "drop the trailing shard-2 spillover"
        );
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

    // ── fetch_orchard_anchor (Public→Private anchor-only) ─────────────────────

    /// `fetch_orchard_anchor` is the anchor-only entry point used by the
    /// Public→Private flow (transparent inputs + Orchard output, no spends).
    /// It must surface a clear connection error when the endpoint is unreachable
    /// rather than hang or panic.
    #[tokio::test]
    async fn fetch_orchard_anchor_fails_on_refused_port() {
        // Bind then immediately drop to get a port guaranteed to be closed.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };
        let err = fetch_orchard_anchor(&format!("https://127.0.0.1:{}", addr.port()), Some(1), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_orchard_anchor_fails_on_malformed_url() {
        let err = fetch_orchard_anchor("definitely not a url !!!", Some(1), None)
            .await
            .unwrap_err();
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

    // ── Pool::tree_state_hex — selects the correct TreeState field ──────────
    //
    // Guards the exact bug class the sync.rs fast-path regression also targets:
    // silently reading the wrong pool's data. `TreeState` carries both
    // `orchard_tree` and `ironwood_tree`; this proves `Pool::tree_state_hex`
    // never accidentally reads the other pool's frontier.

    #[test]
    fn pool_tree_state_hex_selects_orchard_field() {
        let ts = zcash_client_backend::proto::service::TreeState {
            orchard_tree: "orchard_frontier_hex".to_string(),
            ironwood_tree: "ironwood_frontier_hex".to_string(),
            ..Default::default()
        };
        assert_eq!(Pool::Orchard.tree_state_hex(&ts), "orchard_frontier_hex");
    }

    #[test]
    fn pool_tree_state_hex_selects_ironwood_field() {
        let ts = zcash_client_backend::proto::service::TreeState {
            orchard_tree: "orchard_frontier_hex".to_string(),
            ironwood_tree: "ironwood_frontier_hex".to_string(),
            ..Default::default()
        };
        assert_eq!(Pool::Ironwood.tree_state_hex(&ts), "ironwood_frontier_hex");
    }

    // ── push_block_cmxs — pool-scoped action selection ───────────────────────
    //
    // A valid ShardTree witness for an
    // Ironwood note requires its leaves to come from `ironwood_actions`, never
    // `actions` (Orchard) — the ShardTree assembly itself
    // (`zcash_crypto::tree::build_witnesses`) is already exhaustively tested
    // and is pool-agnostic; what Ironwood support adds is feeding it the right
    // leaves, which this test proves.

    #[test]
    fn push_block_cmxs_ironwood_pool_reads_ironwood_actions_only() {
        let block = CompactBlock {
            height: 200,
            vtx: vec![CompactTx {
                actions: vec![CompactOrchardAction {
                    cmx: vec![0xAAu8; 32], // Orchard leaf — must NOT be collected for Pool::Ironwood
                    ..Default::default()
                }],
                ironwood_actions: vec![CompactOrchardAction {
                    cmx: vec![0xBBu8; 32], // Ironwood leaf — must be collected
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut out = Vec::new();
        push_block_cmxs(&block, Pool::Ironwood, &mut out).unwrap();

        assert_eq!(out, vec![[0xBBu8; 32]], "must collect only the Ironwood action's cmx");
    }

    #[test]
    fn push_block_cmxs_orchard_pool_reads_orchard_actions_only() {
        let block = CompactBlock {
            height: 201,
            vtx: vec![CompactTx {
                actions: vec![CompactOrchardAction {
                    cmx: vec![0xAAu8; 32],
                    ..Default::default()
                }],
                ironwood_actions: vec![CompactOrchardAction {
                    cmx: vec![0xBBu8; 32],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut out = Vec::new();
        push_block_cmxs(&block, Pool::Orchard, &mut out).unwrap();

        assert_eq!(out, vec![[0xAAu8; 32]], "must collect only the Orchard action's cmx");
    }

    // ── compute_ironwood_witnesses / fetch_ironwood_anchor — connection paths ──
    //
    // Mirrors the existing Orchard connection-path tests: these public entry
    // points must surface a clear connection error rather than hang or panic.
    // (The pure ShardTree assembly they delegate to is already exhaustively
    // tested in `zcash_crypto::tree` — see that module's `known_good_test_vector`
    // and multi-shard tests — and is unconditionally reused, unmodified, here.)

    #[tokio::test]
    async fn compute_ironwood_witnesses_fails_on_malformed_url() {
        let req = WitnessRequest {
            grpc_url: "definitely not a url !!!".to_string(),
            anchor_height: Some(1),
            anchor_depth_blocks: None,
            notes: vec![NoteRef {
                position: 0,
                cmx: [0u8; 32],
            }],
        };
        let err = compute_ironwood_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_ironwood_anchor_fails_on_malformed_url() {
        let err = fetch_ironwood_anchor("definitely not a url !!!", Some(1), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid gRPC URL"),
            "unexpected error: {err}"
        );
    }

    // ── compute_ironwood_witnesses — block-based path (no GetSubtreeRoots) ────
    //
    // These tests exercise the new `compute_ironwood_witnesses_from_blocks` path
    // that replaced the server-dependent `compute_witnesses_for_pool(Pool::Ironwood)`.
    // They mirror the equivalent Orchard tests above.

    #[tokio::test]
    async fn compute_ironwood_witnesses_rejects_empty_notes() {
        // The empty-notes guard fires before any gRPC call.
        let req = WitnessRequest {
            grpc_url: "https://127.0.0.1:1".to_string(),
            anchor_height: Some(1),
            anchor_depth_blocks: None,
            notes: vec![],
        };
        let err = compute_ironwood_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("notes list is empty"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn compute_ironwood_witnesses_fails_on_refused_port() {
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
        let err = compute_ironwood_witnesses(req).await.unwrap_err();
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "unexpected error: {err}"
        );
    }

    // ── check_scan_width — the fail-fast bound on the local Ironwood scan ──────

    /// An activation height resolved down to genesis must be rejected before any
    /// block is fetched, rather than streaming most of the chain inline in a send.
    #[test]
    fn check_scan_width_rejects_full_chain_scan() {
        let err = check_scan_width(1, 4_193_460).unwrap_err();
        assert!(
            err.to_string().contains("implausible"),
            "unexpected error: {err}"
        );
    }

    /// A realistic NU6.3 testnet range (activation 4,134,000 → anchor 4,193,460,
    /// ~59k blocks) stays well inside the bound.
    #[test]
    fn check_scan_width_admits_realistic_ironwood_range() {
        assert!(check_scan_width(4_134_000, 4_193_460).is_ok());
    }

    /// The guard must not fire as the chain grows normally. Two years of blocks
    /// past activation at Zcash's 75-second spacing (~841k) must still pass —
    /// this bound is a malfunction guard, not a freshness policy.
    #[test]
    fn check_scan_width_admits_years_of_chain_growth() {
        let activation = 4_134_000u32;
        let two_years_of_blocks = 2 * 365 * 24 * 60 * 60 / 75;
        assert!(check_scan_width(activation, activation + two_years_of_blocks).is_ok());
    }

    /// Exactly at the bound is allowed; one block wider is not.
    #[test]
    fn check_scan_width_boundary_is_inclusive() {
        let anchor = 5_000_000u32;
        assert!(check_scan_width(anchor - MAX_IRONWOOD_SCAN_BLOCKS, anchor).is_ok());
        assert!(check_scan_width(anchor - MAX_IRONWOOD_SCAN_BLOCKS - 1, anchor).is_err());
    }

    // ── check_pool_size — the cost budget for the local strategy ───────────────

    /// The pool's present size (well under one completed shard) is admitted.
    #[test]
    fn check_pool_size_admits_current_ironwood_pool() {
        assert!(check_pool_size(9_800).is_ok());
    }

    /// Exactly at the budget is allowed; one leaf more is not.
    #[test]
    fn check_pool_size_boundary_is_inclusive() {
        assert!(check_pool_size(MAX_IRONWOOD_LOCAL_LEAVES).is_ok());
        assert!(check_pool_size(MAX_IRONWOOD_LOCAL_LEAVES + 1).is_err());
    }

    /// Exceeding the budget must point the reader at the server-side replacement
    /// rather than reading as a failure.
    #[test]
    fn check_pool_size_error_names_the_replacement() {
        let err = check_pool_size(MAX_IRONWOOD_LOCAL_LEAVES + 1).unwrap_err();
        assert!(
            err.to_string().contains("GetSubtreeRoots"),
            "unexpected error: {err}"
        );
    }

    // ── shard_leaf_bounds — the branch the live Ironwood path actually takes ───

    /// Ironwood today has no completed shard (~9.8k of the 65,536 leaves shard 0
    /// needs), so `num_complete_shards == 0`, shard 0 *is* the frontier shard, and
    /// the whole scan is its leaf set. This is the branch the deployed code runs.
    #[test]
    fn shard_leaf_bounds_frontier_shard_zero_takes_whole_scan() {
        let (lo, hi) = shard_leaf_bounds(0, 0, 9_800, 0, 9_800).expect("frontier shard 0");
        assert_eq!((lo, hi), (0, 9_800));
    }

    /// A note whose shard lies past the frontier shard is out of range, not an
    /// empty slice: `lo` (65,536) exceeds `hi` (9,800).
    #[test]
    fn shard_leaf_bounds_rejects_shard_past_anchor() {
        let err = shard_leaf_bounds(1, 0, 9_800, 0, 9_800).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "unexpected error: {err}"
        );
    }
}
