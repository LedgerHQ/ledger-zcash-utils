//! Capture harness for the real Ironwood (NU6.3) witness vector baked into
//! `zcash-crypto/tests/ironwood_known_vector.rs` (mirroring the relationship
//! between `capture_witness_vector.rs` and
//! `zcash-crypto/src/tree.rs::known_good_test_vector`, Orchard).
//!
//! Sibling of `capture_witness_vector.rs`, adapted for the Ironwood pool:
//! `ShieldedProtocol::Ironwood` instead of `::Orchard`, `TreeState::ironwood_tree`
//! instead of `::orchard_tree`, and `CompactTx::ironwood_actions` instead of
//! `::actions`. `build_witnesses` itself is unchanged — both pools share the
//! exact same commitment-tree cryptography (see `zcash_sync::witness::Pool`).
//!
//! ## Completed-shard vs. partial-shard capture
//!
//! `capture_witness_vector.rs`'s Orchard `emit()` requires at least one
//! *completed* shard, so it only needs to fetch the (small) frontier shard's
//! leaves from the shard boundary onward. As of this writing, the Ironwood
//! pool has **not yet completed a single shard** on testnet (only ~9.8k of
//! the 65,536 leaves shard 0 needs) — so `emit()` here instead scans from the
//! NU6.3 testnet activation height (the earliest a real Ironwood commitment
//! could exist) through the anchor height, collecting the *entire* partial
//! shard 0. This was confirmed tractable (~2s over ~59k blocks against
//! zec.rocks). Once a shard completes, this harness's `emit()` should be
//! updated to mirror the Orchard boundary-relative scan for efficiency.
//!
//! Network-only (`#[ignore]`d). Regenerate the baked vector with:
//!   cargo test -p zcash-sync --test capture_ironwood_witness_vector -- --ignored --nocapture emit
//!
//! Defaults to the public zec.rocks testnet Zaino node (rather than the Ledger
//! staging Zaino node used by `capture_witness_vector.rs`), since NU6.3/Ironwood
//! testnet activation may reach a public indexer before it reaches Ledger's own
//! staging deployment. Overridable via `ZCASH_TESTNET_GRPC_URL` (same variable
//! `integration_sync.rs` uses). This will migrate to
//! `zec-indexer.coin.ledger-test.com` once Ledger's own Zaino testnet node is
//! NU6.3-aware.

use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, GetSubtreeRootsArg,
    ShieldedProtocol,
};
use zcash_crypto::tree::{build_witnesses, ShardLeaves, WitnessInputs};

const TESTNET_GRPC_URL_DEFAULT: &str = "https://testnet.zec.rocks:443";
const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

/// Earliest height a real Ironwood commitment could exist on testnet
/// (`BranchId::for_height` resolves `Nu6_3` from this height on — verified
/// against `zcash_protocol::consensus`). Used as the scan floor when no
/// Ironwood shard has completed yet (see the module docs).
const NU6_3_TESTNET_ACTIVATION: u64 = 4_134_000;

/// Resolves the testnet gRPC endpoint, overridable via `ZCASH_TESTNET_GRPC_URL`
/// (the same variable `integration_sync.rs` uses).
fn testnet_grpc_url() -> String {
    std::env::var("ZCASH_TESTNET_GRPC_URL").unwrap_or_else(|_| TESTNET_GRPC_URL_DEFAULT.to_string())
}

async fn client() -> CompactTxStreamerClient<Channel> {
    let channel = zcash_sync::client::connect(&testnet_grpc_url())
        .await
        .expect("gRPC connect failed");
    CompactTxStreamerClient::new(channel)
}

const SHARD_HEIGHT: u8 = 16;

/// Collect Ironwood action cmxs from blocks `[start, end]` in tree order.
async fn collect_ironwood_cmxs(
    c: &mut CompactTxStreamerClient<Channel>,
    start: u64,
    end: u64,
) -> Vec<[u8; 32]> {
    let range = BlockRange {
        start: Some(BlockId { height: start, hash: vec![] }),
        end: Some(BlockId { height: end, hash: vec![] }),
        pool_types: vec![],
    };
    let mut req = tonic::Request::new(range);
    req.set_timeout(Duration::from_secs(120));
    let mut stream = c
        .get_block_range(req.into_inner())
        .await
        .expect("block range")
        .into_inner();
    let mut out = Vec::new();
    while let Some(block) = stream.message().await.expect("stream") {
        for tx in &block.vtx {
            for action in &tx.ironwood_actions {
                out.push(<[u8; 32]>::try_from(action.cmx.as_slice()).expect("cmx 32 bytes"));
            }
        }
    }
    out
}

/// Capture a real on-chain Ironwood witness vector and emit it as paste-ready
/// Rust literals / a fixture-file blob for `ironwood_known_vector.rs`.
///
/// Anti-hallucination note: this harness is the *only* legitimate source for
/// the anchor/witness/cmx values an offline Ironwood test bakes in. If this
/// test cannot obtain real data (connection failure, or the Ironwood pool
/// genuinely has zero leaves at the target endpoint), no vector must be
/// fabricated — re-run this harness against a NU6.3-aware endpoint instead.
///
///   cargo test -p zcash-sync --test capture_ironwood_witness_vector -- --ignored --nocapture emit
#[tokio::test]
#[ignore = "requires network access"]
async fn emit() {
    let mut c = client().await;

    // Completed Ironwood shard roots (node-computed cap roots), if any.
    let mut req = tonic::Request::new(GetSubtreeRootsArg {
        start_index: 0,
        shielded_protocol: ShieldedProtocol::Ironwood as i32,
        max_entries: 0,
    });
    req.set_timeout(UNARY_TIMEOUT);
    let mut stream = c
        .get_subtree_roots(req)
        .await
        .expect("roots")
        .into_inner();
    let mut cap_roots: Vec<(u32, [u8; 32])> = Vec::new();
    let mut last_completing = 0u64;
    while let Some(r) = stream.message().await.expect("stream") {
        let idx = cap_roots.len() as u32;
        cap_roots.push((idx, <[u8; 32]>::try_from(r.root_hash.as_slice()).unwrap()));
        last_completing = r.completing_block_height;
    }

    // Anchor height and scan floor differ depending on whether any Ironwood
    // shard has completed yet.
    let (anchor_height, frontier_shard_index, scan_floor) = if cap_roots.is_empty() {
        eprintln!(
            "no completed Ironwood shard at {} — capturing the partial shard 0 from the NU6.3 \
             testnet activation height ({NU6_3_TESTNET_ACTIVATION}) instead",
            testnet_grpc_url()
        );
        let tip_req = tonic::Request::new(zcash_client_backend::proto::service::ChainSpec {});
        let tip = c
            .get_latest_block(tip_req)
            .await
            .expect("get_latest_block")
            .into_inner()
            .height as u32;
        (tip, 0u32, NU6_3_TESTNET_ACTIVATION)
    } else {
        // Mirrors the Orchard capture: a few blocks past the last shard
        // boundary so the frontier shard holds a small number of leaves.
        let anchor_height = (last_completing + 50) as u32;
        let frontier_shard_index = cap_roots.len() as u32;
        (anchor_height, frontier_shard_index, last_completing)
    };
    let base = u64::from(frontier_shard_index) << SHARD_HEIGHT;

    // Frontier at the anchor height.
    let mut req = tonic::Request::new(BlockId {
        height: u64::from(anchor_height),
        hash: vec![],
    });
    req.set_timeout(UNARY_TIMEOUT);
    let ts = c.get_tree_state(req).await.expect("tree state").into_inner();
    let frontier_bytes = hex::decode(&ts.ironwood_tree).expect("hex");

    // Total leaves at the anchor = frontier position + 1. The shard boundary can
    // fall mid-block, so the frontier-shard leaves are the trailing
    // (total - base) commitments — we must align to absolute positions.
    let total_leaves = {
        use incrementalmerkletree::frontier::CommitmentTree;
        use orchard::tree::MerkleHashOrchard;
        use zcash_primitives::merkle_tree::read_commitment_tree;
        let ct: CommitmentTree<MerkleHashOrchard, 32> =
            read_commitment_tree(std::io::Cursor::new(&frontier_bytes)).expect("decode frontier");
        let f = ct.to_frontier();
        u64::from(f.value().expect("non-empty Ironwood frontier — pool has zero leaves at this \
            endpoint; do NOT fabricate a vector, re-run once real Ironwood data exists").position()) + 1
    };
    let shard_leaf_count = (total_leaves - base) as usize;
    eprintln!(
        "total_leaves={total_leaves}, shard leaf count={shard_leaf_count} (base {base}, scan floor {scan_floor})"
    );

    // Collect cmxs from the scan floor (inclusive) through the anchor, then
    // keep only the trailing `shard_leaf_count` — those are shard `frontier_shard_index`.
    let all = collect_ironwood_cmxs(&mut c, scan_floor, u64::from(anchor_height)).await;
    assert!(
        all.len() >= shard_leaf_count,
        "fetched fewer Ironwood cmxs than expected"
    );
    let cmxs: Vec<[u8; 32]> = all[all.len() - shard_leaf_count..].to_vec();

    // Witness the first leaf of the (frontier or completed) shard.
    let note_pos = base;
    let note_cmx = cmxs[0];

    let inputs = WitnessInputs {
        cap_roots: cap_roots.clone(),
        frontier_bytes: frontier_bytes.clone(),
        anchor_height,
        shard_leaves: vec![ShardLeaves {
            shard_index: frontier_shard_index,
            cmxs: cmxs.clone(),
        }],
        notes: vec![(note_pos, note_cmx)],
    };
    let out = build_witnesses(&inputs).expect("build_witnesses failed on real Ironwood data");
    let path = &out.witnesses[0];

    // ── Emit paste-ready literals + the fixture-file blob ────────────────────
    eprintln!("\n==================== BAKE THE FOLLOWING (IRONWOOD) ====================");
    eprintln!("anchor_height = {anchor_height}");
    eprintln!("frontier_shard_index = {frontier_shard_index}");
    eprintln!("note_position = {note_pos}");
    eprintln!("note_cmx = \"{}\"", hex::encode(note_cmx));
    eprintln!("anchor = \"{}\"", hex::encode(out.anchor));
    eprintln!("cap_roots ({}): {:?}", cap_roots.len(), cap_roots);
    eprintln!("frontier_bytes_hex = \"{}\"", hex::encode(&frontier_bytes));
    eprintln!("path.position = {}", u64::from(path.position()));
    eprintln!("path.path_elems ({}):", path.path_elems().len());
    for e in path.path_elems() {
        eprintln!("  \"{}\",", hex::encode(e.to_bytes()));
    }
    eprintln!(
        "cmxs: {} leaves fetched (not printed — too large to bake; only `anchor_height`, \
         `note_position`, `note_cmx`, `anchor`, and `path.path_elems` above are baked into \
         zcash-crypto/tests/ironwood_known_vector.rs; the full leaf set is re-fetched live by \
         `verify_frozen_vector_is_reproducible_from_live_data` below, not stored).",
        cmxs.len()
    );
    eprintln!("=========================================================================\n");
}

/// Re-fetches the real Ironwood leaves at the exact height the anchor baked
/// into `zcash-crypto/tests/ironwood_known_vector.rs` was captured at, and
/// re-derives that anchor (and its witness path) from live data with
/// `build_witnesses`. This is what actually *proves* the frozen anchor is
/// real and recomputable — `ironwood_known_vector.rs` only consumes the
/// anchor (in a Public→Ironwood, dummy-spends-only build) and does not
/// re-verify it against its own leaves, which would be tautological without
/// the full ~9.8k-leaf input this test fetches live instead of baking.
///
/// Uses the same bounded, NU6.3-activation-relative scan as `emit` above
/// (not the generic `compute_ironwood_witnesses` orchestrator, which has no
/// activation-height shortcut and did not return within 2 minutes when tried
/// against this same partial-shard-0 data — a real, discovered limitation of
/// the generic orchestrator for a pool with zero completed shards, tracked as
/// a follow-up rather than worked around here).
///
///   cargo test -p zcash-sync --test capture_ironwood_witness_vector -- --ignored --nocapture verify_frozen_vector_is_reproducible_from_live_data
#[tokio::test]
#[ignore = "requires network access"]
async fn verify_frozen_vector_is_reproducible_from_live_data() {
    const FROZEN_ANCHOR_HEIGHT: u64 = 4_193_460;
    const FROZEN_ANCHOR: &str =
        "727af33dfc1d36e2914771b31ac7de08dc7e546cd10a18ec29a73d5119f2b022";
    const FROZEN_NOTE_CMX: &str =
        "d96886a60491bf3a63eb3ce28f46f6ee70ceaa8dcab4eff13844417851062933";

    let mut c = client().await;

    let mut req = tonic::Request::new(BlockId {
        height: FROZEN_ANCHOR_HEIGHT,
        hash: vec![],
    });
    req.set_timeout(UNARY_TIMEOUT);
    let ts = c.get_tree_state(req).await.expect("tree state").into_inner();
    let frontier_bytes = hex::decode(&ts.ironwood_tree).expect("hex");

    let cmxs = collect_ironwood_cmxs(&mut c, NU6_3_TESTNET_ACTIVATION, FROZEN_ANCHOR_HEIGHT).await;
    let note_cmx: [u8; 32] = hex::decode(FROZEN_NOTE_CMX).unwrap().try_into().unwrap();
    assert_eq!(
        cmxs.first(),
        Some(&note_cmx),
        "the first live-fetched leaf must match the frozen note_cmx"
    );

    let out = build_witnesses(&WitnessInputs {
        cap_roots: vec![],
        frontier_bytes,
        anchor_height: FROZEN_ANCHOR_HEIGHT as u32,
        shard_leaves: vec![ShardLeaves { shard_index: 0, cmxs }],
        notes: vec![(0, note_cmx)],
    })
    .expect("build_witnesses failed on live Ironwood data");

    let expected_anchor: [u8; 32] = hex::decode(FROZEN_ANCHOR).unwrap().try_into().unwrap();
    assert_eq!(
        out.anchor, expected_anchor,
        "the frozen anchor baked into ironwood_known_vector.rs must be reproducible from live data"
    );
    assert_eq!(out.witnesses.len(), 1);
}
