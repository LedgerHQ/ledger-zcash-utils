//! Capture harness for the Orchard known-good witness vector baked into
//! `zcash-crypto/src/tree.rs::known_good_test_vector`.
//!
//! Network-only (`#[ignore]`d). Regenerate the baked vector with:
//!   cargo test -p zcash-sync --test capture_witness_vector -- --ignored --nocapture emit

use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, GetSubtreeRootsArg,
    ShieldedProtocol,
};
use zcash_crypto::tree::{build_witnesses, ShardLeaves, WitnessInputs};

const TESTNET_GRPC_URL: &str = "https://zaino-zec-testnet.nodes.stg.ledger-test.com";
const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

async fn client() -> CompactTxStreamerClient<Channel> {
    let channel = zcash_sync::client::connect(TESTNET_GRPC_URL)
        .await
        .expect("gRPC connect failed");
    CompactTxStreamerClient::new(channel)
}

const SHARD_HEIGHT: u8 = 16;

/// Collect Orchard action cmxs from blocks `[start, end]` in tree order.
async fn collect_cmxs(
    c: &mut CompactTxStreamerClient<Channel>,
    start: u64,
    end: u64,
) -> Vec<[u8; 32]> {
    let range = BlockRange {
        start: Some(BlockId { height: start, hash: vec![] }),
        end: Some(BlockId { height: end, hash: vec![] }),
    };
    let mut stream = c.get_block_range(range).await.expect("block range").into_inner();
    let mut out = Vec::new();
    while let Some(block) = stream.message().await.expect("stream") {
        for tx in &block.vtx {
            for action in &tx.actions {
                out.push(<[u8; 32]>::try_from(action.cmx.as_slice()).expect("cmx 32 bytes"));
            }
        }
    }
    out
}

/// Capture a compact, real on-chain known-good vector and emit it as paste-ready
/// Rust literals for `zcash-crypto/src/tree.rs::known_good_test_vector`.
///
///   cargo test -p zcash-sync --test capture_witness_vector -- --ignored --nocapture emit
#[tokio::test]
#[ignore = "requires network access"]
async fn emit() {
    let mut c = client().await;

    // Completed Orchard shard roots (node-computed cap roots).
    let mut req = tonic::Request::new(GetSubtreeRootsArg {
        start_index: 0,
        shielded_protocol: ShieldedProtocol::Orchard as i32,
        max_entries: 0,
    });
    req.set_timeout(UNARY_TIMEOUT);
    let mut stream = c.get_subtree_roots(req).await.expect("roots").into_inner();
    let mut cap_roots: Vec<(u32, [u8; 32])> = Vec::new();
    let mut last_completing = 0u64;
    while let Some(r) = stream.message().await.expect("stream") {
        let idx = cap_roots.len() as u32;
        cap_roots.push((idx, <[u8; 32]>::try_from(r.root_hash.as_slice()).unwrap()));
        last_completing = r.completing_block_height;
    }
    assert!(!cap_roots.is_empty(), "need at least one completed shard");

    // Anchor height: a few blocks past the last shard boundary so the frontier
    // shard holds a small number of leaves (the boundary block itself often has
    // no Orchard actions, so we scan a short window for the first few).
    let anchor_height = (last_completing + 50) as u32;
    let frontier_shard_index = cap_roots.len() as u32;
    let base = u64::from(frontier_shard_index) << SHARD_HEIGHT;

    // Frontier at the anchor height.
    let mut req = tonic::Request::new(BlockId {
        height: u64::from(anchor_height),
        hash: vec![],
    });
    req.set_timeout(UNARY_TIMEOUT);
    let ts = c.get_tree_state(req).await.expect("tree state").into_inner();
    let frontier_bytes = hex::decode(&ts.orchard_tree).expect("hex");

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
        u64::from(f.value().expect("non-empty frontier").position()) + 1
    };
    let shard_leaf_count = (total_leaves - base) as usize;
    eprintln!("total_leaves={total_leaves}, frontier-shard leaf count={shard_leaf_count} (base {base})");

    // Collect cmxs from the boundary block (inclusive) through the anchor, then
    // keep only the trailing `shard_leaf_count` — those are shard `frontier_shard_index`.
    let all = collect_cmxs(&mut c, last_completing, u64::from(anchor_height)).await;
    assert!(all.len() >= shard_leaf_count, "fetched fewer cmxs than expected");
    let cmxs: Vec<[u8; 32]> = all[all.len() - shard_leaf_count..].to_vec();

    // Witness the first leaf of the frontier shard.
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
    let out = build_witnesses(&inputs).expect("build_witnesses failed on real data");
    let path = &out.witnesses[0];

    // ── Emit paste-ready literals ────────────────────────────────────────────
    eprintln!("\n==================== BAKE THE FOLLOWING ====================");
    eprintln!("anchor_height = {anchor_height}");
    eprintln!("frontier_shard_index = {frontier_shard_index}");
    eprintln!("note_position = {note_pos}");
    eprintln!("note_cmx = \"{}\"", hex::encode(note_cmx));
    eprintln!("anchor = \"{}\"", hex::encode(out.anchor));
    eprintln!("cap_roots ({}):", cap_roots.len());
    for (i, r) in &cap_roots {
        eprintln!("  ({i}, \"{}\"),", hex::encode(r));
    }
    eprintln!("frontier_bytes_hex = \"{}\"", hex::encode(&frontier_bytes));
    eprintln!("cmxs ({}):", cmxs.len());
    for cmx in &cmxs {
        eprintln!("  \"{}\",", hex::encode(cmx));
    }
    eprintln!("path.position = {}", u64::from(path.position()));
    eprintln!("path.path_elems ({}):", path.path_elems().len());
    for e in path.path_elems() {
        eprintln!("  \"{}\",", hex::encode(e.to_bytes()));
    }
    eprintln!("============================================================\n");
}

/// End-to-end check of the witness orchestrator against the known vector. This
/// exercises `compute_witnesses` → `fetch_shard_leaves`, which must correctly
/// handle the shard-1 boundary falling mid-block (the note lives at the first
/// position of the partial frontier shard).
///
///   cargo test -p zcash-sync --test capture_witness_vector -- --ignored --nocapture compute_witnesses_matches_known_vector
#[tokio::test]
#[ignore = "requires network access"]
async fn compute_witnesses_matches_known_vector() {
    use zcash_sync::witness::{compute_witnesses, NoteRef, WitnessRequest};

    let note_cmx: [u8; 32] =
        hex::decode("c53c1944c1add04a071359f9c077aa8991f5431736b1f958270718bc1250c531")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_anchor: [u8; 32] =
        hex::decode("a104cba07fd164a2f4432eac02ce9d4ea76749d63adc02050c7004ccb5c36014")
            .unwrap()
            .try_into()
            .unwrap();

    let out = compute_witnesses(WitnessRequest {
        grpc_url: TESTNET_GRPC_URL.to_string(),
        anchor_height: Some(3_861_070),
        anchor_depth_blocks: None,
        notes: vec![NoteRef {
            position: 131_072,
            cmx: note_cmx,
        }],
    })
    .await
    .expect("compute_witnesses failed");

    assert_eq!(out.anchor, expected_anchor, "orchestrator anchor mismatch");
    assert_eq!(out.witnesses.len(), 1);
    assert_eq!(u64::from(out.witnesses[0].position()), 131_072);
}
