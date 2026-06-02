//! On-demand Orchard ShardTree assembly and Merkle-witness extraction.
//!
//! Witnesses are computed only when the caller needs to spend specific notes.
//! No tree state is persisted between calls: the caller supplies the cap roots
//! (from `GetSubtreeRoots`), the frontier (from `GetTreeState`), and the
//! per-shard cmx leaves (extracted from `GetBlockRange`) for shards that
//! contain spend notes. Empty/complete shards outside that set stay
//! represented by their 32-byte root hash only.

use std::io::Cursor;

use incrementalmerkletree::{Level, Marking, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::{store::memory::MemoryShardStore, ShardTree};

use crate::error::Error;

/// Orchard commitment tree depth.
pub const ORCHARD_DEPTH: u8 = 32;
/// Orchard shard height (DEPTH / 2). Each completed shard covers 2^16 leaves.
pub const ORCHARD_SHARD_HEIGHT: u8 = 16;

/// In-memory ordered cmx leaves for a single shard.
pub struct ShardLeaves {
    /// Shard index = position >> ORCHARD_SHARD_HEIGHT.
    pub shard_index: u32,
    /// cmx (32-byte Pallas base field) for every action in tree order.
    pub cmxs: Vec<[u8; 32]>,
}

/// Pre-fetched inputs to [`build_witnesses`]. Owned values (no lifetimes) so
/// the structure crosses await points in the orchestrator without ceremony.
pub struct WitnessInputs {
    /// Completed shard roots: (shard_index, root_hash[32]). Sorted by index.
    pub cap_roots: Vec<(u32, [u8; 32])>,
    /// Hex-decoded `TreeState.orchard_tree` bytes from the anchor block.
    /// Empty when the anchor sits at Orchard genesis (no commitments yet).
    pub frontier_bytes: Vec<u8>,
    /// Block height that the frontier corresponds to. Used as the checkpoint id.
    pub anchor_height: u32,
    /// Per-shard cmx leaves for shards that contain at least one note to spend.
    pub shard_leaves: Vec<ShardLeaves>,
    /// Notes to witness: (position, cmx). Order is preserved in the output.
    pub notes: Vec<(u64, [u8; 32])>,
}

/// Output of [`build_witnesses`].
#[derive(Debug)]
pub struct WitnessOutput {
    /// Anchor (tree root) as the 32-byte little-endian Pallas encoding.
    pub anchor: [u8; 32],
    /// One `MerklePath` per input note, in the same order as `inputs.notes`.
    pub witnesses: Vec<incrementalmerkletree::MerklePath<MerkleHashOrchard, ORCHARD_DEPTH>>,
}

/// Build all witnesses against the supplied anchor.
///
/// Validates each witness internally: `MerklePath::root(cmx) == anchor`. If any
/// note fails validation the function returns [`Error::WitnessMismatch`].
pub fn build_witnesses(inputs: &WitnessInputs) -> Result<WitnessOutput, Error> {
    // 1. Initialise a memory-backed ShardTree.  Checkpoint id type = u32 (block height).
    let store = MemoryShardStore::<MerkleHashOrchard, u32>::empty();
    let mut tree = ShardTree::<_, ORCHARD_DEPTH, ORCHARD_SHARD_HEIGHT>::new(
        store, /* max_checkpoints */ 1,
    );

    // 2. Insert completed shard roots using `ShardTree::insert`, which accepts a
    //    single hash value at a given Address without requiring a full subtree.
    for (shard_index, root_hash) in &inputs.cap_roots {
        let addr = incrementalmerkletree::Address::from_parts(
            Level::from(ORCHARD_SHARD_HEIGHT),
            u64::from(*shard_index),
        );
        let hash = MerkleHashOrchard::from_bytes(root_hash)
            .into_option()
            .ok_or(Error::InvalidShardRoot {
                shard_index: *shard_index,
            })?;
        tree.insert(addr, hash).map_err(Error::shardtree)?;
    }

    // 3. Insert the frontier (partial rightmost shard at anchor_height).
    let frontier = decode_orchard_frontier(&inputs.frontier_bytes)?;
    tree.insert_frontier(
        frontier,
        Retention::Checkpoint {
            id: inputs.anchor_height,
            marking: Marking::Reference,
        },
    )
    .map_err(Error::shardtree)?;

    // 4. For every shard that contains a note to spend, batch-insert its leaves
    //    so the path through that shard becomes resolvable. Mark leaves we want
    //    witnesses for so the tree retains them.
    //
    //    Overlap note: a *completed* shard can appear both here and in step 2's
    //    `cap_roots` (the common case of a note in an old, since-filled shard).
    //    This is safe and intentional. `insert` (step 2) writes the summary hash
    //    to two stores: the cap and the shard store. `batch_insert` below only
    //    touches the shard store, replacing that shard's summary leaf with the
    //    full subtree (ShardTree trusts the richer data and replaces without
    //    raising a conflict). The cap keeps the summary. Anchor computation for a
    //    completed shard uses the cap summary; the witness path through the shard
    //    uses the batch-inserted leaves. Step 6 enforces `path.root(cmx) == anchor`,
    //    so any divergence between the fetched leaves and the on-chain summary
    //    surfaces as `Error::WitnessMismatch` rather than a silently wrong witness.
    let marked_positions: std::collections::HashSet<u64> =
        inputs.notes.iter().map(|(p, _)| *p).collect();
    for shard in &inputs.shard_leaves {
        let base = u64::from(shard.shard_index) << ORCHARD_SHARD_HEIGHT;
        let leaves: Vec<(MerkleHashOrchard, Retention<u32>)> = shard
            .cmxs
            .iter()
            .enumerate()
            .map(|(i, cmx)| {
                let pos = base + i as u64;
                let retention = if marked_positions.contains(&pos) {
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };
                MerkleHashOrchard::from_bytes(cmx)
                    .into_option()
                    .map(|h| (h, retention))
                    .ok_or(Error::InvalidLeaf { position: pos })
            })
            .collect::<Result<_, _>>()?;

        tree.batch_insert(Position::from(base), leaves.into_iter())
            .map_err(Error::shardtree)?;
    }

    // 5. Anchor = root at the recorded checkpoint (depth 0 = most recent).
    //    `root_at_checkpoint_depth` returns `Option<H>` — `None` means the tree
    //    has no checkpoints at all, which should not happen after insert_frontier.
    let anchor_hash = tree
        .root_at_checkpoint_depth(Some(0))
        .map_err(Error::shardtree)?
        .ok_or(Error::NoCheckpointForAnchor {
            anchor_height: inputs.anchor_height,
        })?;
    let anchor: [u8; 32] = anchor_hash.to_bytes();

    // 6. Compute one MerklePath per requested note and validate root(cmx)==anchor.
    let mut witnesses = Vec::with_capacity(inputs.notes.len());
    for (position, cmx) in &inputs.notes {
        let path = tree
            .witness_at_checkpoint_depth(Position::from(*position), 0)
            .map_err(Error::shardtree)?
            .ok_or(Error::NoCheckpointForAnchor {
                anchor_height: inputs.anchor_height,
            })?;

        let cmx_hash =
            MerkleHashOrchard::from_bytes(cmx)
                .into_option()
                .ok_or(Error::InvalidLeaf {
                    position: *position,
                })?;
        let computed = path.root(cmx_hash);
        if computed.to_bytes() != anchor {
            return Err(Error::WitnessMismatch {
                position: *position,
                expected: anchor,
                got: computed.to_bytes(),
            });
        }
        witnesses.push(path);
    }

    Ok(WitnessOutput { anchor, witnesses })
}

/// Decode hex-decoded `TreeState.orchard_tree` bytes into an incremental Frontier.
///
/// The wire format is the legacy zcashd `CommitmentTree` encoding. An empty
/// byte slice represents the genesis state (no Orchard commitments yet) and
/// produces `Frontier::empty()`.
fn decode_orchard_frontier(
    bytes: &[u8],
) -> Result<incrementalmerkletree::frontier::Frontier<MerkleHashOrchard, ORCHARD_DEPTH>, Error> {
    if bytes.is_empty() {
        return Ok(incrementalmerkletree::frontier::Frontier::empty());
    }
    // `read_commitment_tree` parses the legacy zcashd CommitmentTree binary format.
    // `to_frontier()` converts it to the incremental Frontier type; the conversion
    // is infallible for a non-empty tree (returns the direct frontier representation).
    let legacy: incrementalmerkletree::frontier::CommitmentTree<MerkleHashOrchard, ORCHARD_DEPTH> =
        zcash_primitives::merkle_tree::read_commitment_tree(Cursor::new(bytes))
            .map_err(Error::frontier_decode)?;
    Ok(legacy.to_frontier())
}

/// Number of commitments represented by an encoded `TreeState.orchard_tree`
/// frontier. Returns 0 for the empty (genesis) frontier.
///
/// The witness orchestrator uses this to map block-height ranges to absolute
/// leaf positions: an Orchard shard boundary can fall in the middle of a block,
/// so per-shard `GetBlockRange` results must be trimmed by absolute position
/// rather than assumed to start exactly on a shard boundary.
pub fn frontier_leaf_count(bytes: &[u8]) -> Result<u64, Error> {
    let frontier = decode_orchard_frontier(bytes)?;
    Ok(frontier.value().map_or(0, |nf| u64::from(nf.position()) + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable;

    // ── 1. Empty inputs — no notes, empty frontier ───────────────────────────

    #[test]
    fn empty_inputs_returns_empty_witnesses() {
        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes: vec![],
            anchor_height: 0,
            shard_leaves: vec![],
            notes: vec![],
        };
        // With no notes and an empty tree, the checkpoint on Frontier::empty()
        // records tree_empty, so root_at_checkpoint_depth returns the empty root.
        let result = build_witnesses(&inputs);
        // No notes → witnesses vec is empty; anchor is the empty-tree root.
        match result {
            Ok(out) => {
                assert!(out.witnesses.is_empty());
                // anchor should be the Orchard empty-tree root
                let expected_empty =
                    <MerkleHashOrchard as incrementalmerkletree::Hashable>::empty_root(
                        Level::from(ORCHARD_DEPTH),
                    );
                assert_eq!(out.anchor, expected_empty.to_bytes());
            }
            // Acceptable: with anchor_height=0 and no frontier, there is no
            // checkpoint — the function may return NoCheckpointForAnchor.
            Err(Error::NoCheckpointForAnchor { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // ── 8. Genesis anchor (empty frontier, no notes) ─────────────────────────

    #[test]
    fn genesis_anchor_empty_frontier_no_notes_ok() {
        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes: vec![],
            anchor_height: 1,
            shard_leaves: vec![],
            notes: vec![],
        };
        // insert_frontier on Frontier::empty() with Checkpoint creates a tree_empty checkpoint.
        let result = build_witnesses(&inputs);
        match result {
            Ok(out) => assert!(out.witnesses.is_empty()),
            Err(e) => panic!("unexpected error for genesis anchor: {e}"),
        }
    }

    // ── 5. Invalid cmx bytes (off-curve) → Error::InvalidLeaf ────────────────

    #[test]
    fn invalid_cmx_bytes_yields_invalid_leaf() {
        // All-0xff bytes are not a valid Pallas base-field element.
        let bad_cmx = [0xffu8; 32];
        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes: vec![],
            anchor_height: 1,
            shard_leaves: vec![ShardLeaves {
                shard_index: 0,
                cmxs: vec![bad_cmx],
            }],
            notes: vec![(0, bad_cmx)],
        };
        let err = build_witnesses(&inputs).unwrap_err();
        assert!(
            matches!(err, Error::InvalidLeaf { position: 0 }),
            "expected InvalidLeaf, got: {err}"
        );
    }

    // ── Invalid cmx in cap_roots → Error::InvalidShardRoot ───────────────────

    #[test]
    fn invalid_cap_root_yields_invalid_shard_root() {
        let bad_root = [0xffu8; 32];
        let inputs = WitnessInputs {
            cap_roots: vec![(0, bad_root)],
            frontier_bytes: vec![],
            anchor_height: 1,
            shard_leaves: vec![],
            notes: vec![],
        };
        let err = build_witnesses(&inputs).unwrap_err();
        assert!(
            matches!(err, Error::InvalidShardRoot { shard_index: 0 }),
            "expected InvalidShardRoot, got: {err}"
        );
    }

    // ── 9. Frontier bytes that fail to decode → Error::FrontierDecode ─────────

    #[test]
    fn invalid_frontier_bytes_yields_frontier_decode() {
        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes: vec![0xde, 0xad, 0xbe, 0xef],
            anchor_height: 1,
            shard_leaves: vec![],
            notes: vec![],
        };
        let err = build_witnesses(&inputs).unwrap_err();
        assert!(
            matches!(err, Error::FrontierDecode(_)),
            "expected FrontierDecode, got: {err}"
        );
    }

    // ── 7. Unsorted cap_roots input is tolerated ──────────────────────────────

    #[test]
    fn unsorted_cap_roots_succeeds() {
        // Two completed shards with valid roots inserted in reverse order.
        let root0 = MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT)).to_bytes();
        let root1 = MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT)).to_bytes();
        let inputs = WitnessInputs {
            cap_roots: vec![(1, root1), (0, root0)], // intentionally reversed
            frontier_bytes: vec![],
            anchor_height: 1,
            shard_leaves: vec![],
            notes: vec![],
        };
        // With valid roots and an empty-frontier checkpoint, this should not error.
        let result = build_witnesses(&inputs);
        match result {
            Ok(_) => {}
            Err(e) => panic!("unexpected error with unsorted cap_roots: {e}"),
        }
    }

    // ── Helpers for serializing a frontier as zcashd CommitmentTree bytes ────────

    /// Build a `CommitmentTree<MerkleHashOrchard, 32>` from `n` empty leaves and
    /// serialize it to the zcashd wire format. Returns the serialized bytes and the
    /// corresponding Frontier (for computing the expected anchor).
    fn build_frontier_bytes(
        n: usize,
    ) -> (
        Vec<u8>,
        incrementalmerkletree::frontier::Frontier<MerkleHashOrchard, ORCHARD_DEPTH>,
    ) {
        use incrementalmerkletree::frontier::CommitmentTree;
        use zcash_primitives::merkle_tree::write_commitment_tree;

        let mut ct = CommitmentTree::<MerkleHashOrchard, ORCHARD_DEPTH>::empty();
        for _ in 0..n {
            ct.append(MerkleHashOrchard::empty_leaf()).unwrap();
        }
        let mut buf = Vec::new();
        write_commitment_tree(&ct, &mut buf).unwrap();
        let frontier = ct.to_frontier();
        (buf, frontier)
    }

    // ── 2. Single note inside the frontier shard → path validates ─────────────
    //
    // Strategy: encode `n+1` leaves as a CommitmentTree frontier (the +1 is the
    // checkpoint leaf), supply the first `n` leaves as shard data, and ask
    // build_witnesses to produce a witness for position `mark_pos`.

    #[test]
    fn single_note_in_frontier_shard_validates() {
        let n = 4usize;
        let mark_pos = 1u64;
        let leaf_val = MerkleHashOrchard::empty_leaf().to_bytes();

        // Frontier encodes n+1 leaves (the checkpoint leaf is the last one).
        let (frontier_bytes, frontier) = build_frontier_bytes(n + 1);

        // Build a reference ShardTree using insert_frontier + batch_insert to
        // compute the expected anchor.
        let expected_anchor = {
            use incrementalmerkletree::Retention;
            use shardtree::{store::memory::MemoryShardStore, ShardTree};

            let mut tree = ShardTree::<
                MemoryShardStore<MerkleHashOrchard, u32>,
                ORCHARD_DEPTH,
                ORCHARD_SHARD_HEIGHT,
            >::new(MemoryShardStore::empty(), 2);
            // Insert frontier first (creates checkpoint at pos n, i.e. 4).
            tree.insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: 1u32,
                    marking: Marking::Reference,
                },
            )
            .unwrap();
            // Then batch-insert the shard leaves (positions 0..n) with the marked one.
            let leaves: Vec<(MerkleHashOrchard, Retention<u32>)> = (0..n)
                .map(|i| {
                    let ret = if i as u64 == mark_pos {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    (MerkleHashOrchard::empty_leaf(), ret)
                })
                .collect();
            tree.batch_insert(Position::from(0u64), leaves.into_iter())
                .unwrap();
            tree.root_at_checkpoint_depth(Some(0))
                .unwrap()
                .unwrap()
                .to_bytes()
        };

        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes,
            anchor_height: 1,
            shard_leaves: vec![ShardLeaves {
                shard_index: 0,
                cmxs: vec![leaf_val; n],
            }],
            notes: vec![(mark_pos, leaf_val)],
        };
        let out = build_witnesses(&inputs).expect("build_witnesses failed");
        assert_eq!(out.anchor, expected_anchor);
        assert_eq!(out.witnesses.len(), 1);
    }

    // ── 6. Anchor mismatch (corrupted leaf) → Error::WitnessMismatch ──────────
    //
    // Supply a valid 2-leaf frontier, shard leaves of two empty leaves, but
    // claim in `notes` that position 0 has a *different* cmx than was inserted.

    #[test]
    fn anchor_mismatch_yields_witness_mismatch() {
        let leaf_val = MerkleHashOrchard::empty_leaf().to_bytes();
        // A valid cmx different from empty_leaf (use level-1 empty root).
        let wrong_cmx = MerkleHashOrchard::empty_root(Level::from(1)).to_bytes();
        assert_ne!(
            leaf_val, wrong_cmx,
            "wrong_cmx must differ from the actual leaf"
        );

        // Frontier: 2 leaves (position 0 and 1 both empty_leaf).
        let (frontier_bytes, _) = build_frontier_bytes(2);

        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes,
            anchor_height: 1,
            shard_leaves: vec![ShardLeaves {
                shard_index: 0,
                // Two actual leaf_val entries.
                cmxs: vec![leaf_val, leaf_val],
            }],
            // Claim position 0 has wrong_cmx — path.root(wrong_cmx) != anchor.
            notes: vec![(0, wrong_cmx)],
        };
        let err = build_witnesses(&inputs).unwrap_err();
        assert!(
            matches!(err, Error::WitnessMismatch { position: 0, .. }),
            "expected WitnessMismatch, got: {err}"
        );
    }

    // ── 4. Multi-note order preserved (two notes in same shard) ──────────────
    //
    // Two notes at positions 0 and 2 within shard 0. The notes are supplied in
    // reverse order (2 first, 0 second) and the output witnesses must be in the
    // same order.

    #[test]
    fn multi_note_order_preserved() {
        let leaf_val = MerkleHashOrchard::empty_leaf().to_bytes();
        let n = 4usize;

        // Frontier: n+1 leaves to cover all shard positions + checkpoint.
        let (frontier_bytes, frontier) = build_frontier_bytes(n + 1);

        let expected_anchor = {
            use incrementalmerkletree::Retention;
            use shardtree::{store::memory::MemoryShardStore, ShardTree};

            let mut tree = ShardTree::<
                MemoryShardStore<MerkleHashOrchard, u32>,
                ORCHARD_DEPTH,
                ORCHARD_SHARD_HEIGHT,
            >::new(MemoryShardStore::empty(), 2);
            tree.insert_frontier(
                frontier,
                Retention::Checkpoint {
                    id: 1u32,
                    marking: Marking::Reference,
                },
            )
            .unwrap();
            let leaves: Vec<(MerkleHashOrchard, Retention<u32>)> = (0..n)
                .map(|i| {
                    let ret = if i == 0 || i == 2 {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    (MerkleHashOrchard::empty_leaf(), ret)
                })
                .collect();
            tree.batch_insert(Position::from(0u64), leaves.into_iter())
                .unwrap();
            tree.root_at_checkpoint_depth(Some(0))
                .unwrap()
                .unwrap()
                .to_bytes()
        };

        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes,
            anchor_height: 1,
            shard_leaves: vec![ShardLeaves {
                shard_index: 0,
                cmxs: vec![leaf_val; n],
            }],
            // Reversed order: pos 2 first, pos 0 second.
            notes: vec![(2, leaf_val), (0, leaf_val)],
        };
        let out = build_witnesses(&inputs).expect("build_witnesses failed");
        assert_eq!(out.anchor, expected_anchor);
        assert_eq!(out.witnesses.len(), 2);
    }

    // ── 11. Multi-shard happy path (notes in shard 0 and shard 1) ─────────────
    //
    // Acceptance criterion: "Witnesses are valid for notes in different shards".
    // A user who receives ZEC at two times separated by enough Orchard activity
    // ends up with notes in different shards. Here shard 0 is fully completed
    // (2^16 leaves) so that positions in shard 1 exist, and we request a witness
    // for one note in each shard, asserting both `MerklePath::root(cmx) == anchor`.
    //
    // This also covers the cap-summary / batch-leaf overlap: shard 0 is supplied
    // BOTH as a `cap_roots` summary (step 2's `insert` at Level(16)) AND as full
    // leaves in `shard_leaves` (step 4's `batch_insert`). The shard-store summary
    // is replaced by the full subtree while the cap keeps the summary; a correct
    // witness for the note in shard 0 proves the two representations agree.
    //
    // Marked `#[ignore]` because exercising a real cross-shard path requires
    // filling all 2^16 leaves of shard 0, which means ~131k Sinsemilla hashes —
    // ~220s in an unoptimized test build. Run on demand with:
    //   cargo test -p zcash-crypto multi_shard_witnesses_validate -- --ignored
    // (add `--release` for a ~10-20x speed-up).
    #[test]
    #[ignore = "expensive: fills a full 2^16-leaf shard; run with --ignored (ideally --release)"]
    fn multi_shard_witnesses_validate() {
        let leaf_val = MerkleHashOrchard::empty_leaf().to_bytes();
        let shard_size = 1usize << ORCHARD_SHARD_HEIGHT; // 65536 leaves per shard
        let shard1_len = 4usize; // partial occupancy of shard 1

        // Note positions: one inside shard 0, one inside shard 1.
        let p0 = 1u64;
        let p1 = shard_size as u64 + 1;

        // Total leaves placed in the tree (shard 0 full + a few in shard 1). The
        // frontier encodes `total + 1` leaves — the extra one is the checkpoint
        // tip, mirroring the single-shard tests above.
        let total = shard_size + shard1_len;
        let (frontier_bytes, frontier) = build_frontier_bytes(total + 1);

        // All leaves are `empty_leaf`, so the tree root equals the frontier root
        // hashed up to ORCHARD_DEPTH. This is the same value `build_witnesses`
        // records as the anchor at the frontier checkpoint.
        let expected_anchor = frontier.root().to_bytes();

        // Completed shard 0's summary root. With all-empty leaves it is the empty
        // root at the shard level. Supplying this in `cap_roots` while also
        // supplying shard 0's leaves exercises the summary/leaf overlap.
        let shard0_root = MerkleHashOrchard::empty_root(Level::from(ORCHARD_SHARD_HEIGHT)).to_bytes();

        let inputs = WitnessInputs {
            cap_roots: vec![(0, shard0_root)],
            frontier_bytes,
            anchor_height: 1,
            shard_leaves: vec![
                ShardLeaves {
                    shard_index: 0,
                    cmxs: vec![leaf_val; shard_size],
                },
                ShardLeaves {
                    shard_index: 1,
                    cmxs: vec![leaf_val; shard1_len],
                },
            ],
            // One note per shard, supplied in ascending order.
            notes: vec![(p0, leaf_val), (p1, leaf_val)],
        };

        let out = build_witnesses(&inputs).expect("build_witnesses failed");
        assert_eq!(out.anchor, expected_anchor);
        assert_eq!(out.witnesses.len(), 2);

        // Explicitly re-validate each witness against the anchor. `build_witnesses`
        // already enforces this internally, but the acceptance criterion calls for
        // an independent `MerklePath::root(cmx) == anchor` check per note.
        let leaf_hash = MerkleHashOrchard::from_bytes(&leaf_val).into_option().unwrap();
        for path in &out.witnesses {
            assert_eq!(path.root(leaf_hash).to_bytes(), out.anchor);
        }
    }

    // ── 10. Known-good test vector (real testnet on-chain data) ───────────────
    //
    // Captured from the Ledger-hosted testnet Zaino node
    // (zaino-zec-testnet.nodes.stg.ledger-test.com) at anchor height 3,861,070.
    //
    // At that height the Orchard tree has two completed shards (0 and 1) whose
    // node-computed cap roots come from `GetSubtreeRoots`, plus a partial frontier
    // shard (index 2) holding 31 leaves at positions 131072..=131102. The note we
    // witness is the first leaf of that frontier shard (position 131072).
    //
    // This breaks the circularity of the synthetic tests above: the expected
    // `ANCHOR` is the canonical commitment-tree root obtained by decoding the
    // `GetTreeState` frontier and calling `Frontier::root()` — a code path
    // independent of the `ShardTree` cap-insert + batch-insert assembly that
    // `build_witnesses` uses. The test asserts the two agree, and additionally
    // pins the exact 32-element authentication path produced for the note.
    //
    // To regenerate after a chain reorg or to capture a fresh vector, run the
    // capture harness in zcash-sync:
    //   cargo test -p zcash-sync --test capture_witness_vector -- --ignored --nocapture emit
    #[test]
    fn known_good_test_vector() {
        fn h32(s: &str) -> [u8; 32] {
            hex::decode(s).unwrap().try_into().unwrap()
        }

        const ANCHOR_HEIGHT: u32 = 3_861_070;
        const FRONTIER_SHARD_INDEX: u32 = 2;
        const NOTE_POSITION: u64 = 131_072;

        let anchor = h32("a104cba07fd164a2f4432eac02ce9d4ea76749d63adc02050c7004ccb5c36014");

        let cap_roots = vec![
            (0u32, h32("25934a8c8cde7b4ba7e51d78f2321c7e286d140811a192f692f29d3f0ecce510")),
            (1u32, h32("a7d4af61ae5f9c5a63dd74d7bb541f42ca227c79c30ed360c569167f7dedfc1e")),
        ];

        let frontier_bytes = hex::decode(
            "019d23f92a7612ebfb47f197c6d98f917c070d2cc85e09d4ebaea0ab2deff5cd18001f018dc50720f589a38dd1904e84eaacaf636e172cdd6236e869da03ec8d671ff93801b4f7b74d8c3e760d8d7b2c5bf3981c5fd901515a443131f264927ba3a3c80b1e0182d466c7a813fb5b9797409df09e4c436efb1d7368ab3ccb16d731af23cb1a1c01ac3d9637df091b7d4176cab23fdefddb2d750227df513b150ac5519869a15d270000000000000000000000000165702b4337a80dbc279d6b6d2fb16d177975f9f5de0a05851769e91c0815d9210000000000000000000000000000",
        )
        .unwrap();

        let cmxs: Vec<[u8; 32]> = [
            "c53c1944c1add04a071359f9c077aa8991f5431736b1f958270718bc1250c531",
            "5d8c2880ba85481a078f98482d9616decc89d972408747beeaffd3501c83770b",
            "afed976b3e78da3e6e15175519d90ff4e19d56ff8fbdcc768c826865bd06ed2f",
            "89dd82c073fa703d2eb237135eda398e4e5be95b219e0655d73ca60ffde61910",
            "0e01d27ddb55d79c71ed1007ddc00ff1f61adb2545aeadf9443c0a9447d2601a",
            "a3225a0bed3be441ececa208e426fbfb7cc17007b6cd604bf217944874666421",
            "7a57d611c8620ef573bbc843459ee8c2662d1f9f456b63465dd712f62498cb20",
            "e32b60fb114101c14a1591633c5e6c959fd5fd2d304c31699ad61112af89eb02",
            "b3659a208e3958ca554a2763ce3ed98df74abaf42be87007fec1ecf2c19c003f",
            "126d2b95c741809bc6552500f1ab12e5aad961676cedee2af68d39576be25c3e",
            "70c2eecd566680c316a1c15e9142e1663dc48089c8705aa812555603948f371f",
            "0fbdf20cc8a688d3ead15f29bacb15794706b6f29064b45b53b1ae9995c9c314",
            "f0a46dd38966caa8049163b0d27c626bf77062deace602e1bf859f5035d06f19",
            "e98264efe381ae029710e4a05b02b210561c5ac7dc2449445fe3e9093a28ec37",
            "f625fcf5540416b3897d93ec46721ee0066038d57849836111bdf300518c9213",
            "94351207a621ac9ee760230313435bfdd8e21670c475bb592eedd7bf6aa1272d",
            "185b7fe290de1c4f0775b0d525d477129619f4a2e6e0561c593ab03254d9dd13",
            "a157e564cc4e433fb7a0f13ef66e9f48b8f5f82b6fbbb207b0a34ac42955263d",
            "1faaa991ff88e749b005eca8d6013e97bd3c84b804c2d3f482ef13e1775ba43a",
            "24f4268786e44369e5cb0b36c34458db75ed801a1001608ec963d339710dab00",
            "ae37e678a74351b43d5b54fcc3c1e742d698d6322aca13d9a08d26851979520e",
            "dad0fc2d95fcf8e057860551224c076c18a44c9829b15ae3c1afbde36048a025",
            "c4a86bf50196b30bcf095ffd34880ff1f32a8849a1f42cae92add20faba22f0f",
            "2549fa843e3b3d291b9ccbc6af996c52ee32935ab0a978aee7d5391f1e2a942f",
            "9f9c6987ce9acb233aed23b86cbcb30e01c23d49258a01831ee3d9b6aa10d91d",
            "bf47454b4fef1c0bfc2e364096cf42ae60f072a5221813be6acf2fe69117880d",
            "87f3807ee9ced4a20aafbbbbd6aa7e40244de6039eb322ef29f8803cb9a4742c",
            "ef8e2648c042f6324233801ea6c4f831f8ff58c0d532523e1fa16ef15510a605",
            "1e67edc91e6ecdb57e9426f73ac285824525bfd6676e0ce5a7a27630b47c7731",
            "735c2988d2cf016c3df1d608497c416a343279a09f02811907981b988bfe883d",
            "9d23f92a7612ebfb47f197c6d98f917c070d2cc85e09d4ebaea0ab2deff5cd18",
        ]
        .iter()
        .map(|s| h32(s))
        .collect();

        // The expected 32-element authentication path for the note at 131072.
        let expected_path: Vec<[u8; 32]> = [
            "5d8c2880ba85481a078f98482d9616decc89d972408747beeaffd3501c83770b",
            "0c3b35ea3be9f86735bc97fa4efedb8c56312d9c28f66f30ca01ee328a742b0c",
            "0bdbca276f6f4366cdef2158c9efd699d192756764671189392e00c60de14d28",
            "a5c6d4b7d34d5a8e7f45f267942ee3bf351e78c2de32ef61a2383a6ca42e5723",
            "83eb82f3fa7acb1542c1598cc38bd41feb25646772dc9cda2801c30525ae4d20",
            "873e4157f2c0f0c645e899360069fcc9d2ed9bc11bf59827af0230ed52edab18",
            "27ab1320953ae1ad70c8c15a1253a0a86fbc8a0aa36a84207293f8a495ffc402",
            "4e14563df191a2a65b4b37113b5230680555051b22d74a8e1f1d706f90f3133b",
            "b3bbe4f993d18a0f4eb7f4174b1d8555ce3396855d04676f1ce4f06dda07371f",
            "4ef5bde9c6f0d76aeb9e27e93fba28c679dfcb991cbcb8395a2b57924cbd170e",
            "a3c02568acebf5ca1ec30d6a7d7cd217a47d6a1b8311bf9462a5f939c6b74307",
            "3ef9b30bae6122da1605bad6ec5d49b41d4d40caa96c1cf6302b66c5d2d10d39",
            "22ae2800cb93abe63b70c172de70362d9830e53800398884a7a64ff68ed99e0b",
            "187110d92672c24cedb0979cdfc917a6053b310d145c031c7292bb1d65b7661b",
            "3f98adbe364f148b0cc2042cafc6be1166fae39090ab4b354bfb6217b964453b",
            "63f8dbd10df936f1734973e0b3bd25f4ed440566c923085903f696bc6347ec0f",
            "2182163eac4061885a313568148dfae564e478066dcbe389a0ddb1ecb7f5dc34",
            "65702b4337a80dbc279d6b6d2fb16d177975f9f5de0a05851769e91c0815d921",
            "ca2ced953b7fb95e3ba986333da9e69cd355223c929731094b6c2174c7638d2e",
            "55354b96b56f9e45aae1e0094d71ee248dabf668117778bdc3c19ca5331a4e1a",
            "7097b04c2aa045a0deffcaca41c5ac92e694466578f5909e72bb78d33310f705",
            "e81d6821ff813bd410867a3f22e8e5cb7ac5599a610af5c354eb392877362e01",
            "157de8567f7c4996b8c4fdc94938fd808c3b2a5ccb79d1a63858adaa9a6dd824",
            "fe1fce51cd6120c12c124695c4f98b275918fceae6eb209873ed73fe73775d0b",
            "1f91982912012669f74d0cfa1030ff37b152324e5b8346b3335a0aaeb63a0a2d",
            "5dec15f52af17da3931396183cbbbfbea7ed950714540aec06c645c754975522",
            "e8ae2ad91d463bab75ee941d33cc5817b613c63cda943a4c07f600591b088a25",
            "d53fdee371cef596766823f4a518a583b1158243afe89700f0da76da46d0060f",
            "15d2444cefe7914c9a61e829c730eceb216288fee825f6b3b6298f6f6b6bd62e",
            "4c57a617a0aa10ea7a83aa6b6b0ed685b6a3d9e5b8fd14f56cdc18021b12253f",
            "3fd4915c19bd831a7920be55d969b2ac23359e2559da77de2373f06ca014ba27",
            "87d063cd07ee4944222b7762840eb94c688bec743fa8bdf7715c8fe29f104c2a",
        ]
        .iter()
        .map(|s| h32(s))
        .collect();

        let note_cmx = cmxs[0];

        let inputs = WitnessInputs {
            cap_roots,
            frontier_bytes: frontier_bytes.clone(),
            anchor_height: ANCHOR_HEIGHT,
            shard_leaves: vec![ShardLeaves {
                shard_index: FRONTIER_SHARD_INDEX,
                cmxs,
            }],
            notes: vec![(NOTE_POSITION, note_cmx)],
        };

        let out = build_witnesses(&inputs).expect("build_witnesses failed on real testnet vector");

        // 1. The assembled anchor matches the captured on-chain anchor.
        assert_eq!(out.anchor, anchor, "anchor mismatch");

        // 2. Independent cross-check: the canonical commitment-tree root (decoded
        //    from the GetTreeState frontier via a separate code path) equals the
        //    ShardTree-assembled anchor. This is what makes the vector "known-good"
        //    rather than self-referential.
        let frontier_root = super::decode_orchard_frontier(&frontier_bytes)
            .unwrap()
            .root()
            .to_bytes();
        assert_eq!(frontier_root, anchor, "canonical frontier root disagrees with assembled anchor");

        // 3. Exactly one witness, at the requested position.
        assert_eq!(out.witnesses.len(), 1);
        let path = &out.witnesses[0];
        assert_eq!(u64::from(path.position()), NOTE_POSITION);

        // 4. The authentication path matches the captured 32-element path.
        let got_path: Vec<[u8; 32]> = path.path_elems().iter().map(|e| e.to_bytes()).collect();
        assert_eq!(got_path, expected_path, "authentication path mismatch");

        // 5. And the path re-roots to the anchor against the note cmx.
        let leaf = MerkleHashOrchard::from_bytes(&note_cmx).into_option().unwrap();
        assert_eq!(path.root(leaf).to_bytes(), anchor);
    }

    // ── decode_orchard_frontier helper tests ──────────────────────────────────

    #[test]
    fn decode_empty_frontier_returns_empty() {
        let f = super::decode_orchard_frontier(&[]).unwrap();
        assert!(f.take().is_none(), "expected empty Frontier");
    }

    #[test]
    fn decode_invalid_bytes_returns_frontier_decode_error() {
        let err = super::decode_orchard_frontier(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            matches!(err, Error::FrontierDecode(_)),
            "expected FrontierDecode, got: {err}"
        );
    }

    // ── Note outside any provided shard → ShardTree error ─────────────────────

    #[test]
    fn note_position_outside_shard_returns_error() {
        // We provide shard 0 leaves but ask for a witness at position 2^17
        // (which is in shard 1), with a checkpoint via a frontier on position 3.
        use incrementalmerkletree::Retention;
        use shardtree::{store::memory::MemoryShardStore, ShardTree};

        let leaf = MerkleHashOrchard::empty_leaf().to_bytes();

        // Build a ref tree with a leaf at pos 0 and a checkpoint.
        let mut ref_tree = ShardTree::<
            MemoryShardStore<MerkleHashOrchard, u32>,
            ORCHARD_DEPTH,
            ORCHARD_SHARD_HEIGHT,
        >::new(MemoryShardStore::empty(), 2);
        ref_tree
            .append(MerkleHashOrchard::empty_leaf(), Retention::Ephemeral)
            .unwrap();
        ref_tree
            .append(
                MerkleHashOrchard::empty_leaf(),
                Retention::Checkpoint {
                    id: 1u32,
                    marking: Marking::Reference,
                },
            )
            .unwrap();

        // Ask for a witness at position 0 but with shard 0 leaves AND a note
        // at position 2^17 (shard 1) which we have no leaves for.
        let pos_in_shard1: u64 = 1u64 << ORCHARD_SHARD_HEIGHT;
        let inputs = WitnessInputs {
            cap_roots: vec![],
            frontier_bytes: vec![],
            anchor_height: 1,
            shard_leaves: vec![ShardLeaves {
                shard_index: 0,
                cmxs: vec![leaf, leaf],
            }],
            notes: vec![(pos_in_shard1, leaf)],
        };
        let err = build_witnesses(&inputs).unwrap_err();
        // Should be a ShardTree query error (TreeIncomplete or similar) since the
        // requested position has no data in the tree.
        assert!(
            matches!(err, Error::ShardTree(_)),
            "expected ShardTree error for out-of-shard position, got: {err}"
        );
    }
}
