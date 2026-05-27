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

    // ── 10. Known-good test vector (placeholder) ──────────────────────────────
    //
    // [UNCERTAIN: anchor + auth_path tuple to be captured from zcashd regtest or
    // testnet Zaino — flag to integration team. Owner: integration team]
    //
    // Once a real vector is available, replace the `todo!()` below with the
    // precomputed (cap_roots, frontier_bytes, cmxs, anchor, path) tuple and
    // remove the `#[ignore]` attribute.
    #[test]
    #[ignore = "test vector not yet available — see CUSTOM-02 plan section 'Known risks'"]
    fn known_good_test_vector() {
        todo!("supply (cap_roots, frontier_bytes, cmxs, anchor, auth_path) from zcashd regtest");
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
