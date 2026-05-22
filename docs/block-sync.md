# Block Sync Engine

## Overview

`zcash-sync` implements a two-phase scan algorithm to efficiently find and
decrypt shielded transactions in a block range without fetching every full
transaction from the server.

## Algorithm

```
┌──────────────────────────────────────────────────────────────────────┐
│ Phase 1: Trial decryption (compact blocks — low bandwidth)           │
│                                                                      │
│  GetBlockRange(start, end) ──► stream of CompactBlock               │
│                                                                      │
│  For each CompactBlock:                                              │
│    For each CompactTx:                                               │
│      For each CompactSaplingOutput / CompactOrchardAction:           │
│        try_compact_note_decryption(ivk, compact_output)              │
│        → match found? → add txid to matched set                     │
│                                                                      │
│  Cost: ~170 bytes per Sapling output, ~170 bytes per Orchard action  │
│  No memo, amount, or sender — just enough to detect a match         │
└──────────────────────────────────────────────────────────────────────┘
                              │ matched txids
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Phase 2: Full decryption (full transactions — only for matches)     │
│                                                                      │
│  GetTransaction(txid) ──► raw tx bytes                              │
│                                                                      │
│  decrypt_transaction(network, height, tx, ufvk_map)                 │
│    → DecryptedOutput { amount, memo, transfer_type, nullifier,      │
│                         rseed, cmx, recipient, action_index }       │
│                                                                      │
│  transfer_type: "incoming" | "outgoing" | "internal"                │
│  Spending fields (rseed, cmx, recipient, action_index) are          │
│  populated for incoming/internal Orchard notes only.                │
└──────────────────────────────────────────────────────────────────────┘
                              │ matched txids + our_nullifiers
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Phase 4: Outgoing transaction detection (nullifier matching)        │
│                                                                      │
│  For each block, check if any transaction spends a nullifier from   │
│  our_nullifiers. If so, fetch and full-decrypt that transaction.    │
│  This detects spending txs invisible to trial decryption.           │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Phase 5: Spent-note marking                                         │
│                                                                      │
│  For each received note, if its nullifier was spent in any block    │
│  within the scanned range, set is_spent = true.                    │
│  Position is computed from chain_metadata.orchard_commitment_tree_  │
│  size and the note's action_index within its block.                │
└──────────────────────────────────────────────────────────────────────┘
```

## Why compact blocks?

Compact blocks contain only the data needed for trial decryption (commitment,
ephemeral public key, compact ciphertext). For a block with N outputs, only
N × 170 bytes are transferred, vs. tens of kilobytes for full transactions.
The `GetBlockRange` RPC streams all blocks in a single connection, minimising
latency.

## Byte order

lightwalletd uses **internal (little-endian)** byte order for transaction IDs
in its proto types. Display (explorer) format is big-endian. The sync engine
converts accordingly:

```rust
// proto CompactTx.hash → display (big-endian) hex for our txid field:
let txid_hex = hex::encode(ctx.hash.iter().copied().rev().collect::<Vec<u8>>());

// display hex → internal bytes for TxFilter.hash:
let txid_bytes_le: Vec<u8> = hex::decode(&txid_hex)?.into_iter().rev().collect();
```

## IVK preparation

IVKs are derived from the UFVK once before the scan loop. This is important
because `PreparedIncomingViewingKey::new()` performs pre-computation that
accelerates each `try_compact_note_decryption` call:

```rust
let ivks = decrypt::prepare_ivks(&params.viewing_key)?;
// ivks is reused for every block in the range
```

## Entry point

```rust
// In zcash-sync
pub async fn run_sync(params: SyncParams) -> anyhow::Result<SyncResult>;
pub async fn chain_tip(grpc_url: String) -> anyhow::Result<u32>;
```
