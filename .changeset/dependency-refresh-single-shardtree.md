---
"@ledgerhq/zcash-utils": patch
---

Refresh the dependency lock and collapse the duplicate `shardtree`. The lock
carried two copies of it — our own `0.6.2` plus the `0.7.0` that
`zcash_client_backend` links — so the commitment-tree types existed twice under
identical names and a witness built against one could not cross into the other.
Declaring `shardtree = "0.7"` leaves a single `0.7.1` copy that both sides share.

`pczt` moves to `0.9.3`, still pinned exactly: it defines the byte stream the
firmware parses, so it may only move as a deliberate, tested step and never as a
side effect of `cargo update`. `bitcoin` stays on the `0.32.x` maintenance line
for the same reason — the parallel `0.32.10x` feature line sorts higher and a
broad update would otherwise drift onto it — and the pin is now documented in
`Cargo.toml` so the next refresh keeps it.

The rest is a routine refresh of transitive dependencies. No Zcash protocol crate
moves: `zcash_primitives`, `zcash_keys`, `zcash_transparent`, `orchard` and
`zcash_client_backend` all stay where they were.
