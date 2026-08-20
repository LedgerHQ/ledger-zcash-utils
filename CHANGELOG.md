# @ledgerhq/zcash-utils

## 2.2.0

### Minor Changes

- 0a94002: Build a transparent send without a UFVK. `buildTransaction` required a UFVK for
  every flow, including a fully transparent one — which carries no shielded bundle
  and reads no shielded key material. Its only key requirement is the
  account-level transparent pubkey at `m/44'/coin'/account'`, used to derive the
  internal change address and to verify each input's signing path. A wallet always
  holds those bytes (they are the payload of the account xpub) whereas obtaining a
  UFVK takes a user confirmation on the device, so the requirement forced a
  viewing-key export on anyone spending public funds.

  `ufvk` is now optional and a `transparentAccountPubkey` field accepts those 65
  bytes (32-byte chain code ‖ 33-byte compressed pubkey) as hex. A transparent
  send supplies the pubkey and omits the UFVK; both may be supplied together, in
  which case the UFVK's transparent component is authoritative and the standalone
  field only has to agree with it — a mismatch means key material from two
  different accounts and fails the build rather than picking one. Every flow with
  a shielded bundle (an Orchard spend, or a shielded recipient) still requires the
  UFVK and now says so explicitly instead of failing deeper on a missing Orchard
  component; `buildIronwoodTransaction`, whose bundle is always shielded, is
  unchanged.

  The two orchestrators now share one transparent-input decoder, so the
  fund-safety check that ties each input's `(derivationScope, addressIndex)` to
  its pubkey has a single implementation instead of two copies.

### Patch Changes

- 0a94002: Refresh the dependency lock and collapse the duplicate `shardtree`. The lock
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

## 2.1.1

### Patch Changes

- 152aa4d: Accept V6 transactions when recomputing the txid on broadcast. `broadcastTransaction` derived the txid behind a guard that admitted only V5, which dates from when V5 was the only post-ZIP-225 format and survived the V6 builder, the Ironwood finalize path, and the Ironwood PCZT parse without being revisited. Only a transparent t→t send stays on V5 — any shielded send carrying an Ironwood bundle finalizes to V6 — so every shielded send failed with `expected V5 transaction, got V6` _after_ the device had already signed, and before the transaction was ever submitted. Nothing was lost: the txid is computed before the transaction is handed to the server, so the failing path returned without broadcasting.

  The guard now admits V5 and V6 and still rejects pre-ZIP-225 formats, whose wire layout differs. The txid derives from the stream for both versions: `Transaction::read` dispatches on the version header and forwards its consensus-branch argument only to the V4 reader, so a V6 txid is computed exactly as a V5 one is and still matches the operation hash the sync path records for the same transaction.

  Also derive Ironwood completed-shard roots locally instead of calling `GetSubtreeRoots`. The deployed Zaino does not serve that RPC for the Ironwood pool — it rejects `ShieldedProtocol::Ironwood` as an invalid shielded protocol value — so Ironwood witness computation now streams the pool's cmx leaves over `GetBlockRange` and reduces each completed shard to its root with the same level-encoded Sinsemilla hash the server would have applied. The pure witness assembly is unchanged and still shared with Orchard.

  The pool's first block is located by binary-searching the commitment-tree frontier on leaf count rather than on whether the server's tree-state field is a non-empty string, so the search does not depend on how a server represents an empty frontier. Two bounds are checked before any block is fetched: the pool must be small enough for local reduction to stay interactive, and the scan range must be plausible, so a misresolved activation height fails fast instead of streaming a large share of the chain through a request that carries no timeout. Collected leaf counts are reconciled against the frontier, so a disagreement surfaces as an error rather than a silently wrong witness, and a note position past the anchor's leaf count is rejected up front. Callers should move back to `GetSubtreeRoots` once the server serves it for Ironwood.

## 2.1.0

### Minor Changes

- abe272e: Surface the Ironwood bundle from `parsePczt`.

## 2.0.0

### Major Changes

- b555b18: First stable release (1.0.0): end-to-end shielded transaction crafting.

  Since 0.3.1 the addon grew from a scan-only library into a full Orchard send pipeline:

  - V5 PCZT transaction builder supporting Orchard send flows and mixed
    transparent + Orchard inputs, with bip32 derivation stamped on the change
    output and every transparent input
  - `buildTransaction`, `finalizeTransaction`, and `broadcastTransaction` to
    build, finalize, and submit a shielded transaction
  - `parsePczt(pcztHex)` to decode canonical PCZT bytes into a structured
    `PcztTransaction` consumed by `@ledgerhq/device-signer-kit-zcash`
  - On-demand Orchard ShardTree witness computation at craft time
  - `findBlockHeight(grpcUrl, timestamp)` binary search over block timestamps
  - NU6.2-aware crate versions for correct branch-id resolution and shielded
    parsing at/above the NU6.2 activation height

### Minor Changes

- 65c6a95: Report the transparent bundle of a scanned transaction on `ShieldedTransaction`, via two new fields: `transparentOut` (sum of the transparent outputs, in zatoshis) and `hasTransparentInputs`.

  A shielded→transparent send leaves no decrypted output a wallet can attribute to a counterparty: the value exits through the transparent bundle and only the change comes back, marked `internal`. Consumers therefore saw such a send as a self-transfer moving nothing. The scanner already deserializes the full transaction to compute the fee, so it can report these two facts directly instead of having each consumer re-parse the raw hex. `hasTransparentInputs` is needed alongside the amount: once transparent inputs are present, the transparent outputs may be paid by those inputs rather than out of the shielded pools, and the bundle alone cannot tell the two apart.

- 3f2ea9c: Add `findBlockHeight(grpcUrl, timestamp)` — binary search over block timestamps via gRPC

  - New Rust function `find_block_height` in `zcash-sync` using interpolation search + streaming `GetBlockRange` for fast convergence (~6 RPCs, under 1.5s on mainnet)
  - Exposed via NAPI as `findBlockHeight(grpcUrl: string, timestamp: number): Promise<number>`
  - New CLI subcommand `height-at --grpc-url <URL> --date <YYYY-MM-DD|timestamp>`
  - Returns the height of the first block whose timestamp is ≥ the target

- 01420fd: Add an optional `ironwoodSignatures` field to `FinalizeTransactionParams` to support finalizing V6 Ironwood PCZTs, and widen `finalizeTransaction` to return a V5 (ZIP-225) or V6 (ZIP-230) transaction depending on the input PCZT's shielded bundle. `FinalizeInputs` now accepts per-spend Ironwood `spendAuthSig` bytes injected via `apply_ironwood_signature`.

  The new field is optional, so existing callers that pass only `orchardSignatures` and `transparentSignatures` keep working unchanged — hence a minor rather than a major bump. Each signature list is length-checked against the PCZT's unsigned actions for its pool, so supplying signatures for a pool the PCZT does not spend fails closed.

  Crate dependencies bumped to `pczt 0.9.2`, `zcash_primitives 0.30`, `zcash_transparent 0.10`, `zcash_keys 0.16`, and `zcash_client_backend 0.24.0-rc.7`.

- b7f7d36: Sync the Ironwood (NU6.3) shielded pool in parallel to Orchard. Detect, trial-decrypt, and fully decrypt Ironwood notes (ZIP 2005 `0x03` note plaintext) from the Ironwood bundle of V6 transactions, expose them via a new `ironwoodNotes` array on `ShieldedTransaction` and a per-note `pool` discriminator, derive their position from the Ironwood commitment-tree-size counter, track spends against the Ironwood nullifier set, and compute ShardTree witnesses for the Ironwood tree. Existing Orchard/Sapling sync and the Orchard send path are unchanged. Bumps the Zcash crates to NU6.3-aware versions (orchard 0.15, zcash_primitives 0.29, zcash_protocol 0.10, and the wallet-side crates from crates.io release candidates: `zcash_client_backend 0.24.0-rc.1`, `pczt 0.8.0-rc.1`).
- 485d063: Add spending fields to ShieldedNote (nullifier, rseed, cmx, position, recipient, is_spent) to support shielded transaction crafting via PCZT. Position is derived from CompactBlock chain_metadata, is_spent is computed by nullifier matching across the scanned range.
- b8635d1: Expose the default unified receiving address (ZIP-316, `u1...` / `utest1...`) from key derivation. `DerivedKeys` gains a `unified_address` field, and `ledger-zcash-cli derive` now prints it alongside the UFVK in both `human` and `json` output. Derived purely from the UFVK (watch-only, no spending key involved) and independent of `--no-sapling`, since that flag only controls what's bundled into the encoded UFVK string, not the address's receiver set.
- 0d19606: Add `orchardAddressFromUfvk` — derives the Orchard-only unified address from an encoded UFVK string. Returns the same address the Ledger device shows on the Receive screen (matches `GetShieldedAddress` INS 0x51). Also renames `DerivedKeys.unifiedAddress` to `multiReceiverUnifiedAddress` to distinguish it from the Orchard-only address.
- 41a83b8: Add `finalizeTransaction` and `broadcastTransaction` NAPI functions for the Orchard send flow.
- 400dbb5: Add `buildTransaction` NAPI function for Orchard send flows.
- c16921d: Add `parsePczt(pcztHex)` — decode canonical PCZT bytes into a structured `PcztTransaction`

  - New Rust function `parse_pczt` in `zcash-crypto` that parses the canonical PCZT bytes emitted by `buildTransaction` (`PCZT` magic + u32 LE version + postcard payload) and re-shapes them into a fully structured form: the global header, every transparent input/output, and each Orchard action broken out field-by-field
  - Exposed via NAPI as `parsePczt(pcztHex: string): PcztTransaction`, matching the object `@ledgerhq/device-signer-kit-zcash`'s `DmkSignerZcash.signPcztTransaction` consumes (`Uint8Array` byte fields, `bigint` zatoshi values, `signingPath` derivation strings)
  - Bridges `buildTransaction` (returns `pcztHex`) to the device signer without a TypeScript postcard parser
  - Fails with a clear error when the input is not a valid PCZT or is missing a field the device requires to sign (e.g. Orchard `alpha`/`rcv`, an input's single `bip32_derivation`)

- adb99fb: Add on-demand Orchard ShardTree witness computation.

  Public surface:

  - `zcash_crypto::tree::{build_witnesses, WitnessInputs, WitnessOutput, ShardLeaves}`
  - `zcash_sync::witness::{compute_witnesses, WitnessRequest, NoteRef}`

  Witness data is fetched and assembled on demand at craft time. No tree state
  is persisted between calls.

- 68d013b: Add `buildIronwoodTransaction` for the Ironwood (NU6.3) shielded pool: builds, proves, and serializes an unsigned V6 PCZT carrying an Ironwood bundle (spends and/or outputs), reusing the existing Orchard V5 crafting lifecycle against the updated Action circuit. Ironwood outputs use the `0x03` quantum-recoverable note plaintext, the emitted PCZT is redacted and serialized in the v2 wire format (required for any V6 transaction), and a dedicated non-zero-anchor check rejects an all-zero Ironwood commitment-tree root before it can be silently embedded. Anchor/witness resolution reuses the existing Ironwood sync path (`fetchIronwoodAnchor` / Ironwood witness computation). The shipped Orchard V5 send flow (`buildTransaction`) is unchanged. Like the V5 builder, this is device-coupled (not exposed via the CLI) and depends on release-candidate wallet-side crates (`pczt`, `zcash_client_backend`) pending stable NU6.3 releases.
- 65c6a95: Add `transactionDetails`, which fetches transactions by txid and reads from each what only the raw bytes hold: the fee it actually paid, and the addresses its shielded outputs paid.

  Both answers require the whole transaction, so one fetch serves both. A fee derived from the transparent bundle alone — all an explorer can do — counts value entering a shielded pool as fee and cannot account for value leaving one. Shielded payees are encrypted and recoverable only by the account that created the outputs, through the outgoing viewing key the transaction was built with; pass `ufvk` to recover them.

  Requests are pipelined over a single gRPC channel and answered in order. A transaction that cannot be fetched, parsed, or fully priced yields a `null` fee and no payees rather than an approximation.

  Orchard-family and Sapling notes now also carry the address they pay (`recipient`), which for a note we sent is the payee rather than one of our own addresses.

- e07bc98: Add transparent input support to the V5 PCZT builder.

### Patch Changes

- 4776701: Bump version to deploy new release
- 0c6f624: Update Zcash crates to NU6.2-aware versions (orchard 0.14, zcash_primitives 0.28, zcash_protocol 0.9, and transitive deps). Restores correct branch-id resolution and shielded-transaction parsing for blocks at or above the NU6.2 activation height (mainnet 3,364,600).
- b949c30: Keep the transparent and Orchard send paths working past NU6.3. Three things change under `build_transaction` at that activation even though the code did not: the builder derives V6 from the consensus branch, which the PCZT v1 device contract cannot encode, so the V5 format is now pinned explicitly; an Orchard bundle becomes `orchard_v3` in that epoch and only proves against the NU6.3 circuit generation, so the proving and verifying keys are selected from the branch instead of being fixed to the NU6.2 generation; and the Orchard pool disables cross-address transfers, so retained value is added through the builder's change API, which is what makes z→t build again.

  Also fetch an anchor from the commitment-tree frontier alone. A shielded bundle with outputs but no real spend needs an anchor and no witness, and the frontier determines the root, so shielding no longer streams every completed shard root — and no longer depends on the server serving that pool's `GetSubtreeRoots`, which Ironwood does not yet.

- 6e5e9b0: Bump the librustzcash crate set to NU6.3-aware versions (zcash_protocol 0.10, zcash_primitives 0.29, and the compatible zcash_keys/zcash_address/zcash_transparent/orchard set, plus zcash_client_backend and pczt release candidates). This corrects `BranchId::for_height`, which resolves `Nu6_3` at mainnet height 3,428,143, so transactions parse and build correctly after NU6.3 activation. No public API change.
- 9ccce21: Route surplus change to the pool that funds it: an Orchard change output only when the transaction has Orchard spends (z→z, z→t), a transparent change output when there are none (t→t, t→z). For t→z this keeps the change transparent instead of migrating the whole balance into the shielded pool — only the sent amount is shielded.
- b1766c6: Add new retryable error for "h2 protocol error"
- 936b971: Emission happens AFTER Phase 5 so that `is_spent` flags are correct.
- 50e74c7: Decrease bundle size

## 1.0.4

### Minor Changes

- Report the fee a transaction actually paid and the addresses its shielded outputs paid, through the new `transactionDetails` function
- Report the transparent bundle of a scanned transaction, via `transparentOut` and `hasTransparentInputs` on `ShieldedTransaction`

# @ledgerhq/zcash-utils

## 1.0.3

### Patch Changes

- Fix zero anchor

# @ledgerhq/zcash-utils

## 1.0.2

### Patch Changes

- Fix find block height low boundary block number

# @ledgerhq/zcash-utils

## 1.0.1

### Patch Changes

- Recompute target height

# @ledgerhq/zcash-utils

## 1.0.0

### Major Changes

- NAPI function for parsePCZT

# @ledgerhq/zcash-utils

## 0.1.2

### Patch Changes

- Rework npm package README to document the Node.js NAPI API instead of the Rust workspace. Move workspace/development documentation to CONTRIBUTING.md.

## 0.1.1

### Patch Changes

- Expose `TransactionStream.cancel()` to abort a background scan immediately. Buffered transactions already sent by Rust remain consumable via `next()`.

## 0.1.0

### Initial Release

First public release of the Node.js (NAPI) addon for Zcash shielded transaction scanning.

- `startSync(params)` — scans a compact block range for shielded transactions using trial decryption entirely in Rust
- `getChainTip(grpcUrl)` — queries current chain tip height from a gRPC endpoint
- `TransactionStream` — async iterator over matched and fully-decrypted shielded transactions (`next()`, `stats()`)
- Pre-built `.node` binaries for macOS (arm64, x64), Linux (x64, arm64), and Windows (x64, arm64)
- Orchard-only mode (`orchardOnly: true`) for Ledger wallets
