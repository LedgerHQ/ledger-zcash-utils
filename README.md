# @ledgerhq/zcash-utils

Native Node.js (NAPI) addon for Zcash wallet operations — built in Rust via [napi-rs](https://napi.rs).

It covers the two halves of a shielded wallet that cannot be done in TypeScript: **scanning** the chain for notes belonging to an account (trial decryption of every compact block), and **crafting** a send as a PCZT for a Ledger device to sign, then reassembling and broadcasting the signed transaction. Halo 2 proving, PCZT (postcard) serialization, and the binding signature all happen here, in Rust.

No spending key is needed to do any of it. Scanning and crafting read a Unified Full Viewing Key and an account-level transparent pubkey, and every signature comes from the device. The two exports whose names begin with `test` are the deliberate exception, for integrators who need a device-free test harness — see [Test-only surface](#test-only-surface).

## Installation

```sh
npm install @ledgerhq/zcash-utils
```

Published on the public npm registry under the `@ledgerhq` scope; no registry configuration is needed.

Prebuilt `.node` binaries are bundled for six targets — `darwin-arm64`, `darwin-x64`, `linux-x64-gnu`, `linux-arm64-gnu`, `win32-x64-msvc`, `win32-arm64-msvc` — so there is no compilation step and no Rust toolchain to install. On any other platform, build from source: see [`CONTRIBUTING.md`](CONTRIBUTING.md).

Node.js 20 or later. The addon is a native module, so it runs in Node and in the Electron main process, not in a browser or a renderer without `nodeIntegration`.

## Quick start — scanning

```typescript
import { startSync, getChainTip } from "@ledgerhq/zcash-utils";

// Any lightwalletd or Zaino endpoint. This one is public; Ledger Live points
// at its own infrastructure.
const grpcUrl = "https://testnet.zec.rocks:443";
const tip = await getChainTip(grpcUrl);

const stream = await startSync({
  grpcUrl,
  viewingKey: "uviewtest1...",
  startHeight: tip - 1000,
  endHeight: tip,
  network: "testnet",
  // Skips all Sapling crypto work. Ledger wallets are Orchard-only, but the
  // default is false. Ironwood notes are decrypted regardless of this flag.
  orchardOnly: true,
  // Nullifiers of still-unspent notes from previous scans, so a note spent
  // in this range is detected across the incremental sync boundary.
  knownNullifiers: [],
});

let tx;
while ((tx = await stream.next()) !== null) {
  // Each note carries its spending fields (nullifier, rho, rseed, cmx,
  // position, recipient) — persist them, they are the inputs to a later send.
  console.log(tx.txid, tx.orchardNotes, tx.ironwoodNotes);
}

const stats = await stream.stats();
// stats.spentKnownNullifiers — previously-stored notes to mark as spent.
console.log(`Scanned ${stats.blocksScanned} blocks in ${stats.elapsedMs}ms`);
```

## Sending: the full flow

A send is a round trip through the device. This package owns every step except the signing itself.

1. **Craft** — `buildTransaction` (Orchard and/or transparent source) or `buildIronwoodTransaction` (Ironwood source) selects change, computes Merkle witnesses against an anchor, generates the Halo 2 proof, and returns canonical PCZT bytes as hex. The spend inputs are notes found by a previous scan; the fee is chosen by the caller and validated against ZIP-317.
2. **Parse** — `parsePczt` decodes those bytes into the structured `PcztTransaction` the device signer consumes. The PCZT postcard format is not trivially parseable in TypeScript, which is why this exists.
3. **Sign** — `signPcztTransaction` from [`@ledgerhq/device-signer-kit-zcash`](https://github.com/LedgerHQ/device-sdk-ts/tree/develop/packages/signer/signer-zcash) streams the PCZT to the device over APDUs and returns one RedPallas `spendAuthSig` per _real_ shielded spend, plus one secp256k1 signature per transparent input. Dummy padding spends are not signed on device; they are self-signed host-side, which is why the counts line up with the unsigned actions this package expects back.
4. **Finalize** — `finalizeTransaction` injects those signatures, computes the binding signature host-side, and extracts the signed V5 (ZIP-225) or V6 (ZIP-230) transaction.
5. **Broadcast** — `broadcastTransaction` submits it and returns the txid.

```typescript
import {
  buildTransaction,
  parsePczt,
  finalizeTransaction,
  broadcastTransaction,
  type PcztTransaction,
  type ShieldedNote,
} from "@ledgerhq/zcash-utils";

// A note found by a previous scan — its spending fields are what make it
// spendable (see Quick start above).
declare const note: ShieldedNote;

// Your wrapper around the signer kit's device action. It answers in bytes —
// `{ orchard: [{ spendAuthSig }], ironwood: [...], transparentInputSigs: [] }`
// — so hex-encoding the result is the caller's step. See the signer kit's own
// documentation for its exact shape.
declare function signOnDevice(pczt: PcztTransaction): Promise<{
  orchardSignatures: string[];
  transparentSignatures: string[];
}>;

const { pcztHex } = await buildTransaction({
  grpcUrl,
  // Required by any flow carrying an Orchard bundle. A fully transparent send
  // omits it and passes `transparentAccountPubkey` instead — spending public
  // funds must not require a viewing-key export from the device.
  ufvk: "uviewtest1...",
  network: "testnet",
  // Both read from the device: they let it confirm the PCZT is its own seed's.
  seedFingerprint: "<64-char hex>",
  accountIndex: 0,
  // Caller-owned, decimal zatoshis. Validated against ZIP-317, and change is
  // derived from it — this crate does not compute a fee.
  feeZat: "15000",
  spends: [
    {
      recipient: note.recipient!, // 86-char hex
      valueZat: String(note.amount),
      rho: note.rho!, // 64-char hex
      rseed: note.rseed!, // 64-char hex
      cmx: note.cmx!, // 64-char hex
      position: note.position!, // decimal u64 string
    },
  ],
  // Always present, empty for a shielded-only send.
  transparentInputs: [],
  outputs: [{ address: "u1...", valueZat: "85000", memo: "thanks!" }],
});

const { orchardSignatures, transparentSignatures } = await signOnDevice(parsePczt(pcztHex));

const { txHex, txid } = await finalizeTransaction({
  pczt: pcztHex,
  orchardSignatures, // one 128-hex-char RedPallas sig per real Orchard spend
  // Supply the list matching the PCZT's shielded bundle; the other may be
  // empty or omitted. Each is length-checked against the PCZT's unsigned
  // actions, so signatures for a pool the PCZT does not spend fail closed.
  ironwoodSignatures: [],
  transparentSignatures, // one DER-hex secp256k1 sig per transparent input
});

await broadcastTransaction(grpcUrl, txHex);
```

Only t-addresses (P2PKH/P2SH) and u-addresses with an Orchard receiver are accepted as destinations. Sapling z-addresses and TEX (ZIP-320) addresses are rejected.

`network` accepts `"mainnet"`, `"testnet"` and `"regtest"` on both builders. Regtest resolves to a local network whose upgrades activate in the first two blocks, so a freshly mined chain can craft a send instead of being refused for sitting below the real activation heights.

## API

Full signatures, every field, and its constraints are in [`index.d.ts`](index.d.ts), generated by napi-rs from the Rust doc comments — that file is the reference, not this table.

### Chain queries

| Export | Purpose |
| --- | --- |
| `getChainTip(grpcUrl)` | Current chain tip height. |
| `findBlockHeight(grpcUrl, timestamp)` | Height of the latest block at or before a Unix timestamp, by interpolation search. Clamps to genesis / tip. |

### Scanning

| Export | Purpose |
| --- | --- |
| `startSync(params)` | Starts scanning a block range in the background and returns a `TransactionStream`. Trial decryption runs entirely in Rust; `GetTransaction` is called only for matched transactions. |
| `TransactionStream` | Async iterator: `next()` yields the next match or `null` at end of scan, `cancel()` aborts the background task, `stats()` returns scan statistics once exhausted. |
| `transactionDetails(grpcUrl, requests, network?, ufvk?)` | Reads from raw transaction bytes what an explorer cannot: the true cross-pool fee, and — with a `ufvk` — the payees of shielded outputs. A transaction that cannot be fetched, parsed, or fully priced yields a `null` fee rather than an approximation. |

### Sending

| Export | Purpose |
| --- | --- |
| `buildTransaction(params)` | Builds, proves, and serializes a V5 PCZT from Orchard notes, transparent UTXOs, or both. Bears the Halo 2 proving cost inline (~2–5 s cold, ~hundreds of ms after, via a process-global proving-key cache). |
| `buildIronwoodTransaction(params)` | Same, for an Ironwood (NU6.3) source — a redacted V6 PCZT. See [Ironwood (NU6.3)](#ironwood-nu63) below. |
| `parsePczt(pcztHex)` | Decodes canonical PCZT bytes into the `PcztTransaction` the device signer consumes. Fails if a field the device needs to sign is missing. |
| `finalizeTransaction(params)` | Injects device signatures, computes the binding signature, extracts the signed transaction and its txid. CPU-bound (proof verification), dispatched to a blocking thread. |
| `broadcastTransaction(grpcUrl, txHex)` | Submits a signed transaction to a lightwalletd / Zaino endpoint; returns the txid. |

### Receiving

| Export | Purpose |
| --- | --- |
| `orchardAddressFromUfvk(ufvk)` | The Orchard-only unified address, derived exactly as the device derives it (external scope, diversifier index 0, single receiver) — so it passes on-device verification. Use this for the Receive flow. |

Production key derivation is deliberately **not** exported: a wallet takes its keys from the device. The `zcash-crypto` crate and the `ledger-zcash-cli` binary can derive keys for development, and the test-only surface below exposes a narrow slice of it for automated testing.

### Test-only surface

> **Never call these from wallet code.** Both take a mnemonic and hold spending-key material in process memory, which is exactly what a production host must not do. They exist so a wallet integrating this package can run its send flow in CI without a physical Ledger — they are the device stand-in, not part of the wallet.

| Export | Purpose |
| --- | --- |
| `testDeriveKeys(mnemonic, account, network)` | The account UFVK and transparent xpub a device would report for that seed. Feed them to `startSync` and `buildTransaction` in place of a device read. |
| `testSignPczt(mnemonic, account, network, pcztHex)` | Signs whichever bundles the PCZT carries and returns the signatures in the shape `finalizeTransaction` expects, standing in for step 3 of the send flow. |

They are published rather than hidden behind a build flag because the test harness that needs them consumes the same npm package as production code does. The `test` prefix and this warning are the whole guardrail; nothing prevents a call.

Both accept only `"mainnet"` and `"testnet"`. For a regtest chain, pass `"mainnet"` — this surface derives regtest keys under the mainnet convention, even though the builders take `"regtest"` as a `network` of its own.

## Value encoding

The same quantity is not spelled the same way everywhere in this API. Read this before wiring anything up.

**Zatoshi amounts.** The scanning path returns them as JS numbers (`ShieldedNote.amount`, `ShieldedTransaction.fee`, `transparentOut`). Every crafting and PCZT field instead uses a **decimal string** (`valueZat`, `feeZat`, `value`, `spendValue`, `valueBalance`), which avoids the precision loss of a `u64`/`i128` round-tripping through an f64.

**Txid byte order.** Three fields, three conventions:

| Field | Order |
| --- | --- |
| `ShieldedTransaction.txid`, `FinalizeTransactionResult.txid`, `TransactionDetailsRequest.txid`, `TransparentPrevout.txid` | Big-endian _display_ order — matches explorers and the Ledger Live operation hash. |
| `TransparentInputJs.txid` | Little-endian _internal_ order. Ledger Live surfaces txids in display order, so callers must reverse before passing. |
| `PcztTransparentInput.prevoutTxid` | Internal byte order, as stored in the PCZT. |

**`scriptPubKey`** keeps its canonical Bitcoin/Zcash casing, rather than napi's default camelCasing of the Rust field name (`scriptPubkey`).

## Errors

Every failure surfaces as a plain JavaScript `Error` whose message is the whole signal — there is no `code` property, no error subclass, and no numeric status. [`index.d.ts`](index.d.ts) documents, per function, what each one can fail on; the paragraphs below are what holds across all of them.

**The categories are stable, the wording is not.** Matching on message text is the only way to tell failures apart programmatically today, and it is a fragile contract: treat the distinctions documented per function as durable and the exact strings as not.

**Bad input fails before any work.** Every hex field, decimal-string amount and address is validated up front, so a malformed request costs no gRPC round trip and no proving time. Overflow on value totals is checked rather than wrapped.

**A finished scan is not a successful scan.** `startSync` never throws — it spawns the scan and returns — and `stream.next()` never throws either. It returns `null` both when the range is fully scanned and when the scan died part-way, and those two are indistinguishable from `next()` alone. The failure is reported by `stream.stats()`, and nowhere else, so a caller that persists notes must call `stats()` before treating the results as complete. Calling `stats()` twice, or after `cancel()`, is itself an error.

**A failed broadcast does not mean nothing was sent.** `SendTransaction rejected (code N)` is definitive: the node saw the transaction and refused it. `SendTransaction failed` is not — the request may have been accepted before the connection broke. The txid is derived from the transaction bytes, so it is known before broadcasting: look it up before retrying, rather than assuming the send did not happen.

**Nothing before `broadcastTransaction` leaves a trace.** Crafting and finalizing touch neither the chain nor the device, so any failure in them is safe to retry with the same inputs once corrected.

## Ironwood (NU6.3)

Ironwood is supported on both halves of the wallet, and the crates it rests on are on their stable releases.

Scanning is not gated by `orchardOnly`: `ShieldedTransaction.ironwoodNotes` is populated alongside `orchardNotes`, and `ShieldedNote.pool` tells the two apart. Crafting goes through `buildIronwoodTransaction`, which emits a V6 (ZIP-230) PCZT; `finalizeTransaction` and `broadcastTransaction` accept V6 as they do V5.

What that support is tested against is worth knowing, since the pool is young. Witness computation is checked offline against a real Ironwood anchor captured from a public testnet node, scanning from the NU6.3 testnet activation height. Trial decryption is exercised against a synthetic Ironwood action built from the `orchard` note-encryption API — genuine cryptography, but not a real on-chain transaction, because no Ironwood transaction addressed to a key we hold has been available to capture as a fixture.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — crate layout, dependency graph, design decisions
- [`docs/key-derivation.md`](docs/key-derivation.md) — BIP-39 → ZIP-32 → UFVK pipeline
- [`docs/block-sync.md`](docs/block-sync.md) — gRPC trial + full decryption
- [`docs/ffi-node.md`](docs/ffi-node.md) — this addon in depth, with worked examples
- [`docs/build-targets.md`](docs/build-targets.md) — build scripts and prerequisites
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — building, testing, CLI usage, release process

## License

[Apache-2.0](LICENSE.md)
