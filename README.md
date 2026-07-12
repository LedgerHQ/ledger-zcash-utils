# @ledgerhq/zcash-utils

Native Node.js (NAPI) addon for Zcash shielded transaction scanning — built in Rust via [napi-rs](https://napi.rs).

## Installation

```sh
npm install @ledgerhq/zcash-utils
# or
pnpm add @ledgerhq/zcash-utils
```

## Quick start

```typescript
import { startSync, getChainTip } from "@ledgerhq/zcash-utils";

const tip = await getChainTip(
  "https://zaino-zec-testnet.nodes.stg.ledger-test.com/",
);

const stream = await startSync({
  grpcUrl: "https://zaino-zec-testnet.nodes.stg.ledger-test.com/",
  viewingKey: "uviewtest1...",
  startHeight: tip - 1000,
  endHeight: tip,
  network: "testnet",
  orchardOnly: true,
});

let tx;
while ((tx = await stream.next()) !== null) {
  console.log(tx.txid, tx.orchardNotes);
}

const stats = await stream.stats();
console.log(`Scanned ${stats.blocksScanned} blocks in ${stats.elapsedMs}ms`);
```

## API

### `startSync(params: SyncParams): Promise<TransactionStream>`

Starts scanning a range of compact blocks and returns a transaction stream. The scan runs in the background immediately in Rust — no JS event loop blocking. `GetTransaction` is called only for matched transactions.

### `getChainTip(grpcUrl: string): Promise<number>`

Returns the current chain tip height from the gRPC endpoint.

### `TransactionStream`

Async iterator over matched shielded transactions.

| Method                                         | Description                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `next(): Promise<ShieldedTransaction \| null>` | Returns the next matched transaction, or `null` when the scan is complete.                        |
| `cancel(): void`                               | Cancels the background scan immediately. Buffered transactions are still consumable via `next()`. |
| `stats(): Promise<SyncStats>`                  | Returns scan statistics once the stream is exhausted.                                             |

## Types

### `SyncParams`

```typescript
interface SyncParams {
  /** gRPC endpoint URL */
  grpcUrl: string;
  /** Unified Full Viewing Key (UFVK) for the account to scan */
  viewingKey: string;
  /** First block height to scan (inclusive) */
  startHeight: number;
  /** Last block height to scan (inclusive) */
  endHeight: number;
  /** "mainnet" or "testnet" (default: "testnet") */
  network?: string;
  /**
   * When true, only Orchard actions are processed — eliminates all Sapling
   * crypto work. Set to true for Ledger wallets (Orchard-only support).
   */
  orchardOnly?: boolean;
  /**
   * Maximum retry attempts per range on transient errors.
   * The failing range is split in half on each retry. Defaults to 3.
   */
  maxRetries?: number;
  /** Emit per-phase timing diagnostics to stderr every 10 seconds */
  verbose?: boolean;
}
```

### `ShieldedTransaction`

```typescript
interface ShieldedTransaction {
  txid: string; // Transaction ID (big-endian hex)
  hex: string; // Raw transaction bytes (hex)
  blockHeight: number;
  blockHash: string; // Block hash (big-endian hex)
  blockTime: number; // Unix timestamp (seconds)
  fee: number; // Fee in zatoshis
  saplingNotes: ShieldedNote[];
  orchardNotes: ShieldedNote[];
  ironwoodNotes: ShieldedNote[]; // Ironwood (NU6.3) pool notes
}
```

### `ShieldedNote`

```typescript
interface ShieldedNote {
  amount: number; // Amount in zatoshis
  transferType: string; // "incoming", "outgoing", or "internal"
  memo: string;
  pool: string; // "sapling", "orchard", or "ironwood" — the shielded pool this note belongs to
}
```

### `SyncStats`

```typescript
interface SyncStats {
  blocksScanned: number;
  elapsedMs: number;
}
```

## License

MIT OR Apache-2.0
