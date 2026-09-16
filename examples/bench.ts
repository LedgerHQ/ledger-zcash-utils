#!/usr/bin/env tsx
/**
 * Benchmark: scan a block range with the native Rust sync engine.
 *
 * Usage:
 *   tsx examples/bench.ts [options]
 *
 * Options:
 *   --viewing-key <UFVK>   Unified Full Viewing Key  [default: Alice testnet UFVK]
 *   --grpc-url <URL>       gRPC endpoint             [default: https://zaino-zec-testnet.nodes.stg.ledger-test.com/]
 *   --start-height <N>     First block (inclusive)   [default: 280000]
 *   --end-height <N>       Last block (inclusive)    [default: 285000]
 *   --verbose              Emit Rust diagnostics to stderr every 10s
 */
import { parseArgs } from "node:util";
import { startSync, ShieldedTransaction } from "..";

// Alice's UFVK — public test vector, never use with real funds.
const ALICE_UFVK =
  "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

// A real account's UFVK should reach this script through the environment, never on a
// command line: argv is visible in shell history and in the process list, and a viewing
// key exposes that account's entire transaction history. `--viewing-key` stays supported
// for the public test vector.
//
//   read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK
//
const { values } = parseArgs({
  options: {
    "viewing-key":  { type: "string",  default: process.env.ZCASH_BENCH_UFVK ?? ALICE_UFVK },
    "grpc-url":     { type: "string",  default: "https://zaino-zec-testnet.nodes.stg.ledger-test.com/" },
    "start-height": { type: "string",  default: "280000" },
    "end-height":   { type: "string",  default: "285000" },
    "verbose":      { type: "boolean", default: false },
  },
});

const viewingKey  = values["viewing-key"]!;
const grpcUrl     = values["grpc-url"]!;
const startHeight = Number(values["start-height"]);
const endHeight   = Number(values["end-height"]);
const verbose     = values["verbose"]!;

console.log(`Scanning blocks ${startHeight}–${endHeight} via ${grpcUrl} ...`);

const stream = await startSync({ grpcUrl, viewingKey, startHeight, endHeight, verbose });
const transactions: ShieldedTransaction[] = [];
let tx: ShieldedTransaction | null;
while ((tx = await stream.next()) !== null) {
  transactions.push(tx);
}
const stats = await stream.stats();

const blps = stats.blocksScanned / (stats.elapsedMs / 1000);

const mib = stats.bytesDownloaded / 1024 / 1024;
const bytesPerBlock = stats.bytesDownloaded / stats.blocksScanned;
const mibPerSec = mib / (stats.elapsedMs / 1000);
const decryptMsPerBlock = stats.trialDecryptMs / stats.blocksScanned;

console.log(`\nResults:`);
console.log(`  Blocks scanned : ${stats.blocksScanned}`);
console.log(`  Elapsed        : ${stats.elapsedMs.toFixed(0)} ms`);
console.log(`  Speed          : ${Math.round(blps).toLocaleString()} bl/s`);
console.log(`  Transactions   : ${transactions.length}`);

// Download side — what a first sync costs in mobile data.
console.log(`\nDownload:`);
console.log(`  Payload        : ${mib.toFixed(2)} MiB (protobuf only, no TLS/HTTP2 framing)`);
console.log(`  Per block      : ${bytesPerBlock.toFixed(0)} bytes`);
console.log(`  Throughput     : ${mibPerSec.toFixed(2)} MiB/s`);

// CPU side. trialDecryptMs is summed across concurrently decrypted blocks, so it is
// a measure of work rather than elapsed time — which is why the per-block figure,
// not the total, is what carries across devices.
console.log(`\nDecryption (aggregate CPU, not wall clock):`);
console.log(`  Trial decrypt  : ${stats.trialDecryptMs.toFixed(0)} ms total`);
console.log(`  Per block      : ${decryptMsPerBlock.toFixed(3)} ms`);
console.log(`  Full decrypt   : ${stats.fullDecryptMs.toFixed(0)} ms${transactions.length === 0 ? "  (no matches — this path never ran)" : ""}`);
console.log(`  GetTransaction : ${stats.getTransactionMs.toFixed(0)} ms`);

// Extrapolation to the case that actually matters: a full rewind from Ironwood
// activation. Linear in blocks, which is the right shape for both quantities.
const IRONWOOD_HISTORY_BLOCKS = 55_296;
const scale = IRONWOOD_HISTORY_BLOCKS / stats.blocksScanned;
console.log(`\nExtrapolated to a full Ironwood rewind (${IRONWOOD_HISTORY_BLOCKS.toLocaleString()} blocks):`);
console.log(`  Download       : ${(mib * scale).toFixed(0)} MiB`);
console.log(`  Decrypt work   : ${((stats.trialDecryptMs * scale) / 1000).toFixed(1)} s of CPU`);
console.log(`  (this host)    : ${((stats.elapsedMs * scale) / 1000).toFixed(1)} s wall clock`);

if (transactions.length > 0) {
  console.log(`\nMatched transactions:`);
  for (const tx of transactions) {
    // Ironwood notes count too: omitting them reported "total=0 zat" for every
    // transaction of an Ironwood-only account, which is every Ledger account today.
    const notes = [...tx.saplingNotes, ...tx.orchardNotes, ...tx.ironwoodNotes];
    const total = notes.reduce((s, n) => s + n.amount, 0);
    console.log(`  ${tx.txid}  height=${tx.blockHeight}  total=${total} zat  fee=${tx.fee} zat`);
  }
}
