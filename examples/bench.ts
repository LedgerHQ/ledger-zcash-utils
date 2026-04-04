#!/usr/bin/env tsx
/**
 * Benchmark: scan a block range with the native Rust sync engine.
 *
 * Usage:
 *   tsx examples/bench.ts [options]
 *
 * Options:
 *   --viewing-key <UFVK>   Unified Full Viewing Key  [default: Alice testnet UFVK]
 *   --grpc-url <URL>       gRPC endpoint             [default: https://testnet.zec.rocks:443]
 *   --start-height <N>     First block (inclusive)   [default: 280000]
 *   --end-height <N>       Last block (inclusive)    [default: 285000]
 */
import { parseArgs } from "node:util";
import { syncShielded, SyncResult } from "..";

// Alice's UFVK — public test vector, never use with real funds.
const ALICE_UFVK =
  "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

const { values } = parseArgs({
  options: {
    "viewing-key":  { type: "string",  default: ALICE_UFVK },
    "grpc-url":     { type: "string",  default: "https://testnet.zec.rocks:443" },
    "start-height": { type: "string",  default: "280000" },
    "end-height":   { type: "string",  default: "285000" },
  },
});

const viewingKey  = values["viewing-key"]!;
const grpcUrl     = values["grpc-url"]!;
const startHeight = Number(values["start-height"]);
const endHeight   = Number(values["end-height"]);

console.log(`Scanning blocks ${startHeight}–${endHeight} via ${grpcUrl} ...`);

const result: SyncResult = await syncShielded({ grpcUrl, viewingKey, startHeight, endHeight });

const blps = result.blocksScanned / (result.elapsedMs / 1000);

console.log(`\nResults:`);
console.log(`  Blocks scanned : ${result.blocksScanned}`);
console.log(`  Elapsed        : ${result.elapsedMs.toFixed(0)} ms`);
console.log(`  Speed          : ${Math.round(blps).toLocaleString()} bl/s`);
console.log(`  Transactions   : ${result.transactions.length}`);

if (result.transactions.length > 0) {
  console.log(`\nMatched transactions:`);
  for (const tx of result.transactions) {
    const notes = [...tx.saplingNotes, ...tx.orchardNotes];
    const total = notes.reduce((s, n) => s + n.amount, 0);
    console.log(`  ${tx.txid}  height=${tx.blockHeight}  total=${total} zat`);
  }
}
