#!/usr/bin/env tsx
/**
 * Validation script: check that the native Rust engine correctly detects
 * Sapling and Orchard transactions belonging to Alice (standard testnet
 * account from zcash-android-wallet-sdk / sdk-incubator-lib).
 *
 * This is a *correctness* check, not a benchmark.
 *
 * Usage:
 *   tsx examples/sync-tx.node.ts [options]
 *
 * Options:
 *   --network <mainnet|testnet>   [default: testnet]
 *   --grpc-url <URL>              [default: https://testnet.zec.rocks:443]
 *   --start-height <N>            [default: Sapling activation height]
 *   --end-height <N>              [default: chain tip]
 *   --chunk-size <N>              Blocks per gRPC call [default: 50000]
 *   --expected-txids <a,b,...>    Comma-separated txids to assert presence of
 *
 * Alice's seed (never use with real funds — public test vector):
 *   wish puppy smile loan doll curve hole maze file ginger hair nose
 *   key relax knife witness cannon grab despair throw review deal slush frame
 */
import { parseArgs } from "node:util";
import { syncShielded, getChainTip, SyncResult, ShieldedNote } from "..";

// ── Alice's UFVK (testnet, account index 0) ──────────────────────────────────
const ALICE_UFVK =
  "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

// ── Config ────────────────────────────────────────────────────────────────────
const SAPLING_ACTIVATION: Record<string, number> = { testnet: 280_000, mainnet: 419_200 };
const DEFAULT_GRPC: Record<string, string> = {
  testnet: "https://testnet.zec.rocks:443",
  mainnet: "https://zec.rocks:443",
};

const { values } = parseArgs({
  options: {
    "network":        { type: "string", default: "testnet" },
    "grpc-url":       { type: "string" },
    "start-height":   { type: "string" },
    "end-height":     { type: "string" },
    "chunk-size":     { type: "string", default: "50000" },
    "expected-txids": { type: "string", default: "" },
  },
});

const network = values["network"]!;
if (!["testnet", "mainnet"].includes(network)) {
  console.error(`Error: --network must be "testnet" or "mainnet", got "${network}"`);
  process.exit(1);
}

const saplingActivation = SAPLING_ACTIVATION[network];
const grpcUrl           = values["grpc-url"] ?? DEFAULT_GRPC[network];
const rawStart          = values["start-height"] ? Number(values["start-height"]) : saplingActivation;
const startHeight       = Math.max(rawStart, saplingActivation);
const endHeightOverride = values["end-height"] ? Number(values["end-height"]) : null;
const chunkSize         = Number(values["chunk-size"]);
const expectedTxids     = values["expected-txids"]!
  .split(",").map((s) => s.trim()).filter(Boolean);

// ── Formatting helpers ────────────────────────────────────────────────────────
const ZAT_PER_ZEC = 100_000_000n;

function zatToZec(zat: number): string {
  const z = BigInt(Math.round(zat));
  const whole = z / ZAT_PER_ZEC;
  const frac  = z % ZAT_PER_ZEC;
  return `${whole}.${String(frac).padStart(8, "0")} ZEC`;
}

function pad(label: string, width = 18): string {
  return label.padEnd(width);
}

function printSeparator(char = "─", width = 72): void {
  console.log(char.repeat(width));
}

// ── Main ──────────────────────────────────────────────────────────────────────
console.log("╔══════════════════════════════════════════════════════════════════════╗");
console.log("║           Zcash native engine — Alice correctness check             ║");
console.log("╚══════════════════════════════════════════════════════════════════════╝");
console.log();
console.log(`${pad("Network")}${network}`);
console.log(`${pad("UFVK prefix")}${ALICE_UFVK.slice(0, 24)}…`);
console.log(`${pad("gRPC endpoint")}${grpcUrl}`);
console.log(`${pad("Block range")}${startHeight.toLocaleString()} → ${endHeightOverride != null ? endHeightOverride.toLocaleString() : "chain tip"}`);
if (rawStart < saplingActivation) {
  console.log(`${pad("NOTE")}--start-height ${rawStart} clamped to Sapling activation (${saplingActivation})`);
}
if (expectedTxids.length > 0) {
  console.log(`${pad("Expected txids")}${expectedTxids.length} provided`);
}
console.log();

// 1. Connect and resolve chain tip
process.stdout.write("Connecting to gRPC endpoint… ");
let tip: number;
try {
  tip = await getChainTip(grpcUrl);
  console.log(`OK  (chain tip = ${tip.toLocaleString()})`);
} catch (err) {
  console.log("FAILED");
  console.error(`\nCould not reach ${grpcUrl}:\n  ${(err as Error).message}`);
  process.exit(1);
}

const endHeight = Math.min(endHeightOverride ?? tip, tip);
console.log(`${pad("Effective range")}${startHeight.toLocaleString()} → ${endHeight.toLocaleString()} (${(endHeight - startHeight).toLocaleString()} blocks)`);

// 2. UFVK prefix sanity check
if (!ALICE_UFVK.startsWith("uviewtest")) {
  console.error("\nERROR: ALICE_UFVK does not start with 'uviewtest' — wrong network.");
  process.exit(1);
}
console.log("UFVK prefix check        OK  (starts with 'uviewtest')");

// 3. Scan
console.log();
printSeparator();
console.log(`Scanning ${(endHeight - startHeight).toLocaleString()} blocks…`);
printSeparator();
console.log();

const totalBlocks = endHeight - startHeight;
const chunks: Array<{ from: number; to: number }> = [];
for (let h = startHeight; h < endHeight; h += chunkSize) {
  chunks.push({ from: h, to: Math.min(h + chunkSize - 1, endHeight) });
}
console.log(`Chunk size      : ${chunkSize.toLocaleString()} blocks  (${chunks.length} chunks)`);
console.log();

const t0 = Date.now();
let totalBlocksScanned = 0;
const allTransactions: SyncResult["transactions"] = [];

for (let i = 0; i < chunks.length; i++) {
  const { from, to } = chunks[i];
  const pct      = ((from - startHeight) / totalBlocks * 100).toFixed(1);
  const elapsedS = ((Date.now() - t0) / 1_000).toFixed(0);
  process.stdout.write(
    `  [${String(i + 1).padStart(String(chunks.length).length)}/${chunks.length}]  ` +
    `${from.toLocaleString()}–${to.toLocaleString()}  (${pct}%  ${elapsedS}s elapsed)  … `
  );

  let chunk: SyncResult;
  try {
    chunk = await syncShielded({ grpcUrl, viewingKey: ALICE_UFVK, startHeight: from, endHeight: to, network });
  } catch (err) {
    console.error(`\n\nSync failed on chunk ${from}–${to}:\n  ${(err as Error).message}`);
    process.exit(1);
  }

  totalBlocksScanned += chunk.blocksScanned;
  allTransactions.push(...chunk.transactions);

  const blps  = Math.round(chunk.blocksScanned / (chunk.elapsedMs / 1_000));
  const txTag = chunk.transactions.length > 0 ? `  *** ${chunk.transactions.length} tx found ***` : "";
  console.log(`${blps.toLocaleString()} bl/s${txTag}`);
}

const wallMs = Date.now() - t0;
const result: SyncResult = { transactions: allTransactions, blocksScanned: totalBlocksScanned, elapsedMs: wallMs };

// 4. Summary
const blps = result.blocksScanned / (result.elapsedMs / 1_000);
console.log(`Blocks scanned  : ${result.blocksScanned.toLocaleString()}`);
console.log(`Rust elapsed    : ${result.elapsedMs.toFixed(0)} ms  (wall: ${wallMs} ms)`);
console.log(`Throughput      : ${Math.round(blps).toLocaleString()} bl/s`);
console.log(`Transactions    : ${result.transactions.length}`);
console.log();

// 5. Per-transaction detail
if (result.transactions.length === 0) {
  console.log("⚠  No transactions found for Alice in this range.");
  console.log("   • The range may not contain any of Alice's transactions.");
  console.log("   • prepare_ivks may have used the wrong network → wrong IVKs.");
  console.log("   • trial_decrypt_compact_block may have a decryption bug.");
  console.log();
} else {
  printSeparator();
  console.log("Matched transactions:");
  printSeparator();
  console.log();

  for (const tx of result.transactions) {
    console.log(`  TXID        ${tx.txid}`);
    console.log(`  Height      ${tx.blockHeight.toLocaleString()}`);
    console.log(`  Block hash  ${tx.blockHash}`);
    console.log(`  Time        ${new Date(tx.blockTime * 1_000).toISOString()}`);

    if (tx.saplingNotes.length > 0) {
      console.log(`  ── Sapling (${tx.saplingNotes.length} note${tx.saplingNotes.length > 1 ? "s" : ""})`);
      for (const n of tx.saplingNotes) {
        const memo = n.memo ? `  memo="${n.memo}"` : "";
        console.log(`     [${n.transferType.padEnd(8)}]  ${zatToZec(n.amount)}${memo}`);
      }
    }
    if (tx.orchardNotes.length > 0) {
      console.log(`  ── Orchard (${tx.orchardNotes.length} note${tx.orchardNotes.length > 1 ? "s" : ""})`);
      for (const n of tx.orchardNotes) {
        const memo = n.memo ? `  memo="${n.memo}"` : "";
        console.log(`     [${n.transferType.padEnd(8)}]  ${zatToZec(n.amount)}${memo}`);
      }
    }

    const protocols: string[] = [];
    if (tx.saplingNotes.length > 0) protocols.push("Sapling");
    if (tx.orchardNotes.length > 0) protocols.push("Orchard");
    console.log(`  Protocols   ${protocols.join(" + ")}`);

    const allNotes: ShieldedNote[] = [...tx.saplingNotes, ...tx.orchardNotes];
    const received = allNotes.filter((n) => n.transferType === "incoming").reduce((s, n) => s + n.amount, 0);
    const sent     = allNotes.filter((n) => n.transferType === "outgoing").reduce((s, n) => s + n.amount, 0);
    console.log(`  Net value   +${zatToZec(received)}  −${zatToZec(sent)}`);
    console.log();
  }
}

// 6. Balance summary
printSeparator();
console.log("Balance summary (accumulated across all matched transactions):");
printSeparator();

let saplingReceived = 0n, saplingSpent = 0n;
let orchardReceived = 0n, orchardSpent = 0n;

for (const tx of result.transactions) {
  for (const n of tx.saplingNotes) {
    const v = BigInt(Math.round(n.amount));
    if (n.transferType === "incoming")      saplingReceived += v;
    else if (n.transferType === "outgoing") saplingSpent   += v;
  }
  for (const n of tx.orchardNotes) {
    const v = BigInt(Math.round(n.amount));
    if (n.transferType === "incoming")      orchardReceived += v;
    else if (n.transferType === "outgoing") orchardSpent    += v;
  }
}

const saplingNet = saplingReceived - saplingSpent;
const orchardNet = orchardReceived - orchardSpent;
const totalNet   = saplingNet + orchardNet;

console.log(`  Sapling  received  ${zatToZec(Number(saplingReceived))}`);
console.log(`  Sapling  spent     ${zatToZec(Number(saplingSpent))}`);
console.log(`  Sapling  net       ${zatToZec(Number(saplingNet < 0n ? -saplingNet : saplingNet))}${saplingNet < 0n ? " (negative)" : ""}`);
console.log();
console.log(`  Orchard  received  ${zatToZec(Number(orchardReceived))}`);
console.log(`  Orchard  spent     ${zatToZec(Number(orchardSpent))}`);
console.log(`  Orchard  net       ${zatToZec(Number(orchardNet < 0n ? -orchardNet : orchardNet))}${orchardNet < 0n ? " (negative)" : ""}`);
console.log();
console.log(`  ─────────────────────────────────────`);
console.log(`  Total net balance  ${zatToZec(Number(totalNet < 0n ? -totalNet : totalNet))}${totalNet < 0n ? " (negative)" : ""}`);
console.log();

// 7. Expected txid assertions
let assertionsFailed = 0;
if (expectedTxids.length > 0) {
  printSeparator();
  console.log("Expected txid assertions:");
  printSeparator();
  const foundSet = new Set(result.transactions.map((t) => t.txid.toLowerCase()));
  for (const txid of expectedTxids) {
    const found = foundSet.has(txid.toLowerCase());
    console.log(`  [${found ? "PASS" : "FAIL"}]  ${txid}`);
    if (!found) assertionsFailed++;
  }
  console.log();
}

// 8. Verdict
printSeparator("═");
if (result.transactions.length === 0 && expectedTxids.length === 0) {
  console.log("VERDICT: INCONCLUSIVE — No transactions found, no expected txids given.");
  console.log("         Try --start-height 1130000 --end-height 1180000 for a known Alice tx.");
  process.exit(2);
} else if (assertionsFailed > 0) {
  console.log(`VERDICT: FAIL — ${assertionsFailed} expected txid(s) not found.`);
  process.exit(1);
} else if (result.transactions.length > 0) {
  console.log(`VERDICT: PASS — ${result.transactions.length} transaction(s) found for Alice.`);
  process.exit(0);
} else {
  console.log("VERDICT: PASS");
  process.exit(0);
}
