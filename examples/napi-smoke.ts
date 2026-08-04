#!/usr/bin/env tsx
/**
 * NAPI surface smoke tests — run after rebuilding the native addon.
 *
 * Purpose: verify the full call chain for each exported function:
 *   JS string/args → Rust → JS return value, plus error propagation.
 *   TypeScript compilation (via tsx) also validates index.d.ts is in sync.
 *
 * Add a section here whenever a new #[napi] function is introduced.
 *
 * Usage:
 *   pnpm napi-smoke
 */
import { orchardAddressFromUfvk } from "..";

let passed = 0;
let failed = 0;

function pass(label: string, detail: string) {
  console.log(`  ✓  ${label}: ${detail}`);
  passed++;
}

function fail(label: string, detail: string) {
  console.error(`  ✗  ${label}: ${detail}`);
  failed++;
}

// ── orchardAddressFromUfvk ─────────────────────────────────────────────────────
// Vectors from crates/zcash-crypto/tests/get_orchard_address.rs — must stay in sync.

console.log("\norchardAddressFromUfvk:");

const ORCHARD_CASES = [
  {
    label: "account 0",
    ufvk: "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar",
    expected: "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9",
  },
  {
    label: "account 1",
    ufvk: "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf",
    expected: "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e",
  },
];

for (const { label, ufvk, expected } of ORCHARD_CASES) {
  const result = orchardAddressFromUfvk(ufvk);
  result === expected
    ? pass(label, result)
    : fail(label, `expected ${expected}, got ${result}`);
}

for (const { label, input } of [
  { label: "empty string",   input: "" },
  { label: "garbage input",  input: "notavalidufvk" },
  { label: "truncated UFVK", input: ORCHARD_CASES[0]!.ufvk.slice(0, 40) },
]) {
  try {
    const result = orchardAddressFromUfvk(input);
    fail(label, `expected throw, got: ${result}`);
  } catch (e) {
    pass(label, `threw — ${(e as Error).message}`);
  }
}

// ── Summary ────────────────────────────────────────────────────────────────────
console.log(`\n${passed + failed} checks: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
