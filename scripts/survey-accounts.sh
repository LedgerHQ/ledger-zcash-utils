#!/usr/bin/env bash
#
# Surveys ZIP-32 accounts of one seed and reports how many shielded notes each holds.
#
# Answers "which account is worth benchmarking against" without anyone having to look at,
# paste or transmit key material:
#
#   - the mnemonic is read from the terminal with echo off, and is piped to `derive` on
#     stdin — never in argv, so never in shell history or the process list;
#   - each account's UFVK is held in a shell variable for the length of one scan and is
#     never printed;
#   - the only output is counts.
#
# Usage:
#   ./scripts/survey-accounts.sh [--accounts N] [--network mainnet|testnet]
#                               [--grpc-url URL] [--start-height H] [--end-height H]
#
# Defaults scan the Ironwood range on mainnet, which is what a Ledger account can hold.

set -euo pipefail

ACCOUNTS=6
NETWORK="mainnet"
GRPC_URL=""
START_HEIGHT=""
END_HEIGHT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --accounts)     ACCOUNTS="$2"; shift 2 ;;
    --network)      NETWORK="$2"; shift 2 ;;
    --grpc-url)     GRPC_URL="$2"; shift 2 ;;
    --start-height) START_HEIGHT="$2"; shift 2 ;;
    --end-height)   END_HEIGHT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$GRPC_URL" ]]; then
  if [[ "$NETWORK" == "mainnet" ]]; then
    GRPC_URL="https://zec-indexer.coin.ledger-test.com"
  else
    GRPC_URL="https://zaino-zec-testnet.nodes.stg.ledger-test.com/"
  fi
fi

# Ironwood (NU6.3) activation — the earliest block a Ledger-created shielded account can
# hold a note. Scanning from here rather than from Sapling activation keeps the survey to
# minutes instead of hours.
if [[ -z "$START_HEIGHT" ]]; then
  if [[ "$NETWORK" == "mainnet" ]]; then START_HEIGHT=3428143; else START_HEIGHT=4134000; fi
fi

CLI=(cargo run -q -p zcash-cli --)

echo "Surveying accounts 0..$((ACCOUNTS - 1)) on $NETWORK from height $START_HEIGHT"
echo "Endpoint: $GRPC_URL"
echo

# -s: no echo. -r: backslashes are literal. The mnemonic lives only in this variable.
read -rsp "BIP-39 mnemonic (input hidden, not echoed, not stored): " MNEMONIC
echo
echo

if [[ -z "$MNEMONIC" ]]; then
  echo "No mnemonic entered — nothing to do." >&2
  exit 1
fi

printf "%-8s  %-6s  %-8s  %-8s  %-8s  %-7s\n" account txs ironwood orchard sapling spent
printf "%-8s  %-6s  %-8s  %-8s  %-8s  %-7s\n" -------- ------ -------- -------- -------- -------

BEST_ACCOUNT=""
BEST_NOTES=-1

for (( account = 0; account < ACCOUNTS; account++ )); do
  # Mnemonic goes in on stdin, so it never appears in the argument list.
  ufvk=$(printf '%s' "$MNEMONIC" \
    | "${CLI[@]}" derive --account "$account" --network "$NETWORK" --format json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["ufvk"])')

  sync_args=(sync --grpc-url "$GRPC_URL" --viewing-key "$ufvk"
             --network "$NETWORK" --start-height "$START_HEIGHT"
             --max-retries 3 --format json)
  [[ -n "$END_HEIGHT" ]] && sync_args+=(--end-height "$END_HEIGHT")

  # The UFVK is passed to one child process and then goes out of scope. Counts only.
  counts=$("${CLI[@]}" "${sync_args[@]}" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
txs = d["transactions"]
iron = sum(len(t["ironwood_notes"]) for t in txs)
orch = sum(len(t["orchard_notes"]) for t in txs)
sapl = sum(len(t["sapling_notes"]) for t in txs)
spent = sum(
    1
    for t in txs
    for pool in ("ironwood_notes", "orchard_notes", "sapling_notes")
    for n in t[pool]
    if n["is_spent"]
)
print(len(txs), iron, orch, sapl, spent)
') || counts="? ? ? ? ?"
  unset ufvk

  read -r txs iron orch sapl spent <<< "$counts"
  printf "%-8s  %-6s  %-8s  %-8s  %-8s  %-7s\n" "$account" "$txs" "$iron" "$orch" "$sapl" "$spent"

  if [[ "$iron" =~ ^[0-9]+$ ]]; then
    total=$(( iron + orch + sapl ))
    if (( total > BEST_NOTES )); then BEST_NOTES=$total; BEST_ACCOUNT=$account; fi
  fi
done

unset MNEMONIC

echo
if (( BEST_NOTES > 0 )); then
  echo "Most notes: account $BEST_ACCOUNT with $BEST_NOTES."
  echo
  echo "For the per-note benchmark, export that account's UFVK into the environment"
  echo "rather than passing it on a command line:"
  echo
  echo "  read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK"
  echo "  pnpm bench --start-height $START_HEIGHT"
else
  echo "No notes found in accounts 0..$((ACCOUNTS - 1)) over this range."
  echo "Either the funds predate Ironwood activation, or they are on the other network."
fi
