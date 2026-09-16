#!/usr/bin/env bash
#
# Runs examples/bench.ts against the account in $ZCASH_BENCH_UFVK and prints the
# download / decryption split.
#
# Same contract as count-notes.sh: the key comes from the environment, never from an
# argument, and the network is inferred from the key's own prefix. Unlike the CLI, this
# path reports the timing breakdown — trial decryption, full decryption and
# GetTransaction — because those fields only surface through the NAPI layer.
#
#   read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK
#   ./scripts/bench-account.sh
#
# Options:
#   --blocks N   scan only the first N blocks from the start height
#   --from H     override the start height (default: Ironwood activation)

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -z "${ZCASH_BENCH_UFVK:-}" ]]; then
  echo "ZCASH_BENCH_UFVK is not set. Run: read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK" >&2
  exit 1
fi

BLOCKS=""
FROM=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --blocks) BLOCKS="$2"; shift 2 ;;
    --from)   FROM="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

case "$ZCASH_BENCH_UFVK" in
  uviewtest1*)
    GRPC_URL="https://zaino-zec-testnet.nodes.stg.ledger-test.com/"
    ACTIVATION=4134000
    ;;
  uview1*)
    GRPC_URL="https://zec-indexer.coin.ledger-test.com"
    ACTIVATION=3428143
    ;;
  *)
    echo "key does not start with uview1 or uviewtest1 — is it a UFVK?" >&2
    exit 1
    ;;
esac

START="${FROM:-$ACTIVATION}"

if [[ -n "$BLOCKS" ]]; then
  END=$(( START + BLOCKS - 1 ))
else
  # Default to the chain tip, so a full-history run needs no manual height.
  END=$(cargo run -q -p zcash-cli -- tip --grpc-url "$GRPC_URL" 2>/dev/null | tr -d '[:space:]')
  if ! [[ "$END" =~ ^[0-9]+$ ]]; then
    echo "could not query the chain tip from $GRPC_URL" >&2
    exit 1
  fi
fi

echo "Scanning $START..$END ($(( END - START + 1 )) blocks)" >&2
npx tsx examples/bench.ts --grpc-url "$GRPC_URL" --start-height "$START" --end-height "$END"
