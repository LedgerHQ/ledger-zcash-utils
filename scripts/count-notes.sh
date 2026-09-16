#!/usr/bin/env bash
#
# Counts the shielded notes a viewing key can see, and prints counts only.
#
# Takes the UFVK from $ZCASH_BENCH_UFVK rather than an argument, so the key never lands in
# shell history or the process list:
#
#   read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK
#   ./scripts/count-notes.sh
#
# The network and endpoint are inferred from the key's own prefix, so a mainnet key cannot
# accidentally be scanned against testnet.
#
# Options:
#   --blocks N    scan only the first N blocks from the start height (quick plumbing check)
#   --from H      override the start height (default: Ironwood activation for that network)

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -z "${ZCASH_BENCH_UFVK:-}" ]]; then
  cat >&2 <<'EOF'
ZCASH_BENCH_UFVK is not set in this shell.

Load it without putting it in your shell history:

  read -rs ZCASH_BENCH_UFVK && export ZCASH_BENCH_UFVK

then run this script again from the same terminal.
EOF
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

# Unified viewing keys are HRP-prefixed: mainnet "uview1", testnet "uviewtest1".
case "$ZCASH_BENCH_UFVK" in
  uviewtest1*)
    NETWORK="testnet"
    GRPC_URL="https://zaino-zec-testnet.nodes.stg.ledger-test.com/"
    ACTIVATION=4134000
    ;;
  uview1*)
    NETWORK="mainnet"
    GRPC_URL="https://zec-indexer.coin.ledger-test.com"
    ACTIVATION=3428143
    ;;
  *)
    echo "key does not start with uview1 or uviewtest1 — is it a UFVK?" >&2
    exit 1
    ;;
esac

START="${FROM:-$ACTIVATION}"

args=(sync --grpc-url "$GRPC_URL" --viewing-key "$ZCASH_BENCH_UFVK"
      --network "$NETWORK" --start-height "$START" --max-retries 3 --format json)

if [[ -n "$BLOCKS" ]]; then
  args+=(--end-height "$(( START + BLOCKS - 1 ))")
fi

echo "network=$NETWORK from=$START${BLOCKS:+ blocks=$BLOCKS} — scanning, this can take minutes" >&2

cargo run -q -p zcash-cli -- "${args[@]}" 2>/dev/null | ./scripts/count-notes.py
