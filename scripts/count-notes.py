#!/usr/bin/env python3
"""Summarise `ledger-zcash-cli sync --format json` output as counts only.

Reads the JSON on stdin and prints one line of totals. Deliberately prints no amounts,
addresses, nullifiers or keys, so the output is safe to paste into a ticket or a chat
while the scan itself stays local.

Usage:
    ledger-zcash-cli sync --format json ... | scripts/count-notes.py
"""

import json
import sys


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        # The most common cause is the CLI erroring out and printing nothing, with
        # stderr sent to /dev/null by the caller.
        print(f"no JSON on stdin ({exc}) — did the sync fail?", file=sys.stderr)
        return 1

    txs = data.get("transactions", [])
    pools = ("ironwood_notes", "orchard_notes", "sapling_notes")

    totals = {pool: sum(len(tx.get(pool, [])) for tx in txs) for pool in pools}
    notes = [note for tx in txs for pool in pools for note in tx.get(pool, [])]
    spent = sum(1 for note in notes if note.get("is_spent"))

    # Block spread matters for the sync design: notes concentrated in a few blocks
    # exercise different behaviour from notes spread across the range.
    heights = sorted({tx.get("block_height") for tx in txs if tx.get("block_height")})
    spread = f"{heights[0]}..{heights[-1]}" if heights else "n/a"

    print(
        f"blocks={data.get('blocks_scanned', '?')} "
        f"elapsed_ms={data.get('elapsed_ms', '?')} "
        f"txs={len(txs)} "
        f"notes={len(notes)} "
        f"(ironwood={totals['ironwood_notes']} "
        f"orchard={totals['orchard_notes']} "
        f"sapling={totals['sapling_notes']}) "
        f"spent={spent} unspent={len(notes) - spent} "
        f"height_range={spread}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
