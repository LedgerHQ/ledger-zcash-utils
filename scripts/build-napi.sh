#!/usr/bin/env bash
# Build the Node.js / Electron native addon (.node) for the current host platform.
# Output: index.*.node at the workspace root (loaded by index.js).
#
# Usage:
#   ./scripts/build-napi.sh            # release build
#   DEBUG=1 ./scripts/build-napi.sh    # debug build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

echo "Installing Node dependencies..."
pnpm install

if [[ "${DEBUG:-}" == "1" ]]; then
    echo "Building NAPI addon (debug)..."
    pnpm napi build --platform --cargo-cwd crates/zcash-ffi-node
else
    echo "Building NAPI addon (release)..."
    pnpm napi build --platform --release --cargo-cwd crates/zcash-ffi-node
fi

echo ""
echo "Done. Output: index.*.node"
ls -lh "$REPO_ROOT"/index.*.node 2>/dev/null || true
