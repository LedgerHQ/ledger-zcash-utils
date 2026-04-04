#!/usr/bin/env bash
# Build a static ledger-zcash-cli binary for Linux x86_64.
# Target triple: x86_64-unknown-linux-musl (fully static, no libc dependency).
#
# Uses the local musl-cross toolchain if available (brew install filosottile/musl-cross/musl-cross).
# Falls back to Docker (rust:latest) if the local linker is not found.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
OUTPUT="$DIST_DIR/ledger-zcash-cli-linux-x86_64"

mkdir -p "$DIST_DIR"
cd "$REPO_ROOT"

MUSL_CC="x86_64-linux-musl-gcc"

if command -v "$MUSL_CC" &>/dev/null; then
    echo "Building ledger-zcash-cli (release, Linux x86_64 musl, local toolchain)..."
    rustup target add x86_64-unknown-linux-musl
    CC_x86_64_unknown_linux_musl="$MUSL_CC" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_CC" \
    cargo build --release -p zcash-cli --target x86_64-unknown-linux-musl
else
    echo "musl-cross not found locally — falling back to Docker..."
    docker run --rm \
        --platform linux/amd64 \
        -v "$REPO_ROOT:/workspace" \
        -w /workspace \
        rust:latest \
        bash -c "
            set -euo pipefail
            rustup target add x86_64-unknown-linux-musl
            apt-get update -qq && apt-get install -y -qq musl-tools
            cargo build --release -p zcash-cli --target x86_64-unknown-linux-musl
        "
fi

cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/ledger-zcash-cli" "$OUTPUT"

echo ""
echo "Done: $OUTPUT"
file "$OUTPUT"
