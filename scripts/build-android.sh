#!/usr/bin/env bash
# Build Android JNI shared libraries (.so) for all supported ABIs and generate
# Kotlin UniFFI bindings.
#
# Prerequisites:
#   - Android NDK r26+ installed (ANDROID_NDK_HOME or ANDROID_HOME set)
#   - cargo-ndk: cargo install cargo-ndk
#   - Rust Android targets: installed automatically by this script
#
# Output: dist/android/
#   jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}/libzcash_ffi_mobile.so
#   kotlin/app/zcash/uniffi/zcash.kt  (generated Kotlin bindings)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/android"

# Auto-detect NDK from ANDROID_HOME if ANDROID_NDK_HOME is not set
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    if [[ -n "${ANDROID_HOME:-}" ]] && [[ -d "$ANDROID_HOME/ndk" ]]; then
        NDK_VERSION=$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
        echo "Auto-detected NDK: $ANDROID_NDK_HOME"
    else
        echo "Error: ANDROID_NDK_HOME is not set and could not be auto-detected." >&2
        echo "       Set ANDROID_NDK_HOME to your NDK path (e.g. ~/Library/Android/sdk/ndk/28.x.y)" >&2
        exit 1
    fi
fi

# target:abi pairs — space-separated, one per line
TARGETS="aarch64-linux-android:arm64-v8a
armv7-linux-androideabi:armeabi-v7a
i686-linux-android:x86
x86_64-linux-android:x86_64"

echo "Installing Android Rust targets..."
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

while IFS=: read -r TARGET ABI; do
    echo ""
    echo "Building $TARGET ($ABI)..."
    cargo ndk \
        --target "$TARGET" \
        --platform 21 \
        --output-dir "$DIST_DIR/jniLibs" \
        build --release -p zcash-ffi-mobile
done <<< "$TARGETS"

echo ""
echo "Generating Kotlin UniFFI bindings..."
KOTLIN_OUT="$DIST_DIR/kotlin/app/zcash/uniffi"
mkdir -p "$KOTLIN_OUT"
cargo run -p zcash-ffi-mobile --bin uniffi-bindgen -- generate \
    crates/zcash-ffi-mobile/src/zcash.udl \
    --language kotlin \
    --out-dir "$KOTLIN_OUT"

echo ""
echo "Done: $DIST_DIR"
echo "  JNI libraries: $DIST_DIR/jniLibs/"
echo "  Kotlin bindings: $KOTLIN_OUT/"
