#!/usr/bin/env bash
# Build the iOS XCFramework for zcash-ffi-mobile (device + simulator).
# Requires: Rust toolchain (rustup) + Xcode (xcodebuild, lipo)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
BUILD_DIR="$REPO_ROOT/target/xcframework-staging"
INCLUDE_DIR="$REPO_ROOT/crates/zcash-ffi-mobile/include"
OUTPUT="$DIST_DIR/ZcashFfiMobile.xcframework"
LIB="libzcash_ffi_mobile.a"

# `mobile`, NOT `release`. Under `lto = true` rustc emits LLVM bitcode instead of
# native objects; Xcode's toolchain cannot read Rust's LLVM 22 bitcode and the
# archive exports no symbols ("Unknown attribute kind (105)"). See [profile.mobile]
# in Cargo.toml.
PROFILE="mobile"

# Opt-in cargo features, e.g. ZCASH_FFI_FEATURES=sync. Off by default: `sync`
# links tokio, tonic, hyper and rustls.
FEATURE_ARGS=()
if [ -n "${ZCASH_FFI_FEATURES:-}" ]; then
    FEATURE_ARGS=(--features "$ZCASH_FFI_FEATURES")
    echo "Building with features: $ZCASH_FFI_FEATURES"
fi

# Simulator slices are lipo'd into one fat archive. x86_64 covers Intel Macs; drop
# it from SIM_TARGETS if the team is entirely on Apple Silicon and build time matters.
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")

cd "$REPO_ROOT"

echo "Installing required Rust targets..."
rustup target add "$DEVICE_TARGET" "${SIM_TARGETS[@]}"

for target in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
    echo ""
    echo "Building for $target (profile: $PROFILE)..."
    cargo build --profile "$PROFILE" --target "$target" -p zcash-ffi-mobile ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}
done

# xcodebuild refuses to overwrite an existing .xcframework, so clear prior output.
if [ -d "$BUILD_DIR" ]; then rm -r "$BUILD_DIR"; fi
if [ -d "$OUTPUT" ]; then rm -r "$OUTPUT"; fi
mkdir -p "$BUILD_DIR/simulator" "$DIST_DIR"

echo ""
echo "Creating fat simulator archive with lipo..."
sim_inputs=()
for target in "${SIM_TARGETS[@]}"; do
    sim_inputs+=("$REPO_ROOT/target/$target/$PROFILE/$LIB")
done
lipo -create -output "$BUILD_DIR/simulator/$LIB" "${sim_inputs[@]}"

echo ""
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -library "$REPO_ROOT/target/$DEVICE_TARGET/$PROFILE/$LIB" -headers "$INCLUDE_DIR" \
    -library "$BUILD_DIR/simulator/$LIB"                      -headers "$INCLUDE_DIR" \
    -output "$OUTPUT"

# A silently symbol-less archive is the failure mode this whole profile guards
# against, so assert the symbols are actually there rather than trusting the build.
#
# `nm` exits 1 here even on a good archive: Rust's precompiled `std` for the iOS
# targets carries embedded LLVM bitcode that Apple's nm cannot parse ("Unknown
# attribute kind (105)", ~67 std members). That is upstream, unrelated to
# [profile.mobile], and does not affect our own objects. So decide on the captured
# output, never on nm's exit status — and keep `|| true` so `set -o pipefail`
# does not turn nm's grumbling into a build failure.
echo ""
echo "Verifying exported C symbols..."
for slice in "$OUTPUT"/*/"$LIB"; do
    echo "  $slice"
    symbols="$(nm -g "$slice" 2>/dev/null | grep -E ' T _zcash_' || true)"
    if [ -z "$symbols" ]; then
        echo "    ERROR: no exported _zcash_* symbols found." >&2
        echo "    Was this built with --release instead of --profile mobile?" >&2
        exit 1
    fi
    echo "$symbols" | sed 's/^/    /'
done

echo ""
echo "Done: $OUTPUT"
lipo -info "$OUTPUT"/*/"$LIB"
