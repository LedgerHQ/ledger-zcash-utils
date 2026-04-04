#!/usr/bin/env bash
# Build an iOS XCFramework containing Zcash crypto operations and generate
# Swift UniFFI bindings.
#
# Prerequisites:
#   - macOS with Xcode installed
#   - Rust iOS targets: installed automatically by this script
#
# Output: dist/ios/
#   ZcashFFI.xcframework          (static libraries + headers for Xcode)
#   swift/zcash.swift             (generated Swift bindings)
#   swift/zcashFFI.h              (C header for bridging)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/ios"
LIB_DIR="$DIST_DIR/lib"
SWIFT_DIR="$DIST_DIR/swift"
HEADER_DIR="$SWIFT_DIR/headers"

cd "$REPO_ROOT"

echo "Installing iOS Rust targets..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

for TARGET in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    echo ""
    echo "Building $TARGET..."
    cargo build --release -p zcash-ffi-mobile --target "$TARGET"
done

mkdir -p "$LIB_DIR" "$HEADER_DIR"

echo ""
echo "Creating fat simulator library (arm64-sim + x86_64)..."
lipo -create -output "$LIB_DIR/libzcash_ffi_mobile-sim.a" \
    "$REPO_ROOT/target/aarch64-apple-ios-sim/release/libzcash_ffi_mobile.a" \
    "$REPO_ROOT/target/x86_64-apple-ios/release/libzcash_ffi_mobile.a"

cp "$REPO_ROOT/target/aarch64-apple-ios/release/libzcash_ffi_mobile.a" \
   "$LIB_DIR/libzcash_ffi_mobile-ios.a"

echo ""
echo "Generating Swift UniFFI bindings..."
mkdir -p "$SWIFT_DIR"
cargo run -p zcash-ffi-mobile --bin uniffi-bindgen -- generate \
    crates/zcash-ffi-mobile/src/zcash.udl \
    --language swift \
    --out-dir "$SWIFT_DIR"

# Copy generated C header into the headers directory for XCFramework
cp "$SWIFT_DIR/zcashFFI.h" "$HEADER_DIR/"

# Create module.modulemap for Swift bridging
cat > "$HEADER_DIR/module.modulemap" << 'EOF'
module ZcashFFI {
    header "zcashFFI.h"
    export *
}
EOF

echo ""
echo "Creating XCFramework..."
# Remove stale XCFramework if it exists (xcodebuild will error otherwise)
rm -rf "$DIST_DIR/ZcashFFI.xcframework"

xcodebuild -create-xcframework \
    -library "$LIB_DIR/libzcash_ffi_mobile-ios.a" \
        -headers "$HEADER_DIR" \
    -library "$LIB_DIR/libzcash_ffi_mobile-sim.a" \
        -headers "$HEADER_DIR" \
    -output "$DIST_DIR/ZcashFFI.xcframework"

echo ""
echo "Done:"
echo "  XCFramework: $DIST_DIR/ZcashFFI.xcframework"
echo "  Swift bindings: $SWIFT_DIR/zcash.swift"
