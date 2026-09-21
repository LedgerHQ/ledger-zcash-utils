#!/usr/bin/env bash
# Build Android shared libraries for zcash-ffi-mobile, one per ABI.
#
# Requires:
#   - Rust toolchain (rustup)
#   - cargo-ndk        (cargo install cargo-ndk)
#   - Android NDK, located via $ANDROID_NDK_HOME or $NDK_HOME
#     (brew install --cask android-ndk -> /opt/homebrew/share/android-ndk)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/android"
LIB="libzcash_ffi_mobile.so"

# `mobile`, NOT `release`. Under `lto = true` rustc emits LLVM bitcode instead of
# native objects. See [profile.mobile] in Cargo.toml and scripts/build-mobile-ios.sh.
PROFILE="mobile"

# ABIs and API level mirror ledger-live-mobile:
#   apps/ledger-live-mobile/android/gradle.properties -> reactNativeArchitectures
#   apps/ledger-live-mobile/android/build.gradle      -> minSdkVersion = 25
# Keep these in sync with that app, or the .so set will not match what Gradle packages.
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")
API_LEVEL=25

cd "$REPO_ROOT"

# The NDK ships its llvm-* tools as SYMLINKS, so `find -type f` silently misses
# them and every check that depends on one turns into a no-op. Resolve by glob.
ndk_tool() {
    ls "$1"/toolchains/llvm/prebuilt/*/bin/"$2" 2>/dev/null | head -1
}

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${NDK_HOME:-}" ]; then
    if [ -d "/opt/homebrew/share/android-ndk" ]; then
        export ANDROID_NDK_HOME="/opt/homebrew/share/android-ndk"
        echo "ANDROID_NDK_HOME not set; using $ANDROID_NDK_HOME"
    else
        echo "ERROR: set ANDROID_NDK_HOME (or NDK_HOME) to your Android NDK." >&2
        exit 1
    fi
fi

NDK_ROOT="${ANDROID_NDK_HOME:-$NDK_HOME}"
if [ -f "$NDK_ROOT/source.properties" ]; then
    echo "NDK: $(grep '^Pkg.Revision' "$NDK_ROOT/source.properties" | cut -d= -f2 | tr -d ' ') at $NDK_ROOT"
fi
# ledger-live-mobile pins ndkVersion = "28.0.12674087". A different NDK here is
# usually harmless (the NDK's C ABI is stable and we export plain C), but if a link
# or runtime error ever points at libc/libc++, match the app's NDK first.

echo "Installing required Rust targets..."
rustup target add aarch64-linux-android armv7-linux-androideabi \
    x86_64-linux-android i686-linux-android

echo ""
echo "Building ${#ABIS[@]} ABIs (profile: $PROFILE, API $API_LEVEL)..."
abi_args=()
for abi in "${ABIS[@]}"; do abi_args+=("-t" "$abi"); done

# Record a SONAME. Nothing links against this library today -- the JVM dlopens
# it by path out of jniLibs -- so this is defensive: when a separate shim linked
# against it and found no SONAME, the linker wrote the absolute build-host path
# into that shim's DT_NEEDED, and the library failed to load on device.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-soname,$LIB"

# Opt-in cargo features, e.g. ZCASH_FFI_FEATURES=sync to include the block
# scanner. Off by default: `sync` links tokio, tonic, hyper and rustls, which
# the key-derivation-only build does not carry at all.
FEATURE_ARGS=()
if [ -n "${ZCASH_FFI_FEATURES:-}" ]; then
    FEATURE_ARGS=(--features "$ZCASH_FFI_FEATURES")
    echo "Building with features: $ZCASH_FFI_FEATURES"
fi

cargo ndk "${abi_args[@]}" --platform "$API_LEVEL" -o "$DIST_DIR" \
    build --profile "$PROFILE" -p zcash-ffi-mobile ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

# Decide on captured output, never on nm's exit status: Rust's precompiled `std`
# carries embedded LLVM bitcode that some binutils cannot parse, which makes nm
# exit non-zero on a perfectly good archive. See build-mobile-ios.sh.
echo ""
echo "Verifying exported C symbols and 16 KB page alignment..."
for abi in "${ABIS[@]}"; do
    so="$DIST_DIR/$abi/$LIB"
    if [ ! -f "$so" ]; then
        echo "  ERROR: missing $so" >&2
        exit 1
    fi
    echo "  $abi"

    symbols="$(nm -D "$so" 2>/dev/null | grep -E ' T zcash_' || true)"
    if [ -z "$symbols" ]; then
        # Fall back to the NDK's llvm-nm, which understands Rust's bitcode.
        llvm_nm="$(ndk_tool "$NDK_ROOT" llvm-nm)"
        if [ -n "$llvm_nm" ]; then
            symbols="$("$llvm_nm" --defined-only --extern-only "$so" 2>/dev/null | grep -E ' T zcash_' || true)"
        fi
    fi
    if [ -z "$symbols" ]; then
        echo "    ERROR: no exported zcash_* symbols found in $so" >&2
        echo "    Was this built with --release instead of --profile mobile?" >&2
        exit 1
    fi
    echo "$symbols" | sed 's/^/    /'

    # Android 15+ requires native libraries to support 16 KB memory pages on
    # 64-bit devices; LOAD segments must be aligned to 2**14. 32-bit ABIs are
    # exempt. NDK r28+ does this by default, so this check is a regression guard
    # against someone building with an older NDK.
    case "$abi" in
        arm64-v8a|x86_64)
            readelf="$(ndk_tool "$NDK_ROOT" llvm-readelf)"
            if [ -z "$readelf" ]; then
                echo "    WARNING: llvm-readelf not found in NDK; skipped alignment check." >&2
            else
                aligns="$("$readelf" -l "$so" 2>/dev/null | grep -A1 'LOAD' | grep -oE '0x[0-9a-f]+$' | sort -u | tr '\n' ' ' || true)"
                if echo "$aligns" | grep -qE '0x(4000|10000)'; then
                    echo "    16 KB page alignment: OK ($aligns)"
                else
                    echo "    WARNING: LOAD alignment is not 16 KB ($aligns)." >&2
                    echo "    Android 15+ may refuse to load this on 64-bit devices." >&2
                    echo "    Use NDK r28 or newer." >&2
                fi
            fi
            ;;
    esac
done

echo ""
echo "Done: $DIST_DIR"
echo "Copy these into the RN module's src/main/jniLibs/<abi>/ (or point Gradle at this directory)."
