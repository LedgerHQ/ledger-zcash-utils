# Build Targets

## Node.js / Electron (`scripts/build-napi.sh`)

**Prerequisites:**
- Node.js + pnpm (`npm install -g pnpm`)
- `@napi-rs/cli` (installed via `pnpm install`)

**Output:** `index.darwin-arm64.node` (or appropriate platform suffix)

```bash
./scripts/build-napi.sh          # release
DEBUG=1 ./scripts/build-napi.sh  # debug
```

The `.node` file is loaded by `index.js` which is the npm package entry point.

---

## Android (`scripts/build-android.sh`)

**Prerequisites:**
- Android NDK r26+ — set `ANDROID_NDK_HOME` or `ANDROID_HOME` (NDK auto-detected from `$ANDROID_HOME/ndk/`)
- `cargo-ndk`: `cargo install cargo-ndk`

**Output:**
```
dist/android/
  jniLibs/arm64-v8a/libzcash_ffi_mobile.so
  jniLibs/armeabi-v7a/libzcash_ffi_mobile.so
  jniLibs/x86/libzcash_ffi_mobile.so
  jniLibs/x86_64/libzcash_ffi_mobile.so
  kotlin/app/zcash/uniffi/zcash.kt
```

```bash
# If ANDROID_HOME is set (e.g. ~/Library/Android/sdk), NDK is auto-detected:
./scripts/build-android.sh

# Or set the NDK path explicitly:
ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/28.0.12674087 \
    ./scripts/build-android.sh
```

Copy `jniLibs/` into your Android project's `src/main/` directory.
Copy `zcash.kt` into your Kotlin source tree.

---

## iOS (`scripts/build-ios.sh`)

**Prerequisites:**
- macOS with Xcode installed
- Xcode command line tools: `xcode-select --install`

**Output:**
```
dist/ios/
  ZcashFFI.xcframework/    (drag into Xcode project)
  swift/zcash.swift        (copy into Swift source)
  swift/zcashFFI.h         (included in XCFramework headers)
```

```bash
./scripts/build-ios.sh
```

In Xcode: drag `ZcashFFI.xcframework` into your project → Frameworks,
Libraries, and Embedded Content. Copy `zcash.swift` into your Swift target.

---

## CLI — macOS universal (`scripts/build-cli-macos.sh`)

**Prerequisites:**
- Rust toolchain (rustup)
- Xcode command line tools (for `lipo`)

**Output:** `dist/ledger-zcash-cli-macos-universal` (arm64 + x86_64 fat binary)

```bash
./scripts/build-cli-macos.sh
./dist/ledger-zcash-cli-macos-universal derive --help
```

---

## CLI — Linux static (`scripts/build-cli-linux.sh`)

**Prerequisites (choose one):**
- **Local musl-cross** (faster, ~30s): `brew install filosottile/musl-cross/musl-cross`
- **Docker** (fallback, used automatically if `x86_64-linux-musl-gcc` is not on `$PATH`)

**Output:** `dist/ledger-zcash-cli-linux-x86_64` (static musl binary, no libc)

```bash
./scripts/build-cli-linux.sh
```

---

## Test coverage (`scripts/coverage.sh`)

**Prerequisites:**
- `cargo install cargo-llvm-cov`
- LLVM: installed automatically with `rustup component add llvm-tools-preview`

**Output:** `target/coverage/html/index.html` + `target/coverage/lcov.info`

```bash
./scripts/coverage.sh
OPEN_REPORT=1 ./scripts/coverage.sh  # open HTML report after run
```

Enforces ≥90% line coverage on `zcash-crypto`. Exits with code 1 if the
threshold is not met.
