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

## Mobile — the `mobile` profile, never `release`

Both mobile targets build `zcash-ffi-mobile`, the C-ABI sibling of `zcash-ffi-node`,
with `--profile mobile`.

**This is not interchangeable with `--release`.** The `release` profile sets `lto = true`,
under which rustc writes **LLVM bitcode** into the archive instead of native object code.
Rust 1.97's LLVM 22 bitcode is unreadable by Xcode's toolchain: the `.a` exports no symbols
and the iOS link fails with

```
Unknown attribute kind (105)
(Producer: 'LLVM22.1.6-rust-1.97.1-stable' Reader: 'LLVM APPLE_1_2100.1.1.101_0')
```

`[profile.mobile]` in `Cargo.toml` inherits `release` and disables LTO for exactly this
reason. Both scripts assert the exported symbols afterwards so a regression fails the build
rather than shipping an unlinkable archive.

### iOS — XCFramework (`scripts/build-mobile-ios.sh`)

**Prerequisites:** Rust toolchain (rustup) + Xcode (`xcodebuild`, `lipo`)

**Output:** `dist/ZcashFfiMobile.xcframework`
- `ios-arm64` — device
- `ios-arm64_x86_64-simulator` — simulator (fat: arm64 + x86_64)

```bash
pnpm build:mobile:ios
```

Headers (`zcash_ffi_mobile.h` + `module.modulemap`) are embedded in each slice, so the
framework is consumable from the C++ JSI shim and from Swift (`import ZcashFfiMobile`).

Drop `x86_64-apple-ios` from `SIM_TARGETS` if nobody needs the Intel simulator.

### Android — per-ABI shared libraries (`scripts/build-mobile-android.sh`)

**Prerequisites:**
- Rust toolchain (rustup)
- `cargo install cargo-ndk`
- Android NDK via `$ANDROID_NDK_HOME` (or `$NDK_HOME`);
  `brew install --cask android-ndk` lands at `/opt/homebrew/share/android-ndk`

**Output:** `dist/android/<abi>/libzcash_ffi_mobile.so` for `arm64-v8a`, `armeabi-v7a`,
`x86_64`, `x86` (~1.9–2.4 MB each)

```bash
pnpm build:mobile:android
```

ABIs and API level mirror ledger-live-mobile (`reactNativeArchitectures` in
`android/gradle.properties`; `minSdkVersion = 25` in `android/build.gradle`). Keep them in
sync, or the `.so` set will not match what Gradle packages.

The script also asserts **16 KB page alignment** on the 64-bit ABIs (`LOAD` aligned to
`0x4000`), which Android 15+ requires. NDK r28 and newer do this by default; the check is a
guard against building with an older NDK. 32-bit ABIs are exempt.

> ledger-live-mobile pins `ndkVersion = "28.0.12674087"`. A newer NDK here is normally
> harmless — we export plain C and the NDK's C ABI is stable — but if a link or runtime
> error ever points at `libc`/`libc++`, match the app's NDK version first.

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

Enforces ≥90% line coverage on `zcash-crypto`. Exits with code 1 if the threshold is not met.
