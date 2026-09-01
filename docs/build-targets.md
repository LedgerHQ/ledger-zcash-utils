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
