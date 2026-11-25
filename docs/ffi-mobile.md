# Mobile binding (iOS and Android)

`crates/zcash-ffi-mobile` binds the **read path** of the engine for mobile wallets: chain queries, block scanning, transaction details and the Orchard address of a viewing key. It is the sibling of [`zcash-ffi-node`](ffi-node.md) and runs the same engine, so a wallet gets the same answers on every platform. The write path (building and finalizing transactions) is not bound yet.

## Artifacts

The crate builds as `staticlib` (linked into an iOS XCFramework), `cdylib` (one shared object per Android ABI) and `lib` (so that `cargo test` can link a test harness; a pure C ABI has no host-supplied symbols, unlike the napi crate).

Mobile libraries are built with the `mobile` profile, never `release`. The `release` profile uses LTO, which emits LLVM bitcode that Xcode's linker cannot read, so the archive would export no symbols. The `mobile` profile inherits `release` with `lto = false`:

```bash
cargo build --profile mobile -p zcash-ffi-mobile --target <ios-or-android-triple>
```

The Android JVM cannot call a C ABI, so the same operations are also registered as JNI methods on one Kotlin class. The class path is a single constant in the Android module (`KOTLIN_CLASS`), and it is the only coupling between the library and an app package.

## Exports

Each operation exists as a Node export, a C function (declared in `crates/zcash-ffi-mobile/include/zcash_ffi_mobile.h`) and a JNI method. `READ_PATH_EXPORTS` in `src/lib.rs` is the table; `tests/parity.rs` checks it.

| Node export              | C function                          | JNI method                         | Blocks        |
| ------------------------ | ----------------------------------- | ---------------------------------- | ------------- |
| `getChainTip`            | `zcash_get_chain_tip`               | `nativeGetChainTip`                | yes           |
| `findBlockHeight`        | `zcash_find_block_height`           | `nativeFindBlockHeight`            | yes           |
| `transactionDetails`     | `zcash_transaction_details`         | `nativeTransactionDetails`         | yes           |
| `orchardAddressFromUfvk` | `zcash_orchard_address_from_ufvk`   | `nativeOrchardAddressFromUfvk`     | no            |
| `startSync`              | `zcash_sync_start`                  | `nativeSyncStart`                  | no            |
| (the scan's handle)      | `zcash_sync_cancel`/`finish`/`free` | `nativeSyncCancel`/`Finish`/`Free` | `finish` only |

`testDeriveKeys` and `testSignPczt` are deliberately not bound: a wallet takes its keys from the device, and no API here takes a mnemonic or a spending key. The write-path exports are classified as pending in `tests/parity.rs`.

## Calling convention

Every function returns an `int` status and writes a C string to `*out`. On `ZCASH_OK` the string is the result; on any negative status except `ZCASH_ERR_NULL_ARG` it is an error message. The caller owns the string and frees it with `zcash_string_free`. On `ZCASH_ERR_NULL_ARG` nothing is written.

| Status                   | Value | Meaning                                                                |
| ------------------------ | ----- | ---------------------------------------------------------------------- |
| `ZCASH_OK`               | 0     | Success                                                                |
| `ZCASH_ERR_NULL_ARG`     | -1    | A required pointer was null                                            |
| `ZCASH_ERR_INVALID_UTF8` | -2    | A string argument was not UTF-8                                        |
| `ZCASH_ERR_ENGINE`       | -3    | The engine or the network failed; the message is the engine's own      |
| `ZCASH_ERR_PANIC`        | -4    | A panic was caught at the boundary (a bug)                             |
| `ZCASH_ERR_INTERIOR_NUL` | -5    | The result held a NUL byte and cannot be a C string                    |
| `ZCASH_ERR_INVALID_ARG`  | -6    | A JSON argument did not match its type, or a handle was finished twice |
| `ZCASH_ERR_CANCELLED`    | -7    | The scan was cancelled                                                 |

Every entry point runs behind `catch_unwind`, so a panic is a status, never an unwind across the boundary. That relies on `panic = "unwind"`: do not set `panic = "abort"` in a profile used for mobile.

## JSON contract

Scalars cross as C strings and integers. Structured arguments and every structured result are JSON, with the field names and optionality of the Node binding (`index.d.ts`):

- names are camelCase;
- a TypeScript `?:` field is **omitted** when it has no value, never `null`;
- encodings are not normalised, exactly as in the README's "Value encoding": scan amounts are numbers, a fee is a decimal string, a note position is a decimal string.

`dto.rs` holds the types. `zcash_sync_finish` returns `{"transactions": [...], "stats": {...}}`: the transactions the Node binding streams, and the statistics it reports at the end. Defaults are the Node binding's: `orchardOnly` is `false`, `verbose` is `false`, `maxRetries` is passed through and `knownNullifiers` is empty.

## Ownership

- Strings returned through `out`, `out_error`: `zcash_string_free`. `NULL` is a no-op.
- A scan handle: `zcash_sync_start` creates it, `zcash_sync_free` releases it. `zcash_sync_free` aborts a scan still running. `NULL` is a no-op for `cancel` and `free`.
- `zcash_sync_finish` may be called once per handle; a second call returns `ZCASH_ERR_INVALID_ARG`.
- `zcash_sync_free` must not run concurrently with `zcash_sync_finish` on the same handle.

## Threading

All calls share one process-wide multi-thread tokio runtime, created on first use: 2 worker threads and at most 4 blocking threads. The CPU-heavy trial decryption leaves the async side for Rayon, so the workers only drive network I/O.

- Blocking calls (`zcash_get_chain_tip`, `zcash_find_block_height`, `zcash_transaction_details`, `zcash_sync_finish`) occupy only the calling thread. Call them off the UI thread.
- Calls may be made from several threads at once.
- A scan is a task on the shared runtime. It holds no lock, so chain queries and address derivation return while it runs.
- If the runtime cannot start, every call returns `ZCASH_ERR_ENGINE`; it never panics.

## Cancellation

`zcash_sync_cancel` aborts the scan task, as the Node binding's `TransactionStream.cancel` does. It is idempotent and safe from any thread. `zcash_sync_finish` after a cancel returns `ZCASH_ERR_CANCELLED` and no partial result. The network connection is dropped with the task. Decryption work already handed to Rayon finishes its current block and its result is discarded.

## Multicore is off

`zcash-ffi-mobile` depends on `zcash-crypto` without the `multicore` feature. The feature only affects Halo2 proving, which the read path never does, and `zcash-crypto` keeps it off by default for phones. Trial decryption uses Rayon regardless of the feature. The write-path work, which will measure proving on a device, may turn it on; that is a deliberate edit of the manifest and of the CI check below.

CI enforces the choice: the step "Check the multicore feature wiring" in `.github/workflows/build-test.yml` resolves `zcash-ffi-mobile` alone and fails if `halo2_proofs` gets `multicore`.

## TLS roots

On Android and iOS the engine uses the bundled Mozilla root store (`tls-webpki-roots`, enabled for those targets only), because Android has no `/etc/ssl/certs` and the native store loads empty. Desktop builds and the published addon keep following the OS trust store. See `tls_config` in `crates/zcash-sync/src/client.rs`.

## No viewing key in errors or logs

A viewing key reveals an account's whole history. Messages built by this crate name a parameter and never quote its value, and a malformed JSON argument is reported by kind only (`malformed JSON`, `wrong shape`, `truncated JSON`), because the parser's own text can quote the input. Engine errors pass through verbatim, as in the Node binding. `tests/read_path.rs` checks both the errors and the process's stdout and stderr for any 20-character window of the key.

## Tests

- Unit tests sit beside the code (`cargo test -p zcash-ffi-mobile`): the two device vectors for the Orchard address, null, empty, non-UTF-8 and malformed input, forced panics, the DTO conversions.
- `tests/read_path.rs` drives the C functions against a local mock of the lightwalletd service (`tests/common`): chain tip, block height, a bounded scan, mid-chunk cancellation, concurrent calls, transaction details and the privacy checks.
- `tests/parity.rs` compares the binding with the committed `index.d.ts`: every Node export is classified, every read-path export has a counterpart, and the JSON shapes carry the interfaces' fields and optionality.
