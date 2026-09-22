//! C-ABI binding for iOS and Android.
//!
//! Sibling to `zcash-ffi-node`: same core (`zcash-crypto`), different doorway.
//! Where the Node crate exposes `#[napi]` functions to a JS host that supplies
//! napi symbols at runtime, this crate exposes plain `extern "C"` functions with
//! no host dependency at all — so it links into an iOS static library or an
//! Android shared object, and `cargo test` can exercise it directly.
//!
//! # Calling convention
//!
//! Every entry point returns an `i32` status ([`ZCASH_OK`] or a negative error
//! code) and writes a NUL-terminated, heap-allocated C string to `*out`:
//!
//! - status `ZCASH_OK` -> `*out` is the result.
//! - status negative   -> `*out` is a human-readable error message.
//!
//! Either way the caller **owns** `*out` and must release it with
//! [`zcash_string_free`]. On a null-argument error nothing is written.
//!
//! # Panic safety
//!
//! Desktop hosts this engine in an Electron `utilityProcess`, so a Rust panic
//! kills a disposable helper. On mobile there is no helper process: a panic
//! unwinding across the FFI boundary is undefined behaviour, and at best aborts
//! the whole wallet. Every entry point is therefore wrapped in
//! [`catch_unwind`](std::panic::catch_unwind) and reports [`ZCASH_ERR_PANIC`].
//!
//! This depends on `panic = "unwind"` (the default). Setting `panic = "abort"`
//! in a release profile would silently disable the protection.

// Android cannot call the C ABI below: the JVM speaks only JNI. This module
// adds JNI-shaped entry points over the same `zcash-crypto` calls, so the
// engine ships one library per ABI carrying both doorways and the app needs no
// native build of its own.
#[cfg(target_os = "android")]
mod jni_android;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Call succeeded; `*out` holds the result.
pub const ZCASH_OK: i32 = 0;
/// A required pointer argument was null. Nothing was written to `*out`.
pub const ZCASH_ERR_NULL_ARG: i32 = -1;
/// The input string was not valid UTF-8.
pub const ZCASH_ERR_INVALID_UTF8: i32 = -2;
/// The underlying `zcash-crypto` call failed (e.g. malformed UFVK).
pub const ZCASH_ERR_CRYPTO: i32 = -3;
/// A panic was caught at the boundary. Indicates a bug; report it.
pub const ZCASH_ERR_PANIC: i32 = -4;
/// The produced string contained an interior NUL and cannot cross the C ABI.
pub const ZCASH_ERR_INTERIOR_NUL: i32 = -5;

/// Move an owned Rust string out to the caller as a C string.
///
/// Returns `status` on success, or [`ZCASH_ERR_INTERIOR_NUL`] if the value
/// cannot be represented as a C string.
///
/// # Safety
/// `out` must be non-null and writable.
unsafe fn write_out(out: *mut *mut c_char, value: String, status: i32) -> i32 {
    match CString::new(value) {
        Ok(c) => {
            *out = c.into_raw();
            status
        }
        Err(_) => ZCASH_ERR_INTERIOR_NUL,
    }
}

/// Derive the Orchard-only unified address from an encoded UFVK.
///
/// This is the address the Ledger device displays and matches. It is **not** the
/// multi-receiver unified address — see
/// `zcash_crypto::keys::orchard_address_from_ufvk`.
///
/// # Safety
/// `ufvk` must be a valid NUL-terminated C string; `out` must be a writable
/// pointer to a `*mut c_char`. On [`ZCASH_OK`] or any error except
/// [`ZCASH_ERR_NULL_ARG`], `*out` is owned by the caller and must be released
/// with [`zcash_string_free`].
#[no_mangle]
pub unsafe extern "C" fn zcash_orchard_address_from_ufvk(
    ufvk: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    if ufvk.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let ufvk_str = match CStr::from_ptr(ufvk).to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err((
                    ZCASH_ERR_INVALID_UTF8,
                    "ufvk is not valid UTF-8".to_string(),
                ))
            }
        };

        // Error messages from zcash-crypto are deliberately fixed strings that do
        // not echo the UFVK — a viewing key in a log or error payload is a privacy
        // leak. Do not enrich these messages with the input.
        zcash_crypto::keys::orchard_address_from_ufvk(ufvk_str)
            .map_err(|e| (ZCASH_ERR_CRYPTO, e.to_string()))
    }));

    match result {
        Ok(Ok(address)) => write_out(out, address, ZCASH_OK),
        Ok(Err((code, message))) => write_out(out, message, code),
        Err(_) => write_out(
            out,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Measure whether Rayon actually gives us parallelism on this device.
///
/// **Diagnostic only — not part of the wallet surface.** It answers the
/// question blocking a decision on mobile shielded sync: threads are assumed to
/// work on iOS and Android, but nothing in this crate has ever spawned one. The
/// shipped artifact imports no `pthread_create` at all, because the linker
/// strips Rayon while no exported symbol reaches it.
///
/// The workload is `orchard_address_from_ufvk` repeated `iterations` times —
/// real elliptic-curve work already proven correct on device, rather than a
/// synthetic loop the optimiser might elide. It is *not* trial decryption, so
/// read the result as "does threading work here, and how well does it scale",
/// not as a sync-throughput figure.
///
/// On success `*out` is JSON:
/// `{"threads":N,"iterations":N,"serial_ms":N,"parallel_ms":N,"speedup":N.N}`
///
/// # Safety
/// Same contract as [`zcash_orchard_address_from_ufvk`].
#[no_mangle]
pub unsafe extern "C" fn zcash_ffi_thread_probe(
    ufvk: *const c_char,
    iterations: u32,
    out: *mut *mut c_char,
) -> i32 {
    use rayon::prelude::*;
    use std::time::Instant;

    if ufvk.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let ufvk_str = match CStr::from_ptr(ufvk).to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err((
                    ZCASH_ERR_INVALID_UTF8,
                    "ufvk is not valid UTF-8".to_string(),
                ))
            }
        };

        let n = iterations.max(1);

        // Fail fast on a bad key, so the timings below cannot be an error path
        // being measured instead of the real work.
        zcash_crypto::keys::orchard_address_from_ufvk(ufvk_str)
            .map_err(|e| (ZCASH_ERR_CRYPTO, e.to_string()))?;

        let serial_start = Instant::now();
        for _ in 0..n {
            let _ = zcash_crypto::keys::orchard_address_from_ufvk(ufvk_str);
        }
        let serial_ms = serial_start.elapsed().as_millis();

        let parallel_start = Instant::now();
        (0..n).into_par_iter().for_each(|_| {
            let _ = zcash_crypto::keys::orchard_address_from_ufvk(ufvk_str);
        });
        let parallel_ms = parallel_start.elapsed().as_millis();

        let speedup = if parallel_ms > 0 {
            serial_ms as f64 / parallel_ms as f64
        } else {
            0.0
        };

        Ok(format!(
            "{{\"threads\":{},\"iterations\":{},\"serial_ms\":{},\"parallel_ms\":{},\"speedup\":{:.2}}}",
            rayon::current_num_threads(),
            n,
            serial_ms,
            parallel_ms,
            speedup
        ))
    }));

    match result {
        Ok(Ok(json)) => write_out(out, json, ZCASH_OK),
        Ok(Err((code, message))) => write_out(out, message, code),
        Err(_) => write_out(
            out,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Read a C string argument, or report which one was malformed.
///
/// Never name the *value* in the error, only the parameter: one of these is a
/// viewing key.
///
/// # Safety
/// `p` must be a valid NUL-terminated C string.
#[cfg(feature = "sync")]
unsafe fn read_c_str<'a>(p: *const c_char, name: &str) -> Result<&'a str, (i32, String)> {
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| (ZCASH_ERR_INVALID_UTF8, format!("{name} is not valid UTF-8")))
}

/// Scan a block range and return the result as JSON.
///
/// Shared by the C ABI below and by the JNI entry point in `jni_android`, so
/// the two doorways cannot drift apart.
///
/// # The runtime
///
/// `run_sync` is `async`, and this crate is a `cdylib`/`staticlib` with no
/// ambient executor — unlike `zcash-cli` (which owns `main` via
/// `#[tokio::main]`) or `zcash-ffi-node` (where Node supplies one). So the
/// binding builds its own and blocks on it.
///
/// It is deliberately a **current-thread** runtime. The async side here is
/// I/O — streaming compact blocks off gRPC — and concurrency is not
/// parallelism: `try_buffer_unordered` keeps N requests in flight on one
/// thread perfectly well. All the CPU work already leaves via `spawn_blocking`
/// into Rayon, so worker threads would only add oversubscription on a phone.
#[cfg(feature = "sync")]
fn sync_range_json(
    ufvk: &str,
    grpc_url: &str,
    network: &str,
    start_height: u32,
    end_height: u32,
    known_nullifiers: &str,
) -> Result<String, (i32, String)> {
    use zcash_sync::sync::{run_sync, SyncParams};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // Bounded on purpose: the default blocking pool allows 512 threads,
        // which is not a sensible number on a handset.
        .max_blocking_threads(4)
        .build()
        .map_err(|e| (ZCASH_ERR_CRYPTO, format!("could not start the runtime: {e}")))?;

    let result = runtime
        .block_on(run_sync(SyncParams {
            grpc_url: grpc_url.to_string(),
            viewing_key: ufvk.to_string(),
            start_height,
            end_height,
            network: Some(network.to_string()),
            verbose: false,
            // The indexer returns 503 on large ranges under load; the engine
            // splits and backs off, but only when retries are enabled.
            max_retries: Some(3),
            // Ledger accounts are Orchard-only, so Sapling outputs are stripped
            // before trial decryption. Ironwood is Orchard-family and unaffected.
            orchard_only: true,
            // Always `None` from FFI (see SyncParams): these are the streaming
            // hooks, and a C ABI cannot carry a Rust closure back to the caller.
            // Everything is returned in one blob instead.
            on_block_done: None,
            on_transaction: None,
            // Nullifiers of notes the caller already holds and believes
            // unspent. Without these, a chunked scan cannot see that a note
            // found in an earlier range was spent in this one -- each call is
            // a fresh `run_sync` with no memory of previous ones -- and the
            // note stays marked unspent, inflating the balance. Newline
            // separated; blank lines ignored; empty string means none.
            known_nullifiers: known_nullifiers
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
        }))
        // `zcash-crypto` keeps key material out of its error strings, so this
        // is safe to surface. Do not enrich it with the inputs.
        .map_err(|e| (ZCASH_ERR_CRYPTO, e.to_string()))?;

    serde_json::to_string(&result)
        .map_err(|e| (ZCASH_ERR_CRYPTO, format!("could not serialise the result: {e}")))
}

/// Current chain tip height, as a decimal string.
///
/// The chunked scan loop needs to know where to stop, and only the engine can
/// ask -- there is no gRPC client on the JavaScript side of a phone.
#[cfg(feature = "sync")]
fn chain_tip_string(grpc_url: &str) -> Result<String, (i32, String)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (ZCASH_ERR_CRYPTO, format!("could not start the runtime: {e}")))?;

    runtime
        .block_on(zcash_sync::client::chain_tip(grpc_url.to_string()))
        .map(|h| h.to_string())
        .map_err(|e| (ZCASH_ERR_CRYPTO, e.to_string()))
}

/// Write the current chain tip height to `*out` as a decimal string.
///
/// # Safety
/// Same contract as [`zcash_orchard_address_from_ufvk`].
#[cfg(feature = "sync")]
#[no_mangle]
pub unsafe extern "C" fn zcash_chain_tip(grpc_url: *const c_char, out: *mut *mut c_char) -> i32 {
    if grpc_url.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let grpc_url = read_c_str(grpc_url, "grpc_url")?;
        chain_tip_string(grpc_url)
    }));

    match result {
        Ok(Ok(height)) => write_out(out, height, ZCASH_OK),
        Ok(Err((code, message))) => write_out(out, message, code),
        Err(_) => write_out(
            out,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Scan `start_height..=end_height` for notes belonging to `ufvk`.
///
/// **Blocking, and returns everything at once.** There is no progress and no
/// cancellation: the call occupies the calling thread until the whole range is
/// scanned, and a failure at the last block discards the entire result. That is
/// tolerable for a few thousand blocks and wrong for a full history — see the
/// sync design note on in-stream checkpointing.
///
/// On [`ZCASH_OK`], `*out` is the serialised `SyncResult`.
///
/// # Safety
/// All four string arguments must be valid NUL-terminated C strings, and `out`
/// a writable pointer to a `*mut c_char`. On [`ZCASH_OK`] or any error except
/// [`ZCASH_ERR_NULL_ARG`], the caller owns `*out` and must release it with
/// [`zcash_string_free`].
#[cfg(feature = "sync")]
#[no_mangle]
pub unsafe extern "C" fn zcash_sync_range(
    ufvk: *const c_char,
    grpc_url: *const c_char,
    network: *const c_char,
    start_height: u32,
    end_height: u32,
    known_nullifiers: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    if ufvk.is_null() || grpc_url.is_null() || network.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let ufvk = read_c_str(ufvk, "ufvk")?;
        let grpc_url = read_c_str(grpc_url, "grpc_url")?;
        let network = read_c_str(network, "network")?;
        // Optional: a null pointer means "no known nullifiers".
        let nullifiers = if known_nullifiers.is_null() {
            ""
        } else {
            read_c_str(known_nullifiers, "known_nullifiers")?
        };
        sync_range_json(ufvk, grpc_url, network, start_height, end_height, nullifiers)
    }));

    match result {
        Ok(Ok(json)) => write_out(out, json, ZCASH_OK),
        Ok(Err((code, message))) => write_out(out, message, code),
        Err(_) => write_out(
            out,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Release a string previously returned through an `out` parameter.
///
/// Passing null is a no-op. Passing any pointer not produced by this crate, or
/// the same pointer twice, is undefined behaviour.
///
/// # Safety
/// `s` must be null, or a pointer returned by this crate and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn zcash_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Device-conformance vectors, copied from
    // `crates/zcash-crypto/tests/get_orchard_address.rs`, which sources them from
    // app-zcash `tests/standalone/test_pubkey_cmd.py`. Asserting them here means
    // the FFI returns the same bytes the hardware displays — not merely whatever
    // the Rust layer happens to produce.
    const UFVK0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";
    const EXPECTED0: &str = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9";
    const UFVK1: &str = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf";
    const EXPECTED1: &str = "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e";

    /// Drive the FFI exactly as a C++ caller would, and always free the result.
    fn call(ufvk: &CStr) -> (i32, String) {
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe { zcash_orchard_address_from_ufvk(ufvk.as_ptr(), &mut out) };
        assert!(!out.is_null(), "a non-null-arg call must always write *out");
        let value = unsafe { CStr::from_ptr(out) }
            .to_str()
            .expect("out is valid UTF-8")
            .to_string();
        unsafe { zcash_string_free(out) };
        (status, value)
    }

    #[test]
    fn account_0_matches_device_vector_through_ffi() {
        let ufvk = CString::new(UFVK0).unwrap();
        assert_eq!(call(&ufvk), (ZCASH_OK, EXPECTED0.to_string()));
    }

    #[test]
    fn account_1_matches_device_vector_through_ffi() {
        let ufvk = CString::new(UFVK1).unwrap();
        assert_eq!(call(&ufvk), (ZCASH_OK, EXPECTED1.to_string()));
    }

    #[test]
    fn malformed_ufvk_reports_crypto_error_without_panicking() {
        let ufvk = CString::new("uview1definitelynotavalidkey").unwrap();
        let (status, message) = call(&ufvk);
        assert_eq!(status, ZCASH_ERR_CRYPTO);
        assert!(!message.is_empty(), "an error must carry a message");
    }

    #[test]
    fn empty_input_is_an_error_not_a_crash() {
        let ufvk = CString::new("").unwrap();
        let (status, _) = call(&ufvk);
        assert_eq!(status, ZCASH_ERR_CRYPTO);
    }

    /// A viewing key reveals the account's whole history. It must never travel
    /// back inside an error string, where it would land in logs or crash reports.
    #[test]
    fn error_message_never_echoes_the_viewing_key() {
        let ufvk = CString::new(UFVK0).unwrap();
        // Truncate a valid key so decoding fails on real key material.
        let broken = CString::new(&UFVK0[..UFVK0.len() - 10]).unwrap();
        let (status, message) = call(&broken);
        assert_eq!(status, ZCASH_ERR_CRYPTO);
        assert!(
            !message.contains(&UFVK0[10..40]),
            "error message leaked viewing-key material: {message}"
        );
        drop(ufvk);
    }

    #[test]
    fn non_utf8_input_is_rejected() {
        // 0xFF is never valid UTF-8.
        let raw = CString::new(vec![0x75u8, 0x76, 0xFF, 0xFE]).unwrap();
        let (status, _) = call(&raw);
        assert_eq!(status, ZCASH_ERR_INVALID_UTF8);
    }

    #[test]
    fn null_ufvk_returns_null_arg_and_writes_nothing() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe { zcash_orchard_address_from_ufvk(std::ptr::null(), &mut out) };
        assert_eq!(status, ZCASH_ERR_NULL_ARG);
        assert!(out.is_null(), "must not write *out on a null-arg error");
    }

    #[test]
    fn null_out_pointer_is_rejected_rather_than_dereferenced() {
        let ufvk = CString::new(UFVK0).unwrap();
        let status =
            unsafe { zcash_orchard_address_from_ufvk(ufvk.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(status, ZCASH_ERR_NULL_ARG);
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe { zcash_string_free(std::ptr::null_mut()) };
    }

    /// Allocate and free repeatedly: a leak or double-free here surfaces under
    /// the sanitizers this suite is intended to be run through in CI.
    #[test]
    fn repeated_calls_do_not_leak_or_double_free() {
        let ufvk = CString::new(UFVK0).unwrap();
        for _ in 0..200 {
            let (status, value) = call(&ufvk);
            assert_eq!(status, ZCASH_OK);
            assert_eq!(value, EXPECTED0);
        }
    }
}
