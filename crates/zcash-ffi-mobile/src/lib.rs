//! iOS and Android binding of the Zcash read path.
//!
//! Sibling to `zcash-ffi-node`: same engine (`zcash-crypto`, `zcash-sync`),
//! different doorway. Where the Node crate exposes `#[napi]` functions to a JS
//! host that supplies napi symbols at runtime, this crate exposes plain
//! `extern "C"` functions with no host dependency, so it links into an iOS static
//! library or an Android shared object, and `cargo test` can drive it directly.
//! Android's JVM cannot call a C ABI, so a target-gated JNI module registers the
//! same operations for Kotlin; both doorways call the shared functions in
//! `read`, so they cannot drift.
//!
//! The write path (building and signing transactions) is not bound here.
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
//! # JSON contract
//!
//! Structured arguments and results are JSON strings whose field names and
//! optionality are those of the Node binding (`index.d.ts`): see [`dto`].
//!
//! # Threading
//!
//! All calls share one process-wide runtime ([`runtime`]). Blocking calls occupy
//! only the calling thread, so several threads may call at once, and a scan in
//! flight holds no lock. A scan is started with `zcash_sync_start`, cancelled
//! with `zcash_sync_cancel` and collected with `zcash_sync_finish`.
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
//!
//! # Privacy
//!
//! A viewing key reveals an account's whole history. No error string or log line
//! built here contains an input value; only parameter names appear. Engine
//! errors are passed through verbatim, as the Node binding passes them.
//!
//! See `docs/ffi-mobile.md` for the full reference.

pub mod dto;
mod read;
mod runtime;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub use read::{
    zcash_find_block_height, zcash_get_chain_tip, zcash_sync_cancel, zcash_sync_finish,
    zcash_sync_free, zcash_sync_start, zcash_transaction_details, ZcashSyncHandle,
};

/// Call succeeded; `*out` holds the result.
pub const ZCASH_OK: i32 = 0;
/// A required pointer argument was null. Nothing was written to `*out`.
pub const ZCASH_ERR_NULL_ARG: i32 = -1;
/// The input string was not valid UTF-8.
pub const ZCASH_ERR_INVALID_UTF8: i32 = -2;
/// The engine or the network failed. The message is the engine's own.
pub const ZCASH_ERR_ENGINE: i32 = -3;
/// A panic was caught at the boundary. Indicates a bug; report it.
pub const ZCASH_ERR_PANIC: i32 = -4;
/// The produced string contained an interior NUL and cannot cross the C ABI.
pub const ZCASH_ERR_INTERIOR_NUL: i32 = -5;
/// An argument was not valid JSON for its type, or a handle was already finished.
pub const ZCASH_ERR_INVALID_ARG: i32 = -6;
/// The scan was cancelled before it completed.
pub const ZCASH_ERR_CANCELLED: i32 = -7;

/// A status code and the message that goes with it.
pub(crate) type Failure = (i32, String);

/// One read-path operation, in each of its three spellings.
pub struct MobileExport {
    /// The name of the Node binding's export (`index.d.ts`).
    pub napi_name: &'static str,
    /// The C symbol declared in `include/zcash_ffi_mobile.h`.
    pub c_symbol: &'static str,
    /// The method registered for Kotlin on Android.
    pub jni_method: &'static str,
}

/// The read-path exports of the Node binding that this crate mirrors.
///
/// `tests/parity.rs` checks it against `index.d.ts` and the header. The write
/// path appends its own entries here.
pub const READ_PATH_EXPORTS: &[MobileExport] = &[
    MobileExport {
        napi_name: "getChainTip",
        c_symbol: "zcash_get_chain_tip",
        jni_method: "nativeGetChainTip",
    },
    MobileExport {
        napi_name: "findBlockHeight",
        c_symbol: "zcash_find_block_height",
        jni_method: "nativeFindBlockHeight",
    },
    MobileExport {
        napi_name: "startSync",
        c_symbol: "zcash_sync_start",
        jni_method: "nativeSyncStart",
    },
    MobileExport {
        napi_name: "orchardAddressFromUfvk",
        c_symbol: "zcash_orchard_address_from_ufvk",
        jni_method: "nativeOrchardAddressFromUfvk",
    },
    MobileExport {
        napi_name: "transactionDetails",
        c_symbol: "zcash_transaction_details",
        jni_method: "nativeTransactionDetails",
    },
];

/// Move an owned Rust string out to the caller as a C string.
///
/// Returns `status` on success. A value that cannot be represented as a C string
/// is replaced by a fixed message and reported as [`ZCASH_ERR_INTERIOR_NUL`], so
/// `*out` is always written and always owned by the caller.
///
/// # Safety
/// `out` must be non-null and writable.
pub(crate) unsafe fn write_out(out: *mut *mut c_char, value: String, status: i32) -> i32 {
    match CString::new(value) {
        Ok(c) => {
            *out = c.into_raw();
            status
        }
        Err(_) => {
            let notice = CString::new("result contained an interior NUL")
                .expect("the literal has no interior NUL");
            *out = notice.into_raw();
            ZCASH_ERR_INTERIOR_NUL
        }
    }
}

/// Borrow a required C string argument as `&str`.
///
/// # Safety
/// `ptr` must be non-null and point to a NUL-terminated string.
pub(crate) unsafe fn read_c_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, Failure> {
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| (ZCASH_ERR_INVALID_UTF8, format!("{name} is not valid UTF-8")))
}

/// Borrow an optional C string argument: a null pointer is `None`.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string.
pub(crate) unsafe fn read_opt_c_str<'a>(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<&'a str>, Failure> {
    if ptr.is_null() {
        Ok(None)
    } else {
        read_c_str(ptr, name).map(Some)
    }
}

/// Run `f` behind `catch_unwind` and write its outcome to `*out`.
///
/// `Ok(string)` -> [`ZCASH_OK`]; `Err((code, message))` -> that code with the
/// message; a panic -> [`ZCASH_ERR_PANIC`].
///
/// # Safety
/// `out` must be non-null and writable.
pub(crate) unsafe fn ffi_call(
    out: *mut *mut c_char,
    f: impl FnOnce() -> Result<String, Failure>,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        test_hooks::panic_if_forced();
        f()
    }));
    match result {
        Ok(Ok(value)) => write_out(out, value, ZCASH_OK),
        Ok(Err((code, message))) => write_out(out, message, code),
        Err(_) => write_out(
            out,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Derive the Orchard-only unified address from an encoded UFVK.
///
/// This is the address the Ledger device displays and matches. It is **not** the
/// multi-receiver unified address; see
/// `zcash_crypto::keys::orchard_address_from_ufvk`. Non-blocking.
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
    ffi_call(out, || read::orchard_address(read_c_str(ufvk, "ufvk")?))
}

/// Release a string returned through an out parameter. NULL is a no-op.
///
/// # Safety
/// `s` must be null or a pointer this crate returned, not yet released.
#[no_mangle]
pub unsafe extern "C" fn zcash_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(CString::from_raw(s))));
    }
}

/// Switches that make the guarded paths fail on purpose. Compiled for the
/// crate's own unit tests only, so the shipped library carries no hook.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        static FORCE_CALL_PANIC: Cell<bool> = const { Cell::new(false) };
        static FORCE_TASK_PANIC: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn set_call_panic(on: bool) {
        FORCE_CALL_PANIC.with(|c| c.set(on));
    }

    pub(crate) fn set_task_panic(on: bool) {
        FORCE_TASK_PANIC.with(|c| c.set(on));
    }

    pub(crate) fn panic_if_forced() {
        if FORCE_CALL_PANIC.with(|c| c.get()) {
            panic!("forced panic at the FFI boundary");
        }
    }

    pub(crate) fn task_panic_forced() -> bool {
        FORCE_TASK_PANIC.with(|c| c.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Device-conformance vectors, copied from
    // `crates/zcash-crypto/tests/get_orchard_address.rs`, which sources them from
    // app-zcash `tests/standalone/test_pubkey_cmd.py`. Asserting them here means
    // the FFI returns the same bytes the hardware displays, not merely whatever
    // the Rust layer happens to produce.
    const UFVK0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";
    const EXPECTED0: &str = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9";
    const UFVK1: &str = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf";
    const EXPECTED1: &str = "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e";

    /// Drive the FFI exactly as a C caller would, and always free the result.
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
    fn malformed_ufvk_reports_engine_error_without_panicking() {
        let ufvk = CString::new("uview1definitelynotavalidkey").unwrap();
        let (status, message) = call(&ufvk);
        assert_eq!(status, ZCASH_ERR_ENGINE);
        assert!(!message.is_empty(), "an error must carry a message");
    }

    #[test]
    fn empty_input_is_an_error_not_a_crash() {
        let ufvk = CString::new("").unwrap();
        let (status, _) = call(&ufvk);
        assert_eq!(status, ZCASH_ERR_ENGINE);
    }

    /// A viewing key reveals the account's whole history. It must never travel
    /// back inside an error string, where it would land in logs or crash reports.
    #[test]
    fn error_message_never_echoes_the_viewing_key() {
        // Truncate a valid key so decoding fails on real key material.
        let broken_str = &UFVK0[..UFVK0.len() - 10];
        let broken = CString::new(broken_str).unwrap();
        let (status, message) = call(&broken);
        assert_eq!(status, ZCASH_ERR_ENGINE);
        assert!(
            !message.contains(broken_str),
            "error message contains the whole viewing key: {message}"
        );
        for window in broken_str.as_bytes().windows(20) {
            let window = std::str::from_utf8(window).unwrap();
            assert!(
                !message.contains(window),
                "error message leaked viewing-key material: {message}"
            );
        }
    }

    #[test]
    fn non_utf8_input_is_rejected() {
        // 0xFF is never valid UTF-8.
        let raw = CString::new(vec![0x75u8, 0x76, 0xFF, 0xFE]).unwrap();
        let (status, message) = call(&raw);
        assert_eq!(status, ZCASH_ERR_INVALID_UTF8);
        assert_eq!(message, "ufvk is not valid UTF-8");
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
    /// the sanitizers this suite can be run through.
    #[test]
    fn repeated_calls_do_not_leak_or_double_free() {
        let ufvk = CString::new(UFVK0).unwrap();
        for _ in 0..200 {
            let (status, value) = call(&ufvk);
            assert_eq!(status, ZCASH_OK);
            assert_eq!(value, EXPECTED0);
        }
    }

    #[test]
    fn forced_panic_returns_panic_status_and_process_survives() {
        let ufvk = CString::new(UFVK0).unwrap();

        test_hooks::set_call_panic(true);
        let (status, message) = call(&ufvk);
        test_hooks::set_call_panic(false);
        assert_eq!(status, ZCASH_ERR_PANIC);
        assert_eq!(message, "panic caught at FFI boundary");

        assert_eq!(call(&ufvk), (ZCASH_OK, EXPECTED0.to_string()));
    }

    #[test]
    fn interior_nul_is_reported_and_out_is_still_written() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe { write_out(&mut out, "a\0b".to_string(), ZCASH_OK) };
        assert_eq!(status, ZCASH_ERR_INTERIOR_NUL);
        assert!(!out.is_null());
        let text = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { zcash_string_free(out) };
        assert_eq!(text, "result contained an interior NUL");
    }

    #[test]
    fn optional_c_string_treats_null_as_absent() {
        let present = CString::new("x").unwrap();
        unsafe {
            assert_eq!(read_opt_c_str(std::ptr::null(), "n").unwrap(), None);
            assert_eq!(read_opt_c_str(present.as_ptr(), "n").unwrap(), Some("x"));
        }
        let bad = CString::new(vec![0xFFu8]).unwrap();
        let err = unsafe { read_opt_c_str(bad.as_ptr(), "network") }.unwrap_err();
        assert_eq!(
            err,
            (
                ZCASH_ERR_INVALID_UTF8,
                "network is not valid UTF-8".to_string()
            )
        );
    }

    #[test]
    fn read_path_table_names_are_unique() {
        let mut napi: Vec<_> = READ_PATH_EXPORTS.iter().map(|e| e.napi_name).collect();
        let mut c: Vec<_> = READ_PATH_EXPORTS.iter().map(|e| e.c_symbol).collect();
        napi.sort();
        napi.dedup();
        c.sort();
        c.dedup();
        assert_eq!(napi.len(), READ_PATH_EXPORTS.len());
        assert_eq!(c.len(), READ_PATH_EXPORTS.len());
    }
}
