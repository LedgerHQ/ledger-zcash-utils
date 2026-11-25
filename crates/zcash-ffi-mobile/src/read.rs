//! The read path: shared operations and their `extern "C"` doorway.
//!
//! The functions at the top take Rust types and return `Result<String, Failure>`
//! (the string is the JSON result). The C exports below only check pointers,
//! decode arguments and call them through [`ffi_call`], and the JNI module calls
//! the same functions, so the two doorways answer identically.
//!
//! Error messages follow one rule: an engine error is passed through verbatim
//! (`e.to_string()`, as the Node binding does), and a message this crate writes
//! names a parameter, never its value.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use tokio::task::{AbortHandle, JoinHandle};
use zcash_sync::sync as engine;

use crate::dto::{
    SyncChunkResult, SyncParams, TransactionDetailsRequest, TransactionDetailsResult,
};
use crate::runtime::{block_on, runtime};
use crate::{
    ffi_call, read_c_str, read_opt_c_str, write_out, Failure, ZCASH_ERR_CANCELLED,
    ZCASH_ERR_ENGINE, ZCASH_ERR_INVALID_ARG, ZCASH_ERR_NULL_ARG, ZCASH_ERR_PANIC, ZCASH_OK,
};

fn engine_failure(e: impl std::fmt::Display) -> Failure {
    (ZCASH_ERR_ENGINE, e.to_string())
}

/// A JSON argument that failed to decode. Only the kind of failure is reported:
/// serde's own text can quote the offending value.
fn invalid_json(name: &str, e: &serde_json::Error) -> Failure {
    let kind = match e.classify() {
        serde_json::error::Category::Io => "unreadable",
        serde_json::error::Category::Syntax => "malformed JSON",
        serde_json::error::Category::Data => "wrong shape",
        serde_json::error::Category::Eof => "truncated JSON",
    };
    (
        ZCASH_ERR_INVALID_ARG,
        format!("{name} is not valid: {kind}"),
    )
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, Failure> {
    serde_json::to_string(value).map_err(engine_failure)
}

// ─── shared operations ────────────────────────────────────────────────────────

pub(crate) fn orchard_address(ufvk: &str) -> Result<String, Failure> {
    zcash_crypto::keys::orchard_address_from_ufvk(ufvk).map_err(engine_failure)
}

pub(crate) fn chain_tip(grpc_url: &str) -> Result<String, Failure> {
    let tip =
        block_on(zcash_sync::client::chain_tip(grpc_url.to_owned()))?.map_err(engine_failure)?;
    to_json(&tip)
}

pub(crate) fn find_block_height(grpc_url: &str, timestamp: u32) -> Result<String, Failure> {
    let height = block_on(zcash_sync::client::find_block_height(
        grpc_url.to_owned(),
        timestamp,
    ))?
    .map_err(engine_failure)?;
    to_json(&height)
}

pub(crate) fn transaction_details(
    grpc_url: &str,
    requests_json: &str,
    network: Option<&str>,
    ufvk: Option<&str>,
) -> Result<String, Failure> {
    let network = zcash_crypto::network::parse_network(network).map_err(engine_failure)?;

    let requests: Vec<TransactionDetailsRequest> =
        serde_json::from_str(requests_json).map_err(|e| invalid_json("requests_json", &e))?;
    let requests = requests
        .into_iter()
        .map(TransactionDetailsRequest::into_engine)
        .collect::<Result<Vec<_>, String>>()
        .map_err(|message| (ZCASH_ERR_ENGINE, message))?;

    let results = block_on(zcash_sync::client::transaction_details(
        grpc_url.to_owned(),
        requests,
        network,
        ufvk.map(str::to_owned),
    ))?
    .map_err(engine_failure)?;

    let results: Vec<TransactionDetailsResult> = results.into_iter().map(Into::into).collect();
    to_json(&results)
}

// ─── scan handle ──────────────────────────────────────────────────────────────

type ScanTask = JoinHandle<anyhow::Result<engine::SyncResult>>;

/// A scan running on the shared runtime.
///
/// `abort` cancels without a lock. `join` is taken once, by `finish`, and the
/// lock is released before the wait, so a scan being waited on blocks no other
/// call and `cancel` can reach it meanwhile.
pub struct ZcashSyncHandle {
    abort: AbortHandle,
    join: Mutex<Option<ScanTask>>,
}

pub(crate) fn sync_start(params_json: &str) -> Result<Box<ZcashSyncHandle>, Failure> {
    let params: SyncParams =
        serde_json::from_str(params_json).map_err(|e| invalid_json("params_json", &e))?;
    let params: engine::SyncParams = params.into();

    let runtime = runtime()?;
    #[cfg(test)]
    let force_panic = crate::test_hooks::task_panic_forced();
    let task = runtime.spawn(async move {
        #[cfg(test)]
        if force_panic {
            panic!("forced panic in the scan task");
        }
        engine::run_sync(params).await
    });

    Ok(Box::new(ZcashSyncHandle {
        abort: task.abort_handle(),
        join: Mutex::new(Some(task)),
    }))
}

pub(crate) fn sync_finish(handle: &ZcashSyncHandle) -> Result<String, Failure> {
    let task = handle
        .join
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some(task) = task else {
        return Err((
            ZCASH_ERR_INVALID_ARG,
            "the scan was already finished".to_string(),
        ));
    };

    match block_on(task)? {
        Ok(Ok(result)) => to_json(&SyncChunkResult::from(result)),
        Ok(Err(e)) => Err(engine_failure(e)),
        Err(e) if e.is_cancelled() => Err((ZCASH_ERR_CANCELLED, "sync was cancelled".to_string())),
        Err(_) => Err((ZCASH_ERR_PANIC, "the scan task panicked".to_string())),
    }
}

// ─── C exports ────────────────────────────────────────────────────────────────

/// Current chain tip height. Blocking. `*out` is a JSON number.
///
/// # Safety
/// `grpc_url` must be a NUL-terminated C string and `out` a writable pointer. On
/// every status except [`ZCASH_ERR_NULL_ARG`], `*out` is owned by the caller and
/// released with `zcash_string_free`.
#[no_mangle]
pub unsafe extern "C" fn zcash_get_chain_tip(
    grpc_url: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    if grpc_url.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }
    ffi_call(out, || chain_tip(read_c_str(grpc_url, "grpc_url")?))
}

/// Height of the latest block at or before `timestamp`. Blocking. `*out` is a
/// JSON number.
///
/// # Safety
/// As [`zcash_get_chain_tip`].
#[no_mangle]
pub unsafe extern "C" fn zcash_find_block_height(
    grpc_url: *const c_char,
    timestamp: u32,
    out: *mut *mut c_char,
) -> i32 {
    if grpc_url.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }
    ffi_call(out, || {
        find_block_height(read_c_str(grpc_url, "grpc_url")?, timestamp)
    })
}

/// Fee and shielded payees of transactions fetched by txid. Blocking.
/// `network` and `ufvk` may be null.
///
/// # Safety
/// `grpc_url` and `requests_json` must be NUL-terminated C strings, `network`
/// and `ufvk` null or NUL-terminated, and `out` a writable pointer. Ownership of
/// `*out` as in [`zcash_get_chain_tip`].
#[no_mangle]
pub unsafe extern "C" fn zcash_transaction_details(
    grpc_url: *const c_char,
    requests_json: *const c_char,
    network: *const c_char,
    ufvk: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    if grpc_url.is_null() || requests_json.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }
    ffi_call(out, || {
        transaction_details(
            read_c_str(grpc_url, "grpc_url")?,
            read_c_str(requests_json, "requests_json")?,
            read_opt_c_str(network, "network")?,
            read_opt_c_str(ufvk, "ufvk")?,
        )
    })
}

/// Start scanning one chunk of blocks in the background. Non-blocking.
///
/// On [`ZCASH_OK`], `*out_handle` is a new handle. On any other status except
/// [`ZCASH_ERR_NULL_ARG`], `*out_handle` is null and `*out_error` is a message
/// the caller releases with `zcash_string_free`.
///
/// # Safety
/// `params_json` must be a NUL-terminated C string; `out_handle` and `out_error`
/// must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn zcash_sync_start(
    params_json: *const c_char,
    out_handle: *mut *mut ZcashSyncHandle,
    out_error: *mut *mut c_char,
) -> i32 {
    if params_json.is_null() || out_handle.is_null() || out_error.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }
    *out_handle = std::ptr::null_mut();

    let result = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        crate::test_hooks::panic_if_forced();
        sync_start(read_c_str(params_json, "params_json")?)
    }));
    match result {
        Ok(Ok(handle)) => {
            *out_handle = Box::into_raw(handle);
            ZCASH_OK
        }
        Ok(Err((code, message))) => write_out(out_error, message, code),
        Err(_) => write_out(
            out_error,
            "panic caught at FFI boundary".to_string(),
            ZCASH_ERR_PANIC,
        ),
    }
}

/// Ask the scan to stop. Non-blocking, idempotent, callable from any thread.
/// NULL is a no-op.
///
/// # Safety
/// `handle` must be null or a live handle from [`zcash_sync_start`].
#[no_mangle]
pub unsafe extern "C" fn zcash_sync_cancel(handle: *mut ZcashSyncHandle) {
    if let Some(handle) = handle.as_ref() {
        let _ = catch_unwind(AssertUnwindSafe(|| handle.abort.abort()));
    }
}

/// Wait for the scan to end or to be cancelled. Blocking. `*out` on success is
/// `{"transactions":[...],"stats":{...}}`; a cancelled scan returns
/// [`ZCASH_ERR_CANCELLED`] and nothing partial. A second call on the same handle
/// returns [`ZCASH_ERR_INVALID_ARG`].
///
/// # Safety
/// `handle` must be a live handle and `out` a writable pointer. Ownership of
/// `*out` as in [`zcash_get_chain_tip`].
#[no_mangle]
pub unsafe extern "C" fn zcash_sync_finish(
    handle: *mut ZcashSyncHandle,
    out: *mut *mut c_char,
) -> i32 {
    if handle.is_null() || out.is_null() {
        return ZCASH_ERR_NULL_ARG;
    }
    let handle = &*handle;
    ffi_call(out, || sync_finish(handle))
}

/// Abort the scan if it is still running, then release the handle. NULL is a
/// no-op.
///
/// # Safety
/// `handle` must be null or a live handle not yet freed, and must not be in use
/// by a concurrent [`zcash_sync_finish`].
#[no_mangle]
pub unsafe extern "C" fn zcash_sync_free(handle: *mut ZcashSyncHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let handle = Box::from_raw(handle);
            handle.abort.abort();
            drop(handle);
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_hooks, zcash_string_free};
    use std::ffi::{CStr, CString};

    const PARAMS_NO_KEY: &str =
        r#"{"grpcUrl":"http://127.0.0.1:1","viewingKey":"k","startHeight":1,"endHeight":2}"#;

    fn take(out: *mut c_char) -> String {
        assert!(!out.is_null());
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { zcash_string_free(out) };
        s
    }

    fn start(json: &str) -> (i32, *mut ZcashSyncHandle, String) {
        let json = CString::new(json).unwrap();
        let mut handle: *mut ZcashSyncHandle = std::ptr::dangling_mut();
        let mut err: *mut c_char = std::ptr::null_mut();
        let status = unsafe { zcash_sync_start(json.as_ptr(), &mut handle, &mut err) };
        let message = if err.is_null() {
            String::new()
        } else {
            take(err)
        };
        (status, handle, message)
    }

    fn finish(handle: *mut ZcashSyncHandle) -> (i32, String) {
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe { zcash_sync_finish(handle, &mut out) };
        (status, take(out))
    }

    #[test]
    fn sync_task_panic_is_reported_as_panic() {
        test_hooks::set_task_panic(true);
        let (status, handle, _) = start(PARAMS_NO_KEY);
        test_hooks::set_task_panic(false);
        assert_eq!(status, ZCASH_OK);

        let (status, message) = finish(handle);
        assert_eq!(status, ZCASH_ERR_PANIC);
        assert_eq!(message, "the scan task panicked");
        unsafe { zcash_sync_free(handle) };
    }

    #[test]
    fn panic_while_starting_a_scan_is_caught() {
        test_hooks::set_call_panic(true);
        let (status, handle, message) = start(PARAMS_NO_KEY);
        test_hooks::set_call_panic(false);
        assert_eq!(status, ZCASH_ERR_PANIC);
        assert!(handle.is_null());
        assert_eq!(message, "panic caught at FFI boundary");
    }

    #[test]
    fn engine_error_in_the_scan_comes_back_as_an_engine_status() {
        // "k" is not a viewing key: the engine rejects it before any network I/O.
        let (status, handle, _) = start(PARAMS_NO_KEY);
        assert_eq!(status, ZCASH_OK);
        let (status, message) = finish(handle);
        assert_eq!(status, ZCASH_ERR_ENGINE);
        assert!(!message.is_empty());
        assert!(!message.contains("viewingKey"));
        unsafe { zcash_sync_free(handle) };
    }

    #[test]
    fn a_handle_cannot_be_finished_twice() {
        let (_, handle, _) = start(PARAMS_NO_KEY);
        let _ = finish(handle);
        let (status, message) = finish(handle);
        assert_eq!(status, ZCASH_ERR_INVALID_ARG);
        assert_eq!(message, "the scan was already finished");
        unsafe { zcash_sync_free(handle) };
    }

    #[test]
    fn malformed_params_never_echo_their_content() {
        let secret = "uview1secretmaterialsecretmaterial";
        let (status, handle, message) = start(&format!(
            r#"{{"grpcUrl":"u","viewingKey":"{secret}","startHeight":"x"}}"#
        ));
        assert_eq!(status, ZCASH_ERR_INVALID_ARG);
        assert!(handle.is_null(), "*out_handle must be reset on failure");
        assert!(!message.contains(secret) && !message.contains("secretmaterial"));
        assert_eq!(message, "params_json is not valid: wrong shape");
    }

    #[test]
    fn invalid_json_kinds_are_reported_without_content() {
        let syntax = serde_json::from_str::<SyncParams>("{").unwrap_err();
        assert_eq!(
            invalid_json("p", &syntax).1,
            "p is not valid: truncated JSON"
        );
        let syntax = serde_json::from_str::<SyncParams>("nope").unwrap_err();
        assert_eq!(
            invalid_json("p", &syntax).1,
            "p is not valid: malformed JSON"
        );
    }

    #[test]
    fn transaction_details_rejects_a_bad_network_and_bad_requests() {
        let err =
            transaction_details("http://127.0.0.1:1", "[]", Some("moonnet"), None).unwrap_err();
        assert_eq!(err.0, ZCASH_ERR_ENGINE);

        let err = transaction_details("http://127.0.0.1:1", "not json", None, None).unwrap_err();
        assert_eq!(err.0, ZCASH_ERR_INVALID_ARG);

        let bad_prevout =
            r#"[{"txid":"ab","height":1,"prevouts":[{"txid":"cd","index":0,"value":"zz"}]}]"#;
        let err = transaction_details("http://127.0.0.1:1", bad_prevout, None, None).unwrap_err();
        assert_eq!(err.0, ZCASH_ERR_ENGINE);
        assert!(err.1.starts_with("prevout value zz: "), "got: {}", err.1);
    }

    #[test]
    fn cancel_and_free_accept_null() {
        unsafe {
            zcash_sync_cancel(std::ptr::null_mut());
            zcash_sync_free(std::ptr::null_mut());
        }
    }
}
