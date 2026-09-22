//! Android entry points.
//!
//! Sibling to the C ABI in [`crate`], not a replacement: iOS keeps calling the
//! `extern "C"` functions directly, because Swift speaks C. The JVM does not —
//! it has no FFI at all, only JNI — so Android needs functions shaped the way
//! JNI expects, and this module is that shape.
//!
//! # Why the symbols are registered rather than exported
//!
//! The JVM resolves `external fun foo()` on class `com.ledger.live.Bar` by
//! looking up the symbol `Java_com_ledger_live_Bar_foo`, and nothing else. The
//! obvious implementation therefore exports exactly that name — which bakes
//! *this application's Kotlin package* into the engine's symbol table, inside a
//! library that has no business knowing which wallet loads it.
//!
//! [`JNI_OnLoad`] avoids that. The JVM calls it once when the library loads,
//! and we hand back an explicit table: these function pointers implement those
//! methods on that class. The coupling collapses to [`KOTLIN_CLASS`] — one
//! string, in one place, changeable without touching a symbol name. Nothing
//! below is `#[no_mangle]` except `JNI_OnLoad` itself.
//!
//! # Contract
//!
//! Mirrors the C ABI: a status code plus a string, where the string is the
//! result on [`ZCASH_OK`] and the error message otherwise. JNI has no out
//! parameters, so the status travels in a caller-supplied one-element `int[]`
//! and the string is the return value. This is the same shape Kotlin already
//! saw through the C++ shim these functions replace, so the Kotlin signatures
//! are unchanged.
//!
//! # Panic safety
//!
//! Unwinding into the JVM is undefined behaviour, exactly as across the C
//! boundary. `native_method!` installs its own `catch_unwind` that converts a
//! panic into a thrown `RuntimeException`; we additionally catch around the
//! engine call itself so a panic arrives as [`ZCASH_ERR_PANIC`] in the status
//! array — the contract the C ABI documents and the Kotlin layer already maps.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::errors::Error;
use jni::objects::{JIntArray, JObject, JString};
use jni::sys::{jint, JNI_ERR};
use jni::{jni_str, native_method, Env, JNIVersion, JavaVM, NativeMethod};

use crate::{ZCASH_ERR_CRYPTO, ZCASH_ERR_PANIC, ZCASH_OK};

/// The Kotlin class these implementations back.
///
/// The single point of coupling between this engine and the wallet embedding
/// it. Renaming or moving `ZcashFfiModule` on the app side means editing this
/// line and nothing else — no symbol names, no build files.
const KOTLIN_CLASS: &jni::strings::JNIStr = jni_str!("com/ledger/live/ZcashFfiModule");

/// `nativeDeriveOrchardAddress(String, int[]) -> String`
///
/// The macro derives the JNI signature from the Rust types and checks it
/// against the implementation at compile time, so a mismatch is a build error
/// rather than an `UnsatisfiedLinkError` on device. No `extern` / `export`
/// here: the symbol is deliberately not exported (see the module docs).
const DERIVE_ORCHARD_ADDRESS: NativeMethod = native_method! {
    fn native_derive_orchard_address(ufvk: JString, out_status: [jint]) -> JString,
};

/// `nativeThreadProbe(String, int, int[]) -> String`
const THREAD_PROBE: NativeMethod = native_method! {
    fn native_thread_probe(ufvk: JString, iterations: jint, out_status: [jint]) -> JString,
};

/// `nativeSyncRange(String, String, String, int, int, int[]) -> String`
///
/// Heights cross as `jint`: Java has no unsigned integer type, and a block
/// height fits in a signed 32-bit value for as long as anyone cares.
#[cfg(feature = "sync")]
const SYNC_RANGE: NativeMethod = native_method! {
    fn native_sync_range(
        ufvk: JString,
        grpc_url: JString,
        network: JString,
        start_height: jint,
        end_height: jint,
        known_nullifiers: JString,
        out_status: [jint]
    ) -> JString,
};

/// `nativeChainTip(String, int[]) -> String`
#[cfg(feature = "sync")]
const CHAIN_TIP: NativeMethod = native_method! {
    fn native_chain_tip(grpc_url: JString, out_status: [jint]) -> JString,
};

/// Called by the JVM when `System.loadLibrary("zcash_ffi_mobile")` succeeds.
///
/// `FindClass` resolves through the class loader of whatever called
/// `System.loadLibrary`, which is the Kotlin module itself — so the app's own
/// classes are visible here, unlike from a thread the JVM did not create.
///
/// Returning [`JNI_ERR`] makes `loadLibrary` throw, which is the behaviour we
/// want: a library that cannot register its methods is indistinguishable from
/// an absent one, and the Kotlin layer already reads an `UnsatisfiedLinkError`
/// as "engine unavailable".
///
/// # Safety
/// Called by the JVM with a valid `JavaVM` pointer. Never call this from Rust.
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    let registered = catch_unwind(AssertUnwindSafe(|| {
        let vm = unsafe { JavaVM::from_raw(vm) };

        vm.with_local_frame(8, |env: &mut Env| -> Result<(), Error> {
            // Safety: both descriptors were built by `native_method!`, which
            // checks each function pointer against the signature it registers.
            let class = env.find_class(KOTLIN_CLASS)?;

            // Built at runtime rather than as a literal, because the sync
            // surface is feature-gated: a build without it simply registers
            // two methods, and Kotlin's `external fun` for the third then
            // throws UnsatisfiedLinkError on first call -- which the module
            // already reports as ZCASH_FFI_UNAVAILABLE.
            let mut methods = vec![DERIVE_ORCHARD_ADDRESS, THREAD_PROBE];
            #[cfg(feature = "sync")]
            methods.extend([SYNC_RANGE, CHAIN_TIP]);

            unsafe { env.register_native_methods(&class, &methods) }
        })
    }));

    match registered {
        Ok(Ok(())) => JNIVersion::V1_6.into(),
        // Deliberately silent. The only possible causes are the class or method
        // names above, and a wallet that simply does not carry the Kotlin class
        // should not spew logcat lines on every launch.
        _ => JNI_ERR,
    }
}

/// Hand a result back to Kotlin: status into the `int[]`, string as the return.
fn respond<'local>(
    env: &mut Env<'local>,
    out_status: &JIntArray<'local>,
    status: i32,
    value: String,
) -> Result<JString<'local>, Error> {
    out_status.set_region(env, 0, &[status])?;
    env.new_string(value)
}

/// Backs `ZcashFfiModule.nativeDeriveOrchardAddress`.
fn native_derive_orchard_address<'local>(
    env: &mut Env<'local>,
    _this: JObject<'local>,
    ufvk: JString<'local>,
    out_status: JIntArray<'local>,
) -> Result<JString<'local>, Error> {
    let java_str = ufvk.mutf8_chars(env)?;
    let ufvk_utf8 = java_str.to_str();

    // The engine call is the only part that can panic, and it touches no JNI
    // state — so catching here is honest, and keeps a panic on the documented
    // status path rather than turning into a thrown exception.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let ufvk_str: &str = &ufvk_utf8;

        // Error text from zcash-crypto is fixed strings that never echo the
        // UFVK. Do not enrich it with the input.
        zcash_crypto::keys::orchard_address_from_ufvk(ufvk_str)
            .map_err(|e| (ZCASH_ERR_CRYPTO, e.to_string()))
    }));

    let (status, value) = match outcome {
        Ok(Ok(address)) => (ZCASH_OK, address),
        Ok(Err((code, message))) => (code, message),
        Err(_) => (ZCASH_ERR_PANIC, "panic caught at JNI boundary".to_string()),
    };

    respond(env, &out_status, status, value)
}

/// Backs `ZcashFfiModule.nativeThreadProbe`.
///
/// Diagnostic only. Answers on Android what the iOS run already answered: does
/// Rayon get a real thread pool here, and how well does it scale? Until this
/// runs, every threading figure we hold is an iOS figure.
///
/// The workload is repeated Orchard address derivation — real elliptic-curve
/// work already proven correct on device, not a synthetic loop the optimiser
/// could elide. It is *not* trial decryption, so read it as "does threading
/// work here", never as a sync-throughput number.
fn native_thread_probe<'local>(
    env: &mut Env<'local>,
    _this: JObject<'local>,
    ufvk: JString<'local>,
    iterations: jint,
    out_status: JIntArray<'local>,
) -> Result<JString<'local>, Error> {
    use rayon::prelude::*;
    use std::time::Instant;

    let java_str = ufvk.mutf8_chars(env)?;
    let ufvk_utf8 = java_str.to_str();

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let ufvk_str: &str = &ufvk_utf8;
        let n = iterations.max(1) as u32;

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

    let (status, value) = match outcome {
        Ok(Ok(json)) => (ZCASH_OK, json),
        Ok(Err((code, message))) => (code, message),
        Err(_) => (ZCASH_ERR_PANIC, "panic caught at JNI boundary".to_string()),
    };

    respond(env, &out_status, status, value)
}

/// Backs `ZcashFfiModule.nativeSyncRange`.
///
/// Blocking: occupies the calling thread for the whole range. Kotlin calls it
/// from `Dispatchers.Default`, so the UI thread is unaffected — but there is
/// no progress and no cancellation. See the C ABI twin for the reasoning.
#[cfg(feature = "sync")]
fn native_sync_range<'local>(
    env: &mut Env<'local>,
    _this: JObject<'local>,
    ufvk: JString<'local>,
    grpc_url: JString<'local>,
    network: JString<'local>,
    start_height: jint,
    end_height: jint,
    known_nullifiers: JString<'local>,
    out_status: JIntArray<'local>,
) -> Result<JString<'local>, Error> {
    let ufvk_chars = ufvk.mutf8_chars(env)?;
    let url_chars = grpc_url.mutf8_chars(env)?;
    let network_chars = network.mutf8_chars(env)?;
    let nullifier_chars = known_nullifiers.mutf8_chars(env)?;

    let ufvk_utf8 = ufvk_chars.to_str();
    let url_utf8 = url_chars.to_str();
    let network_utf8 = network_chars.to_str();
    let nullifiers_utf8 = nullifier_chars.to_str();

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        crate::sync_range_json(
            &ufvk_utf8,
            &url_utf8,
            &network_utf8,
            start_height.max(0) as u32,
            end_height.max(0) as u32,
            &nullifiers_utf8,
        )
    }));

    let (status, value) = match outcome {
        Ok(Ok(json)) => (ZCASH_OK, json),
        Ok(Err((code, message))) => (code, message),
        Err(_) => (ZCASH_ERR_PANIC, "panic caught at JNI boundary".to_string()),
    };

    respond(env, &out_status, status, value)
}

/// Backs `ZcashFfiModule.nativeChainTip`.
#[cfg(feature = "sync")]
fn native_chain_tip<'local>(
    env: &mut Env<'local>,
    _this: JObject<'local>,
    grpc_url: JString<'local>,
    out_status: JIntArray<'local>,
) -> Result<JString<'local>, Error> {
    let url_chars = grpc_url.mutf8_chars(env)?;
    let url_utf8 = url_chars.to_str();

    let outcome = catch_unwind(AssertUnwindSafe(|| crate::chain_tip_string(&url_utf8)));

    let (status, value) = match outcome {
        Ok(Ok(height)) => (ZCASH_OK, height),
        Ok(Err((code, message))) => (code, message),
        Err(_) => (ZCASH_ERR_PANIC, "panic caught at JNI boundary".to_string()),
    };

    respond(env, &out_status, status, value)
}
