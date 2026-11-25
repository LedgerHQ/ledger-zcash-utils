//! Drives the `extern "C"` read path the way a C caller would, against a local
//! mock of the lightwalletd service. Every returned string is freed.

mod common;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::{Duration, Instant};

use common::{block_time, MockConfig, MockServer};
use serde_json::{json, Value};
use zcash_ffi_mobile::*;

const UFVK0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";

const TX_HEX: &str = include_str!("../../zcash-crypto/tests/fixtures/tx_0b5baa0c_h3055417.hex");
const TX_ID: &str = "0b5baa0c01ea74f93effe5cc0566eaf086bf67329ff2923bc07a5d0e8859a65e";
const TX_HEIGHT: u32 = 3_055_417;

const SCAN_START: u64 = 1_688_000;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn take(out: *mut c_char) -> String {
    assert!(!out.is_null(), "*out must be written");
    let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
    unsafe { zcash_string_free(out) };
    s
}

fn chain_tip(url: &str) -> (i32, String) {
    let url = c(url);
    let mut out = std::ptr::null_mut();
    let status = unsafe { zcash_get_chain_tip(url.as_ptr(), &mut out) };
    (status, take(out))
}

fn find_height(url: &str, timestamp: u32) -> (i32, String) {
    let url = c(url);
    let mut out = std::ptr::null_mut();
    let status = unsafe { zcash_find_block_height(url.as_ptr(), timestamp, &mut out) };
    (status, take(out))
}

fn orchard_address(ufvk: &str) -> (i32, String) {
    let ufvk = c(ufvk);
    let mut out = std::ptr::null_mut();
    let status = unsafe { zcash_orchard_address_from_ufvk(ufvk.as_ptr(), &mut out) };
    (status, take(out))
}

fn details(url: &str, requests: &str, network: Option<&str>, ufvk: Option<&str>) -> (i32, String) {
    let (url, requests) = (c(url), c(requests));
    let (network, ufvk) = (network.map(c), ufvk.map(c));
    let ptr = |s: &Option<CString>| s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    let mut out = std::ptr::null_mut();
    let status = unsafe {
        zcash_transaction_details(
            url.as_ptr(),
            requests.as_ptr(),
            ptr(&network),
            ptr(&ufvk),
            &mut out,
        )
    };
    (status, take(out))
}

fn start(params: &Value) -> (i32, *mut ZcashSyncHandle, String) {
    let params = c(&params.to_string());
    let mut handle = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    let status = unsafe { zcash_sync_start(params.as_ptr(), &mut handle, &mut err) };
    let message = if status == ZCASH_OK {
        String::new()
    } else {
        take(err)
    };
    (status, handle, message)
}

fn finish(handle: *mut ZcashSyncHandle) -> (i32, String) {
    let mut out = std::ptr::null_mut();
    let status = unsafe { zcash_sync_finish(handle, &mut out) };
    (status, take(out))
}

fn scan_params(url: &str, ufvk: &str, start: u64, end: u64) -> Value {
    json!({
        "grpcUrl": url, "viewingKey": ufvk, "network": "mainnet",
        "startHeight": start, "endHeight": end,
    })
}

fn scan(params: &Value) -> (i32, String) {
    let (status, handle, message) = start(params);
    assert_eq!(status, ZCASH_OK, "start failed: {message}");
    let result = finish(handle);
    unsafe { zcash_sync_free(handle) };
    result
}

fn engine<T>(future: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}

fn closed_port_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    url
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

fn fixture_config() -> MockConfig {
    let mut transactions = HashMap::new();
    transactions.insert(TX_ID.to_string(), hex::decode(TX_HEX.trim()).unwrap());
    MockConfig {
        transactions,
        ..MockConfig::default()
    }
}

// ─── chain queries ────────────────────────────────────────────────────────────

#[test]
fn chain_tip_returns_the_tip_as_a_json_number() {
    let mock = MockServer::start(MockConfig {
        tip: 1_689_123,
        ..MockConfig::default()
    });
    assert_eq!(chain_tip(&mock.url), (ZCASH_OK, "1689123".to_string()));
}

#[test]
fn chain_tip_errors_carry_the_engines_own_message() {
    let dead = closed_port_url();
    let expected = engine(zcash_sync::client::chain_tip(dead.clone()))
        .unwrap_err()
        .to_string();
    assert_eq!(chain_tip(&dead), (ZCASH_ERR_ENGINE, expected));

    let mock = MockServer::start(MockConfig {
        fail_chain_tip: true,
        ..MockConfig::default()
    });
    let expected = engine(zcash_sync::client::chain_tip(mock.url.clone()))
        .unwrap_err()
        .to_string();
    let (status, message) = chain_tip(&mock.url);
    assert_eq!((status, &message), (ZCASH_ERR_ENGINE, &expected));
    assert!(message.contains("GetLatestBlock failed"), "got: {message}");
}

#[test]
fn find_block_height_matches_the_engine_before_between_and_after() {
    let mock = MockServer::start(MockConfig::default());
    let tip = MockConfig::default().tip;
    let cases = [
        (1_000, 1_687_104),
        (block_time(1_688_000) + 10, 1_688_000),
        (block_time(tip) + 10_000, tip),
    ];
    for (timestamp, expected_height) in cases {
        let direct = engine(zcash_sync::client::find_block_height(
            mock.url.clone(),
            timestamp,
        ))
        .unwrap();
        let (status, text) = find_height(&mock.url, timestamp);
        assert_eq!(status, ZCASH_OK);
        assert_eq!(text, direct.to_string(), "timestamp {timestamp}");
        assert_eq!(direct as u64, expected_height, "timestamp {timestamp}");
    }
}

#[test]
fn find_block_height_reports_the_engines_error() {
    let dead = closed_port_url();
    let expected = engine(zcash_sync::client::find_block_height(dead.clone(), 5))
        .unwrap_err()
        .to_string();
    assert_eq!(find_height(&dead, 5), (ZCASH_ERR_ENGINE, expected));
}

// ─── scan ─────────────────────────────────────────────────────────────────────

#[test]
fn bounded_scan_reports_blocks_scanned_and_the_node_shape() {
    let mock = MockServer::start(MockConfig::default());
    for orchard_only in [false, true] {
        let mut params = scan_params(&mock.url, UFVK0, SCAN_START, SCAN_START + 99);
        params["orchardOnly"] = json!(orchard_only);
        let (status, text) = scan(&params);
        assert_eq!(status, ZCASH_OK, "{text}");

        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(keys(&v), ["stats", "transactions"]);
        assert_eq!(v["transactions"], json!([]));
        assert_eq!(
            keys(&v["stats"]),
            ["blocksScanned", "elapsedMs", "spentKnownNullifiers"]
        );
        assert_eq!(v["stats"]["blocksScanned"], 100);
        assert_eq!(v["stats"]["spentKnownNullifiers"], json!([]));
    }
}

#[test]
fn known_nullifiers_are_accepted_and_none_is_reported_spent_without_a_spend() {
    let mock = MockServer::start(MockConfig::default());
    let mut params = scan_params(&mock.url, UFVK0, SCAN_START, SCAN_START + 9);
    params["knownNullifiers"] = json!(["11".repeat(32)]);
    let (status, text) = scan(&params);
    assert_eq!(status, ZCASH_OK, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["stats"]["spentKnownNullifiers"], json!([]));
}

#[test]
fn a_stream_failure_surfaces_as_an_engine_error() {
    let mock = MockServer::start(MockConfig {
        range_error_after: Some(5),
        ..MockConfig::default()
    });
    let (status, message) = scan(&scan_params(&mock.url, UFVK0, SCAN_START, SCAN_START + 50));
    assert_eq!(status, ZCASH_ERR_ENGINE);
    assert!(message.contains("stream error"), "got: {message}");
}

#[test]
fn a_scan_against_an_unreachable_endpoint_is_an_engine_error() {
    let (status, message) = scan(&scan_params(&closed_port_url(), UFVK0, 1, 2));
    assert_eq!(status, ZCASH_ERR_ENGINE);
    assert!(message.contains("gRPC connect failed"), "got: {message}");
}

#[test]
fn a_second_finish_is_an_invalid_argument() {
    let mock = MockServer::start(MockConfig::default());
    let (status, handle, _) = start(&scan_params(&mock.url, UFVK0, SCAN_START, SCAN_START + 2));
    assert_eq!(status, ZCASH_OK);
    assert_eq!(finish(handle).0, ZCASH_OK);
    assert_eq!(finish(handle).0, ZCASH_ERR_INVALID_ARG);
    unsafe { zcash_sync_free(handle) };
}

#[test]
fn cancel_before_finish_returns_cancelled_quickly_and_releases_the_connection() {
    // 10,000 blocks at 50 ms each: more than 8 minutes if it ran to the end.
    let mock = MockServer::start(MockConfig {
        block_delay: Duration::from_millis(50),
        ..MockConfig::default()
    });
    let (status, handle, _) = start(&scan_params(
        &mock.url,
        UFVK0,
        SCAN_START,
        SCAN_START + 9_999,
    ));
    assert_eq!(status, ZCASH_OK);

    std::thread::sleep(Duration::from_millis(300));
    assert!(mock.open_connections() >= 1, "the scan should be connected");

    unsafe { zcash_sync_cancel(handle) };
    unsafe { zcash_sync_cancel(handle) };
    let began = Instant::now();
    let (status, message) = finish(handle);
    assert_eq!(status, ZCASH_ERR_CANCELLED);
    assert_eq!(message, "sync was cancelled");
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "took {:?}",
        began.elapsed()
    );

    unsafe { zcash_sync_free(handle) };
    assert!(
        mock.wait_until_idle(Duration::from_secs(2)),
        "connection still open"
    );
}

#[test]
fn freeing_a_running_scan_aborts_it_and_releases_the_connection() {
    let mock = MockServer::start(MockConfig {
        block_delay: Duration::from_millis(50),
        ..MockConfig::default()
    });
    let (_, handle, _) = start(&scan_params(
        &mock.url,
        UFVK0,
        SCAN_START,
        SCAN_START + 9_999,
    ));
    std::thread::sleep(Duration::from_millis(300));
    unsafe { zcash_sync_free(handle) };
    assert!(
        mock.wait_until_idle(Duration::from_secs(2)),
        "connection still open"
    );
}

#[test]
fn other_calls_return_while_a_scan_is_in_flight() {
    let slow = MockServer::start(MockConfig {
        block_delay: Duration::from_millis(50),
        ..MockConfig::default()
    });
    let quick = MockServer::start(MockConfig::default());
    let (_, handle, _) = start(&scan_params(
        &slow.url,
        UFVK0,
        SCAN_START,
        SCAN_START + 9_999,
    ));
    let handle_addr = handle as usize;
    let waiter = std::thread::spawn(move || finish(handle_addr as *mut ZcashSyncHandle));
    std::thread::sleep(Duration::from_millis(300));

    let quick_url = quick.url.clone();
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let url = quick_url.clone();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let began = Instant::now();
                    assert_eq!(chain_tip(&url).0, ZCASH_OK);
                    assert_eq!(orchard_address(UFVK0).0, ZCASH_OK);
                    assert!(
                        began.elapsed() < Duration::from_secs(1),
                        "{:?}",
                        began.elapsed()
                    );
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert!(!waiter.is_finished(), "the scan must still be in flight");

    unsafe { zcash_sync_cancel(handle) };
    assert_eq!(waiter.join().unwrap().0, ZCASH_ERR_CANCELLED);
    unsafe { zcash_sync_free(handle) };
}

// ─── transaction details ──────────────────────────────────────────────────────

#[test]
fn transaction_details_returns_fee_as_a_decimal_string_and_payees() {
    let mock = MockServer::start(fixture_config());
    let expected_fee = zcash_crypto::fee::transaction_fee(
        TX_HEX.trim(),
        TX_HEIGHT,
        zcash_protocol::consensus::Network::MainNetwork,
        &HashMap::new(),
    )
    .unwrap()
    .expect("the fixture is fully shielded, so its fee is known");

    let requests = json!([{"txid": TX_ID, "height": TX_HEIGHT, "prevouts": []}]).to_string();
    let (status, text) = details(&mock.url, &requests, Some("mainnet"), Some(UFVK0));
    assert_eq!(status, ZCASH_OK, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["txid"], TX_ID);
    assert_eq!(v[0]["fee"], json!(expected_fee.to_string()));
    assert!(v[0]["payees"].is_array());
    assert_eq!(keys(&v[0]), ["fee", "payees", "txid"]);
}

#[test]
fn transaction_details_for_an_unknown_txid_has_no_fee_key() {
    let mock = MockServer::start(fixture_config());
    let unknown = "ab".repeat(32);
    let requests = json!([{"txid": unknown, "height": TX_HEIGHT, "prevouts": []}]).to_string();
    let (status, text) = details(&mock.url, &requests, Some("mainnet"), None);
    assert_eq!(status, ZCASH_OK, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(keys(&v[0]), ["payees", "txid"]);
    assert_eq!(v[0]["payees"], json!([]));
}

#[test]
fn transaction_details_input_errors() {
    let mock = MockServer::start(fixture_config());

    let bad_prevout = json!([{"txid": TX_ID, "height": 1,
        "prevouts": [{"txid": TX_ID, "index": 0, "value": "12x"}]}])
    .to_string();
    let (status, message) = details(&mock.url, &bad_prevout, None, None);
    assert_eq!(status, ZCASH_ERR_ENGINE);
    assert!(message.starts_with("prevout value 12x: "), "got: {message}");

    let (status, message) = details(&mock.url, "[not json", None, None);
    assert_eq!(status, ZCASH_ERR_INVALID_ARG);
    assert_eq!(message, "requests_json is not valid: malformed JSON");

    let (status, _) = details(&mock.url, "[]", Some("moonnet"), None);
    assert_eq!(status, ZCASH_ERR_ENGINE);

    let (status, text) = details(&mock.url, "[]", None, None);
    assert_eq!((status, text.as_str()), (ZCASH_OK, "[]"));
}

// ─── argument handling ────────────────────────────────────────────────────────

#[test]
fn null_arguments_return_null_arg_and_leave_out_untouched() {
    let s = c("x");
    let mut out: *mut c_char = std::ptr::null_mut();
    let mut handle: *mut ZcashSyncHandle = std::ptr::null_mut();
    unsafe {
        assert_eq!(
            zcash_get_chain_tip(std::ptr::null(), &mut out),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_get_chain_tip(s.as_ptr(), std::ptr::null_mut()),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_find_block_height(std::ptr::null(), 1, &mut out),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_transaction_details(
                std::ptr::null(),
                s.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut out
            ),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_transaction_details(
                s.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                &mut out
            ),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_sync_start(std::ptr::null(), &mut handle, &mut out),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_sync_start(s.as_ptr(), std::ptr::null_mut(), &mut out),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_sync_start(s.as_ptr(), &mut handle, std::ptr::null_mut()),
            ZCASH_ERR_NULL_ARG
        );
        assert_eq!(
            zcash_sync_finish(std::ptr::null_mut(), &mut out),
            ZCASH_ERR_NULL_ARG
        );
        zcash_sync_cancel(std::ptr::null_mut());
        zcash_sync_free(std::ptr::null_mut());
    }
    assert!(out.is_null() && handle.is_null());
}

#[test]
fn non_utf8_arguments_are_rejected_by_every_export() {
    let bad = CString::new(vec![0x75u8, 0xFF, 0xFE]).unwrap();
    let ok = c("x");
    let mut out: *mut c_char = std::ptr::null_mut();
    let mut handle: *mut ZcashSyncHandle = std::ptr::null_mut();
    unsafe {
        assert_eq!(
            zcash_get_chain_tip(bad.as_ptr(), &mut out),
            ZCASH_ERR_INVALID_UTF8
        );
        take(out);
        assert_eq!(
            zcash_find_block_height(bad.as_ptr(), 1, &mut out),
            ZCASH_ERR_INVALID_UTF8
        );
        take(out);
        assert_eq!(
            zcash_transaction_details(
                ok.as_ptr(),
                bad.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut out
            ),
            ZCASH_ERR_INVALID_UTF8
        );
        take(out);
        assert_eq!(
            zcash_transaction_details(
                ok.as_ptr(),
                ok.as_ptr(),
                bad.as_ptr(),
                std::ptr::null(),
                &mut out
            ),
            ZCASH_ERR_INVALID_UTF8
        );
        take(out);
        assert_eq!(
            zcash_sync_start(bad.as_ptr(), &mut handle, &mut out),
            ZCASH_ERR_INVALID_UTF8
        );
        take(out);
    }
    assert!(handle.is_null());
}

#[test]
fn empty_and_malformed_json_arguments_are_invalid_arguments() {
    for text in ["", "{", "[]", "null", "{\"grpcUrl\":1}"] {
        let handle_params = c(text);
        let mut handle: *mut ZcashSyncHandle = std::ptr::null_mut();
        let mut err: *mut c_char = std::ptr::null_mut();
        let status = unsafe { zcash_sync_start(handle_params.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, ZCASH_ERR_INVALID_ARG, "input {text:?}");
        take(err);
        assert!(handle.is_null());
    }
    assert_eq!(
        details("http://127.0.0.1:1", "", None, None).0,
        ZCASH_ERR_INVALID_ARG
    );
}

#[test]
fn empty_url_is_an_engine_error() {
    assert_eq!(chain_tip("").0, ZCASH_ERR_ENGINE);
}

// ─── no viewing key in errors or logs ─────────────────────────────────────────

fn windows_of(secret: &str) -> impl Iterator<Item = &str> {
    (0..=secret.len() - 20).map(move |i| &secret[i..i + 20])
}

fn assert_no_key_material(text: &str, secret: &str, context: &str) {
    for window in windows_of(secret) {
        assert!(
            !text.contains(window),
            "{context} leaked viewing-key material: {text}"
        );
    }
}

#[test]
fn errors_never_contain_viewing_key_material() {
    let mock = MockServer::start(fixture_config());
    let broken = &UFVK0[..UFVK0.len() - 10];

    let (status, message) = orchard_address(broken);
    assert_eq!(status, ZCASH_ERR_ENGINE);
    assert_no_key_material(&message, broken, "orchard address");

    let (status, message) = scan(&scan_params(&mock.url, broken, SCAN_START, SCAN_START + 2));
    assert_eq!(status, ZCASH_ERR_ENGINE);
    assert_no_key_material(&message, broken, "scan");

    let requests = json!([{"txid": TX_ID, "height": TX_HEIGHT, "prevouts": []}]).to_string();
    let (_, text) = details(&mock.url, &requests, Some("mainnet"), Some(broken));
    assert_no_key_material(&text, broken, "transaction details");

    let wrong_type = json!({"grpcUrl": mock.url, "viewingKey": broken,
        "startHeight": "not a number", "endHeight": 2});
    let (status, _, message) = start(&wrong_type);
    assert_eq!(status, ZCASH_ERR_INVALID_ARG);
    assert_no_key_material(&message, broken, "scan parameters");
}

/// Runs a scan and a details call with a real key. It does nothing unless the
/// parent test re-executes this binary with the flag set, so that the parent can
/// read everything the process writes to stdout and stderr.
#[test]
fn child_process_workload() {
    if std::env::var("ZCASH_FFI_LOG_CHILD").is_err() {
        return;
    }
    let mock = MockServer::start(fixture_config());
    let broken = &UFVK0[..UFVK0.len() - 10];
    println!(
        "scan: {:?}",
        scan(&scan_params(&mock.url, UFVK0, SCAN_START, SCAN_START + 20))
    );
    println!(
        "bad scan: {:?}",
        scan(&scan_params(&mock.url, broken, SCAN_START, SCAN_START + 2))
    );
    let requests = json!([
        {"txid": TX_ID, "height": TX_HEIGHT, "prevouts": []},
        {"txid": "ab".repeat(32), "height": TX_HEIGHT, "prevouts": []}
    ])
    .to_string();
    println!(
        "details: {:?}",
        details(&mock.url, &requests, Some("mainnet"), Some(UFVK0))
    );
    println!(
        "bad details: {:?}",
        details(&mock.url, &requests, Some("mainnet"), Some(broken))
    );
}

#[test]
fn logs_never_contain_viewing_key_material() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_process_workload",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZCASH_FFI_LOG_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "child failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("scan: (0,"),
        "the workload did not run: {stdout}"
    );
    assert_no_key_material(&stdout, UFVK0, "stdout");
    assert_no_key_material(&stderr, UFVK0, "stderr");
}
