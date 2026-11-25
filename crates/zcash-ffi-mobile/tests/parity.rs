//! Keeps the mobile binding in step with the Node binding.
//!
//! `index.d.ts` is the committed napi output. A new Node export fails
//! `every_node_export_is_classified` until someone says whether the mobile
//! binding mirrors it; a mirrored export must have a C symbol and a JNI method;
//! and the JSON shapes must carry the fields, and the optionality, of the
//! TypeScript interfaces.
//!
//! Moving an export from `WRITE_PATH_PENDING` into the mobile table, and adding
//! its interfaces to the shape lists, is all the write path needs here.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use zcash_ffi_mobile::dto::*;
use zcash_ffi_mobile::READ_PATH_EXPORTS;

const INDEX_D_TS: &str = include_str!("../../../index.d.ts");
const HEADER: &str = include_str!("../include/zcash_ffi_mobile.h");

const READ_PATH: &[&str] = &[
    "getChainTip",
    "findBlockHeight",
    "startSync",
    "orchardAddressFromUfvk",
    "transactionDetails",
];
const WRITE_PATH_PENDING: &[&str] = &[
    "buildTransaction",
    "buildIronwoodTransaction",
    "parsePczt",
    "finalizeTransaction",
    "broadcastTransaction",
];
/// Key-derivation helpers for development; never bound on a wallet surface.
const TEST_ONLY: &[&str] = &["testDeriveKeys", "testSignPczt"];

/// C functions of the header that are not a Node export of their own.
const SUPPORT_SYMBOLS: &[&str] = &[
    "zcash_sync_cancel",
    "zcash_sync_finish",
    "zcash_sync_free",
    "zcash_string_free",
];

fn node_exports() -> BTreeSet<String> {
    INDEX_D_TS
        .lines()
        .filter_map(|l| l.strip_prefix("export declare function "))
        .map(|rest| rest.split('(').next().unwrap().to_string())
        .collect()
}

/// `(name, optional, type)` of each field of `export interface <name>`.
fn interface_fields(name: &str) -> Vec<(String, bool, String)> {
    let header = format!("export interface {name} {{");
    let mut lines = INDEX_D_TS.lines().skip_while(|l| *l != header);
    assert!(
        lines.next().is_some(),
        "interface {name} not found in index.d.ts"
    );
    let mut fields = Vec::new();
    for line in lines {
        if line == "}" {
            break;
        }
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
            continue;
        }
        let (field, ty) = rest.split_once(": ").expect("field line");
        let (field, optional) = match field.strip_suffix('?') {
            Some(f) => (f, true),
            None => (field, false),
        };
        fields.push((field.to_string(), optional, ty.trim().to_string()));
    }
    assert!(!fields.is_empty(), "interface {name} has no fields");
    fields
}

fn sample_for(ty: &str) -> Value {
    match ty {
        "string" => json!("x"),
        "number" => json!(1),
        "boolean" => json!(true),
        t if t.starts_with("Array<") => json!([]),
        other => panic!("unsupported field type {other}"),
    }
}

fn key_set(v: &Value) -> BTreeSet<String> {
    v.as_object().expect("an object").keys().cloned().collect()
}

fn all_fields(name: &str) -> BTreeSet<String> {
    interface_fields(name).into_iter().map(|f| f.0).collect()
}

fn required_fields(name: &str) -> BTreeSet<String> {
    interface_fields(name)
        .into_iter()
        .filter(|f| !f.1)
        .map(|f| f.0)
        .collect()
}

// ─── classification and counterparts ──────────────────────────────────────────

#[test]
fn every_node_export_is_classified() {
    let classified: Vec<&str> = READ_PATH
        .iter()
        .chain(WRITE_PATH_PENDING)
        .chain(TEST_ONLY)
        .copied()
        .collect();
    let unique: BTreeSet<&str> = classified.iter().copied().collect();
    assert_eq!(unique.len(), classified.len(), "a name is classified twice");

    let exports = node_exports();
    let unclassified: Vec<_> = exports
        .iter()
        .filter(|e| !unique.contains(e.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "new Node export(s) {unclassified:?}: classify them in tests/parity.rs as read path, \
         write path pending or test only, and bind a read-path export in the same change"
    );
    let stale: Vec<_> = unique.iter().filter(|c| !exports.contains(**c)).collect();
    assert!(
        stale.is_empty(),
        "classified but not exported by index.d.ts: {stale:?}"
    );
}

#[test]
fn every_read_path_export_has_a_counterpart() {
    for name in READ_PATH {
        let entry = READ_PATH_EXPORTS
            .iter()
            .find(|e| e.napi_name == *name)
            .unwrap_or_else(|| panic!("{name} has no entry in READ_PATH_EXPORTS"));
        assert!(
            header_functions().contains(entry.c_symbol),
            "{} is missing from include/zcash_ffi_mobile.h",
            entry.c_symbol
        );
        assert!(!entry.jni_method.is_empty(), "{name} has no JNI method");
    }
    for entry in READ_PATH_EXPORTS {
        assert!(
            READ_PATH.contains(&entry.napi_name),
            "{} is not classified",
            entry.napi_name
        );
    }
}

fn header_functions() -> BTreeSet<String> {
    let mut text = String::new();
    let mut rest = HEADER;
    while let Some(start) = rest.find("/*") {
        text.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("unterminated comment") + start + 2;
        rest = &rest[end..];
    }
    text.push_str(rest);
    let mut found = BTreeSet::new();
    for (i, _) in text.match_indices('(') {
        let word: String = text[..i]
            .trim_end()
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if word.starts_with("zcash_") {
            found.insert(word);
        }
    }
    found
}

#[test]
fn the_header_declares_exactly_the_mirrored_symbols_and_their_helpers() {
    let expected: BTreeSet<String> = READ_PATH_EXPORTS
        .iter()
        .map(|e| e.c_symbol.to_string())
        .chain(SUPPORT_SYMBOLS.iter().map(|s| s.to_string()))
        .collect();
    assert_eq!(header_functions(), expected);
}

// ─── output shapes ────────────────────────────────────────────────────────────

fn note(full: bool) -> ShieldedNote {
    let s = |v: &str| full.then(|| v.to_string());
    ShieldedNote {
        amount: 1.0,
        transfer_type: "incoming".into(),
        memo: String::new(),
        pool: "orchard".into(),
        nullifier: s("a"),
        rho: s("b"),
        rseed: s("c"),
        cmx: s("d"),
        position: s("1"),
        recipient: s("e"),
        is_spent: false,
    }
}

fn transaction(full: bool) -> ShieldedTransaction {
    let notes = || if full { vec![note(full)] } else { vec![] };
    ShieldedTransaction {
        txid: "t".into(),
        hex: "h".into(),
        block_height: 1,
        block_hash: "b".into(),
        block_time: 1,
        fee: 1.0,
        transparent_out: 0.0,
        has_transparent_inputs: false,
        sapling_notes: notes(),
        orchard_notes: notes(),
        ironwood_notes: notes(),
    }
}

fn assert_shape(name: &str, full: Value, empty: Value) {
    assert_eq!(
        key_set(&full),
        all_fields(name),
        "{name}: a fully populated value"
    );
    assert_eq!(
        key_set(&empty),
        required_fields(name),
        "{name}: an empty value"
    );
}

#[test]
fn output_shapes_carry_the_node_fields_and_optionality() {
    assert_shape(
        "ShieldedNote",
        serde_json::to_value(note(true)).unwrap(),
        serde_json::to_value(note(false)).unwrap(),
    );
    assert_shape(
        "ShieldedTransaction",
        serde_json::to_value(transaction(true)).unwrap(),
        serde_json::to_value(transaction(false)).unwrap(),
    );
    let stats = || SyncStats {
        blocks_scanned: 1,
        elapsed_ms: 1.0,
        spent_known_nullifiers: vec![],
    };
    assert_shape(
        "SyncStats",
        serde_json::to_value(stats()).unwrap(),
        serde_json::to_value(stats()).unwrap(),
    );
    let details = |fee: Option<&str>| TransactionDetailsResult {
        txid: "t".into(),
        fee: fee.map(str::to_string),
        payees: vec![],
    };
    assert_shape(
        "TransactionDetailsResult",
        serde_json::to_value(details(Some("1"))).unwrap(),
        serde_json::to_value(details(None)).unwrap(),
    );
}

#[test]
fn nested_notes_in_a_transaction_follow_the_note_shape() {
    let v = serde_json::to_value(transaction(true)).unwrap();
    for pool in ["saplingNotes", "orchardNotes", "ironwoodNotes"] {
        assert_eq!(key_set(&v[pool][0]), all_fields("ShieldedNote"), "{pool}");
    }
}

#[test]
fn scan_amounts_are_numbers_and_positions_are_strings() {
    let v = serde_json::to_value(note(true)).unwrap();
    assert!(v["amount"].is_number());
    assert!(v["position"].is_string());
    let v = serde_json::to_value(transaction(true)).unwrap();
    assert!(v["fee"].is_number() && v["transparentOut"].is_number());
}

// ─── input shapes ─────────────────────────────────────────────────────────────

fn object_with(name: &str, only_required: bool) -> serde_json::Map<String, Value> {
    interface_fields(name)
        .into_iter()
        .filter(|f| !(only_required && f.1))
        .map(|(field, _, ty)| (field, sample_for(&ty)))
        .collect()
}

fn assert_input<T: serde::de::DeserializeOwned>(name: &str) {
    let required = object_with(name, true);
    serde_json::from_value::<T>(Value::Object(required.clone()))
        .unwrap_or_else(|e| panic!("{name}: required fields alone must deserialise: {e}"));
    serde_json::from_value::<T>(Value::Object(object_with(name, false)))
        .unwrap_or_else(|e| panic!("{name}: every field must deserialise: {e}"));
    for field in required.keys() {
        let mut without = required.clone();
        without.remove(field);
        assert!(
            serde_json::from_value::<T>(Value::Object(without)).is_err(),
            "{name}: dropping required field {field} must fail"
        );
    }
}

#[test]
fn input_shapes_accept_the_node_fields() {
    assert_input::<SyncParams>("SyncParams");
    assert_input::<TransactionDetailsRequest>("TransactionDetailsRequest");
    assert_input::<TransparentPrevout>("TransparentPrevout");
}
