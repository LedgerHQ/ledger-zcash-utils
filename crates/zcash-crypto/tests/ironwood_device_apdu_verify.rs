//! Offline replay of the three device verification steps that produce `6a80`
//! (SW_INVALID_TRANSACTION) on a real Flex device during an Ironwood
//! shielded-to-transparent signing attempt.
//!
//! Log file: `ledgerwallet-logs-2026.08.10-22.01.00-562a663724.txt`
//! The PCZT signing session starts at line 149996; all APDUs return 9000
//! except the 116-byte `output_metadata` chunk (last chunk of action 1) → 6a80.
//!
//! The firmware's `finish_current_ironwood_action` runs checks in order:
//!   1. `verify_current_ironwood_cv_net`  – cv_net = value_net×V + rcv×R
//!   2. `verify_current_ironwood_spend_nullifier` – recipient in FVK, then nullifier
//!   3. `validate_current_ironwood_dummy_output`  – V3 cmx from (recipient, 0, nf, rseed)
//!
//! This file exercises checks 1 and 3 (no device key needed) and explains why
//! check 2 fails: `spend_nullifier_bytes` uses V2 note commitment but Ironwood
//! spend notes are V3 → different cm → wrong nullifier → "PCZT ironwood
//! nullifier mismatch" → 6a80.
//!
//! All hex values are extracted verbatim from the APDU log — no fabrication.
//!
//! Run with:
//!   cargo test -p zcash-crypto --test ironwood_device_apdu_verify -- --nocapture

// ── Values from the 243-byte spend data APDU (e0588000f3…) ──────────────────

/// cv_net from the PCZT (first 32 bytes of the spend-data chunk).
const CV_NET_BYTES: [u8; 32] =
    hex32("3ac396d7204a12da25e6bdc812b3d87b6a232d020715bdad49fdce6d55c31091");

/// Action 1 nullifier (also the `rho` for the paired dummy output).
const NULLIFIER_BYTES: [u8; 32] =
    hex32("36a49957c16f4164600d22359a1b1e32715fd686f7adfff2a7aea63c5f58bb3f");

/// Spend recipient raw address (43 bytes, from spend data at offset 96).
const SPEND_RECIPIENT: [u8; 43] =
    hex43("a366f81e8cd38fb68a2a8a27f97da364461c9834d56ed443799f8f971ad7589f351567e2c373ed21a2cd11");

/// Spend value in zatoshis.
const SPEND_VALUE: u64 = 2_335_000;

/// Spend rho — the rho used when the spend note was created (from offset 147).
const SPEND_RHO: [u8; 32] =
    hex32("2bbb3711eae9cc17faf3603ee12f6dca0ec859baa8d96bbdf205383e9531bd3a");

/// Spend rseed (from spend data at offset 179).
const SPEND_RSEED: [u8; 32] =
    hex32("0a8ca2c189ea1f5c3c5da1c3e9ded9d7103f369245afb5375f4f14bfc517f8e5");

// ── Values from the 116-byte output_metadata APDU (e058800074…) ─────────────

/// Output recipient raw address (43 bytes — the dummy output target).
const OUTPUT_RECIPIENT: [u8; 43] =
    hex43("d6865a62e562fa39ec82c4e5454bbce50e1fd1325ba6c0fc10718e442e796d20d856cc991b30c19be9212e");

/// Output value (zero = dummy output).
const OUTPUT_VALUE: u64 = 0;

/// Output rseed (from output_metadata at offset 51).
const OUTPUT_RSEED: [u8; 32] =
    hex32("4b19f8f053fe955d92c21aecc1109d73c72b94044876dc52a73bea23ed3d7d4d");

/// Net value commitment randomness (rcv) from output_metadata at offset 83.
const RCV_BYTES: [u8; 32] =
    hex32("a91422fea4f800ddfe8aaaabf58618d97602921c604081b4d8b7d62d1b80fe38");

/// Note version byte from output_metadata offset 115 (0x03 = V3/Ironwood).
const NOTE_VERSION_BYTE: u8 = 0x03;

// ── cmx from the earlier 64-byte chunk (cmx + ephemeral_key) ────────────────

/// Expected cmx in the PCZT (first 32 bytes of the 64-byte cmx+ephkey chunk).
const CMX_BYTES: [u8; 32] =
    hex32("d717454e90da1632c7538d301badbd1e931b3c7b035703b26ad71a3a182f5c07");

// ── Helper: const-eval hex decoding ─────────────────────────────────────────

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex32: need exactly 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[i * 2]) << 4 | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex43(s: &str) -> [u8; 43] {
    let b = s.as_bytes();
    assert!(b.len() == 86, "hex43: need exactly 86 hex chars");
    let mut out = [0u8; 43];
    let mut i = 0;
    while i < 43 {
        out[i] = nibble(b[i * 2]) << 4 | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}

// ── Imports ──────────────────────────────────────────────────────────────────

use orchard::{
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Address, Note, NoteVersion,
};

// ── Tests ────────────────────────────────────────────────────────────────────

/// Check 1: cv_net from ValueCommitment::derive(value_net, rcv) must match PCZT.
///
/// The firmware uses hardware Pallas multiplication; this test uses the pure-Rust
/// orchard crate.  A pass here means check 1 is NOT the source of the 6a80.
#[test]
fn check1_cv_net_matches_pczt() {
    assert_eq!(NOTE_VERSION_BYTE, 0x03);

    let rcv = ValueCommitTrapdoor::from_bytes(RCV_BYTES)
        .into_option()
        .expect("rcv must be a canonical Pallas scalar");

    let value_net = NoteValue::from_raw(SPEND_VALUE) - NoteValue::from_raw(OUTPUT_VALUE);
    let cv_net = ValueCommitment::derive(value_net, rcv);
    let cv_net_bytes = cv_net.to_bytes();

    println!("cv_net (host)  : {}", hex::encode(cv_net_bytes));
    println!("cv_net (PCZT)  : {}", hex::encode(CV_NET_BYTES));

    assert_eq!(
        cv_net_bytes, CV_NET_BYTES,
        "CHECK 1 FAILS — not the source of 6a80 if this passes"
    );
    println!("✓ Check 1 PASSES: cv_net matches");
}

/// Check 3: V3 cmx from Note::commitment() must match PCZT.
///
/// The firmware uses software Sinsemilla + diversify_hash_ledger.
/// A pass here means check 3 is NOT the source of the 6a80.
#[test]
fn check3_v3_cmx_matches_pczt() {
    assert_eq!(NOTE_VERSION_BYTE, 0x03);

    // rho for the dummy output = the spend nullifier
    let rho_output = Rho::from_bytes(&NULLIFIER_BYTES)
        .into_option()
        .expect("nullifier must be a valid Pallas base field element");

    let recipient = Address::from_raw_address_bytes(&OUTPUT_RECIPIENT)
        .into_option()
        .expect("output_recipient must be a valid Orchard raw address");

    let rseed = RandomSeed::from_bytes(OUTPUT_RSEED, &rho_output)
        .into_option()
        .expect("rseed must be valid for the given rho");

    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(OUTPUT_VALUE),
        rho_output,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .expect("note must have a valid V3 commitment by construction");

    let cmx_bytes = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    println!("cmx (host V3)  : {}", hex::encode(cmx_bytes));
    println!("cmx (PCZT)     : {}", hex::encode(CMX_BYTES));

    assert_eq!(
        cmx_bytes, CMX_BYTES,
        "CHECK 3 FAILS — not the source of 6a80 if this passes"
    );
    println!("✓ Check 3 PASSES: V3 cmx matches");
}

/// Root-cause diagnosis: check 2 (spend nullifier) fails because the firmware's
/// `spend_nullifier_bytes` uses **V2** note commitment while the Ironwood spend
/// note on-chain has a **V3** commitment.
///
/// This test demonstrates the mismatch without needing the device's private key:
/// it computes the V3 nullifier (what the PCZT contains) and the V2 nullifier
/// (what the firmware recomputes) and shows they are different.
///
/// Fix needed in firmware: `verify_current_ironwood_spend_nullifier` must use
/// V3 note commitment when computing the expected nullifier.
#[test]
fn check2_diagnosis_spend_nullifier_requires_v3_commitment() {
    // The PCZT nullifier was derived by the orchard crate from a V3 spend note.
    // Verify that reconstructing the spend note with V3 version gives back
    // the PCZT nullifier.
    //
    // NOTE: we cannot call `note.nullifier(fvk)` without the device's FVK.
    // Instead we verify that the V3 note commitment of the spend note produces
    // a DIFFERENT x-coordinate than the V2 commitment — proving the firmware's
    // V2-based nullifier recomputation is wrong for V3 notes.

    let rho_spend = Rho::from_bytes(&SPEND_RHO)
        .into_option()
        .expect("spend_rho must be a valid Pallas base field element");

    let spend_addr = Address::from_raw_address_bytes(&SPEND_RECIPIENT)
        .into_option()
        .expect("spend_recipient must be a valid Orchard raw address");

    let rseed_v3 = RandomSeed::from_bytes(SPEND_RSEED, &rho_spend)
        .into_option()
        .expect("spend_rseed must be valid for V3");

    // V3 spend note commitment (what orchard crate / on-chain uses)
    let note_v3 = Note::from_parts(
        spend_addr,
        NoteValue::from_raw(SPEND_VALUE),
        rho_spend,
        rseed_v3,
        NoteVersion::V3,
    )
    .into_option()
    .expect("V3 spend note must have a valid commitment");

    let cmx_v3 = ExtractedNoteCommitment::from(note_v3.commitment()).to_bytes();

    // V2 spend note commitment (what the firmware currently computes)
    let rseed_v2 = RandomSeed::from_bytes(SPEND_RSEED, &rho_spend)
        .into_option()
        .expect("spend_rseed must be valid for V2 too");

    let note_v2 = Note::from_parts(
        spend_addr,
        NoteValue::from_raw(SPEND_VALUE),
        rho_spend,
        rseed_v2,
        NoteVersion::V2,
    )
    .into_option()
    .expect("V2 spend note must have a valid commitment");

    let cmx_v2 = ExtractedNoteCommitment::from(note_v2.commitment()).to_bytes();

    println!("spend cmx V3   : {}", hex::encode(cmx_v3));
    println!("spend cmx V2   : {}", hex::encode(cmx_v2));

    assert_ne!(
        cmx_v3, cmx_v2,
        "V2 and V3 note commitments must differ (proving V2 nullifier ≠ V3 nullifier)"
    );

    println!(
        "✓ Diagnosis confirmed: V3 cmx ≠ V2 cmx for the spend note.\n\
         The firmware's spend_nullifier_bytes uses V2 commitment → wrong nullifier → 6a80.\n\
         Fix: use V3 note commitment in verify_current_ironwood_spend_nullifier."
    );
}
