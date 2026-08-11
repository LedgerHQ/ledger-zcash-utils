//! Diagnostic: determine whether the Speculos test vectors for the Ironwood
//! PCZT test suite use V2 or V3 note commitments.
//!
//! Run with:
//!   cargo test -p zcash-crypto --test ironwood_nullifier_version_check -- --nocapture

use orchard::{
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::NoteValue,
    Address, Note, NoteVersion,
};

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

// Python test vectors
const INTERNAL_RECIPIENT: [u8; 43] =
    hex43("ede3d2ce08c11d8c5c7bfe6814cedafd96c160c3d879cb270946f1ab6fdf442a15648d7c0b3c9fd052e20a");
const DUMMY_RSEED: [u8; 32] =
    hex32("2e00000000000000000000000000000000000000000000000000000000000000");
const V2_DUMMY_CMX: [u8; 32] =
    hex32("825f806345d7c2ae67fe186120cc5b8a370c2cedb55ccf76527e9efa43c94d30");
const V3_DUMMY_CMX: [u8; 32] =
    hex32("f5bc3b62d60bd6ba9af4d7b0fc65cfe2036fa307f5e7a13cb7007c68d4ab300d");
const SPEND_NULLIFIER: [u8; 32] =
    hex32("08f337fd695cb5ca2ad7ced8ec14afed06d2f8a0e5e3d8b58dffbc69e4f81b2f");
const SPEND_RECIPIENT: [u8; 43] =
    hex43("4a6414bb6f09e4a89469663a081fc2646c083708f552597d524b2f1812272e472d2b28f7414ece124ddf02");
const SPEND_RHO: [u8; 32] =
    hex32("0600000000000000000000000000000000000000000000000000000000000000");
const SPEND_RSEED: [u8; 32] =
    hex32("1a00000000000000000000000000000000000000000000000000000000000000");
const SPEND_VALUE: u64 = 300_000;

// New log action 2 dummy output
const ACTION2_OUTPUT_RECIPIENT: [u8; 43] =
    hex43("db2b8ba615b627071abcc30cf5573abfb4fa011872ecb9a9992eca4e6633d06a4f047fb5cd70c6e618a41a");
const ACTION2_OUTPUT_RSEED: [u8; 32] =
    hex32("35ff8abde3408fc1fba1ca5a25dfeaa5ed34b08851172834348d6eabf0f173b1");
const ACTION2_SPEND_NULLIFIER: [u8; 32] =
    hex32("36a49957c16f4164600d22359a1b1e32715fd686f7adfff2a7aea63c5f58bb3f");
const ACTION2_EXPECTED_CMX: [u8; 32] =
    hex32("12c0b0eaa418fc266fd78800b841b91b2248a657bb35517fde33a4c43f3bde0e");

/// Determine which NoteVersion the Python test dummy output vectors correspond to.
#[test]
fn check_dummy_output_cmx_version_match() {
    let rho = Rho::from_bytes(&SPEND_NULLIFIER)
        .into_option()
        .expect("SPEND_NULLIFIER is a valid Pallas base field element");
    let recipient = Address::from_raw_address_bytes(&INTERNAL_RECIPIENT)
        .into_option()
        .expect("INTERNAL_RECIPIENT is a valid Orchard address");

    let note_v2 = Note::from_parts(recipient, NoteValue::from_raw(0), rho,
        RandomSeed::from_bytes(DUMMY_RSEED, &rho).into_option().unwrap(), NoteVersion::V2)
        .into_option().unwrap();
    let cmx_v2 = ExtractedNoteCommitment::from(note_v2.commitment()).to_bytes();

    let note_v3 = Note::from_parts(recipient, NoteValue::from_raw(0), rho,
        RandomSeed::from_bytes(DUMMY_RSEED, &rho).into_option().unwrap(), NoteVersion::V3)
        .into_option().unwrap();
    let cmx_v3 = ExtractedNoteCommitment::from(note_v3.commitment()).to_bytes();

    println!("Dummy output cmx (V2 commitment): {}", hex::encode(cmx_v2));
    println!("Dummy output cmx (V3 commitment): {}", hex::encode(cmx_v3));
    println!("_CMX in test file (115-byte path): {}", hex::encode(V2_DUMMY_CMX));
    println!("_V3_DUMMY_CMX in test file (116-byte V3 path): {}", hex::encode(V3_DUMMY_CMX));
    println!();

    if cmx_v2 == V2_DUMMY_CMX {
        println!("✓ V2 commitment matches _CMX — the 115-byte (no-version) output metadata uses V2 commitment");
    }
    if cmx_v3 == V3_DUMMY_CMX {
        println!("✓ V3 commitment matches _V3_DUMMY_CMX — the 116-byte V3 output metadata uses V3 commitment");
    }
    if cmx_v2 == V3_DUMMY_CMX {
        println!("! V2 commitment matches _V3_DUMMY_CMX — UNEXPECTED");
    }
    if cmx_v3 == V2_DUMMY_CMX {
        println!("! V3 commitment matches _CMX — UNEXPECTED: spend notes for 115-byte APDUs would need V3 nullifier too");
    }

    assert_eq!(cmx_v2, V2_DUMMY_CMX, "V2 cmx must match _CMX");
    assert_eq!(cmx_v3, V3_DUMMY_CMX, "V3 cmx must match _V3_DUMMY_CMX");
}

/// Compare V2 vs V3 cmx for the Speculos spend note.
#[test]
fn check_spend_note_cmx_v2_vs_v3() {
    let rho = Rho::from_bytes(&SPEND_RHO)
        .into_option()
        .expect("SPEND_RHO valid");
    let recipient = Address::from_raw_address_bytes(&SPEND_RECIPIENT)
        .into_option()
        .expect("SPEND_RECIPIENT valid");

    let note_v2 = Note::from_parts(recipient, NoteValue::from_raw(SPEND_VALUE), rho,
        RandomSeed::from_bytes(SPEND_RSEED, &rho).into_option().unwrap(), NoteVersion::V2)
        .into_option().unwrap();
    let cmx_v2 = ExtractedNoteCommitment::from(note_v2.commitment()).to_bytes();

    let note_v3 = Note::from_parts(recipient, NoteValue::from_raw(SPEND_VALUE), rho,
        RandomSeed::from_bytes(SPEND_RSEED, &rho).into_option().unwrap(), NoteVersion::V3)
        .into_option().unwrap();
    let cmx_v3 = ExtractedNoteCommitment::from(note_v3.commitment()).to_bytes();

    println!("Speculos spend note cmx (V2): {}", hex::encode(cmx_v2));
    println!("Speculos spend note cmx (V3): {}", hex::encode(cmx_v3));
    println!();
    println!("The V3 firmware uses cmx_v3 for nullifier computation.");
    println!("The V2 firmware uses cmx_v2 for nullifier computation.");
    println!("If _NULLIFIER was derived with V2 cm, the new firmware (V3) WILL compute a different nullifier.");

    assert_ne!(cmx_v2, cmx_v3, "V2 and V3 spend note cmx must differ");
}

/// Verify action 2 (new log) dummy output cmx with V3 commitment.
#[test]
fn check_action2_dummy_output_cmx_v3() {
    let rho = Rho::from_bytes(&ACTION2_SPEND_NULLIFIER)
        .into_option()
        .expect("ACTION2_SPEND_NULLIFIER valid");
    let recipient = Address::from_raw_address_bytes(&ACTION2_OUTPUT_RECIPIENT)
        .into_option()
        .expect("ACTION2_OUTPUT_RECIPIENT valid");
    let rseed = RandomSeed::from_bytes(ACTION2_OUTPUT_RSEED, &rho)
        .into_option()
        .expect("ACTION2_OUTPUT_RSEED valid");

    let note = Note::from_parts(recipient, NoteValue::from_raw(0), rho, rseed, NoteVersion::V3)
        .into_option()
        .expect("V3 action 2 dummy output note");
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    println!("Action 2 dummy output cmx (V3): {}", hex::encode(cmx));
    println!("Action 2 expected cmx (PCZT):   {}", hex::encode(ACTION2_EXPECTED_CMX));

    assert_eq!(cmx, ACTION2_EXPECTED_CMX,
        "V3 dummy output cmx must match PCZT for action 2 (new log)");
    println!("✓ Action 2 dummy output check 3 SHOULD pass in firmware (cmx matches).");
    println!("  The 6a80 therefore comes from check 2: spend nullifier mismatch.");
    println!("  Root cause: spend_nullifier_bytes_v3 computes wrong nullifier.");
}

/// Derive the Orchard FVK from the Speculos default seed and compute the V3
/// spend nullifier for the test spend note.  This gives the new `_NULLIFIER`
/// value that the updated firmware (using V3 note commitment for nullifier
/// recomputation) will compute for `_valid_ironwood_action()`.
///
/// Run with:
///   cargo test -p zcash-crypto --test ironwood_nullifier_version_check \
///     -- compute_v3_spend_nullifier_from_speculos_seed --nocapture
#[test]
fn compute_v3_spend_nullifier_from_speculos_seed() {
    use bip39::Mnemonic;
    use orchard::note::Nullifier;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::MainNetwork;
    use zip32::AccountId;

    // Speculos default seed (from speculos/main.py DEFAULT_SEED).
    const SPECULOS_MNEMONIC: &str =
        "glory promote mansion idle axis finger extra february uncover one trip \
         resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

    let mnemonic = Mnemonic::parse(SPECULOS_MNEMONIC).expect("valid 24-word mnemonic");
    // BIP-39 seed with empty passphrase — same derivation Speculos uses for ZIP-32.
    let seed_bytes = mnemonic.to_seed("");

    let account_id = AccountId::try_from(0u32).expect("account 0 is valid");
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &seed_bytes, account_id)
        .expect("Orchard USK derivation from Speculos seed must succeed");
    let ufvk = usk.to_unified_full_viewing_key();
    let orchard_fvk = ufvk.orchard().expect("Orchard FVK must be present in USK");

    // Print the raw FVK bytes so we can check nk (bytes [32..64]) if needed.
    let fvk_bytes = orchard_fvk.to_bytes();
    println!("Orchard FVK (ak‖nk‖rivk): {}", hex::encode(fvk_bytes));
    println!("  nk (bytes [32..64]): {}", hex::encode(&fvk_bytes[32..64]));

    // Build the V3 spend note using the test parameters from test_pczt_ironwood.py.
    let rho = Rho::from_bytes(&SPEND_RHO)
        .into_option()
        .expect("SPEND_RHO is a valid Pallas base field element");
    let spend_addr = Address::from_raw_address_bytes(&SPEND_RECIPIENT)
        .into_option()
        .expect("SPEND_RECIPIENT is a valid Orchard raw address");
    let rseed = RandomSeed::from_bytes(SPEND_RSEED, &rho)
        .into_option()
        .expect("SPEND_RSEED is a valid random seed for this rho");

    let note_v3 = Note::from_parts(
        spend_addr,
        NoteValue::from_raw(SPEND_VALUE),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .expect("V3 spend note construction must succeed");

    let nf_v3: Nullifier = note_v3.nullifier(orchard_fvk);
    let nf_v3_bytes = nf_v3.to_bytes();

    println!("\nV3 spend nullifier (new _NULLIFIER): {}", hex::encode(nf_v3_bytes));
    println!("V2 spend nullifier (old _NULLIFIER): {}", hex::encode(SPEND_NULLIFIER));
    println!();

    // The V3 nullifier must differ from the V2 nullifier — this is the whole point.
    assert_ne!(
        nf_v3_bytes, SPEND_NULLIFIER,
        "V3 nullifier must differ from V2 nullifier; if equal, re-check note version"
    );

    println!("✓ V3 nullifier differs from V2 nullifier — update _NULLIFIER in test_pczt_ironwood.py");
    println!("  New _NULLIFIER = {}", hex::encode(nf_v3_bytes));
    println!();
    println!("Next step: compute new _CMX using the V3 nullifier as rho for the dummy output:");
    println!("  Note::from_parts(INTERNAL_RECIPIENT, value=0, rho=nf_v3, RSEED, V2).commitment()");
}

/// Compute the new `_CMX` for `_valid_ironwood_action()` after updating `_NULLIFIER` to V3.
///
/// The dummy output commitment is still V2 (because note_plaintext_version is not set in the
/// 115-byte output_metadata APDU for the standard action).  Only rho changes — it is now the
/// V3 spend nullifier instead of the old V2 one.
///
/// Run with:
///   cargo test -p zcash-crypto --test ironwood_nullifier_version_check \
///     -- compute_new_cmx_for_v3_nullifier --nocapture
#[test]
fn compute_new_cmx_for_v3_nullifier() {
    // V3 spend nullifier — the new _NULLIFIER computed by the updated firmware.
    let new_nullifier = hex32("ed37cc733c228dc3dda2cf088ba646f9d204adc9d8d6f95ec36126eb742c3a10");

    let rho = Rho::from_bytes(&new_nullifier)
        .into_option()
        .expect("new V3 nullifier is a valid Pallas base field element");
    let recipient = Address::from_raw_address_bytes(&INTERNAL_RECIPIENT)
        .into_option()
        .expect("INTERNAL_RECIPIENT is a valid Orchard raw address");
    // DUMMY_RSEED in this file = 0x2e... = _RSEED from test_pczt_ironwood.py (output rseed).
    let rseed = RandomSeed::from_bytes(DUMMY_RSEED, &rho)
        .into_option()
        .expect("DUMMY_RSEED is a valid random seed for this rho");

    // V2 commitment — the 115-byte output_metadata APDU uses V2 cmx path.
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(0),
        rho,
        rseed,
        NoteVersion::V2,
    )
    .into_option()
    .expect("V2 dummy output note construction must succeed");

    let new_cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();

    println!("New _CMX (V2 commitment, rho = V3 nullifier): {}", hex::encode(new_cmx));
    println!("Old _CMX (V2 commitment, rho = V2 nullifier): {}", hex::encode(V2_DUMMY_CMX));
    println!();
    println!("_NULLIFIER = \"{}\"", hex::encode(new_nullifier));
    println!("_CMX       = \"{}\"", hex::encode(new_cmx));

    assert_ne!(new_cmx, V2_DUMMY_CMX, "new _CMX must differ from old _CMX");
    println!("✓ New _CMX computed — update both _NULLIFIER and _CMX in test_pczt_ironwood.py");
}

/// Compute updated external-recipient action vectors for test_pczt_ironwood.py.
///
/// The external action uses a real spend (200000 ZAT) from the device key, with output
/// to an external recipient (180000 ZAT).  The firmware recovers the output via OVK.
/// Since the spend nullifier changes (V3 formula), the output rho, esk, epk, cmx, and
/// out_ciphertext all change.
///
/// Run with:
///   cargo test -p zcash-crypto --test ironwood_nullifier_version_check \
///     -- compute_v3_ext_action_vectors --nocapture
#[test]
fn compute_v3_ext_action_vectors() {
    use bip39::Mnemonic;
    use orchard::{
        action::Action,
        bundle::Authorized,
        keys::{FullViewingKey, Scope},
        note::{Nullifier, RandomSeed},
        primitives::redpallas,
        value::NoteValue,
        Address, Note, NoteVersion,
    };
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_note_encryption::{try_output_recovery_with_ovk, Domain};
    use zcash_protocol::consensus::MainNetwork;
    use zip32::AccountId;

    // Speculos mnemonic → Orchard FVK (same derivation as compute_v3_spend_nullifier_from_speculos_seed)
    let mnemonic = Mnemonic::parse(
        "glory promote mansion idle axis finger extra february uncover one trip \
         resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin",
    )
    .expect("valid Speculos mnemonic");
    let seed_bytes = mnemonic.to_seed("");
    let account_id = AccountId::try_from(0u32).unwrap();
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &seed_bytes, account_id).unwrap();
    let ufvk = usk.to_unified_full_viewing_key();
    let orchard_fvk = ufvk.orchard().unwrap();

    // External OVK — used by firmware to recover the output note.
    let external_ovk = orchard_fvk.to_ovk(Scope::External);

    // --- Step 1: V3 spend nullifier for the external action ---
    let ext_spend_rho = Rho::from_bytes(
        &hex32("0700000000000000000000000000000000000000000000000000000000000000"),
    )
    .into_option()
    .expect("_EXT_SPEND_RHO valid");
    let ext_spend_rseed_bytes =
        hex32("1b00000000000000000000000000000000000000000000000000000000000000");
    let ext_spend_rseed = RandomSeed::from_bytes(ext_spend_rseed_bytes, &ext_spend_rho)
        .into_option()
        .expect("_EXT_SPEND_RSEED valid");
    let ext_spend_addr = Address::from_raw_address_bytes(&SPEND_RECIPIENT)
        .into_option()
        .expect("SPEND_RECIPIENT valid");

    let ext_spend_note = Note::from_parts(
        ext_spend_addr,
        NoteValue::from_raw(200_000),
        ext_spend_rho,
        ext_spend_rseed,
        NoteVersion::V3,
    )
    .into_option()
    .expect("V3 external spend note valid");
    let ext_nullifier: Nullifier = ext_spend_note.nullifier(orchard_fvk);
    let ext_nullifier_bytes = ext_nullifier.to_bytes();
    println!("_EXT_NULLIFIER (V3): {}", hex::encode(ext_nullifier_bytes));

    // --- Step 2: Output note rho = Rho::from_nf_old(ext_nullifier) ---
    // The Orchard protocol uses rho = nf_old (from the PCZT nullifier field).
    // In the orchard crate, Rho::from_nf_old is not pub; use Rho::from_bytes instead
    // since rho IS the nullifier bytes in Orchard.
    let ext_output_rho = Rho::from_bytes(&ext_nullifier_bytes)
        .into_option()
        .expect("ext nullifier is a valid Pallas base field element for rho");

    let ext_recipient_bytes = hex43(
        "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
    );
    let ext_recipient = Address::from_raw_address_bytes(&ext_recipient_bytes)
        .into_option()
        .expect("_EXT_RECIPIENT valid");

    let ext_rseed_bytes =
        hex32("2f00000000000000000000000000000000000000000000000000000000000000");
    let ext_rseed = RandomSeed::from_bytes(ext_rseed_bytes, &ext_output_rho)
        .into_option()
        .expect("_EXT_RSEED valid for new rho");

    // --- Step 3: V2 output note (note_plaintext_version = None in output_metadata → V2) ---
    let ext_output_note = Note::from_parts(
        ext_recipient,
        NoteValue::from_raw(180_000),
        ext_output_rho,
        ext_rseed,
        NoteVersion::V2,
    )
    .into_option()
    .expect("V2 external output note valid");

    use orchard::note::ExtractedNoteCommitment;
    let ext_cmx = ExtractedNoteCommitment::from(ext_output_note.commitment()).to_bytes();
    println!("_EXT_CMX (V2 commitment, new rho): {}", hex::encode(ext_cmx));

    // --- Step 4: Derive esk and epk ---
    let esk = ext_output_note.esk();
    // g_d for external recipient's diversifier
    use orchard::note_encryption::IronwoodNoteEncryption;
    let memo = [0u8; 512];
    let encryptor = IronwoodNoteEncryption::new_with_esk(
        esk,
        Some(external_ovk),
        ext_output_note,
        memo,
    );
    let epk_bytes = orchard::note_encryption::IronwoodDomain::epk_bytes(encryptor.epk());
    println!("_EXT_EPHEMERAL_KEY: {}", hex::encode(epk_bytes.0));

    // --- Step 5: Encrypt note plaintext (enc_ciphertext, V2 scheme) ---
    let enc_ciphertext = encryptor.encrypt_note_plaintext();
    let enc_ct_bytes: &[u8] = enc_ciphertext.as_ref();
    println!("_EXT_ENC_CIPHERTEXT: {}", hex::encode(enc_ct_bytes));

    // --- Step 6: Encrypt outgoing plaintext (out_ciphertext under OVK) ---
    // cv_net stays the same — it's independent of note commitment changes.
    let ext_cv_net_bytes =
        hex32("2bbcd0793d399b207b228ca760f2b51ac8d6866e2649b3c3ff1e67b454c5a6bf");
    let ext_cv_net = orchard::value::ValueCommitment::from_bytes(&ext_cv_net_bytes)
        .unwrap();
    let out_ciphertext = encryptor.encrypt_outgoing_plaintext(
        &ext_cv_net,
        &orchard::note::ExtractedNoteCommitment::from_bytes(&ext_cmx).unwrap(),
        &mut rand::thread_rng(),
    );
    let out_ct_bytes: &[u8] = out_ciphertext.as_ref();
    println!("_EXT_OUT_CIPHERTEXT: {}", hex::encode(out_ct_bytes));
    println!();
    println!("Summary:");
    println!("  _EXT_NULLIFIER = bytes.fromhex(\"{}\")", hex::encode(ext_nullifier_bytes));
    println!("  _EXT_CMX       = bytes.fromhex(\"{}\")", hex::encode(ext_cmx));
    println!("  _EXT_EPHEMERAL_KEY = bytes.fromhex(\"{}\")", hex::encode(epk_bytes.0));
}
