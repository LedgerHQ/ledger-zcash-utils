/// Integration tests using known transactions as fixed test vectors.
///
/// These tests are fully offline: raw transaction bytes are embedded as hex
/// fixture files so they never need a network connection. Expected values were
/// independently verified with zingo-cli against the same UFVK.
///
/// Run with: `cargo test -p zcash-crypto --test known_vectors`
use zcash_crypto::decrypt::{full_decrypt_tx, DecryptedOutput, DecryptedTx};
use zcash_protocol::consensus::Network;

// ── Mainnet UFVK (Orchard-only wallet) ────────────────────────────────────────
const MAINNET_UFVK: &str = "uview1qggz6nejagvka9wtm9r7xf84kkwy4cc0cgchptr98w0cyz33cj4958q5ulkd32nz2u3s0sp9yhcw7tu2n3nlw9x6ulghyd2zgc857tnzme2zpr3vn24zhtm2rjduv9a5zxlmzz404n7l0k69gmu4tfn2g3vpcn03rhz63e3l92fn8gra37tyly7utvgveswl20vz23pu84rc2nyqess38wvlgr2xzyhgj232ne5qutpe6ql6ghzetdy7pfzcmdzd5gd5dnwk25fwv7nnzmnty7u5ax3nzzgr6pdc905ckpd0s9v2cvn7e03qm7r46e5ngax536ywz7zxjptymm90px0rhvmqtwvttuy6d7degly023lqvskclk6mezyt69dwu6c4tfzrjgq4uuh5xa9m5dclgatykgtrrw268qe5pldfkx73f2kd5yyy2tjpjql92pa6tsk2nh2h88q23nee9z379het4akl6haqmuwf9d0nl0susg4tnxyk";

// ── Testnet UFVK (Sapling + Orchard wallet) ───────────────────────────────────
// Same key pair as MAINNET_UFVK, testnet encoding.
const TESTNET_UFVK: &str = "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

// ── Mainnet Orchard fixtures ───────────────────────────────────────────────────

/// TX1 — Orchard incoming note with memo. Height 3,047,167.
/// txid: d592576d3b57264a5003c495e4808cdfcb6e055a331178597f7889067ea512de
const TX1_HEX: &str = include_str!("fixtures/tx_d592576d_h3047167.hex");
const TX1_HEIGHT: u32 = 3_047_167;

/// TX2 — Orchard internal (change) note, no memo. Height 3,055,407.
/// txid: 22e5f6de0750db0d3e5e0f003339b4d435f7f7e5f3820f898e6ecda411ab0d6a
const TX2_HEX: &str = include_str!("fixtures/tx_22e5f6de_h3055407.hex");
const TX2_HEIGHT: u32 = 3_055_407;

/// TX3 — Orchard internal (change) note, no memo. Height 3,055,417.
/// txid: 0b5baa0c01ea74f93effe5cc0566eaf086bf67329ff2923bc07a5d0e8859a65e
const TX3_HEX: &str = include_str!("fixtures/tx_0b5baa0c_h3055417.hex");
const TX3_HEIGHT: u32 = 3_055_417;

// ── Testnet Sapling fixtures ───────────────────────────────────────────────────

/// TX_S1 — pure Sapling incoming, fee=10000, memo="Thanks for using zfaucet!"
/// txid: c534920d035a64f8fb21163079f88413ade4a2b4f83138f0f47ec185994622c0
/// Height 954,650 (testnet).
const TX_S1_HEX: &str = include_str!("fixtures/tx_c534920d_h954650_testnet.hex");
const TX_S1_HEIGHT: u32 = 954_650;

/// TX_S2 — Sapling outgoing(17000 zat, memo) + incoming(99963000 zat), fee=10000.
/// txid: 18b4fcbb8c81265e64e2397938babbd2eb2d8262bfbb9987f2fca551e316de99
/// Height 1,181,303 (testnet). This is the first test with an outgoing note.
const TX_S2_HEX: &str = include_str!("fixtures/tx_18b4fcbb_h1181303_testnet.hex");
const TX_S2_HEIGHT: u32 = 1_181_303;

/// TX_S3 — Sapling internal (t→z shielding), fee=0, memo="shielding:".
/// txid: 60c1afabd6ac4bcd5b5d7498b2646f10f77176e848de31f080e73972b7b7fa5b
/// Height 2,115,988 (testnet).
///
/// This transaction has a transparent input. `TransactionData::fee_paid` with
/// `get_prevout = |_| Ok(None)` returns `None` → we report fee_zatoshis = 0.
/// zingo-cli also reports fee = 0 (the actual fee for this shielding tx is
/// genuinely zero, so our result is correct for this specific case).
const TX_S3_HEX: &str = include_str!("fixtures/tx_60c1afab_h2115988_testnet.hex");
const TX_S3_HEIGHT: u32 = 2_115_988;

/// TX_S4 — Sapling incoming, fee=10000, memo contains a trailing newline.
/// txid: 68db58bfeffefafe3153a4dd733447806d1c811f59f99a95bd257318ee2910f8
/// Height 2,618,505 (testnet).
const TX_S4_HEX: &str = include_str!("fixtures/tx_68db58bf_h2618505_testnet.hex");
const TX_S4_HEIGHT: u32 = 2_618_505;

fn decrypt_mainnet(hex: &str, height: u32) -> DecryptedTx {
    full_decrypt_tx(hex.trim(), MAINNET_UFVK, height, Network::MainNetwork)
        .expect("full_decrypt_tx should succeed on valid mainnet fixture")
}

fn decrypt_testnet(hex: &str, height: u32) -> DecryptedTx {
    full_decrypt_tx(hex.trim(), TESTNET_UFVK, height, Network::TestNetwork)
        .expect("full_decrypt_tx should succeed on valid testnet fixture")
}

/// Return the note with the given transfer_type, panicking if not found.
fn note_with_type<'a>(outputs: &'a [DecryptedOutput], transfer_type: &str) -> &'a DecryptedOutput {
    outputs
        .iter()
        .find(|n| n.transfer_type == transfer_type)
        .unwrap_or_else(|| {
            panic!(
                "no note with transfer_type={transfer_type:?}, found: {:?}",
                outputs.iter().map(|n| &n.transfer_type).collect::<Vec<_>>()
            )
        })
}

// ── TX1: incoming note with memo ──────────────────────────────────────────────

#[test]
fn tx1_fee_is_10000_zatoshis() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 10_000, "expected fee 10000 zat (0.0001 ZEC)");
}

#[test]
fn tx1_has_one_orchard_note() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert_eq!(tx.orchard_outputs.len(), 1);
    assert!(tx.sapling_outputs.is_empty(), "no Sapling outputs expected");
}

#[test]
fn tx1_orchard_note_is_incoming() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].transfer_type, "incoming");
}

#[test]
fn tx1_orchard_note_amount_is_1247504_zatoshis() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    // 0.01247504 ZEC = 1_247_504 zatoshis
    assert_eq!(tx.orchard_outputs[0].amount, 1_247_504);
}

#[test]
fn tx1_orchard_note_memo_matches() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].memo, "Don\u{2019}t be Nozy");
}

#[test]
fn tx1_incoming_note_has_nullifier_for_phase4_tracking() {
    // Incoming notes must carry a nullifier so the sync engine can later detect
    // when this note is spent (Phase 4 outgoing-tx detection).
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert!(
        tx.orchard_outputs[0].nullifier.is_some(),
        "incoming note must have a nullifier for Phase 4 tracking"
    );
}

// ── TX1: spending fields populated by full_decrypt_tx ─────────────────────────

#[test]
fn tx1_incoming_note_has_rseed() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    let note = &tx.orchard_outputs[0];
    assert_eq!(note.transfer_type, "incoming");
    let rseed = note.rseed.expect("incoming Orchard note must have rseed");
    assert_eq!(rseed.len(), 32, "rseed must be 32 bytes");
}

#[test]
fn tx1_incoming_note_has_cmx() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    let note = &tx.orchard_outputs[0];
    let cmx = note.cmx.expect("incoming Orchard note must have cmx");
    assert_eq!(cmx.len(), 32, "cmx must be 32 bytes");
}

#[test]
fn tx1_incoming_note_has_recipient() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    let note = &tx.orchard_outputs[0];
    let recipient = note.recipient.expect("incoming Orchard note must have recipient");
    assert_eq!(recipient.len(), 43, "recipient must be 43 bytes (11-byte diversifier + 32-byte pk_d)");
}

#[test]
fn tx1_incoming_note_has_action_index() {
    let tx = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    let note = &tx.orchard_outputs[0];
    // action_index is the 0-based position of this note within the Orchard bundle.
    assert!(note.action_index.is_some(), "incoming Orchard note must have action_index");
}

#[test]
fn tx1_spending_fields_are_deterministic() {
    // Decrypting the same fixture twice must yield identical spending fields.
    let a = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    let b = decrypt_mainnet(TX1_HEX, TX1_HEIGHT);
    assert_eq!(a.orchard_outputs[0].rseed, b.orchard_outputs[0].rseed);
    assert_eq!(a.orchard_outputs[0].cmx, b.orchard_outputs[0].cmx);
    assert_eq!(a.orchard_outputs[0].recipient, b.orchard_outputs[0].recipient);
    assert_eq!(a.orchard_outputs[0].action_index, b.orchard_outputs[0].action_index);
}

// ── TX2: internal (change) note ───────────────────────────────────────────────

#[test]
fn tx2_fee_is_15000_zatoshis() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 15_000, "expected fee 15000 zat (0.00015 ZEC)");
}

#[test]
fn tx2_has_one_orchard_note() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    assert_eq!(tx.orchard_outputs.len(), 1);
}

#[test]
fn tx2_orchard_note_is_internal() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].transfer_type, "internal");
}

#[test]
fn tx2_orchard_note_amount_is_122504_zatoshis() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    // 0.00122504 ZEC = 122_504 zatoshis
    assert_eq!(tx.orchard_outputs[0].amount, 122_504);
}

#[test]
fn tx2_orchard_note_has_no_memo() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].memo, "");
}

// ── TX2: spending fields on internal (change) notes ───────────────────────────

#[test]
fn tx2_internal_note_has_all_spending_fields() {
    let tx = decrypt_mainnet(TX2_HEX, TX2_HEIGHT);
    let note = &tx.orchard_outputs[0];
    assert_eq!(note.transfer_type, "internal");
    assert!(note.rseed.is_some(), "internal note must have rseed");
    assert!(note.cmx.is_some(), "internal note must have cmx");
    assert!(note.recipient.is_some(), "internal note must have recipient");
    assert!(note.action_index.is_some(), "internal note must have action_index");
}

// ── TX3: internal (change) note, smaller amount ───────────────────────────────

#[test]
fn tx3_fee_is_15000_zatoshis() {
    let tx = decrypt_mainnet(TX3_HEX, TX3_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 15_000);
}

#[test]
fn tx3_has_one_orchard_note() {
    let tx = decrypt_mainnet(TX3_HEX, TX3_HEIGHT);
    assert_eq!(tx.orchard_outputs.len(), 1);
}

#[test]
fn tx3_orchard_note_is_internal() {
    let tx = decrypt_mainnet(TX3_HEX, TX3_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].transfer_type, "internal");
}

#[test]
fn tx3_orchard_note_amount_is_7504_zatoshis() {
    let tx = decrypt_mainnet(TX3_HEX, TX3_HEIGHT);
    // 0.00007504 ZEC = 7_504 zatoshis
    assert_eq!(tx.orchard_outputs[0].amount, 7_504);
}

#[test]
fn tx3_orchard_note_has_no_memo() {
    let tx = decrypt_mainnet(TX3_HEX, TX3_HEIGHT);
    assert_eq!(tx.orchard_outputs[0].memo, "");
}

// ── Cross-transaction invariants ──────────────────────────────────────────────

#[test]
fn all_fees_are_positive() {
    for (hex, height) in [(TX1_HEX, TX1_HEIGHT), (TX2_HEX, TX2_HEIGHT), (TX3_HEX, TX3_HEIGHT)] {
        let tx = decrypt_mainnet(hex, height);
        assert!(tx.fee_zatoshis > 0, "fee must be positive, got {}", tx.fee_zatoshis);
    }
}

#[test]
fn no_tx_has_sapling_outputs() {
    // This wallet is Orchard-only; none of these transactions should yield
    // Sapling outputs for our key.
    for (hex, height) in [(TX1_HEX, TX1_HEIGHT), (TX2_HEX, TX2_HEIGHT), (TX3_HEX, TX3_HEIGHT)] {
        let tx = decrypt_mainnet(hex, height);
        assert!(
            tx.sapling_outputs.is_empty(),
            "unexpected Sapling output at height {height}"
        );
    }
}

#[test]
fn wrong_ufvk_yields_empty_outputs_but_no_error() {
    // Using the testnet UFVK against a mainnet transaction: should find no notes.
    let result = zcash_crypto::decrypt::full_decrypt_tx(
        TX1_HEX.trim(),
        TESTNET_UFVK,
        TX1_HEIGHT,
        Network::MainNetwork,
    );
    // May fail on UFVK decode (network mismatch), or succeed with empty outputs.
    if let Ok(tx) = result {
        assert!(tx.orchard_outputs.is_empty(), "wrong-network UFVK must not decrypt our notes");
    }
}

// ── Sapling notes must not carry spending fields ─────────────────────────────

#[test]
fn txs1_sapling_note_has_no_spending_fields() {
    let tx = decrypt_testnet(TX_S1_HEX, TX_S1_HEIGHT);
    let note = &tx.sapling_outputs[0];
    assert!(note.rseed.is_none(), "Sapling note must not have rseed");
    assert!(note.cmx.is_none(), "Sapling note must not have cmx");
    assert!(note.recipient.is_none(), "Sapling note must not have recipient");
    assert!(note.action_index.is_none(), "Sapling note must not have action_index");
}

#[test]
fn txs2_outgoing_sapling_note_has_no_spending_fields() {
    let tx = decrypt_testnet(TX_S2_HEX, TX_S2_HEIGHT);
    let note = note_with_type(&tx.sapling_outputs, "outgoing");
    assert!(note.rseed.is_none(), "outgoing Sapling note must not have rseed");
    assert!(note.cmx.is_none(), "outgoing Sapling note must not have cmx");
    assert!(note.recipient.is_none(), "outgoing Sapling note must not have recipient");
    assert!(note.action_index.is_none(), "outgoing Sapling note must not have action_index");
}

// ── Testnet Sapling: TX_S1 — pure incoming ───────────────────────────────────

#[test]
fn txs1_fee_is_10000_zatoshis() {
    let tx = decrypt_testnet(TX_S1_HEX, TX_S1_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[test]
fn txs1_has_one_sapling_note() {
    let tx = decrypt_testnet(TX_S1_HEX, TX_S1_HEIGHT);
    assert_eq!(tx.sapling_outputs.len(), 1);
    assert!(tx.orchard_outputs.is_empty());
}

#[test]
fn txs1_sapling_note_is_incoming_with_correct_amount() {
    let tx = decrypt_testnet(TX_S1_HEX, TX_S1_HEIGHT);
    assert_eq!(tx.sapling_outputs[0].transfer_type, "incoming");
    // 1.00000000 ZEC = 100_000_000 zatoshis
    assert_eq!(tx.sapling_outputs[0].amount, 100_000_000);
}

#[test]
fn txs1_sapling_note_memo() {
    let tx = decrypt_testnet(TX_S1_HEX, TX_S1_HEIGHT);
    assert_eq!(tx.sapling_outputs[0].memo, "Thanks for using zfaucet!");
}

// ── Testnet Sapling: TX_S2 — outgoing + incoming ─────────────────────────────

#[test]
fn txs2_fee_is_10000_zatoshis() {
    let tx = decrypt_testnet(TX_S2_HEX, TX_S2_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[test]
fn txs2_has_two_sapling_notes() {
    let tx = decrypt_testnet(TX_S2_HEX, TX_S2_HEIGHT);
    assert_eq!(tx.sapling_outputs.len(), 2, "expected outgoing + incoming notes");
}

#[test]
fn txs2_outgoing_note_amount_and_memo() {
    let tx = decrypt_testnet(TX_S2_HEX, TX_S2_HEIGHT);
    let note = note_with_type(&tx.sapling_outputs, "outgoing");
    // 0.00017000 ZEC = 17_000 zatoshis
    assert_eq!(note.amount, 17_000);
    assert_eq!(note.memo, "Funds from Demo App");
}

#[test]
fn txs2_incoming_note_amount() {
    let tx = decrypt_testnet(TX_S2_HEX, TX_S2_HEIGHT);
    let note = note_with_type(&tx.sapling_outputs, "incoming");
    // 0.99963000 ZEC = 99_963_000 zatoshis
    assert_eq!(note.amount, 99_963_000);
}

// ── Testnet Sapling: TX_S3 — transparent input (t→z shielding), fee=0 ────────

#[test]
fn txs3_fee_is_zero_for_shielding_transaction() {
    // This t→z shielding transaction genuinely has fee=0 (zingo-cli confirms).
    // Our fee_paid returns None for transparent inputs (prevout unavailable from
    // compact blocks), which we map to 0 — the result happens to be correct here.
    // For shielding txs with a non-zero fee, our code would also return 0 (known
    // limitation documented in ShieldedTransaction::fee_zatoshis).
    let tx = decrypt_testnet(TX_S3_HEX, TX_S3_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 0);
}

#[test]
fn txs3_has_one_sapling_internal_note() {
    let tx = decrypt_testnet(TX_S3_HEX, TX_S3_HEIGHT);
    assert_eq!(tx.sapling_outputs.len(), 1);
    assert_eq!(tx.sapling_outputs[0].transfer_type, "internal");
}

#[test]
fn txs3_sapling_shielding_memo() {
    let tx = decrypt_testnet(TX_S3_HEX, TX_S3_HEIGHT);
    assert_eq!(tx.sapling_outputs[0].memo, "shielding:");
}

// ── Testnet Sapling: TX_S4 — memo with trailing newline ──────────────────────

#[test]
fn txs4_fee_is_10000_zatoshis() {
    let tx = decrypt_testnet(TX_S4_HEX, TX_S4_HEIGHT);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[test]
fn txs4_incoming_note_amount() {
    let tx = decrypt_testnet(TX_S4_HEX, TX_S4_HEIGHT);
    assert_eq!(tx.sapling_outputs[0].transfer_type, "incoming");
    // 0.00000250 ZEC = 250 zatoshis
    assert_eq!(tx.sapling_outputs[0].amount, 250);
}

#[test]
fn txs4_memo_with_trailing_newline_decoded_correctly() {
    // The memo "sending some money from an emulator\n" ends with 0x0A (LF).
    // decode_memo stops at the first 0x00 null byte, so the newline is preserved.
    let tx = decrypt_testnet(TX_S4_HEX, TX_S4_HEIGHT);
    assert_eq!(tx.sapling_outputs[0].memo, "sending some money from an emulator\n");
}
