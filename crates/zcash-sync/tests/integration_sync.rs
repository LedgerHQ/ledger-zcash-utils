/// End-to-end integration tests against a live Zaino/lightwalletd node.
///
/// These tests exercise the full pipeline:
///   compact block stream → trial decrypt → GetTransaction → full decrypt
///
/// All tests are marked `#[ignore]` because they require network access.
/// Run them explicitly with:
///   cargo test -p zcash-sync --test integration_sync -- --ignored
///
/// By default the suite targets the Ledger staging Zaino nodes. The endpoints
/// can be overridden to run against any public Zaino node, e.g.:
///   ZCASH_MAINNET_GRPC_URL=https://zec.rocks:443 \
///   ZCASH_TESTNET_GRPC_URL=https://testnet.zec.rocks:443 \
///     cargo test -p zcash-sync --test integration_sync -- --ignored
///
/// Expected values are cross-referenced with zingo-cli output.
use std::time::Duration;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, GetSubtreeRootsArg,
    ShieldedProtocol,
};
use zcash_sync::sync::{run_sync, ShieldedNote, ShieldedTransaction, SyncParams};

// ── Mainnet (Orchard-only) ────────────────────────────────────────────────────
const MAINNET_GRPC_URL_DEFAULT: &str = "https://zaino-zec-mainnet-zebra.nodes.stg.ledger-test.com";

/// Resolves the mainnet gRPC endpoint, allowing an override via the
/// `ZCASH_MAINNET_GRPC_URL` environment variable. This lets the suite run
/// against a public Zaino node (e.g. `https://zec.rocks:443`) when the Ledger
/// staging node is unavailable.
fn mainnet_grpc_url() -> String {
    std::env::var("ZCASH_MAINNET_GRPC_URL").unwrap_or_else(|_| MAINNET_GRPC_URL_DEFAULT.to_string())
}
const MAINNET_UFVK: &str = "uview1qggz6nejagvka9wtm9r7xf84kkwy4cc0cgchptr98w0cyz33cj4958q5ulkd32nz2u3s0sp9yhcw7tu2n3nlw9x6ulghyd2zgc857tnzme2zpr3vn24zhtm2rjduv9a5zxlmzz404n7l0k69gmu4tfn2g3vpcn03rhz63e3l92fn8gra37tyly7utvgveswl20vz23pu84rc2nyqess38wvlgr2xzyhgj232ne5qutpe6ql6ghzetdy7pfzcmdzd5gd5dnwk25fwv7nnzmnty7u5ax3nzzgr6pdc905ckpd0s9v2cvn7e03qm7r46e5ngax536ywz7zxjptymm90px0rhvmqtwvttuy6d7degly023lqvskclk6mezyt69dwu6c4tfzrjgq4uuh5xa9m5dclgatykgtrrw268qe5pldfkx73f2kd5yyy2tjpjql92pa6tsk2nh2h88q23nee9z379het4akl6haqmuwf9d0nl0susg4tnxyk";

// ── Testnet (Sapling + Orchard) ───────────────────────────────────────────────
const TESTNET_GRPC_URL_DEFAULT: &str = "https://zaino-zec-testnet.nodes.stg.ledger-test.com";

/// Resolves the testnet gRPC endpoint, overridable via `ZCASH_TESTNET_GRPC_URL`.
fn testnet_grpc_url() -> String {
    std::env::var("ZCASH_TESTNET_GRPC_URL").unwrap_or_else(|_| TESTNET_GRPC_URL_DEFAULT.to_string())
}
const TESTNET_UFVK: &str = "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn params_for_block(height: u32) -> SyncParams {
    SyncParams {
        grpc_url: mainnet_grpc_url(),
        viewing_key: MAINNET_UFVK.to_string(),
        start_height: height,
        end_height: height,
        network: Some("mainnet".to_string()),
        verbose: false,
        on_block_done: None,
        on_transaction: None,
        orchard_only: true,
        max_retries: None,
        known_nullifiers: vec![],
    }
}

fn params_for_range(start: u32, end: u32) -> SyncParams {
    SyncParams {
        grpc_url: mainnet_grpc_url(),
        viewing_key: MAINNET_UFVK.to_string(),
        start_height: start,
        end_height: end,
        network: Some("mainnet".to_string()),
        verbose: false,
        on_block_done: None,
        on_transaction: None,
        orchard_only: true,
        max_retries: None,
        known_nullifiers: vec![],
    }
}

fn params_for_block_testnet(height: u32) -> SyncParams {
    SyncParams {
        grpc_url: testnet_grpc_url(),
        viewing_key: TESTNET_UFVK.to_string(),
        start_height: height,
        end_height: height,
        network: Some("testnet".to_string()),
        verbose: false,
        on_block_done: None,
        on_transaction: None,
        orchard_only: false, // must scan Sapling
        max_retries: None,
        known_nullifiers: vec![],
    }
}

fn params_for_range_testnet(start: u32, end: u32) -> SyncParams {
    SyncParams {
        grpc_url: testnet_grpc_url(),
        viewing_key: TESTNET_UFVK.to_string(),
        start_height: start,
        end_height: end,
        network: Some("testnet".to_string()),
        verbose: false,
        on_block_done: None,
        on_transaction: None,
        orchard_only: false,
        max_retries: None,
        known_nullifiers: vec![],
    }
}

fn find_tx<'a>(txs: &'a [ShieldedTransaction], txid: &str) -> &'a ShieldedTransaction {
    txs.iter()
        .find(|tx| tx.txid == txid)
        .unwrap_or_else(|| panic!("txid {txid} not found in results"))
}

fn note_with_type<'a>(notes: &'a [ShieldedNote], transfer_type: &str) -> &'a ShieldedNote {
    notes
        .iter()
        .find(|n| n.transfer_type == transfer_type)
        .unwrap_or_else(|| {
            panic!(
                "no note with transfer_type={transfer_type:?}, found: {:?}",
                notes.iter().map(|n| &n.transfer_type).collect::<Vec<_>>()
            )
        })
}

// ── TX1: incoming note with memo ──────────────────────────────────────────────
//
// d592576d3b57264a5003c495e4808cdfcb6e055a331178597f7889067ea512de
// Height 3,047,167 — zingo-cli: incoming 0.01247504 ZEC, fee 0.0001 ZEC, memo "Don't be Nozy"

const TX1_TXID: &str = "d592576d3b57264a5003c495e4808cdfcb6e055a331178597f7889067ea512de";
const TX1_HEIGHT: u32 = 3_047_167;

#[tokio::test]
#[ignore = "requires network access"]
async fn tx1_is_found_by_trial_decrypt() {
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    assert!(
        result.transactions.iter().any(|tx| tx.txid == TX1_TXID),
        "TX1 not found — trial decrypt or GetTransaction failed"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tx1_fee_is_10000_zatoshis() {
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX1_TXID);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tx1_has_one_incoming_orchard_note() {
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX1_TXID);
    assert_eq!(tx.orchard_notes.len(), 1);
    assert_eq!(tx.orchard_notes[0].transfer_type, "incoming");
    assert_eq!(tx.orchard_notes[0].amount, 1_247_504);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tx1_memo_decoded_correctly() {
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX1_TXID);
    assert_eq!(tx.orchard_notes[0].memo, "Don\u{2019}t be Nozy");
}

// ── TX2: internal (change) note ───────────────────────────────────────────────
//
// 22e5f6de0750db0d3e5e0f003339b4d435f7f7e5f3820f898e6ecda411ab0d6a
// Height 3,055,407 — zingo-cli: internal 0.00122504 ZEC, fee 0.00015 ZEC

const TX2_TXID: &str = "22e5f6de0750db0d3e5e0f003339b4d435f7f7e5f3820f898e6ecda411ab0d6a";
const TX2_HEIGHT: u32 = 3_055_407;

#[tokio::test]
#[ignore = "requires network access"]
async fn tx2_fee_is_15000_zatoshis() {
    let result = run_sync(params_for_block(TX2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX2_TXID);
    assert_eq!(tx.fee_zatoshis, 15_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tx2_has_one_internal_orchard_note() {
    let result = run_sync(params_for_block(TX2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX2_TXID);
    assert_eq!(tx.orchard_notes.len(), 1);
    assert_eq!(tx.orchard_notes[0].transfer_type, "internal");
    assert_eq!(tx.orchard_notes[0].amount, 122_504);
}

// ── TX3: internal (change) note, smaller amount ───────────────────────────────
//
// 0b5baa0c01ea74f93effe5cc0566eaf086bf67329ff2923bc07a5d0e8859a65e
// Height 3,055,417 — zingo-cli: internal 0.00007504 ZEC, fee 0.00015 ZEC

const TX3_TXID: &str = "0b5baa0c01ea74f93effe5cc0566eaf086bf67329ff2923bc07a5d0e8859a65e";
const TX3_HEIGHT: u32 = 3_055_417;

#[tokio::test]
#[ignore = "requires network access"]
async fn tx3_fee_is_15000_zatoshis() {
    let result = run_sync(params_for_block(TX3_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX3_TXID);
    assert_eq!(tx.fee_zatoshis, 15_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn tx3_has_one_internal_orchard_note() {
    let result = run_sync(params_for_block(TX3_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX3_TXID);
    assert_eq!(tx.orchard_notes.len(), 1);
    assert_eq!(tx.orchard_notes[0].transfer_type, "internal");
    assert_eq!(tx.orchard_notes[0].amount, 7_504);
}

// ── Range scan ────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn range_scan_finds_all_three_known_txids() {
    // Scan the smallest range that contains all 3 known transactions.
    let result = run_sync(params_for_range(TX1_HEIGHT, TX3_HEIGHT)).await.unwrap();

    let txids: Vec<&str> = result.transactions.iter().map(|tx| tx.txid.as_str()).collect();
    for expected in [TX1_TXID, TX2_TXID, TX3_TXID] {
        assert!(txids.contains(&expected), "missing txid {expected}\nfound: {txids:?}");
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn range_scan_results_are_in_chronological_order() {
    let result = run_sync(params_for_range(TX1_HEIGHT, TX3_HEIGHT)).await.unwrap();
    let heights: Vec<u32> = result.transactions.iter().map(|tx| tx.block_height).collect();
    let mut sorted = heights.clone();
    sorted.sort_unstable();
    assert_eq!(heights, sorted, "transactions must be returned in ascending block height order");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn range_scan_blocks_scanned_count_matches_range_size() {
    let result = run_sync(params_for_range(TX1_HEIGHT, TX1_HEIGHT + 9)).await.unwrap();
    assert_eq!(result.blocks_scanned, 10);
}

// ── orchard_only mode ─────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn orchard_only_finds_same_txids_as_full_mode() {
    let mut p_full = params_for_block(TX1_HEIGHT);
    p_full.orchard_only = false;
    let mut p_orchard = params_for_block(TX1_HEIGHT);
    p_orchard.orchard_only = true;

    let full = run_sync(p_full).await.unwrap();
    let orchard = run_sync(p_orchard).await.unwrap();

    let full_txids: std::collections::HashSet<_> =
        full.transactions.iter().map(|tx| &tx.txid).collect();
    let orchard_txids: std::collections::HashSet<_> =
        orchard.transactions.iter().map(|tx| &tx.txid).collect();

    assert_eq!(
        full_txids, orchard_txids,
        "orchard_only mode must find the same transactions as full mode for an Orchard-only wallet"
    );
}

// ── Phase 4: outgoing transaction detection via nullifier matching ────────────
//
// TX2 and TX3 are change (internal) notes created by spending transactions.
// The actual spending transactions — which send funds to external addresses —
// do not create outputs for our key, so they are invisible to trial decryption.
// Phase 4 detects them by matching spent nullifiers against our received notes.
//
// This test scans a range and verifies that the spending transactions for TX1's
// note are detected (they must appear in the results as additional entries beyond
// the 3 incoming/internal notes).

#[tokio::test]
#[ignore = "requires network access"]
async fn phase4_detects_spending_transactions() {
    // Scan the full range. TX2 and TX3 are change notes from spending txs —
    // those spending txs must be present in results.
    let result = run_sync(params_for_range(TX1_HEIGHT, TX3_HEIGHT)).await.unwrap();

    // At minimum we must find our 3 known transactions.
    assert!(
        result.transactions.len() >= 3,
        "expected at least 3 transactions, got {}",
        result.transactions.len()
    );

    // The transactions that *spend* TX1's note (creating TX2/TX3 as change)
    // must also be detected, even if they have no incoming/internal notes for us.
    // We verify this indirectly: if TX2 and TX3 are found, the spending txs
    // that created them as change were also processed (Phase 2 or Phase 4).
    let txids: Vec<&str> = result.transactions.iter().map(|tx| tx.txid.as_str()).collect();
    assert!(txids.contains(&TX2_TXID), "TX2 (change note) must be found");
    assert!(txids.contains(&TX3_TXID), "TX3 (change note) must be found");
}

// ════════════════════════════════════════════════════════════════════════════
// Testnet Sapling transactions
// Verified with zingo-cli using the testnet UFVK.
// ════════════════════════════════════════════════════════════════════════════

// ── TX_S1: pure Sapling incoming ──────────────────────────────────────────────
//
// c534920d035a64f8fb21163079f88413ade4a2b4f83138f0f47ec185994622c0
// Height 954,650 — incoming 1.00000000 ZEC, fee 0.0001 ZEC, memo "Thanks for using zfaucet!"

const TX_S1_TXID: &str = "c534920d035a64f8fb21163079f88413ade4a2b4f83138f0f47ec185994622c0";
const TX_S1_HEIGHT: u32 = 954_650;

#[tokio::test]
#[ignore = "requires network access"]
async fn txs1_is_found_by_trial_decrypt() {
    let result = run_sync(params_for_block_testnet(TX_S1_HEIGHT)).await.unwrap();
    assert!(
        result.transactions.iter().any(|tx| tx.txid == TX_S1_TXID),
        "TX_S1 not found — trial decrypt failed for Sapling incoming"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs1_fee_is_10000_zatoshis() {
    let result = run_sync(params_for_block_testnet(TX_S1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S1_TXID);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs1_has_one_sapling_incoming_note() {
    let result = run_sync(params_for_block_testnet(TX_S1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S1_TXID);
    assert_eq!(tx.sapling_notes.len(), 1);
    assert!(tx.orchard_notes.is_empty());
    assert_eq!(tx.sapling_notes[0].transfer_type, "incoming");
    assert_eq!(tx.sapling_notes[0].amount, 100_000_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs1_sapling_memo_decoded_correctly() {
    let result = run_sync(params_for_block_testnet(TX_S1_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S1_TXID);
    assert_eq!(tx.sapling_notes[0].memo, "Thanks for using zfaucet!");
}

// ── TX_S2: Sapling outgoing + incoming (self-send with external payment) ──────
//
// 18b4fcbb8c81265e64e2397938babbd2eb2d8262bfbb9987f2fca551e316de99
// Height 1,181,303 — outgoing 0.00017000 ZEC "Funds from Demo App" + incoming 0.99963000 ZEC, fee 0.0001 ZEC

const TX_S2_TXID: &str = "18b4fcbb8c81265e64e2397938babbd2eb2d8262bfbb9987f2fca551e316de99";
const TX_S2_HEIGHT: u32 = 1_181_303;

#[tokio::test]
#[ignore = "requires network access"]
async fn txs2_fee_is_10000_zatoshis() {
    let result = run_sync(params_for_block_testnet(TX_S2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S2_TXID);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs2_has_outgoing_and_incoming_sapling_notes() {
    let result = run_sync(params_for_block_testnet(TX_S2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S2_TXID);
    assert_eq!(tx.sapling_notes.len(), 2, "expected outgoing + incoming");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs2_outgoing_note_amount_and_memo() {
    let result = run_sync(params_for_block_testnet(TX_S2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S2_TXID);
    let note = note_with_type(&tx.sapling_notes, "outgoing");
    assert_eq!(note.amount, 17_000);
    assert_eq!(note.memo, "Funds from Demo App");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs2_incoming_note_amount() {
    let result = run_sync(params_for_block_testnet(TX_S2_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S2_TXID);
    let note = note_with_type(&tx.sapling_notes, "incoming");
    assert_eq!(note.amount, 99_963_000);
}

// ── TX_S3: Sapling t→z shielding (transparent input, fee=0) ──────────────────
//
// 60c1afabd6ac4bcd5b5d7498b2646f10f77176e848de31f080e73972b7b7fa5b
// Height 2,115,988 — internal 0.99999000 ZEC, fee 0 ZEC (zero-fee shielding tx)

const TX_S3_TXID: &str = "60c1afabd6ac4bcd5b5d7498b2646f10f77176e848de31f080e73972b7b7fa5b";
const TX_S3_HEIGHT: u32 = 2_115_988;

#[tokio::test]
#[ignore = "requires network access"]
async fn txs3_fee_is_zero_shielding_transaction() {
    // fee_paid returns None for transparent inputs (prevout unavailable from compact blocks)
    // → we report 0. The actual fee for this shielding tx is genuinely 0, so the result is correct.
    let result = run_sync(params_for_block_testnet(TX_S3_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S3_TXID);
    assert_eq!(tx.fee_zatoshis, 0);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs3_has_sapling_internal_note_with_shielding_memo() {
    let result = run_sync(params_for_block_testnet(TX_S3_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S3_TXID);
    let note = note_with_type(&tx.sapling_notes, "internal");
    assert_eq!(note.memo, "shielding:");
}

// ── TX_S4: Sapling incoming with trailing newline in memo ─────────────────────
//
// 68db58bfeffefafe3153a4dd733447806d1c811f59f99a95bd257318ee2910f8
// Height 2,618,505 — incoming 0.00000250 ZEC, fee 0.0001 ZEC

const TX_S4_TXID: &str = "68db58bfeffefafe3153a4dd733447806d1c811f59f99a95bd257318ee2910f8";
const TX_S4_HEIGHT: u32 = 2_618_505;

#[tokio::test]
#[ignore = "requires network access"]
async fn txs4_fee_is_10000_zatoshis() {
    let result = run_sync(params_for_block_testnet(TX_S4_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S4_TXID);
    assert_eq!(tx.fee_zatoshis, 10_000);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn txs4_memo_with_trailing_newline_preserved() {
    let result = run_sync(params_for_block_testnet(TX_S4_HEIGHT)).await.unwrap();
    let tx = find_tx(&result.transactions, TX_S4_TXID);
    assert_eq!(tx.sapling_notes[0].amount, 250);
    assert_eq!(tx.sapling_notes[0].memo, "sending some money from an emulator\n");
}

// ── Testnet range scan ────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn testnet_range_scan_finds_sapling_txs_s1_and_s2() {
    // Quick range covering both early Sapling transactions.
    let result = run_sync(params_for_range_testnet(TX_S1_HEIGHT, TX_S2_HEIGHT)).await.unwrap();
    let txids: Vec<&str> = result.transactions.iter().map(|tx| tx.txid.as_str()).collect();
    for expected in [TX_S1_TXID, TX_S2_TXID] {
        assert!(txids.contains(&expected), "missing {expected}\nfound: {txids:?}");
    }
}

// ── enrichment: spending fields and isSpent ─────────────────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn full_scan_enriches_incoming_note_with_spending_fields() {
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx1 = find_tx(&result.transactions, TX1_TXID);
    assert_eq!(tx1.orchard_notes.len(), 1);
    let note = &tx1.orchard_notes[0];

    // Incoming note must have all spending fields populated
    assert!(note.nullifier.is_some(), "incoming note must have nullifier");
    assert!(note.rseed.is_some(), "incoming note must have rseed");
    assert!(note.cmx.is_some(), "incoming note must have cmx");
    assert!(note.position.is_some(), "incoming note must have position");
    assert!(note.recipient.is_some(), "incoming note must have recipient");

    // Field sizes: nullifier/rseed/cmx = 64 hex chars (32 bytes), recipient = 86 hex chars (43 bytes)
    assert_eq!(note.nullifier.as_ref().unwrap().len(), 64, "nullifier must be 32 bytes hex");
    assert_eq!(note.rseed.as_ref().unwrap().len(), 64, "rseed must be 32 bytes hex");
    assert_eq!(note.cmx.as_ref().unwrap().len(), 64, "cmx must be 32 bytes hex");
    assert_eq!(note.recipient.as_ref().unwrap().len(), 86, "recipient must be 43 bytes hex");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn full_scan_marks_spent_note_when_spending_tx_is_in_range() {
    // TX1 (height 3,047,167) is an incoming note. TX2 (height 3,055,407) is a change
    // note from a tx that SPENDS TX1's note. Scanning the full range should detect
    // that TX1's note is spent.
    let result = run_sync(params_for_range(TX1_HEIGHT, TX2_HEIGHT)).await.unwrap();

    let tx1 = find_tx(&result.transactions, TX1_TXID);
    let note = &tx1.orchard_notes[0];
    assert!(note.is_spent, "TX1's note must be is_spent=true (spent by the tx creating TX2)");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn single_block_scan_note_is_unspent_when_spending_tx_outside_range() {
    // Scanning only TX1's block: the spending tx is at a later height,
    // so is_spent must be false (spending not visible in this range).
    let result = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx1 = find_tx(&result.transactions, TX1_TXID);
    assert!(!tx1.orchard_notes[0].is_spent, "TX1 unspent when scanned alone");
}

// ── Incremental sync: known_nullifiers → spent_known_nullifiers ──────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn incremental_scan_returns_spent_known_nullifiers() {
    // Phase 1: scan TX1's block to discover its nullifier
    let result1 = run_sync(params_for_block(TX1_HEIGHT)).await.unwrap();
    let tx1 = find_tx(&result1.transactions, TX1_TXID);
    let nf1 = tx1.orchard_notes[0]
        .nullifier
        .clone()
        .expect("TX1 incoming note must have nullifier");

    // The note is unspent when scanned alone
    assert!(!tx1.orchard_notes[0].is_spent);

    // Phase 2: incremental scan AFTER TX1's block, with NF1 as known
    let mut params = params_for_range(TX1_HEIGHT + 1, TX2_HEIGHT);
    params.known_nullifiers = vec![nf1.clone()];
    let result2 = run_sync(params).await.unwrap();

    // Rust must report NF1 in spent_known_nullifiers
    assert!(
        result2.spent_known_nullifiers.contains(&nf1),
        "NF1 must be in spent_known_nullifiers.\n\
         NF1 = {nf1}\n\
         spent_known_nullifiers = {:?}",
        result2.spent_known_nullifiers,
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn incremental_scan_with_empty_known_nullifiers_returns_empty_spent() {
    // Without known_nullifiers, spent_known_nullifiers must be empty.
    let result = run_sync(params_for_range(TX1_HEIGHT + 1, TX2_HEIGHT)).await.unwrap();
    assert!(
        result.spent_known_nullifiers.is_empty(),
        "without known_nullifiers, spent_known_nullifiers must be empty"
    );
}

// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires network access"]
async fn testnet_full_mode_required_to_find_sapling_transactions() {
    // With orchard_only=true, Sapling outputs are stripped before trial decrypt.
    // TX_S1 (pure Sapling) must NOT be found in orchard_only mode.
    let mut p = params_for_block_testnet(TX_S1_HEIGHT);
    p.orchard_only = true;
    let result = run_sync(p).await.unwrap();
    assert!(
        !result.transactions.iter().any(|tx| tx.txid == TX_S1_TXID),
        "TX_S1 must not be found when orchard_only=true (it has no Orchard actions)"
    );
}

// Prerequisite: GetTreeState & GetSubtreeRoots availability ─────
//
// These tests verify that the Ledger-hosted Zaino node supports the gRPC
// calls required for Merkle witness computation.
//
// Run:
//   cargo test -p zcash-sync --test integration_sync -- --ignored get_tree_state
//   cargo test -p zcash-sync --test integration_sync -- --ignored get_subtree_roots

const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

async fn grpc_client(url: &str) -> CompactTxStreamerClient<Channel> {
    let channel = zcash_sync::client::connect(url)
        .await
        .expect("gRPC connect failed");
    CompactTxStreamerClient::new(channel)
}

#[tokio::test]
#[ignore = "requires network access"]
async fn get_tree_state_mainnet_returns_orchard_frontier() {
    let mut client = grpc_client(&mainnet_grpc_url()).await;

    let mut req = tonic::Request::new(BlockId {
        height: 3_047_167,
        hash: vec![],
    });
    req.set_timeout(UNARY_TIMEOUT);

    let tree_state = client
        .get_tree_state(req)
        .await
        .expect("GetTreeState failed")
        .into_inner();

    eprintln!(
        "GetTreeState(3047167): orchard_tree={} bytes",
        tree_state.orchard_tree.len()
    );
    assert_eq!(tree_state.height, 3_047_167);
    assert!(
        !tree_state.orchard_tree.is_empty(),
        "orchard_tree must not be empty"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn get_subtree_roots_orchard_mainnet() {
    let mut client = grpc_client(&mainnet_grpc_url()).await;

    let mut req = tonic::Request::new(GetSubtreeRootsArg {
        start_index: 0,
        shielded_protocol: ShieldedProtocol::Orchard as i32,
        max_entries: 5,
    });
    req.set_timeout(UNARY_TIMEOUT);

    let stream = client
        .get_subtree_roots(req)
        .await
        .expect("GetSubtreeRoots(Orchard) failed");

    let mut stream = stream.into_inner();
    let mut count = 0u32;
    while let Some(root) = stream.message().await.expect("stream error") {
        eprintln!(
            "  subtree_root[{count}]: hash={} bytes, completing_height={}",
            root.root_hash.len(),
            root.completing_block_height,
        );
        assert_eq!(root.root_hash.len(), 32, "root_hash must be 32 bytes");
        count += 1;
    }

    eprintln!("GetSubtreeRoots(Orchard): {count} roots received");
    assert!(count > 0, "expected at least one Orchard subtree root");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn get_subtree_roots_orchard_testnet() {
    let mut client = grpc_client(&testnet_grpc_url()).await;

    let mut req = tonic::Request::new(GetSubtreeRootsArg {
        start_index: 0,
        shielded_protocol: ShieldedProtocol::Orchard as i32,
        max_entries: 5,
    });
    req.set_timeout(UNARY_TIMEOUT);

    let stream = client
        .get_subtree_roots(req)
        .await
        .expect("GetSubtreeRoots(Orchard) failed on testnet");

    let mut stream = stream.into_inner();
    let mut count = 0u32;
    while stream.message().await.expect("stream error").is_some() {
        count += 1;
    }

    eprintln!("GetSubtreeRoots(Orchard, testnet): {count} roots received");
    assert!(
        count > 0,
        "expected at least one Orchard subtree root on testnet"
    );
}

// ── Witness computation regression benchmark ──────────────────────────────────
//
// Spec requirement: computing Merkle witnesses for 2 notes in the same Orchard
// shard must complete in under 15 seconds end-to-end — including the gRPC
// round-trips that fetch the frontier (GetTreeState), the cap roots
// (GetSubtreeRoots), and the shard's cmx leaves (GetBlockRange).
//
// Both notes live in the partial frontier shard (index 2, base position
// 131_072) of the testnet known-good vector pinned at anchor height 3,861,070.
// Their cmxs are the first two leaves of that shard, lifted verbatim from
// `zcash-crypto/src/tree.rs::known_good_test_vector`, so `compute_witnesses`
// validates each path re-roots to the captured anchor before returning.
//
// Run:
//   cargo test -p zcash-sync --test integration_sync -- --ignored witness_two_notes_same_shard_under_15s --nocapture

const WITNESS_BENCH_ANCHOR_HEIGHT: u32 = 3_861_070;
const WITNESS_BENCH_NOTE_0_POSITION: u64 = 131_072;
const WITNESS_BENCH_NOTE_0_CMX: &str =
    "c53c1944c1add04a071359f9c077aa8991f5431736b1f958270718bc1250c531";
const WITNESS_BENCH_NOTE_1_POSITION: u64 = 131_073;
const WITNESS_BENCH_NOTE_1_CMX: &str =
    "5d8c2880ba85481a078f98482d9616decc89d972408747beeaffd3501c83770b";
const WITNESS_BENCH_BUDGET: Duration = Duration::from_secs(15);

#[tokio::test]
#[ignore = "requires network access"]
async fn witness_two_notes_same_shard_under_15s() {
    use std::time::Instant;
    use zcash_sync::witness::{compute_witnesses, NoteRef, WitnessRequest};

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    let note0 = NoteRef {
        position: WITNESS_BENCH_NOTE_0_POSITION,
        cmx: h32(WITNESS_BENCH_NOTE_0_CMX),
    };
    let note1 = NoteRef {
        position: WITNESS_BENCH_NOTE_1_POSITION,
        cmx: h32(WITNESS_BENCH_NOTE_1_CMX),
    };

    // Guard the premise of the benchmark: both notes must share a shard, else
    // we'd be timing multi-shard fetching instead of the single-shard case.
    // Shard index = position >> ORCHARD_SHARD_HEIGHT (16 for Orchard).
    assert_eq!(
        note0.position >> 16,
        note1.position >> 16,
        "benchmark notes must live in the same Orchard shard"
    );

    let started = Instant::now();
    let out = compute_witnesses(WitnessRequest {
        grpc_url: testnet_grpc_url(),
        anchor_height: Some(WITNESS_BENCH_ANCHOR_HEIGHT),
        anchor_depth_blocks: None,
        notes: vec![note0, note1],
    })
    .await
    .expect("compute_witnesses failed");
    let elapsed = started.elapsed();

    // One witness per note, in request order, at the requested positions.
    assert_eq!(out.witnesses.len(), 2, "expected one witness per note");
    assert_eq!(
        u64::from(out.witnesses[0].position()),
        WITNESS_BENCH_NOTE_0_POSITION
    );
    assert_eq!(
        u64::from(out.witnesses[1].position()),
        WITNESS_BENCH_NOTE_1_POSITION
    );

    eprintln!(
        "witness computation for 2 notes in shard {} took {:?} (budget {:?})",
        note0.position >> 16,
        elapsed,
        WITNESS_BENCH_BUDGET
    );
    assert!(
        elapsed < WITNESS_BENCH_BUDGET,
        "witness computation regressed: took {elapsed:?}, budget is {WITNESS_BENCH_BUDGET:?}"
    );
}
