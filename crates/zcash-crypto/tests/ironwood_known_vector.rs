//! Integration test using a real captured Ironwood (NU6.3) anchor as a fixed
//! test vector, fully offline (no network access at test time).
//!
//! ## Provenance (anti-hallucination)
//!
//! `EXPECTED_ANCHOR` (and the accompanying witness/position/cmx, recorded
//! below for reference) were captured from the public zec.rocks testnet
//! Zaino node (`https://testnet.zec.rocks:443`), reading
//! `TreeState::ironwood_tree` at height 4,193,460 and scanning
//! `GetBlockRange` over `CompactTx::ironwood_actions` from the NU6.3 testnet
//! activation height (4,134,000) through that height. No value here is
//! fabricated.
//!
//! ## Why this file only bakes the anchor (not the full leaf set)
//!
//! The Ironwood pool has not completed a single shard on testnet yet (only
//! ~9.8k of the 65,536 leaves shard 0 needs), so reproducing the *recomputation*
//! of this anchor from scratch requires the entire real leaf set — impractical
//! to bake here (it does not fit as inline literals, and a large generated
//! fixture file is not worth checking in for this). That recomputation check
//! (`build_witnesses` on the live leaves reproduces exactly `EXPECTED_ANCHOR`
//! and `EXPECTED_WITNESS_PATH`) instead lives in the capture harness itself —
//! see `zcash-sync/tests/capture_ironwood_witness_vector.rs`'s
//! `verify_frozen_vector_is_reproducible_from_live_data` test, which re-fetches
//! the real leaves at this exact height and re-derives the anchor/path,
//! proving they are real and recomputable (not just self-consistent literals).
//!
//! This file only needs the **anchor** value: the single test below exercises
//! `build_ironwood_transaction`'s Public→Ironwood flow (dummy spends only), for
//! which the anchor's in-circuit Merkle-root check is a no-op — so this is the
//! one flow shape that can legitimately combine a real, historical anchor with
//! a synthetic (non-owned) note. Asserting a frozen anchor against itself here
//! would be tautological; the harness test above is what proves the anchor is
//! real, and this test is what proves `build_ironwood_transaction` accepts it
//! and produces a valid V6 PCZT.
//!
//! Run with: `cargo test -p zcash-crypto --test ironwood_known_vector`

use zcash_crypto::craft::{
    build_ironwood_transaction, IronwoodBuildInputs, IronwoodDestination, IronwoodOutputRequest,
    TransparentInput,
};
use zcash_protocol::consensus::Network;

// ── Captured vector (real testnet data, see module doc) ──────────────────────

/// Height the anchor below was captured at (also the `target_height` basis for
/// the build below, since NU6.3 must be active at `target_height`).
const ANCHOR_HEIGHT: u32 = 4_193_460;

/// Real Ironwood anchor (commitment-tree root) at `ANCHOR_HEIGHT`. The only
/// captured value this file's test actually consumes.
const EXPECTED_ANCHOR: &str = "727af33dfc1d36e2914771b31ac7de08dc7e546cd10a18ec29a73d5119f2b022";

/// Leaf position of the witnessed note the anchor above roots (the very first
/// real Ironwood commitment ever observed on testnet). Recorded for
/// provenance/cross-reference with the capture harness's recomputation check;
/// not needed by this file's Public→Ironwood test (which carries no real
/// spend at this position).
#[allow(dead_code)]
const NOTE_POSITION: u64 = 0;

/// The real on-chain commitment at `NOTE_POSITION`. Recorded for provenance
/// only (see above).
#[allow(dead_code)]
const NOTE_CMX_HEX: &str = "d96886a60491bf3a63eb3ce28f46f6ee70ceaa8dcab4eff13844417851062933";

/// The real 32-element authentication path from `NOTE_POSITION` to
/// `EXPECTED_ANCHOR`. Recorded for provenance only — reproduced and verified
/// against live data in the capture harness (see the module doc above), not
/// re-verified in this offline test.
#[allow(dead_code)]
const EXPECTED_WITNESS_PATH: [&str; 32] = [
    "3e254e08f8bed22aa74fc61c3ceb955dc311833d9cc3dc99b5448622716b6f31",
    "b7723607a89c83d1c14141cf57aa3e462d772a2cbb9af2ac85a4863307c3072e",
    "036e9e102172e29851e949a8d785cb97ecb347b2dec5bd00bbd1cd18e7ca8100",
    "bb17d420d4d2554c7d262e0267f5b8f162000929a001214397378b29f852bc23",
    "1d177210265e125d095fe53f128343fa983e5c2b4ee60215f881cd614654e122",
    "65cfebc5097272b668edf54d48891addaa812cfd39e5a29d4cc4c0e931818912",
    "9d576d73e74362b8336a1f2287ddb19e0ea35da7a641a9551ba6e40cfca4ba1d",
    "2b4b3b155397033052439e5b2589006662bb66d416a0564c6fc0dfbcf7cece1e",
    "f9a605162f94170167bdc14a0d0ddf0e175bd96d2bd71e0289b9458225fd873e",
    "c2eb3b3bb4eebd97c8f6a0fe4e661c6b1d99c166a872834163d8b1ad908d1d39",
    "b77939bba3804b23f30de5a449439632c685cd33d221975086848ac7df764f1a",
    "f7fea8485ba875e7ec706e8cbaa5329815a0bbf4eee5011c5293e3680f2ef33a",
    "95d364fc1d8903ce705f711e46526995ec4dc34ee7a752d0cb185dcc8b758726",
    "b5ebf2de99883720912b941f1840965a8a9556f850de62bda76aad0d0246e218",
    "3f98adbe364f148b0cc2042cafc6be1166fae39090ab4b354bfb6217b964453b",
    "63f8dbd10df936f1734973e0b3bd25f4ed440566c923085903f696bc6347ec0f",
    "2182163eac4061885a313568148dfae564e478066dcbe389a0ddb1ecb7f5dc34",
    "bd9dc0681918a3f3f9cd1f9e06aa1ad68927da63acc13b92a2578b2738a6d331",
    "ca2ced953b7fb95e3ba986333da9e69cd355223c929731094b6c2174c7638d2e",
    "55354b96b56f9e45aae1e0094d71ee248dabf668117778bdc3c19ca5331a4e1a",
    "7097b04c2aa045a0deffcaca41c5ac92e694466578f5909e72bb78d33310f705",
    "e81d6821ff813bd410867a3f22e8e5cb7ac5599a610af5c354eb392877362e01",
    "157de8567f7c4996b8c4fdc94938fd808c3b2a5ccb79d1a63858adaa9a6dd824",
    "fe1fce51cd6120c12c124695c4f98b275918fceae6eb209873ed73fe73775d0b",
    "1f91982912012669f74d0cfa1030ff37b152324e5b8346b3335a0aaeb63a0a2d",
    "5dec15f52af17da3931396183cbbbfbea7ed950714540aec06c645c754975522",
    "e8ae2ad91d463bab75ee941d33cc5817b613c63cda943a4c07f600591b088a25",
    "d53fdee371cef596766823f4a518a583b1158243afe89700f0da76da46d0060f",
    "15d2444cefe7914c9a61e829c730eceb216288fee825f6b3b6298f6f6b6bd62e",
    "4c57a617a0aa10ea7a83aa6b6b0ed685b6a3d9e5b8fd14f56cdc18021b12253f",
    "3fd4915c19bd831a7920be55d969b2ac23359e2559da77de2373f06ca014ba27",
    "87d063cd07ee4944222b7762840eb94c688bec743fa8bdf7715c8fe29f104c2a",
];

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// A deterministic compressed secp256k1 pubkey (33 bytes) for a synthetic
/// transparent input, mirroring `craft.rs`'s own private test helper (not
/// reusable across the crate boundary, so duplicated here).
fn make_test_pubkey() -> [u8; 33] {
    use secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x01u8; 32]).unwrap();
    secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
}

/// Standard P2PKH scriptPubKey (25 bytes) for a 20-byte hash.
fn make_p2pkh_script(hash: [u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(&hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

fn pubkey_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
    use bitcoin::hashes::{hash160, Hash};
    hash160::Hash::hash(pubkey).to_byte_array()
}

/// Builds a V6/Ironwood PCZT using `build_ironwood_transaction` against the
/// **real** captured testnet anchor above (Public→Ironwood: a transparent
/// input funds a synthetic Ironwood output; no real Ironwood spends). This is
/// the only flow shape that can legitimately combine a real, historical
/// anchor with a synthetic note: the builder injects value-0 dummy spends to
/// pad the bundle, and a dummy spend's in-circuit Merkle-root check is
/// disabled, so any validly-encoded anchor is accepted (mirrors the Orchard V5
/// `public_to_private_produces_orchard_output_pczt` test's rationale) — unlike
/// a real spend, which would require the actual (unknown to us) rho/rseed of
/// whatever note truly sits at `NOTE_POSITION` on testnet.
#[test]
fn build_ironwood_transaction_with_real_testnet_anchor_produces_valid_v6_pczt() {
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&[7u8; 32], 133, zip32::AccountId::ZERO)
        .unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
    let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let ovk = Some(fvk.to_ovk(orchard::keys::Scope::External));

    let pubkey = make_test_pubkey();
    let transparent_input = TransparentInput {
        pubkey,
        txid: [0x01u8; 32],
        vout: 0,
        script_pubkey: make_p2pkh_script(pubkey_hash160(&pubkey)),
        value: 25_000, // 10_000 output + 15_000 ZIP-317 fee (exact balance)
        derivation_scope: 0,
        derivation_address_index: 0,
    };

    // 0 ironwood spends (padded to 2), 1 ironwood output, 1 transparent input,
    // 0 transparent output → logical = max(1,0) + max(2,1) = 1 + 2 = 3 → 15_000.
    let fee = 15_000u64;

    let inputs = IronwoodBuildInputs {
        network: Network::TestNetwork,
        target_height: ANCHOR_HEIGHT + zcash_crypto::craft::DEFAULT_TX_EXPIRY_DELTA,
        ironwood_fvk: None, // no real Ironwood spends
        ovk,
        change_address: Some(change_address),
        transparent_change_address: None,
        transparent_change_pubkey: None,
        transparent_change_address_index: None,
        anchor: h32(EXPECTED_ANCHOR),
        seed_fingerprint: [0x42; 32],
        account_index: 0,
        fee,
        spends: vec![],
        transparent_inputs: vec![transparent_input],
        outputs: vec![IronwoodOutputRequest {
            destination: IronwoodDestination::Ironwood(recipient),
            value: 10_000,
            memo: None,
        }],
    };

    let out = build_ironwood_transaction(inputs)
        .expect("build_ironwood_transaction must succeed against the real testnet anchor");

    assert_eq!(&out.pczt_bytes[..4], b"PCZT");
    assert_eq!(
        &out.pczt_bytes[4..8],
        &2u32.to_le_bytes(),
        "V6/Ironwood PCZT must serialize as v2"
    );
    assert!(
        out.n_actions_ironwood >= 1,
        "must carry a non-empty Ironwood bundle (dummy-padded)"
    );
    assert_eq!(out.n_transparent_inputs, 1);
    assert_eq!(out.n_transparent_outputs, 0, "exact balance leaves no transparent change");
    assert_eq!(out.fee, fee);
}
