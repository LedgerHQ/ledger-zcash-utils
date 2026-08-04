use zcash_address::unified::{Container, Encoding, Fvk, Ufvk};
use zcash_protocol::consensus::NetworkType;
use zcash_crypto::error::Error;
use zcash_crypto::keys::{derive_keys, orchard_address_from_ufvk, ZcashNetwork};

// ── Conformance vectors from app-zcash tests/standalone/test_pubkey_cmd.py ────
// These are the ground truth — derived from m/32'/133'/<account>' + m/44'/133'/<account>'.
// If these fail, host and device are out of sync.

const UFVK0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";
const UFVK1: &str = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf";

const EXPECTED0: &str = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9";
const EXPECTED1: &str = "u1n4d94z4l9zs0kxhhytwyktg3rsmr9u0eagt3kn78j9m3lmnuzswuwn63az5jzfwqmvrfn0g8s3rvvg0wr0pklnkejm6d69hv8u5g6w9e";

// Mnemonic for tests that need to derive keys from scratch
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ── Conformance ────────────────────────────────────────────────────────────────

#[test]
fn account_0_matches_device_vector() {
    assert_eq!(orchard_address_from_ufvk(UFVK0).unwrap(), EXPECTED0);
}

#[test]
fn account_1_matches_device_vector() {
    assert_eq!(orchard_address_from_ufvk(UFVK1).unwrap(), EXPECTED1);
}

// ── Differs from multi_receiver_unified_address ────────────────────────────────
// Explicitly asserted so a future refactor that collapses the two fails loudly.

#[test]
fn orchard_address_differs_from_multi_receiver_address() {
    let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
    let orchard_addr = orchard_address_from_ufvk(&keys.ufvk).unwrap();
    assert_ne!(
        orchard_addr, keys.multi_receiver_unified_address,
        "orchard_address_from_ufvk must not equal multi_receiver_unified_address — \
         they produce different receiver sets and the device only matches the Orchard-only one"
    );
}

// ── Determinism ────────────────────────────────────────────────────────────────

#[test]
fn same_ufvk_returns_same_address_twice() {
    assert_eq!(
        orchard_address_from_ufvk(UFVK0).unwrap(),
        orchard_address_from_ufvk(UFVK0).unwrap()
    );
}

#[test]
fn different_accounts_return_different_addresses() {
    assert_ne!(
        orchard_address_from_ufvk(UFVK0).unwrap(),
        orchard_address_from_ufvk(UFVK1).unwrap()
    );
}

// ── Network prefix ─────────────────────────────────────────────────────────────

#[test]
fn mainnet_ufvk_returns_u1_prefix() {
    assert!(orchard_address_from_ufvk(UFVK0).unwrap().starts_with("u1"));
}

#[test]
fn testnet_ufvk_returns_utest1_prefix() {
    let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Testnet, None).unwrap();
    let addr = orchard_address_from_ufvk(&keys.ufvk).unwrap();
    assert!(addr.starts_with("utest1"), "got: {addr}");
}

// ── Error cases ────────────────────────────────────────────────────────────────

#[test]
fn malformed_ufvk_returns_invalid_ufvk_error() {
    let err = orchard_address_from_ufvk("notavalidufvk").unwrap_err();
    assert!(matches!(err, Error::InvalidUfvk { .. }));
}

#[test]
fn empty_string_returns_invalid_ufvk_error() {
    let err = orchard_address_from_ufvk("").unwrap_err();
    assert!(matches!(err, Error::InvalidUfvk { .. }));
}

#[test]
fn truncated_bech32m_returns_invalid_ufvk_error() {
    let truncated = &UFVK0[..40];
    let err = orchard_address_from_ufvk(truncated).unwrap_err();
    assert!(matches!(err, Error::InvalidUfvk { .. }));
}

#[test]
fn sapling_only_ufvk_returns_no_orchard_receiver_error() {
    // Derive a real UFVK, strip the Orchard component → valid Sapling-only UFVK.
    // Tests that the error is NoOrchardReceiver, distinct from InvalidUfvk.
    let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
    let (net, container) = Ufvk::decode(&keys.ufvk).unwrap();

    let sapling_only: Vec<Fvk> = container
        .items_as_parsed()
        .iter()
        .filter(|item| matches!(item, Fvk::Sapling(_)))
        .cloned()
        .collect();

    let encoded = Ufvk::try_from_items(sapling_only).unwrap().encode(&net);

    let err = orchard_address_from_ufvk(&encoded).unwrap_err();
    assert!(
        matches!(err, Error::NoOrchardReceiver),
        "expected NoOrchardReceiver, got: {err:?}"
    );
}

#[test]
fn regtest_ufvk_returns_unsupported_network_error() {
    // Re-encode a valid mainnet UFVK with the regtest HRP to simulate a regtest UFVK.
    let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
    let (_, container) = Ufvk::decode(&keys.ufvk).unwrap();
    let items: Vec<Fvk> = container.items_as_parsed().to_vec();
    let regtest_ufvk = Ufvk::try_from_items(items).unwrap().encode(&NetworkType::Regtest);

    let err = orchard_address_from_ufvk(&regtest_ufvk).unwrap_err();
    assert!(
        matches!(err, Error::UnsupportedNetwork { .. }),
        "expected UnsupportedNetwork, got: {err:?}"
    );
}

#[test]
fn invalid_and_no_orchard_errors_are_distinct() {
    let invalid_err = orchard_address_from_ufvk("garbage").unwrap_err();
    assert!(matches!(invalid_err, Error::InvalidUfvk { .. }));

    let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
    let (net, container) = Ufvk::decode(&keys.ufvk).unwrap();
    let sapling_only: Vec<Fvk> = container
        .items_as_parsed()
        .iter()
        .filter(|item| matches!(item, Fvk::Sapling(_)))
        .cloned()
        .collect();
    let encoded = Ufvk::try_from_items(sapling_only).unwrap().encode(&net);
    let no_orchard_err = orchard_address_from_ufvk(&encoded).unwrap_err();

    assert!(matches!(no_orchard_err, Error::NoOrchardReceiver));
    assert!(!matches!(no_orchard_err, Error::InvalidUfvk { .. }));
}
