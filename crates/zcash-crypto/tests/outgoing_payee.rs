/// Recovery of a shielded payment's destination, on known transactions.
///
/// The payee of a shielded output is only recoverable by the sender, through
/// the outgoing viewing key the transaction was built with. These tests use the
/// same offline fixtures and UFVK as `known_vectors`.
///
/// Run with: `cargo test -p zcash-crypto --test outgoing_payee`
use zcash_crypto::payee::outgoing_payees;
use zcash_keys::address::Address;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

const MAINNET_UFVK: &str = "uview1qggz6nejagvka9wtm9r7xf84kkwy4cc0cgchptr98w0cyz33cj4958q5ulkd32nz2u3s0sp9yhcw7tu2n3nlw9x6ulghyd2zgc857tnzme2zpr3vn24zhtm2rjduv9a5zxlmzz404n7l0k69gmu4tfn2g3vpcn03rhz63e3l92fn8gra37tyly7utvgveswl20vz23pu84rc2nyqess38wvlgr2xzyhgj232ne5qutpe6ql6ghzetdy7pfzcmdzd5gd5dnwk25fwv7nnzmnty7u5ax3nzzgr6pdc905ckpd0s9v2cvn7e03qm7r46e5ngax536ywz7zxjptymm90px0rhvmqtwvttuy6d7degly023lqvskclk6mezyt69dwu6c4tfzrjgq4uuh5xa9m5dclgatykgtrrw268qe5pldfkx73f2kd5yyy2tjpjql92pa6tsk2nh2h88q23nee9z379het4akl6haqmuwf9d0nl0susg4tnxyk";

/// Same key pair as `MAINNET_UFVK`, testnet encoding.
const TESTNET_UFVK: &str = "uviewtest1eacc7lytmvgp0sshwjjv4qsg9fnewq00s6zye8hqwndpdsg0tum2ft4k96t86eapddpq56exfycnxnlds75vvpydv8fgj4cecczkmt3rjat8qjfqrk2cdlm9alep2z04785sx6yekqjk6wywkttlthld4c3xmg8fvneg4p97vzxwu9xtuh0xrgfy90p6uuxf8cwl8nxfq6hlte0nnylk59xceldrkx9vge3k4utkue2txu5kpp60aw07q0f0jgp0pv2c0gr7jdm6273uxyskt72jehte5jf2dg94d84le08h2t5rhd93j2d98ja59h46est69f3a7rav7k6744p2u8dxasc7nr9p2k95x7uaknahj0kw7mu5zq9nllj7x2qswq3jswsuzwms7shv7dhxz9s4yudatwu3u3v3wqznkhu6jt7xt8whjh3dkzvsf28p6mj8tya009gwzgszz2at8alquu8y0fmqt7klayrjx7n3ulml5q00fgdr";

/// TX_S2 — Sapling outgoing(17000 zat, memo) + incoming(99963000 zat).
/// The outgoing note is recovered through the outgoing viewing key, which is
/// what makes its payee knowable at all.
const TX_S2_HEX: &str = include_str!("fixtures/tx_18b4fcbb_h1181303_testnet.hex");
const TX_S2_HEIGHT: u32 = 1_181_303;

/// TX3 — a single Orchard internal (change) note. Height 3,055,417.
const TX3_HEX: &str = include_str!("fixtures/tx_0b5baa0c_h3055417.hex");
const TX3_HEIGHT: u32 = 3_055_417;

/// TX1 — a single Orchard incoming note. Height 3,047,167.
const TX1_HEX: &str = include_str!("fixtures/tx_d592576d_h3047167.hex");
const TX1_HEIGHT: u32 = 3_047_167;

#[test]
fn recovers_the_payee_of_an_outgoing_sapling_note() {
    let payees = outgoing_payees(
        TX_S2_HEX.trim(),
        TESTNET_UFVK,
        TX_S2_HEIGHT,
        Network::TestNetwork,
    )
    .expect("decryption should succeed on a valid fixture");

    assert_eq!(
        payees.len(),
        1,
        "the transaction has exactly one outgoing note"
    );

    let payee = &payees[0];
    assert!(
        payee.starts_with("ztestsapling1"),
        "expected a testnet Sapling address, got {payee}"
    );
    assert!(
        matches!(
            Address::decode(&Network::TestNetwork, payee),
            Some(Address::Sapling(_))
        ),
        "recovered payee must be a decodable Sapling address"
    );
}

/// The point of the recovery: the payee is someone else. An address of our own
/// would mean we had recovered change and mistaken it for a destination.
#[test]
fn the_recovered_payee_is_not_one_of_our_own_addresses() {
    let payees = outgoing_payees(
        TX_S2_HEX.trim(),
        TESTNET_UFVK,
        TX_S2_HEIGHT,
        Network::TestNetwork,
    )
    .expect("decryption should succeed on a valid fixture");

    let ufvk = UnifiedFullViewingKey::decode(&Network::TestNetwork, TESTNET_UFVK)
        .expect("fixture viewing key should decode");
    let sapling = ufvk
        .sapling()
        .expect("testnet fixture wallet has a Sapling key");

    let encode = |(_, address)| Address::Sapling(address).encode(&Network::TestNetwork);
    let ours = [
        encode(sapling.default_address()),
        encode(sapling.change_address()),
    ];

    assert!(
        !ours.contains(&payees[0]),
        "recovered a change address instead of the payee"
    );
}

/// Change pays us back, so it is not a destination to report.
#[test]
fn an_internal_change_note_is_not_a_payee() {
    let payees = outgoing_payees(
        TX3_HEX.trim(),
        MAINNET_UFVK,
        TX3_HEIGHT,
        Network::MainNetwork,
    )
    .expect("decryption should succeed on a valid fixture");

    assert!(payees.is_empty(), "change is not a payee, got {payees:?}");
}

/// A note paying us has a recipient — ourselves — which must not be reported as
/// somewhere we sent funds.
#[test]
fn an_incoming_note_is_not_a_payee() {
    let payees = outgoing_payees(
        TX1_HEX.trim(),
        MAINNET_UFVK,
        TX1_HEIGHT,
        Network::MainNetwork,
    )
    .expect("decryption should succeed on a valid fixture");

    assert!(
        payees.is_empty(),
        "an incoming note is not a payee, got {payees:?}"
    );
}

/// A transaction we have nothing to do with reveals no payee: without a note of
/// ours to decrypt, the destination stays private.
#[test]
fn a_transaction_of_someone_elses_reveals_no_payee() {
    let payees = outgoing_payees(
        TX_S2_HEX.trim(),
        MAINNET_UFVK,
        TX_S2_HEIGHT,
        Network::TestNetwork,
    )
    .expect("decryption of an undecryptable transaction is not an error");

    assert!(
        payees.is_empty(),
        "expected no payee for a foreign transaction, got {payees:?}"
    );
}
