/// Fee computation on known mainnet transactions that move value across the
/// transparent/shielded boundary — the case a Bitcoin-shaped indexer gets wrong.
///
/// Both fixtures were observed in Ledger Live, where the Zcash indexer reported
/// the fee as `Σ transparent inputs − Σ transparent outputs`, swallowing the
/// value that crossed into the shielded pool.
///
/// Run with: `cargo test -p zcash-crypto --test transaction_fee`
use zcash_crypto::fee::{transaction_fee, PrevoutValues};
use zcash_protocol::consensus::Network;

/// TX_T2Z — transparent→shielded send. 9 transparent inputs totalling 39,360,963
/// zat, one transparent change output of 29,305,963, and 10,000,000 into the
/// Orchard pool. The indexer reported 10,055,000 as the fee; the real fee is
/// 55,000.
/// txid: 76ec3b3879c037f8a0acddcaf3fece972fb73cb030793c54675f48f2e8c015fd
const TX_T2Z_HEX: &str = include_str!("fixtures/tx_76ec3b38_h3426175.hex");
const TX_T2Z_HEIGHT: u32 = 3_426_175;

/// TX_Z2T — shielded→transparent send. No transparent inputs, 500,000 zat out
/// to a transparent address, paid from the Orchard pool.
/// txid: 932c99c7837d7be18ed347213ae9a89a848ea9303f55e07ae5392f858f9258fc
const TX_Z2T_HEX: &str = include_str!("fixtures/tx_932c99c7_h3425858.hex");
const TX_Z2T_HEIGHT: u32 = 3_425_858;

fn t2z_prevouts() -> PrevoutValues {
    [
        (
            (
                "2a84cff0674167c31cc4a7f04e80e6dd0261cb2892c264f99dbb4703ab9a0dbe".to_string(),
                0,
            ),
            6_191_914,
        ),
        (
            (
                "d452101fabffdad3bc880c944a7672512740304416e41a90cd1fda1370ec1d42".to_string(),
                0,
            ),
            5_865_000,
        ),
        (
            (
                "3149b398b245e3ee92cdf8a81e53657d040742fdcce33eb90f57efd2fd90f9a3".to_string(),
                0,
            ),
            185_000,
        ),
        (
            (
                "56f48be32ca5768dc5e54c43835feffdea9f8459baed4d0b628dbd59eb0aa949".to_string(),
                0,
            ),
            235_000,
        ),
        (
            (
                "5055a9fff1e02227d7bd92a0a823b52af10a6b0d35fbf713041fd6892a0791a9".to_string(),
                0,
            ),
            100_000,
        ),
        (
            (
                "681a4c6872a4569e0779a84b4976e09299a6ebad42649b480e6b465c03cc21fb".to_string(),
                0,
            ),
            12_163_913,
        ),
        (
            (
                "c355f5cad162303b6606593e71e1221bcff2ab20226c21c9a812e09391ded484".to_string(),
                0,
            ),
            6_441_297,
        ),
        (
            (
                "d8f78db6b809139cd7074c58e0ebd6d655294be310acb8eb3fe3563123b3fc7d".to_string(),
                0,
            ),
            2_875_184,
        ),
        (
            (
                "5160f03c3d9c4362d25fafdfcaadca978c66af15b02f0c8e061a3177a61c6451".to_string(),
                0,
            ),
            5_303_655,
        ),
    ]
    .into_iter()
    .collect()
}

fn fee_of(hex: &str, height: u32, prevouts: &PrevoutValues) -> Option<u64> {
    transaction_fee(hex.trim(), height, Network::MainNetwork, prevouts)
        .expect("transaction_fee should succeed on a valid mainnet fixture")
}

/// The value entering the Orchard pool is not a fee. Counting it as one — which
/// is all the transparent bundle allows — inflates the fee by 10,000,000 zat.
#[test]
fn t2z_fee_excludes_the_value_that_entered_the_shielded_pool() {
    assert_eq!(
        fee_of(TX_T2Z_HEX, TX_T2Z_HEIGHT, &t2z_prevouts()),
        Some(55_000)
    );
}

/// A deshielding send has no transparent inputs at all, so the transparent
/// bundle on its own yields a negative balance. The Orchard value balance is
/// what makes the fee computable.
#[test]
fn z2t_fee_accounts_for_the_value_that_left_the_shielded_pool() {
    assert_eq!(
        fee_of(TX_Z2T_HEX, TX_Z2T_HEIGHT, &PrevoutValues::new()),
        Some(15_000)
    );
}

/// A transaction spending transparent inputs whose values were not supplied has
/// no computable fee. Reporting one anyway would mean reporting a wrong one.
#[test]
fn t2z_fee_is_unknown_without_the_prevout_values() {
    assert_eq!(
        fee_of(TX_T2Z_HEX, TX_T2Z_HEIGHT, &PrevoutValues::new()),
        None
    );
}

/// One missing prevout is enough to make the total unknowable — a partial sum
/// would silently understate the fee.
#[test]
fn t2z_fee_is_unknown_when_a_single_prevout_is_missing() {
    let mut prevouts = t2z_prevouts();
    prevouts.remove(&(
        "5160f03c3d9c4362d25fafdfcaadca978c66af15b02f0c8e061a3177a61c6451".to_string(),
        0,
    ));
    assert_eq!(fee_of(TX_T2Z_HEX, TX_T2Z_HEIGHT, &prevouts), None);
}

/// Prevouts are keyed by the big-endian txid shown in explorers, while the
/// outpoint stores it byte-reversed; keying by the raw internal order finds
/// nothing.
#[test]
fn prevouts_keyed_in_internal_byte_order_do_not_match() {
    let reversed: PrevoutValues = t2z_prevouts()
        .into_iter()
        .map(|((txid, index), value)| {
            let mut bytes = hex::decode(&txid).expect("fixture txids are valid hex");
            bytes.reverse();
            ((hex::encode(bytes), index), value)
        })
        .collect();
    assert_eq!(fee_of(TX_T2Z_HEX, TX_T2Z_HEIGHT, &reversed), None);
}
