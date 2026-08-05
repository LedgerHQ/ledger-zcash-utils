//! Protocol-level fee of a raw transaction.
//!
//! A transaction's fee is what remains once every pool is accounted for:
//! transparent inputs and outputs, plus the value balance of each shielded
//! bundle. Deriving it from the transparent bundle alone — as a Bitcoin-shaped
//! indexer does — counts the value entering the shielded pools as fee, and
//! misses the value leaving them.
//!
//! The transparent input values are not carried by the transaction itself, so
//! the caller must supply them. When one is missing the fee is reported as
//! unknown rather than guessed.

use std::collections::HashMap;
use std::io::Cursor;

use zcash_primitives::transaction::Transaction as ZcashTransaction;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    value::{BalanceError, Zatoshis},
};

use crate::error::Error;

/// Value of a transparent output being spent, keyed by the outpoint that
/// references it: `(txid in big-endian display hex, output index)`.
pub type PrevoutValues = HashMap<(String, u32), u64>;

/// Fee paid by `tx_hex`, in zatoshis.
///
/// Returns `Ok(None)` when a transparent input's value was not supplied — the
/// fee cannot be computed accurately without it, and a wrong figure is worse
/// than none.
///
/// # Errors
///
/// Returns [`Error::Decrypt`] if the hex is malformed or the transaction
/// cannot be parsed at the given block height.
pub fn transaction_fee(
    tx_hex: &str,
    height: u32,
    network: Network,
    prevouts: &PrevoutValues,
) -> Result<Option<u64>, Error> {
    let branch_id = BranchId::for_height(&network, BlockHeight::from(height));
    let tx_bytes =
        hex::decode(tx_hex).map_err(|e| Error::Decrypt(format!("hex decode failed: {:?}", e)))?;
    let tx = ZcashTransaction::read(&mut Cursor::new(tx_bytes), branch_id)
        .map_err(|e| Error::Decrypt(format!("TX parse failed: {:?}", e)))?;

    let fee = tx
        .into_data()
        .fee_paid(|outpoint| -> Result<Option<Zatoshis>, BalanceError> {
            let key = (display_txid(outpoint.hash()), outpoint.n());
            prevouts
                .get(&key)
                .copied()
                .map(Zatoshis::from_u64)
                .transpose()
        })
        .map_err(|e| Error::Decrypt(format!("fee computation failed: {:?}", e)))?;

    Ok(fee.map(|z| z.into_u64()))
}

/// Outpoints carry the txid in internal (little-endian) byte order; callers
/// key their prevouts by the big-endian hex shown in explorers.
fn display_txid(internal: &[u8; 32]) -> String {
    let mut bytes = *internal;
    bytes.reverse();
    hex::encode(bytes)
}
