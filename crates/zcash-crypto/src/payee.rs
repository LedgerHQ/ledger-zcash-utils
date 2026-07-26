//! Where a shielded payment went.
//!
//! A shielded output names its recipient only inside the encrypted note, so a
//! transaction reveals nothing about its payee to an observer — including to
//! the sender's own explorer. What an explorer reports as the destination of a
//! transparent-to-shielded send is therefore the transparent change output,
//! which pays the sender back rather than the payee.
//!
//! The sender can still recover the payee, because the transaction was built
//! with the account's outgoing viewing key: trial-decrypting the outputs with
//! it yields the notes we created, and each note names who it pays.
//!
//! The recovered address is the Orchard receiver itself, re-encoded as a
//! unified address. When the payee was given as a unified address bundling
//! several receivers, this is the same destination but not the same string.

use sapling_crypto::PaymentAddress;
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::consensus::Network;

use crate::decrypt::full_decrypt_tx;
use crate::error::Error;

/// Addresses paid by the shielded outputs `ufvk` created in `tx_hex`, in bundle
/// order.
///
/// Empty when the transaction has no shielded output of ours — either it is not
/// ours, or it only pays us (notes paying us are not payees).
///
/// # Errors
///
/// Returns [`Error::Decrypt`] if the hex is malformed, the transaction cannot be
/// parsed at the given block height, or the viewing key cannot be decoded.
pub fn outgoing_payees(
    tx_hex: &str,
    ufvk: &str,
    height: u32,
    network: Network,
) -> Result<Vec<String>, Error> {
    let decrypted = full_decrypt_tx(tx_hex, ufvk, height, network)?;

    let orchard = decrypted
        .orchard_outputs
        .iter()
        .chain(decrypted.ironwood_outputs.iter())
        .filter(|output| output.transfer_type == "outgoing")
        .filter_map(|output| output.recipient)
        .filter_map(|bytes| encode_orchard_receiver(&bytes, network));

    let sapling = decrypted
        .sapling_outputs
        .iter()
        .filter(|output| output.transfer_type == "outgoing")
        .filter_map(|output| output.recipient)
        .filter_map(|bytes| encode_sapling_receiver(&bytes, network));

    Ok(orchard.chain(sapling).collect())
}

/// Encodes raw Orchard receiver bytes as a unified address. Returns `None` if
/// the bytes are not a valid Orchard address, which can only happen if the
/// decryption that produced them was itself unsound.
fn encode_orchard_receiver(bytes: &[u8; 43], network: Network) -> Option<String> {
    let address = orchard::Address::from_raw_address_bytes(bytes).into_option()?;
    UnifiedAddress::from_receivers(Some(address), None, None).map(|ua| ua.encode(&network))
}

/// Encodes raw Sapling receiver bytes as a `zs`-prefixed address.
fn encode_sapling_receiver(bytes: &[u8; 43], network: Network) -> Option<String> {
    PaymentAddress::from_bytes(bytes).map(|address| Address::Sapling(address).encode(&network))
}
