//! Parse canonical PCZT bytes into a structured representation ready for the
//! Ledger device signer (`DmkSignerZcash.signPcztTransaction`).
//!
//! `craft::build_transaction` emits canonical PCZT bytes (`PCZT` magic + u32 LE
//! version + postcard payload). The device signer, however, consumes a fully
//! structured object (see `@ledgerhq/device-signer-kit-zcash`'s
//! `PcztTransaction`): the transparent inputs/outputs and every Orchard action
//! broken out field-by-field. The postcard payload is not trivially parseable in
//! TypeScript, so this module does it in Rust with `pczt::Pczt::parse` and
//! re-shapes the result into plain Rust structs that the FFI layer maps 1:1 to
//! the TypeScript `PcztTransaction`.
//!
//! ## Field sourcing
//!
//! Most fields come from the fully-typed protocol bundles exposed by the
//! `pczt` **Verifier** role (`orchard::pczt::Bundle` / `zcash_transparent::pczt::Bundle`),
//! whose getters mirror the conversions the `pczt` crate itself performs in
//! `serialize_from`. Three PCZT-global fields (`coin_type`, `fallback_lock_time`,
//! `tx_modifiable`) are kept `pub(crate)` by the `pczt` crate without a getter,
//! so they are read via serde (the global struct has no non-string map keys, so
//! `serde_json` round-trips cleanly).
//!
//! ## Signable-state requirement
//!
//! The device requires certain per-action / per-input fields to be present
//! (e.g. Orchard `alpha`, `rcv`, spend note components, each input's single
//! `bip32_derivation`). A freshly built PCZT retains all of them. If any is
//! absent this returns [`Error::Parse`] rather than emitting a half-populated
//! object the device would reject.

use std::collections::BTreeMap;

use ff::PrimeField;
use pczt::roles::verifier::{OrchardError, TransparentError, Verifier};
use pczt::Pczt;
use zcash_script::script::Evaluable;

use crate::error::Error;

/// A BIP-32 / ZIP-32 derivation entry (keyed by its controlling public key).
#[derive(Debug, Clone)]
pub struct ParsedBip32Derivation {
    /// Derivation path formatted for the device, without the `m/` prefix and
    /// with hardened indices suffixed by `'` (e.g. `44'/133'/0'/0/0`).
    pub signing_path: String,
    /// Compressed secp256k1 public key (33 bytes) — the map key in the PCZT.
    pub pubkey: [u8; 33],
    /// ZIP-32 seed fingerprint (32 bytes).
    pub seed_fingerprint: [u8; 32],
}

/// The PCZT global (`common::Global`) fields the device header consumes.
#[derive(Debug, Clone)]
pub struct ParsedGlobal {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    /// `None` encodes the absent optional lock time.
    pub fallback_lock_time: Option<u32>,
    pub expiry_height: u32,
    /// SLIP-44 coin type (133 mainnet, 1 testnet).
    pub coin_type: u32,
    pub tx_modifiable: u8,
}

/// A single transparent input.
#[derive(Debug, Clone)]
pub struct ParsedTransparentInput {
    pub prevout_txid: [u8; 32],
    pub prevout_index: u32,
    /// `None` encodes the absent optional sequence number (final `0xffffffff`).
    pub sequence: Option<u32>,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub sighash_type: u8,
    pub derivation: ParsedBip32Derivation,
}

/// A single transparent output.
#[derive(Debug, Clone)]
pub struct ParsedTransparentOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    /// Present only for change outputs the wallet controls.
    pub derivation: Option<ParsedBip32Derivation>,
}

/// A single Orchard action (spend + output halves), flattened for the device.
#[derive(Debug, Clone)]
pub struct ParsedOrchardAction {
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub spend_recipient: [u8; 43],
    pub spend_value: u64,
    pub spend_rho: [u8; 32],
    pub spend_rseed: [u8; 32],
    pub alpha: [u8; 32],
    pub signing_path: String,
    pub seed_fingerprint: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub recipient: [u8; 43],
    pub value: u64,
    pub rseed: [u8; 32],
    pub rcv: [u8; 32],
}

/// The Orchard action bundle plus its trailing bundle-level fields.
#[derive(Debug, Clone)]
pub struct ParsedOrchardBundle {
    pub actions: Vec<ParsedOrchardAction>,
    pub flags: u8,
    /// Net value balance in zatoshis (spends − outputs), signed.
    pub value_balance: i128,
    pub anchor: [u8; 32],
}

/// A fully structured PCZT ready for the device signer.
#[derive(Debug, Clone)]
pub struct ParsedPczt {
    pub global: ParsedGlobal,
    pub transparent_inputs: Vec<ParsedTransparentInput>,
    pub transparent_outputs: Vec<ParsedTransparentOutput>,
    /// `None` when the transaction has no Orchard actions.
    pub orchard_bundle: Option<ParsedOrchardBundle>,
}

/// Parse canonical PCZT bytes (`PCZT` magic + u32 LE version + postcard payload)
/// into a [`ParsedPczt`].
pub fn parse_pczt(bytes: &[u8]) -> Result<ParsedPczt, Error> {
    let pczt = Pczt::parse(bytes).map_err(|e| Error::Parse(format!("PCZT parse failed: {e:?}")))?;

    // Read the global fields before the pczt is moved into the Verifier.
    let global = parse_global(&pczt)?;

    let mut transparent_inputs = Vec::new();
    let mut transparent_outputs = Vec::new();
    let mut orchard_bundle = None;

    // The Verifier role parses the protocol-specific bundles into their fully
    // typed forms and lends them read-only inside a closure.
    let verifier = Verifier::new(pczt)
        .with_transparent::<String, _>(|bundle| {
            for input in bundle.inputs() {
                transparent_inputs
                    .push(convert_transparent_input(input).map_err(TransparentError::Custom)?);
            }
            for output in bundle.outputs() {
                transparent_outputs
                    .push(convert_transparent_output(output).map_err(TransparentError::Custom)?);
            }
            Ok(())
        })
        .map_err(map_transparent_err)?;

    verifier
        .with_orchard::<String, _>(|bundle| {
            orchard_bundle = convert_orchard_bundle(bundle).map_err(OrchardError::Custom)?;
            Ok(())
        })
        .map_err(map_orchard_err)?;

    Ok(ParsedPczt {
        global,
        transparent_inputs,
        transparent_outputs,
        orchard_bundle,
    })
}

// ─── global ────────────────────────────────────────────────────────────────

fn parse_global(pczt: &Pczt) -> Result<ParsedGlobal, Error> {
    let global = pczt.global();

    // `coin_type`, `fallback_lock_time` and `tx_modifiable` have no public
    // getter; read them by name from the serde representation. `Global` has no
    // non-string map keys, so serde_json round-trips without error.
    let json = serde_json::to_value(global)
        .map_err(|e| Error::Parse(format!("global serialize failed: {e}")))?;

    let coin_type = json
        .get("coin_type")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::Parse("global.coin_type missing".into()))? as u32;

    let tx_modifiable = json
        .get("tx_modifiable")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::Parse("global.tx_modifiable missing".into()))?
        as u8;

    let fallback_lock_time = match json.get("fallback_lock_time") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| Error::Parse("global.fallback_lock_time invalid".into()))?
                as u32,
        ),
    };

    Ok(ParsedGlobal {
        tx_version: *global.tx_version(),
        version_group_id: *global.version_group_id(),
        consensus_branch_id: *global.consensus_branch_id(),
        fallback_lock_time,
        expiry_height: *global.expiry_height(),
        coin_type,
        tx_modifiable,
    })
}

// ─── transparent ─────────────────────────────────────────────────────────────

fn convert_transparent_input(
    input: &zcash_transparent::pczt::Input,
) -> Result<ParsedTransparentInput, String> {
    // The device signs exactly one key per transparent input, so the PCZT must
    // carry exactly one `bip32_derivation` entry.
    let derivation = single_derivation(input.bip32_derivation())?
        .ok_or_else(|| "transparent input requires exactly one bip32_derivation".to_string())?;

    Ok(ParsedTransparentInput {
        prevout_txid: (*input.prevout_txid()).into(),
        prevout_index: *input.prevout_index(),
        sequence: *input.sequence(),
        value: input.value().into_u64(),
        script_pubkey: input.script_pubkey().to_bytes(),
        sighash_type: input.sighash_type().encode(),
        derivation,
    })
}

fn convert_transparent_output(
    output: &zcash_transparent::pczt::Output,
) -> Result<ParsedTransparentOutput, String> {
    Ok(ParsedTransparentOutput {
        value: output.value().into_u64(),
        script_pubkey: output.script_pubkey().to_bytes(),
        derivation: single_derivation(output.bip32_derivation())?,
    })
}

/// Extracts a single `bip32_derivation` entry (or `None` for an empty map).
/// Errors if the map has more than one entry, which the device cannot represent.
fn single_derivation(
    map: &BTreeMap<[u8; 33], zcash_transparent::pczt::Bip32Derivation>,
) -> Result<Option<ParsedBip32Derivation>, String> {
    match map.len() {
        0 => Ok(None),
        1 => {
            let (pubkey, deriv) = map.iter().next().expect("len == 1");
            Ok(Some(ParsedBip32Derivation {
                signing_path: format_derivation_path(
                    deriv.derivation_path().iter().copied().map(u32::from),
                ),
                pubkey: *pubkey,
                seed_fingerprint: *deriv.seed_fingerprint(),
            }))
        }
        n => Err(format!(
            "expected 0 or 1 bip32_derivation entries, found {n}"
        )),
    }
}

// ─── orchard ─────────────────────────────────────────────────────────────────

fn convert_orchard_bundle(
    bundle: &orchard::pczt::Bundle,
) -> Result<Option<ParsedOrchardBundle>, String> {
    if bundle.actions().is_empty() {
        return Ok(None);
    }

    let mut actions = Vec::with_capacity(bundle.actions().len());
    for action in bundle.actions() {
        actions.push(convert_orchard_action(action)?);
    }

    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let value_balance = if matches!(sign, orchard::value::Sign::Negative) {
        -(magnitude as i128)
    } else {
        magnitude as i128
    };

    Ok(Some(ParsedOrchardBundle {
        actions,
        flags: bundle.flags().to_byte(),
        value_balance,
        anchor: bundle.anchor().to_bytes(),
    }))
}

fn convert_orchard_action(
    action: &orchard::pczt::Action,
) -> Result<ParsedOrchardAction, String> {
    let spend = action.spend();
    let output = action.output();

    let rk: [u8; 32] = spend.rk().into();

    let spend_recipient = spend
        .recipient()
        .map(|r| r.to_raw_address_bytes())
        .ok_or("orchard spend missing recipient")?;
    let spend_value = spend
        .value()
        .map(|v| v.inner())
        .ok_or("orchard spend missing value")?;
    let spend_rho = spend
        .rho()
        .map(|r| r.to_bytes())
        .ok_or("orchard spend missing rho")?;
    let spend_rseed = spend
        .rseed()
        .map(|r| *r.as_bytes())
        .ok_or("orchard spend missing rseed")?;
    let alpha = spend
        .alpha()
        .map(|a| a.to_repr())
        .ok_or("orchard spend missing alpha")?;

    let zip32 = spend
        .zip32_derivation()
        .as_ref()
        .ok_or("orchard spend missing zip32_derivation")?;
    let signing_path =
        format_derivation_path(zip32.derivation_path().iter().map(|c| c.index()));
    let seed_fingerprint = *zip32.seed_fingerprint();

    let note = output.encrypted_note();

    let recipient = output
        .recipient()
        .map(|r| r.to_raw_address_bytes())
        .ok_or("orchard output missing recipient")?;
    let value = output
        .value()
        .map(|v| v.inner())
        .ok_or("orchard output missing value")?;
    let rseed = output
        .rseed()
        .map(|r| *r.as_bytes())
        .ok_or("orchard output missing rseed")?;

    let rcv = action
        .rcv()
        .as_ref()
        .map(|r| r.to_bytes())
        .ok_or("orchard action missing rcv")?;

    Ok(ParsedOrchardAction {
        cv_net: action.cv_net().to_bytes(),
        nullifier: spend.nullifier().to_bytes(),
        rk,
        spend_recipient,
        spend_value,
        spend_rho,
        spend_rseed,
        alpha,
        signing_path,
        seed_fingerprint,
        cmx: output.cmx().to_bytes(),
        ephemeral_key: note.epk_bytes,
        enc_ciphertext: note.enc_ciphertext.to_vec(),
        out_ciphertext: note.out_ciphertext.to_vec(),
        recipient,
        value,
        rseed,
        rcv,
    })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Formats a sequence of raw ZIP-32/BIP-32 indices (hardened bit in bit 31) as
/// the device's path string: no `m/` prefix, hardened indices suffixed with `'`.
fn format_derivation_path(indices: impl Iterator<Item = u32>) -> String {
    indices
        .map(|i| {
            if i & 0x8000_0000 != 0 {
                format!("{}'", i & 0x7fff_ffff)
            } else {
                i.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn map_transparent_err(e: TransparentError<String>) -> Error {
    match e {
        TransparentError::Custom(msg) => Error::Parse(msg),
        other => Error::Parse(format!("transparent bundle: {other:?}")),
    }
}

fn map_orchard_err(e: OrchardError<String>) -> Error {
    match e {
        OrchardError::Custom(msg) => Error::Parse(msg),
        other => Error::Parse(format!("orchard bundle: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pczt_rejects_too_short_input() {
        let err = parse_pczt(b"PCZT").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn parse_pczt_rejects_bad_magic() {
        let mut bytes = vec![0u8; 16];
        bytes[..4].copy_from_slice(b"NOPE");
        let err = parse_pczt(&bytes).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn parse_pczt_rejects_valid_magic_but_garbage_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PCZT");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0xffu8; 32]);
        let err = parse_pczt(&bytes).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn format_derivation_path_marks_hardened_indices() {
        let path = format_derivation_path(
            [0x8000_0000 + 44, 0x8000_0000 + 133, 0x8000_0000, 0, 0].into_iter(),
        );
        assert_eq!(path, "44'/133'/0'/0/0");
    }

    #[test]
    fn format_derivation_path_all_hardened() {
        let path =
            format_derivation_path([0x8000_0000 + 44, 0x8000_0000 + 133, 0x8000_0000].into_iter());
        assert_eq!(path, "44'/133'/0'");
    }
}
