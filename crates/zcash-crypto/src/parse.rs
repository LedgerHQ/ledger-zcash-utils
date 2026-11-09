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
use orchard::bundle::BundleVersion;
use orchard::note::NoteVersion;
use orchard::ValuePool;
use pczt::roles::verifier::{OrchardError, TransparentError, Verifier};
use pczt::Pczt;
use zcash_address::unified::{
    Address as UnifiedAddress, Container as _, Encoding as _, Receiver as UnifiedReceiver,
};
use zcash_keys::address::Address as ZcashAddress;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_protocol::consensus::{BranchId, Network, NetworkType};
use zcash_script::script::Evaluable;
use zcash_transparent::address::TransparentAddress;

use crate::error::Error;

/// The transaction version that introduces the Ironwood pool (NU6.3).
const V6_TX_VERSION: u32 = 6;

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

/// One receiver of a unified address, as the device shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReceiver {
    /// ZIP 316 typecode: P2PKH `0x00`, P2SH `0x01`, Sapling `0x02`, Orchard `0x03`.
    pub typecode: u8,
    /// Raw receiver bytes.
    pub receiver: Vec<u8>,
}

/// A single transparent output.
#[derive(Debug, Clone)]
pub struct ParsedTransparentOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    /// Present only for change outputs the wallet controls.
    pub derivation: Option<ParsedBip32Derivation>,
    /// The address the user entered (ZIP 374 `user_address`), when recorded.
    pub user_address: Option<String>,
    /// The receivers of `user_address` other than the one this output pays, in
    /// ascending typecode order. `None` when no address was recorded or it holds
    /// a receiver of a type this crate does not know.
    pub user_address_receivers: Option<Vec<ParsedReceiver>>,
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
    /// The address the user entered (ZIP 374 `user_address`), when recorded.
    pub user_address: Option<String>,
    /// The receivers of `user_address` other than the Orchard `recipient`, in
    /// ascending typecode order. `None` when no address was recorded or it holds
    /// a receiver of a type this crate does not know.
    pub user_address_receivers: Option<Vec<ParsedReceiver>>,
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

/// A single Ironwood action (NU6.3, V6 transactions only).
///
/// An Ironwood action *is* an Orchard action plus the PCZT v2 note-plaintext
/// lead byte, so it composes [`ParsedOrchardAction`] rather than repeating its
/// eighteen fields: the device's Ironwood wire format mirrors `orchard::Action`
/// with `note_plaintext_version` appended (`PcztIronwoodAction` in
/// `@ledgerhq/device-signer-kit-zcash`). Composing keeps the two shapes from
/// drifting when a field is added to the Orchard action.
#[derive(Debug, Clone)]
pub struct ParsedIronwoodAction {
    /// The Orchard-shaped body of the action.
    pub action: ParsedOrchardAction,
    /// Note-plaintext lead byte (`0x03` for the ZIP 2005 Ironwood format).
    pub note_plaintext_version: u8,
}

/// The Ironwood action bundle plus its trailing bundle-level fields.
#[derive(Debug, Clone)]
pub struct ParsedIronwoodBundle {
    pub actions: Vec<ParsedIronwoodAction>,
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
    /// `None` when the transaction has no Ironwood actions, which is always the
    /// case below transaction version 6 — the Ironwood pool is V6-only.
    pub ironwood_bundle: Option<ParsedIronwoodBundle>,
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
    let mut ironwood_bundle = None;

    let branch = BranchId::try_from(global.consensus_branch_id).map_err(|_| {
        Error::Parse(format!(
            "unrecognized consensus branch id {:#010x}",
            global.consensus_branch_id
        ))
    })?;

    // The Verifier role parses the protocol-specific bundles into their fully
    // typed forms and lends them read-only inside a closure.
    let verifier = Verifier::new(pczt)
        .with_transparent::<String, _>(|bundle| {
            for input in bundle.inputs() {
                transparent_inputs
                    .push(convert_transparent_input(input).map_err(TransparentError::Custom)?);
            }
            for output in bundle.outputs() {
                transparent_outputs.push(
                    convert_transparent_output(output, global.coin_type)
                        .map_err(TransparentError::Custom)?,
                );
            }
            Ok(())
        })
        .map_err(map_transparent_err)?;

    let verifier = verifier
        .with_orchard::<String, _>(|bundle| {
            orchard_bundle =
                convert_orchard_bundle(bundle, branch, ValuePool::Orchard, global.coin_type)
                    .map_err(OrchardError::Custom)?;
            Ok(())
        })
        .map_err(map_orchard_err)?;

    // The Ironwood pool exists only from V6. Below that the PCZT's Ironwood
    // section is the canonical empty bundle, and asking the Verifier to parse it
    // under a pre-NU6.3 anchor requirement would be meaningless work on every
    // V5 (Orchard) transaction — so leave it untouched and report `None`.
    if global.tx_version >= V6_TX_VERSION {
        verifier
            .with_ironwood::<String, _>(|bundle| {
                ironwood_bundle = convert_ironwood_bundle(bundle, branch, global.coin_type)
                    .map_err(OrchardError::Custom)?;
                Ok(())
            })
            .map_err(map_ironwood_err)?;
    }

    Ok(ParsedPczt {
        global,
        transparent_inputs,
        transparent_outputs,
        orchard_bundle,
        ironwood_bundle,
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

    let tx_modifiable =
        json.get("tx_modifiable")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Error::Parse("global.tx_modifiable missing".into()))? as u8;

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
    coin_type: u32,
) -> Result<ParsedTransparentOutput, String> {
    let script_pubkey = output.script_pubkey().to_bytes();
    let user_address = output.user_address().clone();
    let user_address_receivers = match &user_address {
        Some(address) => {
            let paid = paid_transparent_receiver(&script_pubkey)
                .ok_or("transparent output with a user_address pays a non-standard script")?;
            user_address_receivers(address, &paid, coin_type)?
        }
        None => None,
    };
    Ok(ParsedTransparentOutput {
        value: output.value().into_u64(),
        script_pubkey,
        derivation: single_derivation(output.bip32_derivation())?,
        user_address,
        user_address_receivers,
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

/// The bundle version in force for `pool` on `branch`.
///
/// The flags byte is only representable against the right version — the Orchard
/// pool flips `cross_address_enabled` at NU6.3, and the Ironwood pool encodes it
/// in its own bit — so the version cannot be hardcoded. This follows the epoch
/// the bundle is mined in rather than the transaction version, the same rule
/// (and the same upstream function) as [`crate::circuit`].
fn bundle_version_for(branch: BranchId, pool: ValuePool) -> Result<BundleVersion, String> {
    bundle_version_for_branch(branch, pool)
        .ok_or_else(|| format!("no {pool:?} bundle version for branch {branch:?}"))
}

fn convert_orchard_bundle(
    bundle: &orchard::pczt::Bundle,
    branch: BranchId,
    pool: ValuePool,
    coin_type: u32,
) -> Result<Option<ParsedOrchardBundle>, String> {
    if bundle.actions().is_empty() {
        return Ok(None);
    }

    let bundle_version = bundle_version_for(branch, pool)?;

    let mut actions = Vec::with_capacity(bundle.actions().len());
    for action in bundle.actions() {
        actions.push(convert_orchard_action(action, coin_type)?);
    }

    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let value_balance = if matches!(sign, orchard::value::Sign::Negative) {
        -(magnitude as i128)
    } else {
        magnitude as i128
    };

    Ok(Some(ParsedOrchardBundle {
        actions,
        flags: bundle.flags().to_byte(bundle_version).ok_or_else(|| {
            format!("bundle flags not representable for bundle version {bundle_version:?}")
        })?,
        value_balance,
        anchor: bundle.anchor().to_bytes(),
    }))
}

/// Converts the PCZT's Ironwood section, which the `pczt` crate exposes as the
/// same [`orchard::pczt::Bundle`] type as the Orchard section.
///
/// The two differ only in the bundle version used to encode the flags byte and
/// in the per-action note-plaintext lead byte the device needs for PCZT v2, so
/// this reuses [`convert_orchard_bundle`] for the shared body.
fn convert_ironwood_bundle(
    bundle: &orchard::pczt::Bundle,
    branch: BranchId,
    coin_type: u32,
) -> Result<Option<ParsedIronwoodBundle>, String> {
    let Some(orchard_shaped) =
        convert_orchard_bundle(bundle, branch, ValuePool::Ironwood, coin_type)?
    else {
        return Ok(None);
    };

    // Every action in a bundle carries the note version of the bundle itself;
    // `orchard`'s parser rejects a PCZT whose actions disagree with it, so the
    // bundle version is the authoritative source for the lead byte.
    let note_plaintext_version =
        note_plaintext_lead_byte(bundle_version_for(branch, ValuePool::Ironwood)?.note_version());

    Ok(Some(ParsedIronwoodBundle {
        actions: orchard_shaped
            .actions
            .into_iter()
            .map(|action| ParsedIronwoodAction {
                action,
                note_plaintext_version,
            })
            .collect(),
        flags: orchard_shaped.flags,
        value_balance: orchard_shaped.value_balance,
        anchor: orchard_shaped.anchor,
    }))
}

/// The note-plaintext lead byte signalling `version`.
///
/// `orchard` keeps its own `NoteVersion::lead_byte` crate-private, so the
/// mapping is restated here against the values the variants document: ZIP 212
/// (`0x02`) and ZIP 2005 (`0x03`).
fn note_plaintext_lead_byte(version: NoteVersion) -> u8 {
    match version {
        NoteVersion::V2 => 0x02,
        NoteVersion::V3 => 0x03,
    }
}

fn convert_orchard_action(
    action: &orchard::pczt::Action,
    coin_type: u32,
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
    let signing_path = format_derivation_path(zip32.derivation_path().iter().map(|c| c.index()));
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

    let user_address = output.user_address().clone();
    let user_address_receivers = match &user_address {
        Some(address) => {
            user_address_receivers(address, &PaidReceiver::Orchard(recipient), coin_type)?
        }
        None => None,
    };

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
        enc_ciphertext: note.enc_ciphertext.0.to_vec(),
        out_ciphertext: note.out_ciphertext.to_vec(),
        recipient,
        value,
        rseed,
        rcv,
        user_address,
        user_address_receivers,
    })
}

// ─── user address ────────────────────────────────────────────────────────────

/// The receiver an output pays, which its `user_address` must contain.
enum PaidReceiver {
    Orchard([u8; 43]),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

/// Reads the receiver a standard transparent `script_pubkey` pays: P2PKH
/// (`OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`) or P2SH
/// (`OP_HASH160 <20> OP_EQUAL`).
fn paid_transparent_receiver(script: &[u8]) -> Option<PaidReceiver> {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            Some(PaidReceiver::P2pkh(hash.try_into().ok()?))
        }
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            Some(PaidReceiver::P2sh(hash.try_into().ok()?))
        }
        _ => None,
    }
}

/// Checks an output's `user_address` against the receiver it pays and returns
/// its other receivers.
///
/// A Signer must confirm that the address contains the paid receiver (ZIP 374),
/// so a mismatch is an error. The list is `None` when the address holds a
/// receiver of an unknown type, since the device cannot show what it cannot
/// describe, and `Some(vec![])` when the paid receiver is the only one. A plain
/// transparent address equal to the paid one is accepted, with no list: ZIP 374
/// allows any address encoding here, even though this library's builder only ever
/// records unified addresses.
fn user_address_receivers(
    user_address: &str,
    paid: &PaidReceiver,
    coin_type: u32,
) -> Result<Option<Vec<ParsedReceiver>>, String> {
    let (network, _, unified) = match UnifiedAddress::decode(user_address) {
        Ok(decoded) => decoded,
        // A string with a unified address prefix is a malformed unified address:
        // report why it failed rather than comparing it to the transparent one.
        Err(e) if has_unified_address_prefix(user_address) => {
            return Err(format!("user_address is not a valid unified address: {e}"));
        }
        Err(_) => {
            return check_plain_transparent_address(user_address, paid, coin_type).map(|()| None)
        }
    };

    let expected_coin_type = match network {
        NetworkType::Main => 133,
        NetworkType::Test | NetworkType::Regtest => 1,
    };
    if coin_type != expected_coin_type {
        return Err(format!(
            "user_address is for another network than coin type {coin_type}"
        ));
    }

    let paid_receiver = match paid {
        PaidReceiver::Orchard(bytes) => UnifiedReceiver::Orchard(*bytes),
        PaidReceiver::P2pkh(hash) => UnifiedReceiver::P2pkh(*hash),
        PaidReceiver::P2sh(hash) => UnifiedReceiver::P2sh(*hash),
    };
    if !unified.contains_receiver(&paid_receiver) {
        return Err("user_address does not contain the receiver this output pays".to_string());
    }

    let mut others = Vec::new();
    for receiver in unified.items() {
        if receiver == paid_receiver {
            continue;
        }
        others.push(match receiver {
            UnifiedReceiver::P2pkh(h) => ParsedReceiver {
                typecode: 0x00,
                receiver: h.to_vec(),
            },
            UnifiedReceiver::P2sh(h) => ParsedReceiver {
                typecode: 0x01,
                receiver: h.to_vec(),
            },
            UnifiedReceiver::Sapling(b) => ParsedReceiver {
                typecode: 0x02,
                receiver: b.to_vec(),
            },
            UnifiedReceiver::Orchard(b) => ParsedReceiver {
                typecode: 0x03,
                receiver: b.to_vec(),
            },
            UnifiedReceiver::Unknown { .. } => return Ok(None),
        });
    }
    others.sort_by_key(|r| r.typecode);
    Ok(Some(others))
}

/// Whether `address` starts with the human-readable part of a unified address
/// (any revision, any network) followed by the Bech32m `1` separator. No
/// transparent address starts that way: their Base58Check prefixes are `t1`,
/// `t3`, `tm` and `t2`.
fn has_unified_address_prefix(address: &str) -> bool {
    use zcash_address::constants::{mainnet, regtest, testnet};

    [
        mainnet::HRP_UNIFIED_ADDRESS,
        mainnet::HRP_UNIFIED_ADDRESS_R2,
        mainnet::HRP_UNIFIED_ADDRESS_R2_TI,
        testnet::HRP_UNIFIED_ADDRESS,
        testnet::HRP_UNIFIED_ADDRESS_R2,
        testnet::HRP_UNIFIED_ADDRESS_R2_TI,
        regtest::HRP_UNIFIED_ADDRESS,
        regtest::HRP_UNIFIED_ADDRESS_R2,
        regtest::HRP_UNIFIED_ADDRESS_R2_TI,
    ]
    .iter()
    .any(|hrp| {
        address
            .strip_prefix(hrp)
            .is_some_and(|rest| rest.starts_with('1'))
    })
}

/// A `user_address` that is not a unified address must be the plain transparent
/// address the output pays.
fn check_plain_transparent_address(
    user_address: &str,
    paid: &PaidReceiver,
    coin_type: u32,
) -> Result<(), String> {
    let params = if coin_type == 133 {
        Network::MainNetwork
    } else {
        Network::TestNetwork
    };
    let paid_address = match paid {
        PaidReceiver::P2pkh(hash) => Some(TransparentAddress::PublicKeyHash(*hash)),
        PaidReceiver::P2sh(hash) => Some(TransparentAddress::ScriptHash(*hash)),
        PaidReceiver::Orchard(_) => None,
    };
    match (ZcashAddress::decode(&params, user_address), paid_address) {
        (Some(ZcashAddress::Transparent(decoded)), Some(paid)) if decoded == paid => Ok(()),
        _ => Err(
            "user_address is neither a unified address nor the paid transparent address"
                .to_string(),
        ),
    }
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

/// As [`map_orchard_err`], but labelled for the Ironwood section — both sections
/// are parsed through the same `orchard` machinery and so share its error type.
fn map_ironwood_err(e: OrchardError<String>) -> Error {
    match e {
        OrchardError::Custom(msg) => Error::Parse(msg),
        other => Error::Parse(format!("ironwood bundle: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags byte is only representable against the pool's own bundle
    /// version: the Orchard pool disables cross-address transfers at NU6.3 and
    /// the Ironwood pool carries the choice in its own bit, so a hardcoded
    /// version would make `to_byte` return `None` for one of them.
    #[test]
    fn bundle_version_tracks_the_pool_and_the_branch() {
        let orchard_v2 = bundle_version_for(BranchId::Nu6_2, ValuePool::Orchard)
            .expect("the Orchard pool exists at NU6.2");
        assert_eq!(orchard_v2, BundleVersion::orchard_v2());

        let orchard_v3 = bundle_version_for(BranchId::Nu6_3, ValuePool::Orchard)
            .expect("the Orchard pool exists at NU6.3");
        assert_eq!(
            orchard_v3,
            BundleVersion::orchard_v3(),
            "past NU6.3 the Orchard bundle is v3, not v2"
        );

        let ironwood = bundle_version_for(BranchId::Nu6_3, ValuePool::Ironwood)
            .expect("the Ironwood pool is introduced at NU6.3");
        assert_eq!(ironwood, BundleVersion::ironwood_v3());
    }

    /// The Ironwood pool does not exist before NU6.3, so asking for its bundle
    /// version on an earlier branch must fail loudly rather than fall back to a
    /// version whose flags encoding would be wrong.
    #[test]
    fn ironwood_has_no_bundle_version_before_nu6_3() {
        for branch in [
            BranchId::Nu5,
            BranchId::Nu6,
            BranchId::Nu6_1,
            BranchId::Nu6_2,
        ] {
            assert!(
                bundle_version_for(branch, ValuePool::Ironwood).is_err(),
                "{branch:?} predates the Ironwood pool"
            );
        }
    }

    /// The device needs the note-plaintext lead byte to parse a PCZT v2 note.
    /// `orchard` keeps its own mapping crate-private, so this pins ours to the
    /// values the `NoteVersion` variants document (ZIP 212 / ZIP 2005).
    #[test]
    fn note_plaintext_lead_bytes_match_their_zips() {
        assert_eq!(note_plaintext_lead_byte(NoteVersion::V2), 0x02);
        assert_eq!(note_plaintext_lead_byte(NoteVersion::V3), 0x03);
    }

    /// The Ironwood pool uses V3 note plaintexts; the byte the device receives
    /// follows from the bundle version rather than being hardcoded at the call
    /// site.
    #[test]
    fn ironwood_bundle_version_selects_the_v3_note_plaintext() {
        let ironwood = bundle_version_for(BranchId::Nu6_3, ValuePool::Ironwood)
            .expect("the Ironwood pool is introduced at NU6.3");
        assert_eq!(
            note_plaintext_lead_byte(ironwood.note_version()),
            0x03,
            "Ironwood notes are ZIP 2005 (V3) plaintexts"
        );

        let orchard = bundle_version_for(BranchId::Nu6_3, ValuePool::Orchard)
            .expect("the Orchard pool exists at NU6.3");
        assert_eq!(
            note_plaintext_lead_byte(orchard.note_version()),
            0x02,
            "the Orchard pool keeps ZIP 212 (V2) plaintexts even at NU6.3"
        );
    }

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

    // ── user address ──────────────────────────────────────────────────────────

    fn ua(items: Vec<UnifiedReceiver>, network: NetworkType) -> String {
        use zcash_address::unified::{Revision, Uitem};
        UnifiedAddress::try_from_items(Revision::R0, items.into_iter().map(Uitem::Data).collect())
            .expect("valid unified address")
            .encode(&network)
    }

    #[test]
    fn user_address_receivers_lists_the_others_in_typecode_order() {
        let address = ua(
            vec![
                UnifiedReceiver::Orchard([0x03; 43]),
                UnifiedReceiver::Sapling([0x02; 43]),
                UnifiedReceiver::P2pkh([0x00; 20]),
            ],
            NetworkType::Main,
        );

        let receivers = user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133)
            .expect("accepted")
            .expect("known receivers only");

        assert_eq!(
            receivers,
            vec![
                ParsedReceiver {
                    typecode: 0x00,
                    receiver: vec![0x00; 20]
                },
                ParsedReceiver {
                    typecode: 0x02,
                    receiver: vec![0x02; 43]
                },
            ]
        );
    }

    #[test]
    fn user_address_receivers_for_a_transparent_payment_lists_sapling_and_orchard() {
        let address = ua(
            vec![
                UnifiedReceiver::Orchard([0x03; 43]),
                UnifiedReceiver::P2sh([0x01; 20]),
            ],
            NetworkType::Test,
        );

        let receivers = user_address_receivers(&address, &PaidReceiver::P2sh([0x01; 20]), 1)
            .expect("accepted")
            .expect("known receivers only");

        assert_eq!(receivers.len(), 1);
        assert_eq!(receivers[0].typecode, 0x03);
    }

    #[test]
    fn user_address_receivers_is_empty_for_an_orchard_only_address() {
        let address = ua(
            vec![UnifiedReceiver::Orchard([0x03; 43])],
            NetworkType::Main,
        );
        let receivers = user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133)
            .expect("accepted");
        assert_eq!(receivers, Some(vec![]));
    }

    #[test]
    fn user_address_receivers_rejects_an_address_without_the_paid_receiver() {
        let address = ua(
            vec![UnifiedReceiver::Orchard([0x04; 43])],
            NetworkType::Main,
        );
        let err =
            user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133).unwrap_err();
        assert!(err.contains("does not contain"), "got: {err}");
    }

    #[test]
    fn user_address_receivers_rejects_the_wrong_network() {
        let address = ua(
            vec![UnifiedReceiver::Orchard([0x03; 43])],
            NetworkType::Test,
        );
        let err =
            user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133).unwrap_err();
        assert!(err.contains("another network"), "got: {err}");
    }

    #[test]
    fn user_address_receivers_is_none_when_a_receiver_type_is_unknown() {
        let address = ua(
            vec![
                UnifiedReceiver::Orchard([0x03; 43]),
                UnifiedReceiver::Unknown {
                    typecode: 0x42,
                    data: vec![1, 2, 3],
                },
            ],
            NetworkType::Main,
        );
        let receivers = user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133)
            .expect("an unknown receiver is still accepted");
        assert_eq!(receivers, None);
    }

    #[test]
    fn user_address_receivers_accepts_the_paid_plain_transparent_address() {
        // The P2PKH t-address of hash [0x11; 20] on mainnet.
        let t_addr = zcash_keys::address::Address::Transparent(TransparentAddress::PublicKeyHash(
            [0x11; 20],
        ))
        .encode(&Network::MainNetwork);

        let accepted = user_address_receivers(&t_addr, &PaidReceiver::P2pkh([0x11; 20]), 133)
            .expect("the paid address is accepted");
        assert_eq!(accepted, None);

        let err =
            user_address_receivers(&t_addr, &PaidReceiver::P2pkh([0x12; 20]), 133).unwrap_err();
        assert!(err.contains("neither a unified address"), "got: {err}");
    }

    #[test]
    fn user_address_receivers_reports_why_a_malformed_unified_address_fails() {
        let mut address = ua(
            vec![UnifiedReceiver::Orchard([0x03; 43])],
            NetworkType::Main,
        );
        // Break the Bech32m checksum.
        let last = address.pop().expect("non-empty");
        address.push(if last == 'q' { 'p' } else { 'q' });

        let err =
            user_address_receivers(&address, &PaidReceiver::Orchard([0x03; 43]), 133).unwrap_err();
        assert!(err.contains("not a valid unified address"), "got: {err}");
    }

    #[test]
    fn unified_address_prefixes_are_told_apart_from_transparent_ones() {
        assert!(has_unified_address_prefix("u1qqqq"));
        assert!(has_unified_address_prefix("utest1qqqq"));
        assert!(has_unified_address_prefix("uregtest1qqqq"));
        assert!(!has_unified_address_prefix(
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"
        ));
        assert!(!has_unified_address_prefix("tmqqqq"));
        // "u" followed by anything other than the separator is not a prefix match.
        assert!(!has_unified_address_prefix("uview1qqqq"));
    }

    #[test]
    fn user_address_receivers_accepts_the_paid_plain_transparent_address_on_testnet() {
        let t_addr = zcash_keys::address::Address::Transparent(TransparentAddress::PublicKeyHash(
            [0x11; 20],
        ))
        .encode(&Network::TestNetwork);

        let accepted = user_address_receivers(&t_addr, &PaidReceiver::P2pkh([0x11; 20]), 1)
            .expect("the paid testnet address is accepted");
        assert_eq!(accepted, None);

        // The same address read against mainnet does not decode as the paid one.
        let err =
            user_address_receivers(&t_addr, &PaidReceiver::P2pkh([0x11; 20]), 133).unwrap_err();
        assert!(err.contains("neither a unified address"), "got: {err}");
    }

    #[test]
    fn transparent_output_with_a_user_address_on_a_non_standard_script_is_refused() {
        let address = ua(
            vec![
                UnifiedReceiver::P2pkh([0x11; 20]),
                UnifiedReceiver::Orchard([0x03; 43]),
            ],
            NetworkType::Main,
        );
        // OP_RETURN: no receiver a unified address could hold.
        let output = zcash_transparent::pczt::Output::parse(
            1_000,
            vec![0x6a, 0x01, 0x00],
            None,
            BTreeMap::new(),
            Some(address),
            BTreeMap::new(),
        )
        .expect("a well-formed output");

        let err = convert_transparent_output(&output, 133).unwrap_err();
        assert!(err.contains("non-standard script"), "got: {err}");
    }

    #[test]
    fn paid_transparent_receiver_reads_p2pkh_and_p2sh_scripts() {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend([0x11; 20]);
        p2pkh.extend([0x88, 0xac]);
        assert!(matches!(
            paid_transparent_receiver(&p2pkh),
            Some(PaidReceiver::P2pkh(h)) if h == [0x11; 20]
        ));

        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend([0x22; 20]);
        p2sh.push(0x87);
        assert!(matches!(
            paid_transparent_receiver(&p2sh),
            Some(PaidReceiver::P2sh(h)) if h == [0x22; 20]
        ));

        assert!(paid_transparent_receiver(&[0x6a, 0x01, 0x00]).is_none());
    }
}
