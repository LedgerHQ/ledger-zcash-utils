//! Build, prove, and serialize a PCZT for Orchard and transparent send flows.
//!
//! Covers all four send flows:
//!   - Private → Private  (Orchard spends + Orchard outputs)
//!   - Private → Public   (Orchard spends + at least one transparent output)
//!   - Public  → Private  (transparent inputs + Orchard output; anchor-only)
//!   - Public  → Public   (transparent inputs + transparent outputs; no Orchard bundle)
//!
//! Lifecycle (host side):
//!   1. Construct `zcash_primitives::transaction::builder::Builder` with the
//!      anchor from `zcash_sync::witness::WitnessOutput`.
//!   2. For each Orchard spend: reconstruct the `Note` via `Note::from_parts`
//!      and call `add_orchard_spend(fvk, note, merkle_path)`.
//!   3. For each transparent input: validate the pubkey + OutPoint + TxOut,
//!      then call `add_transparent_p2pkh_input(pubkey, outpoint, coin)`.
//!   4. For each output: dispatch on the destination address type and call
//!      `add_orchard_output` or `add_transparent_output`. An automatic change
//!      output is added when value balance is positive.
//!   5. `Builder::build_for_pczt(OsRng, &FeeRule::standard())` → `PcztParts`.
//!   6. `pczt::roles::creator::Creator::build_from_parts` wraps it into a
//!      wire-format `Pczt`.
//!   7. When an Orchard bundle is present: stamp ZIP-32 derivation paths, run
//!      `IoFinalizer::finalize_io()`, `Prover::create_orchard_proof(&pk)`.
//!      For transparent-only: skip stamp + prover, only run `IoFinalizer`.
//!   8. `Pczt::serialize()` emits the canonical wire format
//!      (`PCZT` magic + u32 version + postcard payload).
//!
//! ## Binding signature (bsk) — intentionally not exposed
//!
//! In the Ledger PCZT signing flow the device returns only Orchard
//! spend-authorization signatures; it never computes the binding signature.
//! The binding signing key `bsk = Σ rcv` is value-commitment randomness owned
//! by the host, so it is derived host-side from the PCZT during finalization
//! and never needs to leave Rust. This builder therefore does not
//! surface `bsk`, which also sidesteps the `pczt 0.7` limitation that the
//! wire-format `bsk` field has no public accessor.
//!
//! ## Per-action ZIP-32 derivation
//!
//! For the device to authorize a spend it must know which key to use.
//! `Builder::build_for_pczt` records each spend's `fvk` and `alpha` but leaves
//! `zip32_derivation` empty. After wrapping the PcztParts we run the Updater
//! role to stamp the derivation path `m/32'/coin_type'/account'` and the
//! wallet's seed fingerprint onto every action's spend.
//!
//! The device's PCZT parser builds one signing record per action and aborts if
//! any action lacks a path, so dummy-spend actions (which the builder injects
//! to pad to the change output) must be stamped too. That is safe: dummy spends
//! are already signed host-side by the IO Finalizer via `dummy_sk`, so the host
//! never asks the device to sign those action indices. The path shape matches
//! exactly what the device validates and re-derives from
//! (`app-rust-zcash` `check_bip44_compliance` / `derive_orchard_fvk`).
//!
//! ## Transparent BIP-44 `bip32_derivation`
//!
//! The transparent pool needs the analogous metadata, stamped onto the PCZT's
//! transparent bundle by [`stamp_transparent_derivations`]:
//!
//!   - **Every transparent input** is stamped with its compressed pubkey and the
//!     BIP-44 path `m/44'/coin_type'/account'/scope/address_index`. In the Ledger
//!     PCZT signing flow this path *is* the signing-key locator — the sign APDU
//!     (`handler_pczt_sign_transparent`) carries no path, and the device parser
//!     rejects any transparent input whose `bip32_derivation` is missing or not
//!     exactly one entry. The device signs with this path without re-checking it
//!     against the pubkey, so the caller must guarantee it derives to the pubkey
//!     (the sync layer verifies this against the UFVK before building).
//!   - **The transparent change output** is stamped with the change pubkey and
//!     the internal path `m/44'/coin_type'/account'/1/address_index`. Without it
//!     the device classifies the wallet's own change as a third-party recipient
//!     and shows it to the user; with it the device re-derives the pubkey from
//!     the path, matches its hash against the output script, and hides it as
//!     change. Regular (non-change) transparent recipient outputs are left
//!     un-stamped so the device displays them as external payments.
//!
//! Transparent stamping runs after the IO Finalizer and Prover because
//! `bip32_derivation` is signer metadata that does not affect the txid or
//! sighash, and the transparent Updater role has no `tx_modifiable` gate.
//!
//! ## Transparent inputs — encoding conventions
//!
//! `txid`: The 32-byte txid is supplied in **internal (little-endian) byte
//! order**, matching what `OutPoint::new([u8;32], u32)` expects and what the
//! Bitcoin/Zcash wire encoding stores. Ledger Live sources txids in display
//! (big-endian) order; callers must reverse before passing here.
//!
//! `script_pubkey`: Supplied as **raw script bytes** (no CompactSize length
//! prefix). `Script::read` expects a CompactSize-prefixed encoding, so we
//! construct `Script(script::Code(bytes))` directly from the raw slice.

use std::sync::OnceLock;

use orchard::{
    builder::BundleType as OrchardBundleType,
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey as OrchardFvk, OutgoingViewingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    pczt::Zip32Derivation,
    value::NoteValue,
    Address as OrchardAddress,
};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor,
        updater::Updater,
    },
    Pczt,
};
use rand::rngs::OsRng;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317::{FeeError as Zip317FeeError, FeeRule},
};
use zcash_protocol::{
    consensus::{BlockHeight, Network, NetworkConstants, NetworkUpgrade, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::{
    address::TransparentAddress, pczt::Bip32Derivation as TransparentBip32Derivation,
};
use zip32::ChildIndex;

use crate::error::Error;

/// Default expiry delta in blocks. Matches `DEFAULT_TX_EXPIRY_DELTA` in
/// `zcash_primitives::transaction::builder`.
pub const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

/// One Orchard note to spend.
#[derive(Clone, Debug)]
pub struct OrchardSpendInput {
    /// Raw 43-byte recipient (11-byte diversifier `d` || 32-byte `pk_d`).
    pub recipient: [u8; 43],
    /// Note value in zatoshis.
    pub value: u64,
    /// 32-byte rho (nullifier of the predecessor note in derivation order).
    pub rho: [u8; 32],
    /// 32-byte rseed (random seed for the note).
    pub rseed: [u8; 32],
    /// Merkle witness for this note (from `zcash_crypto::tree::WitnessOutput`).
    pub merkle_path: incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>,
}

/// One transparent (P2PKH) UTXO to spend.
#[derive(Clone, Debug)]
pub struct TransparentInput {
    /// 33-byte compressed secp256k1 public key controlling the UTXO. The device
    /// holds the matching private key; this builder produces an unsigned input.
    pub pubkey: [u8; 33],
    /// 32-byte prevout txid in **internal (little-endian) byte order**.
    /// Zcash/Bitcoin display txids in reversed (big-endian) order; callers must
    /// reverse before passing.
    pub txid: [u8; 32],
    /// Output index within the origin transaction (prevout vout).
    pub vout: u32,
    /// The UTXO's `scriptPubKey` as **raw script bytes** (no CompactSize prefix).
    /// For a standard P2PKH output this is the 25-byte
    /// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG` script.
    pub script_pubkey: Vec<u8>,
    /// UTXO value in zatoshis.
    pub value: u64,
    /// BIP-44 chain (scope) the controlling key was derived at: `0` = external,
    /// `1` = internal (change). Combined with the shared `account_index` and the
    /// network coin type into the input's signing path
    /// `m/44'/coin_type'/account'/scope/address_index`, which is stamped into the
    /// PCZT as this input's `bip32_derivation`.
    ///
    /// The Ledger device reads the signing path exclusively from this field in
    /// the PCZT flow (`handler_pczt_sign_transparent` carries no path APDU); a
    /// transparent input without a `bip32_derivation` is rejected by the device
    /// parser. The path is not re-checked against `pubkey` on-device, so callers
    /// must ensure it derives to `pubkey` (the sync layer verifies this against
    /// the UFVK before building).
    pub derivation_scope: u32,
    /// Non-hardened BIP-44 address index of the controlling key (see
    /// [`Self::derivation_scope`]).
    pub derivation_address_index: u32,
}

/// A destination for one output.
#[derive(Clone, Debug)]
pub enum Destination {
    /// Orchard payment address (already decoded). Derived from a Unified
    /// Address's Orchard receiver or from a u-address.
    Orchard(OrchardAddress),
    /// Transparent payment address (P2PKH or P2SH).
    Transparent(TransparentAddress),
}

/// One output of the transaction.
#[derive(Clone, Debug)]
pub struct OutputRequest {
    pub destination: Destination,
    pub value: u64,
    /// Memo bytes for Orchard outputs. Ignored for transparent outputs.
    pub memo: Option<Vec<u8>>,
}

/// Inputs to [`build_transaction`].
pub struct BuildInputs {
    pub network: Network,
    /// Target block height. Builder uses `target + DEFAULT_TX_EXPIRY_DELTA` for
    /// the expiry. Branch ID is derived from this height.
    pub target_height: u32,
    /// Orchard full viewing key (extracted from the UFVK). Required (`Some`)
    /// only when an Orchard bundle will be present (Orchard spends or Orchard
    /// outputs). `None` is valid for the transparent-only Public→Public flow,
    /// where no Orchard key material is read.
    pub orchard_fvk: Option<OrchardFvk>,
    /// Optional Outgoing Viewing Key for output recipients. Pass `Some(external_ovk)`
    /// if the wallet should be able to later decrypt its own outgoing notes.
    pub ovk: Option<OutgoingViewingKey>,
    /// Internal-scope Orchard change address. Required (`Some`) only when an
    /// Orchard bundle is present and `change > 0`; `None` is valid for the
    /// transparent-only Public→Public flow.
    pub change_address: Option<OrchardAddress>,
    /// Internal-scope transparent change address. Required when `has_orchard ==
    /// false` and `change > 0` (Public→Public flow). `None` is valid when no
    /// change is expected, or when change is taken in Orchard.
    pub transparent_change_address: Option<TransparentAddress>,
    /// Compressed secp256k1 pubkey (33 bytes) of `transparent_change_address`.
    /// Required (`Some`) whenever a transparent change output is produced. It is
    /// stamped into the change output's `bip32_derivation` so the Ledger device
    /// recognizes the output as change (and hides it) instead of displaying it as
    /// a third-party recipient. The device re-derives this pubkey from the change
    /// path and aborts if it does not match, so it must be the exact pubkey of
    /// `transparent_change_address`.
    pub transparent_change_pubkey: Option<[u8; 33]>,
    /// Non-hardened BIP-44 address index of `transparent_change_address`.
    /// Combined with the shared `account_index`, the internal scope (`1`), and
    /// the network coin type into the change path
    /// `m/44'/coin_type'/account'/1/address_index`. Required (`Some`) whenever a
    /// transparent change output is produced.
    pub transparent_change_address_index: Option<u32>,
    /// Anchor root (32-byte little-endian Pallas encoding) from `zcash_sync::witness::WitnessOutput`.
    /// Used only when an Orchard bundle is present; pass `[0u8; 32]` for
    /// Public→Public (no Orchard bundle).
    pub anchor: [u8; 32],
    /// ZIP-32 seed fingerprint of the wallet seed (see ZIP-32 §"Seed
    /// fingerprints"). Stamped onto every real Orchard spend so the device can
    /// confirm the PCZT belongs to its seed before producing a spend-auth signature.
    pub seed_fingerprint: [u8; 32],
    /// ZIP-32 account index the `orchard_fvk` was derived at. Combined with the
    /// network coin type into the per-spend path `m/32'/coin_type'/account'`.
    pub account_index: u32,
    /// Caller-owned fee in zatoshis (FR-4). The fee is selected upstream by
    /// ledger-live; this builder never *chooses* a fee. It is used
    /// to derive the change amount (`change = total_in − total_out − fee`) and
    /// is validated against ZIP-317 for the final action layout — our ZIP-317
    /// implementation is validation-only.
    pub fee: u64,
    /// Orchard notes to spend. Empty for Public→* flows.
    pub spends: Vec<OrchardSpendInput>,
    /// Transparent (P2PKH) UTXOs to spend. Empty for Private→* flows.
    pub transparent_inputs: Vec<TransparentInput>,
    pub outputs: Vec<OutputRequest>,
}

/// Output of [`build_transaction`].
#[derive(Debug)]
pub struct BuildOutput {
    /// Canonical PCZT bytes (`PCZT` magic + u32 LE version + postcard payload).
    pub pczt_bytes: Vec<u8>,
    /// Fee in zatoshis. Echoes the caller-supplied fee, which has been
    /// validated against ZIP-317 for the final action layout.
    pub fee: u64,
    /// Anchor height (== `target_height - DEFAULT_TX_EXPIRY_DELTA`, clamped).
    pub anchor_height: u32,
    /// Orchard action count after dummy padding.
    pub n_actions_orchard: u32,
    /// Transparent input count.
    pub n_transparent_inputs: u32,
    /// Transparent output count (including change).
    pub n_transparent_outputs: u32,
    /// Ironwood action count after dummy padding. Always `0` for a transaction
    /// built by [`build_transaction`] (the V5/Orchard path never carries an
    /// Ironwood bundle); populated by [`build_ironwood_transaction`].
    pub n_actions_ironwood: u32,
}

/// Process-global Halo 2 proving key. First initialization is ~2–5 s;
/// subsequent accesses reuse the same allocation.
pub(crate) fn proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
}

/// Build, prove, and serialize a PCZT for an Orchard or transparent send.
///
/// # Errors
///
/// Returns [`Error::Craft`] for:
/// - both orchard spends and transparent inputs are empty;
/// - invalid spend components (recipient bytes, rho, rseed → `Note::from_parts` fails);
/// - invalid transparent input (pubkey bytes, OutPoint, TxOut construction);
/// - invalid anchor encoding (when an Orchard bundle is present);
/// - unsupported network state (NU5 not active at `target_height`);
/// - builder errors (insufficient funds, add_orchard_* / add_transparent_* failures);
/// - PCZT IO finalizer or prover errors;
/// - value-out-of-range conversion errors (zatoshis cap = 2^63 - 1).
pub fn build_transaction(inputs: BuildInputs) -> Result<BuildOutput, Error> {
    let BuildInputs {
        network,
        target_height,
        orchard_fvk,
        ovk,
        change_address,
        transparent_change_address,
        transparent_change_pubkey,
        transparent_change_address_index,
        anchor,
        seed_fingerprint,
        account_index,
        fee,
        spends,
        transparent_inputs,
        outputs,
    } = inputs;

    let target = BlockHeight::from(target_height);
    if !network.is_nu_active(NetworkUpgrade::Nu5, target) {
        // This builder always emits a v5 transaction (`BuildConfig::Standard`),
        // and the v5 format is gated on NU5 regardless of which pools are used —
        // so this also applies to transparent-only (Public→Public) transactions
        // that contain no Orchard bundle.
        return Err(Error::Craft(format!(
            "NU5 is not active at target_height {target_height}; this builder emits v5 \
             transactions, which require NU5 (or a later upgrade) to be active"
        )));
    }
    if spends.is_empty() && transparent_inputs.is_empty() {
        return Err(Error::Craft(
            "no inputs: both orchard spends and transparent inputs are empty".into(),
        ));
    }
    if outputs.is_empty() {
        return Err(Error::Craft("outputs list is empty".into()));
    }

    // Determine whether an Orchard bundle will be present. An Orchard bundle
    // is created when there are Orchard spends OR any Orchard output.
    let has_orchard = !spends.is_empty()
        || outputs
            .iter()
            .any(|o| matches!(o.destination, Destination::Orchard(_)));

    // Every PCZT this builder emits is serialized as PCZT v1 (the device signing
    // contract), and the v1 encoding requires the Orchard bundle to carry an
    // anchor even when it has no actions. For Orchard flows this is the supplied
    // note-commitment tree anchor; transparent-only flows have no Orchard actions,
    // so the canonical empty-tree anchor is used (no action ever references it).
    let orchard_anchor = Some(if has_orchard {
        if anchor == [0u8; 32] {
            return Err(Error::Craft(
                "Orchard anchor must be non-zero (zero is not a valid commitment-tree root)".into(),
            ));
        }
        orchard::Anchor::from_bytes(anchor)
            .into_option()
            .ok_or_else(|| Error::Craft("invalid Orchard anchor encoding".into()))?
    } else {
        orchard::Anchor::empty_tree()
    });
    let build_config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor,
        ironwood_anchor: None,
        orchard_pool_bundle_type: OrchardBundleType::DEFAULT,
    };

    // ── 1. Builder + Orchard spends + transparent inputs + non-change outputs ──
    let mut builder = Builder::new(network, target, build_config);

    let mut total_in: u64 = 0;
    if !spends.is_empty() {
        let fvk = orchard_fvk.as_ref().ok_or_else(|| {
            Error::Craft("orchard_fvk is required when Orchard spends are present".into())
        })?;
        for spend in &spends {
            add_spend(&mut builder, fvk, spend)?;
            total_in = total_in
                .checked_add(spend.value)
                .ok_or_else(|| Error::Craft("spend value overflow".into()))?;
        }
    }
    let n_spends = spends.len() as u32;

    for tin in &transparent_inputs {
        add_transparent_input(&mut builder, tin)?;
        total_in = total_in
            .checked_add(tin.value)
            .ok_or_else(|| Error::Craft("transparent input value overflow".into()))?;
    }
    let n_transparent_inputs = transparent_inputs.len() as u32;

    let mut total_out: u64 = 0;
    let mut n_orchard_outputs: u32 = 0;
    let mut n_transparent_outputs: u32 = 0;
    for out in &outputs {
        add_output(&mut builder, ovk.as_ref(), out)?;
        match out.destination {
            Destination::Orchard(_) => n_orchard_outputs += 1,
            Destination::Transparent(_) => n_transparent_outputs += 1,
        }
        total_out = total_out
            .checked_add(out.value)
            .ok_or_else(|| Error::Craft("output value overflow".into()))?;
    }

    // ── 2. Change derivation + fee validation ────────────────────────────────
    // FR-4: the fee is owned by the caller (ledger-live); this
    // builder never *chooses* a fee. We derive the change from the supplied fee
    // and use ZIP-317 only to *validate* that fee against the final layout.
    let fee_rule = FeeRule::standard();

    let outflow = total_out
        .checked_add(fee)
        .ok_or_else(|| Error::Craft("total_out + fee overflow".into()))?;
    if total_in < outflow {
        return Err(Error::Craft(format!(
            "insufficient funds: total_in={total_in} < total_out={total_out} + fee={fee}"
        )));
    }
    let change = total_in - outflow;

    // Route surplus change to the pool that funds it:
    // - Orchard spends present → Orchard change output (z→z, z→t: the surplus
    //   comes from the spent Orchard notes, so change stays shielded).
    // - No Orchard spends → transparent change output (t→t and t→z: the surplus
    //   comes from the transparent inputs). For t→z this keeps the change
    //   transparent instead of migrating the whole balance into the shielded
    //   pool — only the sent amount is shielded.
    //
    // When a transparent change output is added we record its index in the
    // transparent bundle plus the metadata needed to stamp its `bip32_derivation`
    // (so the device can recognize it as change). The transparent builder appends
    // outputs in insertion order without shuffling, so the change output — added
    // here, after all caller-supplied outputs — is the last transparent output;
    // its index equals the number of transparent outputs added before it.
    let mut transparent_change_stamp: Option<(usize, [u8; 33], u32)> = None;
    if change > 0 {
        if n_spends > 0 {
            let change_addr = change_address.ok_or_else(|| {
                Error::Craft(
                    "change_address required for Orchard change but none supplied".into(),
                )
            })?;
            let change_req = OutputRequest {
                destination: Destination::Orchard(change_addr),
                value: change,
                memo: None,
            };
            add_output(&mut builder, ovk.as_ref(), &change_req)?;
            n_orchard_outputs += 1;
        } else {
            let addr = transparent_change_address.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_address supplied".into(),
                )
            })?;
            let change_pubkey = transparent_change_pubkey.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_pubkey supplied — \
                     the device needs the change output's bip32_derivation to recognize it as \
                     change rather than a third-party recipient"
                        .into(),
                )
            })?;
            let change_address_index = transparent_change_address_index.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_address_index supplied"
                        .into(),
                )
            })?;
            let change_req = OutputRequest {
                destination: Destination::Transparent(addr),
                value: change,
                memo: None,
            };
            let change_output_index = n_transparent_outputs as usize;
            add_output(&mut builder, None, &change_req)?;
            n_transparent_outputs += 1;
            transparent_change_stamp =
                Some((change_output_index, change_pubkey, change_address_index));
        }
    }

    // ZIP-317 validation (validation-only). The supplied fee must equal the
    // ZIP-317 fee for the *final* action layout (after any change output).
    let required_fee = zip317_fee(
        n_spends,
        n_orchard_outputs,
        n_transparent_inputs,
        n_transparent_outputs,
    );
    if fee != required_fee {
        return Err(Error::Craft(format!(
            "fee {fee} does not satisfy ZIP-317 for this transaction (requires {required_fee}); \
             fee selection is owned by the caller and must equal the ZIP-317 fee — \
             total_in={total_in}, total_out={total_out}, change={change}"
        )));
    }

    // Defense-in-depth: cross-check against the builder's own fee rule. With the
    // validation above this should never fire; it guards against our ZIP-317
    // model drifting from the library's `FeeRule::standard()`.
    let builder_fee = builder.get_fee(&fee_rule).map(u64::from).map_err(
        |e: zcash_primitives::transaction::builder::FeeError<Zip317FeeError>| {
            Error::Craft(format!("get_fee: {e:?}"))
        },
    )?;
    if builder_fee != fee {
        return Err(Error::Craft(format!(
            "fee mismatch — caller-supplied {fee}, builder {builder_fee}"
        )));
    }

    // ── 3. build_for_pczt + PCZT roles ───────────────────────────────────────
    let pczt_result = builder
        .build_for_pczt(OsRng, &fee_rule)
        .map_err(|e| Error::Craft(format!("build_for_pczt: {e:?}")))?;
    let n_actions_orchard = pczt_result
        .pczt_parts
        .orchard
        .as_ref()
        .map_or(0u32, |b| b.actions().len() as u32);

    let pczt: Pczt = Creator::build_from_parts(pczt_result.pczt_parts).ok_or_else(|| {
        Error::Craft("PCZT Creator rejected the PcztParts (unsupported tx version)".into())
    })?;

    // Stamp ZIP-32 derivation paths only when an Orchard bundle is present.
    // For Public→Public there is no Orchard bundle; `update_orchard_with` errors
    // on an absent/empty bundle, so we gate it behind `has_orchard`.
    let pczt = if has_orchard {
        stamp_spend_derivations(pczt, &network, seed_fingerprint, account_index)?
    } else {
        pczt
    };

    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| Error::Craft(format!("PCZT IoFinalizer: {e:?}")))?;

    // Generate the Orchard proof only when the bundle exists.
    let prover = Prover::new(pczt);
    let pczt = if prover.requires_orchard_proof() {
        prover
            .create_orchard_proof(proving_key())
            .map_err(|e| Error::Craft(format!("PCZT Prover (orchard): {e:?}")))?
            .finish()
    } else {
        prover.finish()
    };

    // Stamp transparent `bip32_derivation`s. Done after IoFinalizer/Prover because
    // these are signer metadata that do not affect the txid or sighash, and the
    // transparent Updater role has no `tx_modifiable` gate. The device requires a
    // `bip32_derivation` on every transparent input (it is the signing path in the
    // PCZT flow) and on the transparent change output (so it is recognized as
    // change). Skipped entirely for flows with no transparent inputs and no
    // transparent change.
    let pczt = if !transparent_inputs.is_empty() || transparent_change_stamp.is_some() {
        stamp_transparent_derivations(
            pczt,
            &network,
            seed_fingerprint,
            account_index,
            &transparent_inputs,
            transparent_change_stamp,
        )?
    } else {
        pczt
    };

    // Serialize as PCZT v1 for every flow, matching the device signing contract:
    // app-zcash rejects any header version other than v1. v1 encoding succeeds for
    // every PCZT this path produces (V5 transaction, canonical empty Ironwood
    // bundle, Orchard notes at NoteVersion::V2), including transparent-only ones.
    // The v2 (redaction) format is reserved for the Ironwood/NU6.3 work.
    let pczt_bytes = pczt::v1::Pczt::try_from(pczt)
        .map_err(|e| Error::Craft(format!("PCZT v1 encoding: {e:?}")))?
        .serialize();

    Ok(BuildOutput {
        pczt_bytes,
        fee,
        anchor_height: target_height.saturating_sub(DEFAULT_TX_EXPIRY_DELTA),
        n_actions_orchard,
        n_transparent_inputs,
        n_transparent_outputs,
        // This path never builds an Ironwood bundle.
        n_actions_ironwood: 0,
    })
}

/// Stamps **every** Orchard action's spend in the PCZT with the ZIP-32
/// derivation path `m/32'/coin_type'/account'` and the wallet seed fingerprint.
///
/// Only called when an Orchard bundle is present. The Ledger device's PCZT
/// parser requires a derivation path on every action (it builds one signing
/// record per action and aborts with `BadState` if the path is missing — see
/// `app-rust-zcash` `src/parser/pczt/orchard.rs`), so dummy-spend actions that
/// the builder injects for change must be stamped too. This is safe: dummy
/// spends are already signed host-side by the IO Finalizer (via `dummy_sk`),
/// so the host never requests a device signature for those action indices, and
/// the device only ever signs the indices it is asked to. All spends in a
/// single-account transaction share the same path.
fn stamp_spend_derivations(
    pczt: Pczt,
    network: &Network,
    seed_fingerprint: [u8; 32],
    account_index: u32,
) -> Result<Pczt, Error> {
    const HARDENED_OFFSET: u32 = 1 << 31;
    if account_index >= HARDENED_OFFSET {
        return Err(Error::Craft(format!(
            "account_index {account_index} exceeds the ZIP-32 hardened range"
        )));
    }
    // All indices are hardened (high bit set), as required by Orchard ZIP-32.
    let derivation_path: Vec<u32> = vec![
        ChildIndex::hardened(32).index(),
        ChildIndex::hardened(network.coin_type()).index(),
        ChildIndex::hardened(account_index).index(),
    ];

    Updater::new(pczt)
        .update_orchard_with(|mut updater| {
            let action_count = updater.bundle().actions().len();
            for i in 0..action_count {
                // Indices are hardened by construction, so `parse` is infallible
                // here; the map_err only satisfies the closure's error type.
                let derivation = Zip32Derivation::parse(seed_fingerprint, derivation_path.clone())
                    .map_err(|_| orchard::pczt::UpdaterError::InvalidIndex)?;
                updater.update_action_with(i, |mut action| {
                    action.set_spend_zip32_derivation(derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| Error::Craft(format!("PCZT Updater (orchard zip32): {e:?}")))
        .map(Updater::finish)
}

/// BIP-44 internal (change) scope. Transparent change addresses live on the
/// internal chain; the Ledger device only accepts a change output whose
/// `bip32_derivation` path has scope `1` (`check_bip44_compliance` with
/// `is_change_path: true`).
const TRANSPARENT_INTERNAL_SCOPE: u32 = 1;

/// Builds the transparent BIP-44 derivation path
/// `m/44'/coin_type'/account'/scope/address_index` as raw ZIP-32 child indices
/// (the first three hardened, the last two non-hardened).
///
/// This matches what the Ledger device validates via `check_bip44_compliance`
/// (purpose `44`, the network coin type) and — for change outputs — re-derives
/// the pubkey from.
fn bip44_transparent_path(
    coin_type: u32,
    account_index: u32,
    scope: u32,
    address_index: u32,
) -> Result<Vec<u32>, Error> {
    const HARDENED_OFFSET: u32 = 1 << 31;
    if account_index >= HARDENED_OFFSET {
        return Err(Error::Craft(format!(
            "account_index {account_index} exceeds the ZIP-32 hardened range"
        )));
    }
    if scope >= HARDENED_OFFSET {
        return Err(Error::Craft(format!(
            "transparent derivation scope {scope} must be non-hardened"
        )));
    }
    if address_index >= HARDENED_OFFSET {
        return Err(Error::Craft(format!(
            "transparent address index {address_index} must be non-hardened"
        )));
    }
    Ok(vec![
        ChildIndex::hardened(44).index(),
        ChildIndex::hardened(coin_type).index(),
        ChildIndex::hardened(account_index).index(),
        scope,
        address_index,
    ])
}

/// Stamps the transparent bundle's `bip32_derivation`s:
///
/// - **Every transparent input** gets a derivation keyed by its compressed
///   pubkey at path `m/44'/coin_type'/account'/scope/address_index`. In the
///   Ledger PCZT signing flow this path *is* the signing key locator — the
///   device reads it from the PCZT (the sign APDU carries no path) and rejects
///   inputs whose `bip32_derivation` is absent or not exactly one entry.
/// - **The transparent change output** (when present) gets a derivation keyed by
///   the change pubkey at path `m/44'/coin_type'/account'/1/address_index`, so
///   the device classifies it as change (re-deriving the pubkey from the path
///   and matching its hash against the output script) instead of showing it as a
///   third-party recipient.
///
/// Regular (non-change) transparent recipient outputs are intentionally left
/// without a derivation so the device displays them as external payments.
///
/// Derivations are pre-computed before entering the updater closure so path and
/// parse errors surface as [`Error::Craft`]; the closure itself can only yield
/// the transparent `UpdaterError` (invalid index).
fn stamp_transparent_derivations(
    pczt: Pczt,
    network: &Network,
    seed_fingerprint: [u8; 32],
    account_index: u32,
    transparent_inputs: &[TransparentInput],
    change: Option<(usize, [u8; 33], u32)>,
) -> Result<Pczt, Error> {
    let coin_type = network.coin_type();

    let mut input_derivations: Vec<([u8; 33], TransparentBip32Derivation)> =
        Vec::with_capacity(transparent_inputs.len());
    for tin in transparent_inputs {
        let path = bip44_transparent_path(
            coin_type,
            account_index,
            tin.derivation_scope,
            tin.derivation_address_index,
        )?;
        let derivation = TransparentBip32Derivation::parse(seed_fingerprint, path)
            .map_err(|e| Error::Craft(format!("transparent input bip32 derivation: {e:?}")))?;
        input_derivations.push((tin.pubkey, derivation));
    }

    let change_derivation = match change {
        Some((index, pubkey, address_index)) => {
            let path = bip44_transparent_path(
                coin_type,
                account_index,
                TRANSPARENT_INTERNAL_SCOPE,
                address_index,
            )?;
            let derivation = TransparentBip32Derivation::parse(seed_fingerprint, path)
                .map_err(|e| {
                    Error::Craft(format!("transparent change bip32 derivation: {e:?}"))
                })?;
            Some((index, pubkey, derivation))
        }
        None => None,
    };

    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            for (i, (pubkey, derivation)) in input_derivations.into_iter().enumerate() {
                updater.update_input_with(i, |mut input| {
                    input.set_bip32_derivation(pubkey, derivation);
                    Ok(())
                })?;
            }
            if let Some((index, pubkey, derivation)) = change_derivation {
                updater.update_output_with(index, |mut output| {
                    output.set_bip32_derivation(pubkey, derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| Error::Craft(format!("PCZT Updater (transparent bip32): {e:?}")))
        .map(Updater::finish)
}

fn add_spend(
    builder: &mut Builder<Network, ()>,
    fvk: &OrchardFvk,
    spend: &OrchardSpendInput,
) -> Result<(), Error> {
    let recipient = OrchardAddress::from_raw_address_bytes(&spend.recipient)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Orchard recipient bytes in spend".into()))?;
    let rho = Rho::from_bytes(&spend.rho)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Orchard rho bytes".into()))?;
    let rseed = RandomSeed::from_bytes(spend.rseed, &rho)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Orchard rseed for the given rho".into()))?;
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(spend.value),
        rho,
        rseed,
        NoteVersion::V2,
    )
    .into_option()
    .ok_or_else(|| Error::Craft("Note::from_parts produced a non-canonical note".into()))?;
    let merkle_path: orchard::tree::MerklePath = spend.merkle_path.clone().into();
    builder
        .add_orchard_spend::<Zip317FeeError>(fvk.clone(), note, merkle_path)
        .map_err(|e| Error::Craft(format!("add_orchard_spend: {e:?}")))?;
    Ok(())
}

/// Add one transparent P2PKH UTXO to the builder.
///
/// `txid` must be in **internal (little-endian) byte order** — this is the
/// byte order `OutPoint::new([u8;32], u32)` stores internally and what the
/// sighash computation uses. Zcash/Bitcoin display txids in big-endian (reversed)
/// order; callers sourcing txids from ledger-live's display representation must
/// reverse the 32-byte array before passing.
///
/// `script_pubkey` must be **raw script bytes** with no length prefix. A standard
/// P2PKH scriptPubKey is 25 bytes: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
/// `Script::read` expects a CompactSize-prefixed encoding; we prepend the
/// CompactSize varint before calling it (the inner `script::Code` type is private
/// in `zcash_transparent` and cannot be named from outside the crate).
fn add_transparent_input(
    builder: &mut Builder<Network, ()>,
    tin: &TransparentInput,
) -> Result<(), Error> {
    use zcash_transparent::{address::Script, bundle::TxOut};

    let pubkey = secp256k1::PublicKey::from_slice(&tin.pubkey)
        .map_err(|e| Error::Craft(format!("invalid transparent pubkey: {e}")))?;

    // OutPoint::new takes [u8;32] in internal byte order (verified: bundle.rs:168).
    let outpoint = zcash_transparent::bundle::OutPoint::new(tin.txid, tin.vout);

    let value = Zatoshis::from_u64(tin.value)
        .map_err(|e| Error::Craft(format!("transparent input value out of range: {e}")))?;

    // Script::read expects a CompactSize-prefixed encoding (address.rs:63-68).
    // We prepend the length as a single byte, which is only valid while the length
    // fits a one-byte CompactSize: values 0–252 (0xFC) encode as one byte, while
    // 253+ require a multi-byte varint (0xFD + u16, etc.). 252 is therefore the
    // CompactSize single-byte boundary, not an arbitrary policy cap. All standard
    // scripts fit comfortably (P2PKH = 25 bytes, P2SH = 23 bytes).
    let script_len = tin.script_pubkey.len();
    if script_len > 252 {
        return Err(Error::Craft(format!(
            "scriptPubKey length ({script_len} bytes) exceeds the single-byte CompactSize limit (252 bytes); larger scripts would need a multi-byte length prefix"
        )));
    }
    let mut prefixed = Vec::with_capacity(1 + script_len);
    prefixed.push(script_len as u8);
    prefixed.extend_from_slice(&tin.script_pubkey);

    let script_pubkey = Script::read(prefixed.as_slice())
        .map_err(|e| Error::Craft(format!("invalid scriptPubKey: {e}")))?;

    let coin = TxOut::new(value, script_pubkey);

    builder
        .add_transparent_p2pkh_input(pubkey, outpoint, coin)
        .map_err(|e| Error::Craft(format!("add_transparent_p2pkh_input: {e:?}")))?;
    Ok(())
}

fn add_output(
    builder: &mut Builder<Network, ()>,
    ovk: Option<&OutgoingViewingKey>,
    out: &OutputRequest,
) -> Result<(), Error> {
    let value = Zatoshis::from_u64(out.value)
        .map_err(|e| Error::Craft(format!("output value out of range: {e}")))?;
    match &out.destination {
        Destination::Orchard(addr) => {
            let memo = encode_memo(out.memo.as_deref())?;
            builder
                .add_orchard_output::<Zip317FeeError>(ovk.cloned(), *addr, value, memo)
                .map_err(|e| Error::Craft(format!("add_orchard_output: {e:?}")))?;
        }
        Destination::Transparent(addr) => {
            builder
                .add_transparent_output(addr, value)
                .map_err(|e| Error::Craft(format!("add_transparent_output: {e:?}")))?;
        }
    }
    Ok(())
}

fn encode_memo(memo: Option<&[u8]>) -> Result<MemoBytes, Error> {
    match memo {
        None => Ok(MemoBytes::empty()),
        Some(bytes) => MemoBytes::from_bytes(bytes)
            .map_err(|e| Error::Craft(format!("invalid memo bytes: {e}"))),
    }
}

/// ZIP-317 marginal fee (5_000 zat).
const MARGINAL_FEE: u64 = 5_000;
/// ZIP-317 grace actions (2).
const GRACE_ACTIONS: u64 = 2;
/// Orchard `BundleType::DEFAULT` pads to at least this many actions.
/// Mirrors `MIN_ACTIONS` in `orchard::builder`.
const ORCHARD_MIN_ACTIONS: u64 = 2;

/// ZIP-317 fee in zatoshis. Matches the formula implemented by
/// `zcash_primitives::transaction::fees::zip317::FeeRule::fee_required`:
///
/// `fee = MARGINAL_FEE × max(GRACE_ACTIONS, transparent_actions + sapling_actions + orchard_actions)`
///
/// where:
///   - `transparent_actions = max(t_in, t_out)` (standard P2PKH sizing: each
///     input/output counts as one standard unit)
///   - `sapling_actions = 0` (Sapling not in scope)
///   - `orchard_actions` is computed by `BundleType::DEFAULT::num_actions`
///     which pads to a minimum of `MIN_ACTIONS = 2` when any Orchard items present.
fn zip317_fee(
    n_spends: u32,
    n_orchard_outputs: u32,
    n_transparent_inputs: u32,
    n_transparent_outputs: u32,
) -> u64 {
    let requested = u64::from(std::cmp::max(n_spends, n_orchard_outputs));
    let orchard_actions = if n_spends == 0 && n_orchard_outputs == 0 {
        0
    } else {
        std::cmp::max(ORCHARD_MIN_ACTIONS, requested)
    };
    // ZIP-317 transparent logical actions = max(t_in, t_out).
    // For standard P2PKH each input/output is one standard-sized unit.
    let transparent_actions = u64::from(std::cmp::max(n_transparent_inputs, n_transparent_outputs));
    let sapling_actions = 0u64;
    let logical = transparent_actions + sapling_actions + orchard_actions;
    MARGINAL_FEE * std::cmp::max(GRACE_ACTIONS, logical)
}

// ── Ironwood (NU6.3) — V6 transaction construction ──────────────────────────
//
// V6 (ZIP 229) appends a second, structurally-identical Orchard-family bundle
// — the Ironwood bundle — to the V5 format, proved against the updated
// (`PostNu6_3`) Action circuit and carrying `0x03`-versioned (ZIP 2005,
// quantum-recoverable) note plaintexts. [`build_ironwood_transaction`] below
// builds V6 transactions whose sole shielded pool is Ironwood: Ledger does not
// spend the legacy Orchard pool under the NU6.3 scope (the ZIP 2006 winddown /
// same-receiver path is out of scope — see the task's "Out of scope" note), so
// this is a distinct, additive path rather than an extension of the Orchard
// V5 `BuildInputs`/`Destination`/`OutputRequest` types above, which are left
// byte-unchanged. Change is always routed back into the Ironwood pool (never
// transparent), since an Ironwood bundle is mandatory for this builder.
//
// Reuses the shipped `build_for_pczt` + PCZT-role lifecycle, but:
//   - serializes as PCZT **v2** (the only encoding able to represent a V6 /
//     Ironwood-bearing PCZT — `pczt::v1` refuses both), with the upstream
//     HW-signer redaction applied first (see [`apply_v6_redaction`]);
//   - proves against a second, `PostNu6_3` proving key (see
//     [`ironwood_proving_key`]), distinct from the `FixedPostNu6_2` key the V5
//     path caches.

/// One Ironwood note to spend. Structurally identical to [`OrchardSpendInput`];
/// kept as a distinct type so the Orchard V5 path above is never touched here.
#[derive(Clone, Debug)]
pub struct IronwoodSpendInput {
    /// Raw 43-byte recipient (11-byte diversifier `d` || 32-byte `pk_d`).
    pub recipient: [u8; 43],
    /// Note value in zatoshis.
    pub value: u64,
    /// 32-byte rho (nullifier of the predecessor note in derivation order).
    pub rho: [u8; 32],
    /// 32-byte rseed (random seed for the note).
    pub rseed: [u8; 32],
    /// Merkle witness for this note, against the Ironwood commitment tree.
    pub merkle_path: incrementalmerkletree::MerklePath<orchard::tree::MerkleHashOrchard, 32>,
}

/// A destination for one V6/Ironwood output: the Ironwood pool or the
/// transparent pool. No plain-Orchard variant — see the module-level
/// "Out of scope" note above.
#[derive(Clone, Debug)]
pub enum IronwoodDestination {
    /// Ironwood payment address (same `orchard::Address` type as the Orchard
    /// pool; the pool is selected by which builder method is called, not by
    /// address encoding).
    Ironwood(OrchardAddress),
    /// Transparent payment address (P2PKH or P2SH).
    Transparent(TransparentAddress),
}

/// One output of a V6/Ironwood transaction.
#[derive(Clone, Debug)]
pub struct IronwoodOutputRequest {
    pub destination: IronwoodDestination,
    pub value: u64,
    /// Memo bytes for Ironwood outputs. Ignored for transparent outputs.
    pub memo: Option<Vec<u8>>,
}

/// Inputs to [`build_ironwood_transaction`].
pub struct IronwoodBuildInputs {
    pub network: Network,
    /// Target block height. Builder uses `target + DEFAULT_TX_EXPIRY_DELTA` for
    /// the expiry. Branch ID is derived from this height and must resolve to
    /// `Nu6_3` (or later) for the Ironwood bundle to be available.
    pub target_height: u32,
    /// Orchard/Ironwood full viewing key (the same key type spends from either
    /// pool — see [`IronwoodDestination`]). Required (`Some`) only when
    /// Ironwood spends are present.
    pub ironwood_fvk: Option<OrchardFvk>,
    /// Optional Outgoing Viewing Key for output recipients.
    pub ovk: Option<OutgoingViewingKey>,
    /// Internal-scope Ironwood change address. Required when there are
    /// Ironwood spends and `change > 0` (Ironwood→* flows: the surplus comes
    /// from the spent Ironwood notes, so change stays shielded). `None` is
    /// valid when no change is expected, or when change is taken transparent.
    pub change_address: Option<OrchardAddress>,
    /// Internal-scope transparent change address. Required when there are no
    /// Ironwood spends and `change > 0` (Public→Ironwood: the surplus comes
    /// from the transparent inputs, so change stays transparent — only the
    /// sent amount is shielded). `None` is valid when no change is expected,
    /// or when change is taken in Ironwood.
    pub transparent_change_address: Option<TransparentAddress>,
    /// Compressed secp256k1 pubkey (33 bytes) of `transparent_change_address`.
    /// Required (`Some`) whenever a transparent change output is produced. It
    /// is stamped into the change output's `bip32_derivation` so the Ledger
    /// device recognizes the output as change (and hides it) instead of
    /// displaying it as a third-party recipient. The device re-derives this
    /// pubkey from the change path and aborts if it does not match, so it
    /// must be the exact pubkey of `transparent_change_address`.
    pub transparent_change_pubkey: Option<[u8; 33]>,
    /// Non-hardened BIP-44 address index of `transparent_change_address`.
    /// Combined with the shared `account_index`, the internal scope (`1`),
    /// and the network coin type into the change path
    /// `m/44'/coin_type'/account'/1/address_index`. Required (`Some`)
    /// whenever a transparent change output is produced.
    pub transparent_change_address_index: Option<u32>,
    /// Ironwood anchor root (32-byte little-endian Pallas encoding).
    pub anchor: [u8; 32],
    /// ZIP-32 seed fingerprint of the wallet seed. Stamped onto every real
    /// Ironwood spend so the device can confirm the PCZT belongs to its seed.
    pub seed_fingerprint: [u8; 32],
    /// ZIP-32 account index the `ironwood_fvk` was derived at.
    pub account_index: u32,
    /// Caller-owned fee in zatoshis (FR-4, same convention as [`BuildInputs::fee`]).
    pub fee: u64,
    /// Ironwood notes to spend. Empty for Public→Ironwood.
    pub spends: Vec<IronwoodSpendInput>,
    /// Transparent (P2PKH) UTXOs to spend. Empty for Ironwood→* flows.
    pub transparent_inputs: Vec<TransparentInput>,
    pub outputs: Vec<IronwoodOutputRequest>,
}

/// Process-global proving key for the updated (`PostNu6_3`) Action circuit.
///
/// `PostNu6_3` is a *different* verifying key from the `FixedPostNu6_2` key
/// [`proving_key`] caches for the shipped V5 path — hence a second `OnceLock`
/// rather than reusing it (no V5 regression). Within one V6 transaction this
/// single key serves both the Orchard and the Ironwood bundle, since the pools
/// are "not distinguished by separate circuits" (ZIP 229).
pub(crate) fn ironwood_proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}

/// Build, prove, and serialize a redacted V6 PCZT for an Ironwood send.
///
/// # Errors
///
/// Returns [`Error::Craft`] for the same class of failures as
/// [`build_transaction`] (invalid note/anchor components, insufficient funds,
/// builder/PCZT-role errors), plus:
/// - NU6.3 not active at `target_height` (the Ironwood bundle requires V6);
/// - both Ironwood spends and Ironwood outputs are empty (no Ironwood bundle
///   would result — use [`build_transaction`] for a transparent-only send).
pub fn build_ironwood_transaction(inputs: IronwoodBuildInputs) -> Result<BuildOutput, Error> {
    let IronwoodBuildInputs {
        network,
        target_height,
        ironwood_fvk,
        ovk,
        change_address,
        transparent_change_address,
        transparent_change_pubkey,
        transparent_change_address_index,
        anchor,
        seed_fingerprint,
        account_index,
        fee,
        spends,
        transparent_inputs,
        outputs,
    } = inputs;

    let target = BlockHeight::from(target_height);
    if !network.is_nu_active(NetworkUpgrade::Nu6_3, target) {
        return Err(Error::Craft(format!(
            "NU6.3 is not active at target_height {target_height}; the Ironwood bundle \
             requires the V6 transaction format, which requires NU6.3 (or a later upgrade) \
             to be active"
        )));
    }
    if spends.is_empty() && transparent_inputs.is_empty() {
        return Err(Error::Craft(
            "no inputs: both ironwood spends and transparent inputs are empty".into(),
        ));
    }
    if outputs.is_empty() {
        return Err(Error::Craft("outputs list is empty".into()));
    }

    let has_ironwood = !spends.is_empty()
        || outputs
            .iter()
            .any(|o| matches!(o.destination, IronwoodDestination::Ironwood(_)));
    if !has_ironwood {
        return Err(Error::Craft(
            "no Ironwood bundle: ironwood spends and ironwood outputs are both empty — \
             use build_transaction for a transparent-only send"
                .into(),
        ));
    }

    // Zero-Ironwood-anchor guard. `Anchor::from_bytes([0u8; 32])` decodes to
    // `Some(Fp::zero())` — a syntactically-valid but semantically invalid
    // commitment-tree root — so this must run *before* `from_bytes`,
    // mirroring the Orchard V5 zero-anchor guard above, with a distinct
    // message for the Ironwood path.
    if anchor == [0u8; 32] {
        return Err(Error::Craft(
            "Ironwood anchor must be non-zero (zero is not a valid commitment-tree root)".into(),
        ));
    }
    let ironwood_anchor = orchard::Anchor::from_bytes(anchor)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Ironwood anchor encoding".into()))?;

    let build_config = BuildConfig::Standard {
        sapling_anchor: None,
        // No Orchard bundle: this builder is Ironwood-only (see the module
        // docs above — Ledger never spends the legacy Orchard pool under the
        // NU6.3 scope).
        orchard_anchor: None,
        ironwood_anchor: Some(ironwood_anchor),
        orchard_pool_bundle_type: OrchardBundleType::DEFAULT,
    };

    // ── 1. Builder + Ironwood spends + transparent inputs + non-change outputs ──
    let mut builder = Builder::new(network, target, build_config);

    let mut total_in: u64 = 0;
    if !spends.is_empty() {
        let fvk = ironwood_fvk.as_ref().ok_or_else(|| {
            Error::Craft("ironwood_fvk is required when Ironwood spends are present".into())
        })?;
        for spend in &spends {
            add_ironwood_spend(&mut builder, fvk, spend)?;
            total_in = total_in
                .checked_add(spend.value)
                .ok_or_else(|| Error::Craft("spend value overflow".into()))?;
        }
    }
    let n_spends = spends.len() as u32;

    for tin in &transparent_inputs {
        add_transparent_input(&mut builder, tin)?;
        total_in = total_in
            .checked_add(tin.value)
            .ok_or_else(|| Error::Craft("transparent input value overflow".into()))?;
    }
    let n_transparent_inputs = transparent_inputs.len() as u32;

    let mut total_out: u64 = 0;
    let mut n_ironwood_outputs: u32 = 0;
    let mut n_transparent_outputs: u32 = 0;
    for out in &outputs {
        add_ironwood_output(&mut builder, ovk.as_ref(), out)?;
        match out.destination {
            IronwoodDestination::Ironwood(_) => n_ironwood_outputs += 1,
            IronwoodDestination::Transparent(_) => n_transparent_outputs += 1,
        }
        total_out = total_out
            .checked_add(out.value)
            .ok_or_else(|| Error::Craft("output value overflow".into()))?;
    }

    // ── 2. Change derivation + fee validation ────────────────────────────────
    let fee_rule = FeeRule::standard();

    let outflow = total_out
        .checked_add(fee)
        .ok_or_else(|| Error::Craft("total_out + fee overflow".into()))?;
    if total_in < outflow {
        return Err(Error::Craft(format!(
            "insufficient funds: total_in={total_in} < total_out={total_out} + fee={fee}"
        )));
    }
    let change = total_in - outflow;

    // Route surplus change to the pool that funds it (mirrors the V5 fix in
    // `build_transaction` above, applied to the Ironwood pool):
    // - Ironwood spends present → Ironwood change output (Ironwood→*: the
    //   surplus comes from the spent Ironwood notes, so change stays shielded).
    // - No Ironwood spends → transparent change output (Public→Ironwood: the
    //   surplus comes from the transparent inputs). This keeps the change
    //   transparent instead of migrating the whole balance into the Ironwood
    //   pool — only the sent amount is shielded.
    let mut transparent_change_stamp: Option<(usize, [u8; 33], u32)> = None;
    if change > 0 {
        if n_spends > 0 {
            let change_addr = change_address.ok_or_else(|| {
                Error::Craft(
                    "change_address required for Ironwood change but none supplied".into(),
                )
            })?;
            let change_req = IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(change_addr),
                value: change,
                memo: None,
            };
            add_ironwood_output(&mut builder, ovk.as_ref(), &change_req)?;
            n_ironwood_outputs += 1;
        } else {
            let addr = transparent_change_address.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_address supplied".into(),
                )
            })?;
            let change_pubkey = transparent_change_pubkey.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_pubkey supplied — \
                     the device needs the change output's bip32_derivation to recognize it as \
                     change rather than a third-party recipient"
                        .into(),
                )
            })?;
            let change_address_index = transparent_change_address_index.ok_or_else(|| {
                Error::Craft(
                    "transparent change required but no transparent_change_address_index supplied"
                        .into(),
                )
            })?;
            let change_req = IronwoodOutputRequest {
                destination: IronwoodDestination::Transparent(addr),
                value: change,
                memo: None,
            };
            let change_output_index = n_transparent_outputs as usize;
            add_ironwood_output(&mut builder, None, &change_req)?;
            n_transparent_outputs += 1;
            transparent_change_stamp =
                Some((change_output_index, change_pubkey, change_address_index));
        }
    }

    // ZIP-317 Rev 1 validation (validation-only, mirrors `build_transaction`).
    let required_fee = zip317_fee_ironwood(
        n_spends,
        n_ironwood_outputs,
        n_transparent_inputs,
        n_transparent_outputs,
    );
    if fee != required_fee {
        return Err(Error::Craft(format!(
            "fee {fee} does not satisfy ZIP-317 for this transaction (requires {required_fee}); \
             fee selection is owned by the caller and must equal the ZIP-317 fee — \
             total_in={total_in}, total_out={total_out}, change={change}"
        )));
    }

    // Defense-in-depth: cross-check against the builder's own fee rule (which
    // already prices Ironwood actions under ZIP-317 Rev 1).
    let builder_fee = builder.get_fee(&fee_rule).map(u64::from).map_err(
        |e: zcash_primitives::transaction::builder::FeeError<Zip317FeeError>| {
            Error::Craft(format!("get_fee: {e:?}"))
        },
    )?;
    if builder_fee != fee {
        return Err(Error::Craft(format!(
            "fee mismatch — caller-supplied {fee}, builder {builder_fee}"
        )));
    }

    // ── 3. build_for_pczt + PCZT roles ───────────────────────────────────────
    let pczt_result = builder
        .build_for_pczt(OsRng, &fee_rule)
        .map_err(|e| Error::Craft(format!("build_for_pczt: {e:?}")))?;
    let n_actions_ironwood = pczt_result
        .pczt_parts
        .ironwood
        .as_ref()
        .map_or(0u32, |b| b.actions().len() as u32);

    let pczt: Pczt = Creator::build_from_parts(pczt_result.pczt_parts).ok_or_else(|| {
        Error::Craft("PCZT Creator rejected the PcztParts (unsupported tx version)".into())
    })?;

    let pczt = stamp_ironwood_spend_derivations(pczt, &network, seed_fingerprint, account_index)?;

    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| Error::Craft(format!("PCZT IoFinalizer: {e:?}")))?;

    // Generate the Ironwood proof, using the pool-shared `PostNu6_3` key.
    let prover = Prover::new(pczt);
    let pczt = if prover.requires_ironwood_proof() {
        prover
            .create_ironwood_proof(ironwood_proving_key())
            .map_err(|e| Error::Craft(format!("PCZT Prover (ironwood): {e:?}")))?
            .finish()
    } else {
        prover.finish()
    };

    let pczt = if !transparent_inputs.is_empty() || transparent_change_stamp.is_some() {
        stamp_transparent_derivations(
            pczt,
            &network,
            seed_fingerprint,
            account_index,
            &transparent_inputs,
            transparent_change_stamp,
        )?
    } else {
        pczt
    };

    // Upstream HW-signer redaction, then serialize as PCZT v2 — the only
    // encoding able to represent a V6 / Ironwood-bearing PCZT (`pczt::v1`
    // refuses both a V6 tx and a non-canonical Ironwood bundle).
    let pczt = apply_v6_redaction(pczt);
    let pczt_bytes = pczt::v2::Pczt::try_from(pczt)
        .map_err(|e| Error::Craft(format!("PCZT v2 encoding: {e:?}")))?
        .serialize();

    Ok(BuildOutput {
        pczt_bytes,
        fee,
        anchor_height: target_height.saturating_sub(DEFAULT_TX_EXPIRY_DELTA),
        n_actions_orchard: 0,
        n_transparent_inputs,
        n_transparent_outputs,
        n_actions_ironwood,
    })
}

/// Stamps **every** Ironwood action's spend in the PCZT with the ZIP-32
/// derivation path `m/32'/coin_type'/account'` and the wallet seed
/// fingerprint. Sibling of [`stamp_spend_derivations`] (Orchard), operating on
/// the Ironwood bundle via `update_ironwood_with` instead of
/// `update_orchard_with`; same rationale (dummy-spend padding must be stamped
/// too, since the device requires a path on every action).
fn stamp_ironwood_spend_derivations(
    pczt: Pczt,
    network: &Network,
    seed_fingerprint: [u8; 32],
    account_index: u32,
) -> Result<Pczt, Error> {
    const HARDENED_OFFSET: u32 = 1 << 31;
    if account_index >= HARDENED_OFFSET {
        return Err(Error::Craft(format!(
            "account_index {account_index} exceeds the ZIP-32 hardened range"
        )));
    }
    let derivation_path: Vec<u32> = vec![
        ChildIndex::hardened(32).index(),
        ChildIndex::hardened(network.coin_type()).index(),
        ChildIndex::hardened(account_index).index(),
    ];

    Updater::new(pczt)
        .update_ironwood_with(|mut updater| {
            let action_count = updater.bundle().actions().len();
            for i in 0..action_count {
                // Indices are hardened by construction, so `parse` is infallible
                // here; the map_err only satisfies the closure's error type.
                let derivation = Zip32Derivation::parse(seed_fingerprint, derivation_path.clone())
                    .map_err(|_| orchard::pczt::UpdaterError::InvalidIndex)?;
                updater.update_action_with(i, |mut action| {
                    action.set_spend_zip32_derivation(derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| Error::Craft(format!("PCZT Updater (ironwood zip32): {e:?}")))
        .map(Updater::finish)
}

fn add_ironwood_spend(
    builder: &mut Builder<Network, ()>,
    fvk: &OrchardFvk,
    spend: &IronwoodSpendInput,
) -> Result<(), Error> {
    let recipient = OrchardAddress::from_raw_address_bytes(&spend.recipient)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Ironwood recipient bytes in spend".into()))?;
    let rho = Rho::from_bytes(&spend.rho)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Ironwood rho bytes".into()))?;
    let rseed = RandomSeed::from_bytes(spend.rseed, &rho)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Ironwood rseed for the given rho".into()))?;
    // Ironwood spends must reconstruct the note at `NoteVersion::V3` — the
    // ZIP 2005 quantum-recoverable plaintext version `add_ironwood_spend`
    // requires (it rejects any other version).
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(spend.value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or_else(|| Error::Craft("Note::from_parts produced a non-canonical Ironwood note".into()))?;
    let merkle_path: orchard::tree::MerklePath = spend.merkle_path.clone().into();
    builder
        .add_ironwood_spend::<Zip317FeeError>(fvk.clone(), note, merkle_path)
        .map_err(|e| Error::Craft(format!("add_ironwood_spend: {e:?}")))?;
    Ok(())
}

fn add_ironwood_output(
    builder: &mut Builder<Network, ()>,
    ovk: Option<&OutgoingViewingKey>,
    out: &IronwoodOutputRequest,
) -> Result<(), Error> {
    let value = Zatoshis::from_u64(out.value)
        .map_err(|e| Error::Craft(format!("output value out of range: {e}")))?;
    match &out.destination {
        IronwoodDestination::Ironwood(addr) => {
            let memo = encode_memo(out.memo.as_deref())?;
            builder
                .add_ironwood_output::<Zip317FeeError>(ovk.cloned(), *addr, value, memo)
                .map_err(|e| Error::Craft(format!("add_ironwood_output: {e:?}")))?;
        }
        IronwoodDestination::Transparent(addr) => {
            builder
                .add_transparent_output(addr, value)
                .map_err(|e| Error::Craft(format!("add_transparent_output: {e:?}")))?;
        }
    }
    Ok(())
}

/// ZIP-317 Revision 1 fee in zatoshis for a V6/Ironwood transaction.
///
/// Identical formula to [`zip317_fee`], except the Ironwood bundle's actions
/// are priced exactly like Orchard actions (`nActionsIronwood`, ZIP-317
/// Revision 1). Kept as a separate function — rather than an extra parameter
/// on `zip317_fee` — so the shipped V5 fee model stays byte-identical.
fn zip317_fee_ironwood(
    n_ironwood_spends: u32,
    n_ironwood_outputs: u32,
    n_transparent_inputs: u32,
    n_transparent_outputs: u32,
) -> u64 {
    let requested = u64::from(std::cmp::max(n_ironwood_spends, n_ironwood_outputs));
    let ironwood_actions = if n_ironwood_spends == 0 && n_ironwood_outputs == 0 {
        0
    } else {
        // Same `BundleType::DEFAULT` padding policy as Orchard (MIN_ACTIONS = 2).
        std::cmp::max(ORCHARD_MIN_ACTIONS, requested)
    };
    let transparent_actions =
        u64::from(std::cmp::max(n_transparent_inputs, n_transparent_outputs));
    MARGINAL_FEE * std::cmp::max(GRACE_ACTIONS, transparent_actions + ironwood_actions)
}

/// Applies a representative upstream HW-signer PCZT redaction before v2
/// emission. Mirrors (without literally calling — `zcash_client_backend`'s
/// `redact_pczt_for_batch_signer` is not yet published for NU6.3, see the
/// implementation plan's "Repo-specific pitfalls") the semantics of
/// librustzcash PRs #2555 (memo-plaintext / ciphertext resolution), #2557
/// (redact `cv_net`), and #2593 (optional Orchard `cmx`):
///   - both bundles: drop each action's `cv_net` (recomputed from the spend
///     and output values plus `rcv`) and the spend's full viewing key
///     (superseded by the `zip32_derivation` already stamped on every
///     action); resolve `enc_ciphertext` down to its memo plaintext where
///     decryptable.
///   - the classic Orchard bundle only: also drop `cmx` (#2593) — the
///     receiver recomputes it from the output fields and the spend
///     nullifier. Always a no-op here (this builder never carries Orchard
///     actions), kept for symmetry should a co-present Orchard bundle ever
///     be added.
///   - the Ironwood bundle: `cmx` is kept on the wire for every `0x03` note,
///     as the device-facing PCZT v2 minimal field set requires it on the wire
///     for the quantum-recoverable note (the device does not recompute it).
///   - the bundle-level anchor is deliberately left untouched (unlike
///     #2557's Orchard-anchor redaction): it is still needed to re-parse the
///     already-proved PCZT (e.g. to stamp further metadata, or to inspect it
///     in tests), and clearing it is not required by this task's acceptance
///     criteria.
///   - `nullifier` and `rk` are never touched — the pczt Redactor role does
///     not expose a way to clear them, and the device's signing contract
///     needs both.
fn apply_v6_redaction(pczt: Pczt) -> Pczt {
    Redactor::new(pczt)
        .redact_orchard_with(|mut r| {
            r.redact_actions(|mut a| {
                a.clear_cv_net();
                a.clear_cmx();
                a.clear_spend_fvk();
                a.replace_enc_ciphertext_with_decrypted_memo_plaintext(NoteVersion::V2);
            });
        })
        .redact_ironwood_with(|mut r| {
            r.redact_actions(|mut a| {
                a.clear_cv_net();
                a.clear_spend_fvk();
                a.replace_enc_ciphertext_with_decrypted_memo_plaintext(NoteVersion::V3);
            });
        })
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Marking, Position, Retention};
    use orchard::{
        keys::{Scope, SpendingKey},
        note::ExtractedNoteCommitment,
        tree::MerkleHashOrchard,
    };
    use shardtree::{store::memory::MemoryShardStore, ShardTree};
    use zip32::AccountId;

    /// Construct a deterministic Orchard FVK from a fixed seed.
    fn make_fvk() -> OrchardFvk {
        let sk = SpendingKey::from_zip32_seed(&[1u8; 32], 133, AccountId::ZERO).unwrap();
        OrchardFvk::from(&sk)
    }

    /// Build a one-leaf ShardTree containing `cmx`, returning `(anchor, path)`.
    fn synthetic_anchor_and_path(
        leaf: MerkleHashOrchard,
    ) -> (
        [u8; 32],
        incrementalmerkletree::MerklePath<MerkleHashOrchard, 32>,
    ) {
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let mp = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();
        (root.to_bytes(), mp)
    }

    /// Build a multi-leaf ShardTree containing `leaves` in order, returning the
    /// shared anchor and one Merkle path per leaf.
    fn synthetic_anchor_and_paths(
        leaves: &[MerkleHashOrchard],
    ) -> (
        [u8; 32],
        Vec<incrementalmerkletree::MerklePath<MerkleHashOrchard, 32>>,
    ) {
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        let last = leaves.len() - 1;
        for (i, leaf) in leaves.iter().enumerate() {
            let retention = if i == last {
                Retention::Checkpoint {
                    id: 0,
                    marking: Marking::Marked,
                }
            } else {
                Retention::Marked
            };
            tree.append(*leaf, retention).unwrap();
        }
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let paths = (0..leaves.len())
            .map(|i| {
                tree.witness_at_checkpoint_id(Position::from(i as u64), &0)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        (root.to_bytes(), paths)
    }

    /// NU5 (Orchard) activation heights.
    fn nu5_activation_height(network: Network) -> u32 {
        match network {
            Network::MainNetwork => 1_687_104,
            Network::TestNetwork => 1_842_420,
        }
    }

    /// NU6.3 (Ironwood) activation heights.
    fn nu6_3_activation_height(network: Network) -> u32 {
        match network {
            Network::MainNetwork => 3_428_143,
            Network::TestNetwork => 4_134_000,
        }
    }

    /// Make a single-Ironwood-spend `IronwoodBuildInputs` that balances
    /// exactly (no change).
    fn make_single_ironwood_spend_inputs(
        network: Network,
        out_destination: IronwoodDestination,
        out_value: u64,
    ) -> IronwoodBuildInputs {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let fee = match &out_destination {
            IronwoodDestination::Ironwood(_) => zip317_fee_ironwood(1, 1, 0, 0),
            IronwoodDestination::Transparent(_) => zip317_fee_ironwood(1, 0, 0, 1),
        };
        let spend_value = out_value + fee;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let change = fvk.address_at(0u32, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::External));

        IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: Some(fvk),
            ovk,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![IronwoodSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequest {
                destination: out_destination,
                value: out_value,
                memo: None,
            }],
        }
    }

    /// Make a single-spend BuildInputs that balances exactly (no change).
    fn make_single_spend_inputs(
        network: Network,
        out_destination: Destination,
        out_value: u64,
    ) -> BuildInputs {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let fee = match &out_destination {
            Destination::Orchard(_) => zip317_fee(1, 1, 0, 0),
            Destination::Transparent(_) => zip317_fee(1, 0, 0, 1),
        };
        let spend_value = out_value + fee;
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let change = fvk.address_at(0u32, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::External));

        BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk),
            ovk,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: out_destination,
                value: out_value,
                memo: None,
            }],
        }
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

    /// A deterministic compressed secp256k1 pubkey (33 bytes) for testing.
    fn make_test_pubkey() -> [u8; 33] {
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x01u8; 32]).unwrap();
        secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
    }

    /// HASH160 (RIPEMD160 ∘ SHA256) of a compressed pubkey — the value that a
    /// standard P2PKH scriptPubKey commits to. `add_transparent_p2pkh_input`
    /// rejects an input whose scriptPubKey hash does not equal this.
    fn pubkey_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
        use bitcoin::hashes::{hash160, Hash};
        hash160::Hash::hash(pubkey).to_byte_array()
    }

    /// Make a minimal TransparentInput for unit tests. The scriptPubKey is the
    /// real P2PKH script paying to `hash160(pubkey)`, so the builder's
    /// pubkey↔script consistency check passes.
    fn make_transparent_input(value: u64) -> TransparentInput {
        let pubkey = make_test_pubkey();
        TransparentInput {
            pubkey,
            // txid in internal (little-endian) byte order.
            txid: [0x01u8; 32],
            vout: 0,
            script_pubkey: make_p2pkh_script(pubkey_hash160(&pubkey)),
            value,
            derivation_scope: 0,
            derivation_address_index: 0,
        }
    }

    // ── Error-path tests (fast, no proof generation) ──────────────────────────

    #[test]
    fn invalid_anchor_encoding_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let dummy_recipient = fvk.address_at(0u32, Scope::External);
        let dummy_note = Note::from_parts(dummy_recipient, NoteValue::from_raw(1), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let (_anchor, path) = synthetic_anchor_and_path(MerkleHashOrchard::from_cmx(
            &ExtractedNoteCommitment::from(dummy_note.commitment()),
        ));
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0xff; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 50,
            spends: vec![OrchardSpendInput {
                recipient: dummy_note.recipient().to_raw_address_bytes(),
                value: 100,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(dummy_recipient),
                value: 50,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("invalid Orchard anchor encoding")),
            "got: {err}"
        );
    }

    #[test]
    fn zero_anchor_with_orchard_bundle_returns_craft_error() {
        // A syntactically-valid (all-zero) byte string decodes fine via
        // `orchard::Anchor::from_bytes`, but the all-zero value is not a valid
        // commitment-tree root, so a bundle-carrying flow must reject it up front
        // with a distinct error (not the generic "invalid encoding" one).
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let recipient = fvk.address_at(0u32, Scope::External);
        let note = Note::from_parts(recipient, NoteValue::from_raw(20_000), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (_anchor, path) = synthetic_anchor_and_path(leaf);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32], // zero anchor is invalid when a bundle is present
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: 20_000,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: 10_000,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s)
                if s.contains("Orchard anchor must be non-zero")
                    && !s.contains("invalid Orchard anchor encoding")),
            "zero anchor must be rejected with the dedicated non-zero error, got: {err}"
        );
    }

    #[test]
    fn empty_spends_and_transparent_inputs_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(fvk.address_at(0u32, Scope::External)),
                value: 1,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("no inputs")),
            "got: {err}"
        );
    }

    #[test]
    fn empty_outputs_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let recipient = fvk.address_at(0u32, Scope::External);
        let note = Note::from_parts(recipient, NoteValue::from_raw(1), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: 1,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("outputs list is empty")),
            "got: {err}"
        );
    }

    #[test]
    fn nu5_not_active_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: 100,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(20_000)],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(TransparentAddress::PublicKeyHash(
                    [0x11u8; 20],
                )),
                value: 1,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s)
                if s.contains("NU5 is not active") && !s.contains("Orchard")),
            "transparent-only NU5 error must not be attributed to Orchard, got: {err}"
        );
    }

    #[test]
    fn encode_memo_empty_for_none() {
        let m = encode_memo(None).unwrap();
        assert_eq!(m, MemoBytes::empty());
    }

    #[test]
    fn encode_memo_passes_through_valid_bytes() {
        let m = encode_memo(Some(b"hello"));
        assert!(m.is_ok());
    }

    #[test]
    fn encode_memo_rejects_too_long() {
        let big = vec![0u8; 1024];
        let err = encode_memo(Some(&big)).unwrap_err();
        assert!(matches!(&err, Error::Craft(s) if s.contains("invalid memo bytes")));
    }

    // ── ZIP-317 fee math (no proof gen) ───────────────────────────────────────

    #[test]
    fn zip317_fee_one_spend_one_orchard_output_is_10000() {
        assert_eq!(zip317_fee(1, 1, 0, 0), 10_000);
    }

    #[test]
    fn zip317_fee_one_spend_one_orchard_one_transparent_out_is_15000() {
        // orchard=2 (padded), transparent=max(0,1)=1 → logical=3 → 15_000.
        assert_eq!(zip317_fee(1, 1, 0, 1), 15_000);
    }

    #[test]
    fn zip317_fee_two_spends_three_outputs_is_15000() {
        assert_eq!(zip317_fee(2, 3, 0, 0), 15_000);
    }

    #[test]
    fn zip317_change_output_does_not_bump_fee_when_grace_bound() {
        assert_eq!(zip317_fee(1, 1, 0, 0), 10_000);
        assert_eq!(zip317_fee(1, 2, 0, 0), 10_000);
    }

    #[test]
    fn zip317_change_output_bumps_fee_past_grace_bound() {
        assert_eq!(zip317_fee(1, 2, 0, 0), 10_000);
        assert_eq!(zip317_fee(1, 3, 0, 0), 15_000);
    }

    #[test]
    fn zip317_no_spends_no_outputs_is_grace_bound() {
        assert_eq!(zip317_fee(0, 0, 0, 0), 10_000);
    }

    // ── ZIP-317 with transparent inputs (new) ─────────────────────────────────

    #[test]
    fn zip317_one_transparent_in_one_transparent_out_is_10000() {
        // transparent_actions = max(1,1) = 1; orchard = 0; logical = 1 → grace → 10_000.
        assert_eq!(zip317_fee(0, 0, 1, 1), 10_000);
    }

    #[test]
    fn zip317_two_transparent_in_one_transparent_out_is_10000() {
        // transparent_actions = max(2,1) = 2; orchard = 0; logical = 2 → grace → 10_000.
        assert_eq!(zip317_fee(0, 0, 2, 1), 10_000);
    }

    #[test]
    fn zip317_one_orchard_spend_one_orchard_out_one_transparent_in() {
        // orchard = max(2, max(1,1)) = 2; transparent = max(1,0) = 1; logical = 3 → 15_000.
        assert_eq!(zip317_fee(1, 1, 1, 0), 15_000);
    }

    // ── scriptPubKey encoding and txid endianness pinning ─────────────────────

    /// Verify that a standard 25-byte P2PKH scriptPubKey round-trips through the
    /// exact encoding the production `add_transparent_input` helper uses: a raw
    /// script with a prepended CompactSize length prefix, parsed by
    /// `Script::read`. This pins the convention (raw scriptPubKey bytes from the
    /// host, CompactSize-prefixed before `Script::read`).
    #[test]
    fn p2pkh_script_pubkey_compactsize_roundtrip() {
        use zcash_transparent::address::Script;
        let hash = [0xabu8; 20];
        let raw = make_p2pkh_script(hash);
        assert_eq!(raw.len(), 25, "standard P2PKH script is exactly 25 bytes");

        // Mirror production: prepend the 1-byte CompactSize varint before Script::read.
        let mut prefixed = Vec::with_capacity(1 + raw.len());
        prefixed.push(raw.len() as u8);
        prefixed.extend_from_slice(&raw);

        let script = Script::read(prefixed.as_slice())
            .expect("Script::read must accept a CompactSize-prefixed P2PKH script");

        // Writing it back reproduces the CompactSize-prefixed encoding exactly.
        let mut written = Vec::new();
        script.write(&mut written).unwrap();
        assert_eq!(
            written, prefixed,
            "Script must round-trip to its prefixed form"
        );
        assert_eq!(script.serialized_size(), prefixed.len());

        let value = Zatoshis::from_u64(10_000).unwrap();
        let txout = zcash_transparent::bundle::TxOut::new(value, script);
        assert_eq!(u64::from(txout.value()), 10_000);
    }

    /// Verify txid byte order: OutPoint::new takes internal (little-endian)
    /// byte order and returns the same bytes via txid().as_ref().
    #[test]
    fn txid_internal_byte_order_roundtrip() {
        let txid_le: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let outpoint = zcash_transparent::bundle::OutPoint::new(txid_le, 3);
        let retrieved: &[u8; 32] = outpoint.txid().as_ref();
        assert_eq!(
            *retrieved, txid_le,
            "OutPoint stores txid in the byte order supplied to ::new (internal/LE)"
        );
        assert_eq!(outpoint.n(), 3);
    }

    /// Verify that an invalid 33-byte pubkey (all 0xff) is rejected.
    #[test]
    fn invalid_transparent_pubkey_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let t_dest = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let fee = zip317_fee(0, 0, 1, 1);
        let out_value = 10_000u64;
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![TransparentInput {
                pubkey: [0xffu8; 33], // invalid
                txid: [0x01u8; 32],
                vout: 0,
                script_pubkey: make_p2pkh_script([0x11u8; 20]),
                value: out_value + fee,
                derivation_scope: 0,
                derivation_address_index: 0,
            }],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_dest),
                value: out_value,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("invalid transparent pubkey")),
            "got: {err}"
        );
    }

    /// Verify that a missing transparent_change_address when surplus exists and
    /// no Orchard bundle is present returns the expected error.
    #[test]
    fn missing_transparent_change_address_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let t_dest = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let fee = zip317_fee(0, 0, 1, 1); // 10_000
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(change),
            transparent_change_address: None, // intentionally missing
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(30_000)],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_dest),
                value: 10_000,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("transparent change required")),
            "got: {err}"
        );
    }

    // ── Happy-path tests (proof generation; slow on first run) ────────────────
    //
    // These tests exercise the full PCZT pipeline. They are NOT `#[ignore]`'d
    // because we need the coverage they produce on craft.rs.

    #[test]
    fn private_to_private_produces_valid_pczt() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let inputs = make_single_spend_inputs(
            Network::MainNetwork,
            Destination::Orchard(recipient),
            10_000,
        );
        let out = build_transaction(inputs).expect("private→private must succeed");
        assert!(out.pczt_bytes.len() > 8);
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        // PCZT version is 1 in LE.
        assert_eq!(&out.pczt_bytes[4..8], &1u32.to_le_bytes());
        // Balances exactly (no change output); Orchard still pads to
        // MIN_ACTIONS = 2, so n_actions >= 1 holds comfortably.
        assert!(out.n_actions_orchard >= 1);
        assert!(out.fee >= 10_000);
        assert_eq!(out.n_transparent_inputs, 0);
        assert_eq!(out.n_transparent_outputs, 0);
    }

    #[test]
    fn zip32_derivation_stamped_on_every_action() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut inputs = make_single_spend_inputs(
            Network::MainNetwork,
            Destination::Orchard(recipient),
            10_000,
        );
        inputs.seed_fingerprint = [0x7c; 32];
        inputs.account_index = 3;
        let out = build_transaction(inputs).expect("build must succeed");

        // Re-parse and inspect the Orchard spends via the Updater's read access.
        let parsed = Pczt::parse(&out.pczt_bytes).expect("PCZT must parse");
        Updater::new(parsed)
            .update_orchard_with(|updater| {
                let actions = updater.bundle().actions();
                // With a change output the builder pads to >= 2 actions (one
                // carries a dummy spend). The device requires a path on EVERY
                // action, so every action must be stamped.
                assert!(actions.len() >= 2, "expected padding to >= 2 actions");
                let expected_path: Vec<u32> = vec![
                    ChildIndex::hardened(32).index(),
                    ChildIndex::hardened(133).index(), // mainnet coin type
                    ChildIndex::hardened(3).index(),
                ];
                for action in actions {
                    let d = action
                        .spend()
                        .zip32_derivation()
                        .as_ref()
                        .expect("every action's spend must carry a derivation path");
                    assert_eq!(d.seed_fingerprint(), &[0x7c; 32]);
                    let path: Vec<u32> = d.derivation_path().iter().map(|i| i.index()).collect();
                    assert_eq!(path, expected_path);
                }
                Ok(())
            })
            .expect("updater read-back must succeed");
    }

    /// Cross-check that the built PCZT carries every field the Ledger device's
    /// PCZT parser consumes per Orchard action, at the exact sizes/shape it
    /// expects (`app-rust-zcash` `src/parser/pczt/orchard.rs` and the
    /// `tests/application_client/pczt.py` reference helper). Guards against a
    /// silent drift if `orchard`/`pczt` change their wire layout.
    #[test]
    fn pczt_matches_device_orchard_wire_format() {
        // Device-side constants (see app-rust-zcash pczt.py).
        const ORCHARD_ENC_CIPHERTEXT_SIZE: usize = 580;
        const ORCHARD_OUT_CIPHERTEXT_SIZE: usize = 80;

        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let inputs = make_single_spend_inputs(
            Network::MainNetwork,
            Destination::Orchard(recipient),
            10_000,
        );
        let out = build_transaction(inputs).expect("build must succeed");

        let parsed = Pczt::parse(&out.pczt_bytes).expect("PCZT must parse");
        Updater::new(parsed)
            .update_orchard_with(|updater| {
                let bundle = updater.bundle();
                assert!(!bundle.actions().is_empty(), "no orchard actions");
                for action in bundle.actions() {
                    let spend = action.spend();
                    // Per-action fields the device reads, in APDU order:
                    // cv_net(32), nullifier(32), rk(32), alpha(32), zip32 path,
                    // cmx(32), ephemeral_key(32), enc_ciphertext, out_ciphertext.
                    assert_eq!(action.cv_net().to_bytes().len(), 32);
                    assert_eq!(spend.nullifier().to_bytes().len(), 32);
                    assert!(spend.alpha().is_some(), "device requires per-action alpha");
                    assert!(
                        spend.zip32_derivation().is_some(),
                        "device requires per-action zip32 derivation"
                    );
                    let note = action.output().encrypted_note();
                    assert_eq!(note.epk_bytes.len(), 32);
                    assert_eq!(
                        note.enc_ciphertext.len(),
                        ORCHARD_ENC_CIPHERTEXT_SIZE,
                        "enc_ciphertext size must match device constant"
                    );
                    assert_eq!(
                        note.out_ciphertext.len(),
                        ORCHARD_OUT_CIPHERTEXT_SIZE,
                        "out_ciphertext size must match device constant"
                    );
                    assert_eq!(action.output().cmx().to_bytes().len(), 32);
                }
                // Bundle-level fields the device reads after the actions:
                // flags(1), value_sum, anchor(32).
                assert_eq!(bundle.anchor().to_bytes().len(), 32);
                Ok(())
            })
            .expect("updater read-back must succeed");
    }

    #[test]
    fn private_to_public_produces_valid_pczt() {
        let t_addr = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let inputs = make_single_spend_inputs(
            Network::MainNetwork,
            Destination::Transparent(t_addr),
            10_000,
        );
        let out = build_transaction(inputs).expect("private→public must succeed");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert!(out.n_actions_orchard >= 1);
        assert_eq!(out.n_transparent_inputs, 0);
        assert_eq!(out.n_transparent_outputs, 1);
    }

    #[test]
    fn multi_spend_with_real_change_output_produces_valid_pczt() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();

        // Two distinct spend notes (different rseed + value → distinct
        // commitment and nullifier).
        let spend_values = [20_000u64, 25_000u64];
        let rseeds = [[0xab; 32], [0xcd; 32]];
        let notes: Vec<Note> = spend_values
            .iter()
            .zip(rseeds.iter())
            .map(|(&v, &r)| {
                let rseed = RandomSeed::from_bytes(r, &rho).into_option().unwrap();
                Note::from_parts(recipient, NoteValue::from_raw(v), rho, rseed, NoteVersion::V2)
                    .into_option()
                    .unwrap()
            })
            .collect();
        let leaves: Vec<MerkleHashOrchard> = notes
            .iter()
            .map(|n| MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(n.commitment())))
            .collect();
        let (anchor, paths) = synthetic_anchor_and_paths(&leaves);

        let out_value = 10_000u64;
        // 2 spends + 1 recipient + 1 change = 2 orchard outputs → 10_000.
        let fee = zip317_fee(2, 2, 0, 0);
        let total_in: u64 = spend_values.iter().sum();
        let change = total_in - out_value - fee;
        assert!(
            change > 0,
            "test must exercise a real (positive) change output"
        );

        let spends = (0..2)
            .map(|i| OrchardSpendInput {
                recipient: notes[i].recipient().to_raw_address_bytes(),
                value: spend_values[i],
                rho: rho.to_bytes(),
                rseed: rseeds[i],
                merkle_path: paths[i].clone(),
            })
            .collect();

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends,
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("multi-spend with change must succeed");
        assert_eq!(out.fee, fee, "fee must echo the caller-supplied value");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        // 2 spends + 2 outputs (recipient + change) → exactly 2 orchard actions.
        assert_eq!(out.n_actions_orchard, 2);
    }

    #[test]
    fn surplus_below_change_output_cost_is_rejected() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();

        // Single spend of 20_000.
        let spend_value = 20_000u64;
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        // Two recipient outputs of 4_000 each → total_out = 8_000. Supplied
        // fee = 10_000 (the no-change fee for 1 spend + 2 orchard outputs).
        //   change = 20_000 − 8_000 − 10_000 = 2_000 > 0
        // so a change output is added, making 3 orchard outputs whose ZIP-317
        // fee is 15_000. The supplied 10_000 no longer matches, and the 2_000
        // surplus cannot fund the +5_000 extra-action cost → rejected. This is
        // the band the old dead "surplus-into-fee" branch tried (and failed) to
        // absorb.
        let fee = 10_000u64; // == zip317_fee(1, 2, 0, 0)
        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![
                OutputRequest {
                    destination: Destination::Orchard(recipient),
                    value: 4_000,
                    memo: None,
                },
                OutputRequest {
                    destination: Destination::Orchard(recipient),
                    value: 4_000,
                    memo: None,
                },
            ],
        };

        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s)
                if s.contains("does not satisfy ZIP-317") && s.contains("requires 15000")),
            "got: {err}"
        );
    }

    #[test]
    fn fee_exceeding_inputs_returns_insufficient_funds() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let spend_value = 10_000u64;
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        // out 10_000 + fee 5_000 = 15_000 > total_in 10_000 → insufficient funds.
        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 5_000,
            spends: vec![OrchardSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: 10_000,
                memo: None,
            }],
        };

        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("insufficient funds")),
            "got: {err}"
        );
    }

    #[test]
    fn proving_key_is_cached_across_calls() {
        // Initialise — first call may be slow.
        let pk1: *const ProvingKey = proving_key();
        // Subsequent call must return the same pointer (same OnceLock cell).
        let pk2: *const ProvingKey = proving_key();
        assert_eq!(pk1, pk2, "proving_key() must return cached pointer");
    }

    // ── Public→Public happy path ───────────────────────────────────────────────

    /// Public→Public: one transparent input + two transparent outputs (recipient + change).
    /// Must produce a PCZT with a transparent bundle and NO Orchard bundle.
    #[test]
    fn public_to_public_produces_transparent_only_pczt() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let t_recv = TransparentAddress::PublicKeyHash([0x22u8; 20]);
        let t_change = TransparentAddress::PublicKeyHash([0x33u8; 20]);
        // 1 t_in + 2 t_out → max(1,2) = 2 transparent actions → grace → 10_000.
        let fee = zip317_fee(0, 0, 1, 2); // 10_000
        let out_value = 15_000u64;
        let change_value = 5_000u64;
        let total_in = out_value + change_value + fee;

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: Some(t_change),
            transparent_change_pubkey: Some(make_test_pubkey()),
            transparent_change_address_index: Some(0),
            anchor: [0u8; 32], // ignored for transparent-only
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_recv),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("public→public must succeed");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert_eq!(
            &out.pczt_bytes[4..8],
            &1u32.to_le_bytes(),
            "transparent-only PCZT must serialize as v1; the device signer rejects any other header version"
        );
        assert_eq!(
            out.n_actions_orchard, 0,
            "Public→Public must have no Orchard actions"
        );
        assert_eq!(out.n_transparent_inputs, 1);
        assert_eq!(out.n_transparent_outputs, 2, "recipient + change");
        assert_eq!(out.fee, fee);
    }

    // ── parse::parse_pczt round-trips ─────────────────────────────────────────

    /// A private→public transaction (Orchard spend → transparent output) built
    /// here must round-trip through [`crate::parse::parse_pczt`] into the
    /// structured form the device signer consumes: an Orchard bundle with fully
    /// populated actions plus one transparent (recipient) output.
    #[test]
    fn parse_pczt_private_to_public_roundtrips() {
        let t_addr = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let inputs =
            make_single_spend_inputs(Network::MainNetwork, Destination::Transparent(t_addr), 10_000);
        let out = build_transaction(inputs).expect("private→public must succeed");

        let parsed = crate::parse::parse_pczt(&out.pczt_bytes).expect("parse_pczt must succeed");

        // Global header (mainnet → coin type 133, V5).
        assert_eq!(parsed.global.tx_version, 5);
        assert_eq!(parsed.global.coin_type, 133);

        // Orchard bundle present with fully-populated actions.
        let bundle = parsed.orchard_bundle.expect("orchard bundle must be present");
        assert!(!bundle.actions.is_empty(), "expected >= 1 orchard action");
        assert_eq!(bundle.anchor.len(), 32);
        for action in &bundle.actions {
            // Fixed-width fields at the sizes the device parser expects.
            assert_eq!(action.spend_recipient.len(), 43);
            assert_eq!(action.recipient.len(), 43);
            assert_eq!(action.alpha.len(), 32);
            assert_eq!(action.rcv.len(), 32);
            assert_eq!(action.enc_ciphertext.len(), 580);
            assert_eq!(action.out_ciphertext.len(), 80);
            // The Orchard spend path is fully hardened: 32'/133'/<account>'.
            assert_eq!(action.signing_path, "32'/133'/0'");
            assert_eq!(action.seed_fingerprint, [0x42u8; 32]);
        }

        // One transparent recipient output, no change derivation on it.
        assert!(parsed.transparent_inputs.is_empty());
        assert_eq!(parsed.transparent_outputs.len(), 1);
        assert!(parsed.transparent_outputs[0].derivation.is_none());
        assert_eq!(parsed.transparent_outputs[0].value, 10_000);
    }

    /// A public→public transaction (transparent input + recipient + change) must
    /// round-trip with no Orchard bundle, the input carrying its single signing
    /// derivation, and exactly one of the two outputs (the change) carrying one.
    #[test]
    fn parse_pczt_public_to_public_roundtrips() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let t_recv = TransparentAddress::PublicKeyHash([0x22u8; 20]);
        let t_change = TransparentAddress::PublicKeyHash([0x33u8; 20]);
        let fee = zip317_fee(0, 0, 1, 2);
        let out_value = 15_000u64;
        let change_value = 5_000u64;
        let total_in = out_value + change_value + fee;
        let input_pubkey = make_test_pubkey();

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: Some(t_change),
            transparent_change_pubkey: Some(make_test_pubkey()),
            transparent_change_address_index: Some(0),
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_recv),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("public→public must succeed");
        let parsed = crate::parse::parse_pczt(&out.pczt_bytes).expect("parse_pczt must succeed");

        // Purely transparent: no Orchard bundle.
        assert!(parsed.orchard_bundle.is_none());

        // Single input carries exactly one derivation at m/44'/133'/0'/0/0.
        assert_eq!(parsed.transparent_inputs.len(), 1);
        let input = &parsed.transparent_inputs[0];
        assert_eq!(input.value, total_in);
        assert_eq!(input.prevout_txid, [0x01u8; 32]);
        assert_eq!(input.sighash_type, 1, "SIGHASH_ALL");
        assert_eq!(input.derivation.pubkey, input_pubkey);
        assert_eq!(input.derivation.signing_path, "44'/133'/0'/0/0");

        // Recipient + change outputs; exactly the change carries a derivation.
        assert_eq!(parsed.transparent_outputs.len(), 2);
        let with_deriv = parsed
            .transparent_outputs
            .iter()
            .filter(|o| o.derivation.is_some())
            .count();
        assert_eq!(with_deriv, 1, "only the change output carries a derivation");
    }

    /// Public→Public: re-parse the serialized PCZT and assert that the device's
    /// hard requirements are met — every transparent input carries exactly one
    /// `bip32_derivation` (its signing path), the change output carries one (so
    /// the device recognizes it as change), and the recipient output carries none
    /// (so the device shows it as an external payment).
    #[test]
    fn public_to_public_stamps_transparent_bip32_derivations() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let input_pubkey = make_test_pubkey();
        let change_pubkey = {
            use secp256k1::{Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[0x02u8; 32]).unwrap();
            secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
        };
        let t_recv = TransparentAddress::PublicKeyHash([0x22u8; 20]);
        let t_change = TransparentAddress::PublicKeyHash([0x33u8; 20]);
        let fee = zip317_fee(0, 0, 1, 2);
        let out_value = 15_000u64;
        let change_value = 5_000u64;
        let total_in = out_value + change_value + fee;
        let seed_fingerprint = [0x42u8; 32];

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: Some(t_change),
            transparent_change_pubkey: Some(change_pubkey),
            transparent_change_address_index: Some(7),
            anchor: [0u8; 32],
            seed_fingerprint,
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![TransparentInput {
                pubkey: input_pubkey,
                txid: [0x01u8; 32],
                vout: 0,
                script_pubkey: make_p2pkh_script(pubkey_hash160(&input_pubkey)),
                value: total_in,
                derivation_scope: 0,
                derivation_address_index: 3,
            }],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_recv),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("public→public must succeed");
        let parsed = Pczt::parse(&out.pczt_bytes).expect("PCZT must re-parse");

        Updater::new(parsed)
            .update_transparent_with(|updater| {
                let bundle = updater.bundle();

                // Input: exactly one derivation keyed by the input pubkey, at the
                // expected external signing path m/44'/133'/0'/0/3.
                let input = &bundle.inputs()[0];
                assert_eq!(
                    input.bip32_derivation().len(),
                    1,
                    "device requires exactly one transparent input bip32 derivation"
                );
                let in_deriv = input
                    .bip32_derivation()
                    .get(&input_pubkey)
                    .expect("input derivation must be keyed by the input pubkey");
                // `bip32::ChildNumber::index()` strips the hardened bit, so compare
                // de-hardened indices and hardened flags separately. Expected
                // external signing path m/44'/133'/0'/0/3.
                let in_indices: Vec<u32> =
                    in_deriv.derivation_path().iter().map(|c| c.index()).collect();
                let in_hardened: Vec<bool> = in_deriv
                    .derivation_path()
                    .iter()
                    .map(|c| c.is_hardened())
                    .collect();
                assert_eq!(in_indices, vec![44, 133, 0, 0, 3]);
                assert_eq!(in_hardened, vec![true, true, true, false, false]);
                assert_eq!(in_deriv.seed_fingerprint(), &seed_fingerprint);

                // Outputs: recipient (index 0) has no derivation; change (index 1,
                // appended last) has one, keyed by the change pubkey, at the
                // internal change path m/44'/133'/0'/1/7.
                let recipient = &bundle.outputs()[0];
                assert!(
                    recipient.bip32_derivation().is_empty(),
                    "recipient output must have no bip32 derivation"
                );
                let change = &bundle.outputs()[1];
                let out_deriv = change
                    .bip32_derivation()
                    .get(&change_pubkey)
                    .expect("change output must carry a derivation keyed by the change pubkey");
                // Expected internal change path m/44'/133'/0'/1/7.
                let out_indices: Vec<u32> =
                    out_deriv.derivation_path().iter().map(|c| c.index()).collect();
                let out_hardened: Vec<bool> = out_deriv
                    .derivation_path()
                    .iter()
                    .map(|c| c.is_hardened())
                    .collect();
                assert_eq!(out_indices, vec![44, 133, 0, 1, 7]);
                assert_eq!(out_hardened, vec![true, true, true, false, false]);
                assert_eq!(out_deriv.seed_fingerprint(), &seed_fingerprint);
                Ok(())
            })
            .expect("transparent updater read-back must succeed");
    }

    /// Public→Public with exact balance (no change needed).
    #[test]
    fn public_to_public_exact_balance_no_change() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let t_recv = TransparentAddress::PublicKeyHash([0x22u8; 20]);
        let fee = zip317_fee(0, 0, 1, 1); // 10_000
        let out_value = 10_000u64;
        let total_in = out_value + fee;

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None, // no change needed
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![OutputRequest {
                destination: Destination::Transparent(t_recv),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("public→public exact balance must succeed");
        assert_eq!(out.n_actions_orchard, 0);
        assert_eq!(out.n_transparent_inputs, 1);
        assert_eq!(out.n_transparent_outputs, 1);
    }

    // ── Public→Private happy path ──────────────────────────────────────────────

    /// Public→Private: one transparent input + one Orchard output (anchor-only).
    ///
    /// There are no real Orchard spends, so the builder injects dummy (value-0)
    /// spends to populate the bundle. A dummy spend's in-circuit Merkle-root
    /// check is disabled, so any validly-encoded anchor is accepted — this is the
    /// exact situation `zcash_sync::witness::fetch_orchard_anchor` serves (it
    /// returns an anchor with an empty witness list). The result must carry BOTH
    /// a transparent bundle (the input) and an Orchard bundle (output + dummies).
    #[test]
    fn public_to_private_produces_orchard_output_pczt() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);

        // A validly-encoded anchor from a synthetic one-leaf tree. Its value is
        // irrelevant here because only value-0 dummy spends are present, but it
        // must decode via `orchard::Anchor::from_bytes`.
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let anchor_note = Note::from_parts(recipient, NoteValue::from_raw(1), rho, rseed, NoteVersion::V2)
            .into_option()
            .unwrap();
        let leaf =
            MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(anchor_note.commitment()));
        let (anchor, _path) = synthetic_anchor_and_path(leaf);

        // 1 transparent input, 1 Orchard output, no change (exact balance).
        // orchard_actions = max(MIN=2, max(0,1)) = 2; transparent = max(1,0) = 1;
        // logical = 3 → 15_000.
        let fee = zip317_fee(0, 1, 1, 0);
        assert_eq!(fee, 15_000);
        let out_value = 10_000u64;
        let total_in = out_value + fee;

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None, // exact balance: no change
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("public→private must succeed");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert_eq!(&out.pczt_bytes[4..8], &1u32.to_le_bytes());
        // The Orchard bundle pads to MIN_ACTIONS = 2 (one real output + dummies).
        assert!(
            out.n_actions_orchard >= 1,
            "Public→Private must carry an Orchard bundle"
        );
        assert_eq!(out.n_transparent_inputs, 1);
        assert_eq!(
            out.n_transparent_outputs, 0,
            "exact balance leaves no transparent change"
        );
        assert_eq!(out.fee, fee);
    }

    #[test]
    fn public_to_private_takes_transparent_change() {
        // A transparent→shielded send with surplus takes its change on the
        // TRANSPARENT side (the pool that funds it), not Orchard: only the sent
        // amount is shielded, the change stays transparent. Regression guard for
        // the routing rule "Orchard change iff there are Orchard spends".
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);

        // Valid Orchard anchor (only value-0 dummy spends reference it).
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let anchor_note =
            Note::from_parts(recipient, NoteValue::from_raw(1), rho, rseed, NoteVersion::V2)
                .into_option()
                .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(
            anchor_note.commitment(),
        ));
        let (anchor, _path) = synthetic_anchor_and_path(leaf);

        let change_pubkey = {
            use secp256k1::{Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[0x02u8; 32]).unwrap();
            secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
        };
        let t_change = TransparentAddress::PublicKeyHash([0x33u8; 20]);

        // 1 transparent input, 1 Orchard output, 1 transparent change output.
        // orchard_actions = max(MIN=2, 1) = 2; transparent = max(1, 1) = 1 → 15_000.
        let fee = zip317_fee(0, 1, 1, 1);
        let out_value = 10_000u64;
        let change_value = 50_000u64;
        let total_in = out_value + change_value + fee;

        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: Some(fvk.clone()),
            ovk: Some(fvk.to_ovk(Scope::External)),
            // Orchard change address is supplied but must NOT be used here: with
            // no Orchard spends the change is taken transparent.
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: Some(t_change),
            transparent_change_pubkey: Some(change_pubkey),
            transparent_change_address_index: Some(7),
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_transaction(inputs).expect("t→z with change must succeed");
        assert_eq!(out.n_transparent_inputs, 1);
        // The change is taken on the transparent side, NOT Orchard. The old
        // behaviour routed it to Orchard, which would leave this at 0.
        assert_eq!(
            out.n_transparent_outputs, 1,
            "t→z change must stay transparent"
        );
        assert!(
            out.n_actions_orchard >= 1,
            "the sent amount is still shielded (Orchard output present)"
        );
        assert_eq!(out.fee, fee);
    }

    /// Regression: existing Private→Private tests still pass with the new fields
    /// `transparent_inputs: vec![]` and `transparent_change_address: None`.
    #[test]
    fn private_to_private_regression_with_new_fields() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut inputs = make_single_spend_inputs(
            Network::MainNetwork,
            Destination::Orchard(recipient),
            10_000,
        );
        inputs.transparent_inputs = vec![];
        inputs.transparent_change_address = None;
        let out = build_transaction(inputs).expect("regression: private→private must still pass");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert!(out.n_actions_orchard >= 1);
    }

    // ── Ironwood (NU6.3) — build_ironwood_transaction ─────────────────────────

    #[test]
    fn zero_ironwood_anchor_rejected() {
        let mut inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(
                make_fvk().address_at(0u32, Scope::External),
            ),
            10_000,
        );
        inputs.anchor = [0u8; 32];
        let err = build_ironwood_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s)
                if s.contains("Ironwood anchor must be non-zero")
                    && !s.contains("invalid Ironwood anchor encoding")),
            "zero Ironwood anchor must be rejected with the dedicated non-zero error, got: {err}"
        );
    }

    #[test]
    fn invalid_ironwood_anchor_encoding_returns_craft_error() {
        let mut inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(
                make_fvk().address_at(0u32, Scope::External),
            ),
            10_000,
        );
        inputs.anchor = [0xff; 32];
        let err = build_ironwood_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("invalid Ironwood anchor encoding")),
            "got: {err}"
        );
    }

    #[test]
    fn ironwood_bundle_build_produces_valid_pczt() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(recipient),
            10_000,
        );
        let out = build_ironwood_transaction(inputs).expect("ironwood→ironwood must succeed");
        assert!(out.pczt_bytes.len() > 8);
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert!(out.n_actions_ironwood >= 1, "expected a non-empty Ironwood bundle");
        assert_eq!(out.n_actions_orchard, 0, "this builder never carries an Orchard bundle");
        assert!(out.fee >= 10_000);

        // The emitted bytes must parse back and carry a non-empty Ironwood bundle.
        let parsed = pczt::parse(&out.pczt_bytes).expect("v2 PCZT must parse");
        assert!(!parsed.ironwood().actions().is_empty());
    }

    #[test]
    fn ironwood_send_to_transparent_produces_valid_pczt() {
        let t_addr = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Transparent(t_addr),
            10_000,
        );
        let out = build_ironwood_transaction(inputs).expect("ironwood→public must succeed");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert!(out.n_actions_ironwood >= 1);
        assert_eq!(out.n_transparent_inputs, 0);
        assert_eq!(out.n_transparent_outputs, 1);
    }

    /// Real (positive) Ironwood change: two spends whose total exceeds the
    /// recipient output plus fee. Mirrors `multi_spend_with_real_change_output_
    /// produces_valid_pczt` (Orchard V5) but for the Ironwood pool — exercises
    /// the `change > 0` branch that routes surplus back into the Ironwood
    /// output rather than a transparent one.
    #[test]
    fn ironwood_multi_spend_with_real_change_output_produces_valid_pczt() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();

        let spend_values = [20_000u64, 25_000u64];
        let rseeds = [[0xab; 32], [0xcd; 32]];
        let notes: Vec<Note> = spend_values
            .iter()
            .zip(rseeds.iter())
            .map(|(&v, &r)| {
                let rseed = RandomSeed::from_bytes(r, &rho).into_option().unwrap();
                Note::from_parts(recipient, NoteValue::from_raw(v), rho, rseed, NoteVersion::V3)
                    .into_option()
                    .unwrap()
            })
            .collect();
        let leaves: Vec<MerkleHashOrchard> = notes
            .iter()
            .map(|n| MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(n.commitment())))
            .collect();
        let (anchor, paths) = synthetic_anchor_and_paths(&leaves);

        let out_value = 10_000u64;
        // 2 spends + 1 recipient + 1 change = 2 ironwood outputs → 10_000.
        let fee = zip317_fee_ironwood(2, 2, 0, 0);
        let total_in: u64 = spend_values.iter().sum();
        let change = total_in - out_value - fee;
        assert!(
            change > 0,
            "test must exercise a real (positive) Ironwood change output"
        );

        let spends = (0..2)
            .map(|i| IronwoodSpendInput {
                recipient: notes[i].recipient().to_raw_address_bytes(),
                value: spend_values[i],
                rho: rho.to_bytes(),
                rseed: rseeds[i],
                merkle_path: paths[i].clone(),
            })
            .collect();

        let inputs = IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: Some(fvk.clone()),
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends,
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out =
            build_ironwood_transaction(inputs).expect("ironwood multi-spend with change must succeed");
        assert_eq!(out.fee, fee, "fee must echo the caller-supplied value");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        // 2 spends + 2 outputs (recipient + change) → exactly 2 ironwood actions.
        assert_eq!(out.n_actions_ironwood, 2);
        assert_eq!(
            out.n_transparent_outputs, 0,
            "Ironwood change must be routed into the Ironwood pool, never transparent"
        );
    }

    /// A surplus that requires an Ironwood change output, with no
    /// `change_address` supplied, must be rejected with the dedicated error —
    /// distinct from `ironwood_multi_spend_with_real_change_output_produces_
    /// valid_pczt` above, which supplies one and succeeds.
    #[test]
    fn missing_ironwood_change_address_returns_craft_error() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();

        let spend_value = 30_000u64;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        let out_value = 10_000u64;
        let fee = zip317_fee_ironwood(1, 1, 0, 0);
        assert!(
            spend_value > out_value + fee,
            "fixture must leave a positive Ironwood change"
        );

        let inputs = IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: Some(fvk.clone()),
            ovk: None,
            change_address: None, // intentionally missing
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![IronwoodSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        };
        let err = build_ironwood_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("change_address required for Ironwood change")),
            "got: {err}"
        );
    }

    /// Public→Ironwood: one transparent input + one Ironwood output (anchor-only,
    /// no real Ironwood spends). Mirrors `public_to_private_produces_orchard_
    /// output_pczt` (Orchard V5) — exercises `add_transparent_input` and
    /// `stamp_transparent_derivations` on the Ironwood builder's success path.
    #[test]
    fn public_to_ironwood_via_transparent_input_produces_valid_pczt() {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);

        // A validly-encoded anchor from a synthetic one-leaf tree. Its value is
        // irrelevant here because only value-0 dummy spends are present, but it
        // must decode via `orchard::Anchor::from_bytes`.
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
            .into_option()
            .unwrap();
        let anchor_note = Note::from_parts(
            recipient,
            NoteValue::from_raw(1),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .unwrap();
        let leaf =
            MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(anchor_note.commitment()));
        let (anchor, _path) = synthetic_anchor_and_path(leaf);

        // 1 transparent input, 1 Ironwood output, no change (exact balance).
        // ironwood_actions = max(MIN=2, max(0,1)) = 2; transparent = max(1,0) = 1;
        // logical = 3 → 15_000.
        let fee = zip317_fee_ironwood(0, 1, 1, 0);
        assert_eq!(fee, 15_000);
        let out_value = 10_000u64;
        let total_in = out_value + fee;

        let inputs = IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: None,
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_ironwood_transaction(inputs).expect("public→ironwood must succeed");
        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert!(
            out.n_actions_ironwood >= 1,
            "Public→Ironwood must carry an Ironwood bundle"
        );
        assert_eq!(out.n_transparent_inputs, 1);
        assert_eq!(
            out.n_transparent_outputs, 0,
            "exact balance leaves no transparent change"
        );
        assert_eq!(out.fee, fee);
    }

    #[test]
    fn public_to_ironwood_takes_transparent_change() {
        // A transparent→Ironwood send with surplus takes its change on the
        // TRANSPARENT side (the pool that funds it), not Ironwood: only the
        // sent amount is shielded, the change stays transparent. Regression
        // guard for the routing rule "Ironwood change iff there are Ironwood
        // spends" — mirrors the Orchard V5 fix (`public_to_private_takes_
        // transparent_change`) applied to the Ironwood pool.
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);

        let change_pubkey = {
            use secp256k1::{Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[0x02u8; 32]).unwrap();
            secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize()
        };
        let t_change = TransparentAddress::PublicKeyHash([0x33u8; 20]);

        // 1 transparent input, 1 Ironwood output, 1 transparent change output.
        // ironwood_actions = max(MIN=2, max(0,1)) = 2; transparent = max(1, 1) = 1
        // → logical = 3 → 15_000.
        let fee = zip317_fee_ironwood(0, 1, 1, 1);
        let out_value = 10_000u64;
        let change_value = 50_000u64;
        let total_in = out_value + change_value + fee;

        let inputs = IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: None,
            ovk: Some(fvk.to_ovk(Scope::External)),
            // An Ironwood change address is supplied but must NOT be used here:
            // with no Ironwood spends the change is taken transparent.
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: Some(t_change),
            transparent_change_pubkey: Some(change_pubkey),
            transparent_change_address_index: Some(7),
            anchor: {
                let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
                let rseed = RandomSeed::from_bytes([0xab; 32], &rho)
                    .into_option()
                    .unwrap();
                let anchor_note = Note::from_parts(
                    recipient,
                    NoteValue::from_raw(1),
                    rho,
                    rseed,
                    NoteVersion::V3,
                )
                .into_option()
                .unwrap();
                let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(
                    anchor_note.commitment(),
                ));
                synthetic_anchor_and_path(leaf).0
            },
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(total_in)],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        };

        let out = build_ironwood_transaction(inputs).expect("t→ironwood with change must succeed");
        assert_eq!(out.n_transparent_inputs, 1);
        // The change is taken on the transparent side, NOT Ironwood. The old
        // behaviour routed it to Ironwood, which would leave this at 0.
        assert_eq!(
            out.n_transparent_outputs, 1,
            "t→ironwood change must stay transparent"
        );
        assert!(
            out.n_actions_ironwood >= 1,
            "the sent amount is still shielded (Ironwood output present)"
        );
        assert_eq!(out.fee, fee);
    }

    #[test]
    fn v6_serialization_uses_pczt_v2_header_and_rejects_v1() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(recipient),
            10_000,
        );
        let out = build_ironwood_transaction(inputs).expect("build must succeed");

        assert_eq!(&out.pczt_bytes[..4], b"PCZT");
        assert_eq!(
            &out.pczt_bytes[4..8],
            &2u32.to_le_bytes(),
            "a V6/Ironwood PCZT must serialize as v2"
        );

        // v1 cannot represent a V6 tx or a non-canonical Ironwood bundle — guards
        // against accidental v1 emission for this path.
        let parsed = pczt::parse(&out.pczt_bytes).expect("v2 PCZT must parse");
        let err = pczt::v1::Pczt::try_from(parsed).unwrap_err();
        assert!(matches!(err, pczt::EncodingError::UnsupportedTxVersion));
    }

    #[test]
    fn ironwood_proving_key_is_cached_across_calls() {
        let pk1: *const ProvingKey = ironwood_proving_key();
        let pk2: *const ProvingKey = ironwood_proving_key();
        assert_eq!(pk1, pk2, "ironwood_proving_key() must return cached pointer");
        // The two proving keys (Orchard V5's `FixedPostNu6_2` vs Ironwood's
        // `PostNu6_3`) are distinct allocations, not the same cached key.
        assert_ne!(
            proving_key() as *const ProvingKey,
            ironwood_proving_key() as *const ProvingKey,
        );
    }

    /// A single `PostNu6_3` proving key must serve both a classic Orchard
    /// bundle and an Ironwood bundle within one V6 transaction (ZIP 229:
    /// the pools are "not distinguished by separate circuits" — there is no
    /// separate Ironwood verifying key). Exercised at the low level (direct
    /// `zcash_primitives`/`pczt` role calls) rather than through
    /// `build_ironwood_transaction`, which is deliberately Ironwood-only (see
    /// the module docs) and never builds a real co-present Orchard bundle.
    #[test]
    fn v6_both_pools_prove_with_shared_ironwood_key() {
        let network = Network::MainNetwork;
        let target = BlockHeight::from(nu6_3_activation_height(network) + 1);
        let fvk = make_fvk();
        // Post-NU6.3 the classic Orchard bundle's default flags disable
        // cross-address transfers (`enableCrossAddress`, ZIP 229) — an ordinary
        // `add_orchard_output` to any recipient is rejected outright
        // (`CrossAddressDisabled`). Only a same-owner change output is
        // representable, via `add_orchard_change_output`.
        let orchard_change_recipient = fvk.address_at(0u32, Scope::Internal);
        let ironwood_recipient = fvk.address_at(1u32, Scope::External);

        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_pool_bundle_type: OrchardBundleType::DEFAULT,
        };
        let mut builder = Builder::new(network, target, build_config);
        // Fund the two 1_000-zat outputs plus the ZIP-317 fee for the resulting
        // layout: 1 transparent input (1 logical action) + 2 orchard actions
        // (the change, padded to MIN_ACTIONS) + 2 ironwood actions (the output,
        // padded to MIN_ACTIONS) = 5 logical actions × 5_000 = 25_000.
        add_transparent_input(&mut builder, &make_transparent_input(27_000)).unwrap();
        builder
            .add_orchard_change_output::<Zip317FeeError>(
                fvk.clone(),
                None,
                orchard_change_recipient,
                Zatoshis::from_u64(1_000).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_ironwood_output::<Zip317FeeError>(
                None,
                ironwood_recipient,
                Zatoshis::from_u64(1_000).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();

        let fee_rule = FeeRule::standard();
        let pczt_result = builder.build_for_pczt(OsRng, &fee_rule).unwrap();
        let pczt: Pczt = Creator::build_from_parts(pczt_result.pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

        let prover = Prover::new(pczt);
        assert!(prover.requires_orchard_proof());
        assert!(prover.requires_ironwood_proof());

        let prover = prover
            .create_orchard_proof(ironwood_proving_key())
            .expect("the shared PostNu6_3 key must prove the Orchard bundle");
        let pczt = prover
            .create_ironwood_proof(ironwood_proving_key())
            .expect("the shared PostNu6_3 key must prove the Ironwood bundle")
            .finish();

        assert!(!Prover::new(pczt.clone()).requires_orchard_proof());
        assert!(!Prover::new(pczt).requires_ironwood_proof());
    }

    /// Builds a balanced, single-Ironwood-spend `IronwoodBuildInputs` whose
    /// note (and therefore whose anchor) is derived from `rseed_byte` — used by
    /// [`v6_ironwood_anchor_accepted_in_authorizing_data`] to obtain two
    /// otherwise-identical inputs that differ only in their Ironwood anchor.
    fn make_ironwood_inputs_with_rseed(rseed_byte: u8) -> IronwoodBuildInputs {
        let network = Network::MainNetwork;
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[0u8; 32]).into_option().unwrap();
        let rseed = RandomSeed::from_bytes([rseed_byte; 32], &rho)
            .into_option()
            .unwrap();
        let fee = zip317_fee_ironwood(1, 1, 0, 0);
        let out_value = 10_000u64;
        let spend_value = out_value + fee;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(spend_value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        IronwoodBuildInputs {
            network,
            target_height: nu6_3_activation_height(network) + 1,
            ironwood_fvk: Some(fvk.clone()),
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: Some(fvk.address_at(0u32, Scope::Internal)),
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends: vec![IronwoodSpendInput {
                recipient: note.recipient().to_raw_address_bytes(),
                value: spend_value,
                rho: rho.to_bytes(),
                rseed: *rseed.as_bytes(),
                merkle_path: path,
            }],
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Ironwood(recipient),
                value: out_value,
                memo: None,
            }],
        }
    }

    #[test]
    fn v6_ironwood_anchor_accepted_in_authorizing_data() {
        // V6 sighash introspection (asserting the anchor's raw digest placement)
        // is library-internal and not exposed by `zcash_primitives`/`pczt` — per
        // the implementation plan's fallback, this asserts round-trip validity
        // instead: two builds that differ *only* in their (valid, non-zero)
        // Ironwood anchor — each derived from a different note/tree, so each
        // anchor is only valid for its own witness — must both succeed and
        // produce distinct, individually valid PCZTs (the anchor is accepted as
        // authorizing-data input to the proof, not rejected or silently ignored).
        let inputs_a = make_ironwood_inputs_with_rseed(0xab);
        let inputs_b = make_ironwood_inputs_with_rseed(0xcd);
        assert_ne!(inputs_a.anchor, inputs_b.anchor, "test fixture must use distinct anchors");

        let out_a = build_ironwood_transaction(inputs_a).expect("build with anchor A must succeed");
        let out_b = build_ironwood_transaction(inputs_b).expect("build with anchor B must succeed");

        assert_ne!(
            out_a.pczt_bytes, out_b.pczt_bytes,
            "different anchors must produce different serialized PCZTs"
        );
        assert!(out_a.n_actions_ironwood >= 1);
        assert!(out_b.n_actions_ironwood >= 1);
    }

    #[test]
    fn ironwood_zip32_derivation_stamped_on_every_action() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(recipient),
            10_000,
        );
        inputs.seed_fingerprint = [0x7c; 32];
        inputs.account_index = 3;
        let out = build_ironwood_transaction(inputs).expect("build must succeed");

        let parsed = Pczt::parse(&out.pczt_bytes).expect("PCZT must parse");
        Updater::new(parsed)
            .update_ironwood_with(|updater| {
                let actions = updater.bundle().actions();
                assert!(!actions.is_empty());
                let expected_path: Vec<u32> = vec![
                    ChildIndex::hardened(32).index(),
                    ChildIndex::hardened(133).index(),
                    ChildIndex::hardened(3).index(),
                ];
                for action in actions {
                    let d = action
                        .spend()
                        .zip32_derivation()
                        .as_ref()
                        .expect("every Ironwood action's spend must carry a derivation path");
                    assert_eq!(d.seed_fingerprint(), &[0x7c; 32]);
                    let path: Vec<u32> = d.derivation_path().iter().map(|i| i.index()).collect();
                    assert_eq!(path, expected_path);
                }
                Ok(())
            })
            .expect("updater read-back must succeed");
    }

    #[test]
    fn v6_pczt_is_redacted_with_memo_plaintext_and_retained_fields() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(recipient),
            10_000,
        );
        inputs.outputs[0].memo = Some(b"hello ironwood".to_vec());
        // Re-derive the fee and spend value for the now-nonzero memo: memo
        // content does not change the ZIP-317 fee (action count is unchanged),
        // so the existing fixture's fee/spend value already balance correctly.
        let out = build_ironwood_transaction(inputs).expect("build must succeed");

        let parsed = pczt::parse(&out.pczt_bytes).expect("v2 PCZT must parse");
        let bundle = parsed.ironwood();
        assert!(!bundle.actions().is_empty());
        for action in bundle.actions() {
            // `cv_net` is compacted (recomputed downstream from value + rcv).
            assert!(action.cv_net().is_none(), "cv_net must be redacted");
            // The 0x03 Ironwood note keeps `cmx` on the wire (device contract).
            assert!(action.output().cmx().is_some(), "cmx must be retained for the Ironwood note");
            // nullifier/rk are structurally always present (the Redactor role
            // exposes no way to clear either).
            assert_eq!(action.spend().nullifier().len(), 32);
            assert_eq!(action.spend().rk().len(), 32);
        }
        // At least one action carries the real (memo-bearing) output; its
        // enc_ciphertext must have been resolved to a memo plaintext — this
        // also proves the redaction used the correct (V3) note version, since
        // decryption under the wrong domain would silently fail and leave the
        // ciphertext `Encrypted`.
        assert!(
            bundle
                .actions()
                .iter()
                .any(|a| a.output().enc_ciphertext().clone().into_encrypted().is_none()),
            "at least one Ironwood action's enc_ciphertext must be resolved to a memo plaintext"
        );
    }

    #[test]
    fn zip317_fee_ironwood_counts_ironwood_actions() {
        assert_eq!(zip317_fee_ironwood(1, 1, 0, 0), 10_000);
        assert_eq!(zip317_fee_ironwood(2, 3, 0, 0), 15_000);
        assert_eq!(zip317_fee_ironwood(0, 0, 1, 1), 10_000);
        assert_eq!(zip317_fee_ironwood(1, 1, 1, 0), 15_000);
    }

    #[test]
    fn build_ironwood_output_has_no_bsk_field() {
        // Exhaustive field list: if a `bsk` (or any other) field were ever added
        // to `BuildOutput`, this literal would fail to compile without updating
        // it — a compile-time guarantee that binding-signature material is
        // never surfaced to the caller (see the module doc's "Binding
        // signature" section: `bsk` is derived and consumed host-side during
        // finalization, for both `bsk_orchard` and `bsk_ironwood`).
        let _: BuildOutput = BuildOutput {
            pczt_bytes: Vec::new(),
            fee: 0,
            anchor_height: 0,
            n_actions_orchard: 0,
            n_transparent_inputs: 0,
            n_transparent_outputs: 0,
            n_actions_ironwood: 0,
        };
    }

    #[test]
    fn no_ironwood_bundle_returns_craft_error() {
        let t_addr = TransparentAddress::PublicKeyHash([0x11u8; 20]);
        let inputs = IronwoodBuildInputs {
            network: Network::MainNetwork,
            target_height: nu6_3_activation_height(Network::MainNetwork) + 1,
            ironwood_fvk: None,
            ovk: None,
            change_address: None,
            transparent_change_address: None,
            transparent_change_pubkey: None,
            transparent_change_address_index: None,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: zip317_fee_ironwood(0, 0, 1, 1),
            spends: vec![],
            transparent_inputs: vec![make_transparent_input(20_000)],
            outputs: vec![IronwoodOutputRequest {
                destination: IronwoodDestination::Transparent(t_addr),
                value: 10_000,
                memo: None,
            }],
        };
        let err = build_ironwood_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("no Ironwood bundle")),
            "got: {err}"
        );
    }

    #[test]
    fn nu6_3_not_active_returns_craft_error() {
        let fvk = make_fvk();
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut inputs = make_single_ironwood_spend_inputs(
            Network::MainNetwork,
            IronwoodDestination::Ironwood(recipient),
            10_000,
        );
        inputs.target_height = 100;
        let err = build_ironwood_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("NU6.3 is not active")),
            "got: {err}"
        );
    }
}
