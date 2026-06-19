//! Build, prove, and serialize a PCZT for the Orchard send flows.
//!
//! Covers the two flows where the source is Orchard:
//!   - Private → Private (Orchard spends + Orchard outputs)
//!   - Private → Public  (Orchard spends + at least one transparent output)
//!
//! Transparent *inputs* are out of scope (deferred to `zcash_sync::craft`).
//!
//! Lifecycle (host side):
//!   1. Construct `zcash_primitives::transaction::builder::Builder` with the
//!      anchor from `zcash_sync::witness::WitnessOutput`.
//!   2. For each spend: reconstruct the Orchard `Note` via `Note::from_parts`
//!      and call `add_orchard_spend(fvk, note, merkle_path)`.
//!   3. For each output: dispatch on the destination address type and call
//!      `add_orchard_output` or `add_transparent_output`. An automatic change
//!      output is added when value balance is positive.
//!   4. `Builder::build_for_pczt(OsRng, &FeeRule::standard())` → `PcztParts`.
//!   5. `pczt::roles::creator::Creator::build_from_parts` wraps it into a
//!      wire-format `Pczt`.
//!   6. `pczt::roles::io_finalizer::IoFinalizer::finalize_io()` computes the
//!      Orchard binding signing key (bsk) and signs dummy spends.
//!   7. `pczt::roles::prover::Prover::create_orchard_proof(&pk)` generates the
//!      Halo 2 proof. The `ProvingKey` is cached process-globally via
//!      `OnceLock` (first build ~2-5 s, subsequent reuse ~hundreds of ms).
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

use std::sync::OnceLock;

use orchard::{
    circuit::ProvingKey,
    keys::{FullViewingKey as OrchardFvk, OutgoingViewingKey},
    note::{Note, RandomSeed, Rho},
    pczt::Zip32Derivation,
    value::NoteValue,
    Address as OrchardAddress,
};
use pczt::{
    roles::{creator::Creator, io_finalizer::IoFinalizer, prover::Prover, updater::Updater},
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
use zcash_transparent::address::TransparentAddress;
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
    /// Orchard full viewing key (extracted from the UFVK).
    pub orchard_fvk: OrchardFvk,
    /// Optional Outgoing Viewing Key for output recipients. Pass `Some(external_ovk)`
    /// if the wallet should be able to later decrypt its own outgoing notes.
    pub ovk: Option<OutgoingViewingKey>,
    /// Internal-scope Orchard change address.
    pub change_address: OrchardAddress,
    /// Anchor root (32-byte little-endian Pallas encoding) from `zcash_sync::witness::WitnessOutput`.
    pub anchor: [u8; 32],
    /// ZIP-32 seed fingerprint of the wallet seed (see ZIP-32 §"Seed
    /// fingerprints"). Stamped onto every real spend so the device can confirm
    /// the PCZT belongs to its seed before producing a spend-auth signature.
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
    pub spends: Vec<OrchardSpendInput>,
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
}

/// Process-global Halo 2 proving key. First initialization is ~2–5 s;
/// subsequent accesses reuse the same allocation.
pub(crate) fn proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(ProvingKey::build)
}

/// Build, prove, and serialize a PCZT for an Orchard-source send.
///
/// # Errors
///
/// Returns [`Error::Craft`] for:
/// - invalid spend components (recipient bytes, rho, rseed → `Note::from_parts` fails);
/// - invalid anchor encoding;
/// - unsupported network state (NU5 not active at `target_height`);
/// - builder errors (insufficient funds, add_orchard_* failures);
/// - PCZT IO finalizer or prover errors;
/// - value-out-of-range conversion errors (zatoshis cap = 2^63 - 1).
pub fn build_transaction(inputs: BuildInputs) -> Result<BuildOutput, Error> {
    let BuildInputs {
        network,
        target_height,
        orchard_fvk,
        ovk,
        change_address,
        anchor,
        seed_fingerprint,
        account_index,
        fee,
        spends,
        outputs,
    } = inputs;

    let target = BlockHeight::from(target_height);
    if !network.is_nu_active(NetworkUpgrade::Nu5, target) {
        return Err(Error::Craft(format!(
            "Orchard (NU5) is not active at target_height {target_height}"
        )));
    }
    if spends.is_empty() {
        return Err(Error::Craft("spends list is empty".into()));
    }
    if outputs.is_empty() {
        return Err(Error::Craft("outputs list is empty".into()));
    }

    let orchard_anchor = orchard::Anchor::from_bytes(anchor)
        .into_option()
        .ok_or_else(|| Error::Craft("invalid Orchard anchor encoding".into()))?;
    let build_config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(orchard_anchor),
    };

    // ── 1. Builder + spends + non-change outputs ─────────────────────────────
    let mut builder = Builder::new(network, target, build_config);

    let mut total_in: u64 = 0;
    let mut n_spends: u32 = 0;
    for spend in &spends {
        add_spend(&mut builder, &orchard_fvk, spend)?;
        total_in = total_in
            .checked_add(spend.value)
            .ok_or_else(|| Error::Craft("spend value overflow".into()))?;
        n_spends += 1;
    }

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

    // change = total_in − total_out − fee. Must be ≥ 0; a negative result means
    // the inputs cannot cover the requested outputs plus the supplied fee.
    let outflow = total_out
        .checked_add(fee)
        .ok_or_else(|| Error::Craft("total_out + fee overflow".into()))?;
    if total_in < outflow {
        return Err(Error::Craft(format!(
            "insufficient funds: total_in={total_in} < total_out={total_out} + fee={fee}"
        )));
    }
    let change = total_in - outflow;

    // Any positive surplus becomes a single Orchard change output. Note that a
    // surplus can never be "absorbed into the fee": `build_for_pczt` enforces
    // `value_balance == ZIP-317 fee` exactly (it returns `ChangeRequired` for
    // any leftover), so the only valid placements for surplus value are a
    // change output (when it can fund the extra action) or nothing (exact
    // fee). A surplus too small to fund the change output's extra action is
    // therefore unrepresentable and is rejected by the validation below with a
    // precise message rather than a cryptic builder error.
    if change > 0 {
        let change_req = OutputRequest {
            destination: Destination::Orchard(change_address),
            value: change,
            memo: None,
        };
        add_output(&mut builder, ovk.as_ref(), &change_req)?;
        n_orchard_outputs += 1;
    }

    // ZIP-317 validation (validation-only). The supplied fee must equal the
    // ZIP-317 fee for the *final* action layout (after any change output).
    let required_fee = zip317_fee(n_spends, n_orchard_outputs, n_transparent_outputs);
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
    let builder_fee = builder
        .get_fee(&fee_rule)
        .map(u64::from)
        .map_err(|e: zcash_primitives::transaction::builder::FeeError<Zip317FeeError>| {
            Error::Craft(format!("get_fee: {e:?}"))
        })?;
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

    // Stamp every action's spend with its ZIP-32 derivation path so the device
    // can locate the signing key (the device requires a path on every action).
    let pczt = stamp_spend_derivations(pczt, &network, seed_fingerprint, account_index)?;

    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| Error::Craft(format!("PCZT IoFinalizer: {e:?}")))?;

    let pczt = Prover::new(pczt)
        .create_orchard_proof(proving_key())
        .map_err(|e| Error::Craft(format!("PCZT Prover (orchard): {e:?}")))?
        .finish();

    let pczt_bytes = pczt.serialize();

    Ok(BuildOutput {
        pczt_bytes,
        fee,
        anchor_height: target_height.saturating_sub(DEFAULT_TX_EXPIRY_DELTA),
        n_actions_orchard,
    })
}

/// Stamps **every** Orchard action's spend in the PCZT with the ZIP-32
/// derivation path `m/32'/coin_type'/account'` and the wallet seed fingerprint.
///
/// The Ledger device's PCZT parser requires a derivation path on every action
/// (it builds one signing record per action and aborts with `BadState` if the
/// path is missing — see `app-rust-zcash` `src/parser/pczt/orchard.rs`), so
/// dummy-spend actions that the builder injects for change must be stamped too.
/// This is safe: dummy spends are already signed host-side by the IO Finalizer
/// (via `dummy_sk`), so the host never requests a device signature for those
/// action indices, and the device only ever signs the indices it is asked to.
/// All spends in a single-account transaction share the same path.
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

fn add_spend(
    builder: &mut Builder<'_, Network, ()>,
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
    let note = Note::from_parts(recipient, NoteValue::from_raw(spend.value), rho, rseed)
        .into_option()
        .ok_or_else(|| Error::Craft("Note::from_parts produced a non-canonical note".into()))?;
    let merkle_path: orchard::tree::MerklePath = spend.merkle_path.clone().into();
    builder
        .add_orchard_spend::<Zip317FeeError>(fvk.clone(), note, merkle_path)
        .map_err(|e| Error::Craft(format!("add_orchard_spend: {e:?}")))?;
    Ok(())
}

fn add_output(
    builder: &mut Builder<'_, Network, ()>,
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
///   - `transparent_actions = max(t_in_size / STD_IN, t_out_size / STD_OUT)`
///     (we have no transparent inputs in this task; each standard output counts as 1)
///   - `sapling_actions = max(n_sapling_in, n_sapling_out)` (0 here)
///   - `orchard_actions` is computed by `BundleType::DEFAULT::num_actions`
///     which pads to a minimum of `MIN_ACTIONS = 2`.
fn zip317_fee(n_spends: u32, n_orchard_outputs: u32, n_transparent_outputs: u32) -> u64 {
    let requested = u64::from(std::cmp::max(n_spends, n_orchard_outputs));
    let orchard_actions = if n_spends == 0 && n_orchard_outputs == 0 {
        0
    } else {
        std::cmp::max(ORCHARD_MIN_ACTIONS, requested)
    };
    let transparent_actions = u64::from(n_transparent_outputs);
    let sapling_actions = 0u64;
    let logical = transparent_actions + sapling_actions + orchard_actions;
    MARGINAL_FEE * std::cmp::max(GRACE_ACTIONS, logical)
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
    /// Mirrors the orchard 0.14 PCZT test pattern in
    /// `~/.cargo/registry/src/.../orchard-0.14.0/src/pczt.rs::tests::shielded_bundle`.
    fn synthetic_anchor_and_path(
        leaf: MerkleHashOrchard,
    ) -> ([u8; 32], incrementalmerkletree::MerklePath<MerkleHashOrchard, 32>) {
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
        let mp = tree.witness_at_checkpoint_id(position, &0).unwrap().unwrap();
        (root.to_bytes(), mp)
    }

    /// Build a multi-leaf ShardTree containing `leaves` in order, returning the
    /// shared anchor and one Merkle path per leaf. All leaves are marked so a
    /// witness can be produced for each; a single checkpoint is taken after the
    /// last append so every path shares the same anchor.
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

    /// NU5 (Orchard) activation heights — hardcoded since `Network` does not
    /// expose them via `Parameters` in 0.9.
    fn nu5_activation_height(network: Network) -> u32 {
        match network {
            Network::MainNetwork => 1_687_104,
            Network::TestNetwork => 1_842_420,
        }
    }

    /// Make a single-spend BuildInputs that balances exactly (no change). The
    /// spend value is set to `out_value + fee` so `total_in == total_out + fee`
    /// and no change output is produced. The leaf's commitment is computed from
    /// the actual spend value so the builder's anchor-mismatch check passes.
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
        // Exact ZIP-317 fee for the no-change layout (caller-owned per FR-4):
        //   - Private→Private: 1 spend + 1 orchard output → orchard=2 → 10_000.
        //   - Private→Public:  1 spend + 1 transparent output → orchard=2, t=1
        //     → 15_000.
        let fee = match &out_destination {
            Destination::Orchard(_) => zip317_fee(1, 1, 0),
            Destination::Transparent(_) => zip317_fee(1, 0, 1),
        };
        let spend_value = out_value + fee;
        let note =
            Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed)
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
            orchard_fvk: fvk,
            ovk,
            change_address: change,
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
            outputs: vec![OutputRequest {
                destination: out_destination,
                value: out_value,
                memo: None,
            }],
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
        let dummy_note = Note::from_parts(dummy_recipient, NoteValue::from_raw(1), rho, rseed)
            .into_option()
            .unwrap();
        let (_anchor, path) = synthetic_anchor_and_path(MerkleHashOrchard::from_cmx(
            &ExtractedNoteCommitment::from(dummy_note.commitment()),
        ));
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: change,
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
    fn empty_spends_returns_craft_error() {
        let fvk = make_fvk();
        let change = fvk.address_at(0u32, Scope::Internal);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: change,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![],
            outputs: vec![OutputRequest {
                destination: Destination::Orchard(fvk.address_at(0u32, Scope::External)),
                value: 1,
                memo: None,
            }],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("spends list is empty")),
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
        let note = Note::from_parts(recipient, NoteValue::from_raw(1), rho, rseed)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);
        let inputs = BuildInputs {
            network: Network::MainNetwork,
            target_height: nu5_activation_height(Network::MainNetwork) + 1,
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: change,
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
            target_height: 100, // far before NU5 activation
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: change,
            anchor: [0u8; 32],
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee: 10_000,
            spends: vec![],
            outputs: vec![],
        };
        let err = build_transaction(inputs).unwrap_err();
        assert!(
            matches!(&err, Error::Craft(s) if s.contains("Orchard (NU5) is not active")),
            "got: {err}"
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
        // orchard padded to MIN_ACTIONS=2, transparent=0 → logical=2 → 10000.
        assert_eq!(zip317_fee(1, 1, 0), 10_000);
    }

    #[test]
    fn zip317_fee_one_spend_one_orchard_one_transparent_is_15000() {
        // orchard=2 (padded), transparent=1 → logical=3 → 15_000.
        assert_eq!(zip317_fee(1, 1, 1), 15_000);
    }

    #[test]
    fn zip317_fee_two_spends_three_outputs_is_15000() {
        // orchard = max(2 padded, max(2,3)) = 3 → logical=3 → 15_000.
        assert_eq!(zip317_fee(2, 3, 0), 15_000);
    }

    #[test]
    fn zip317_change_output_does_not_bump_fee_when_grace_bound() {
        // 1 spend + 1 orchard recipient output. Adding the change output makes
        // it 2 orchard outputs, but orchard actions are already padded to
        // MIN_ACTIONS=2, so the fee stays at the grace-bound 10_000 either way.
        assert_eq!(zip317_fee(1, 1, 0), 10_000); // no change
        assert_eq!(zip317_fee(1, 2, 0), 10_000); // with change, still 10_000
    }

    #[test]
    fn zip317_change_output_bumps_fee_past_grace_bound() {
        // 1 spend + 2 orchard recipient outputs. Without change orchard=2 →
        // 10_000; the change output makes 3 orchard outputs → orchard=3 →
        // 15_000. This is the band where a sub-change-output surplus is
        // unrepresentable (see surplus-band validation test).
        assert_eq!(zip317_fee(1, 2, 0), 10_000); // no change
        assert_eq!(zip317_fee(1, 3, 0), 15_000); // with change
    }

    #[test]
    fn zip317_no_spends_no_outputs_is_grace_bound() {
        // No actions at all → orchard_actions=0, logical=0 → max(grace=2, 0)=2 → 10_000.
        assert_eq!(zip317_fee(0, 0, 0), 10_000);
    }

    // ── Happy-path tests (proof generation; slow on first run) ────────────────
    //
    // These tests exercise the full PCZT pipeline including Halo 2 proof
    // generation (~2-5 s on first call, cached afterwards). They are NOT
    // `#[ignore]`'d because we need the coverage they produce on craft.rs.

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
                Note::from_parts(recipient, NoteValue::from_raw(v), rho, rseed)
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
        let fee = zip317_fee(2, 2, 0);
        let total_in: u64 = spend_values.iter().sum();
        let change = total_in - out_value - fee;
        assert!(change > 0, "test must exercise a real (positive) change output");

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
            orchard_fvk: fvk.clone(),
            ovk: Some(fvk.to_ovk(Scope::External)),
            change_address: fvk.address_at(0u32, Scope::Internal),
            anchor,
            seed_fingerprint: [0x42; 32],
            account_index: 0,
            fee,
            spends,
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

        let parsed = Pczt::parse(&out.pczt_bytes).expect("PCZT must parse");
        Updater::new(parsed)
            .update_orchard_with(|updater| {
                // Both actions carry an output note (recipient + change).
                assert_eq!(updater.bundle().actions().len(), 2);
                Ok(())
            })
            .expect("updater read-back must succeed");
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
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed)
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
        let fee = 10_000u64; // == zip317_fee(1, 2, 0)
        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: fvk.address_at(0u32, Scope::Internal),
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
        let note = Note::from_parts(recipient, NoteValue::from_raw(spend_value), rho, rseed)
            .into_option()
            .unwrap();
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
        let (anchor, path) = synthetic_anchor_and_path(leaf);

        // out 10_000 + fee 5_000 = 15_000 > total_in 10_000 → insufficient funds.
        let inputs = BuildInputs {
            network,
            target_height: nu5_activation_height(network) + 1,
            orchard_fvk: fvk.clone(),
            ovk: None,
            change_address: fvk.address_at(0u32, Scope::Internal),
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
}
