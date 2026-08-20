//! Transaction-crafting orchestrator.
//!
//! Wraps `zcash_crypto::craft::build_transaction` with the gRPC-side
//! concerns: anchor resolution via `compute_witnesses` / `fetch_orchard_anchor`,
//! UFVK parsing, and destination-address decoding.
//!
//! Supports all four send flows:
//!   - Private → Private  (Orchard spends + Orchard outputs)
//!   - Private → Public   (Orchard spends + transparent outputs)
//!   - Public  → Private  (transparent inputs + Orchard output; anchor-only)
//!   - Public  → Public   (transparent inputs + transparent outputs; no Orchard bundle)
//!
//! The first three read Orchard key material and therefore require a UFVK. The
//! fully transparent flow reads none: the only key it needs is the account-level
//! transparent pubkey (`m/44'/coin'/account'`), used to verify each input's
//! signing path and to derive the internal change address. A caller that holds
//! that pubkey — a wallet always does, it is the account xpub's payload — can
//! supply it directly and omit the UFVK, so spending transparent funds never
//! requires exporting a viewing key.

use anyhow::{anyhow, Result};
use orchard::keys::Scope;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_crypto::{
    craft::{
        build_ironwood_transaction, build_transaction, BuildInputs, BuildOutput, Destination,
        IronwoodBuildInputs, IronwoodDestination, IronwoodOutputRequest, IronwoodSpendInput,
        OrchardSpendInput, OutputRequest, TransparentInput, DEFAULT_TX_EXPIRY_DELTA,
    },
    network::parse_network,
};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};
use zcash_transparent::keys::AccountPubKey;

use crate::witness::{
    compute_ironwood_witnesses, compute_witnesses, fetch_ironwood_anchor, fetch_orchard_anchor,
    resolve_anchor_height, NoteRef, WitnessRequest,
};

/// JS-facing spend descriptor — hex strings come directly from `ShieldedNote`.
#[derive(Clone, Debug)]
pub struct SpendInputDto {
    /// 86-char hex (43 bytes: 11-byte d + 32-byte pk_d).
    pub recipient_hex: String,
    pub value_zat: u64,
    /// 64-char hex (32 bytes).
    pub rho_hex: String,
    /// 64-char hex.
    pub rseed_hex: String,
    /// 64-char hex.
    pub cmx_hex: String,
    /// Leaf index in the Orchard commitment tree.
    pub position: u64,
}

/// JS-facing transparent input descriptor.
#[derive(Clone, Debug)]
pub struct TransparentInputDto {
    /// 64-char hex (32 bytes) prevout txid in **internal (little-endian) byte
    /// order**. Ledger Live surfaces txids in display (big-endian) order;
    /// callers must reverse before passing.
    pub txid_hex: String,
    /// Output index within the origin transaction.
    pub vout: u32,
    /// Hex-encoded raw scriptPubKey bytes (no CompactSize length prefix).
    pub script_pubkey_hex: String,
    /// UTXO value in zatoshis.
    pub value_zat: u64,
    /// 66-char hex (33 bytes) compressed secp256k1 pubkey.
    pub pubkey_hex: String,
    /// BIP-44 chain (scope) the controlling key lives on: `0` = external,
    /// `1` = internal (change). Together with `address_index` and the account's
    /// path this identifies the input's signing key. Verified against the UFVK
    /// (the derived pubkey must equal `pubkey_hex`) and stamped into the PCZT as
    /// the input's `bip32_derivation` — the Ledger device's sole source for the
    /// transparent signing path in the PCZT flow.
    pub derivation_scope: u32,
    /// Non-hardened BIP-44 address index of the controlling key (see
    /// `derivation_scope`).
    pub address_index: u32,
}

#[derive(Clone, Debug)]
pub struct OutputRequestDto {
    /// Recipient address. Accepts t-addr (P2PKH/P2SH) and u-addr (Orchard receiver).
    /// Sapling z-addresses and TEX (ZIP-320) addresses are rejected with a
    /// clear error.
    pub address: String,
    pub value_zat: u64,
    /// Optional UTF-8 memo. Encoded into `MemoBytes` for Orchard outputs;
    /// ignored for transparent outputs.
    pub memo: Option<String>,
}

pub struct CraftRequest {
    pub grpc_url: String,
    /// Unified full viewing key of the spending account. Required by every flow
    /// that carries an Orchard bundle (an Orchard spend or an Orchard output);
    /// `None` is accepted only for the fully transparent flow, which reads no
    /// shielded key material and takes its transparent account key from
    /// `transparent_account_pubkey_hex` instead.
    pub ufvk: Option<String>,
    /// 130-char hex (65 bytes: 32-byte chain code ‖ 33-byte compressed pubkey)
    /// account-level transparent pubkey at `m/44'/coin'/account'` — the payload
    /// of the account xpub, and the same bytes a UFVK carries as its P2PKH item.
    ///
    /// Optional next to `ufvk`: when the UFVK is present its own transparent
    /// component is authoritative and this field only has to agree with it (a
    /// disagreement is a caller bug and fails the build). It is the sole source
    /// when the UFVK is absent.
    ///
    /// One of the two must be supplied — see the guard at the top of
    /// [`craft_transaction`] for why the rule is checked rather than typed.
    pub transparent_account_pubkey_hex: Option<String>,
    /// `"mainnet"` / `"testnet"`. `None` ⇒ testnet (matches sync default).
    pub network: Option<String>,
    /// 64-char hex (32 bytes): ZIP-32 seed fingerprint of the wallet seed,
    /// obtained from the device. Stamped onto each real spend so the device can
    /// confirm the PCZT belongs to its seed.
    pub seed_fingerprint_hex: String,
    /// ZIP-32 account index the UFVK was derived at.
    pub account_index: u32,
    /// Caller-owned fee in zatoshis (FR-4). Selected upstream by ledger-live
    /// and forwarded to the builder, which validates it
    /// against ZIP-317 and derives the change output from it.
    pub fee_zat: u64,
    pub spends: Vec<SpendInputDto>,
    /// Transparent (P2PKH) UTXOs to spend. Empty for Private→* flows.
    pub transparent_inputs: Vec<TransparentInputDto>,
    pub outputs: Vec<OutputRequestDto>,
    /// Explicit anchor height; `None` ⇒ tip − 10 (defaults via the witness
    /// orchestrator).
    pub anchor_height: Option<u32>,
}

/// Compute witnesses, decode addresses, then call the pure builder.
pub async fn craft_transaction(req: CraftRequest) -> Result<BuildOutput> {
    let has_orchard_spends = !req.spends.is_empty();
    let has_transparent_inputs = !req.transparent_inputs.is_empty();

    if !has_orchard_spends && !has_transparent_inputs {
        return Err(anyhow!(
            "craft: no inputs — both orchard spends and transparent inputs are empty"
        ));
    }
    if req.outputs.is_empty() {
        return Err(anyhow!("craft: outputs list is empty"));
    }
    // Supplying neither key source is a caller mistake no flow can recover from,
    // so it is refused here with one message rather than a few calls deeper,
    // where it would surface as whichever of change derivation or input
    // verification the flow happened to reach first. The two fields are
    // independently optional because the JS-facing struct they cross
    // (`BuildTransactionParams`) cannot express "exactly one of" — napi has no
    // encoding for a data-carrying enum.
    if req.ufvk.is_none() && req.transparent_account_pubkey_hex.is_none() {
        return Err(anyhow!(
            "craft: no account key — neither a UFVK nor transparent_account_pubkey was \
             supplied; a fully transparent send needs the account's transparent pubkey, and \
             every flow with a shielded bundle needs the UFVK"
        ));
    }

    let network = parse_network(req.network.as_deref()).map_err(|e| anyhow!("{e}"))?;
    let seed_fingerprint = hex_to_array::<32>(&req.seed_fingerprint_hex, "seed_fingerprint")?;

    // ── 1. Parse UFVK ─────────────────────────────────────────────────────────
    // Absent for a fully transparent send; step 2 rejects that for any flow that
    // needs Orchard key material.
    let ufvk = req
        .ufvk
        .as_deref()
        .map(|encoded| {
            let (_net, ufvk_str) =
                Ufvk::decode(encoded).map_err(|e| anyhow!("UFVK decode failed: {e:?}"))?;
            UnifiedFullViewingKey::parse(&ufvk_str).map_err(|e| anyhow!("UFVK parse failed: {e:?}"))
        })
        .transpose()?;

    // Decode destination addresses once, up front. The resulting destinations
    // both drive the flow-type detection below and are reused when assembling
    // the builder's `OutputRequest`s in step 6.
    let outputs: Vec<OutputRequest> = req
        .outputs
        .iter()
        .map(|o| {
            let destination = decode_destination(&network, &o.address)?;
            Ok(OutputRequest {
                destination,
                value: o.value_zat,
                memo: o.memo.as_ref().map(|s| s.as_bytes().to_vec()),
            })
        })
        .collect::<Result<_>>()?;

    // Determine flow type from the already-decoded destinations.
    let has_orchard_outputs = outputs
        .iter()
        .any(|o| matches!(o.destination, Destination::Orchard(_)));
    let has_orchard_bundle = has_orchard_spends || has_orchard_outputs;

    // ── 2. Extract Orchard FVK and change address when needed ────────────────
    let (orchard_fvk, change_address, ovk) = if has_orchard_bundle {
        let fvk = ufvk
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "this flow carries an Orchard bundle (an Orchard spend or an Orchard \
                     recipient) and needs the account's Orchard key material, so a UFVK is \
                     required; only a fully transparent send may omit it"
                )
            })?
            .orchard()
            .ok_or_else(|| anyhow!("UFVK does not contain an Orchard component"))?
            .clone();
        let change = fvk.address_at(0u32, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::External));
        (Some(fvk), Some(change), ovk)
    } else {
        // Public→Public: no Orchard bundle. The builder reads no Orchard key
        // material in this flow, so pass `None` for both the FVK and the
        // Orchard change address (transparent change is handled below).
        (None, None, None)
    };

    // The account-level transparent key, used twice below: to derive the internal
    // change address (step 3) and to verify each input's signing path (step 5).
    // A UFVK's P2PKH item and the standalone field carry the same 65 bytes, so
    // when both are present they must agree — a mismatch means the caller mixed
    // key material from two accounts, and deriving from either one would produce
    // a change address or a signing path that does not belong to the funds being
    // spent, so it fails the build rather than picking a winner.
    let account_pubkey: Option<AccountPubKey> = match (
        ufvk.as_ref().and_then(|k| k.transparent()),
        req.transparent_account_pubkey_hex.as_deref(),
    ) {
        (Some(from_ufvk), Some(explicit_hex)) => {
            let explicit = decode_account_pubkey(explicit_hex)?;
            if explicit.serialize() != from_ufvk.serialize() {
                return Err(anyhow!(
                    "transparent_account_pubkey does not match the UFVK's transparent component; \
                     they must describe the same account"
                ));
            }
            Some(explicit)
        }
        (Some(from_ufvk), None) => Some(from_ufvk.clone()),
        (None, Some(explicit_hex)) => Some(decode_account_pubkey(explicit_hex)?),
        (None, None) => None,
    };

    // ── 3. Transparent change address (transparent-funded flows) ─────────────
    // Change returns to the pool that funds it: with no Orchard spends the
    // surplus comes from the transparent inputs, so change is transparent. This
    // covers both Public→Public AND transparent→shielded (t→z) — for t→z only
    // the sent amount is shielded, the change stays transparent instead of
    // migrating the whole balance into the shielded pool. Flows that spend from
    // Orchard (z→z, z→t) take change in Orchard (handled above).
    //
    // We derive the internal change address from the account's transparent key
    // (step 2) when available, otherwise accept None (exact-balance transactions
    // need no change address). Without that key we can only proceed if the
    // transaction produces no change; if it would, fail fast here with an
    // actionable error rather than letting the deeper, generic builder error
    // surface later.
    // Derive the internal change address *and* the metadata the device needs to
    // recognize it as change: the change pubkey (33 bytes) and its non-hardened
    // address index. These flow into the change output's `bip32_derivation`.
    let transparent_change: Option<(
        zcash_transparent::address::TransparentAddress,
        [u8; 33],
        u32,
    )> = if !has_orchard_spends {
        let derived = account_pubkey.as_ref().and_then(|tpk| {
            use zcash_transparent::keys::{IncomingViewingKey, TransparentKeyScope};
            let ivk = tpk.derive_internal_ivk().ok()?;
            // `default_address()` returns the first non-hardened index whose key
            // derivation succeeds, scanning up from 0. For secp256k1 this is
            // index 0 except in a ~2^-128 derivation-failure case, in which case
            // it transparently advances to the next valid index. Whatever index
            // it lands on, the wallet (Ledger Live) must scan the internal chain
            // (scope 1) from index 0 under the standard BIP-44 gap limit to
            // rediscover and later spend this change — the index is exactly what
            // `default_address()` picks, so a standard scan always finds it.
            let (addr, index) = ivk.default_address();
            // Fund-safety invariant: `addr` and `pubkey` are derived along the
            // *same* path `m/44'/coin'/account'/1/index` (addr from the internal
            // ivk, pubkey from the account key at INTERNAL scope), so they can
            // never diverge. The change output's bip32_derivation carries this
            // pubkey; the device re-derives it from the path, hashes it, and
            // matches it against the output script (which encodes `addr`) — that
            // check only passes because both sides come from this one index.
            let pubkey = tpk
                .derive_address_pubkey(TransparentKeyScope::INTERNAL, index)
                .ok()?
                .serialize();
            Some((addr, pubkey, index.index()))
        });
        if derived.is_none() {
            let total_in = req
                .transparent_inputs
                .iter()
                .try_fold(0u64, |acc, t| acc.checked_add(t.value_zat))
                .ok_or_else(|| anyhow!("transparent input value overflow"))?;
            let total_out = req
                .outputs
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.value_zat))
                .ok_or_else(|| anyhow!("output value overflow"))?;
            let outflow = total_out
                .checked_add(req.fee_zat)
                .ok_or_else(|| anyhow!("total_out + fee overflow"))?;
            if total_in > outflow {
                return Err(anyhow!(
                    "transparent change of {} zatoshis is required but no transparent account \
                     key was supplied to derive an internal change address from; pass \
                     transparent_account_pubkey (or a UFVK carrying a transparent component), \
                     or send an exact-balance amount (transparent inputs == outputs + fee)",
                    total_in - outflow
                ));
            }
        }
        derived
    } else {
        None
    };
    let transparent_change_address = transparent_change.as_ref().map(|(addr, _, _)| *addr);
    let transparent_change_pubkey = transparent_change.as_ref().map(|(_, pk, _)| *pk);
    let transparent_change_address_index = transparent_change.as_ref().map(|(_, _, i)| *i);

    // ── 4. Anchor routing ─────────────────────────────────────────────────────
    // Each branch resolves the anchor height the transaction is built against.
    // For the shielded flows this is the height the witness orchestrator already
    // resolved (an explicit `anchor_height`, or `tip − depth`); the
    // transparent-only flow resolves it independently since it builds no Orchard
    // bundle. Step 7 derives `target_height` from this so the expiry/branch-id
    // stays consistent with the anchor the paths were computed against.
    let (anchor, spends, resolved_anchor_height) = if has_orchard_spends {
        // Private→* : compute full witnesses for each spend note.
        let notes: Vec<NoteRef> = req
            .spends
            .iter()
            .map(|s| {
                Ok(NoteRef {
                    position: s.position,
                    cmx: hex_to_array::<32>(&s.cmx_hex, "cmx")?,
                })
            })
            .collect::<Result<_>>()?;
        let witness_out = compute_witnesses(WitnessRequest {
            grpc_url: req.grpc_url.clone(),
            anchor_height: req.anchor_height,
            anchor_depth_blocks: None,
            notes,
        })
        .await?;

        if witness_out.witnesses.len() != req.spends.len() {
            return Err(anyhow!(
                "internal: witness count {} != spends count {}",
                witness_out.witnesses.len(),
                req.spends.len()
            ));
        }

        let spends: Vec<OrchardSpendInput> = req
            .spends
            .iter()
            .zip(witness_out.witnesses.iter().cloned())
            .map(|(dto, mp)| {
                Ok(OrchardSpendInput {
                    recipient: hex_to_array::<43>(&dto.recipient_hex, "recipient")?,
                    value: dto.value_zat,
                    rho: hex_to_array::<32>(&dto.rho_hex, "rho")?,
                    rseed: hex_to_array::<32>(&dto.rseed_hex, "rseed")?,
                    merkle_path: mp,
                })
            })
            .collect::<Result<_>>()?;

        (witness_out.anchor, spends, witness_out.anchor_height)
    } else if has_orchard_outputs {
        // Public→Private: fetch anchor only (no spend witnesses).
        let witness_out = fetch_orchard_anchor(&req.grpc_url, req.anchor_height, None).await?;
        (witness_out.anchor, vec![], witness_out.anchor_height)
    } else {
        // Public→Public: no Orchard bundle; the anchor is unused, but the target
        // height still must track the live tip (or an explicit anchor), so
        // resolve it here rather than defaulting to a fixed low height.
        let resolved = resolve_anchor_height(&req.grpc_url, req.anchor_height, None).await?;
        ([0u8; 32], vec![], resolved)
    };

    // ── 5. Decode transparent inputs ─────────────────────────────────────────
    // For each input we verify that its (derivation_scope, address_index) really
    // identifies the supplied pubkey under this account key, then record the path
    // so the builder can stamp the input's `bip32_derivation` (the device's only
    // source for the transparent signing path). The device signs with that path
    // without re-checking it against the pubkey, so getting it wrong would yield
    // an invalid signature — this up-front check turns that into a clear build
    // error.
    let transparent_inputs =
        decode_transparent_inputs(account_pubkey.as_ref(), &req.transparent_inputs)?;

    // Destinations were decoded once in step 1 and reused here as `outputs`.

    // ── 7. target_height = anchor_height + DEFAULT_TX_EXPIRY_DELTA ───────────
    // Use the anchor height resolved in step 4 (an explicit `anchor_height`, or
    // `tip − depth`), NOT a fixed fallback. Deriving the target from a stale
    // default (e.g. 1 → target 41) would put it below the NU5 activation height
    // and the builder — which always emits v5 — would reject every send.
    let target_height = resolved_anchor_height
        .checked_add(DEFAULT_TX_EXPIRY_DELTA)
        .ok_or_else(|| anyhow!("target_height overflow"))?;

    // ── 8. Build ──────────────────────────────────────────────────────────────
    build_transaction(BuildInputs {
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
        account_index: req.account_index,
        fee: req.fee_zat,
        spends,
        transparent_inputs,
        outputs,
    })
    .map_err(|e| anyhow!("build_transaction: {e}"))
}

/// Decode a destination address string into a builder [`Destination`].
///
/// Accepts transparent (P2PKH/P2SH) addresses and unified addresses with an
/// Orchard or transparent receiver. Sapling z-addresses and ZIP-320 TEX
/// addresses are rejected.
fn decode_destination(
    network: &zcash_protocol::consensus::Network,
    address: &str,
) -> Result<Destination> {
    let addr = Address::decode(network, address)
        .ok_or_else(|| anyhow!("invalid destination address: {address}"))?;
    match addr {
        Address::Transparent(ta) => Ok(Destination::Transparent(ta)),
        Address::Unified(ua) => {
            if let Some(oa) = ua.orchard() {
                Ok(Destination::Orchard(*oa))
            } else if let Some(ta) = ua.transparent() {
                Ok(Destination::Transparent(*ta))
            } else {
                Err(anyhow!(
                    "unified address has no Orchard or Transparent receiver: {address}"
                ))
            }
        }
        Address::Sapling(_) => Err(anyhow!("Sapling destination not supported")),
        Address::Tex(_) => Err(anyhow!("ZIP-320 TEX address not supported")),
    }
}

fn hex_to_array<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let v = hex::decode(s).map_err(|e| anyhow!("{field} hex decode: {e}"))?;
    let arr: [u8; N] = v
        .try_into()
        .map_err(|got: Vec<u8>| anyhow!("{field}: expected {N} bytes, got {}", got.len()))?;
    Ok(arr)
}

/// Decode a hex account-level transparent pubkey (32-byte chain code ‖ 33-byte
/// compressed secp256k1 pubkey) into an [`AccountPubKey`].
///
/// This is the same 65-byte serialization a UFVK carries as its P2PKH item, so a
/// key decoded here derives exactly what the equivalent UFVK component would: the
/// BIP-32 metadata a UFVK does not preserve (depth, parent fingerprint, child
/// number) plays no part in child derivation.
fn decode_account_pubkey(hex_str: &str) -> Result<AccountPubKey> {
    let bytes = hex_to_array::<65>(hex_str, "transparent_account_pubkey")?;
    AccountPubKey::deserialize(&bytes).map_err(|e| {
        anyhow!("transparent_account_pubkey is not a valid account-level transparent pubkey: {e}")
    })
}

// ── Ironwood (NU6.3) — V6 orchestrator ──────────────────────────────────────
//
// Wraps `zcash_crypto::craft::build_ironwood_transaction` with the same
// gRPC-side concerns as `craft_transaction` above: anchor/witness resolution
// (via the Ironwood siblings `compute_ironwood_witnesses` /
// `fetch_ironwood_anchor`), UFVK parsing, and destination-address decoding.
// Additive and decoupled from `craft_transaction` — no shared code path is
// modified.
//
// Supports the two Ironwood send-flow shapes `build_ironwood_transaction`
// itself supports (an Ironwood bundle is mandatory; there is no
// transparent-only flow here — see that function's module docs):
//   - Ironwood → Ironwood (spends + Ironwood outputs)
//   - Ironwood → Public    (spends + transparent outputs)
//   - Public   → Ironwood  (transparent inputs + Ironwood output; anchor-only)

/// JS-facing Ironwood spend descriptor. Identical shape to [`SpendInputDto`];
/// kept distinct so the Orchard V5 DTOs above are never touched by this
/// addition.
#[derive(Clone, Debug)]
pub struct IronwoodSpendInputDto {
    /// 86-char hex (43 bytes: 11-byte d + 32-byte pk_d).
    pub recipient_hex: String,
    pub value_zat: u64,
    /// 64-char hex (32 bytes).
    pub rho_hex: String,
    /// 64-char hex.
    pub rseed_hex: String,
    /// 64-char hex.
    pub cmx_hex: String,
    /// Leaf index in the Ironwood commitment tree.
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct IronwoodOutputRequestDto {
    /// Recipient address. Accepts t-addr (P2PKH/P2SH) and u-addr (Orchard
    /// receiver — the same receiver bytes select the Ironwood pool here; see
    /// `decode_ironwood_destination`). Sapling z-addresses and TEX (ZIP-320)
    /// addresses are rejected.
    pub address: String,
    pub value_zat: u64,
    /// Optional UTF-8 memo. Encoded into `MemoBytes` for Ironwood outputs;
    /// ignored for transparent outputs.
    pub memo: Option<String>,
}

pub struct IronwoodCraftRequest {
    pub grpc_url: String,
    pub ufvk: String,
    /// `"mainnet"` / `"testnet"`. `None` ⇒ testnet (matches sync default).
    pub network: Option<String>,
    /// 64-char hex (32 bytes): ZIP-32 seed fingerprint of the wallet seed,
    /// obtained from the device. Stamped onto each real spend so the device can
    /// confirm the PCZT belongs to its seed.
    pub seed_fingerprint_hex: String,
    /// ZIP-32 account index the UFVK was derived at.
    pub account_index: u32,
    /// Caller-owned fee in zatoshis (FR-4). Selected upstream by ledger-live
    /// and forwarded to the builder, which validates it against ZIP-317 Rev 1
    /// and derives the (always-Ironwood) change output from it.
    pub fee_zat: u64,
    pub spends: Vec<IronwoodSpendInputDto>,
    /// Transparent (P2PKH) UTXOs to spend. Empty for Ironwood→* flows.
    pub transparent_inputs: Vec<TransparentInputDto>,
    pub outputs: Vec<IronwoodOutputRequestDto>,
    /// Explicit anchor height; `None` ⇒ tip − 10 (defaults via the witness
    /// orchestrator).
    pub anchor_height: Option<u32>,
}

/// Compute Ironwood witnesses, decode addresses, then call the pure builder.
pub async fn craft_ironwood_transaction(req: IronwoodCraftRequest) -> Result<BuildOutput> {
    let has_ironwood_spends = !req.spends.is_empty();
    let has_transparent_inputs = !req.transparent_inputs.is_empty();

    if !has_ironwood_spends && !has_transparent_inputs {
        return Err(anyhow!(
            "craft: no inputs — both ironwood spends and transparent inputs are empty"
        ));
    }
    if req.outputs.is_empty() {
        return Err(anyhow!("craft: outputs list is empty"));
    }

    let network = parse_network(req.network.as_deref()).map_err(|e| anyhow!("{e}"))?;
    let seed_fingerprint = hex_to_array::<32>(&req.seed_fingerprint_hex, "seed_fingerprint")?;

    // ── 1. Parse UFVK ─────────────────────────────────────────────────────────
    let (_net, ufvk_str) =
        Ufvk::decode(&req.ufvk).map_err(|e| anyhow!("UFVK decode failed: {e:?}"))?;
    let ufvk =
        UnifiedFullViewingKey::parse(&ufvk_str).map_err(|e| anyhow!("UFVK parse failed: {e:?}"))?;

    // Decode destination addresses once, up front — both drives the
    // Ironwood-bundle-presence check below and is reused when assembling the
    // builder's `IronwoodOutputRequest`s in step 5.
    let outputs: Vec<IronwoodOutputRequest> = req
        .outputs
        .iter()
        .map(|o| {
            let destination = decode_ironwood_destination(&network, &o.address)?;
            Ok(IronwoodOutputRequest {
                destination,
                value: o.value_zat,
                memo: o.memo.as_ref().map(|s| s.as_bytes().to_vec()),
            })
        })
        .collect::<Result<_>>()?;

    let has_ironwood_outputs = outputs
        .iter()
        .any(|o| matches!(o.destination, IronwoodDestination::Ironwood(_)));
    let has_ironwood_bundle = has_ironwood_spends || has_ironwood_outputs;
    if !has_ironwood_bundle {
        return Err(anyhow!(
            "craft: no Ironwood bundle — ironwood spends and ironwood outputs are both empty; \
             use craft_transaction for a transparent-only send"
        ));
    }

    // ── 2. Extract the Orchard-family FVK + change address ──────────────────
    // An Ironwood bundle is mandatory here (checked above), and Ironwood spends
    // an the Ironwood pool the same viewing key as Orchard — so, unlike
    // `craft_transaction`, this key is always required (no transparent-only
    // branch exists in `build_ironwood_transaction`). `ovk` makes any Ironwood
    // output recoverable by us regardless of change routing, so it stays
    // unconditional; only `change_address` (the Ironwood-pool change) is
    // routing-dependent — see step 3.
    let fvk = ufvk
        .orchard()
        .ok_or_else(|| {
            anyhow!(
                "UFVK does not contain an Orchard component (required for Ironwood spends and \
                 outputs — the same key spends and receives both pools)"
            )
        })?
        .clone();
    let ovk = Some(fvk.to_ovk(Scope::External));

    // Change returns to the pool that funds it (mirrors `craft_transaction`'s
    // transparent-change fix, applied to the Ironwood pool): with Ironwood
    // spends present the surplus comes from the spent Ironwood notes, so
    // change stays shielded (Ironwood-pool change address); with no Ironwood
    // spends (Public→Ironwood) the surplus comes from the transparent inputs,
    // so change is taken transparent instead — only the sent amount is
    // shielded.
    let change_address = if has_ironwood_spends {
        Some(fvk.address_at(0u32, Scope::Internal))
    } else {
        None
    };

    // ── 3. Transparent change address (Public→Ironwood) ──────────────────────
    // For the no-Ironwood-spends flow we derive the internal change address
    // from the UFVK's transparent component when available, otherwise accept
    // None (exact-balance transactions need no change address). When the UFVK
    // has no transparent receiver we can only proceed if the transaction
    // produces no change; if it would, fail fast here with an actionable error
    // rather than letting the deeper, generic builder error surface later.
    // Derive the internal change address *and* the metadata the device needs
    // to recognize it as change: the change pubkey (33 bytes) and its
    // non-hardened address index. These flow into the change output's
    // `bip32_derivation`. Mirrors `craft_transaction`'s step 3 exactly.
    let transparent_change: Option<(
        zcash_transparent::address::TransparentAddress,
        [u8; 33],
        u32,
    )> = if !has_ironwood_spends {
        let derived = ufvk.transparent().and_then(|tpk| {
            use zcash_transparent::keys::{IncomingViewingKey, TransparentKeyScope};
            let ivk = tpk.derive_internal_ivk().ok()?;
            let (addr, index) = ivk.default_address();
            let pubkey = tpk
                .derive_address_pubkey(TransparentKeyScope::INTERNAL, index)
                .ok()?
                .serialize();
            Some((addr, pubkey, index.index()))
        });
        if derived.is_none() {
            let total_in = req
                .transparent_inputs
                .iter()
                .try_fold(0u64, |acc, t| acc.checked_add(t.value_zat))
                .ok_or_else(|| anyhow!("transparent input value overflow"))?;
            let total_out = req
                .outputs
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.value_zat))
                .ok_or_else(|| anyhow!("output value overflow"))?;
            let outflow = total_out
                .checked_add(req.fee_zat)
                .ok_or_else(|| anyhow!("total_out + fee overflow"))?;
            if total_in > outflow {
                return Err(anyhow!(
                    "transparent change of {} zatoshis is required but the UFVK has no \
                     transparent receiver to derive an internal change address from; \
                     use a UFVK with a transparent component or send an exact-balance \
                     amount (transparent inputs == outputs + fee)",
                    total_in - outflow
                ));
            }
        }
        derived
    } else {
        None
    };
    let transparent_change_address = transparent_change.as_ref().map(|(addr, _, _)| *addr);
    let transparent_change_pubkey = transparent_change.as_ref().map(|(_, pk, _)| *pk);
    let transparent_change_address_index = transparent_change.as_ref().map(|(_, _, i)| *i);

    // ── 4. Anchor routing ─────────────────────────────────────────────────────
    let (anchor, spends, resolved_anchor_height) = if has_ironwood_spends {
        // Ironwood→* : compute full witnesses for each spend note.
        let notes: Vec<NoteRef> = req
            .spends
            .iter()
            .map(|s| {
                Ok(NoteRef {
                    position: s.position,
                    cmx: hex_to_array::<32>(&s.cmx_hex, "cmx")?,
                })
            })
            .collect::<Result<_>>()?;
        let witness_out = compute_ironwood_witnesses(WitnessRequest {
            grpc_url: req.grpc_url.clone(),
            anchor_height: req.anchor_height,
            anchor_depth_blocks: None,
            notes,
        })
        .await?;

        if witness_out.witnesses.len() != req.spends.len() {
            return Err(anyhow!(
                "internal: witness count {} != spends count {}",
                witness_out.witnesses.len(),
                req.spends.len()
            ));
        }

        let spends: Vec<IronwoodSpendInput> = req
            .spends
            .iter()
            .zip(witness_out.witnesses.iter().cloned())
            .map(|(dto, mp)| {
                Ok(IronwoodSpendInput {
                    recipient: hex_to_array::<43>(&dto.recipient_hex, "recipient")?,
                    value: dto.value_zat,
                    rho: hex_to_array::<32>(&dto.rho_hex, "rho")?,
                    rseed: hex_to_array::<32>(&dto.rseed_hex, "rseed")?,
                    merkle_path: mp,
                })
            })
            .collect::<Result<_>>()?;

        (witness_out.anchor, spends, witness_out.anchor_height)
    } else {
        // Public→Ironwood: fetch anchor only (no spend witnesses).
        let witness_out = fetch_ironwood_anchor(&req.grpc_url, req.anchor_height, None).await?;
        (witness_out.anchor, vec![], witness_out.anchor_height)
    };

    // ── 5. Decode + verify transparent inputs ────────────────────────────────
    let transparent_inputs =
        decode_transparent_inputs(ufvk.transparent(), &req.transparent_inputs)?;

    // Destinations were decoded once in step 1 and reused here as `outputs`.

    // ── 6. target_height = anchor_height + DEFAULT_TX_EXPIRY_DELTA ───────────
    let target_height = resolved_anchor_height
        .checked_add(DEFAULT_TX_EXPIRY_DELTA)
        .ok_or_else(|| anyhow!("target_height overflow"))?;

    // ── 7. Build ──────────────────────────────────────────────────────────────
    build_ironwood_transaction(IronwoodBuildInputs {
        network,
        target_height,
        ironwood_fvk: Some(fvk),
        ovk,
        change_address,
        transparent_change_address,
        transparent_change_pubkey,
        transparent_change_address_index,
        anchor,
        seed_fingerprint,
        account_index: req.account_index,
        fee: req.fee_zat,
        spends,
        transparent_inputs,
        outputs,
    })
    .map_err(|e| anyhow!("build_ironwood_transaction: {e}"))
}

/// Decode a destination address string into an [`IronwoodDestination`].
///
/// Accepts transparent (P2PKH/P2SH) addresses and unified addresses with an
/// Orchard receiver — the same receiver bytes as [`decode_destination`] uses
/// for the Orchard pool: there is no separate "Ironwood" unified-address
/// receiver kind (ZIP 316), the pool is selected by which builder method is
/// called with the decoded address, not by its encoding. Sapling z-addresses
/// and ZIP-320 TEX addresses are rejected.
fn decode_ironwood_destination(
    network: &zcash_protocol::consensus::Network,
    address: &str,
) -> Result<IronwoodDestination> {
    let addr = Address::decode(network, address)
        .ok_or_else(|| anyhow!("invalid destination address: {address}"))?;
    match addr {
        Address::Transparent(ta) => Ok(IronwoodDestination::Transparent(ta)),
        Address::Unified(ua) => {
            if let Some(oa) = ua.orchard() {
                Ok(IronwoodDestination::Ironwood(*oa))
            } else if let Some(ta) = ua.transparent() {
                Ok(IronwoodDestination::Transparent(*ta))
            } else {
                Err(anyhow!(
                    "unified address has no Orchard or Transparent receiver: {address}"
                ))
            }
        }
        Address::Sapling(_) => Err(anyhow!("Sapling destination not supported")),
        Address::Tex(_) => Err(anyhow!("ZIP-320 TEX address not supported")),
    }
}

/// Decode and verify each transparent input's signing-key derivation against the
/// account's transparent key, producing the builder's `TransparentInput` records.
/// Shared by both orchestrators (step 5 of each).
///
/// `account_pubkey` is `None` only when the caller supplied neither a UFVK with a
/// transparent component nor a standalone transparent account pubkey; that is an
/// error as soon as there is any input to verify, so a spend never proceeds on an
/// unverified derivation path.
fn decode_transparent_inputs(
    account_pubkey: Option<&AccountPubKey>,
    dtos: &[TransparentInputDto],
) -> Result<Vec<TransparentInput>> {
    use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};

    dtos.iter()
        .map(|dto| {
            let txid = hex_to_array::<32>(&dto.txid_hex, "txid")?;
            let pubkey = hex_to_array::<33>(&dto.pubkey_hex, "pubkey")?;
            let script_pubkey = hex::decode(&dto.script_pubkey_hex)
                .map_err(|e| anyhow!("script_pubkey hex: {e}"))?;

            let scope = match dto.derivation_scope {
                0 => TransparentKeyScope::EXTERNAL,
                1 => TransparentKeyScope::INTERNAL,
                other => {
                    return Err(anyhow!(
                        "transparent input derivation_scope must be 0 (external) or 1 (internal), \
                         got {other}"
                    ))
                }
            };
            let apk = account_pubkey.ok_or_else(|| {
                anyhow!(
                    "transparent inputs were supplied but no transparent account key was given \
                     to derive (and verify) their signing keys from; pass \
                     transparent_account_pubkey, or a UFVK carrying a transparent component"
                )
            })?;
            let index = NonHardenedChildIndex::from_index(dto.address_index).ok_or_else(|| {
                anyhow!(
                    "transparent input address_index {} is not a valid non-hardened index",
                    dto.address_index
                )
            })?;
            let derived_pubkey = apk.derive_address_pubkey(scope, index).map_err(|e| {
                anyhow!(
                    "failed to derive transparent input pubkey at scope {} index {}: {e}",
                    dto.derivation_scope,
                    dto.address_index
                )
            })?;
            if derived_pubkey.serialize() != pubkey {
                return Err(anyhow!(
                    "transparent input pubkey does not match the key derived from the account's \
                     transparent key at scope {} index {}; the supplied (derivation_scope, \
                     address_index) does not identify this UTXO's key",
                    dto.derivation_scope,
                    dto.address_index
                ));
            }

            Ok(TransparentInput {
                txid,
                vout: dto.vout,
                script_pubkey,
                value: dto.value_zat,
                pubkey,
                derivation_scope: dto.derivation_scope,
                derivation_address_index: dto.address_index,
            })
        })
        .collect::<Result<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_spend() -> SpendInputDto {
        SpendInputDto {
            recipient_hex: "00".repeat(43),
            value_zat: 100_000,
            rho_hex: "00".repeat(32),
            rseed_hex: "ab".repeat(32),
            cmx_hex: "00".repeat(32),
            position: 0,
        }
    }

    fn dummy_output() -> OutputRequestDto {
        OutputRequestDto {
            address: "u1somewhere".into(),
            value_zat: 10_000,
            memo: None,
        }
    }

    fn dummy_transparent_input() -> TransparentInputDto {
        TransparentInputDto {
            txid_hex: "01".repeat(32),
            vout: 0,
            script_pubkey_hex: "76a914".to_string() + &"11".repeat(20) + "88ac",
            value_zat: 100_000,
            pubkey_hex: "02".to_string() + &"01".repeat(32),
            derivation_scope: 0,
            address_index: 0,
        }
    }

    fn dummy_transparent_output() -> OutputRequestDto {
        OutputRequestDto {
            address: "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".into(),
            value_zat: 10_000,
            memo: None,
        }
    }

    // ── DTO decoding tests ────────────────────────────────────────────────────

    #[test]
    fn hex_to_array_rejects_wrong_length() {
        let err = hex_to_array::<32>("aabb", "cmx").unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn hex_to_array_rejects_bad_hex() {
        let err = hex_to_array::<32>("zz".repeat(32).as_str(), "cmx").unwrap_err();
        assert!(err.to_string().contains("cmx hex decode"));
    }

    #[test]
    fn transparent_input_dto_bad_txid_hex_rejected() {
        let dto = TransparentInputDto {
            txid_hex: "not_hex".into(),
            ..dummy_transparent_input()
        };
        let result: Result<[u8; 32]> = hex_to_array::<32>(&dto.txid_hex, "txid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("txid hex decode"));
    }

    #[test]
    fn transparent_input_dto_wrong_txid_length_rejected() {
        let dto = TransparentInputDto {
            txid_hex: "aabb".into(), // 2 bytes, not 32
            ..dummy_transparent_input()
        };
        let result: Result<[u8; 32]> = hex_to_array::<32>(&dto.txid_hex, "txid");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected 32 bytes"));
    }

    #[test]
    fn transparent_input_dto_bad_pubkey_hex_rejected() {
        let dto = TransparentInputDto {
            pubkey_hex: "zz".repeat(33),
            ..dummy_transparent_input()
        };
        let result: Result<[u8; 33]> = hex_to_array::<33>(&dto.pubkey_hex, "pubkey");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pubkey hex decode"));
    }

    #[test]
    fn transparent_input_dto_wrong_pubkey_length_rejected() {
        let dto = TransparentInputDto {
            pubkey_hex: "aabb".into(), // 2 bytes, not 33
            ..dummy_transparent_input()
        };
        let result: Result<[u8; 33]> = hex_to_array::<33>(&dto.pubkey_hex, "pubkey");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected 33 bytes"));
    }

    #[test]
    fn transparent_input_dto_bad_script_pubkey_rejected() {
        let dto = TransparentInputDto {
            script_pubkey_hex: "not_hex_zz".into(),
            ..dummy_transparent_input()
        };
        let result = hex::decode(&dto.script_pubkey_hex);
        assert!(result.is_err());
    }

    // ── Guard tests (no network) ──────────────────────────────────────────────

    #[tokio::test]
    async fn empty_spends_and_transparent_inputs_returns_error() {
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some("uview1bogus".into()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![],
            outputs: vec![dummy_output()],
            anchor_height: Some(1),
        };
        let err = craft_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("no inputs"), "got: {err}");
    }

    #[tokio::test]
    async fn empty_outputs_returns_error() {
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some("uview1bogus".into()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![dummy_spend()],
            transparent_inputs: vec![],
            outputs: vec![],
            anchor_height: Some(1),
        };
        let err = craft_transaction(req).await.unwrap_err();
        assert!(
            err.to_string().contains("outputs list is empty"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn malformed_ufvk_returns_error() {
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some("this is not a UFVK".into()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![dummy_spend()],
            transparent_inputs: vec![],
            outputs: vec![dummy_output()],
            anchor_height: Some(1),
        };
        let err = craft_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("UFVK decode failed"), "got: {err}");
    }

    /// A request with transparent inputs only (Public→Public routing) should
    /// NOT fail with "no inputs" — it must pass the input guard and fail later
    /// on the bogus gRPC port or UFVK, NOT with the "spends list is empty" message.
    #[tokio::test]
    async fn transparent_only_input_passes_input_guard() {
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some("uview1bogus".into()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![dummy_transparent_output()],
            anchor_height: Some(1),
        };
        let err = craft_transaction(req).await.unwrap_err();
        // Must NOT fail with "no inputs" — that error is only for the empty-both case.
        assert!(
            !err.to_string().contains("no inputs"),
            "should not fail with 'no inputs', got: {err}"
        );
        // Should fail with UFVK decode error (first real operation after guard).
        assert!(
            err.to_string().contains("UFVK"),
            "expected UFVK error, got: {err}"
        );
    }

    /// Regression (target-height bug): Public→Public with `anchor_height: None`
    /// must resolve the anchor height from the live chain tip rather than
    /// silently defaulting to a fixed low height (which produced target_height
    /// 41, below NU5, failing every send). With a valid UFVK and a transparent
    /// output the request gets past the guards and change derivation, then hits
    /// the tip query in the anchor-routing step and fails on the refused gRPC
    /// port — proving the transparent-only path now queries the tip when no
    /// explicit anchor is supplied.
    #[tokio::test]
    async fn public_to_public_resolves_tip_when_anchor_height_omitted() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Real mainnet UFVK (has a transparent component, so change derivation
        // does not fast-fail).
        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();

        // Refused port: bind then drop to guarantee ECONNREFUSED.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };

        let req = CraftRequest {
            grpc_url: format!("https://127.0.0.1:{}", addr.port()),
            ufvk: Some(keys.ufvk.clone()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![dummy_transparent_output()],
            anchor_height: None, // must trigger a tip query on the transparent path
        };

        let err = craft_transaction(req).await.unwrap_err();
        // Must reach the tip query (and fail there), not an earlier guard, and
        // never the old silent default.
        assert!(
            !err.to_string().contains("no inputs"),
            "should pass the input guard, got: {err}"
        );
        assert!(
            !err.to_string().contains("UFVK"),
            "UFVK must parse cleanly, got: {err}"
        );
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "expected tip-query connect failure, got: {err}"
        );
    }

    /// Public→Private routing: transparent inputs + an Orchard (unified-address)
    /// output and no Orchard spends must route through the `fetch_orchard_anchor`
    /// (anchor-only) branch, NOT `compute_witnesses`. With a valid UFVK and a
    /// valid Orchard destination, the request gets past the input guard, UFVK
    /// parse and destination decode, then fails at the anchor fetch on a refused
    /// gRPC port — proving the Public→Private path is wired to the anchor-only
    /// orchestrator.
    #[tokio::test]
    async fn public_to_private_routes_through_anchor_only_fetch() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_protocol::consensus::Network;

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Real UFVK + matching Orchard unified address for mainnet.
        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (_net, ufvk_str) = Ufvk::decode(&keys.ufvk).unwrap();
        let ufvk = UnifiedFullViewingKey::parse(&ufvk_str).unwrap();
        let (ua, _) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let orchard_addr = ua.encode(&Network::MainNetwork);

        // Refused port: bind then drop to guarantee ECONNREFUSED.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };

        let req = CraftRequest {
            grpc_url: format!("https://127.0.0.1:{}", addr.port()),
            ufvk: Some(keys.ufvk.clone()),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 15_000,
            spends: vec![], // no Orchard spends → anchor-only
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![OutputRequestDto {
                address: orchard_addr,
                value_zat: 10_000,
                memo: None,
            }],
            anchor_height: Some(1),
        };

        let err = craft_transaction(req).await.unwrap_err();
        // Must reach the anchor fetch (and fail there), not an earlier guard.
        assert!(
            !err.to_string().contains("no inputs"),
            "should pass the input guard, got: {err}"
        );
        assert!(
            !err.to_string().contains("UFVK"),
            "UFVK must parse cleanly, got: {err}"
        );
        assert!(
            !err.to_string().contains("invalid destination address"),
            "Orchard destination must decode, got: {err}"
        );
        // The anchor-only fetch is the first network operation and must fail here.
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "expected anchor-fetch connect failure, got: {err}"
        );
    }

    /// Public→Public with a transparent-key-less UFVK and surplus value (change
    /// required) must fail fast with an actionable error at the change-derivation
    /// step — before any network operation — rather than surfacing the deep,
    /// generic builder error later.
    #[tokio::test]
    async fn transparent_change_without_transparent_ufvk_fails_fast() {
        use zcash_address::unified::{Container, Fvk};
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Derive a real UFVK, then strip the transparent (P2PKH) component so the
        // wallet has no transparent receiver to source an internal change address.
        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (net, container) = Ufvk::decode(&keys.ufvk).unwrap();
        let filtered = container
            .items_as_parsed()
            .iter()
            .filter(|item| !matches!(item, Fvk::P2pkh(_)))
            .cloned()
            .collect::<Vec<_>>();
        let ufvk_no_transparent = Ufvk::try_from_items(filtered).unwrap().encode(&net);

        // 100_000 in, 10_000 out, 10_000 fee → 80_000 of transparent change.
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some(ufvk_no_transparent),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![dummy_transparent_output()],
            anchor_height: Some(1),
        };

        let err = craft_transaction(req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("transparent change of 80000 zatoshis is required"),
            "expected actionable change error, got: {msg}"
        );
        assert!(
            msg.contains("no transparent account key was supplied"),
            "error must explain the missing transparent account key, got: {msg}"
        );
    }

    /// Public→Public with a transparent-key-less UFVK but an exact-balance
    /// transaction (no change) must NOT trip the fast-fail guard; it should get
    /// past change derivation and proceed to the build.
    #[tokio::test]
    async fn transparent_exact_balance_without_transparent_ufvk_is_allowed() {
        use zcash_address::unified::{Container, Fvk};
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (net, container) = Ufvk::decode(&keys.ufvk).unwrap();
        let filtered = container
            .items_as_parsed()
            .iter()
            .filter(|item| !matches!(item, Fvk::P2pkh(_)))
            .cloned()
            .collect::<Vec<_>>();
        let ufvk_no_transparent = Ufvk::try_from_items(filtered).unwrap().encode(&net);

        // 100_000 in, 90_000 out, 10_000 fee → exactly 0 change.
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: Some(ufvk_no_transparent),
            transparent_account_pubkey_hex: None,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![OutputRequestDto {
                value_zat: 90_000,
                ..dummy_transparent_output()
            }],
            anchor_height: Some(1),
        };

        let err = craft_transaction(req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("transparent change"),
            "exact-balance tx must not trip the change guard, got: {msg}"
        );
    }

    // ── Transparent sends without a UFVK ──────────────────────────────────────
    //
    // A fully transparent send reads no shielded key material, so the wallet must
    // be able to build one from the account's transparent pubkey alone — the
    // payload of the account xpub it already holds. Requiring a UFVK there would
    // force a viewing-key export on a user who only ever holds public funds.

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// The test account's transparent key material, in both the forms a caller can
    /// supply: the full UFVK, and the standalone 65-byte account pubkey (chain
    /// code ‖ compressed pubkey) that a wallet slices out of its account xpub.
    fn test_account_keys() -> (String, AccountPubKey, String) {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        let keys = derive_keys(TEST_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (_net, container) = Ufvk::decode(&keys.ufvk).unwrap();
        let ufvk = UnifiedFullViewingKey::parse(&container).unwrap();
        let apk = ufvk
            .transparent()
            .expect("test UFVK has a P2PKH item")
            .clone();
        let apk_hex = hex::encode(apk.serialize());
        (keys.ufvk, apk, apk_hex)
    }

    /// A transparent input whose pubkey and scriptPubKey really are the ones the
    /// account key derives at `(scope, index)`, so it passes the step-5
    /// verification and reaches the builder.
    fn owned_transparent_input(apk: &AccountPubKey, value_zat: u64) -> TransparentInputDto {
        use zcash_transparent::keys::{
            IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope,
        };

        let index = NonHardenedChildIndex::from_index(0).unwrap();
        let pubkey = apk
            .derive_address_pubkey(TransparentKeyScope::EXTERNAL, index)
            .unwrap();
        let address = apk
            .derive_external_ivk()
            .unwrap()
            .derive_address(index)
            .unwrap();
        // `Script` is the serialized (byte) form of the address's scriptPubKey;
        // `TransparentAddress::script()` itself yields opcodes.
        let script_pubkey = zcash_transparent::address::Script::from(address.script());

        TransparentInputDto {
            txid_hex: "01".repeat(32),
            vout: 0,
            script_pubkey_hex: hex::encode(&script_pubkey.0 .0),
            value_zat,
            pubkey_hex: hex::encode(pubkey.serialize()),
            derivation_scope: 0,
            address_index: 0,
        }
    }

    /// Mainnet height well past NU5, so `target_height` lands on a real consensus
    /// branch. Explicit, so the transparent path resolves it without any network.
    const OFFLINE_ANCHOR_HEIGHT: u32 = 2_800_000;

    fn transparent_request(
        ufvk: Option<String>,
        transparent_account_pubkey_hex: Option<String>,
        input: TransparentInputDto,
        output_value_zat: u64,
    ) -> CraftRequest {
        CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk,
            transparent_account_pubkey_hex,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![input],
            outputs: vec![OutputRequestDto {
                value_zat: output_value_zat,
                ..dummy_transparent_output()
            }],
            anchor_height: Some(OFFLINE_ANCHOR_HEIGHT),
        }
    }

    /// The regression this whole path exists for: Public→Public with **no UFVK**,
    /// only the transparent account pubkey, must build a complete PCZT — change
    /// output included — without touching the network or the shielded pool.
    #[tokio::test]
    async fn public_to_public_builds_without_ufvk() {
        let (_ufvk, apk, apk_hex) = test_account_keys();
        // 100_000 in, 10_000 out, 10_000 fee → 80_000 of transparent change, so
        // the change-derivation path is exercised rather than skipped.
        let req = transparent_request(
            None,
            Some(apk_hex),
            owned_transparent_input(&apk, 100_000),
            10_000,
        );

        let out = craft_transaction(req).await.expect("transparent build");
        assert_eq!(out.n_transparent_inputs, 1);
        assert_eq!(
            out.n_transparent_outputs, 2,
            "recipient + transparent change"
        );
        assert_eq!(out.n_actions_orchard, 0, "no Orchard bundle in a t→t send");
        assert_eq!(out.fee, 10_000);
    }

    /// The transparent account pubkey and the UFVK's P2PKH item are the same 65
    /// bytes, so the two forms must produce byte-identical transactions. This is
    /// the fund-safety property behind the option: the change address and every
    /// input's signing path cannot depend on which form the caller passed.
    #[tokio::test]
    async fn transparent_account_pubkey_and_ufvk_build_identically() {
        let (ufvk, apk, apk_hex) = test_account_keys();

        let from_ufvk = craft_transaction(transparent_request(
            Some(ufvk),
            None,
            owned_transparent_input(&apk, 100_000),
            10_000,
        ))
        .await
        .expect("build from UFVK");
        let from_apk = craft_transaction(transparent_request(
            None,
            Some(apk_hex),
            owned_transparent_input(&apk, 100_000),
            10_000,
        ))
        .await
        .expect("build from account pubkey");

        assert_eq!(from_apk.pczt_bytes, from_ufvk.pczt_bytes);
    }

    /// Neither form supplied: refused by the up-front guard, so the caller gets
    /// one actionable message instead of whichever of change derivation or input
    /// verification the flow would have reached first.
    #[tokio::test]
    async fn no_account_key_at_all_is_rejected_up_front() {
        let (_ufvk, apk, _apk_hex) = test_account_keys();
        let req = transparent_request(None, None, owned_transparent_input(&apk, 100_000), 90_000);

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(msg.contains("craft: no account key"), "got: {msg}");
    }

    /// The guard is about the *absence of any key source*, not about the flow:
    /// an Orchard spend with neither form hits the same up-front message rather
    /// than the Orchard-specific one, since there is nothing to build from.
    #[tokio::test]
    async fn no_account_key_is_rejected_before_the_flow_matters() {
        let req = CraftRequest {
            spends: vec![dummy_spend()],
            transparent_inputs: vec![],
            ..transparent_request(None, None, dummy_transparent_input(), 10_000)
        };

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(msg.contains("craft: no account key"), "got: {msg}");
    }

    /// A UFVK that carries no transparent component still leaves the deeper
    /// verification in place: the guard above passes (a key source *was*
    /// supplied) and step 5 refuses the input it cannot verify.
    #[tokio::test]
    async fn transparent_input_unverifiable_under_the_supplied_ufvk_is_rejected() {
        use zcash_address::unified::{Container, Fvk};
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        let (_ufvk, apk, _apk_hex) = test_account_keys();
        let keys = derive_keys(TEST_MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (net, container) = Ufvk::decode(&keys.ufvk).unwrap();
        let filtered = container
            .items_as_parsed()
            .iter()
            .filter(|item| !matches!(item, Fvk::P2pkh(_)))
            .cloned()
            .collect::<Vec<_>>();
        let ufvk_no_transparent = Ufvk::try_from_items(filtered).unwrap().encode(&net);

        // Exact balance, so the change guard does not fire first and the error
        // comes from input verification.
        let req = transparent_request(
            Some(ufvk_no_transparent),
            None,
            owned_transparent_input(&apk, 100_000),
            90_000,
        );

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(
            msg.contains("no transparent account key was given"),
            "got: {msg}"
        );
    }

    /// The two forms describing different accounts is a caller bug: deriving from
    /// either one would produce a change address or signing path that does not
    /// belong to the funds being spent, so the build fails instead of choosing.
    #[tokio::test]
    async fn mismatched_account_pubkey_and_ufvk_is_rejected() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        let (ufvk, apk, _apk_hex) = test_account_keys();
        let other = derive_keys(TEST_MNEMONIC, 1, ZcashNetwork::Mainnet, None).unwrap();
        let (_net, other_container) = Ufvk::decode(&other.ufvk).unwrap();
        let other_apk_hex = hex::encode(
            UnifiedFullViewingKey::parse(&other_container)
                .unwrap()
                .transparent()
                .unwrap()
                .serialize(),
        );

        let req = transparent_request(
            Some(ufvk),
            Some(other_apk_hex),
            owned_transparent_input(&apk, 100_000),
            10_000,
        );

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(
            msg.contains("does not match the UFVK's transparent component"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn malformed_transparent_account_pubkey_is_rejected() {
        let (_ufvk, apk, _apk_hex) = test_account_keys();
        let req = transparent_request(
            None,
            Some("ff".repeat(65)), // right length, not a valid secp256k1 point
            owned_transparent_input(&apk, 100_000),
            10_000,
        );

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(
            msg.contains("not a valid account-level transparent pubkey"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn transparent_account_pubkey_wrong_length_is_rejected() {
        let (_ufvk, apk, _apk_hex) = test_account_keys();
        let req = transparent_request(
            None,
            Some("ab".repeat(64)),
            owned_transparent_input(&apk, 100_000),
            10_000,
        );

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(
            msg.contains("transparent_account_pubkey: expected 65 bytes"),
            "got: {msg}"
        );
    }

    /// A shielded recipient makes the flow carry an Orchard bundle, which needs
    /// Orchard key material the transparent pubkey cannot supply — so the UFVK
    /// stays mandatory there, with an error that says so.
    #[tokio::test]
    async fn shielded_flow_without_ufvk_is_rejected() {
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_protocol::consensus::Network;

        let (ufvk_str, apk, apk_hex) = test_account_keys();
        let (_net, container) = Ufvk::decode(&ufvk_str).unwrap();
        let (ua, _) = UnifiedFullViewingKey::parse(&container)
            .unwrap()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();

        let req = CraftRequest {
            // A unified address resolves to an Orchard destination.
            outputs: vec![OutputRequestDto {
                address: ua.encode(&Network::MainNetwork),
                value_zat: 10_000,
                memo: None,
            }],
            ..transparent_request(
                None,
                Some(apk_hex),
                owned_transparent_input(&apk, 100_000),
                10_000,
            )
        };

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(msg.contains("a UFVK is required"), "got: {msg}");
    }

    /// Same for an Orchard spend: the note cannot be spent without its FVK, and
    /// the transparent account pubkey is no substitute — supplying it gets past
    /// the key-source guard and straight to the Orchard requirement.
    #[tokio::test]
    async fn orchard_spend_without_ufvk_is_rejected() {
        let (_ufvk, _apk, apk_hex) = test_account_keys();
        let req = CraftRequest {
            spends: vec![dummy_spend()],
            transparent_inputs: vec![],
            ..transparent_request(None, Some(apk_hex), dummy_transparent_input(), 10_000)
        };

        let msg = craft_transaction(req).await.unwrap_err().to_string();
        assert!(msg.contains("a UFVK is required"), "got: {msg}");
    }

    // ── Ironwood (NU6.3) — craft_ironwood_transaction ─────────────────────────

    fn dummy_ironwood_spend() -> IronwoodSpendInputDto {
        IronwoodSpendInputDto {
            recipient_hex: "00".repeat(43),
            value_zat: 100_000,
            rho_hex: "00".repeat(32),
            rseed_hex: "ab".repeat(32),
            cmx_hex: "00".repeat(32),
            position: 0,
        }
    }

    fn dummy_ironwood_output() -> IronwoodOutputRequestDto {
        IronwoodOutputRequestDto {
            address: "u1somewhere".into(),
            value_zat: 10_000,
            memo: None,
        }
    }

    #[tokio::test]
    async fn ironwood_empty_spends_and_transparent_inputs_returns_error() {
        let req = IronwoodCraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: "uview1bogus".into(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![],
            outputs: vec![dummy_ironwood_output()],
            anchor_height: Some(1),
        };
        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("no inputs"), "got: {err}");
    }

    #[tokio::test]
    async fn ironwood_empty_outputs_returns_error() {
        let req = IronwoodCraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: "uview1bogus".into(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![dummy_ironwood_spend()],
            transparent_inputs: vec![],
            outputs: vec![],
            anchor_height: Some(1),
        };
        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(
            err.to_string().contains("outputs list is empty"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn ironwood_malformed_ufvk_returns_error() {
        let req = IronwoodCraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: "this is not a UFVK".into(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![dummy_ironwood_spend()],
            transparent_inputs: vec![],
            outputs: vec![dummy_ironwood_output()],
            anchor_height: Some(1),
        };
        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("UFVK decode failed"), "got: {err}");
    }

    /// A request with transparent inputs only and no Ironwood spends is a
    /// legitimate Public→Ironwood shape (the Ironwood output alone makes the
    /// bundle non-empty) — it must NOT fail with "no inputs".
    #[tokio::test]
    async fn ironwood_transparent_only_input_passes_input_guard() {
        let req = IronwoodCraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: "uview1bogus".into(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![dummy_ironwood_output()],
            anchor_height: Some(1),
        };
        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(
            !err.to_string().contains("no inputs"),
            "should pass the input guard, got: {err}"
        );
        assert!(
            err.to_string().contains("UFVK"),
            "expected UFVK error, got: {err}"
        );
    }

    /// Transparent inputs + a transparent-only output (no Ironwood spends, no
    /// Ironwood output) is not a valid Ironwood send — must be rejected with
    /// the dedicated "no Ironwood bundle" error before any network I/O, rather
    /// than silently falling through to a Public→Public build.
    #[tokio::test]
    async fn ironwood_no_bundle_transparent_only_returns_error() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();

        let req = IronwoodCraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: keys.ufvk,
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![IronwoodOutputRequestDto {
                address: "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".into(),
                value_zat: 10_000,
                memo: None,
            }],
            anchor_height: Some(1),
        };
        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("no Ironwood bundle"), "got: {err}");
    }

    /// Ironwood→* routing: a real Ironwood spend must route through
    /// `compute_ironwood_witnesses`, not the Orchard witness path — reaching
    /// the gRPC witness fetch (and failing there, on a refused port) rather
    /// than an earlier guard.
    #[tokio::test]
    async fn ironwood_spend_routes_through_witness_fetch() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_protocol::consensus::Network;

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        // A real (Orchard-family) destination address matching the UFVK — the
        // output must decode successfully so the request reaches the witness
        // fetch, not fail earlier on address decoding.
        let (_net, ufvk_str) = Ufvk::decode(&keys.ufvk).unwrap();
        let ufvk = UnifiedFullViewingKey::parse(&ufvk_str).unwrap();
        let (ua, _) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let ironwood_addr = ua.encode(&Network::MainNetwork);

        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };

        let req = IronwoodCraftRequest {
            grpc_url: format!("https://127.0.0.1:{}", addr.port()),
            ufvk: keys.ufvk.clone(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![dummy_ironwood_spend()],
            transparent_inputs: vec![],
            outputs: vec![IronwoodOutputRequestDto {
                address: ironwood_addr,
                value_zat: 10_000,
                memo: None,
            }],
            anchor_height: Some(1),
        };

        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(
            !err.to_string().contains("no inputs"),
            "should pass the input guard, got: {err}"
        );
        assert!(
            !err.to_string().contains("UFVK"),
            "UFVK must parse cleanly, got: {err}"
        );
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "expected witness-fetch connect failure, got: {err}"
        );
    }

    /// Public→Ironwood routing: transparent inputs + an Ironwood (unified
    /// address) output and no Ironwood spends must route through
    /// `fetch_ironwood_anchor` (anchor-only), not `compute_ironwood_witnesses`.
    #[tokio::test]
    async fn public_to_ironwood_routes_through_anchor_only_fetch() {
        use zcash_crypto::keys::{derive_keys, ZcashNetwork};
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_protocol::consensus::Network;

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let keys = derive_keys(MNEMONIC, 0, ZcashNetwork::Mainnet, None).unwrap();
        let (_net, ufvk_str) = Ufvk::decode(&keys.ufvk).unwrap();
        let ufvk = UnifiedFullViewingKey::parse(&ufvk_str).unwrap();
        let (ua, _) = ufvk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let ironwood_addr = ua.encode(&Network::MainNetwork);

        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };

        let req = IronwoodCraftRequest {
            grpc_url: format!("https://127.0.0.1:{}", addr.port()),
            ufvk: keys.ufvk.clone(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 15_000,
            spends: vec![], // no Ironwood spends → anchor-only
            transparent_inputs: vec![dummy_transparent_input()],
            outputs: vec![IronwoodOutputRequestDto {
                address: ironwood_addr,
                value_zat: 10_000,
                memo: None,
            }],
            anchor_height: Some(1),
        };

        let err = craft_ironwood_transaction(req).await.unwrap_err();
        assert!(
            !err.to_string().contains("no inputs"),
            "should pass the input guard, got: {err}"
        );
        assert!(
            !err.to_string().contains("UFVK"),
            "UFVK must parse cleanly, got: {err}"
        );
        assert!(
            !err.to_string().contains("invalid destination address"),
            "Ironwood destination must decode, got: {err}"
        );
        assert!(
            err.to_string().contains("gRPC connect failed"),
            "expected anchor-fetch connect failure, got: {err}"
        );
    }
}
