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

use anyhow::{anyhow, Result};
use orchard::keys::Scope;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_crypto::{
    craft::{
        build_transaction, BuildInputs, BuildOutput, Destination, OrchardSpendInput, OutputRequest,
        TransparentInput, DEFAULT_TX_EXPIRY_DELTA,
    },
    network::parse_network,
};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};

use crate::witness::{compute_witnesses, fetch_orchard_anchor, NoteRef, WitnessRequest};

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

    let network = parse_network(req.network.as_deref()).map_err(|e| anyhow!("{e}"))?;
    let seed_fingerprint = hex_to_array::<32>(&req.seed_fingerprint_hex, "seed_fingerprint")?;

    // ── 1. Parse UFVK ─────────────────────────────────────────────────────────
    let (_net, ufvk_str) =
        Ufvk::decode(&req.ufvk).map_err(|e| anyhow!("UFVK decode failed: {e:?}"))?;
    let ufvk =
        UnifiedFullViewingKey::parse(&ufvk_str).map_err(|e| anyhow!("UFVK parse failed: {e:?}"))?;

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

    // ── 3. Transparent change address (Public→Public) ─────────────────────────
    // For the transparent-only flow we derive the internal change address from
    // the UFVK's transparent component when available, otherwise accept None
    // (exact-balance transactions need no change address). When the UFVK has no
    // transparent receiver we can only proceed if the transaction produces no
    // change; if it would, fail fast here with an actionable error rather than
    // letting the deeper, generic builder error surface later.
    // Derive the internal change address *and* the metadata the device needs to
    // recognize it as change: the change pubkey (33 bytes) and its non-hardened
    // address index. These flow into the change output's `bip32_derivation`.
    let transparent_change: Option<(
        zcash_transparent::address::TransparentAddress,
        [u8; 33],
        u32,
    )> = if !has_orchard_bundle {
        let derived = ufvk.transparent().and_then(|tpk| {
            use zcash_transparent::keys::{IncomingViewingKey, TransparentKeyScope};
            let ivk = tpk.derive_internal_ivk().ok()?;
            let (addr, index) = ivk.default_address();
            // The change output's bip32_derivation pubkey must be the exact pubkey
            // backing `addr` so the device's re-derive-and-match check passes.
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
    let (anchor, spends) = if has_orchard_spends {
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

        (witness_out.anchor, spends)
    } else if has_orchard_outputs {
        // Public→Private: fetch anchor only (no spend witnesses).
        let witness_out = fetch_orchard_anchor(&req.grpc_url, req.anchor_height, None).await?;
        (witness_out.anchor, vec![])
    } else {
        // Public→Public: no Orchard bundle; anchor is unused.
        ([0u8; 32], vec![])
    };

    // ── 5. Decode transparent inputs ─────────────────────────────────────────
    // For each input we verify that its (derivation_scope, address_index) really
    // identifies the supplied pubkey under this UFVK, then record the path so the
    // builder can stamp the input's `bip32_derivation` (the device's only source
    // for the transparent signing path). The device signs with that path without
    // re-checking it against the pubkey, so getting it wrong would yield an
    // invalid signature — this up-front check turns that into a clear build error.
    let account_pubkey = ufvk.transparent();
    let transparent_inputs: Vec<TransparentInput> = req
        .transparent_inputs
        .iter()
        .map(|dto| {
            use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};

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
                    "transparent inputs were supplied but the UFVK has no transparent component \
                     to derive (and verify) their signing keys from"
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
                    "transparent input pubkey does not match the key derived from the UFVK at \
                     scope {} index {}; the supplied (derivation_scope, address_index) does not \
                     identify this UTXO's key",
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
        .collect::<Result<_>>()?;

    // Destinations were decoded once in step 1 and reused here as `outputs`.

    // ── 7. target_height = anchor_height + DEFAULT_TX_EXPIRY_DELTA ───────────
    let anchor_height: u32 = req.anchor_height.unwrap_or(0).max(1);
    let target_height = anchor_height
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
            ufvk: "uview1bogus".into(),
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
            ufvk: "uview1bogus".into(),
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
            ufvk: "this is not a UFVK".into(),
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
            ufvk: "uview1bogus".into(),
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
            ufvk: keys.ufvk.clone(),
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
            ufvk: ufvk_no_transparent,
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
            msg.contains("UFVK has no transparent receiver"),
            "error must explain the missing transparent receiver, got: {msg}"
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
            ufvk: ufvk_no_transparent,
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
}
