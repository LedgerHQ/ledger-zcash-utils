//! Orchard transaction-crafting orchestrator.
//!
//! Wraps `zcash_crypto::craft::build_transaction` with the gRPC-side
//! concerns: anchor resolution via `compute_witnesses`, UFVK
//! parsing, and destination-address decoding.

use anyhow::{anyhow, Result};
use orchard::keys::Scope;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_crypto::{
    craft::{
        build_transaction, BuildInputs, BuildOutput, Destination, OrchardSpendInput, OutputRequest,
        DEFAULT_TX_EXPIRY_DELTA,
    },
    network::parse_network,
};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};

use crate::witness::{compute_witnesses, NoteRef, WitnessRequest};

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
    pub outputs: Vec<OutputRequestDto>,
    /// Explicit anchor height; `None` ⇒ tip − 10 (defaults via the witness
    /// orchestrator).
    pub anchor_height: Option<u32>,
}

/// Compute witnesses, decode addresses, then call the pure builder.
pub async fn craft_orchard_transaction(req: CraftRequest) -> Result<BuildOutput> {
    if req.spends.is_empty() {
        return Err(anyhow!("craft: spends list is empty"));
    }
    if req.outputs.is_empty() {
        return Err(anyhow!("craft: outputs list is empty"));
    }

    let network = parse_network(req.network.as_deref()).map_err(|e| anyhow!("{e}"))?;
    let seed_fingerprint = hex_to_array::<32>(&req.seed_fingerprint_hex, "seed_fingerprint")?;

    // ── 1. Parse UFVK → Orchard FVK + change address + OVK ───────────────────
    let (_net, ufvk_str) =
        Ufvk::decode(&req.ufvk).map_err(|e| anyhow!("UFVK decode failed: {e:?}"))?;
    let ufvk = UnifiedFullViewingKey::parse(&ufvk_str)
        .map_err(|e| anyhow!("UFVK parse failed: {e:?}"))?;
    let orchard_fvk = ufvk
        .orchard()
        .ok_or_else(|| anyhow!("UFVK does not contain an Orchard component"))?
        .clone();
    let change_address = orchard_fvk.address_at(0u32, Scope::Internal);
    let ovk = Some(orchard_fvk.to_ovk(Scope::External));

    // ── 2. Compute witnesses (delegates to `zcash_sync::witness::compute_witnesses`) ────────────────────────
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

    // ── 3. Convert spends DTO → domain type with attached witness ────────────
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

    // ── 4. Decode destination addresses ──────────────────────────────────────
    let outputs: Vec<OutputRequest> = req
        .outputs
        .iter()
        .map(|o| {
            let addr = Address::decode(&network, &o.address)
                .ok_or_else(|| anyhow!("invalid destination address: {}", o.address))?;
            let destination = match addr {
                Address::Transparent(ta) => Destination::Transparent(ta),
                Address::Unified(ua) => {
                    if let Some(oa) = ua.orchard() {
                        Destination::Orchard(*oa)
                    } else if let Some(ta) = ua.transparent() {
                        Destination::Transparent(*ta)
                    } else {
                        return Err(anyhow!(
                            "unified address has no Orchard or Transparent receiver: {}",
                            o.address
                        ));
                    }
                }
                Address::Sapling(_) => {
                    return Err(anyhow!(
                        "Sapling destination not supported in (Orchard-only)"
                    ));
                }
                Address::Tex(_) => {
                    return Err(anyhow!("ZIP-320 TEX address not supported in (Orchard-only)"));
                }
            };
            Ok(OutputRequest {
                destination,
                value: o.value_zat,
                memo: o.memo.as_ref().map(|s| s.as_bytes().to_vec()),
            })
        })
        .collect::<Result<_>>()?;

    // ── 5. target_height = anchor_height + DEFAULT_TX_EXPIRY_DELTA ───────────
    let anchor_height: u32 = req.anchor_height.unwrap_or(0).max(1);
    let target_height = anchor_height
        .checked_add(DEFAULT_TX_EXPIRY_DELTA)
        .ok_or_else(|| anyhow!("target_height overflow"))?;

    // ── 6. Build ──────────────────────────────────────────────────────────────
    build_transaction(BuildInputs {
        network,
        target_height,
        orchard_fvk,
        ovk,
        change_address,
        anchor: witness_out.anchor,
        seed_fingerprint,
        account_index: req.account_index,
        fee: req.fee_zat,
        spends,
        outputs,
    })
    .map_err(|e| anyhow!("build_transaction: {e}"))
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

    #[tokio::test]
    async fn empty_spends_returns_error() {
        let req = CraftRequest {
            grpc_url: "https://127.0.0.1:1".into(),
            ufvk: "uview1bogus".into(),
            network: Some("mainnet".into()),
            seed_fingerprint_hex: "42".repeat(32),
            account_index: 0,
            fee_zat: 10_000,
            spends: vec![],
            outputs: vec![dummy_output()],
            anchor_height: Some(1),
        };
        let err = craft_orchard_transaction(req).await.unwrap_err();
        assert!(
            err.to_string().contains("spends list is empty"),
            "got: {err}"
        );
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
            outputs: vec![],
            anchor_height: Some(1),
        };
        let err = craft_orchard_transaction(req).await.unwrap_err();
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
            outputs: vec![dummy_output()],
            anchor_height: Some(1),
        };
        let err = craft_orchard_transaction(req).await.unwrap_err();
        assert!(err.to_string().contains("UFVK decode failed"), "got: {err}");
    }

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
}
