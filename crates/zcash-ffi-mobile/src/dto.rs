//! JSON shapes of the mobile boundary.
//!
//! Each type mirrors the corresponding NAPI type of `zcash-ffi-node` field for
//! field, so a JavaScript caller that `JSON.parse`s a result gets the object the
//! Node binding would have returned. Three rules keep the shapes equal:
//!
//! - names are camelCase, as napi renames them;
//! - an optional output field (`?:` in `index.d.ts`) is omitted when it has no
//!   value, never written as `null`;
//! - value encodings are not normalised: scan amounts are numbers, craft-side
//!   and fee amounts are decimal strings, exactly as on the Node binding.
//!
//! `crates/zcash-ffi-mobile/tests/parity.rs` compares these shapes with the
//! committed `index.d.ts`.

use serde::{Deserialize, Serialize};
use zcash_sync::sync as engine;

/// Parameters of one chunk scan. Mirrors the NAPI `SyncParams`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncParams {
    pub grpc_url: String,
    pub viewing_key: String,
    pub start_height: u32,
    pub end_height: u32,
    pub network: Option<String>,
    pub orchard_only: Option<bool>,
    pub max_retries: Option<u32>,
    pub verbose: Option<bool>,
    pub known_nullifiers: Option<Vec<String>>,
}

impl From<SyncParams> for engine::SyncParams {
    /// Applies the defaults the NAPI binding applies. The callbacks stay `None`:
    /// results come back through the scan handle.
    fn from(p: SyncParams) -> Self {
        engine::SyncParams {
            grpc_url: p.grpc_url,
            viewing_key: p.viewing_key,
            start_height: p.start_height,
            end_height: p.end_height,
            network: p.network,
            verbose: p.verbose.unwrap_or(false),
            orchard_only: p.orchard_only.unwrap_or(false),
            max_retries: p.max_retries,
            on_block_done: None,
            on_transaction: None,
            known_nullifiers: p.known_nullifiers.unwrap_or_default(),
        }
    }
}

/// A transparent output being spent, and its value. Mirrors `TransparentPrevout`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparentPrevout {
    pub txid: String,
    pub index: u32,
    /// Zatoshis, as a decimal string.
    pub value: String,
}

/// A transaction to resolve. Mirrors `TransactionDetailsRequest`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetailsRequest {
    pub txid: String,
    pub height: u32,
    pub prevouts: Vec<TransparentPrevout>,
}

impl TransactionDetailsRequest {
    /// Maps to the engine request. The error text for a bad prevout value is the
    /// NAPI binding's, and it names the offending value as that binding does.
    pub fn into_engine(self) -> Result<zcash_sync::client::DetailsRequest, String> {
        let prevouts = self
            .prevouts
            .into_iter()
            .map(|p| {
                let value = p
                    .value
                    .parse::<u64>()
                    .map_err(|e| format!("prevout value {}: {e}", p.value))?;
                Ok(((p.txid, p.index), value))
            })
            .collect::<Result<_, String>>()?;
        Ok(zcash_sync::client::DetailsRequest {
            txid: self.txid,
            height: self.height,
            prevouts,
        })
    }
}

/// Mirrors `TransactionDetailsResult`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetailsResult {
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<String>,
    pub payees: Vec<String>,
}

impl From<zcash_sync::client::DetailsResult> for TransactionDetailsResult {
    fn from(r: zcash_sync::client::DetailsResult) -> Self {
        TransactionDetailsResult {
            txid: r.txid,
            fee: r.fee.map(|f| f.to_string()),
            payees: r.payees,
        }
    }
}

/// Mirrors `ShieldedNote`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedNote {
    pub amount: f64,
    pub transfer_type: String,
    pub memo: String,
    pub pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rho: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rseed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub is_spent: bool,
}

impl ShieldedNote {
    /// Sapling notes carry no spending fields: the binding is Orchard-only for
    /// spending, and the Node binding drops them the same way.
    fn from_sapling(n: engine::ShieldedNote) -> Self {
        ShieldedNote {
            amount: n.amount as f64,
            transfer_type: n.transfer_type,
            memo: n.memo,
            pool: n.pool,
            nullifier: None,
            rho: None,
            rseed: None,
            cmx: None,
            position: None,
            recipient: None,
            is_spent: false,
        }
    }

    /// Orchard and Ironwood notes keep every spending field.
    fn from_orchard_family(n: engine::ShieldedNote) -> Self {
        ShieldedNote {
            amount: n.amount as f64,
            transfer_type: n.transfer_type,
            memo: n.memo,
            pool: n.pool,
            nullifier: n.nullifier,
            rho: n.rho,
            rseed: n.rseed,
            cmx: n.cmx,
            position: n.position.map(|p| p.to_string()),
            recipient: n.recipient,
            is_spent: n.is_spent,
        }
    }
}

/// Mirrors `ShieldedTransaction`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedTransaction {
    pub txid: String,
    pub hex: String,
    pub block_height: u32,
    pub block_hash: String,
    pub block_time: u32,
    pub fee: f64,
    pub transparent_out: f64,
    pub has_transparent_inputs: bool,
    pub sapling_notes: Vec<ShieldedNote>,
    pub orchard_notes: Vec<ShieldedNote>,
    pub ironwood_notes: Vec<ShieldedNote>,
}

impl From<engine::ShieldedTransaction> for ShieldedTransaction {
    fn from(tx: engine::ShieldedTransaction) -> Self {
        ShieldedTransaction {
            txid: tx.txid,
            hex: tx.hex,
            block_height: tx.block_height,
            block_hash: tx.block_hash,
            block_time: tx.block_time,
            fee: tx.fee_zatoshis as f64,
            transparent_out: tx.transparent_out_zatoshis as f64,
            has_transparent_inputs: tx.has_transparent_inputs,
            sapling_notes: tx
                .sapling_notes
                .into_iter()
                .map(ShieldedNote::from_sapling)
                .collect(),
            orchard_notes: tx
                .orchard_notes
                .into_iter()
                .map(ShieldedNote::from_orchard_family)
                .collect(),
            ironwood_notes: tx
                .ironwood_notes
                .into_iter()
                .map(ShieldedNote::from_orchard_family)
                .collect(),
        }
    }
}

/// Mirrors `SyncStats`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStats {
    pub blocks_scanned: u32,
    pub elapsed_ms: f64,
    pub spent_known_nullifiers: Vec<String>,
}

/// What `zcash_sync_finish` returns: the transactions the Node binding streams,
/// and the statistics it reports once the stream ends.
#[derive(Debug, Serialize)]
pub struct SyncChunkResult {
    pub transactions: Vec<ShieldedTransaction>,
    pub stats: SyncStats,
}

impl From<engine::SyncResult> for SyncChunkResult {
    fn from(r: engine::SyncResult) -> Self {
        SyncChunkResult {
            stats: SyncStats {
                blocks_scanned: r.blocks_scanned,
                elapsed_ms: r.elapsed_ms as f64,
                spent_known_nullifiers: r.spent_known_nullifiers,
            },
            transactions: r.transactions.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_note(position: Option<u64>) -> engine::ShieldedNote {
        engine::ShieldedNote {
            amount: 12_345,
            transfer_type: "incoming".into(),
            memo: "hi".into(),
            pool: "orchard".into(),
            nullifier: Some("aa".into()),
            rho: Some("bb".into()),
            rseed: Some("cc".into()),
            cmx: Some("dd".into()),
            position,
            recipient: Some("ee".into()),
            is_spent: true,
        }
    }

    fn engine_tx() -> engine::ShieldedTransaction {
        engine::ShieldedTransaction {
            txid: "t".into(),
            hex: "h".into(),
            block_height: 7,
            block_hash: "bh".into(),
            block_time: 9,
            fee_zatoshis: 10_000,
            transparent_out_zatoshis: 5,
            has_transparent_inputs: true,
            sapling_notes: vec![engine_note(Some(1))],
            orchard_notes: vec![engine_note(Some(u64::MAX))],
            ironwood_notes: vec![engine_note(None)],
        }
    }

    #[test]
    fn sync_params_defaults_match_the_node_binding() {
        let p: SyncParams = serde_json::from_str(
            r#"{"grpcUrl":"u","viewingKey":"k","startHeight":1,"endHeight":2}"#,
        )
        .unwrap();
        let e: engine::SyncParams = p.into();
        assert!(!e.orchard_only, "orchardOnly defaults to false");
        assert!(!e.verbose);
        assert_eq!(e.max_retries, None, "maxRetries is passed through");
        assert!(e.known_nullifiers.is_empty());
        assert!(e.on_block_done.is_none() && e.on_transaction.is_none());
        assert_eq!(e.network, None);
    }

    #[test]
    fn sync_params_forward_every_optional_field() {
        let p: SyncParams = serde_json::from_str(
            r#"{"grpcUrl":"u","viewingKey":"k","startHeight":1,"endHeight":2,
                "network":"mainnet","orchardOnly":true,"maxRetries":5,
                "verbose":true,"knownNullifiers":["ab","cd"]}"#,
        )
        .unwrap();
        let e: engine::SyncParams = p.into();
        assert_eq!(e.network.as_deref(), Some("mainnet"));
        assert!(e.orchard_only && e.verbose);
        assert_eq!(e.max_retries, Some(5));
        assert_eq!(e.known_nullifiers, vec!["ab", "cd"]);
        assert_eq!((e.start_height, e.end_height), (1, 2));
    }

    #[test]
    fn sync_params_missing_required_field_is_rejected() {
        assert!(serde_json::from_str::<SyncParams>(
            r#"{"grpcUrl":"u","viewingKey":"k","startHeight":1}"#
        )
        .is_err());
    }

    #[test]
    fn details_request_maps_prevouts_and_rejects_a_bad_value() {
        let ok: TransactionDetailsRequest = serde_json::from_str(
            r#"{"txid":"ab","height":3,"prevouts":[{"txid":"cd","index":1,"value":"42"}]}"#,
        )
        .unwrap();
        let req = ok.into_engine().unwrap();
        assert_eq!(req.height, 3);
        assert_eq!(req.prevouts.get(&("cd".to_string(), 1)), Some(&42));

        let bad: TransactionDetailsRequest = serde_json::from_str(
            r#"{"txid":"ab","height":3,"prevouts":[{"txid":"cd","index":1,"value":"4x2"}]}"#,
        )
        .unwrap();
        let err = bad.into_engine().err().expect("must fail");
        assert!(err.starts_with("prevout value 4x2: "), "got: {err}");
    }

    #[test]
    fn transaction_converts_like_the_node_binding() {
        let tx: ShieldedTransaction = engine_tx().into();
        assert_eq!(tx.fee, 10_000.0);
        assert_eq!(tx.transparent_out, 5.0);

        let sapling = &tx.sapling_notes[0];
        assert_eq!(sapling.nullifier, None);
        assert_eq!(sapling.position, None);
        assert!(!sapling.is_spent, "sapling notes never report spent");

        let orchard = &tx.orchard_notes[0];
        assert_eq!(orchard.position.as_deref(), Some("18446744073709551615"));
        assert!(orchard.is_spent);
        assert_eq!(orchard.nullifier.as_deref(), Some("aa"));

        assert_eq!(tx.ironwood_notes[0].position, None);
        assert_eq!(tx.ironwood_notes[0].rseed.as_deref(), Some("cc"));
    }

    #[test]
    fn serialised_note_omits_absent_fields_and_uses_camel_case() {
        let note = ShieldedNote::from_sapling(engine_note(None));
        let v = serde_json::to_value(&note).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        for k in ["amount", "transferType", "memo", "pool", "isSpent"] {
            assert!(keys.contains(&k), "missing {k}");
        }
        assert_eq!(keys.len(), 5, "optional fields must be omitted: {keys:?}");
    }

    #[test]
    fn details_result_omits_an_unknown_fee_and_renders_a_known_one_as_a_string() {
        let unknown = TransactionDetailsResult::from(zcash_sync::client::DetailsResult {
            txid: "t".into(),
            fee: None,
            payees: vec![],
        });
        let v = serde_json::to_value(&unknown).unwrap();
        assert!(v.get("fee").is_none());
        assert_eq!(v["payees"], serde_json::json!([]));

        let known = TransactionDetailsResult::from(zcash_sync::client::DetailsResult {
            txid: "t".into(),
            fee: Some(10_000),
            payees: vec!["u1x".into()],
        });
        let v = serde_json::to_value(&known).unwrap();
        assert_eq!(v["fee"], serde_json::json!("10000"));
    }

    #[test]
    fn chunk_result_carries_transactions_and_stats() {
        let r = engine::SyncResult {
            transactions: vec![engine_tx()],
            blocks_scanned: 100,
            elapsed_ms: 1_500,
            stream_wait_ms: 0,
            trial_decrypt_ms: 0,
            get_transaction_ms: 0,
            full_decrypt_ms: 0,
            spent_known_nullifiers: vec!["ab".into()],
        };
        let v = serde_json::to_value(SyncChunkResult::from(r)).unwrap();
        assert_eq!(v["stats"]["blocksScanned"], 100);
        assert_eq!(v["stats"]["elapsedMs"], 1500.0);
        assert_eq!(
            v["stats"]["spentKnownNullifiers"],
            serde_json::json!(["ab"])
        );
        assert_eq!(v["transactions"].as_array().unwrap().len(), 1);
    }
}
