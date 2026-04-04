use napi_derive::napi;
use zcash_crypto::keys::ZcashNetwork;
use zcash_grpc::sync::{run_sync, SyncParams as GrpcSyncParams};

// ─── NAPI types ───────────────────────────────────────────────────────────────

/// Parameters for deriving Zcash viewing keys from a BIP-39 mnemonic.
#[napi(object)]
pub struct DeriveKeysParams {
    /// BIP-39 mnemonic phrase (12 or 24 words).
    pub mnemonic: String,
    /// ZIP-32 account index (default: 0).
    pub account: u32,
    /// `"mainnet"` or `"testnet"` (default: `"mainnet"`).
    pub network: Option<String>,
    /// Custom BIP-32 xpub derivation path (default: `m/44'/133'/{account}'`).
    pub xpub_path: Option<String>,
    /// Whether to include the Sapling FVK inside the generated UFVK (default: true).
    pub include_sapling_in_ufvk: Option<bool>,
}

/// Viewing keys for a single shielded pool.
#[napi(object)]
pub struct PoolViewingKeys {
    pub fvk: String,
    pub ivk: String,
    pub ovk: String,
}

/// All keys derived from a BIP-39 mnemonic for a Zcash account.
#[napi(object)]
pub struct DerivedKeys {
    /// Bech32m Unified Full Viewing Key (HRP `"uview1"` / `"uviewtest1"`).
    pub ufvk: String,
    /// BIP-32 transparent extended public key (Base58Check).
    pub xpub: String,
    /// BIP-32 path used for xpub derivation.
    pub xpub_path: String,
    /// Sapling pool viewing keys.
    pub sapling: Option<PoolViewingKeys>,
    /// Orchard pool viewing keys.
    pub orchard: Option<PoolViewingKeys>,
}

/// Parameters for scanning a block range for shielded transactions.
#[napi(object)]
pub struct SyncParams {
    /// gRPC endpoint URL (e.g. `"https://testnet.zec.rocks:443"`).
    pub grpc_url: String,
    /// Unified Full Viewing Key (UFVK) for the account to scan.
    pub viewing_key: String,
    /// First block height to scan (inclusive).
    pub start_height: u32,
    /// Last block height to scan (inclusive).
    pub end_height: u32,
    /// `"mainnet"` or `"testnet"` (default: `"testnet"`).
    pub network: Option<String>,
}

/// A single shielded note found during decryption.
#[napi(object)]
pub struct ShieldedNote {
    /// Amount in zatoshis (f64 for JS Number compatibility).
    pub amount: f64,
    /// `"incoming"`, `"outgoing"`, or `"internal"`.
    pub transfer_type: String,
    /// Memo text decoded from the note.
    pub memo: String,
}

/// A matched and fully-decrypted shielded transaction.
#[napi(object)]
pub struct ShieldedTransaction {
    /// Transaction ID in big-endian (display) hex order.
    pub txid: String,
    /// Raw transaction bytes as a hex string.
    pub hex: String,
    /// Block height at which this transaction was confirmed.
    pub block_height: u32,
    /// Block hash in big-endian (display) hex order.
    pub block_hash: String,
    /// Block timestamp (Unix seconds).
    pub block_time: u32,
    /// Decrypted Sapling notes belonging to this account.
    pub sapling_notes: Vec<ShieldedNote>,
    /// Decrypted Orchard notes belonging to this account.
    pub orchard_notes: Vec<ShieldedNote>,
}

/// Result returned after scanning a block range.
#[napi(object)]
pub struct SyncResult {
    pub transactions: Vec<ShieldedTransaction>,
    pub blocks_scanned: u32,
    pub elapsed_ms: f64,
}

// ─── NAPI functions ───────────────────────────────────────────────────────────

/// Derive all Zcash viewing keys from a BIP-39 mnemonic.
///
/// Returns UFVK, xpub, and per-pool (Sapling + Orchard) viewing keys.
///
/// This is a CPU-bound synchronous operation — it does not require a gRPC connection.
#[napi]
pub fn derive_keys(params: DeriveKeysParams) -> napi::Result<DerivedKeys> {
    let network = match params.network.as_deref().unwrap_or("mainnet") {
        "testnet" => ZcashNetwork::Testnet,
        "mainnet" => ZcashNetwork::Mainnet,
        other => {
            return Err(napi::Error::from_reason(format!(
                "unknown network {:?}, expected \"mainnet\" or \"testnet\"",
                other
            )))
        }
    };

    let options = zcash_crypto::keys::DeriveOptions {
        include_sapling_in_ufvk: params.include_sapling_in_ufvk.unwrap_or(true),
    };

    let keys = zcash_crypto::keys::derive_keys_with_options(
        &params.mnemonic,
        params.account,
        network,
        params.xpub_path.as_deref(),
        options,
    )
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(DerivedKeys {
        ufvk: keys.ufvk,
        xpub: keys.xpub,
        xpub_path: keys.xpub_path,
        sapling: keys.sapling.map(|p| PoolViewingKeys {
            fvk: p.fvk,
            ivk: p.ivk,
            ovk: p.ovk,
        }),
        orchard: keys.orchard.map(|p| PoolViewingKeys {
            fvk: p.fvk,
            ivk: p.ivk,
            ovk: p.ovk,
        }),
    })
}

/// Scan a range of Zcash compact blocks for shielded transactions matching the given UFVK.
///
/// Uses gRPC `GetBlockRange` streaming for maximum throughput. Trial decryption runs
/// entirely in Rust (no JS event loop blocking). `GetTransaction` is called only for
/// matched transactions, minimising bandwidth.
#[napi]
pub async fn sync_shielded(params: SyncParams) -> napi::Result<SyncResult> {
    let result = run_sync(GrpcSyncParams {
        grpc_url: params.grpc_url,
        viewing_key: params.viewing_key,
        start_height: params.start_height,
        end_height: params.end_height,
        network: params.network,
    })
    .await
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(SyncResult {
        transactions: result
            .transactions
            .into_iter()
            .map(|tx| ShieldedTransaction {
                txid: tx.txid,
                hex: tx.hex,
                block_height: tx.block_height,
                block_hash: tx.block_hash,
                block_time: tx.block_time,
                sapling_notes: tx
                    .sapling_notes
                    .into_iter()
                    .map(|n| ShieldedNote {
                        amount: n.amount as f64,
                        transfer_type: n.transfer_type,
                        memo: n.memo,
                    })
                    .collect(),
                orchard_notes: tx
                    .orchard_notes
                    .into_iter()
                    .map(|n| ShieldedNote {
                        amount: n.amount as f64,
                        transfer_type: n.transfer_type,
                        memo: n.memo,
                    })
                    .collect(),
            })
            .collect(),
        blocks_scanned: result.blocks_scanned,
        elapsed_ms: result.elapsed_ms as f64,
    })
}

/// Returns the current chain tip height from the gRPC endpoint.
#[napi]
pub async fn get_chain_tip(grpc_url: String) -> napi::Result<u32> {
    zcash_grpc::client::chain_tip(grpc_url)
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}
