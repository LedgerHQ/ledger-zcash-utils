// Include the UniFFI scaffolding generated from src/zcash.udl at build time.
uniffi::include_scaffolding!("zcash");

use std::sync::Arc;
use zcash_crypto::{
    decrypt::{
        self, CompactOrchardAction, CompactSaplingOutput, CompactTransaction, DecryptedOutput,
    },
    error::Error as CryptoError,
    keys::{DeriveOptions, ZcashNetwork},
    network::parse_network,
};
use zcash_grpc::{client, sync};

// ─── error mapping ────────────────────────────────────────────────────────────

/// Error type exposed to UniFFI consumers (Kotlin / Swift).
#[derive(Debug, thiserror::Error)]
pub enum ZcashError {
    #[error("{message}")]
    Mnemonic { message: String },
    #[error("{message}")]
    Derivation { message: String },
    #[error("{message}")]
    Bip32 { message: String },
    #[error("{message}")]
    Decrypt { message: String },
    #[error("{message}")]
    Sync { message: String },
}

impl From<CryptoError> for ZcashError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Mnemonic(inner) => ZcashError::Mnemonic { message: inner.to_string() },
            CryptoError::Derivation(msg) => ZcashError::Derivation { message: msg },
            CryptoError::Bip32(inner) => ZcashError::Bip32 { message: inner.to_string() },
            CryptoError::Decrypt(msg) => ZcashError::Decrypt { message: msg },
        }
    }
}

// ─── UDL sync types ───────────────────────────────────────────────────────────

pub struct SyncParams {
    pub grpc_url: String,
    pub viewing_key: String,
    pub start_height: u32,
    pub end_height: u32,
    pub network: Option<String>,
}

pub struct ShieldedNote {
    pub amount: u64,
    pub transfer_type: String,
    pub memo: String,
}

pub struct ShieldedTransaction {
    pub txid: String,
    pub hex: String,
    pub block_height: u32,
    pub block_hash: String,
    pub block_time: u32,
    pub sapling_notes: Vec<ShieldedNote>,
    pub orchard_notes: Vec<ShieldedNote>,
}

pub struct SyncResult {
    pub transactions: Vec<ShieldedTransaction>,
    pub blocks_scanned: u32,
    pub elapsed_ms: u64,
}

// ─── UDL dictionary types (auto-generated scaffolding references these) ───────

pub struct PoolViewingKeys {
    pub fvk: String,
    pub ivk: String,
    pub ovk: String,
}

pub struct DerivedKeys {
    pub ufvk: String,
    pub xpub: String,
    pub xpub_path: String,
    pub sapling: Option<PoolViewingKeys>,
    pub orchard: Option<PoolViewingKeys>,
}

pub struct CompactSaplingOutputData {
    pub cmu: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct CompactOrchardActionData {
    pub cmx: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct CompactTransactionData {
    pub txid: String,
    pub sapling_outputs: Vec<CompactSaplingOutputData>,
    pub orchard_actions: Vec<CompactOrchardActionData>,
}

pub struct DecryptedOutputData {
    pub amount: u64,
    pub memo: String,
    pub transfer_type: String,
}

pub struct DecryptedTxResult {
    pub sapling_outputs: Vec<DecryptedOutputData>,
    pub orchard_outputs: Vec<DecryptedOutputData>,
}

/// Opaque, thread-safe handle to pre-computed IVKs.
pub struct PreparedIvksHandle {
    inner: Arc<decrypt::PreparedIvks>,
}

// ─── key derivation ───────────────────────────────────────────────────────────

/// Derive all Zcash viewing keys from a BIP-39 mnemonic.
pub fn derive_zcash_keys(
    mnemonic: String,
    account: u32,
    network: String,
) -> Result<DerivedKeys, ZcashError> {
    let net = parse_zcash_network(&network)?;
    let keys =
        zcash_crypto::keys::derive_keys(&mnemonic, account, net, None).map_err(ZcashError::from)?;
    Ok(to_derived_keys(keys))
}

/// Derive keys with UFVK composition options.
pub fn derive_zcash_keys_with_options(
    mnemonic: String,
    account: u32,
    network: String,
    include_sapling_in_ufvk: bool,
) -> Result<DerivedKeys, ZcashError> {
    let net = parse_zcash_network(&network)?;
    let options = DeriveOptions { include_sapling_in_ufvk };
    let keys = zcash_crypto::keys::derive_keys_with_options(&mnemonic, account, net, None, options)
        .map_err(ZcashError::from)?;
    Ok(to_derived_keys(keys))
}

// ─── decryption ───────────────────────────────────────────────────────────────

/// Prepare pre-computed IVKs from a UFVK string.
pub fn prepare_ivks_from_ufvk(ufvk: String) -> Result<Arc<PreparedIvksHandle>, ZcashError> {
    let ivks = decrypt::prepare_ivks(&ufvk).map_err(ZcashError::from)?;
    Ok(Arc::new(PreparedIvksHandle { inner: Arc::new(ivks) }))
}

/// Trial-decrypt a batch of compact transactions.
pub fn trial_decrypt_compact_txs(
    handle: Arc<PreparedIvksHandle>,
    transactions: Vec<CompactTransactionData>,
) -> Vec<String> {
    let compact_txs: Vec<CompactTransaction> = transactions
        .into_iter()
        .map(|t| CompactTransaction {
            txid: t.txid,
            sapling_outputs: t
                .sapling_outputs
                .into_iter()
                .map(|o| CompactSaplingOutput {
                    cmu: o.cmu,
                    ephemeral_key: o.ephemeral_key,
                    ciphertext: o.ciphertext,
                })
                .collect(),
            orchard_actions: t
                .orchard_actions
                .into_iter()
                .map(|a| CompactOrchardAction {
                    cmx: a.cmx,
                    ephemeral_key: a.ephemeral_key,
                    ciphertext: a.ciphertext,
                })
                .collect(),
        })
        .collect();
    decrypt::trial_decrypt_block(&compact_txs, &handle.inner)
}

/// Full-decrypt a raw transaction to extract notes with amounts and memos.
pub fn full_decrypt_transaction(
    tx_hex: String,
    ufvk: String,
    height: u32,
    network: String,
) -> Result<DecryptedTxResult, ZcashError> {
    let net = parse_network(Some(&network)).map_err(ZcashError::from)?;
    let decrypted = decrypt::full_decrypt_tx(&tx_hex, &ufvk, height, net)
        .map_err(ZcashError::from)?;
    Ok(DecryptedTxResult {
        sapling_outputs: decrypted.sapling_outputs.into_iter().map(to_output_data).collect(),
        orchard_outputs: decrypted.orchard_outputs.into_iter().map(to_output_data).collect(),
    })
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn parse_zcash_network(network: &str) -> Result<ZcashNetwork, ZcashError> {
    match network {
        "mainnet" => Ok(ZcashNetwork::Mainnet),
        "testnet" => Ok(ZcashNetwork::Testnet),
        other => Err(ZcashError::Derivation {
            message: format!("unknown network {:?}, expected \"mainnet\" or \"testnet\"", other),
        }),
    }
}

fn to_derived_keys(keys: zcash_crypto::keys::DerivedKeys) -> DerivedKeys {
    DerivedKeys {
        ufvk: keys.ufvk,
        xpub: keys.xpub,
        xpub_path: keys.xpub_path,
        sapling: keys.sapling.map(|p| PoolViewingKeys { fvk: p.fvk, ivk: p.ivk, ovk: p.ovk }),
        orchard: keys.orchard.map(|p| PoolViewingKeys { fvk: p.fvk, ivk: p.ivk, ovk: p.ovk }),
    }
}

fn to_output_data(o: DecryptedOutput) -> DecryptedOutputData {
    DecryptedOutputData { amount: o.amount, memo: o.memo, transfer_type: o.transfer_type }
}

// ─── gRPC sync ────────────────────────────────────────────────────────────────

/// Scan a range of compact blocks for shielded transactions matching the UFVK.
///
/// Blocks the calling thread — invoke from a background thread (Kotlin
/// `Dispatchers.IO`, Swift `Task` with background priority, RN native module
/// thread).
pub fn sync_shielded(params: SyncParams) -> Result<SyncResult, ZcashError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ZcashError::Sync { message: e.to_string() })?;
    let grpc_params = sync::SyncParams {
        grpc_url: params.grpc_url,
        viewing_key: params.viewing_key,
        start_height: params.start_height,
        end_height: params.end_height,
        network: params.network,
    };
    let result = rt
        .block_on(sync::run_sync(grpc_params))
        .map_err(|e| ZcashError::Sync { message: e.to_string() })?;
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
                        amount: n.amount,
                        transfer_type: n.transfer_type,
                        memo: n.memo,
                    })
                    .collect(),
                orchard_notes: tx
                    .orchard_notes
                    .into_iter()
                    .map(|n| ShieldedNote {
                        amount: n.amount,
                        transfer_type: n.transfer_type,
                        memo: n.memo,
                    })
                    .collect(),
            })
            .collect(),
        blocks_scanned: result.blocks_scanned,
        elapsed_ms: result.elapsed_ms,
    })
}

/// Return the current chain tip height from a gRPC endpoint.
///
/// Blocks the calling thread — invoke from a background thread.
pub fn get_chain_tip(grpc_url: String) -> Result<u32, ZcashError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ZcashError::Sync { message: e.to_string() })?;
    rt.block_on(client::chain_tip(grpc_url))
        .map_err(|e| ZcashError::Sync { message: e.to_string() })
}
