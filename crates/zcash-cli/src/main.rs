use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::BufRead;
use std::sync::Arc;
use zcash_crypto::keys::{derive_keys_with_options, DeriveOptions, PoolViewingKeys, ZcashNetwork};

// ─── shared CLI enums ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Human,
    Json,
}

// ─── top-level CLI ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "ledger-zcash-cli",
    about = "Zcash cryptographic utilities: key derivation and block scanning",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Derive all Zcash viewing keys from a BIP-39 mnemonic.
    ///
    /// Outputs: UFVK, xpub, and per-pool (Sapling + Orchard) FVK/IVK/OVK.
    /// No spending key material is exposed.
    Derive(DeriveArgs),

    /// Query the current chain tip height from a lightwalletd gRPC endpoint.
    Tip(TipArgs),

    /// Scan a range of compact blocks for shielded transactions.
    ///
    /// Requires a running lightwalletd / Zaino endpoint.
    Sync(SyncArgs),

    /// Find the block height closest to a given date or Unix timestamp.
    ///
    /// Performs a binary search over block timestamps via gRPC.
    HeightAt(HeightAtArgs),
}

// ─── derive subcommand ────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct DeriveArgs {
    /// BIP-39 mnemonic phrase (reads from stdin if not provided)
    #[arg(long)]
    mnemonic: Option<String>,

    /// ZIP-32 account index — controls UFVK and default xpub path
    #[arg(long, default_value_t = 0)]
    account: u32,

    /// Explicit BIP-32 path for the transparent xpub (e.g. "m/44'/133'/0'").
    /// Defaults to m/44'/133'/{account}' when not set.
    #[arg(long)]
    xpub_path: Option<String>,

    /// Target network
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,

    /// Exclude the Sapling FVK from the generated UFVK.
    /// Sapling pool keys are still derived and printed separately.
    #[arg(long)]
    no_sapling: bool,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
}

// ─── tip subcommand ───────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct TipArgs {
    /// gRPC endpoint URL (e.g. `https://zaino-zec-testnet.nodes.stg.ledger-test.com/`)
    #[arg(long)]
    grpc_url: String,
}

// ─── height-at subcommand ────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct HeightAtArgs {
    /// gRPC endpoint URL (e.g. `https://zaino-zec-testnet.nodes.stg.ledger-test.com/`)
    #[arg(long)]
    grpc_url: String,

    /// Target date (YYYY-MM-DD) or Unix timestamp (integer).
    /// Returns the latest block at or before this time.
    #[arg(long)]
    date: String,
}

// ─── sync subcommand ──────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct SyncArgs {
    /// gRPC endpoint URL
    #[arg(long)]
    grpc_url: String,

    /// Unified Full Viewing Key for the account to scan
    #[arg(long)]
    viewing_key: String,

    /// First block height to scan (inclusive).
    /// Defaults to Sapling activation height (testnet: 280000, mainnet: 419200).
    #[arg(long)]
    start_height: Option<u32>,

    /// Last block height to scan (inclusive).
    /// Defaults to the current chain tip (queried via gRPC).
    #[arg(long)]
    end_height: Option<u32>,

    /// Target network
    #[arg(long, value_enum, default_value_t = Network::Testnet)]
    network: Network,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,

    /// Number of blocks per gRPC call (default: 5 000).
    /// Smaller values reduce the risk of server-side timeouts at the cost of
    /// more TLS connection overhead. Heavy mainnet blocks (height > 1,700,000)
    /// can saturate CPU trial decryption; 5k keeps each chunk under ~40s.
    #[arg(long)]
    chunk_size: Option<u32>,

    /// Maximum number of retry attempts per chunk on timeout errors (default: 3).
    /// On each retry the failing range is split in half, so up to 2^max_retries
    /// sub-requests may be issued for a single original chunk.
    #[arg(long)]
    max_retries: Option<u32>,

    /// Skip Sapling trial decryption entirely — only Orchard actions are processed.
    ///
    /// When set, the default --start-height is adjusted to the Orchard activation
    /// block (mainnet: 1 687 104, testnet: 1 842 420) since earlier blocks contain
    /// no Orchard outputs and can be skipped completely.
    ///
    /// Use this flag when the wallet only supports Orchard (e.g. Ledger devices).
    #[arg(long)]
    orchard_only: bool,

    /// Print progress and match info to stderr
    #[arg(long)]
    verbose: bool,
}

// ─── entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Derive(args) => cmd_derive(args),
        Commands::Tip(args) => cmd_tip(args).await,
        Commands::HeightAt(args) => cmd_height_at(args).await,
        Commands::Sync(args) => cmd_sync(args).await,
    }
}

// ─── command implementations ──────────────────────────────────────────────────

fn cmd_derive(args: DeriveArgs) {
    let mnemonic = match args.mnemonic {
        Some(m) => m,
        None => {
            eprintln!("Reading mnemonic from stdin...");
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .expect("failed to read mnemonic from stdin");
            line.trim().to_string()
        }
    };

    let network = match args.network {
        Network::Mainnet => ZcashNetwork::Mainnet,
        Network::Testnet => ZcashNetwork::Testnet,
    };

    match derive_keys_with_options(
        &mnemonic,
        args.account,
        network,
        args.xpub_path.as_deref(),
        DeriveOptions { include_sapling_in_ufvk: !args.no_sapling },
    ) {
        Ok(keys) => match args.format {
            Format::Human => {
                println!("ufvk      : {}", keys.ufvk);
                println!("xpub      : {}", keys.xpub);
                println!("xpub path : (derived from requested account)");
                if let Some(s) = &keys.sapling {
                    print_pool_human("sapling", s);
                }
                if let Some(o) = &keys.orchard {
                    print_pool_human("orchard", o);
                }
            }
            Format::Json => {
                let pool_json = |p: &PoolViewingKeys| {
                    serde_json::json!({
                        "fvk": p.fvk,
                        "ivk": p.ivk,
                        "ovk": p.ovk,
                    })
                };
                let json = serde_json::json!({
                    "ufvk": keys.ufvk,
                    "xpub": keys.xpub,
                    "xpub_path": format!("(derived from account {})", args.account),
                    "sapling": keys.sapling.as_ref().map(pool_json),
                    "orchard": keys.orchard.as_ref().map(pool_json),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
        },
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_tip(args: TipArgs) {
    match zcash_sync::client::chain_tip(args.grpc_url).await {
        Ok(height) => println!("{height}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_height_at(args: HeightAtArgs) {
    let timestamp = match parse_date_or_timestamp(&args.date) {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    match zcash_sync::client::find_block_height(args.grpc_url, timestamp).await {
        Ok(height) => println!("{height}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse a date string (`YYYY-MM-DD`, midnight UTC) or a raw Unix timestamp.
fn parse_date_or_timestamp(input: &str) -> Result<u32, String> {
    // Try as integer first.
    if let Ok(ts) = input.parse::<u32>() {
        return Ok(ts);
    }

    // Try as YYYY-MM-DD → midnight UTC.
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() == 3 {
        let year: i32 = parts[0].parse().map_err(|_| format!("invalid year: {}", parts[0]))?;
        let month_num: u8 = parts[1].parse().map_err(|_| format!("invalid month: {}", parts[1]))?;
        let day: u8 = parts[2].parse().map_err(|_| format!("invalid day: {}", parts[2]))?;
        let month = time::Month::try_from(month_num)
            .map_err(|_| format!("month out of range: {month_num}"))?;
        let date = time::Date::from_calendar_date(year, month, day)
            .map_err(|_| format!("invalid date: {input}"))?;
        let ts = date.with_hms(0, 0, 0).unwrap().assume_utc().unix_timestamp();
        if ts >= 0 {
            return Ok(ts as u32);
        }
        return Err(format!("date '{input}' is before Unix epoch"));
    }

    Err(format!("cannot parse '{input}' as YYYY-MM-DD or Unix timestamp"))
}

async fn cmd_sync(args: SyncArgs) {

    let network_str = match args.network {
        Network::Mainnet => "mainnet".to_string(),
        Network::Testnet => "testnet".to_string(),
    };

    let default_start_height = if args.orchard_only {
        // Skip pre-Orchard blocks entirely — no Orchard outputs before NU5.
        match args.network {
            Network::Mainnet => 1_687_104u32,
            Network::Testnet => 1_842_420u32,
        }
    } else {
        match args.network {
            Network::Mainnet => 419_200u32,
            Network::Testnet => 280_000u32,
        }
    };

    let start_height = args.start_height.unwrap_or(default_start_height);

    let end_height = match args.end_height {
        Some(h) => h,
        None => {
            if args.verbose {
                eprintln!("[sync] --end-height not set, querying chain tip from {}...", args.grpc_url);
            }
            match zcash_sync::client::chain_tip(args.grpc_url.clone()).await {
                Ok(h) => {
                    if args.verbose {
                        eprintln!("[sync] chain tip = {h}");
                    }
                    h
                }
                Err(e) => {
                    eprintln!("Error fetching chain tip: {e}");
                    std::process::exit(1);
                }
            }
        }
    };

    let chunk_size = args.chunk_size.unwrap_or(10_000);
    if chunk_size == 0 {
        eprintln!("Error: --chunk-size must be greater than 0");
        std::process::exit(1);
    }
    let max_retries = args.max_retries.unwrap_or(3);
    let total_blocks = end_height.saturating_sub(start_height) + 1;
    let n_chunks = (total_blocks + chunk_size - 1) / chunk_size;
    let verbose = args.verbose;

    // ── Params summary (always printed) ──────────────────────────────────────
    let ufvk_prefix = if args.viewing_key.len() > 26 {
        format!("{}…", &args.viewing_key[..26])
    } else {
        args.viewing_key.clone()
    };
    let w = 16; // label column width
    let sep = "─".repeat(72);
    eprintln!("{sep}");
    eprintln!("{:<w$}{}", "Network",     network_str);
    eprintln!("{:<w$}{}", "UFVK",        ufvk_prefix);
    eprintln!("{:<w$}{}", "gRPC",        args.grpc_url);
    eprintln!("{:<w$}{} → {}  ({} blocks)",
        "Block range",
        fmt_num(start_height), fmt_num(end_height), fmt_num(total_blocks));
    eprintln!("{:<w$}{} chunks × {} blocks",
        "Chunks", fmt_num(n_chunks), fmt_num(chunk_size));
    eprintln!("{:<w$}{}",
        "Mode",
        if args.orchard_only { "orchard-only (Sapling skipped)" } else { "full (Sapling + Orchard)" });
    eprintln!("{sep}");
    eprintln!();

    if verbose {
        eprintln!(
            "[sync] network={} range={}..{} ({} blocks, {} chunks of {})",
            network_str, start_height, end_height, total_blocks, n_chunks, chunk_size
        );
    }

    // Progress bar (shown only when not in verbose mode).
    // Wrapped in Arc so it can be shared with the on_block_done callback.
    let pb = if !verbose {
        let bar = ProgressBar::new(total_blocks as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{bar:45.green/white}] {pos}/{len} blocks \
                 ({percent}%)  {per_sec}  ETA {eta}  {msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ ")
            .with_key("per_sec", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                let bps = state.per_sec();
                if bps >= 1_000_000.0 {
                    write!(w, "{:.1}M bl/s", bps / 1_000_000.0).unwrap();
                } else if bps >= 1_000.0 {
                    write!(w, "{:.0}k bl/s", bps / 1_000.0).unwrap();
                } else {
                    write!(w, "{:.0} bl/s", bps).unwrap();
                }
            }),
        );
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(Arc::new(bar))
    } else {
        None
    };

    // Callback invoked per block by the sync engine — drives real-time progress.
    let on_block_done: Option<Arc<dyn Fn() + Send + Sync>> = pb.as_ref().map(|b| {
        let b = Arc::clone(b);
        Arc::new(move || { b.inc(1); }) as Arc<dyn Fn() + Send + Sync>
    });

    // Build the full list of chunks upfront so we can fan them out.
    let chunks = build_chunks(start_height, end_height, chunk_size);

    let global_start = std::time::Instant::now();

    let chunk_results: Vec<_> = {
        let grpc_url = args.grpc_url.clone();
        let viewing_key = args.viewing_key.clone();
        let network_str = network_str.clone();
        let orchard_only = args.orchard_only;

        futures::stream::iter(chunks.into_iter().enumerate())
            .map(|(idx, (s, e))| {
                let grpc_url = grpc_url.clone();
                let viewing_key = viewing_key.clone();
                let network_str = network_str.clone();
                let on_block_done = on_block_done.as_ref().map(Arc::clone);
                async move {
                    let r = zcash_sync::sync::run_sync(zcash_sync::sync::SyncParams {
                        grpc_url,
                        viewing_key,
                        start_height: s,
                        end_height: e,
                        network: Some(network_str),
                        verbose,
                        max_retries: Some(max_retries),
                        orchard_only,
                        on_block_done,
                        on_transaction: None,
                    })
                    .await;
                    (idx, s, e, r)
                }
            })
            .buffer_unordered(1)
            .collect()
            .await
    };

    let mut all_transactions: Vec<zcash_sync::sync::ShieldedTransaction> = Vec::new();
    let mut total_blocks_scanned = 0u32;
    let mut total_tx_found = 0usize;

    // Sort results back into chunk order before merging (buffer_unordered is unordered).
    let mut sorted_results = chunk_results;
    sorted_results.sort_unstable_by_key(|(idx, _, _, _)| *idx);

    for (idx, s, e, result) in sorted_results {
        let chunk_result = match result {
            Ok(r) => r,
            Err(err) => {
                if let Some(ref bar) = pb { bar.abandon(); }
                eprintln!("Error on chunk {}..{}: {err}", s, e);
                std::process::exit(1);
            }
        };

        if verbose {
            let blps = chunk_result.blocks_scanned as f64
                / (chunk_result.elapsed_ms as f64 / 1000.0).max(0.001);
            let tx_tag = if chunk_result.transactions.is_empty() { String::new() }
                         else { format!("  *** {} tx found ***", chunk_result.transactions.len()) };
            eprintln!(
                "[sync] chunk {}/{} done: {} blocks in {}ms ({:.0} bl/s){}",
                idx + 1, n_chunks,
                chunk_result.blocks_scanned,
                chunk_result.elapsed_ms,
                blps, tx_tag,
            );
            eprintln!(
                "[sync]   trial_decrypt={}ms  get_transaction={}ms  full_decrypt={}ms",
                chunk_result.trial_decrypt_ms,
                chunk_result.get_transaction_ms,
                chunk_result.full_decrypt_ms,
            );
        }

        total_blocks_scanned += chunk_result.blocks_scanned;
        total_tx_found += chunk_result.transactions.len();
        all_transactions.extend(chunk_result.transactions);

        if let Some(ref bar) = pb {
            if total_tx_found > 0 {
                bar.set_message(format!("{total_tx_found} tx found"));
            }
        }
    }

    if let Some(bar) = pb.as_deref() {
        bar.finish_and_clear();
    }

    if verbose {
        eprintln!(
            "[sync] done: {} blocks in {}ms, {} tx found",
            total_blocks_scanned,
            global_start.elapsed().as_millis(),
            all_transactions.len()
        );
    }

    let result = zcash_sync::sync::SyncResult {
        transactions: all_transactions,
        blocks_scanned: total_blocks_scanned,
        elapsed_ms: global_start.elapsed().as_millis() as u64,
        stream_wait_ms: 0,
        trial_decrypt_ms: 0,
        get_transaction_ms: 0,
        full_decrypt_ms: 0,
    };

    match args.format {
            Format::Human => {
                let sep  = "─".repeat(72);
                let sep2 = "═".repeat(72);

                // ── stats header ─────────────────────────────────────────────
                let elapsed_str = if result.elapsed_ms >= 1_000 {
                    format!("{:.1} s", result.elapsed_ms as f64 / 1_000.0)
                } else {
                    format!("{} ms", result.elapsed_ms)
                };
                let tx_count = result.transactions.len();

                println!("{sep2}");
                println!("Scan results");
                println!("{sep}");
                println!("  Blocks scanned   {}", fmt_num(result.blocks_scanned));
                println!("  Transactions     {tx_count}");
                println!("  Elapsed          {elapsed_str}");
                println!("{sep2}");

                if result.transactions.is_empty() {
                    println!();
                    println!("  No transactions found.");
                    println!();
                } else {
                    // accumulate balance summary while printing
                    let mut sapling_recv = 0u64;
                    let mut sapling_sent = 0u64;
                    let mut orchard_recv = 0u64;
                    let mut orchard_sent = 0u64;

                    for (i, tx) in result.transactions.iter().enumerate() {
                        let s_recv: u64 = tx.sapling_notes.iter()
                            .filter(|n| n.transfer_type == "incoming").map(|n| n.amount).sum();
                        let s_sent: u64 = tx.sapling_notes.iter()
                            .filter(|n| n.transfer_type == "outgoing").map(|n| n.amount).sum();
                        let o_recv: u64 = tx.orchard_notes.iter()
                            .filter(|n| n.transfer_type == "incoming").map(|n| n.amount).sum();
                        let o_sent: u64 = tx.orchard_notes.iter()
                            .filter(|n| n.transfer_type == "outgoing").map(|n| n.amount).sum();

                        sapling_recv += s_recv;
                        sapling_sent += s_sent;
                        orchard_recv += o_recv;
                        orchard_sent += o_sent;

                        let time = format_block_time(tx.block_time);
                        let protocols = match (!tx.sapling_notes.is_empty(), !tx.orchard_notes.is_empty()) {
                            (true,  true)  => "Sapling + Orchard",
                            (true,  false) => "Sapling",
                            (false, true)  => "Orchard",
                            (false, false) => "—",
                        };

                        println!();
                        println!("  [{}/{}]  {}", i + 1, tx_count, tx.txid);
                        println!("           Height     {}   {time}", fmt_num(tx.block_height));
                        println!("           Protocols  {protocols}");

                        if !tx.sapling_notes.is_empty() {
                            println!("           ── Sapling ({} note{})",
                                tx.sapling_notes.len(),
                                if tx.sapling_notes.len() == 1 { "" } else { "s" });
                            for n in &tx.sapling_notes {
                                let memo = if n.memo.is_empty() { String::new() }
                                           else { format!("  memo={:?}", n.memo) };
                                println!("              [{:<8}]  {}{}",
                                    n.transfer_type, fmt_zec(n.amount), memo);
                            }
                        }
                        if !tx.orchard_notes.is_empty() {
                            println!("           ── Orchard ({} note{})",
                                tx.orchard_notes.len(),
                                if tx.orchard_notes.len() == 1 { "" } else { "s" });
                            for n in &tx.orchard_notes {
                                let memo = if n.memo.is_empty() { String::new() }
                                           else { format!("  memo={:?}", n.memo) };
                                println!("              [{:<8}]  {}{}",
                                    n.transfer_type, fmt_zec(n.amount), memo);
                            }
                        }

                        let tx_recv = s_recv + o_recv;
                        let tx_sent = s_sent + o_sent;
                        println!("           Fee        {}", fmt_zec(tx.fee_zatoshis as u64));
                        println!("           Net        +{}  −{}", fmt_zec(tx_recv), fmt_zec(tx_sent));
                    }

                    // ── balance summary ──────────────────────────────────────
                    println!();
                    println!("{sep2}");
                    println!("Balance summary");
                    println!("{sep}");

                    let fmt_signed = |recv: u64, sent: u64| -> String {
                        if recv >= sent {
                            format!("+{}", fmt_zec(recv - sent))
                        } else {
                            format!("−{}", fmt_zec(sent - recv))
                        }
                    };

                    println!("  Sapling   received {}   sent {}   net {}",
                        fmt_zec(sapling_recv), fmt_zec(sapling_sent),
                        fmt_signed(sapling_recv, sapling_sent));
                    println!("  Orchard   received {}   sent {}   net {}",
                        fmt_zec(orchard_recv), fmt_zec(orchard_sent),
                        fmt_signed(orchard_recv, orchard_sent));
                    println!("  {}", "─".repeat(68));
                    let total_recv = sapling_recv + orchard_recv;
                    let total_sent = sapling_sent + orchard_sent;
                    println!("  Total net balance   {}", fmt_signed(total_recv, total_sent));
                }
                println!("{sep2}");
            }
            Format::Json => {
                let pool_notes = |notes: &[zcash_sync::sync::ShieldedNote]| {
                    notes
                        .iter()
                        .map(|n| {
                            serde_json::json!({
                                "amount": n.amount,
                                "transfer_type": n.transfer_type,
                                "memo": n.memo,
                            })
                        })
                        .collect::<Vec<_>>()
                };
                let json = serde_json::json!({
                    "blocks_scanned": result.blocks_scanned,
                    "elapsed_ms": result.elapsed_ms,
                    "transactions": result.transactions.iter().map(|tx| {
                        serde_json::json!({
                            "txid": tx.txid,
                            "block_height": tx.block_height,
                            "block_hash": tx.block_hash,
                            "block_time": tx.block_time,
                            "fee_zatoshis": tx.fee_zatoshis,
                            "sapling_notes": pool_notes(&tx.sapling_notes),
                            "orchard_notes": pool_notes(&tx.orchard_notes),
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Format an integer with thousands separators: 3654470 → "3,654,470".
fn fmt_num(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

/// Format zatoshis as "1.23456789 ZEC".
fn fmt_zec(zat: u64) -> String {
    let whole = zat / 100_000_000;
    let frac  = zat % 100_000_000;
    format!("{}.{:08} ZEC", whole, frac)
}

/// Format a Unix timestamp as ISO-8601 UTC (seconds precision).
fn format_block_time(ts: u32) -> String {
    // Manual conversion — no chrono dependency needed for seconds-precision ISO 8601.
    let s = ts as u64;
    let secs_per_day = 86_400u64;
    // Days since Unix epoch
    let days = s / secs_per_day;
    let time_of_day = s % secs_per_day;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    // Gregorian calendar computation
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

/// Split `[start, end]` into consecutive chunks of at most `chunk_size` blocks.
///
/// Returns an empty vec when `start > end`.
fn build_chunks(start: u32, end: u32, chunk_size: u32) -> Vec<(u32, u32)> {
    if start > end {
        return Vec::new();
    }
    let total = end - start + 1;
    let n = ((total + chunk_size - 1) / chunk_size) as usize;
    let mut v = Vec::with_capacity(n);
    let mut h = start;
    while h <= end {
        let chunk_end = (h + chunk_size - 1).min(end);
        v.push((h, chunk_end));
        h = chunk_end + 1;
    }
    v
}

fn print_pool_human(label: &str, pool: &PoolViewingKeys) {
    println!("  {label}:");
    println!("    fvk : {}", pool.fvk);
    println!("    ivk : {}", pool.ivk);
    println!("    ovk : {}", pool.ovk);
}

// ─── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── fmt_num ───────────────────────────────────────────────────────────────

    #[test]
    fn fmt_num_zero() {
        assert_eq!(fmt_num(0), "0");
    }

    #[test]
    fn fmt_num_below_thousand() {
        assert_eq!(fmt_num(999), "999");
    }

    #[test]
    fn fmt_num_exact_thousand() {
        assert_eq!(fmt_num(1_000), "1,000");
    }

    #[test]
    fn fmt_num_millions() {
        assert_eq!(fmt_num(3_654_470), "3,654,470");
    }

    #[test]
    fn fmt_num_max_u32() {
        assert_eq!(fmt_num(u32::MAX), "4,294,967,295");
    }

    // ── fmt_zec ───────────────────────────────────────────────────────────────

    #[test]
    fn fmt_zec_zero() {
        assert_eq!(fmt_zec(0), "0.00000000 ZEC");
    }

    #[test]
    fn fmt_zec_one_zatoshi() {
        assert_eq!(fmt_zec(1), "0.00000001 ZEC");
    }

    #[test]
    fn fmt_zec_one_zec() {
        assert_eq!(fmt_zec(100_000_000), "1.00000000 ZEC");
    }

    #[test]
    fn fmt_zec_fractional() {
        assert_eq!(fmt_zec(123_456_789), "1.23456789 ZEC");
    }

    #[test]
    fn fmt_zec_ten_zec() {
        assert_eq!(fmt_zec(1_000_000_000), "10.00000000 ZEC");
    }

    // ── format_block_time ─────────────────────────────────────────────────────

    #[test]
    fn format_block_time_unix_epoch() {
        assert_eq!(format_block_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_block_time_one_day() {
        assert_eq!(format_block_time(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn format_block_time_known_timestamp() {
        // 2009-01-09T02:54:25Z — Bitcoin genesis block timestamp (well-known)
        assert_eq!(format_block_time(1_231_469_665), "2009-01-09T02:54:25Z");
    }

    #[test]
    fn format_block_time_leap_year() {
        // 2000-02-29T00:00:00Z — leap day
        assert_eq!(format_block_time(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn format_block_time_end_of_day() {
        // 1970-01-01T23:59:59Z
        assert_eq!(format_block_time(86_399), "1970-01-01T23:59:59Z");
    }

    // ── build_chunks ──────────────────────────────────────────────────────────

    #[test]
    fn build_chunks_empty_when_start_exceeds_end() {
        assert!(build_chunks(10, 5, 100).is_empty());
    }

    #[test]
    fn build_chunks_single_block() {
        assert_eq!(build_chunks(42, 42, 100), vec![(42, 42)]);
    }

    #[test]
    fn build_chunks_exact_fit() {
        // 10 blocks, chunk_size=5 → two equal chunks
        assert_eq!(build_chunks(0, 9, 5), vec![(0, 4), (5, 9)]);
    }

    #[test]
    fn build_chunks_remainder() {
        // 7 blocks, chunk_size=3 → [0,2], [3,5], [6,6]
        assert_eq!(build_chunks(0, 6, 3), vec![(0, 2), (3, 5), (6, 6)]);
    }

    #[test]
    fn build_chunks_larger_than_range() {
        assert_eq!(build_chunks(100, 104, 1_000), vec![(100, 104)]);
    }

    #[test]
    fn build_chunks_covers_full_range() {
        let chunks = build_chunks(419_200, 419_209, 3);
        // Verify no gap and no overlap between consecutive chunks
        for w in chunks.windows(2) {
            assert_eq!(w[0].1 + 1, w[1].0, "gap or overlap between chunks");
        }
        assert_eq!(chunks.first().unwrap().0, 419_200);
        assert_eq!(chunks.last().unwrap().1, 419_209);
    }

    #[test]
    fn build_chunks_total_blocks_preserved() {
        let start = 1_000u32;
        let end = 9_999u32;
        let chunk_size = 1_000u32;
        let chunks = build_chunks(start, end, chunk_size);
        let total: u32 = chunks.iter().map(|(s, e)| e - s + 1).sum();
        assert_eq!(total, end - start + 1);
    }
}
