use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::BufRead;
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
    /// gRPC endpoint URL (e.g. `https://testnet.zec.rocks:443`)
    #[arg(long)]
    grpc_url: String,
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

    /// Number of blocks per gRPC call (default: 50 000)
    #[arg(long)]
    chunk_size: Option<u32>,

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
                println!("xpub path : {}", keys.xpub_path);
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
                    "xpub_path": keys.xpub_path,
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
    match zcash_grpc::client::chain_tip(args.grpc_url).await {
        Ok(height) => println!("{height}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

async fn cmd_sync(args: SyncArgs) {
    use zcash_grpc::sync::{run_sync, SyncParams};

    let network_str = match args.network {
        Network::Mainnet => "mainnet".to_string(),
        Network::Testnet => "testnet".to_string(),
    };

    let sapling_activation = match args.network {
        Network::Mainnet => 419_200u32,
        Network::Testnet => 280_000u32,
    };

    let start_height = args.start_height.unwrap_or(sapling_activation);

    let end_height = match args.end_height {
        Some(h) => h,
        None => {
            if args.verbose {
                eprintln!("[sync] --end-height not set, querying chain tip from {}...", args.grpc_url);
            }
            match zcash_grpc::client::chain_tip(args.grpc_url.clone()).await {
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

    let chunk_size = args.chunk_size.unwrap_or(50_000);
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
    eprintln!("{sep}");
    eprintln!();

    if verbose {
        eprintln!(
            "[sync] network={} range={}..{} ({} blocks, {} chunks of {})",
            network_str, start_height, end_height, total_blocks, n_chunks, chunk_size
        );
    }

    // Progress bar (shown only when not in verbose mode)
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
        Some(bar)
    } else {
        None
    };

    let global_start = std::time::Instant::now();
    let mut all_transactions: Vec<zcash_grpc::sync::ShieldedTransaction> = Vec::new();
    let mut total_blocks_scanned = 0u32;
    let mut total_tx_found = 0usize;

    let mut h = start_height;
    let mut chunk_idx = 0u32;
    while h <= end_height {
        let chunk_end = (h + chunk_size - 1).min(end_height);
        let chunk_t0 = std::time::Instant::now();

        if verbose {
            let pct = (h - start_height) * 100 / total_blocks;
            eprintln!(
                "[sync] chunk {}/{}: {}..{} ({}% done, {}s elapsed)",
                chunk_idx + 1, n_chunks, h, chunk_end, pct,
                global_start.elapsed().as_secs()
            );
        }

        let chunk_result = match run_sync(SyncParams {
            grpc_url: args.grpc_url.clone(),
            viewing_key: args.viewing_key.clone(),
            start_height: h,
            end_height: chunk_end,
            network: Some(network_str.clone()),
        }).await {
            Ok(r) => r,
            Err(e) => {
                if let Some(ref bar) = pb { bar.abandon(); }
                eprintln!("Error on chunk {}..{}: {e}", h, chunk_end);
                std::process::exit(1);
            }
        };

        if verbose {
            let blps = chunk_result.blocks_scanned as f64 / chunk_t0.elapsed().as_secs_f64();
            let tx_tag = if chunk_result.transactions.is_empty() { String::new() }
                         else { format!("  *** {} tx found ***", chunk_result.transactions.len()) };
            eprintln!(
                "[sync] chunk {}/{} done: {} blocks in {}ms ({:.0} bl/s){}",
                chunk_idx + 1, n_chunks,
                chunk_result.blocks_scanned,
                chunk_t0.elapsed().as_millis(),
                blps, tx_tag
            );
        }

        total_blocks_scanned += chunk_result.blocks_scanned;
        total_tx_found += chunk_result.transactions.len();
        all_transactions.extend(chunk_result.transactions);

        if let Some(ref bar) = pb {
            bar.inc(chunk_result.blocks_scanned as u64);
            if total_tx_found > 0 {
                bar.set_message(format!("{total_tx_found} tx found"));
            }
        }

        h = chunk_end + 1;
        chunk_idx += 1;
    }

    if let Some(ref bar) = pb {
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

    let result = zcash_grpc::sync::SyncResult {
        transactions: all_transactions,
        blocks_scanned: total_blocks_scanned,
        elapsed_ms: global_start.elapsed().as_millis() as u64,
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
                let pool_notes = |notes: &[zcash_grpc::sync::ShieldedNote]| {
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

fn print_pool_human(label: &str, pool: &PoolViewingKeys) {
    println!("  {label}:");
    println!("    fvk : {}", pool.fvk);
    println!("    ivk : {}", pool.ivk);
    println!("    ovk : {}", pool.ovk);
}
