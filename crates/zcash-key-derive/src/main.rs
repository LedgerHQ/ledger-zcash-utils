use clap::{Parser, ValueEnum};
use std::io::BufRead;
use zcash_key_derive::{derive_keys_with_options, DeriveOptions, PoolViewingKeys, ZcashNetwork};

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

#[derive(Parser, Debug)]
#[command(
    name = "zcash-key-derive",
    about = "Derive all Zcash viewing keys from a BIP-39 mnemonic",
    long_about = "\
Derives for a given account:
  - UFVK     Unified Full Viewing Key (ZIP-316, all pools by default)
  - xpub     Transparent extended public key (BIP-32)
  - sapling  FVK / IVK / OVK (hex)
  - orchard  FVK / IVK / OVK (hex)

No spending key material is exposed.
Use --account to target a specific ZIP-32 account index (default: 0).
Use --xpub-path to override the transparent derivation path independently.
Use --no-sapling to omit the Sapling FVK from the generated UFVK."
)]
struct Args {
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

fn print_pool_human(label: &str, pool: &PoolViewingKeys) {
    println!("  {label}:");
    println!("    fvk : {}", pool.fvk);
    println!("    ivk : {}", pool.ivk);
    println!("    ovk : {}", pool.ovk);
}

fn main() {
    let args = Args::parse();

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
        DeriveOptions {
            include_sapling_in_ufvk: !args.no_sapling,
        },
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
