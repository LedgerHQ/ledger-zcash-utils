use assert_cmd::Command;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("ledger-zcash-cli").unwrap()
}

// ─── top-level help ───────────────────────────────────────────────────────────

#[test]
fn help_exits_zero() {
    cmd().arg("--help").assert().success();
}

#[test]
fn help_lists_subcommands() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("derive"))
        .stdout(contains("tip"))
        .stdout(contains("height-at"))
        .stdout(contains("sync"));
}

#[test]
fn no_args_exits_nonzero() {
    cmd().assert().failure();
}

// ─── derive subcommand ────────────────────────────────────────────────────────

#[test]
fn derive_help_exits_zero() {
    cmd().args(["derive", "--help"]).assert().success();
}

#[test]
fn derive_invalid_network_exits_nonzero() {
    cmd()
        .args(["derive", "--mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "--network", "invalidnet"])
        .assert()
        .failure();
}

#[test]
fn derive_known_mnemonic_human() {
    // BIP-39 test vector — all-abandon mnemonic, account 0, mainnet
    cmd()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--network",
            "mainnet",
            "--format",
            "human",
        ])
        .assert()
        .success()
        .stdout(contains("ufvk"))
        .stdout(contains("xpub"))
        .stdout(contains("sapling"))
        .stdout(contains("orchard"));
}

#[test]
fn derive_known_mnemonic_json() {
    cmd()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--network",
            "mainnet",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(contains("\"ufvk\""))
        .stdout(contains("\"xpub\""))
        .stdout(contains("\"sapling\""))
        .stdout(contains("\"orchard\""));
}

#[test]
fn derive_no_sapling_excludes_sapling_from_ufvk() {
    // With --no-sapling the output must still succeed and print an Orchard key
    cmd()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--no-sapling",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(contains("\"orchard\""));
}

#[test]
fn derive_testnet_succeeds() {
    cmd()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--network",
            "testnet",
        ])
        .assert()
        .success();
}

#[test]
fn derive_account_index_is_accepted() {
    cmd()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--account",
            "1",
        ])
        .assert()
        .success();
}

// ─── tip subcommand ───────────────────────────────────────────────────────────

#[test]
fn tip_help_exits_zero() {
    cmd().args(["tip", "--help"]).assert().success();
}

#[test]
fn tip_missing_grpc_url_exits_nonzero() {
    cmd().arg("tip").assert().failure();
}

// ─── height-at subcommand ────────────────────────────────────────────────

#[test]
fn height_at_help_exits_zero() {
    cmd().args(["height-at", "--help"]).assert().success();
}

#[test]
fn height_at_missing_args_exits_nonzero() {
    cmd().arg("height-at").assert().failure();
}

#[test]
fn height_at_missing_date_exits_nonzero() {
    cmd()
        .args(["height-at", "--grpc-url", "https://example.com"])
        .assert()
        .failure();
}

#[test]
fn height_at_missing_grpc_url_exits_nonzero() {
    cmd()
        .args(["height-at", "--date", "2024-01-15"])
        .assert()
        .failure();
}

// ─── sync subcommand ─────────────────────────────────────────────────────────

#[test]
fn sync_help_exits_zero() {
    cmd().args(["sync", "--help"]).assert().success();
}

#[test]
fn sync_missing_required_args_exits_nonzero() {
    cmd().arg("sync").assert().failure();
}
