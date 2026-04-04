use assert_cmd::Command;

const KNOWN_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_derive_json_output_has_ufvk_key() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args(["derive", "--mnemonic", KNOWN_MNEMONIC, "--format", "json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"ufvk\""));
}

#[test]
fn test_derive_json_mainnet_ufvk_prefix() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args([
        "derive",
        "--mnemonic",
        KNOWN_MNEMONIC,
        "--network",
        "mainnet",
        "--format",
        "json",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains("uview1"));
}

#[test]
fn test_derive_json_testnet_ufvk_prefix() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args([
        "derive",
        "--mnemonic",
        KNOWN_MNEMONIC,
        "--network",
        "testnet",
        "--format",
        "json",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains("uviewtest1"));
}

#[test]
fn test_derive_human_output_has_ufvk_label() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args(["derive", "--mnemonic", KNOWN_MNEMONIC, "--format", "human"])
        .assert()
        .success()
        .stdout(predicates::str::contains("ufvk"));
}

#[test]
fn test_derive_invalid_mnemonic_exits_nonzero() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args(["derive", "--mnemonic", "not a valid mnemonic phrase here"])
        .assert()
        .failure();
}

#[test]
fn test_derive_no_sapling_flag() {
    let mut cmd = Command::cargo_bin("ledger-zcash-cli").unwrap();
    cmd.args([
        "derive",
        "--mnemonic",
        KNOWN_MNEMONIC,
        "--no-sapling",
        "--format",
        "json",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains("\"ufvk\""));
}
