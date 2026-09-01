use crate::error::Error;
use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

/// Parse a network name string into a [`zcash_protocol::consensus::Network`].
///
/// Accepts `"mainnet"` or `"testnet"`. Defaults to `"testnet"` when `None` is passed.
///
/// This feeds the scanning/decryption path (`decrypt`, `zcash_sync::client` /
/// `zcash_sync::sync`), which never gates on network-upgrade activation height and
/// has no regtest use case today. For the transaction-building path, which does
/// gate on activation height (NU5/NU6.3) and needs regtest support, see
/// [`parse_any_network`] instead.
///
/// # Errors
///
/// Returns [`Error::Derivation`] if the string is not a recognised network name.
pub fn parse_network(s: Option<&str>) -> Result<Network, Error> {
    match s.unwrap_or("testnet") {
        "testnet" => Ok(Network::TestNetwork),
        "mainnet" => Ok(Network::MainNetwork),
        other => Err(Error::Derivation(format!(
            "unknown network {:?}, expected \"mainnet\" or \"testnet\"",
            other
        ))),
    }
}

/// A concrete Zcash network parameter set: either a named, real-world network
/// ([`Network::MainNetwork`] / [`Network::TestNetwork`], whose NU5/NU6.x
/// activation heights are hardcoded upstream) or a caller-configured
/// [`LocalNetwork`] (regtest, whose activation heights track a `zcashd`/`zebrad`
/// regtest node's configured `nuparams`).
///
/// `Network` and `LocalNetwork` are two distinct concrete types that both
/// implement [`Parameters`]. `craft::BuildInputs`/`craft::IronwoodBuildInputs`
/// need a single `network` field that is owned, `Clone`-able, and can be stored
/// and re-read across the build (it is read again after being moved into the
/// `zcash_primitives` `Builder`). Making the builder generic over `Parameters`
/// would ripple a type parameter through every helper function in `craft.rs`
/// that currently pins the concrete `Network` type, for no benefit beyond this
/// one field — so instead this enum wraps whichever concrete network is in
/// play and forwards `Parameters` to it by delegation, which is a drop-in
/// replacement at every call site that previously stored a bare `Network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyZcashNetwork {
    /// A named, real-world network (mainnet or testnet).
    Named(Network),
    /// A caller-configured local network (regtest).
    Local(LocalNetwork),
}

impl Parameters for AnyZcashNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            AnyZcashNetwork::Named(network) => network.network_type(),
            // Kept as `LocalNetwork`'s own `Regtest` (pure delegation), even
            // though `zcash_protocol`'s blanket `NetworkConstants` impl derives
            // `coin_type()` from exactly this value: `zcash_address::Address::decode`
            // (called by this crate's `decode_destination`/`decode_ironwood_destination`
            // on every transparent/unified destination string) checks the address's
            // encoded version bytes against this same `network_type()`, and every
            // regtest address this package's callers pass in is deliberately encoded
            // with regtest's own (testnet-shared) version bytes -- overriding this to
            // `Main` made every transparent destination decode fail with "invalid
            // destination address" (empirically confirmed). See `craft::stamped_coin_type`
            // for where the mainnet coin type is instead applied narrowly, only to the
            // derivation paths this crate itself stamps into a PCZT.
            AnyZcashNetwork::Local(network) => network.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            AnyZcashNetwork::Named(network) => network.activation_height(nu),
            AnyZcashNetwork::Local(network) => network.activation_height(nu),
        }
    }
}

impl From<Network> for AnyZcashNetwork {
    fn from(network: Network) -> Self {
        AnyZcashNetwork::Named(network)
    }
}

impl From<LocalNetwork> for AnyZcashNetwork {
    fn from(network: LocalNetwork) -> Self {
        AnyZcashNetwork::Local(network)
    }
}

/// Regtest activation heights matching the canonical set zebra, zaino, and
/// librustzcash agree on: Overwinter through Canopy activate at height 1, NU5 at
/// height 2, and NU6/NU6.1/NU6.2/NU6.3 at height 2. Mirrors a `zcashd`/`zebrad`
/// regtest node's default `nuparams` configuration.
///
/// This crate does not support per-caller regtest activation heights (see
/// [`parse_any_network`]) — a caller running against a regtest node configured
/// with different `nuparams` is not supported today.
pub const ZCASH_REGTEST: LocalNetwork = LocalNetwork {
    overwinter: Some(BlockHeight::from_u32(1)),
    sapling: Some(BlockHeight::from_u32(1)),
    blossom: Some(BlockHeight::from_u32(1)),
    heartwood: Some(BlockHeight::from_u32(1)),
    canopy: Some(BlockHeight::from_u32(1)),
    nu5: Some(BlockHeight::from_u32(2)),
    nu6: Some(BlockHeight::from_u32(2)),
    nu6_1: Some(BlockHeight::from_u32(2)),
    nu6_2: Some(BlockHeight::from_u32(2)),
    nu6_3: Some(BlockHeight::from_u32(2)),
};

/// Parse a network name string into an [`AnyZcashNetwork`] for transaction
/// building.
///
/// Accepts `"mainnet"`, `"testnet"`, or `"regtest"`. Defaults to `"testnet"` when
/// `None` is passed. `"regtest"` resolves to [`ZCASH_REGTEST`].
///
/// Feeds `craft::build_transaction`/`craft::build_ironwood_transaction` (via
/// `zcash_sync::craft::craft_transaction`/`craft_ironwood_transaction`), which
/// gate on NU5/NU6.3 activation height and therefore need regtest support so a
/// local-node build doesn't reject every send. See [`parse_network`] for the
/// (unaffected, mainnet/testnet-only) scanning/decryption path.
///
/// # Errors
///
/// Returns [`Error::Derivation`] if the string is not a recognised network name.
pub fn parse_any_network(s: Option<&str>) -> Result<AnyZcashNetwork, Error> {
    match s.unwrap_or("testnet") {
        "testnet" => Ok(AnyZcashNetwork::Named(Network::TestNetwork)),
        "mainnet" => Ok(AnyZcashNetwork::Named(Network::MainNetwork)),
        "regtest" => Ok(AnyZcashNetwork::Local(ZCASH_REGTEST)),
        other => Err(Error::Derivation(format!(
            "unknown network {:?}, expected \"mainnet\", \"testnet\", or \"regtest\"",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network_mainnet() {
        assert_eq!(
            parse_network(Some("mainnet")).unwrap(),
            Network::MainNetwork
        );
    }

    #[test]
    fn test_parse_network_testnet() {
        assert_eq!(
            parse_network(Some("testnet")).unwrap(),
            Network::TestNetwork
        );
    }

    #[test]
    fn test_parse_network_default_is_testnet() {
        assert_eq!(parse_network(None).unwrap(), Network::TestNetwork);
    }

    #[test]
    fn test_parse_network_invalid() {
        let err = parse_network(Some("devnet")).unwrap_err();
        assert!(matches!(err, Error::Derivation(_)));
        assert!(err.to_string().contains("devnet"));
    }

    #[test]
    fn test_parse_network_empty_string() {
        let err = parse_network(Some("")).unwrap_err();
        assert!(matches!(err, Error::Derivation(_)));
    }

    #[test]
    fn test_parse_network_rejects_regtest() {
        let err = parse_network(Some("regtest")).unwrap_err();
        assert!(matches!(err, Error::Derivation(_)));
        assert!(err.to_string().contains("regtest"));
    }

    #[test]
    fn test_parse_any_network_mainnet() {
        assert_eq!(
            parse_any_network(Some("mainnet")).unwrap(),
            AnyZcashNetwork::Named(Network::MainNetwork)
        );
    }

    #[test]
    fn test_parse_any_network_testnet() {
        assert_eq!(
            parse_any_network(Some("testnet")).unwrap(),
            AnyZcashNetwork::Named(Network::TestNetwork)
        );
    }

    #[test]
    fn test_parse_any_network_default_is_testnet() {
        assert_eq!(
            parse_any_network(None).unwrap(),
            AnyZcashNetwork::Named(Network::TestNetwork)
        );
    }

    #[test]
    fn test_parse_any_network_regtest() {
        assert_eq!(
            parse_any_network(Some("regtest")).unwrap(),
            AnyZcashNetwork::Local(ZCASH_REGTEST)
        );
    }

    #[test]
    fn test_parse_any_network_invalid() {
        let err = parse_any_network(Some("devnet")).unwrap_err();
        assert!(matches!(err, Error::Derivation(_)));
        assert!(err.to_string().contains("devnet"));
        assert!(err.to_string().contains("regtest"));
    }

    #[test]
    fn test_any_zcash_network_from_conversions() {
        let named: AnyZcashNetwork = Network::MainNetwork.into();
        assert_eq!(named, AnyZcashNetwork::Named(Network::MainNetwork));

        let local: AnyZcashNetwork = ZCASH_REGTEST.into();
        assert_eq!(local, AnyZcashNetwork::Local(ZCASH_REGTEST));
    }

    #[test]
    fn test_any_zcash_network_type_delegates() {
        assert_eq!(
            AnyZcashNetwork::Named(Network::MainNetwork).network_type(),
            NetworkType::Main
        );
        assert_eq!(
            AnyZcashNetwork::Named(Network::TestNetwork).network_type(),
            NetworkType::Test
        );
        assert_eq!(
            AnyZcashNetwork::Local(ZCASH_REGTEST).network_type(),
            NetworkType::Regtest
        );
    }

    #[test]
    fn test_any_zcash_network_activation_height_delegates() {
        let named = AnyZcashNetwork::Named(Network::MainNetwork);
        assert_eq!(
            named.activation_height(NetworkUpgrade::Nu5),
            Network::MainNetwork.activation_height(NetworkUpgrade::Nu5)
        );

        let local = AnyZcashNetwork::Local(ZCASH_REGTEST);
        assert_eq!(
            local.activation_height(NetworkUpgrade::Nu5),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(
            local.activation_height(NetworkUpgrade::Nu6_3),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(
            local.activation_height(NetworkUpgrade::Overwinter),
            Some(BlockHeight::from_u32(1))
        );
    }

    #[test]
    fn test_any_zcash_network_is_nu_active_on_regtest() {
        let local = AnyZcashNetwork::Local(ZCASH_REGTEST);
        assert!(!local.is_nu_active(NetworkUpgrade::Nu5, BlockHeight::from_u32(1)));
        assert!(local.is_nu_active(NetworkUpgrade::Nu5, BlockHeight::from_u32(2)));
        assert!(local.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(3)));
    }
}
