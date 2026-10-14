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
/// A caller whose regtest node schedules its upgrades differently overrides
/// individual heights with [`RegtestActivationHeights`] (see
/// [`resolve_any_network`]); every height it leaves unset keeps the value here.
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
    // Not part of the canonical regtest set: a regtest node only reaches NU7 when its
    // `nuparams` schedule it, which a caller then mirrors with
    // `RegtestActivationHeights::nu7`.
    nu7: None,
};

/// Caller-supplied regtest activation heights, one per network upgrade.
///
/// Mirrors the `nuparams` (zcashd) or `activation_heights` (zebrad) a local
/// regtest node was started with, so the builder selects the same branch id
/// and caps the expiry height at the same upcoming activation the node will
/// enforce. Each `Some` replaces the matching [`ZCASH_REGTEST`] height; each
/// `None` keeps it. There is no way to unschedule an upgrade the canonical set
/// activates — no regtest node this crate targets runs without them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegtestActivationHeights {
    pub overwinter: Option<u32>,
    pub sapling: Option<u32>,
    pub blossom: Option<u32>,
    pub heartwood: Option<u32>,
    pub canopy: Option<u32>,
    pub nu5: Option<u32>,
    pub nu6: Option<u32>,
    pub nu6_1: Option<u32>,
    pub nu6_2: Option<u32>,
    pub nu6_3: Option<u32>,
    pub nu7: Option<u32>,
}

impl RegtestActivationHeights {
    /// Applies these overrides on top of [`ZCASH_REGTEST`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Derivation`] if a height is 0 (the genesis block
    /// activates nothing) or if the resulting schedule is not ordered: each
    /// scheduled upgrade must activate at or after its predecessor, and none
    /// may follow an unscheduled one. A node rejects such a schedule too, so
    /// accepting it here would only build against a chain that cannot exist.
    pub fn to_local_network(&self) -> Result<LocalNetwork, Error> {
        let pick = |name: &str,
                    over: Option<u32>,
                    base: Option<BlockHeight>|
         -> Result<Option<BlockHeight>, Error> {
            match over {
                Some(0) => Err(Error::Derivation(format!(
                    "regtest activation height for {name} must be at least 1"
                ))),
                Some(h) => Ok(Some(BlockHeight::from_u32(h))),
                None => Ok(base),
            }
        };
        let base = ZCASH_REGTEST;
        let local = LocalNetwork {
            overwinter: pick("overwinter", self.overwinter, base.overwinter)?,
            sapling: pick("sapling", self.sapling, base.sapling)?,
            blossom: pick("blossom", self.blossom, base.blossom)?,
            heartwood: pick("heartwood", self.heartwood, base.heartwood)?,
            canopy: pick("canopy", self.canopy, base.canopy)?,
            nu5: pick("nu5", self.nu5, base.nu5)?,
            nu6: pick("nu6", self.nu6, base.nu6)?,
            nu6_1: pick("nu6_1", self.nu6_1, base.nu6_1)?,
            nu6_2: pick("nu6_2", self.nu6_2, base.nu6_2)?,
            nu6_3: pick("nu6_3", self.nu6_3, base.nu6_3)?,
            nu7: pick("nu7", self.nu7, base.nu7)?,
        };

        let schedule = [
            ("overwinter", local.overwinter),
            ("sapling", local.sapling),
            ("blossom", local.blossom),
            ("heartwood", local.heartwood),
            ("canopy", local.canopy),
            ("nu5", local.nu5),
            ("nu6", local.nu6),
            ("nu6_1", local.nu6_1),
            ("nu6_2", local.nu6_2),
            ("nu6_3", local.nu6_3),
            ("nu7", local.nu7),
        ];
        for pair in schedule.windows(2) {
            let ((prev_name, prev), (name, cur)) = (pair[0], pair[1]);
            match (prev, cur) {
                (None, Some(_)) => {
                    return Err(Error::Derivation(format!(
                        "regtest activation schedule: {name} is scheduled but {prev_name} is not"
                    )))
                }
                (Some(p), Some(c)) if c < p => return Err(Error::Derivation(format!(
                    "regtest activation schedule: {name} ({c}) activates before {prev_name} ({p})"
                ))),
                _ => {}
            }
        }
        Ok(local)
    }
}

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
    resolve_any_network(s, None)
}

/// [`parse_any_network`], with the regtest activation heights optionally
/// overridden by the caller.
///
/// `regtest_heights` only applies to `"regtest"`: the named networks'
/// activation heights are consensus constants, so overrides passed with
/// `"mainnet"` or `"testnet"` are refused rather than silently ignored.
///
/// # Errors
///
/// Returns [`Error::Derivation`] if the network name is not recognised, if
/// overrides accompany a named network, or if the overridden schedule is
/// invalid (see [`RegtestActivationHeights::to_local_network`]).
pub fn resolve_any_network(
    s: Option<&str>,
    regtest_heights: Option<&RegtestActivationHeights>,
) -> Result<AnyZcashNetwork, Error> {
    let name = s.unwrap_or("testnet");
    let named = match name {
        "testnet" => Network::TestNetwork,
        "mainnet" => Network::MainNetwork,
        "regtest" => {
            return Ok(AnyZcashNetwork::Local(match regtest_heights {
                Some(heights) => heights.to_local_network()?,
                None => ZCASH_REGTEST,
            }))
        }
        other => {
            return Err(Error::Derivation(format!(
                "unknown network {:?}, expected \"mainnet\", \"testnet\", or \"regtest\"",
                other
            )))
        }
    };
    if regtest_heights.is_some() {
        return Err(Error::Derivation(format!(
            "regtest activation heights were supplied for network {name:?}; they only apply to \"regtest\""
        )));
    }
    Ok(AnyZcashNetwork::Named(named))
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

    #[test]
    fn test_resolve_any_network_without_overrides_matches_parse() {
        for name in [None, Some("mainnet"), Some("testnet"), Some("regtest")] {
            assert_eq!(
                resolve_any_network(name, None).unwrap(),
                parse_any_network(name).unwrap()
            );
        }
    }

    #[test]
    fn test_resolve_any_network_empty_overrides_keep_canonical_regtest() {
        let heights = RegtestActivationHeights::default();
        assert_eq!(
            resolve_any_network(Some("regtest"), Some(&heights)).unwrap(),
            AnyZcashNetwork::Local(ZCASH_REGTEST)
        );
    }

    #[test]
    fn test_resolve_any_network_applies_regtest_overrides() {
        let heights = RegtestActivationHeights {
            nu6_3: Some(150),
            nu7: Some(200),
            ..Default::default()
        };
        let network = resolve_any_network(Some("regtest"), Some(&heights)).unwrap();
        assert_eq!(
            network.activation_height(NetworkUpgrade::Nu6_3),
            Some(BlockHeight::from_u32(150))
        );
        assert_eq!(
            network.activation_height(NetworkUpgrade::Nu7),
            Some(BlockHeight::from_u32(200))
        );
        // Unset fields keep the canonical heights.
        assert_eq!(
            network.activation_height(NetworkUpgrade::Nu6_2),
            Some(BlockHeight::from_u32(2))
        );
        assert_eq!(
            network.activation_height(NetworkUpgrade::Canopy),
            Some(BlockHeight::from_u32(1))
        );
    }

    #[test]
    fn test_resolve_any_network_rejects_overrides_on_named_networks() {
        let heights = RegtestActivationHeights {
            nu7: Some(10),
            ..Default::default()
        };
        for name in [None, Some("mainnet"), Some("testnet")] {
            let err = resolve_any_network(name, Some(&heights)).unwrap_err();
            assert!(matches!(err, Error::Derivation(_)));
            assert!(err.to_string().contains("only apply to \"regtest\""));
        }
    }

    #[test]
    fn test_resolve_any_network_still_rejects_unknown_names() {
        let heights = RegtestActivationHeights::default();
        let err = resolve_any_network(Some("devnet"), Some(&heights)).unwrap_err();
        assert!(err.to_string().contains("devnet"));
    }

    #[test]
    fn test_regtest_heights_reject_zero() {
        let heights = RegtestActivationHeights {
            nu5: Some(0),
            ..Default::default()
        };
        let err = heights.to_local_network().unwrap_err();
        assert!(err.to_string().contains("nu5 must be at least 1"));
    }

    #[test]
    fn test_regtest_heights_reject_out_of_order_schedule() {
        // NU6.3 moved past NU7.
        let heights = RegtestActivationHeights {
            nu6_3: Some(300),
            nu7: Some(200),
            ..Default::default()
        };
        let err = heights.to_local_network().unwrap_err();
        assert!(err
            .to_string()
            .contains("nu7 (200) activates before nu6_3 (300)"));

        // An upgrade moved below its (unchanged) predecessor.
        let heights = RegtestActivationHeights {
            nu5: Some(1),
            canopy: Some(5),
            ..Default::default()
        };
        let err = heights.to_local_network().unwrap_err();
        assert!(err
            .to_string()
            .contains("nu5 (1) activates before canopy (5)"));
    }

    #[test]
    fn test_regtest_heights_accept_equal_heights() {
        let heights = RegtestActivationHeights {
            nu7: Some(2),
            ..Default::default()
        };
        let local = heights.to_local_network().unwrap();
        assert_eq!(local.nu7, Some(BlockHeight::from_u32(2)));
        assert_eq!(local.nu6_3, Some(BlockHeight::from_u32(2)));
    }
}
