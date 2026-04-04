use crate::error::Error;
use zcash_protocol::consensus::Network;

/// Parse a network name string into a [`zcash_protocol::consensus::Network`].
///
/// Accepts `"mainnet"` or `"testnet"`. Defaults to `"testnet"` when `None` is passed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network_mainnet() {
        assert_eq!(parse_network(Some("mainnet")).unwrap(), Network::MainNetwork);
    }

    #[test]
    fn test_parse_network_testnet() {
        assert_eq!(parse_network(Some("testnet")).unwrap(), Network::TestNetwork);
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
}
