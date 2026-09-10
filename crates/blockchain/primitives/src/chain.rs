//! Outbe chain constants and network identification.
//!
//! Native token: COEN (18 decimals), base unit: unit.

/// Canonical Outbe network identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutbeNetwork {
    Devnet,
    Testnet,
    Mainnet,
}

impl OutbeNetwork {
    /// Returns the configured chain id for networks that are already assigned in-tree.
    pub const fn chain_id(self) -> Option<u64> {
        match self {
            Self::Devnet => Some(DEVNET_CHAIN_ID),
            Self::Testnet => Some(TESTNET_CHAIN_ID),
            Self::Mainnet => Some(MAINNET_CHAIN_ID),
        }
    }

    pub const fn chain_name(self) -> &'static str {
        match self {
            Self::Devnet => DEVNET_CHAIN_NAME,
            Self::Testnet => TESTNET_CHAIN_NAME,
            Self::Mainnet => MAINNET_CHAIN_NAME,
        }
    }

    pub const fn is_devnet(self) -> bool {
        matches!(self, Self::Devnet)
    }

    pub const fn is_testnet(self) -> bool {
        matches!(self, Self::Testnet)
    }

    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }
}

/// Chain ID for outbe-devnet-1.
pub const DEVNET_CHAIN_ID: u64 = 424_242;
/// Chain ID for rudis-rehearsal.
pub const TESTNET_CHAIN_ID: u64 = 70_860_602;
/// Chain ID for outbe-mainnet-1.
pub const MAINNET_CHAIN_ID: u64 = 676;

/// Chain name for outbe-devnet-1.
pub const DEVNET_CHAIN_NAME: &str = "outbe-devnet-1";
/// Chain name for rudis-rehearsal.
pub const TESTNET_CHAIN_NAME: &str = "rudis-rehearsal";
/// Chain name for outbe-mainnet-1.
pub const MAINNET_CHAIN_NAME: &str = "outbe-mainnet-1";

/// Default compiled chain ID.
pub const CHAIN_ID: u64 = DEVNET_CHAIN_ID;
/// Default compiled chain name.
pub const CHAIN_NAME: &str = DEVNET_CHAIN_NAME;

/// Resolves a chain id to a known Outbe network.
pub const fn network_for_chain_id(chain_id: u64) -> Option<OutbeNetwork> {
    match chain_id {
        DEVNET_CHAIN_ID => Some(OutbeNetwork::Devnet),
        TESTNET_CHAIN_ID => Some(OutbeNetwork::Testnet),
        MAINNET_CHAIN_ID => Some(OutbeNetwork::Mainnet),
        _ => None,
    }
}

pub const fn is_devnet(chain_id: u64) -> bool {
    match network_for_chain_id(chain_id) {
        Some(network) => network.is_devnet(),
        None => false,
    }
}

pub const fn is_testnet(chain_id: u64) -> bool {
    match network_for_chain_id(chain_id) {
        Some(network) => network.is_testnet(),
        None => false,
    }
}

pub const fn is_mainnet(chain_id: u64) -> bool {
    match network_for_chain_id(chain_id) {
        Some(network) => network.is_mainnet(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_network_identities_are_bijective() {
        let cases = [
            (OutbeNetwork::Devnet, DEVNET_CHAIN_ID, DEVNET_CHAIN_NAME),
            (OutbeNetwork::Testnet, TESTNET_CHAIN_ID, TESTNET_CHAIN_NAME),
            (OutbeNetwork::Mainnet, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME),
        ];

        for (network, chain_id, chain_name) in cases {
            assert_eq!(network.chain_id(), Some(chain_id));
            assert_eq!(network.chain_name(), chain_name);
            assert_eq!(network_for_chain_id(chain_id), Some(network));
            assert_eq!(is_devnet(chain_id), network.is_devnet());
            assert_eq!(is_testnet(chain_id), network.is_testnet());
            assert_eq!(is_mainnet(chain_id), network.is_mainnet());
        }
    }

    #[test]
    fn unknown_chain_id_is_not_an_outbe_network() {
        let unknown = u64::MAX;
        assert_eq!(network_for_chain_id(unknown), None);
        assert!(!is_devnet(unknown));
        assert!(!is_testnet(unknown));
        assert!(!is_mainnet(unknown));
    }

    #[test]
    fn compiled_default_remains_devnet() {
        assert_eq!(CHAIN_ID, DEVNET_CHAIN_ID);
        assert_eq!(CHAIN_NAME, DEVNET_CHAIN_NAME);
    }

    #[test]
    fn rudis_identity_selects_the_testnet_profile() {
        assert_eq!(network_for_chain_id(70_860_602), Some(OutbeNetwork::Testnet));
        assert_eq!(OutbeNetwork::Testnet.chain_name(), "rudis-rehearsal");
        assert_eq!(network_for_chain_id(54_322_345), None);
    }
}
