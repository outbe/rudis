//! Protocol constants for upgrade scheduling and activation.
//!
//! All values are `const` and change only via hardfork.

/// Minimum blocks between vote approval and activation height.
pub const MIN_ACTIVATION_BUFFER: u64 = 100;

/// Activation buffer for `chain_id`. Zero on the localnet chain so e2e updates
/// activate promptly; the standard [`MIN_ACTIVATION_BUFFER`] everywhere else.
/// Mirrors how `outbe_vote` shortens the voting window for localnet - but
/// keyed purely on the chain id, with no env/config override.
pub fn min_activation_buffer(chain_id: u64) -> u64 {
    if chain_id == outbe_primitives::chain::TESTNET_CHAIN_ID {
        0
    } else {
        MIN_ACTIVATION_BUFFER
    }
}

/// Maximum scheduled updates waiting for activation height.
pub const MAX_WAITING_FOR_ACTIVATION_UPDATES: u32 = 64;

/// Current binary protocol version.
pub const PROTOCOL_VERSION: crate::ProtocolVersion =
    crate::encode_protocol_version(PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);

/// Max version that may be activated on `chain_id`.
///
/// Every network is strict: an update can activate only after the operator has
/// installed a binary whose own protocol version supports it.
pub fn max_activatable_version(_chain_id: u64) -> crate::ProtocolVersion {
    PROTOCOL_VERSION
}

/// Bits reserved for the minor part of an on-chain protocol version.
pub(crate) const PROTOCOL_VERSION_MINOR_BITS: u32 = 24;

/// Maximum minor value in the `u8 major + u24 minor` protocol version encoding.
pub(crate) const MAX_PROTOCOL_VERSION_MINOR: u32 = (1u32 << PROTOCOL_VERSION_MINOR_BITS) - 1;

/// Protocol version embedded into this crate at compile time.
pub(crate) const PROTOCOL_VERSION_MAJOR: u8 =
    crate::version::parse_protocol_version_major_component(env!("CARGO_PKG_VERSION_MAJOR"));
pub(crate) const PROTOCOL_VERSION_MINOR: u32 =
    crate::version::parse_protocol_version_minor_component(env!("CARGO_PKG_VERSION_MINOR"));

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_primitives::chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};

    #[test]
    fn every_network_is_strictly_capped_to_the_binary_version() {
        for chain_id in [DEVNET_CHAIN_ID, TESTNET_CHAIN_ID, MAINNET_CHAIN_ID] {
            assert_eq!(max_activatable_version(chain_id), PROTOCOL_VERSION);
        }
    }

    #[test]
    fn only_testnet_skips_the_activation_buffer() {
        assert_eq!(min_activation_buffer(TESTNET_CHAIN_ID), 0);
        for chain_id in [DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, 1_000_000_001] {
            assert_eq!(min_activation_buffer(chain_id), MIN_ACTIVATION_BUFFER);
        }
    }
}
