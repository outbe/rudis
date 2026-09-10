//! Validator set data types.
//!
//! These are pure data types shared between consensus internals (DKG manager,
//! application handler, tests) and the engine layer (`outbe-engine`), which
//! owns storage I/O. The engine module `outbe_engine::validators` reads
//! ValidatorSet from Reth state and constructs it for the consensus stack.

use alloy_primitives::{Address, B256};
use commonware_cryptography::bls12381;
use commonware_p2p::Address as CommonwareAddress;

/// Canonical registration proof version used by fresh Outbe networks.
pub const VALIDATOR_REGISTRATION_VERSION: u8 = 2;

/// BLS MinPk domain separation tag for ValidatorSet registration proofs.
pub const VALIDATOR_REGISTRATION_DST: &[u8] = b"OUTBE_VALIDATOR_REGISTRATION_V2";

/// Canonical message signed by a validator's individual BLS key when registering.
///
/// The fixed-width preimage binds the proof to its format version, Outbe chain,
/// validator address, and immutable Radicle transport identity.
pub fn validator_registration_message(
    chain_id: u64,
    validator: Address,
    radicle_node_id: B256,
) -> [u8; 61] {
    let mut message = [0_u8; 61];
    message[0] = VALIDATOR_REGISTRATION_VERSION;
    message[1..9].copy_from_slice(&chain_id.to_be_bytes());
    message[9..29].copy_from_slice(validator.as_slice());
    message[29..61].copy_from_slice(radicle_node_id.as_slice());
    message
}

/// Consensus cap for canonical TEE-expiry exclusions carried by one DKG
/// boundary. This equals the protocol validator cap and is enforced before any
/// artifact is constructed or decoded.
pub const MAX_TEE_EXPIRED_TARGET_EXCLUSIONS: usize = 256;

/// Loaded validator set.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Ordered list of BLS MinPk public keys (determines participant indices).
    pub public_keys: Vec<bls12381::PublicKey>,
    /// Corresponding Ethereum addresses (same order as public_keys).
    pub addresses: Vec<Address>,
    /// P2P addresses for each validator (same order).
    pub p2p_addresses: Vec<ValidatorP2pAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorP2pAddress {
    /// No registry address exists; static bootstrap may fill this gap.
    Missing,
    /// Registry contained an invalid address; exclude this peer and do not
    /// substitute static/bootstrap target addresses.
    Invalid,
    /// Valid decoded Commonware target address.
    Known(CommonwareAddress),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    #[test]
    fn validator_registration_v2_preimage_is_exact_and_node_id_bound() {
        let validator = address!("0x11223344556677889900aabbccddeeff00112233");
        let node_id = b256!("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let message = validator_registration_message(0x0102030405060708, validator, node_id);

        assert_eq!(message.len(), 61);
        assert_eq!(message[0], VALIDATOR_REGISTRATION_VERSION);
        assert_eq!(&message[1..9], &0x0102030405060708_u64.to_be_bytes());
        assert_eq!(&message[9..29], validator.as_slice());
        assert_eq!(&message[29..61], node_id.as_slice());
        assert_eq!(
            VALIDATOR_REGISTRATION_DST,
            b"OUTBE_VALIDATOR_REGISTRATION_V2"
        );
    }

    #[test]
    fn validator_registration_v2_changes_when_node_id_changes() {
        let validator = Address::repeat_byte(0x42);
        let first = validator_registration_message(7, validator, B256::repeat_byte(0x11));
        let second = validator_registration_message(7, validator, B256::repeat_byte(0x12));

        assert_ne!(first, second);
    }
}
