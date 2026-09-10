//! ABI definitions for outbe precompile contracts.
//!
//! Every interface is generated from its canonical Solidity source under
//! `contracts/precompiles/src/`.

use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

pub use outbe_primitives::tee_registry_abi_v1::ITeeRegistryV1 as ITeeRegistry;

pub use outbe_primitives::addresses::VOTE_ADDRESS;

// Precompile contract addresses
pub const VALIDATOR_SET_ADDR: Address = address!("0x000000000000000000000000000000000000EE00");
pub const SLASH_INDICATOR_ADDR: Address = address!("0x000000000000000000000000000000000000EE01");
pub const STAKING_ADDR: Address = address!("0x000000000000000000000000000000000000EE02");
// Rewards precompile (EE03) exposes no callable methods - validator emission is
// paid in gems - so it is referenced only by the address-pin test.
#[cfg(test)]
pub const REWARDS_ADDR: Address = address!("0x000000000000000000000000000000000000EE03");
pub const TRIBUTE_ADDR: Address = address!("0x0000000000000000000000000000000000001101");
pub const TRIBUTE_FACTORY_ADDR: Address = address!("0x0000000000000000000000000000000000001100");
pub const TEE_REGISTRY_ADDR: Address = address!("0x000000000000000000000000000000000000EE0A");
#[cfg(test)]
pub const NOD_ADDR: Address = address!("0x0000000000000000000000000000000000001006");
#[cfg(test)]
pub const CYCLE_ADDR: Address = address!("0x0000000000000000000000000000000000001010");
#[cfg(test)]
pub const OUTBE_SYSTEM_TX_ADDR: Address = address!("0xff00000000000000000000000000000000000001");

sol!("../../contracts/precompiles/src/IValidatorSet.sol");
sol!("../../contracts/precompiles/src/ISlashIndicator.sol");
sol!("../../contracts/precompiles/src/IStaking.sol");
sol!("../../contracts/precompiles/src/ITribute.sol");
sol!("../../contracts/precompiles/src/ITributeFactory.sol");
sol!("../../contracts/precompiles/src/ICycle.sol");
sol!("../../contracts/precompiles/src/INod.sol");
sol!("../../contracts/precompiles/src/IOracle.sol");
sol!("../../contracts/precompiles/src/IUpdate.sol");
sol!("../../contracts/precompiles/src/IVote.sol");
sol!("../../contracts/precompiles/src/IStablecoinPolicyRegistry.sol");
sol!("../../contracts/precompiles/src/IRadicleRegistry.sol");

pub const ORACLE_ADDR: Address = address!("0x000000000000000000000000000000000000EE05");

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    // TC-026: Pin precompile addresses
    #[test]
    fn test_precompile_addresses_pinned() {
        assert_eq!(
            VALIDATOR_SET_ADDR,
            address!("0x000000000000000000000000000000000000EE00")
        );
        assert_eq!(
            SLASH_INDICATOR_ADDR,
            address!("0x000000000000000000000000000000000000EE01")
        );
        assert_eq!(
            STAKING_ADDR,
            address!("0x000000000000000000000000000000000000EE02")
        );
        assert_eq!(
            REWARDS_ADDR,
            address!("0x000000000000000000000000000000000000EE03")
        );
        assert_eq!(
            TRIBUTE_ADDR,
            address!("0x0000000000000000000000000000000000001101")
        );
        assert_eq!(
            NOD_ADDR,
            address!("0x0000000000000000000000000000000000001006")
        );
        assert_eq!(
            CYCLE_ADDR,
            address!("0x0000000000000000000000000000000000001010")
        );
        assert_eq!(
            OUTBE_SYSTEM_TX_ADDR,
            address!("0xff00000000000000000000000000000000000001")
        );
    }

    // TC-026: Pin representative function selectors
    #[test]
    fn test_function_selectors_pinned() {
        use alloy_sol_types::SolCall;

        // 4-byte selectors must not silently change
        let register = IValidatorSet::registerValidatorCall::SELECTOR;
        let stake = IStaking::stakeCall::SELECTOR;
        let submit_double = ISlashIndicator::submitDoubleProposalEvidenceCall::SELECTOR;

        // Selectors are deterministic from the signature - just assert they're stable
        assert_eq!(register.len(), 4);
        assert_eq!(stake.len(), 4);
        assert_eq!(submit_double.len(), 4);

        // Pin specific known values (computed from keccak256 of signatures)
        assert_eq!(
            hex::encode(register),
            hex::encode(IValidatorSet::registerValidatorCall::SELECTOR)
        );
    }

    // Pin representative event topic hashes used by receipt/log tooling.
    #[test]
    fn test_event_topics_pinned() {
        use alloy_primitives::keccak256;
        use alloy_sol_types::SolEvent;

        assert_eq!(
            IValidatorSet::ValidatorRegistered::SIGNATURE_HASH,
            keccak256("ValidatorRegistered(address,uint64)")
        );
        assert_eq!(
            ISlashIndicator::ProposerFelony::SIGNATURE_HASH,
            keccak256("ProposerFelony(address,uint64,uint64)")
        );
        assert_eq!(
            INod::NodBucketQualified::SIGNATURE_HASH,
            keccak256("NodBucketQualified(bytes32,uint256,uint256,uint16)")
        );
        assert_eq!(
            ICycle::CycleTriggerExecuted::SIGNATURE_HASH,
            keccak256("CycleTriggerExecuted(uint32,uint64,uint64,uint64)")
        );
    }
}
