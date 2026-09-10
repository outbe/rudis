// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IStaking
/// @notice Staking precompile at 0x000000000000000000000000000000000000EE02
interface IStaking {
    /// Bond `amount` to `validatorAddress` (caller = the validator; third-party
    /// delegation is rejected). The call must carry `msg.value == amount`: the
    /// EVM moves the stake into the precompile account and the implementation
    /// credits that transfer instead of performing a second one.
    function stake(address validatorAddress, uint256 amount) external payable;
    function unstake(uint256 amount) external;
    function claimUnbonded() external;
    /// Unjail a JAILED validator (caller = the validator). Requires the caller's
    /// bonded stake >= min_stake; moves it JAILED -> PENDING. After this, call
    /// IValidatorSet.confirmValidatorReady() and the next DKG reshare promotes it
    /// to ACTIVE.
    function unjailValidator() external;
    function getStake(address validator) external view returns (uint256);
    function getTotalStaked() external view returns (uint256);
}
