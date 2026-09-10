// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// Agent-reward distribution surface. A claim issues the reward as a Gem:
/// the WAA pool issues a Wallet Gem, the SRA pool an Sra Gem. The Rust dispatch is
/// synthesized at compile time from `#[contract_public(...)]` annotations
/// in `crates/core/agentreward/src/precompile.rs` (the `#[contract_dispatch]`
/// macro pilot). The drift test in that crate keeps the two in sync.
interface IAgentReward {
    function getClaimableBalance(address account) external view returns (uint256);
    function getPoolClaimableBalance(address account, uint8 pool) external view returns (uint256);
    /// @notice Issues `amount` of the caller's balance in `pool` (0 = WAA, 1 = SRA)
    /// as a Gem; `amount` of zero claims the whole pool balance. What is left
    /// keeps accruing and cannot be forfeited, so sizing the claim is the
    /// caller's own risk control.
    /// @return gemId the Gem issued for the caller.
    function claimReward(uint8 pool, uint256 amount) external returns (uint256 gemId);
}
