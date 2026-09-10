use alloy_primitives::{Address, U256};
#[allow(unused_imports)]
use outbe_macros::{contract_dispatch, contract_public, contract_view};
use outbe_primitives::error::Result;

use crate::schema::{AgentRewardContract, RewardPool};

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// ABI surface for the AgentReward precompile.
///
/// Each method is annotated with `#[contract_public("<Solidity signature>")]`.
/// `#[contract_dispatch]` collects them, emits a private `sol!` interface,
/// and synthesizes `pub fn dispatch(storage, data, caller, value) -> Result<Bytes>`.
#[contract_dispatch]
impl AgentRewardContract<'_> {
    #[contract_public("getClaimableBalance(address) view returns (uint256)")]
    #[contract_view]
    fn _abi_get_claimable_balance(&mut self, account: Address) -> Result<U256> {
        self.get_claimable_reward(account)
    }

    #[contract_public("getPoolClaimableBalance(address,uint8) view returns (uint256)")]
    #[contract_view]
    fn _abi_get_pool_claimable_balance(&mut self, account: Address, pool: u8) -> Result<U256> {
        self.get_pool_claimable_reward(RewardPool::from_abi(pool)?, account)
    }

    #[contract_public("claimReward(uint8,uint256) returns (uint256)")]
    fn _abi_claim_reward(&mut self, sender: Address, pool: u8, amount: U256) -> Result<U256> {
        let pool = RewardPool::from_abi(pool)?;
        // amount = 0 means claim the whole pool balance, and nothing to claim is
        // then a no-op rather than a failure - the pre-Gem claim behaved the same
        // way.
        if amount.is_zero() && self.get_pool_claimable_reward(pool, sender)?.is_zero() {
            return Ok(U256::ZERO);
        }
        self.claim_reward(pool, sender, amount)
    }
}
