use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall, SolInterface};
use outbe_primitives::dispatch::{
    dispatch_call, metadata, mutate_void, mutate_void_payable, reject_value_unless_payable, view,
};
use outbe_primitives::error::Result;

use crate::contract::Staking;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[IStaking::stakeCall::SELECTOR];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IStaking.sol"
);

/// Dispatches an ABI-encoded call to the Staking precompile.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    // Staking is a payable route, so the boundary credits value to this
    // address; every selector the module has not published refuses it here.
    reject_value_unless_payable(data, PAYABLE_SELECTORS, &value)?;
    dispatch_call(data, IStaking::IStakingCalls::abi_decode, |call| {
        let mut staking = Staking::new(storage);
        use IStaking::IStakingCalls::*;
        match call {
            stake(c) => {
                mutate_void_payable(c, PAYABLE_SELECTORS, caller, value, |sender, c, val| {
                    if val != c.amount {
                        return Err(outbe_primitives::error::PrecompileError::Revert(
                            "msg.value must equal stake amount".into(),
                        ));
                    }
                    staking.stake(sender, c.validatorAddress, c.amount)
                })
            }
            unstake(c) => mutate_void(c, caller, |sender, c| staking.unstake(sender, c.amount)),
            claimUnbonded(c) => mutate_void(c, caller, |sender, _c| staking.claim_unbonded(sender)),
            unjailValidator(c) => {
                mutate_void(c, caller, |sender, _c| staking.unjail_validator(sender))
            }
            getStake(c) => view(c, |c| staking.get_stake(c.validator)),
            getTotalStaked(_) => {
                metadata::<IStaking::getTotalStakedCall>(|| staking.get_total_staked())
            }
        }
    })
}
