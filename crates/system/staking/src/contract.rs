use alloy_primitives::{Address, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot};

/// EVM storage layout for the Staking contract.
///
/// Tracks validator stake amounts, total staked, and the unbonding queue.
/// The unbonding queue uses a flat array pattern keyed by index (u32).
#[contract(addr = STAKING_ADDRESS)]
pub struct Staking {
    // slot 0: minimum stake required to be an active validator
    pub config_min_stake: Slot<U256>,
    // slot 1: unbonding period in seconds
    pub config_unbonding_period: Slot<u64>,
    // slot 2: maximum stake percent of total staked (e.g. 5 = 5%)
    pub config_max_stake_percent: Slot<u64>,
    // slot 3: mapping(validator address => staked amount)
    pub stake_amount: Mapping<Address, U256>,
    // slot 4: total amount staked across all validators
    pub total_staked: Slot<U256>,
    // slot 5: number of unbonding queue entries (ever-incrementing tail pointer)
    pub unbonding_count: Slot<u32>,
    // slot 6: mapping(index => validator address) for unbonding queue
    pub unbonding_validator: Mapping<u32, Address>,
    // slot 7: mapping(index => unbonding amount) for unbonding queue
    pub unbonding_amount: Mapping<u32, U256>,
    // slot 8: mapping(index => complete timestamp) for unbonding queue
    pub unbonding_complete_time: Mapping<u32, u64>,
    // slot 9: per-validator linked list head - stored as idx+1 (0 = empty)
    pub per_val_unbonding_head: Mapping<Address, u32>,
    // slot 10: next pointer for unbonding linked list - stored as idx+1 (0 = end)
    pub unbonding_next: Mapping<u32, u32>,
    // slot 11: withdrawability delay for slashed validators. 0 = default to 2x unbonding_period.
    pub config_slashed_withdrawal_delay: Slot<u64>,
}
