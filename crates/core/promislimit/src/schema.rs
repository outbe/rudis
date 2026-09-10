use alloy_primitives::U256;
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::PROMIS_LIMIT_ADDRESS;

#[storage_schema]
#[contract(addr = PROMIS_LIMIT_ADDRESS)]
pub struct PromisLimitContract {
    #[attribute(order = 0)]
    pub total_unallocated: outbe_primitives::storage::dsl::Value<U256>,
}
