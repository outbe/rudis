use alloy_primitives::B256;
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::TRIBUTE_FACTORY_ADDRESS;

/// EVM storage layout for the Tribute Factory contract.
///
/// Tracks used SU (Spending Unit) hashes to prevent replay.
/// TEE configuration is managed off-chain / via system calls.
#[storage_schema]
#[contract(addr = TRIBUTE_FACTORY_ADDRESS)]
pub struct TributeFactoryContract {
    // slot 0: used SU hash marker (suHash -> bool)
    #[attribute(order = 0)]
    pub used_su_hashes: outbe_primitives::storage::dsl::Map<B256, bool>,
}
