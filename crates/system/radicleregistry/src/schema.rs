use alloy_primitives::{Address, B256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::RADICLE_REGISTRY_ADDRESS;

/// Consensus storage layout for the V1 Radicle repository registry.
///
/// Slots:
/// 0 repository_count; 1 repository_by_index; 2 repository_index (index + 1);
/// 3 repository_registrant; 4 registry_generation; 5 config_max_repositories.
#[storage_schema]
#[contract(addr = RADICLE_REGISTRY_ADDRESS)]
pub struct RadicleRegistry {
    #[attribute(order = 0)]
    pub repository_count: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 1)]
    pub repository_by_index: outbe_primitives::storage::dsl::Map<u32, B256>,
    #[attribute(order = 2)]
    pub repository_index: outbe_primitives::storage::dsl::Map<B256, u32>,
    #[attribute(order = 3)]
    pub repository_registrant: outbe_primitives::storage::dsl::Map<B256, Address>,
    #[attribute(order = 4)]
    pub registry_generation: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 5)]
    pub config_max_repositories: outbe_primitives::storage::dsl::Value<u32>,
}
