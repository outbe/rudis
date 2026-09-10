use alloy_primitives::{B256, U256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::{
    addresses::OCOMP_REGISTRY_ADDRESS,
    storage::types::{Mapping, StorageBytes},
};

/// Consensus storage owned exclusively by the OCOMP protocol registry.
#[storage_schema]
#[contract(addr = OCOMP_REGISTRY_ADDRESS)]
pub struct OcompRegistry {
    #[attribute(order = 0)]
    pub active_request_profile: StorageBytes,
    #[attribute(order = 1)]
    pub active_protocol_bundle: StorageBytes,
    #[attribute(order = 2)]
    pub active_protocol_bundle_hash: outbe_primitives::storage::dsl::Value<B256>,
    #[attribute(order = 3)]
    pub install_hash: outbe_primitives::storage::dsl::Value<B256>,
    #[attribute(order = 4)]
    pub activation_height: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 5)]
    pub staged_successor: StorageBytes,
    #[attribute(order = 6)]
    pub staged_proposal_id: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 7)]
    pub retiring_authority: StorageBytes,
    #[attribute(order = 8)]
    pub lineage_bundle: Mapping<B256, B256>,
    #[attribute(order = 9)]
    pub live_lineage_count: Mapping<B256, u32>,
    #[attribute(order = 10)]
    pub retention_until: Mapping<B256, u64>,
}
