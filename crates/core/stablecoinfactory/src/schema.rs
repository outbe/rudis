use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::STABLECOIN_FACTORY_ADDRESS;
use outbe_primitives::stablecoin_fork::STABLECOIN_V1_SCHEMA_VERSION;

#[derive(Clone, Debug, PartialEq, Eq)]
#[storage_record(exists_field = exists)]
pub struct ReservationRecord {
    #[key]
    pub proposal_id: U256,

    #[attribute(order = 0)]
    pub exists: bool,

    #[attribute(order = 1)]
    pub token_id: B256,

    #[attribute(order = 2)]
    pub ticker_hash: B256,

    #[attribute(order = 3)]
    pub token: Address,
}

/// Stable V1 layout:
///
/// - slot 0: schema version (`0` is pristine; the first write installs V1);
/// - slots 1..=2: permanent token address set;
/// - slots 3..=5: permanent id/ticker/reverse indexes;
/// - slots 6..=8: pending token-id/ticker/address reservations;
/// - slots 9..=12: proposal reservation record fields.
#[storage_schema]
#[contract(addr = STABLECOIN_FACTORY_ADDRESS)]
pub struct StablecoinFactoryContract {
    #[attribute(order = 0)]
    pub schema_version: outbe_primitives::storage::dsl::Value<u32>,

    #[attribute(order = 1)]
    pub tokens: outbe_primitives::storage::dsl::Set<Address>,

    #[attribute(order = 2)]
    pub token_by_id_index: outbe_primitives::storage::dsl::Map<B256, Address>,

    #[attribute(order = 3)]
    pub token_by_ticker_index: outbe_primitives::storage::dsl::Map<B256, Address>,

    #[attribute(order = 4)]
    pub token_id_of_index: outbe_primitives::storage::dsl::Map<Address, B256>,

    #[attribute(order = 5)]
    pub pending_token_id: outbe_primitives::storage::dsl::Map<B256, U256>,

    #[attribute(order = 6)]
    pub pending_ticker: outbe_primitives::storage::dsl::Map<B256, U256>,

    #[attribute(order = 7)]
    pub pending_address: outbe_primitives::storage::dsl::Map<Address, U256>,

    #[attribute(order = 8)]
    pub reservations: outbe_primitives::storage::dsl::Map<U256, ReservationRecord>,
}

pub(crate) const FACTORY_SCHEMA_VERSION: u32 = STABLECOIN_V1_SCHEMA_VERSION;
