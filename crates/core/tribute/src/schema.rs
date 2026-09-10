use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::WwdEntityId;
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::TRIBUTE_ADDRESS;
use outbe_primitives::time::WorldwideDay;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[storage_record(exists_field = owner)]
pub struct TributeData {
    #[key]
    pub tribute_id: WwdEntityId,

    #[attribute(order = 0)]
    pub owner: Address,

    #[attribute(order = 1)]
    pub worldwide_day: WorldwideDay,

    #[attribute(order = 2)]
    pub issuance_amount_minor: U256,

    #[attribute(order = 3)]
    pub issuance_currency: u16,

    #[attribute(order = 4)]
    pub nominal_amount_minor: U256,

    #[attribute(order = 5)]
    pub reference_currency: u16,

    #[attribute(order = 6)]
    pub tribute_price_minor: U256,

    #[attribute(order = 7, default = false)]
    pub exclude_from_intex_issuance: bool,
}

#[storage_record(exists_field = initialized)]
pub struct DayTotals {
    #[key]
    pub worldwide_day: WorldwideDay,

    #[attribute(order = 0, default = false)]
    pub initialized: bool,

    #[attribute(order = 1, default = 0)]
    pub tribute_count: u32,

    #[attribute(order = 2, default = U256::ZERO)]
    pub tribute_nominal_amount: U256,

    #[attribute(order = 4, default = false)]
    pub is_sealed: bool,
}

/// Bounded, incrementally maintained Tribute inputs used by OCOMP
/// pre-admission. The live accumulator is frozen exactly once after the
/// Tribute WWD and its CE collection have both been sealed.
#[storage_record(exists_field = initialized)]
pub struct DayPreAdmission {
    #[key]
    pub worldwide_day: WorldwideDay,

    #[attribute(order = 0, default = false)]
    pub initialized: bool,

    #[attribute(order = 1, default = false)]
    pub is_sealed: bool,

    #[attribute(order = 2, default = B256::ZERO)]
    pub sealed_collection_root: B256,

    #[attribute(order = 3, default = 0)]
    pub sealed_tribute_count: u32,

    #[attribute(order = 4, default = U256::ZERO)]
    pub sealed_tribute_nominal_amount: U256,

    #[attribute(order = 5, default = 0)]
    pub canonical_body_bytes: u64,

    #[attribute(order = 6, default = 0)]
    pub distinct_owner_count: u32,

    #[attribute(order = 7, default = 0)]
    pub distinct_reference_currency_count: u16,

    /// Certified source generation. A sealed, unconsumed Tribute partition is
    /// generation 0; OCM-20 advances it exactly once on logical retirement.
    /// This is owner state, not an OCOMP reservation.
    #[attribute(order = 9, default = 0)]
    pub source_generation: u64,
}

#[storage_schema]
#[contract(addr = TRIBUTE_ADDRESS)]
pub struct TributeContract {
    #[attribute(order = 0)]
    pub total_supply: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 2)]
    pub day_totals: outbe_primitives::storage::dsl::Map<WorldwideDay, DayTotals>,

    #[attribute(order = 3)]
    pub day_pre_admission: outbe_primitives::storage::dsl::Map<WorldwideDay, DayPreAdmission>,

    #[attribute(order = 5)]
    pub day_reference_currency_refcount: outbe_primitives::storage::dsl::Map<B256, u32>,

    /// Set only by the genesis-bound OCOMP lifecycle. When false, all
    /// historical Tribute mutations keep their pre-activation storage footprint.
    #[attribute(order = 6)]
    pub ocomp_profile_ready: outbe_primitives::storage::dsl::Value<bool>,
}

impl<'storage> TributeContract<'storage> {
    pub(crate) fn storage_handle(&self) -> outbe_primitives::storage::StorageHandle<'storage> {
        self.storage.clone()
    }
}
