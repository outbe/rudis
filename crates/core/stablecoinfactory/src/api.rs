//! Narrow Factory-only mutation surface used by the compile-time Vote adapter.

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::error::Result;
use outbe_primitives::stablecoin::StablecoinCreatePayload;
use outbe_primitives::storage::StorageHandle;

use crate::schema::{ReservationRecord, StablecoinFactoryContract};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryReservation {
    pub proposal_id: U256,
    pub token_id: B256,
    pub ticker: String,
    pub token: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedStablecoinCreate {
    pub payload: StablecoinCreatePayload,
    pub token_id: B256,
    pub token: Address,
}

pub struct StablecoinFactoryApi;

impl StablecoinFactoryApi {
    pub fn validate_create(
        storage: StorageHandle<'_>,
        proposer: Address,
        raw_payload: &[u8],
    ) -> Result<ValidatedStablecoinCreate> {
        StablecoinFactoryContract::new(storage).validate_create(proposer, raw_payload)
    }

    pub fn reserve(storage: StorageHandle<'_>, reservation: &FactoryReservation) -> Result<()> {
        StablecoinFactoryContract::new(storage).reserve(reservation)
    }

    pub fn execute_approved(
        storage: StorageHandle<'_>,
        proposal_id: U256,
        proposer: Address,
        raw_payload: &[u8],
        creation_protocol_version: u64,
    ) -> Result<ValidatedStablecoinCreate> {
        StablecoinFactoryContract::new(storage).execute_approved(
            proposal_id,
            proposer,
            raw_payload,
            creation_protocol_version,
        )
    }

    pub fn release(storage: StorageHandle<'_>, proposal_id: U256) -> Result<ReservationRecord> {
        StablecoinFactoryContract::new(storage).release(proposal_id)
    }

    pub fn consume(storage: StorageHandle<'_>, proposal_id: U256) -> Result<ReservationRecord> {
        StablecoinFactoryContract::new(storage).consume_and_register(proposal_id)
    }

    pub fn token_id_of(storage: StorageHandle<'_>, token: Address) -> Result<Option<B256>> {
        StablecoinFactoryContract::new(storage).registered_token_id(token)
    }
}
