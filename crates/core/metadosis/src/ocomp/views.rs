use alloy_primitives::B256;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    error::Result,
    storage::{dsl::missing_record_err, StorageHandle},
};

use crate::schema::MetadosisContract;

use super::schema::poc_schema_limits;

/// Returns one complete canonical OCB1 job record through the existing
/// Metadosis public precompile.
pub fn get_offchain_job(storage: StorageHandle<'_>, intent_id: B256) -> Result<Vec<u8>> {
    let limits = poc_schema_limits();
    let record = MetadosisContract::new(storage)
        .ocomp_job_record(intent_id, &limits)?
        .ok_or_else(|| missing_record_err("OcompJobRecordV1"))?;
    record
        .encode_canonical(&limits)
        .map_err(|error| crate::errors::storage_corruption(error.to_string()))
}

/// Returns the complete bounded vote/accountability record selected
/// by consensus for one finalized JobId.
pub fn get_offchain_vote_accountability(
    storage: StorageHandle<'_>,
    job_id: B256,
) -> Result<Vec<u8>> {
    let limits = poc_schema_limits();
    let accountability = MetadosisContract::new(storage)
        .result_vote_accountability(job_id, &limits)?
        .ok_or_else(|| missing_record_err("OcompVoteAccountabilityV1"))?;
    accountability
        .encode_canonical(&limits)
        .map_err(|error| crate::errors::storage_corruption(error.to_string()))
}

/// Returns the canonical active generation selected by completed Metadosis
/// state, never by supervisor-local storage.
pub fn get_active_lysis_generation(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<Vec<u8>> {
    let limits = poc_schema_limits();
    let generation = MetadosisContract::new(storage)
        .active_lysis_generation(wwd, &limits)?
        .ok_or_else(|| missing_record_err("ActiveGenerationV1"))?;
    generation
        .encode_canonical(&limits)
        .map_err(|error| crate::errors::storage_corruption(error.to_string()))
}

/// Returns the aggregate receipt embedded in a completed or certified-conflict
/// job record.
pub fn get_lysis_terminal_receipt(storage: StorageHandle<'_>, intent_id: B256) -> Result<Vec<u8>> {
    let limits = poc_schema_limits();
    let record = MetadosisContract::new(storage)
        .ocomp_job_record(intent_id, &limits)?
        .ok_or_else(|| missing_record_err("OcompJobRecordV1"))?;
    let receipt = record
        .terminal
        .and_then(|terminal| terminal.completed_binding)
        .map(|binding| binding.terminal_receipt)
        .ok_or_else(|| missing_record_err("AggregateActivationReceiptV1"))?;
    receipt
        .encode_canonical(&limits)
        .map_err(|error| crate::errors::storage_corruption(error.to_string()))
}
