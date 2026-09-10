//! Canonical proof-backed materialization of certified NOD generations.

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolError, SolEvent};
use outbe_chain_constants::NodMaterializationProfileV1;
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_nod::{NodContract, NodIssueParams};
use outbe_ocomp_protocol::{
    nod_materialization::{
        verify_nod_materialization_batch, NodMaterializationBatchV1, NodMaterializationHeadV1,
    },
    SchemaLimits,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::NOD_FACTORY_ADDRESS,
    error::{PrecompileError, Result},
    storage::StorageHandle,
};
use outbe_validatorset::delegation::ValidatorDelegateRole;

use crate::{errors::NodFactoryError, precompile::INodFactory, runtime};

/// Stable typed rejection codes used by the system-carrier failure boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NodMaterializationRejectionV1 {
    StaleQueueSequence = 1,
    StaleCursor = 2,
    AttemptLimit = 3,
    InvalidBatchShape = 4,
    InvalidProof = 5,
    DuplicateNod = 6,
    UnauthorizedSigner = 7,
}

/// Receipt-like local result of one successfully committed materialization batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodMaterializationOutcomeV1 {
    pub queue_sequence: u64,
    pub worldwide_day: u32,
    pub first_nod_ordinal: u32,
    pub next_nod_ordinal: u32,
    pub completed: bool,
}

/// Canonical ABI revert bytes for one typed materialization rejection.
#[must_use]
pub fn materialization_revert_data(rejection: NodMaterializationRejectionV1) -> Bytes {
    Bytes::from(
        INodFactory::NodMaterializationRejected {
            code: rejection as u8,
        }
        .abi_encode(),
    )
}

/// True only for the six race/proof failures that may become status-zero
/// system-carrier receipts without invalidating the surrounding block.
#[must_use]
pub fn is_soft_materialization_revert_data(data: &[u8]) -> bool {
    [
        NodMaterializationRejectionV1::StaleQueueSequence,
        NodMaterializationRejectionV1::StaleCursor,
        NodMaterializationRejectionV1::AttemptLimit,
        NodMaterializationRejectionV1::InvalidBatchShape,
        NodMaterializationRejectionV1::InvalidProof,
        NodMaterializationRejectionV1::DuplicateNod,
    ]
    .into_iter()
    .any(|rejection| data == materialization_revert_data(rejection).as_ref())
}

/// Maps the public handler's stable string errors onto typed ABI reverts.
pub(crate) fn typed_materialization_error(error: PrecompileError) -> PrecompileError {
    let PrecompileError::Revert(reason) = error else {
        return error;
    };
    let rejection = if reason == NodFactoryError::UnauthorizedMaterializer.to_string() {
        NodMaterializationRejectionV1::UnauthorizedSigner
    } else if reason == NodFactoryError::MaterializationAttemptLimit.to_string() {
        NodMaterializationRejectionV1::AttemptLimit
    } else if reason == NodFactoryError::StaleMaterializationQueue.to_string() {
        NodMaterializationRejectionV1::StaleQueueSequence
    } else if reason == NodFactoryError::StaleMaterializationCursor.to_string() {
        NodMaterializationRejectionV1::StaleCursor
    } else if reason == NodFactoryError::InvalidMaterializationBatchShape.to_string() {
        NodMaterializationRejectionV1::InvalidBatchShape
    } else if reason == NodFactoryError::InvalidMaterializationProof.to_string() {
        NodMaterializationRejectionV1::InvalidProof
    } else if reason == NodFactoryError::DuplicateMaterializedNod.to_string() {
        NodMaterializationRejectionV1::DuplicateNod
    } else {
        return PrecompileError::Revert(reason);
    };
    PrecompileError::RevertBytes(materialization_revert_data(rejection))
}

/// Repeats current ACTIVE OCOMP-role authorization at the execution owner.
pub fn authorize_materializer(storage: StorageHandle<'_>, caller: Address) -> Result<()> {
    let authorized = outbe_validatorset::contract::ValidatorSet::new(storage)
        .resolve_validator_for_role(caller, ValidatorDelegateRole::Ocomp)?
        .is_some();
    if !authorized {
        return Err(NodFactoryError::UnauthorizedMaterializer.into());
    }
    Ok(())
}

/// Consumes the canonical per-block allowance before proof work.
pub fn consume_materialization_attempt(
    storage: &StorageHandle<'_>,
    profile: NodMaterializationProfileV1,
) -> Result<()> {
    let block_height = storage.block_number()?;
    let nod = NodContract::new(storage.clone());
    let stored_height = nod.ocomp_materialization_attempt_height.read()?;
    let stored_count = nod.ocomp_materialization_attempt_count.read()?;
    let next_count = if stored_height == block_height {
        stored_count.checked_add(1).ok_or_else(|| {
            PrecompileError::Fatal("Nod materialization attempt counter overflow".into())
        })?
    } else {
        1
    };
    if next_count > profile.max_attempts_per_block {
        return Err(NodFactoryError::MaterializationAttemptLimit.into());
    }
    nod.ocomp_materialization_attempt_height
        .write(block_height)?;
    nod.ocomp_materialization_attempt_count.write(next_count)
}

/// Applies one already-authorized canonical batch atomically.
pub fn materialize_certified_nods_authorized(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    batch: &NodMaterializationBatchV1,
    profile: NodMaterializationProfileV1,
    limits: &SchemaLimits,
) -> Result<NodMaterializationOutcomeV1> {
    storage.clone().with_checkpoint(|| {
        consume_materialization_attempt(storage, profile)?;
        materialize_after_attempt(storage, scope, parent, batch, profile, limits)
    })
}

pub(crate) fn materialize_after_attempt(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    batch: &NodMaterializationBatchV1,
    profile: NodMaterializationProfileV1,
    limits: &SchemaLimits,
) -> Result<NodMaterializationOutcomeV1> {
    let nod = NodContract::new(storage.clone());
    let head = nod
        .ocomp_materialization_head()?
        .ok_or(NodFactoryError::StaleMaterializationQueue)?;
    if batch.queue_sequence != head.queue_sequence {
        return Err(NodFactoryError::StaleMaterializationQueue.into());
    }
    if batch.first_nod_ordinal != head.next_nod_ordinal {
        return Err(NodFactoryError::StaleMaterializationCursor.into());
    }
    let verified =
        verify_nod_materialization_batch(batch, &head, profile.batch_subtree_height, limits)
            .map_err(|_| PrecompileError::from(NodFactoryError::InvalidMaterializationProof))?;

    let worldwide_day = WorldwideDay::new(head.worldwide_day);
    for action in verified.actions() {
        let derived_nod_id = NodContract::generate_nod_id(action.owner, worldwide_day)?;
        let supplied_nod_id = WwdEntityId::try_from(action.nod_id.0.as_slice())
            .map_err(|_| PrecompileError::from(NodFactoryError::InvalidMaterializationProof))?;
        let derived_bucket_key = NodContract::bucket_key(
            worldwide_day,
            action.floor_price_minor,
            action.reference_currency,
        );
        if supplied_nod_id != derived_nod_id || action.bucket_key != derived_bucket_key {
            return Err(NodFactoryError::InvalidMaterializationProof.into());
        }
    }

    for action in verified.actions() {
        let params = NodIssueParams {
            owner: action.owner,
            worldwide_day,
            league_id: action.league_id,
            floor_price_minor: action.floor_price_minor,
            gratis_load_minor: action.gratis_load_minor,
            entry_price_minor: action.entry_price_minor,
            issuance_currency: action.issuance_currency,
            reference_currency: action.reference_currency,
        };
        if let Err(error) = runtime::issue_nod(storage, scope, parent, &params) {
            if matches!(
                &error,
                PrecompileError::Revert(reason)
                    if reason == &NodFactoryError::NodAlreadyExists.to_string()
            ) {
                return Err(NodFactoryError::DuplicateMaterializedNod.into());
            }
            return Err(error);
        }
    }

    let action_count = u32::try_from(verified.actions().len()).map_err(|_| {
        PrecompileError::Fatal("Nod materialization action count does not fit u32".into())
    })?;
    let next_nod_ordinal = head
        .next_nod_ordinal
        .checked_add(action_count)
        .ok_or_else(|| PrecompileError::Fatal("Nod materialization cursor overflow".into()))?;
    if next_nod_ordinal > head.nod_count {
        return Err(PrecompileError::Fatal(
            "Nod materialization cursor exceeds certified count".into(),
        ));
    }
    let block_number = storage.block_number()?;
    let completed = next_nod_ordinal == head.nod_count;
    if completed {
        let stored_head = nod.ocomp_materialization_head_sequence.read()?;
        let stored_tail = nod.ocomp_materialization_tail_sequence.read()?;
        if stored_head != head.queue_sequence || stored_head >= stored_tail {
            return Err(PrecompileError::Fatal(
                "Nod materialization FIFO changed during execution".into(),
            ));
        }
        let next_head = stored_head.checked_add(1).ok_or_else(|| {
            PrecompileError::Fatal("Nod materialization FIFO head overflow".into())
        })?;
        nod.ocomp_materialization_queue_wwd
            .write(&stored_head, WorldwideDay::new(0))?;
        nod.ocomp_materialization_head_sequence.write(next_head)?;
        nod.clear_ocomp_certified_generation(worldwide_day)?;
    } else {
        nod.ocomp_materialization_next_nod_ordinal
            .write(&worldwide_day, next_nod_ordinal)?;
        nod.ocomp_materialization_last_progress_height
            .write(&worldwide_day, block_number)?;
    }

    storage.emit_event(
        NOD_FACTORY_ADDRESS,
        INodFactory::NodMaterializationProgress {
            queueSequence: head.queue_sequence,
            worldwideDay: head.worldwide_day,
            generation: head.generation,
            firstNodOrdinal: head.next_nod_ordinal,
            nextNodOrdinal: next_nod_ordinal,
            completed,
            blockNumber: block_number,
        }
        .encode_log_data(),
    )?;

    Ok(NodMaterializationOutcomeV1 {
        queue_sequence: head.queue_sequence,
        worldwide_day: head.worldwide_day,
        first_nod_ordinal: head.next_nod_ordinal,
        next_nod_ordinal,
        completed,
    })
}

/// Encodes the exact current public head response.
pub fn encode_materialization_head(
    head: Option<NodMaterializationHeadV1>,
    limits: &SchemaLimits,
) -> Result<(bool, Bytes)> {
    match head {
        Some(head) => head
            .encode_canonical(limits)
            .map(|bytes| (true, bytes.into()))
            .map_err(|error| {
                PrecompileError::Fatal(format!("encode Nod materialization head: {error}"))
            }),
        None => Ok((false, Bytes::new())),
    }
}
