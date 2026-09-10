//! Backend-neutral finalized-receipt projection for Outbe off-chain data.
//!
//! This crate deliberately knows nothing about Reth or MongoDB. A node adapter
//! normalizes finalized blocks into [`FinalizedBlock`], while the projector
//! consumes only the shared off-chain storage capabilities.

mod runtime_readers;

pub use outbe_primitives::projection::{
    projection_readiness, ProjectionCheckpoint, ProjectionFailure, ProjectionFailureClass,
    ProjectionReadinessHandle, ProjectionReadinessPublisher, ProjectionStatus, WaitOutcome,
};
pub use runtime_readers::{ExecutionReadBudgetGuard, RuntimeBodyFailure, RuntimeBodyReaders};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, LowerHex},
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::{Address, LogData, B256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    body_commitment, decode_nod_bucket_v1, decode_nod_item_v1, decode_tribute_v1,
    derive_poseidon_entity_id, encode_nod_bucket_v1, encode_nod_item_v1, encode_tribute_v1,
    IdPageRequest, StoredBody, WwdEntityId, ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
    MAX_ID_PAGE_LIMIT,
};
use outbe_nod::{
    precompile::INod, projection::NOD_PROJECTION_NAMESPACES, NodBucketState, NodItemState,
    NodRepositoryError, NodRepositoryReader,
};
use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanRequest, StorageError,
    StorageMetadata, StorageReaderHandle, StorageWriterHandle, StoredValue, Value,
};
use outbe_primitives::addresses::{NOD_ADDRESS, TRIBUTE_ADDRESS};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{
    precompile::ITribute, projection::TRIBUTE_PROJECTION_NAMESPACES, RetainedTributePin,
    RetainedTributeReader, TributeData, TributeRepositoryError, TributeRepositoryReader,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Local representation version owned by this projector.
///
/// Version 2 adds the job-scoped retained Tribute body and day-index
/// namespaces. Version 1 nodes must fail closed instead of silently ignoring
/// those records during OCOMP retention and release.
pub const STORAGE_SCHEMA_VERSION: u32 = 2;
/// Namespace containing the singleton projector state.
pub const PROJECTION_STATE_NAMESPACE: &str = "projection_state";
/// Singleton projector-state key.
pub const PROJECTION_STATE_KEY: &[u8] = b"offchain_data";

const SOURCE_KEYS: [&str; 7] = [
    "block_number",
    "block_hash",
    "tx_hash",
    "transaction_index",
    "log_index",
    "emitter",
    "event_signature",
];

/// Network identity and the first block that must be projected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionConfig {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub start_block: u64,
}

/// Node-owned, read-only selector for the one active PoC retention pin.
///
/// The projector supplies the partition day discovered from the finalized
/// Tribute event. Callers cannot pass a pin through [`FinalizedBlock`].
pub trait TributeRetentionSelector: Send + Sync {
    fn active_pin_for(
        &self,
        worldwide_day: WorldwideDay,
    ) -> Result<Option<RetainedTributePin>, String>;
}

/// Portable projector identity and progress persisted beside domain data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionState {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub storage_schema_version: u32,
    pub start_block: u64,
    pub checkpoint: Option<ProjectionCheckpoint>,
}

/// Typed provenance attached to a projected primary body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionSource {
    pub block_number: u64,
    pub block_hash: B256,
    pub tx_hash: B256,
    pub transaction_index: u64,
    pub log_index: u64,
    pub emitter: Address,
    pub event_signature: B256,
}

impl ProjectionSource {
    /// Converts typed provenance into the storage facade's validated map.
    pub fn to_storage_metadata(self) -> Result<StorageMetadata, ProjectionError> {
        StorageMetadata::new(BTreeMap::from([
            ("block_number".to_owned(), self.block_number.to_string()),
            ("block_hash".to_owned(), format!("{:#x}", self.block_hash)),
            ("tx_hash".to_owned(), format!("{:#x}", self.tx_hash)),
            (
                "transaction_index".to_owned(),
                self.transaction_index.to_string(),
            ),
            ("log_index".to_owned(), self.log_index.to_string()),
            ("emitter".to_owned(), format!("{:#x}", self.emitter)),
            (
                "event_signature".to_owned(),
                format!("{:#x}", self.event_signature),
            ),
        ]))
        .map_err(ProjectionError::Storage)
    }

    /// Strictly decodes the fixed metadata schema.
    pub fn from_storage_metadata(metadata: &StorageMetadata) -> Result<Self, ProjectionError> {
        if metadata.len() != SOURCE_KEYS.len() {
            return Err(ProjectionError::MalformedProjectionMetadata(
                "projection metadata must contain exactly seven fields".to_owned(),
            ));
        }
        for (key, _) in metadata.iter() {
            if !SOURCE_KEYS.contains(&key) {
                return Err(ProjectionError::MalformedProjectionMetadata(format!(
                    "unknown projection metadata field {key}"
                )));
            }
        }
        Ok(Self {
            block_number: parse_metadata(metadata, "block_number")?,
            block_hash: parse_fixed(metadata, "block_hash")?,
            tx_hash: parse_fixed(metadata, "tx_hash")?,
            transaction_index: parse_metadata(metadata, "transaction_index")?,
            log_index: parse_metadata(metadata, "log_index")?,
            emitter: parse_fixed(metadata, "emitter")?,
            event_signature: parse_fixed(metadata, "event_signature")?,
        })
    }
}

fn metadata_value<'a>(
    metadata: &'a StorageMetadata,
    key: &'static str,
) -> Result<&'a str, ProjectionError> {
    metadata
        .get(key)
        .ok_or_else(|| ProjectionError::MalformedProjectionMetadata(format!("missing {key}")))
}

fn parse_metadata<T>(metadata: &StorageMetadata, key: &'static str) -> Result<T, ProjectionError>
where
    T: FromStr + Display,
{
    let encoded = metadata_value(metadata, key)?;
    let parsed: T = encoded
        .parse()
        .map_err(|_| ProjectionError::MalformedProjectionMetadata(format!("invalid {key}")))?;
    if parsed.to_string() != encoded {
        return Err(ProjectionError::MalformedProjectionMetadata(format!(
            "non-canonical {key}"
        )));
    }
    Ok(parsed)
}

fn parse_fixed<T>(metadata: &StorageMetadata, key: &'static str) -> Result<T, ProjectionError>
where
    T: FromStr + LowerHex,
{
    let encoded = metadata_value(metadata, key)?;
    let parsed: T = encoded
        .parse()
        .map_err(|_| ProjectionError::MalformedProjectionMetadata(format!("invalid {key}")))?;
    if format!("{parsed:#x}") != encoded {
        return Err(ProjectionError::MalformedProjectionMetadata(format!(
            "non-canonical {key}"
        )));
    }
    Ok(parsed)
}

/// Backend-neutral finalized log, including its canonical block-global index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedLog {
    pub log_index: u64,
    pub emitter: Address,
    pub data: LogData,
}

/// Backend-neutral successful or reverted receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedReceipt {
    pub tx_hash: B256,
    pub transaction_index: u64,
    pub success: bool,
    pub logs: Vec<FinalizedLog>,
}

/// Complete normalized receipt input for one exact finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedBlock {
    pub number: u64,
    pub hash: B256,
    pub receipts: Vec<FinalizedReceipt>,
}

/// Prepared mutations for one successful receipt containing projection events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedReceipt {
    tx_hash: B256,
    transaction_index: u64,
    batch: AtomicWriteBatch,
}

impl PreparedReceipt {
    #[must_use]
    pub const fn tx_hash(&self) -> B256 {
        self.tx_hash
    }

    #[must_use]
    pub const fn transaction_index(&self) -> u64 {
        self.transaction_index
    }

    #[must_use]
    pub const fn batch(&self) -> &AtomicWriteBatch {
        &self.batch
    }
}

/// A fully decoded and simulated block. Constructed only after prepare succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBlock {
    checkpoint: ProjectionCheckpoint,
    receipts: Vec<PreparedReceipt>,
}

impl PreparedBlock {
    #[must_use]
    pub const fn checkpoint(&self) -> ProjectionCheckpoint {
        self.checkpoint
    }

    #[must_use]
    pub fn receipts(&self) -> &[PreparedReceipt] {
        &self.receipts
    }
}

/// Result of applying one finalized block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionOutcome {
    Applied {
        checkpoint: ProjectionCheckpoint,
        receipt_batches: usize,
    },
    AlreadyApplied(ProjectionCheckpoint),
}

/// Deterministic projector over shared backend-neutral storage capabilities.
pub struct OffchainDataProjection {
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
    state: ProjectionState,
    tribute_retention_selector: Option<Arc<dyn TributeRetentionSelector>>,
}

/// Reads and validates the managed projection state without acquiring a writer.
///
/// Snapshot exporters use this narrow surface only as an availability signal.
/// The checkpoint is never input authority; exported bodies still have to close
/// against the exact finalized compressed-entity snapshot.
pub fn read_projection_state(
    config: ProjectionConfig,
    reader: StorageReaderHandle,
) -> Result<Option<ProjectionState>, ProjectionError> {
    let namespace = state_namespace()?;
    let key = state_key()?;
    let Some(record) = reader.get_record(namespace, &key)? else {
        return Ok(None);
    };
    if record.metadata.is_some() {
        return Err(ProjectionError::CorruptProjectionState(
            "projection state must not carry metadata".to_owned(),
        ));
    }
    let state = decode_state(record.value.as_bytes())?;
    validate_state(&state, config)?;
    Ok(Some(state))
}

impl OffchainDataProjection {
    /// Opens a managed database or initializes an empty one.
    pub fn open(
        config: ProjectionConfig,
        reader: StorageReaderHandle,
        writer: StorageWriterHandle,
    ) -> Result<Self, ProjectionError> {
        let state = match read_projection_state(config, reader.clone())? {
            Some(state) => state,
            None => {
                if contains_unmanaged_data(&reader)? {
                    return Err(ProjectionError::UnmanagedProjectionData);
                }
                let state = ProjectionState {
                    chain_id: config.chain_id,
                    genesis_hash: config.genesis_hash,
                    storage_schema_version: STORAGE_SCHEMA_VERSION,
                    start_block: config.start_block,
                    checkpoint: None,
                };
                writer.apply_atomic(&state_batch(&state)?)?;
                state
            }
        };
        Ok(Self {
            reader,
            writer,
            state,
            tribute_retention_selector: None,
        })
    }

    /// Opens the projector with the node-owned active-pin selector.
    pub fn open_with_retention_selector(
        config: ProjectionConfig,
        reader: StorageReaderHandle,
        writer: StorageWriterHandle,
        selector: Arc<dyn TributeRetentionSelector>,
    ) -> Result<Self, ProjectionError> {
        let mut projection = Self::open(config, reader, writer)?;
        projection.tribute_retention_selector = Some(selector);
        Ok(projection)
    }

    #[must_use]
    pub const fn state(&self) -> &ProjectionState {
        &self.state
    }

    /// Decodes and simulates the entire block without performing any writes.
    pub fn prepare_block(&self, block: &FinalizedBlock) -> Result<PreparedBlock, ProjectionError> {
        self.validate_next_block(block.number, block.hash)?;
        validate_normalized_block(block)?;

        let mut decoded_receipts = Vec::with_capacity(block.receipts.len());
        for receipt in &block.receipts {
            let mut events = Vec::new();
            for log in &receipt.logs {
                let Some(signature) = log.data.topics().first().copied() else {
                    continue;
                };
                let source = ProjectionSource {
                    block_number: block.number,
                    block_hash: block.hash,
                    tx_hash: receipt.tx_hash,
                    transaction_index: receipt.transaction_index,
                    log_index: log.log_index,
                    emitter: log.emitter,
                    event_signature: signature,
                };
                let recognized = is_projection_pair(log.emitter, signature);
                if !receipt.success {
                    if recognized {
                        return Err(ProjectionError::ProjectionLogInFailedReceipt(Box::new(
                            source,
                        )));
                    }
                    continue;
                }
                if let Some(event) = decode_event(source, &log.data)? {
                    events.push(event);
                }
            }
            decoded_receipts.push((receipt, events));
        }

        let tribute_reader = TributeRepositoryReader::new(self.reader.clone());
        let retained_tribute_reader = RetainedTributeReader::new(self.reader.clone());
        let nod_reader = NodRepositoryReader::new(self.reader.clone());
        let mut tribute_ids = BTreeSet::new();
        let mut nod_ids = BTreeSet::new();
        let mut bucket_ids = BTreeSet::new();

        for (_, events) in &decoded_receipts {
            for event in events {
                match event.identity() {
                    None => {}
                    Some(EntityIdentity::Tribute(id)) => {
                        tribute_ids.insert(id);
                    }
                    Some(EntityIdentity::Nod(id)) => {
                        nod_ids.insert(id);
                    }
                    Some(EntityIdentity::Bucket(key)) => {
                        bucket_ids.insert(key);
                    }
                }
                if let ProjectionEvent::TributePartitionRetired { worldwide_day } = event {
                    let mut after = None;
                    loop {
                        let page = tribute_reader.list_ids_by_day(
                            *worldwide_day,
                            IdPageRequest {
                                after,
                                limit: MAX_ID_PAGE_LIMIT,
                            },
                        )?;
                        tribute_ids.extend(page.ids);
                        let Some(next) = page.next_after else {
                            break;
                        };
                        after = Some(next);
                    }
                }
            }
        }

        let tribute_ids: Vec<_> = tribute_ids.into_iter().collect();
        let nod_ids: Vec<_> = nod_ids.into_iter().collect();
        let bucket_ids: Vec<_> = bucket_ids.into_iter().collect();
        let mut tributes = tribute_reader.projection_session(&tribute_ids)?;
        for tribute_id in &tribute_ids {
            validate_existing_record("Tribute", tributes.current_with_metadata(*tribute_id)?)?;
        }
        let mut nods = nod_reader.projection_session(&nod_ids, &bucket_ids)?;
        for nod_id in &nod_ids {
            validate_existing_record("Nod", nods.current_item_with_metadata(*nod_id)?)?;
        }
        for bucket_id in &bucket_ids {
            validate_existing_record("Nod bucket", nods.current_bucket_with_metadata(*bucket_id)?)?;
        }

        let mut prepared_receipts = Vec::new();
        let mut seen_tributes = BTreeSet::new();
        let mut seen_nods = BTreeSet::new();
        let mut seen_buckets = BTreeSet::new();
        for (receipt, events) in decoded_receipts {
            let mut batch = AtomicWriteBatch::new();
            for event in events {
                match event {
                    ProjectionEvent::TributeStored {
                        source,
                        tribute_id,
                        stored_body,
                        previous_commitment,
                    } => {
                        let old = tributes.current(tribute_id)?;
                        validate_tribute_transition(
                            tribute_id,
                            old,
                            previous_commitment,
                            seen_tributes.insert(tribute_id),
                        )?;
                        let planned = tributes.store(
                            tribute_id,
                            stored_body,
                            Some(source.to_storage_metadata()?),
                        )?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                    ProjectionEvent::TributeDeleted {
                        tribute_id,
                        previous_commitment,
                    } => {
                        let old = tributes.current(tribute_id)?;
                        validate_tribute_transition(
                            tribute_id,
                            old,
                            previous_commitment,
                            seen_tributes.insert(tribute_id),
                        )?;
                        let planned = tributes.delete(tribute_id)?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                    ProjectionEvent::TributePartitionRetired { worldwide_day } => {
                        let retention_pin = self
                            .tribute_retention_selector
                            .as_ref()
                            .map(|selector| selector.active_pin_for(worldwide_day))
                            .transpose()
                            .map_err(|reason| ProjectionError::RetentionSelector {
                                worldwide_day,
                                reason,
                            })?
                            .flatten();
                        if let Some(pin) = retention_pin {
                            if pin.worldwide_day != worldwide_day {
                                return Err(ProjectionError::RetentionPinDayMismatch {
                                    requested: worldwide_day,
                                    selected: pin.worldwide_day,
                                });
                            }
                        }
                        for tribute_id in &tribute_ids {
                            let belongs_to_partition = tributes
                                .current(*tribute_id)?
                                .is_some_and(|tribute| tribute.worldwide_day == worldwide_day);
                            if belongs_to_partition {
                                let planned = match retention_pin {
                                    Some(pin) => tributes.retain_then_delete(
                                        &retained_tribute_reader,
                                        pin,
                                        *tribute_id,
                                    )?,
                                    None => tributes.delete(*tribute_id)?,
                                };
                                batch.extend(planned.operations().iter().cloned());
                            }
                        }
                    }
                    ProjectionEvent::NodStored {
                        source,
                        nod_id,
                        stored_body,
                        previous_commitment,
                    } => {
                        let old = nods.current_item(nod_id)?;
                        validate_nod_transition(
                            nod_id,
                            old,
                            previous_commitment,
                            seen_nods.insert(nod_id),
                        )?;
                        let planned = nods.store_item(
                            nod_id,
                            stored_body,
                            Some(source.to_storage_metadata()?),
                        )?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                    ProjectionEvent::NodDeleted {
                        nod_id,
                        previous_commitment,
                    } => {
                        let old = nods.current_item(nod_id)?;
                        validate_nod_transition(
                            nod_id,
                            old,
                            previous_commitment,
                            seen_nods.insert(nod_id),
                        )?;
                        let planned = nods.delete_item(nod_id)?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                    ProjectionEvent::BucketStored {
                        source,
                        bucket_id,
                        stored_body,
                        previous_commitment,
                    } => {
                        let old = nods.current_bucket(bucket_id)?;
                        validate_bucket_transition(
                            bucket_id,
                            old,
                            previous_commitment,
                            seen_buckets.insert(bucket_id),
                        )?;
                        let planned = nods.store_bucket(
                            bucket_id,
                            stored_body,
                            Some(source.to_storage_metadata()?),
                        )?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                    ProjectionEvent::BucketDeleted {
                        bucket_id,
                        previous_commitment,
                    } => {
                        let old = nods.current_bucket(bucket_id)?;
                        validate_bucket_transition(
                            bucket_id,
                            old,
                            previous_commitment,
                            seen_buckets.insert(bucket_id),
                        )?;
                        let planned = nods.delete_bucket(bucket_id)?;
                        batch.extend(planned.operations().iter().cloned());
                    }
                }
            }
            if !batch.is_empty() {
                batch.validate()?;
                prepared_receipts.push(PreparedReceipt {
                    tx_hash: receipt.tx_hash,
                    transaction_index: receipt.transaction_index,
                    batch,
                });
            }
        }

        Ok(PreparedBlock {
            checkpoint: ProjectionCheckpoint {
                block_number: block.number,
                block_hash: block.hash,
            },
            receipts: prepared_receipts,
        })
    }

    /// Applies every receipt mutation and the checkpoint in one backend transaction.
    pub fn apply_prepared(
        &mut self,
        prepared: PreparedBlock,
    ) -> Result<ProjectionOutcome, ProjectionError> {
        self.apply_prepared_with_batch(prepared)
            .map(|(outcome, _batch)| outcome)
    }

    /// Applies one prepared block to this projector and returns the exact same
    /// atomic batch for ordered delivery to a separate durable adapter.
    pub fn apply_prepared_with_batch(
        &mut self,
        prepared: PreparedBlock,
    ) -> Result<(ProjectionOutcome, AtomicWriteBatch), ProjectionError> {
        match self.validate_next_block(
            prepared.checkpoint.block_number,
            prepared.checkpoint.block_hash,
        )? {
            NextBlock::AlreadyApplied(checkpoint) => {
                return Ok((
                    ProjectionOutcome::AlreadyApplied(checkpoint),
                    AtomicWriteBatch::new(),
                ));
            }
            NextBlock::Apply => {}
        }
        let next_state = ProjectionState {
            checkpoint: Some(prepared.checkpoint),
            ..self.state.clone()
        };
        let mut block_batch = AtomicWriteBatch::new();
        for receipt in &prepared.receipts {
            block_batch.extend(receipt.batch.operations().iter().cloned());
        }
        block_batch.extend(state_batch(&next_state)?.operations().iter().cloned());
        block_batch.validate()?;
        self.writer.apply_atomic(&block_batch)?;
        self.state = next_state;
        Ok((
            ProjectionOutcome::Applied {
                checkpoint: prepared.checkpoint,
                receipt_batches: prepared.receipts.len(),
            },
            block_batch,
        ))
    }

    /// Prepares and applies one exact finalized block.
    pub fn project_block(
        &mut self,
        block: &FinalizedBlock,
    ) -> Result<ProjectionOutcome, ProjectionError> {
        if let NextBlock::AlreadyApplied(checkpoint) =
            self.validate_next_block(block.number, block.hash)?
        {
            return Ok(ProjectionOutcome::AlreadyApplied(checkpoint));
        }
        let prepared = self.prepare_block(block)?;
        self.apply_prepared(prepared)
    }

    fn validate_next_block(&self, number: u64, hash: B256) -> Result<NextBlock, ProjectionError> {
        match self.state.checkpoint {
            Some(checkpoint) if checkpoint.block_number == number => {
                if checkpoint.block_hash == hash {
                    Ok(NextBlock::AlreadyApplied(checkpoint))
                } else {
                    Err(ProjectionError::CheckpointMismatch {
                        block_number: number,
                        expected: checkpoint.block_hash,
                        actual: hash,
                    })
                }
            }
            Some(checkpoint) => {
                let expected = checkpoint.block_number.checked_add(1).ok_or(
                    ProjectionError::NonSequentialBlock {
                        expected: checkpoint.block_number,
                        actual: number,
                    },
                )?;
                if number != expected {
                    return Err(ProjectionError::NonSequentialBlock {
                        expected,
                        actual: number,
                    });
                }
                Ok(NextBlock::Apply)
            }
            None if number == self.state.start_block => Ok(NextBlock::Apply),
            None => Err(ProjectionError::NonSequentialBlock {
                expected: self.state.start_block,
                actual: number,
            }),
        }
    }
}

fn validate_existing_record<T>(
    entity: &'static str,
    record: Option<(&T, Option<&StorageMetadata>)>,
) -> Result<(), ProjectionError> {
    let Some((_body, metadata)) = record else {
        return Ok(());
    };
    let metadata = metadata.ok_or(ProjectionError::MissingProjectionMetadata { entity })?;
    ProjectionSource::from_storage_metadata(metadata)?;
    Ok(())
}

fn validate_tribute_transition(
    identity: WwdEntityId,
    old: Option<&TributeData>,
    previous: B256,
    first_in_block: bool,
) -> Result<(), ProjectionError> {
    if first_in_block {
        return Ok(());
    }
    let current = match old {
        Some(body) => {
            let payload = encode_tribute_v1(&outbe_tribute::canonical_body(body))
                .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            let commitment =
                body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, identity, &payload)
                    .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            B256::from(*commitment.as_bytes())
        }
        None => B256::ZERO,
    };
    validate_transition("Tribute", identity, current, previous)
}

fn validate_nod_transition(
    identity: WwdEntityId,
    old: Option<&NodItemState>,
    previous: B256,
    first_in_block: bool,
) -> Result<(), ProjectionError> {
    if first_in_block {
        return Ok(());
    }
    let current = match old {
        Some(body) => {
            let payload = encode_nod_item_v1(&outbe_nod::canonical_item(body))
                .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            let commitment =
                body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, identity, &payload)
                    .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            B256::from(*commitment.as_bytes())
        }
        None => B256::ZERO,
    };
    validate_transition("Nod", identity, current, previous)
}

fn validate_bucket_transition(
    identity: WwdEntityId,
    old: Option<&NodBucketState>,
    previous: B256,
    first_in_block: bool,
) -> Result<(), ProjectionError> {
    if first_in_block {
        return Ok(());
    }
    let current = match old {
        Some(body) => {
            let payload = encode_nod_bucket_v1(&outbe_nod::canonical_bucket(body))
                .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            let commitment =
                body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, identity, &payload)
                    .map_err(|error| ProjectionError::CorruptProjectedBody(error.to_string()))?;
            B256::from(*commitment.as_bytes())
        }
        None => B256::ZERO,
    };
    validate_transition("Nod bucket", identity, current, previous)
}

fn validate_transition(
    entity: &'static str,
    identity: WwdEntityId,
    current: B256,
    previous: B256,
) -> Result<(), ProjectionError> {
    if current == previous {
        return Ok(());
    }
    Err(ProjectionError::CommitmentTransitionMismatch {
        entity,
        identity,
        expected_previous: previous,
        actual: current,
    })
}

#[derive(Clone, Copy)]
enum NextBlock {
    Apply,
    AlreadyApplied(ProjectionCheckpoint),
}

#[derive(Clone, Copy)]
enum EntityIdentity {
    Tribute(WwdEntityId),
    Nod(WwdEntityId),
    Bucket(WwdEntityId),
}

enum ProjectionEvent {
    TributeStored {
        source: ProjectionSource,
        tribute_id: WwdEntityId,
        stored_body: Value,
        previous_commitment: B256,
    },
    TributeDeleted {
        tribute_id: WwdEntityId,
        previous_commitment: B256,
    },
    TributePartitionRetired {
        worldwide_day: WorldwideDay,
    },
    NodStored {
        source: ProjectionSource,
        nod_id: WwdEntityId,
        stored_body: Value,
        previous_commitment: B256,
    },
    NodDeleted {
        nod_id: WwdEntityId,
        previous_commitment: B256,
    },
    BucketStored {
        source: ProjectionSource,
        bucket_id: WwdEntityId,
        stored_body: Value,
        previous_commitment: B256,
    },
    BucketDeleted {
        bucket_id: WwdEntityId,
        previous_commitment: B256,
    },
}

impl ProjectionEvent {
    fn identity(&self) -> Option<EntityIdentity> {
        match self {
            Self::TributeStored { tribute_id, .. } => Some(EntityIdentity::Tribute(*tribute_id)),
            Self::TributeDeleted { tribute_id, .. } => Some(EntityIdentity::Tribute(*tribute_id)),
            Self::TributePartitionRetired { .. } => None,
            Self::NodStored { nod_id, .. } => Some(EntityIdentity::Nod(*nod_id)),
            Self::NodDeleted { nod_id, .. } => Some(EntityIdentity::Nod(*nod_id)),
            Self::BucketStored { bucket_id, .. } | Self::BucketDeleted { bucket_id, .. } => {
                Some(EntityIdentity::Bucket(*bucket_id))
            }
        }
    }
}

fn is_projection_pair(emitter: Address, signature: B256) -> bool {
    (emitter == TRIBUTE_ADDRESS
        && (signature == ITribute::TributeBodyStored::SIGNATURE_HASH
            || signature == ITribute::TributeBodyDeleted::SIGNATURE_HASH
            || signature == ITribute::TributePartitionRetired::SIGNATURE_HASH))
        || (emitter == NOD_ADDRESS
            && (signature == INod::NodBodyStored::SIGNATURE_HASH
                || signature == INod::NodBodyDeleted::SIGNATURE_HASH
                || signature == INod::NodBucketBodyStored::SIGNATURE_HASH
                || signature == INod::NodBucketBodyDeleted::SIGNATURE_HASH))
}

fn decode_event(
    source: ProjectionSource,
    data: &LogData,
) -> Result<Option<ProjectionEvent>, ProjectionError> {
    let decoded = if source.emitter == TRIBUTE_ADDRESS
        && source.event_signature == ITribute::TributeBodyStored::SIGNATURE_HASH
    {
        let event = ITribute::TributeBodyStored::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_versions(source, event.commitmentSchemeVersion, event.schemaVersion)?;
        let tribute_id = WwdEntityId::from(event.tributeId);
        let canonical = decode_tribute_v1(&event.canonicalPayload)
            .map_err(|error| malformed_event(source, error))?;
        if canonical.tribute_id != tribute_id {
            return Err(malformed_event(
                source,
                "Tribute event identity/payload mismatch",
            ));
        }
        validate_poseidon_identity(
            source,
            "Tribute",
            tribute_id,
            canonical.owner,
            canonical.worldwide_day,
        )?;
        validate_stored_commitment(
            source,
            tribute_id,
            &event.canonicalPayload,
            event.previousCommitment,
            event.newCommitment,
        )?;
        Some(ProjectionEvent::TributeStored {
            source,
            tribute_id,
            stored_body: stored_event_body(source, event.schemaVersion, &event.canonicalPayload)?,
            previous_commitment: event.previousCommitment,
        })
    } else if source.emitter == TRIBUTE_ADDRESS
        && source.event_signature == ITribute::TributeBodyDeleted::SIGNATURE_HASH
    {
        let event = ITribute::TributeBodyDeleted::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_deleted_commitment(source, event.previousCommitment)?;
        Some(ProjectionEvent::TributeDeleted {
            tribute_id: WwdEntityId::from(event.tributeId),
            previous_commitment: event.previousCommitment,
        })
    } else if source.emitter == TRIBUTE_ADDRESS
        && source.event_signature == ITribute::TributePartitionRetired::SIGNATURE_HASH
    {
        let event = ITribute::TributePartitionRetired::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        Some(ProjectionEvent::TributePartitionRetired {
            worldwide_day: event.worldwideDay.into(),
        })
    } else if source.emitter == NOD_ADDRESS
        && source.event_signature == INod::NodBodyStored::SIGNATURE_HASH
    {
        let event = INod::NodBodyStored::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_versions(source, event.commitmentSchemeVersion, event.schemaVersion)?;
        let nod_id = WwdEntityId::from(event.nodId);
        let canonical = decode_nod_item_v1(&event.canonicalPayload)
            .map_err(|error| malformed_event(source, error))?;
        if canonical.nod_id != nod_id {
            return Err(malformed_event(
                source,
                "Nod event identity/payload mismatch",
            ));
        }
        validate_poseidon_identity(
            source,
            "Nod item",
            nod_id,
            canonical.owner,
            canonical.worldwide_day,
        )?;
        validate_stored_commitment(
            source,
            nod_id,
            &event.canonicalPayload,
            event.previousCommitment,
            event.newCommitment,
        )?;
        Some(ProjectionEvent::NodStored {
            source,
            nod_id,
            stored_body: stored_event_body(source, event.schemaVersion, &event.canonicalPayload)?,
            previous_commitment: event.previousCommitment,
        })
    } else if source.emitter == NOD_ADDRESS
        && source.event_signature == INod::NodBodyDeleted::SIGNATURE_HASH
    {
        let event = INod::NodBodyDeleted::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_deleted_commitment(source, event.previousCommitment)?;
        Some(ProjectionEvent::NodDeleted {
            nod_id: WwdEntityId::from(event.nodId),
            previous_commitment: event.previousCommitment,
        })
    } else if source.emitter == NOD_ADDRESS
        && source.event_signature == INod::NodBucketBodyStored::SIGNATURE_HASH
    {
        let event = INod::NodBucketBodyStored::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_versions(source, event.commitmentSchemeVersion, event.schemaVersion)?;
        let bucket_id = WwdEntityId::from(event.bucketId);
        let canonical = decode_nod_bucket_v1(&event.canonicalPayload)
            .map_err(|error| malformed_event(source, error))?;
        if canonical.entity_id() != bucket_id {
            return Err(malformed_event(
                source,
                "Nod bucket event identity/payload mismatch",
            ));
        }
        validate_stored_commitment(
            source,
            bucket_id,
            &event.canonicalPayload,
            event.previousCommitment,
            event.newCommitment,
        )?;
        Some(ProjectionEvent::BucketStored {
            source,
            bucket_id,
            stored_body: stored_event_body(source, event.schemaVersion, &event.canonicalPayload)?,
            previous_commitment: event.previousCommitment,
        })
    } else if source.emitter == NOD_ADDRESS
        && source.event_signature == INod::NodBucketBodyDeleted::SIGNATURE_HASH
    {
        let event = INod::NodBucketBodyDeleted::decode_log_data(data)
            .map_err(|error| malformed_event(source, error))?;
        validate_deleted_commitment(source, event.previousCommitment)?;
        Some(ProjectionEvent::BucketDeleted {
            bucket_id: WwdEntityId::from(event.bucketId),
            previous_commitment: event.previousCommitment,
        })
    } else {
        None
    };
    Ok(decoded)
}

fn validate_poseidon_identity(
    source: ProjectionSource,
    entity: &'static str,
    actual: WwdEntityId,
    owner: Address,
    worldwide_day: outbe_primitives::time::WorldwideDay,
) -> Result<(), ProjectionError> {
    let expected = derive_poseidon_entity_id(owner, worldwide_day)
        .map_err(|error| malformed_event(source, error))?;
    if actual != expected {
        return Err(malformed_event(
            source,
            format!("{entity} canonical identity mismatch: expected {expected}, found {actual}"),
        ));
    }
    Ok(())
}

fn stored_event_body(
    source: ProjectionSource,
    schema_version: u32,
    payload: &[u8],
) -> Result<Value, ProjectionError> {
    let stored = StoredBody::new(schema_version, payload.to_vec())
        .map_err(|error| malformed_event(source, error))?;
    Value::new(stored.encode()).map_err(ProjectionError::Storage)
}

fn validate_versions(
    source: ProjectionSource,
    commitment_scheme_version: u32,
    schema_version: u32,
) -> Result<(), ProjectionError> {
    if commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME {
        return Err(malformed_event(
            source,
            format!("unsupported commitment scheme {commitment_scheme_version}"),
        ));
    }
    if schema_version != BODY_SCHEMA_V1 {
        return Err(malformed_event(
            source,
            format!("unsupported body schema {schema_version}"),
        ));
    }
    Ok(())
}

fn validate_stored_commitment(
    source: ProjectionSource,
    identity: WwdEntityId,
    payload: &[u8],
    previous: B256,
    new: B256,
) -> Result<(), ProjectionError> {
    if !previous.is_zero() {
        outbe_compressed_entities::Commitment::try_from(previous.0)
            .map_err(|error| malformed_event(source, error))?;
    }
    let expected = body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, identity, payload)
        .map_err(|error| malformed_event(source, error))?;
    if new != B256::from(*expected.as_bytes()) {
        return Err(malformed_event(
            source,
            "new commitment does not match payload",
        ));
    }
    Ok(())
}

fn validate_deleted_commitment(
    source: ProjectionSource,
    previous: B256,
) -> Result<(), ProjectionError> {
    outbe_compressed_entities::Commitment::try_from(previous.0)
        .map(|_| ())
        .map_err(|error| malformed_event(source, error))
}

fn malformed_event(source: ProjectionSource, error: impl std::fmt::Display) -> ProjectionError {
    ProjectionError::MalformedProjectionEvent {
        event_source: Box::new(source),
        reason: error.to_string(),
    }
}

fn validate_normalized_block(block: &FinalizedBlock) -> Result<(), ProjectionError> {
    let mut expected_log_index = 0_u64;
    for (expected_index, receipt) in block.receipts.iter().enumerate() {
        let expected_index =
            u64::try_from(expected_index).map_err(|_| ProjectionError::TransactionIndexOverflow)?;
        if receipt.transaction_index != expected_index {
            return Err(ProjectionError::InvalidTransactionOrder {
                expected: expected_index,
                actual: receipt.transaction_index,
            });
        }
        for log in &receipt.logs {
            if log.log_index != expected_log_index {
                return Err(ProjectionError::InvalidLogOrder {
                    expected: expected_log_index,
                    actual: log.log_index,
                });
            }
            expected_log_index = expected_log_index
                .checked_add(1)
                .ok_or(ProjectionError::LogIndexOverflow)?;
        }
    }
    Ok(())
}

fn contains_unmanaged_data(reader: &StorageReaderHandle) -> Result<bool, ProjectionError> {
    for name in TRIBUTE_PROJECTION_NAMESPACES
        .iter()
        .chain(NOD_PROJECTION_NAMESPACES.iter())
    {
        let namespace = Namespace::new(*name)?;
        let request = ScanRequest::new(&[], None, 1)?;
        if !reader.scan_prefix(namespace, request)?.entries.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_state(
    state: &ProjectionState,
    config: ProjectionConfig,
) -> Result<(), ProjectionError> {
    if state.storage_schema_version != STORAGE_SCHEMA_VERSION {
        return Err(ProjectionError::ProjectionSchemaMismatch {
            expected: STORAGE_SCHEMA_VERSION,
            actual: state.storage_schema_version,
        });
    }
    if state.chain_id != config.chain_id
        || state.genesis_hash != config.genesis_hash
        || state.start_block != config.start_block
    {
        return Err(ProjectionError::ProjectionIdentityMismatch {
            expected: config,
            actual_chain_id: state.chain_id,
            actual_genesis_hash: state.genesis_hash,
            actual_start_block: state.start_block,
        });
    }
    if state
        .checkpoint
        .is_some_and(|checkpoint| checkpoint.block_number < state.start_block)
    {
        return Err(ProjectionError::CorruptProjectionState(
            "checkpoint precedes configured start block".to_owned(),
        ));
    }
    Ok(())
}

fn state_namespace() -> Result<Namespace, ProjectionError> {
    Ok(Namespace::new(PROJECTION_STATE_NAMESPACE)?)
}

fn state_key() -> Result<Key, ProjectionError> {
    Ok(Key::new(PROJECTION_STATE_KEY.to_vec())?)
}

fn state_batch(state: &ProjectionState) -> Result<AtomicWriteBatch, ProjectionError> {
    let bytes = postcard::to_stdvec(state).map_err(ProjectionError::StateEncode)?;
    let operation = AtomicWriteOperation::put_record(
        state_namespace()?,
        state_key()?,
        StoredValue::plain(Value::new(bytes)?),
    );
    Ok(AtomicWriteBatch::from_operations(vec![operation]))
}

fn decode_state(bytes: &[u8]) -> Result<ProjectionState, ProjectionError> {
    let (state, remainder): (ProjectionState, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(ProjectionError::StateDecode)?;
    if !remainder.is_empty() {
        return Err(ProjectionError::CorruptProjectionState(
            "projection state has trailing bytes".to_owned(),
        ));
    }
    Ok(state)
}

/// Stable projector failures; no backend-specific type crosses this boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProjectionError {
    #[error("off-chain storage failure: {0}")]
    Storage(#[from] StorageError),
    #[error("Tribute repository failure: {0}")]
    Tribute(#[from] TributeRepositoryError),
    #[error("Nod repository failure: {0}")]
    Nod(#[from] NodRepositoryError),
    #[error("failed to encode projection state")]
    StateEncode(#[source] postcard::Error),
    #[error("failed to decode projection state")]
    StateDecode(#[source] postcard::Error),
    #[error("corrupt projection state: {0}")]
    CorruptProjectionState(String),
    #[error("projection schema mismatch: expected {expected}, found {actual}")]
    ProjectionSchemaMismatch { expected: u32, actual: u32 },
    #[error("projection identity does not match configured chain")]
    ProjectionIdentityMismatch {
        expected: ProjectionConfig,
        actual_chain_id: u64,
        actual_genesis_hash: B256,
        actual_start_block: u64,
    },
    #[error("body/index records exist without projection state")]
    UnmanagedProjectionData,
    #[error(
        "checkpoint hash mismatch at block {block_number}: expected {expected}, found {actual}"
    )]
    CheckpointMismatch {
        block_number: u64,
        expected: B256,
        actual: B256,
    },
    #[error("non-sequential block: expected {expected}, found {actual}")]
    NonSequentialBlock { expected: u64, actual: u64 },
    #[error("invalid transaction order: expected {expected}, found {actual}")]
    InvalidTransactionOrder { expected: u64, actual: u64 },
    #[error("transaction index does not fit u64")]
    TransactionIndexOverflow,
    #[error("invalid block-global log order: expected {expected}, found {actual}")]
    InvalidLogOrder { expected: u64, actual: u64 },
    #[error("block-global log index overflow")]
    LogIndexOverflow,
    #[error("recognized projection log appears in a failed receipt at {0:?}")]
    ProjectionLogInFailedReceipt(Box<ProjectionSource>),
    #[error("malformed recognized projection event at {event_source:?}: {reason}")]
    MalformedProjectionEvent {
        event_source: Box<ProjectionSource>,
        reason: String,
    },
    #[error("malformed projection metadata: {0}")]
    MalformedProjectionMetadata(String),
    #[error("managed {entity} primary record has no projection metadata")]
    MissingProjectionMetadata { entity: &'static str },
    #[error("OCOMP retention selector failed for day {worldwide_day}: {reason}")]
    RetentionSelector {
        worldwide_day: WorldwideDay,
        reason: String,
    },
    #[error(
        "OCOMP retention selector returned day {selected} for requested partition {requested}"
    )]
    RetentionPinDayMismatch {
        requested: WorldwideDay,
        selected: WorldwideDay,
    },
    #[error("corrupt projected body: {0}")]
    CorruptProjectedBody(String),
    #[error(
        "{entity} {identity} commitment transition expected previous {expected_previous}, found {actual}"
    )]
    CommitmentTransitionMismatch {
        entity: &'static str,
        identity: WwdEntityId,
        expected_previous: B256,
        actual: B256,
    },
}
