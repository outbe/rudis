//! Reth ExEx adapter for finalized offchain-data projection.
//!
//! Canonical-chain notifications are deliberately only drained here. The provider's finalized
//! block signal is the sole authority that permits projection writes.

use std::{
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

#[cfg(test)]
use std::sync::Mutex;

use alloy_consensus::transaction::TxHashRef;
#[cfg(test)]
use alloy_consensus::BlockHeader;
#[cfg(test)]
use alloy_primitives::Sealable;
use alloy_primitives::B256;
use eyre::{bail, Context};
#[cfg(test)]
use futures::{FutureExt, Stream, StreamExt};
#[cfg(test)]
use metrics::counter;
use metrics::gauge;
use outbe_offchain_data::{
    FinalizedBlock, FinalizedLog, FinalizedReceipt, OffchainDataProjection, ProjectionConfig,
    ProjectionFailure, ProjectionFailureClass, ProjectionOutcome, ProjectionReadinessHandle,
    ProjectionReadinessPublisher, ProjectionStatus, RuntimeBodyReaders, TributeRetentionSelector,
};
use outbe_offchain_storage::{
    AtomicWriteBatch, OpenedStorage, PendingOverlayStorage, StorageConfig, StorageError,
    StorageErrorKind, StorageOwnershipGuard, StorageProvider, StorageReaderHandle,
    StorageWriterHandle,
};
use outbe_primitives::{
    chain::network_for_chain_id,
    projection::{projection_readiness, ProjectionCheckpoint},
};
use outbe_tribute::RetainedTributeWriter;
#[cfg(test)]
use reth_ethereum::exex::ExExEvent;
use reth_primitives_traits::{Block, BlockBody, Receipt as RethReceipt};
#[cfg(test)]
use reth_provider::BlockReader;
use reth_provider::{BlockHashReader, BlockIdReader};
#[cfg(test)]
use tokio::time::MissedTickBehavior;
#[cfg(test)]
use tracing::error;
use tracing::{info, warn};

use crate::finalized_frame::FinalizedFrame;

pub use outbe_offchain_data::RuntimeBodyFailure;

const PROJECTION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
pub const PROJECTION_RECOVERY_DEADLINE: Duration = Duration::from_secs(8);

#[derive(Debug, thiserror::Error)]
#[error("offchain storage projection reconnect deadline expired for block {block_number} ({block_hash})")]
pub struct ProjectionWriteDeadlineError {
    block_number: u64,
    block_hash: B256,
    #[source]
    source: Option<StorageError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FinalizedTarget {
    number: u64,
    hash: B256,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalizedTargetDisposition {
    Attempt,
    Unchanged,
    Rejected,
}

impl FinalizedTarget {
    const fn new(number: u64, hash: B256) -> Self {
        Self { number, hash }
    }
}

#[cfg(test)]
#[derive(Debug, thiserror::Error)]
enum HistoricalProjectionDataError {
    #[error("canonical block {block_number} is unavailable")]
    CanonicalBlock { block_number: u64 },
    #[error("canonical block {block_number} ({block_hash}) is unavailable by hash")]
    CanonicalBlockByHash { block_number: u64, block_hash: B256 },
    #[error("receipts for canonical block {block_number} are unavailable")]
    Receipts { block_number: u64 },
}

#[cfg(test)]
type ProjectionAttempt = tokio::sync::oneshot::Receiver<eyre::Result<Option<FinalizedTarget>>>;

struct DurableProjectionWrite {
    checkpoint: FinalizedTarget,
    batch: AtomicWriteBatch,
    overlay_ack: Option<(Arc<PendingOverlayStorage>, u64)>,
}

#[cfg(test)]
fn spawn_detached_projection_work<T: Send + 'static>(
    name: &str,
    work: impl FnOnce() -> T + Send + 'static,
) -> std::io::Result<tokio::sync::oneshot::Receiver<T>> {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _ = result_tx.send(work());
        })?;
    Ok(result_rx)
}

/// Structured terminal condition reported to the top-level node lifecycle owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionExit {
    pub failure: ProjectionFailure,
}

/// Complete startup configuration for the required finalized offchain-data projection.
#[derive(Clone)]
pub struct OffchainDataProjectionConfig {
    /// EVM chain identity recorded in the managed projection state.
    pub chain_id: u64,
    /// Canonical genesis hash recorded in the managed projection state.
    pub genesis_hash: B256,
    /// Shared backend configuration, including the first projected block.
    pub storage: StorageConfig,
}

/// Projection instance whose offchain storage connection, topology, and managed state passed preflight.
pub struct PreparedOffchainDataProjection {
    projector: OffchainDataProjection,
    storage: OpenedStorage,
    overlay: Arc<PendingOverlayStorage>,
    readiness_publisher: ProjectionReadinessPublisher,
    readiness: ProjectionReadinessHandle,
    runtime_failure_sender: tokio::sync::watch::Sender<Option<RuntimeBodyFailure>>,
    runtime_failure_receiver: tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>,
    retention_fence: Arc<ProjectionRetentionFence>,
}

/// Orders retained-input projection commits against OCOMP garbage collection.
///
/// Projection holds the shared side from pin selection through the durable
/// offchain storage commit. The retention worker briefly takes the exclusive side only
/// while it durably claims a lease for collection; physical deletion happens
/// after the exclusive guard is released.
#[derive(Default)]
pub struct ProjectionRetentionFence {
    gate: RwLock<()>,
}

impl ProjectionRetentionFence {
    fn projection_guard(&self) -> eyre::Result<RwLockReadGuard<'_, ()>> {
        self.gate
            .read()
            .map_err(|_| eyre::eyre!("OCOMP projection/GC fence is poisoned"))
    }

    pub(crate) fn gc_claim_guard(&self) -> Result<RwLockWriteGuard<'_, ()>, &'static str> {
        self.gate
            .write()
            .map_err(|_| "OCOMP projection/GC fence is poisoned")
    }
}

impl PreparedOffchainDataProjection {
    /// Typed read-only capabilities injected into EVM execution.
    #[must_use]
    pub fn runtime_body_readers(&self) -> RuntimeBodyReaders {
        let reader: StorageReaderHandle = self.overlay.clone();
        RuntimeBodyReaders::new_supervised(reader, self.runtime_failure_sender.clone())
    }

    /// Backend-neutral exact-checkpoint readiness used by local execution gates.
    #[must_use]
    pub fn readiness(&self) -> ProjectionReadinessHandle {
        self.readiness.clone()
    }

    /// Durable release capability backed by the exact storage owned by this projection.
    #[must_use]
    pub fn retained_tribute_writer(&self) -> Arc<RetainedTributeWriter> {
        let reader = self.storage.reader.clone();
        let writer = self.storage.writer.clone();
        Arc::new(RetainedTributeWriter::new(reader, writer))
    }

    /// Exact process-local fence shared by projection and retained-input GC.
    #[must_use]
    pub fn retention_fence(&self) -> Arc<ProjectionRetentionFence> {
        Arc::clone(&self.retention_fence)
    }
}

/// Projection instance whose available canonical checkpoint identity passed startup checks.
pub struct ReadyOffchainDataProjection {
    projector: OffchainDataProjection,
    readiness_publisher: ProjectionReadinessPublisher,
    projection_config: ProjectionConfig,
    _reader: StorageReaderHandle,
    overlay: Arc<PendingOverlayStorage>,
    writer: StorageWriterHandle,
    writer_lease: StorageOwnershipGuard,
    runtime_failure_sender: tokio::sync::watch::Sender<Option<RuntimeBodyFailure>>,
    runtime_failure_receiver: tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>,
    retention_fence: Arc<ProjectionRetentionFence>,
}

#[derive(Clone)]
pub struct ProjectionRuntimeRecoveryHandle {
    writer: StorageWriterHandle,
    failure_sender: tokio::sync::watch::Sender<Option<RuntimeBodyFailure>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionRuntimeRecoveryV1 {
    Recovered,
    Unavailable,
    Fatal(ProjectionFailure),
}

impl ProjectionRuntimeRecoveryHandle {
    /// Proves that the shared offchain storage backend can start transactions again, then closes only the
    /// transient runtime-read outage. A fatal body failure is sticky and is never cleared here.
    pub fn reconcile(&self, generation: u64) -> ProjectionRuntimeRecoveryV1 {
        if let Err(error) = self.writer.verify_transaction_capability() {
            return if error.kind() == StorageErrorKind::Unavailable {
                ProjectionRuntimeRecoveryV1::Unavailable
            } else {
                ProjectionRuntimeRecoveryV1::Fatal(ProjectionFailure::new(
                    storage_failure_class(&error),
                    format!("offchain runtime-body storage recovery failed: {error}"),
                ))
            };
        }
        let cleared = self.failure_sender.send_if_modified(|current| {
            if matches!(
                current,
                Some(RuntimeBodyFailure::Unavailable {
                    generation: current_generation,
                    ..
                }) if *current_generation == generation
            ) {
                *current = None;
                true
            } else {
                false
            }
        });
        if cleared {
            return ProjectionRuntimeRecoveryV1::Recovered;
        }
        match self.failure_sender.borrow().clone() {
            Some(RuntimeBodyFailure::Unavailable { .. }) => {
                ProjectionRuntimeRecoveryV1::Unavailable
            }
            Some(RuntimeBodyFailure::Fatal(failure)) => ProjectionRuntimeRecoveryV1::Fatal(failure),
            None => ProjectionRuntimeRecoveryV1::Recovered,
        }
    }
}

/// Deep sink for projecting an already-read finalized frame into durable Mongo state.
///
/// The sink owns the logical overlay and the single-writer lease inherited from
/// [`ReadyOffchainDataProjection`]. [`Self::project_frame`] does not return a new checkpoint until
/// the exact atomic batch has committed through the durable writer. Frames below the durable
/// checkpoint are accepted as restart replay; a replay at the checkpoint height must have the
/// exact durable hash.
pub struct FinalizedProjectionSink {
    runtime: ProjectionRuntime,
    durable_checkpoint: Option<ProjectionCheckpoint>,
    provider_recovery_floor: Option<ProjectionCheckpoint>,
    retention_fence: Option<Arc<ProjectionRetentionFence>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizedTargetReconciliationV1 {
    AwaitingProviderRecovery,
    Process {
        target: ProjectionCheckpoint,
        recovered_floor: Option<ProjectionCheckpoint>,
    },
}

impl FinalizedProjectionSink {
    #[must_use]
    pub fn new(ready: ReadyOffchainDataProjection) -> Self {
        let retention_fence = Arc::clone(&ready.retention_fence);
        Self::from_runtime_with_retention_fence(ProjectionRuntime::new(ready), retention_fence)
    }

    #[must_use]
    pub const fn durable_checkpoint(&self) -> Option<ProjectionCheckpoint> {
        self.durable_checkpoint
    }

    pub fn runtime_failure_receiver(
        &self,
    ) -> eyre::Result<tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>> {
        self.runtime
            .runtime_failure_receiver
            .as_ref()
            .cloned()
            .ok_or_else(|| eyre::eyre!("projection body-read failure receiver is unavailable"))
    }

    pub fn runtime_recovery_handle(&self) -> eyre::Result<ProjectionRuntimeRecoveryHandle> {
        Ok(ProjectionRuntimeRecoveryHandle {
            writer: self.runtime.writer.clone(),
            failure_sender: self
                .runtime
                .runtime_failure_sender
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    eyre::eyre!("projection body-read recovery sender is unavailable")
                })?,
        })
    }

    pub fn publish_failure(&self, failure: ProjectionFailure) {
        self.runtime
            .readiness_publisher
            .publish(ProjectionStatus::Fatal {
                checkpoint: self.durable_checkpoint,
                error: failure,
            });
    }

    /// Reconciles a sampled provider finalized target with the durable projection floor.
    ///
    /// Reth can temporarily expose no finalized marker, or an older marker, while restoring its
    /// forkchoice state after restart. That state is recoverable only when the durable checkpoint
    /// still has the exact canonical hash validated at startup. Readiness remains closed until the
    /// provider reaches the floor again; a same-height identity conflict remains fatal.
    pub fn reconcile_finalized_target(
        &mut self,
        target: Option<ProjectionCheckpoint>,
    ) -> eyre::Result<FinalizedTargetReconciliationV1> {
        let Some(durable) = self.durable_checkpoint else {
            return Ok(match target {
                Some(target) => FinalizedTargetReconciliationV1::Process {
                    target,
                    recovered_floor: None,
                },
                None => {
                    publish_status(
                        &self.runtime.readiness_publisher,
                        ProjectionStatus::CatchingUp { checkpoint: None },
                        None,
                    );
                    FinalizedTargetReconciliationV1::AwaitingProviderRecovery
                }
            });
        };
        let provider_target =
            target.map(|target| FinalizedTarget::new(target.block_number, target.block_hash));
        let reconciled = require_finalized_checkpoint(durable, provider_target)?;
        let Some(reconciled) = reconciled else {
            self.provider_recovery_floor = Some(durable);
            publish_status(
                &self.runtime.readiness_publisher,
                ProjectionStatus::CatchingUp {
                    checkpoint: Some(durable),
                },
                provider_target,
            );
            return Ok(FinalizedTargetReconciliationV1::AwaitingProviderRecovery);
        };
        Ok(FinalizedTargetReconciliationV1::Process {
            target: ProjectionCheckpoint {
                block_number: reconciled.number,
                block_hash: reconciled.hash,
            },
            recovered_floor: self.provider_recovery_floor.take(),
        })
    }

    /// Publishes projection readiness against the coordinator's sampled finalized target.
    pub fn publish_progress(&self, target: ProjectionCheckpoint) -> eyre::Result<()> {
        let durable = self.durable_checkpoint.unwrap_or(ProjectionCheckpoint {
            block_number: 0,
            block_hash: self.runtime.projection_config.genesis_hash,
        });
        if durable.block_number > target.block_number
            || (durable.block_number == target.block_number
                && durable.block_hash != target.block_hash)
        {
            bail!("durable projection checkpoint is ahead of or conflicts with finalized target");
        }
        self.runtime
            .readiness_publisher
            .publish(if durable == target {
                ProjectionStatus::Ready {
                    checkpoint: durable,
                }
            } else {
                ProjectionStatus::CatchingUp {
                    checkpoint: Some(durable),
                }
            });
        Ok(())
    }

    /// Projects one shared finalized frame and returns the exact durable projection checkpoint.
    ///
    /// This method is synchronous because the configured storage interface is synchronous. An
    /// async coordinator should call it on its blocking worker. Durable write failures retry the
    /// same atomic batch and never expose logical progress as durable P.
    pub fn project_frame(&mut self, frame: &FinalizedFrame) -> eyre::Result<ProjectionCheckpoint> {
        self.project_frame_until(
            frame,
            std::time::Instant::now() + PROJECTION_RECOVERY_DEADLINE,
        )
    }

    pub fn project_frame_until(
        &mut self,
        frame: &FinalizedFrame,
        deadline: std::time::Instant,
    ) -> eyre::Result<ProjectionCheckpoint> {
        let identity = frame.identity();
        if let Some(checkpoint) = self.durable_checkpoint {
            if identity.number < checkpoint.block_number {
                return Ok(checkpoint);
            }
            if identity.number == checkpoint.block_number {
                if identity.hash != checkpoint.block_hash {
                    bail!(
                        "finalized frame hash {} conflicts with durable projection hash {} at height {}",
                        identity.hash,
                        checkpoint.block_hash,
                        identity.number
                    );
                }
                return Ok(checkpoint);
            }
        }

        let retention_fence = self.retention_fence.clone();
        let _retention_guard = retention_fence
            .as_ref()
            .map(|fence| fence.projection_guard())
            .transpose()?;
        let normalized = normalize_finalized_block(
            identity.number,
            identity.hash,
            frame.block(),
            frame.receipts(),
        )?;
        let overlay = self.runtime.overlay.clone();
        let prepared = self
            .runtime
            .projector
            .prepare_block(&normalized)
            .wrap_err_with(|| format!("project finalized frame {}", identity.number))?;
        let (projected, durable_batch) = self
            .runtime
            .projector
            .apply_prepared_with_batch(prepared)
            .wrap_err_with(|| format!("apply logical finalized frame {}", identity.number))?;
        let projected = match projected {
            ProjectionOutcome::Applied { checkpoint, .. } => checkpoint,
            ProjectionOutcome::AlreadyApplied(checkpoint) => {
                bail!(
                    "logical projection checkpoint {} ({}) is ahead of durable frame-sink authority",
                    checkpoint.block_number,
                    checkpoint.block_hash
                );
            }
        };
        if projected.block_number != identity.number || projected.block_hash != identity.hash {
            bail!(
                "projector returned checkpoint {} ({}) after projecting shared frame {} ({})",
                projected.block_number,
                projected.block_hash,
                identity.number,
                identity.hash
            );
        }
        let overlay_ack = overlay
            .as_ref()
            .map(|overlay| (Arc::clone(overlay), overlay.current_generation()));
        apply_durable_projection_write_before(
            &self.runtime.writer,
            &DurableProjectionWrite {
                checkpoint: FinalizedTarget::new(projected.block_number, projected.block_hash),
                batch: durable_batch,
                overlay_ack,
            },
            deadline,
        )?;
        self.durable_checkpoint = Some(projected);
        Ok(projected)
    }

    #[cfg(test)]
    fn from_runtime(runtime: ProjectionRuntime) -> Self {
        Self::from_runtime_inner(runtime, None)
    }

    fn from_runtime_with_retention_fence(
        runtime: ProjectionRuntime,
        retention_fence: Arc<ProjectionRetentionFence>,
    ) -> Self {
        Self::from_runtime_inner(runtime, Some(retention_fence))
    }

    fn from_runtime_inner(
        runtime: ProjectionRuntime,
        retention_fence: Option<Arc<ProjectionRetentionFence>>,
    ) -> Self {
        let durable_checkpoint = runtime.projector.state().checkpoint;
        Self {
            runtime,
            durable_checkpoint,
            // A reopened durable projection must prove this exact canonical floor once more at
            // the live provider boundary before processing resumes. This also covers a provider
            // marker that jumps from behind the floor to above it before the first poll.
            provider_recovery_floor: durable_checkpoint,
            retention_fence,
        }
    }
}

#[cfg(test)]
fn apply_durable_projection_write_until(
    writer: &StorageWriterHandle,
    write: &DurableProjectionWrite,
    deadline: Duration,
) -> eyre::Result<()> {
    apply_durable_projection_write_before(writer, write, std::time::Instant::now() + deadline)
}

fn apply_durable_projection_write_before(
    writer: &StorageWriterHandle,
    write: &DurableProjectionWrite,
    deadline: std::time::Instant,
) -> eyre::Result<()> {
    let mut last_unavailable = None;
    loop {
        if std::time::Instant::now() >= deadline {
            if let Some(source) = last_unavailable.take() {
                return Err(ProjectionWriteDeadlineError {
                    block_number: write.checkpoint.number,
                    block_hash: write.checkpoint.hash,
                    source: Some(source),
                }
                .into());
            }
        }
        match writer.apply_atomic(&write.batch) {
            Ok(()) => {
                if std::time::Instant::now() >= deadline {
                    return Err(ProjectionWriteDeadlineError {
                        block_number: write.checkpoint.number,
                        block_hash: write.checkpoint.hash,
                        source: None,
                    }
                    .into());
                }
                if let Some((overlay, generation)) = &write.overlay_ack {
                    overlay.acknowledge(*generation);
                }
                return Ok(());
            }
            Err(error)
                if error.kind() == StorageErrorKind::Unavailable
                    && std::time::Instant::now() < deadline =>
            {
                warn!(
                    %error,
                    block_number = write.checkpoint.number,
                    block_hash = %write.checkpoint.hash,
                    "offchain storage projection write failed; retrying exact atomic batch"
                );
                std::thread::sleep(
                    PROJECTION_RETRY_INTERVAL
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
                last_unavailable = Some(error);
            }
            Err(source) if source.kind() == StorageErrorKind::Unavailable => {
                return Err(ProjectionWriteDeadlineError {
                    block_number: write.checkpoint.number,
                    block_hash: write.checkpoint.hash,
                    source: Some(source),
                }
                .into());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[must_use]
pub fn projection_frame_failure_class(error: &eyre::Report) -> ProjectionFailureClass {
    if error
        .chain()
        .any(|cause| cause.is::<ProjectionWriteDeadlineError>())
    {
        return ProjectionFailureClass::MongoReconnectDeadline;
    }
    if let Some(storage) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StorageError>())
    {
        return storage_failure_class(storage);
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<outbe_offchain_data::ProjectionError>()
            .is_some()
    }) {
        ProjectionFailureClass::MalformedEvent
    } else {
        ProjectionFailureClass::Other
    }
}

fn storage_failure_class(error: &StorageError) -> ProjectionFailureClass {
    match error.kind() {
        StorageErrorKind::Corruption => ProjectionFailureClass::CorruptBody,
        StorageErrorKind::WriterLeaseLost => ProjectionFailureClass::WriterLeaseLost,
        StorageErrorKind::InvalidArgument => ProjectionFailureClass::StorageInvalidArgument,
        StorageErrorKind::Unavailable => ProjectionFailureClass::StorageUnavailable,
        StorageErrorKind::Backend => ProjectionFailureClass::StorageBackend,
        StorageErrorKind::RequestDeadline => ProjectionFailureClass::StorageRequestDeadline,
    }
}

/// Connects to offchain storage and validates storage prerequisites before Reth component initialization.
pub fn prepare_offchain_data_projection(
    config: OffchainDataProjectionConfig,
) -> eyre::Result<PreparedOffchainDataProjection> {
    prepare_offchain_data_projection_inner(config, None)
}

/// Prepares projection with the node-owned OCOMP retention selector installed on both the
/// durable preflight and logical frame sink.
pub fn prepare_offchain_data_projection_with_retention(
    config: OffchainDataProjectionConfig,
    selector: Arc<dyn TributeRetentionSelector>,
) -> eyre::Result<PreparedOffchainDataProjection> {
    prepare_offchain_data_projection_inner(config, Some(selector))
}

fn prepare_offchain_data_projection_inner(
    config: OffchainDataProjectionConfig,
    selector: Option<Arc<dyn TributeRetentionSelector>>,
) -> eyre::Result<PreparedOffchainDataProjection> {
    validate_projection_network(config.chain_id)?;
    if config.storage.start_block != 1 {
        bail!(
            "ADR-005 requires projection start_block 1, found {}",
            config.storage.start_block
        );
    }

    let started = std::time::Instant::now();
    loop {
        let remaining = PROJECTION_RECOVERY_DEADLINE.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("offchain storage startup recovery exceeded the eight-second total deadline");
        }
        let (attempt_tx, attempt_rx) = std::sync::mpsc::sync_channel(1);
        let attempt_config = config.clone();
        let attempt_selector = selector.clone();
        std::thread::Builder::new()
            .name("offchain-startup".to_owned())
            .spawn(move || {
                let _ = attempt_tx.send(prepare_projection_attempt(
                    &attempt_config,
                    attempt_selector,
                ));
            })
            .wrap_err("spawn offchain storage startup validation worker")?;
        let attempt = match attempt_rx.recv_timeout(remaining) {
            Ok(attempt) => attempt,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                bail!("offchain storage startup recovery exceeded the eight-second total deadline");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("offchain storage startup validation worker exited unexpectedly");
            }
        };
        match attempt {
            Ok((storage, overlay, projector)) => {
                let initial = match projector.state().checkpoint {
                    Some(checkpoint) => ProjectionStatus::CatchingUp {
                        checkpoint: Some(checkpoint),
                    },
                    None => ProjectionStatus::Starting,
                };
                let (readiness_publisher, readiness) = projection_readiness(
                    ProjectionCheckpoint {
                        block_number: 0,
                        block_hash: config.genesis_hash,
                    },
                    initial,
                );
                let (runtime_failure_sender, runtime_failure_receiver) =
                    tokio::sync::watch::channel(None);
                return Ok(PreparedOffchainDataProjection {
                    projector,
                    storage,
                    overlay,
                    readiness_publisher,
                    readiness,
                    runtime_failure_sender,
                    runtime_failure_receiver,
                    retention_fence: Arc::new(ProjectionRetentionFence::default()),
                });
            }
            Err(error)
                if error.is_unavailable() && started.elapsed() < PROJECTION_RECOVERY_DEADLINE =>
            {
                let remaining = PROJECTION_RECOVERY_DEADLINE.saturating_sub(started.elapsed());
                std::thread::sleep(PROJECTION_RETRY_INTERVAL.min(remaining));
            }
            Err(error) => return Err(error.into_eyre()),
        }
    }
}

fn validate_projection_network(chain_id: u64) -> eyre::Result<()> {
    if network_for_chain_id(chain_id).is_none() {
        bail!("offchain projection rejects unknown Outbe chain ID {chain_id}");
    }
    Ok(())
}

enum PrepareProjectionError {
    Storage(StorageError),
    Projection(outbe_offchain_data::ProjectionError),
}

impl PrepareProjectionError {
    fn is_unavailable(&self) -> bool {
        match self {
            Self::Storage(error)
            | Self::Projection(outbe_offchain_data::ProjectionError::Storage(error)) => {
                error.kind() == StorageErrorKind::Unavailable
            }
            Self::Projection(_) => false,
        }
    }

    fn into_eyre(self) -> eyre::Report {
        match self {
            Self::Storage(error) => eyre::Report::new(error),
            Self::Projection(error) => eyre::Report::new(error),
        }
    }
}

fn prepare_projection_attempt(
    config: &OffchainDataProjectionConfig,
    selector: Option<Arc<dyn TributeRetentionSelector>>,
) -> Result<
    (
        OpenedStorage,
        Arc<PendingOverlayStorage>,
        OffchainDataProjection,
    ),
    PrepareProjectionError,
> {
    let projection_config = ProjectionConfig {
        chain_id: config.chain_id,
        genesis_hash: config.genesis_hash,
        start_block: config.storage.start_block,
    };
    let storage = StorageProvider::new(config.storage.clone())
        .and_then(|provider| provider.open_writer())
        .map_err(PrepareProjectionError::Storage)?;
    let reader = storage.reader.clone();
    match selector.as_ref() {
        Some(selector) => OffchainDataProjection::open_with_retention_selector(
            projection_config,
            reader.clone(),
            storage.writer.clone(),
            Arc::clone(selector),
        ),
        None => {
            OffchainDataProjection::open(projection_config, reader.clone(), storage.writer.clone())
        }
    }
    .map_err(PrepareProjectionError::Projection)?;
    storage
        .writer
        .verify_transaction_capability()
        .map_err(PrepareProjectionError::Storage)?;
    gauge!("outbe_projection_storage_write_capable", "backend" => config.storage.backend_name())
        .set(1.0);
    info!(
        backend = config.storage.backend_name(),
        "offchain storage opened"
    );
    let (overlay, projector) = open_logical_projection(projection_config, reader, selector)
        .map_err(PrepareProjectionError::Projection)?;
    Ok((storage, overlay, projector))
}

fn open_logical_projection(
    projection_config: ProjectionConfig,
    durable_reader: StorageReaderHandle,
    selector: Option<Arc<dyn TributeRetentionSelector>>,
) -> Result<
    (Arc<PendingOverlayStorage>, OffchainDataProjection),
    outbe_offchain_data::ProjectionError,
> {
    let overlay = Arc::new(PendingOverlayStorage::new(durable_reader));
    let projector = match selector {
        Some(selector) => OffchainDataProjection::open_with_retention_selector(
            projection_config,
            overlay.clone(),
            overlay.clone(),
            selector,
        )?,
        None => OffchainDataProjection::open(projection_config, overlay.clone(), overlay.clone())?,
    };
    Ok((overlay, projector))
}

/// Validates a persisted checkpoint against canonical Reth state during ExEx initialization.
pub fn validate_offchain_data_checkpoint<P>(
    prepared: PreparedOffchainDataProjection,
    canonical_hashes: &P,
) -> eyre::Result<ReadyOffchainDataProjection>
where
    P: BlockHashReader + BlockIdReader,
{
    let projector = prepared.projector;
    let projection_config = ProjectionConfig {
        chain_id: projector.state().chain_id,
        genesis_hash: projector.state().genesis_hash,
        start_block: projector.state().start_block,
    };
    let overlay = prepared.overlay;
    let reader: StorageReaderHandle = overlay.clone();
    let writer = prepared.storage.writer;
    let readiness_publisher = prepared.readiness_publisher;
    let runtime_failure_sender = prepared.runtime_failure_sender;
    let runtime_failure_receiver = prepared.runtime_failure_receiver;
    let retention_fence = prepared.retention_fence;
    let writer_lease = prepared.storage.ownership;
    let local_finalized = canonical_hashes
        .finalized_block_num_hash()
        .wrap_err("read local Reth finalized checkpoint for offchain-data validation")?
        .map(|block| FinalizedTarget::new(block.number, block.hash));
    if let Some(checkpoint) = projector.state().checkpoint {
        let reconciled = require_finalized_checkpoint(checkpoint, local_finalized)?;
        match canonical_hashes
            .block_hash(checkpoint.block_number)
            .wrap_err("read canonical Reth hash for offchain-data checkpoint validation")?
        {
            Some(canonical_hash) if canonical_hash == checkpoint.block_hash => {}
            Some(canonical_hash) => return Err(eyre::eyre!(
                "offchain-data offchain storage checkpoint identity mismatch at block {}: stored {}, canonical {}",
                checkpoint.block_number,
                checkpoint.block_hash,
                canonical_hash
            )),
            None => return Err(eyre::eyre!(
                "canonical block {} for Mongo checkpoint {} is unavailable locally",
                checkpoint.block_number,
                checkpoint.block_hash
            )),
        }
        if reconciled.is_some_and(|target| checkpoint.block_number == target.number) {
            publish_status(
                &readiness_publisher,
                ProjectionStatus::Ready { checkpoint },
                local_finalized,
            );
        } else {
            publish_status(
                &readiness_publisher,
                ProjectionStatus::CatchingUp {
                    checkpoint: Some(checkpoint),
                },
                local_finalized,
            );
        }
    } else {
        let target = local_finalized.map(|block| FinalizedTarget::new(block.number, block.hash));
        let status = match target {
            Some(target) if target.number == 0 && target.hash == projection_config.genesis_hash => {
                ProjectionStatus::Ready {
                    checkpoint: ProjectionCheckpoint {
                        block_number: 0,
                        block_hash: projection_config.genesis_hash,
                    },
                }
            }
            _ => ProjectionStatus::CatchingUp { checkpoint: None },
        };
        publish_status(&readiness_publisher, status, target);
    }
    let projection_state = projector.state();
    info!(
        chain_id = projection_state.chain_id,
        genesis_hash = %projection_state.genesis_hash,
        start_block = projection_state.start_block,
        "finalized offchain-data projection ready"
    );
    Ok(ReadyOffchainDataProjection {
        projector,
        readiness_publisher,
        projection_config,
        _reader: reader,
        overlay,
        writer,
        writer_lease,
        runtime_failure_sender,
        runtime_failure_receiver,
        retention_fence,
    })
}

fn require_finalized_checkpoint(
    checkpoint: ProjectionCheckpoint,
    local_finalized: Option<FinalizedTarget>,
) -> eyre::Result<Option<FinalizedTarget>> {
    let Some(local_finalized) = local_finalized else {
        return Ok(None);
    };
    if checkpoint.block_number > local_finalized.number {
        return Ok(None);
    }
    if checkpoint.block_number == local_finalized.number
        && checkpoint.block_hash != local_finalized.hash
    {
        bail!(
            "offchain-data offchain storage checkpoint {} ({}) does not match local Reth finalized {} ({})",
            checkpoint.block_number,
            checkpoint.block_hash,
            local_finalized.number,
            local_finalized.hash
        );
    }
    Ok(Some(local_finalized))
}

/// OCOMP-specific interpretation of a durable Mongo projection checkpoint.
///
/// Unlike execution readiness, a projection may be ahead of the finalized job
/// height because Mongo is transport, not authority. Both the projection
/// checkpoint and the requested job identity are still checked against local
/// finalized canonical Reth history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OcompProjectionContainment {
    Behind {
        checkpoint: ProjectionCheckpoint,
        required: ProjectionCheckpoint,
    },
    Contains {
        checkpoint: ProjectionCheckpoint,
        required: ProjectionCheckpoint,
    },
}

pub fn ocomp_projection_contains<P>(
    checkpoint: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
    canonical: &P,
) -> eyre::Result<OcompProjectionContainment>
where
    P: BlockHashReader + BlockIdReader,
{
    let finalized = canonical
        .finalized_block_num_hash()
        .wrap_err("read local Reth finality for OCOMP projection containment")?
        .map(|block| FinalizedTarget::new(block.number, block.hash))
        .ok_or_else(|| eyre::eyre!("OCOMP projection containment has no local finalized block"))?;
    let checkpoint_hash = canonical
        .block_hash(checkpoint.block_number)
        .wrap_err("read canonical hash for OCOMP projection checkpoint")?;
    let required_hash = canonical
        .block_hash(required.block_number)
        .wrap_err("read canonical hash for OCOMP finalized job")?;
    evaluate_ocomp_projection_containment(
        checkpoint,
        required,
        finalized,
        checkpoint_hash,
        required_hash,
    )
}

fn evaluate_ocomp_projection_containment(
    checkpoint: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
    finalized: FinalizedTarget,
    checkpoint_canonical_hash: Option<B256>,
    required_canonical_hash: Option<B256>,
) -> eyre::Result<OcompProjectionContainment> {
    if checkpoint.block_number > finalized.number {
        bail!(
            "OCOMP Mongo checkpoint {} ({}) is not finalized; local finality is {} ({})",
            checkpoint.block_number,
            checkpoint.block_hash,
            finalized.number,
            finalized.hash
        );
    }
    if required.block_number > finalized.number {
        bail!(
            "OCOMP job checkpoint {} ({}) is not finalized; local finality is {} ({})",
            required.block_number,
            required.block_hash,
            finalized.number,
            finalized.hash
        );
    }
    match checkpoint_canonical_hash {
        Some(hash) if hash == checkpoint.block_hash => {}
        Some(hash) => {
            bail!(
                "OCOMP Mongo checkpoint hash conflict at {}: stored {}, canonical {}",
                checkpoint.block_number,
                checkpoint.block_hash,
                hash
            );
        }
        None => {
            bail!(
                "OCOMP Mongo checkpoint {} ({}) is unavailable in local canonical history",
                checkpoint.block_number,
                checkpoint.block_hash
            );
        }
    }
    match required_canonical_hash {
        Some(hash) if hash == required.block_hash => {}
        Some(hash) => {
            bail!(
                "OCOMP finalized job hash conflict at {}: requested {}, canonical {}",
                required.block_number,
                required.block_hash,
                hash
            );
        }
        None => {
            bail!(
                "OCOMP finalized job {} ({}) is unavailable in local canonical history",
                required.block_number,
                required.block_hash
            );
        }
    }
    if checkpoint.block_number < required.block_number {
        Ok(OcompProjectionContainment::Behind {
            checkpoint,
            required,
        })
    } else {
        Ok(OcompProjectionContainment::Contains {
            checkpoint,
            required,
        })
    }
}

struct ProjectionRuntime {
    projector: OffchainDataProjection,
    readiness_publisher: ProjectionReadinessPublisher,
    projection_config: ProjectionConfig,
    _reader: StorageReaderHandle,
    overlay: Option<Arc<PendingOverlayStorage>>,
    writer: StorageWriterHandle,
    _writer_lease: Option<StorageOwnershipGuard>,
    runtime_failure_sender: Option<tokio::sync::watch::Sender<Option<RuntimeBodyFailure>>>,
    runtime_failure_receiver: Option<tokio::sync::watch::Receiver<Option<RuntimeBodyFailure>>>,
}

impl ProjectionRuntime {
    fn new(ready: ReadyOffchainDataProjection) -> Self {
        Self {
            projector: ready.projector,
            readiness_publisher: ready.readiness_publisher,
            projection_config: ready.projection_config,
            _reader: ready._reader,
            overlay: Some(ready.overlay),
            writer: ready.writer,
            _writer_lease: Some(ready.writer_lease),
            runtime_failure_sender: Some(ready.runtime_failure_sender),
            runtime_failure_receiver: Some(ready.runtime_failure_receiver),
        }
    }
}

#[cfg(test)]
fn run_durable_projection_writer(
    writer: StorageWriterHandle,
    mut writes: tokio::sync::mpsc::UnboundedReceiver<DurableProjectionWrite>,
    durable_checkpoint_tx: tokio::sync::mpsc::UnboundedSender<FinalizedTarget>,
) {
    while let Some(write) = writes.blocking_recv() {
        apply_durable_projection_write(&writer, &write);
        if durable_checkpoint_tx.send(write.checkpoint).is_err() {
            return;
        }
    }
}

#[cfg(test)]
fn apply_durable_projection_write(writer: &StorageWriterHandle, write: &DurableProjectionWrite) {
    loop {
        match writer.apply_atomic(&write.batch) {
            Ok(()) => {
                if let Some((overlay, generation)) = &write.overlay_ack {
                    overlay.acknowledge(*generation);
                }
                return;
            }
            Err(error) => {
                warn!(
                    %error,
                    block_number = write.checkpoint.number,
                    block_hash = %write.checkpoint.hash,
                    "offchain storage projection write failed; retrying exact atomic batch"
                );
                std::thread::sleep(PROJECTION_RETRY_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
async fn supervise_projection_future<F>(
    future: F,
    publisher: ProjectionReadinessPublisher,
    projection_exit: tokio::sync::mpsc::UnboundedSender<ProjectionExit>,
) -> eyre::Result<()>
where
    F: std::future::Future<Output = eyre::Result<()>>,
{
    let message = match std::panic::AssertUnwindSafe(future).catch_unwind().await {
        Ok(Ok(())) => "offchain-data ExEx returned unexpectedly".to_owned(),
        Ok(Err(error)) => format!("offchain-data ExEx failed: {error}"),
        Err(_) => "offchain-data ExEx panicked".to_owned(),
    };
    publish_fatal(
        &publisher,
        &projection_exit,
        ProjectionFailureClass::ProjectorExited,
        message,
    );
    std::future::pending().await
}

#[cfg(test)]
async fn run_projection_loop<P, N, F>(
    provider: P,
    mut notifications: N,
    mut finalized_blocks: F,
    events: tokio::sync::mpsc::UnboundedSender<ExExEvent>,
    runtime: ProjectionRuntime,
    projection_exit: tokio::sync::mpsc::UnboundedSender<ProjectionExit>,
) -> eyre::Result<()>
where
    P: BlockIdReader + BlockReader + Clone + Send + 'static,
    N: Stream<Item = Result<(), String>> + Unpin,
    F: Stream<Item = FinalizedTarget> + Unpin,
{
    let mut runtime = runtime;
    let start_block = runtime.projector.state().start_block;
    let durable_startup_checkpoint = runtime
        .projector
        .state()
        .checkpoint
        .map(|checkpoint| FinalizedTarget::new(checkpoint.block_number, checkpoint.block_hash));
    let recovery_baseline = FinalizedTarget::new(0, runtime.projection_config.genesis_hash);
    let readiness_publisher = runtime.readiness_publisher.clone();
    let durable_writer = runtime.writer.clone();
    let mut runtime_failures = runtime
        .runtime_failure_receiver
        .take()
        .ok_or_else(|| eyre::eyre!("projection body-read failure receiver is unavailable"))?;
    let projector = Arc::new(Mutex::new(runtime));
    let (logical_checkpoint_tx, mut logical_checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
    let (durable_checkpoint_tx, mut durable_checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
    let (durable_write_tx, durable_write_rx) = tokio::sync::mpsc::unbounded_channel();
    let (recovery_ack_tx, mut recovery_ack_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("offchain-storage-writer".to_owned())
        .spawn(move || {
            run_durable_projection_writer(durable_writer, durable_write_rx, durable_checkpoint_tx);
        })
        .wrap_err("spawn offchain-data offchain storage writer")?;

    // `finalized_block_stream` emits only changes, so the current provider value must be sampled
    // separately to avoid waiting forever when the node starts at an already-finalized height.
    let initial_target = match provider.finalized_block_num_hash() {
        Ok(block) => block.map(|block| FinalizedTarget::new(block.number, block.hash)),
        Err(error) => {
            warn!(%error, "failed to sample current finalized block; retrying later");
            None
        }
    };

    let mut startup_checkpoint_floor = match (durable_startup_checkpoint, initial_target) {
        (Some(checkpoint), Some(target)) if target.number < checkpoint.number => Some(checkpoint),
        _ => None,
    };
    let initial_target = initial_target.filter(|_| startup_checkpoint_floor.is_none());
    let mut latest_target = initial_target;
    let mut pending_target = initial_target;
    let mut projection_attempt: Option<ProjectionAttempt> = None;
    let mut can_start_attempt = true;
    let mut finality_stalled = false;
    let mut notifications_open = true;
    let mut finalized_stream_open = true;
    let mut runtime_failures_open = true;
    let mut storage_unavailable_since: Option<tokio::time::Instant> = None;
    let mut immediate_recovery_used = false;

    let retry_start = tokio::time::Instant::now() + PROJECTION_RETRY_INTERVAL;
    let mut retry = tokio::time::interval_at(retry_start, PROJECTION_RETRY_INTERVAL);
    retry.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        if projection_attempt.is_none() && can_start_attempt && !finality_stalled {
            if let Some(target) = pending_target {
                let provider = provider.clone();
                let projector = Arc::clone(&projector);
                let logical_checkpoint_tx = logical_checkpoint_tx.clone();
                let durable_write_tx = durable_write_tx.clone();
                let recovery_ack_tx = recovery_ack_tx.clone();
                match spawn_detached_projection_work("offchain-projector", move || {
                    project_through_target(
                        provider,
                        &projector,
                        target,
                        &logical_checkpoint_tx,
                        &durable_write_tx,
                        &recovery_ack_tx,
                    )
                }) {
                    Ok(result_rx) => {
                        projection_attempt = Some(result_rx);
                        can_start_attempt = false;
                    }
                    Err(error) => {
                        publish_fatal(
                            &readiness_publisher,
                            &projection_exit,
                            ProjectionFailureClass::ProjectorExited,
                            format!("failed to spawn offchain-data projection worker: {error}"),
                        );
                        can_start_attempt = false;
                        finality_stalled = true;
                    }
                }
            }
        }

        tokio::select! {
            notification = notifications.next(), if notifications_open => {
                match notification {
                    Some(Ok(())) => {
                        // Receiving the notification is the required action. Canonical commit and
                        // reorg notifications never authorize off-chain writes.
                    }
                    None => {
                        notifications_open = false;
                        warn!("offchain-data ExEx notification stream closed");
                    }
                    Some(Err(error)) => {
                        // A malformed/backfill notification must not kill the ExEx. Continue
                        // polling so the manager is not backpressured by this projection.
                        warn!(%error, "failed to drain offchain-data ExEx notification");
                    }
                }
            }

            finalized = finalized_blocks.next(), if finalized_stream_open => {
                match finalized {
                    Some(target) => {
                        match admit_startup_finalized_target(&mut startup_checkpoint_floor, target) {
                            Ok(false) => continue,
                            Ok(true) => {}
                            Err(error) => {
                                publish_fatal(
                                    &readiness_publisher,
                                    &projection_exit,
                                    ProjectionFailureClass::CheckpointMismatch,
                                    error.to_string(),
                                );
                                can_start_attempt = false;
                                finality_stalled = true;
                                continue;
                            }
                        }
                        match record_or_publish_finalized_target(
                            &mut latest_target,
                            &mut pending_target,
                            target,
                            &readiness_publisher,
                            &projection_exit,
                        ) {
                            FinalizedTargetDisposition::Attempt => can_start_attempt = true,
                            FinalizedTargetDisposition::Unchanged => can_start_attempt = false,
                            FinalizedTargetDisposition::Rejected => {
                                can_start_attempt = false;
                                finality_stalled = true;
                            }
                        }
                    }
                    None => {
                        finalized_stream_open = false;
                        warn!("offchain-data finalized block stream closed");
                    }
                }
            }

            changed = runtime_failures.changed(), if runtime_failures_open && !finality_stalled => {
                match changed {
                    Ok(()) => match runtime_failures.borrow_and_update().clone() {
                    Some(RuntimeBodyFailure::Unavailable { .. }) => {
                        let since = *storage_unavailable_since
                            .get_or_insert_with(tokio::time::Instant::now);
                        publish_status(
                            &readiness_publisher,
                            ProjectionStatus::MongoUnavailable {
                                checkpoint: readiness_checkpoint(&readiness_publisher.current()),
                                since: since.into_std(),
                            },
                            latest_target,
                        );
                        gauge!("outbe_projection_storage_reconnect_active").set(1.0);
                        gauge!("outbe_projection_storage_reconnect_remaining_seconds")
                            .set(PROJECTION_RECOVERY_DEADLINE.as_secs_f64());
                        let recovery_target = latest_target.unwrap_or(recovery_baseline);
                        pending_target = Some(match pending_target {
                            Some(pending) if pending.number > recovery_target.number => pending,
                            _ => recovery_target,
                        });
                        can_start_attempt = projection_attempt.is_none();
                        immediate_recovery_used = true;
                    }
                    Some(RuntimeBodyFailure::Fatal(failure)) => {
                        publish_projection_failure(
                            &readiness_publisher,
                            &projection_exit,
                            failure,
                        );
                        finality_stalled = true;
                        can_start_attempt = false;
                    }
                    None => {}
                    },
                    Err(_) => runtime_failures_open = false,
                }
            }

            result = async {
                match projection_attempt.as_mut() {
                    Some(attempt) => attempt.await,
                    None => std::future::pending().await,
                }
            }, if projection_attempt.is_some() => {
                projection_attempt = None;
                if finality_stalled {
                    continue;
                }
                match result {
                    Ok(Ok(durable_checkpoint)) => {
                        let attempted_target = pending_target;
                        storage_unavailable_since = None;
                        immediate_recovery_used = false;
                        if pending_target.is_some_and(|pending| {
                            durable_checkpoint.map_or(
                                pending.number < start_block,
                                |checkpoint| pending.number <= checkpoint.number,
                            )
                        }) {
                            pending_target = None;
                        }
                        can_start_attempt = pending_target.is_some();
                        publish_progress(
                            &readiness_publisher,
                            durable_checkpoint
                                .map(|checkpoint| ProjectionCheckpoint {
                                    block_number: checkpoint.number,
                                    block_hash: checkpoint.hash,
                                })
                                .or_else(|| {
                                    attempted_target
                                        .filter(|target| target.number < start_block)
                                        .map(|_| ProjectionCheckpoint {
                                            block_number: recovery_baseline.number,
                                            block_hash: recovery_baseline.hash,
                                        })
                                }),
                            pending_target,
                        );
                    }
                    Ok(Err(error)) => {
                        if projection_is_unavailable(&error) {
                            let since = *storage_unavailable_since
                                .get_or_insert_with(tokio::time::Instant::now);
                            publish_status(
                                &readiness_publisher,
                                ProjectionStatus::MongoUnavailable {
                                    checkpoint: readiness_checkpoint(&readiness_publisher.current()),
                                    since: since.into_std(),
                                },
                                latest_target,
                            );
                            gauge!("outbe_projection_storage_reconnect_active").set(1.0);
                            gauge!("outbe_projection_storage_reconnect_remaining_seconds").set(
                                PROJECTION_RECOVERY_DEADLINE
                                    .saturating_sub(since.elapsed())
                                    .as_secs_f64(),
                            );
                            if since.elapsed() >= PROJECTION_RECOVERY_DEADLINE {
                                publish_fatal(
                                    &readiness_publisher,
                                    &projection_exit,
                                    ProjectionFailureClass::MongoReconnectDeadline,
                                    "offchain storage reconnect deadline expired",
                                );
                                finality_stalled = true;
                                can_start_attempt = false;
                            } else if !immediate_recovery_used {
                                immediate_recovery_used = true;
                                can_start_attempt = true;
                            } else {
                                can_start_attempt = false;
                            }
                            warn!("finalized offchain-data projection unavailable; recovery active");
                        } else {
                            error!(%error, "fatal finalized offchain-data projection failure");
                            publish_fatal(
                                &readiness_publisher,
                                &projection_exit,
                                projection_failure_class(&error),
                                error.to_string(),
                            );
                            finality_stalled = true;
                            can_start_attempt = false;
                        }
                    }
                    Err(error) => {
                        error!(%error, "finalized offchain-data projection worker failed");
                        publish_fatal(
                            &readiness_publisher,
                            &projection_exit,
                            ProjectionFailureClass::ProjectorExited,
                            "offchain-data projection worker exited unexpectedly",
                        );
                        finality_stalled = true;
                        can_start_attempt = false;
                    }
                }
            }

            checkpoint = logical_checkpoint_rx.recv(), if !finality_stalled => {
                if let Some(checkpoint) = checkpoint {
                    let projection_checkpoint = ProjectionCheckpoint {
                        block_number: checkpoint.number,
                        block_hash: checkpoint.hash,
                    };
                    let caught_up = latest_target.is_some_and(|target| target == checkpoint);
                    publish_status(&readiness_publisher, if caught_up {
                        ProjectionStatus::Ready {
                            checkpoint: projection_checkpoint,
                        }
                    } else {
                        ProjectionStatus::CatchingUp {
                            checkpoint: Some(projection_checkpoint),
                        }
                    }, latest_target);
                }
            }

            checkpoint = durable_checkpoint_rx.recv(), if !finality_stalled => {
                if let Some(checkpoint) = checkpoint {
                    let finished = (checkpoint.number, checkpoint.hash).into();
                    if events.send(ExExEvent::FinishedHeight(finished)).is_err() {
                        // The manager channel can disappear during shutdown. Returning from a
                        // critical ExEx task would turn that into a node panic, so remain alive.
                        warn!("failed to publish durable offchain-data height");
                    } else {
                        info!(
                            block_number = checkpoint.number,
                            block_hash = %checkpoint.hash,
                            "finalized offchain-data projection checkpoint advanced"
                        );
                    }
                }
            }

            recovered = recovery_ack_rx.recv(), if !finality_stalled => {
                if recovered.is_some() && storage_unavailable_since.take().is_some() {
                    immediate_recovery_used = false;
                    publish_status(
                        &readiness_publisher,
                        ProjectionStatus::CatchingUp {
                            checkpoint: readiness_checkpoint(&readiness_publisher.current()),
                        },
                        latest_target,
                    );
                    gauge!("outbe_projection_storage_reconnect_active").set(0.0);
                    gauge!("outbe_projection_storage_reconnect_remaining_seconds").set(0.0);
                }
            }

            _ = async {
                match storage_unavailable_since {
                    Some(since) => {
                        tokio::time::sleep_until(since + PROJECTION_RECOVERY_DEADLINE).await
                    }
                    None => std::future::pending().await,
                }
            }, if !finality_stalled => {
                publish_fatal(
                    &readiness_publisher,
                    &projection_exit,
                    ProjectionFailureClass::MongoReconnectDeadline,
                    "offchain storage reconnect deadline expired",
                );
                finality_stalled = true;
                can_start_attempt = false;
            }

            _ = retry.tick(), if projection_attempt.is_none() && !finality_stalled => {
                if pending_target.is_some() {
                    can_start_attempt = true;
                } else {
                    match provider.finalized_block_num_hash() {
                        Ok(Some(block)) => {
                            let target = FinalizedTarget::new(block.number, block.hash);
                            match admit_startup_finalized_target(
                                &mut startup_checkpoint_floor,
                                target,
                            ) {
                                Ok(false) => continue,
                                Ok(true) => {}
                                Err(error) => {
                                    publish_fatal(
                                        &readiness_publisher,
                                        &projection_exit,
                                        ProjectionFailureClass::CheckpointMismatch,
                                        error.to_string(),
                                    );
                                    can_start_attempt = false;
                                    finality_stalled = true;
                                    continue;
                                }
                            }
                            match record_or_publish_finalized_target(
                                &mut latest_target,
                                &mut pending_target,
                                target,
                                &readiness_publisher,
                                &projection_exit,
                            ) {
                                FinalizedTargetDisposition::Attempt => can_start_attempt = true,
                                FinalizedTargetDisposition::Unchanged => can_start_attempt = false,
                                FinalizedTargetDisposition::Rejected => {
                                    can_start_attempt = false;
                                    finality_stalled = true;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%error, "failed to sample current finalized block; retrying later");
                        }
                    }
                }
            }

            // Keep the critical ExEx task alive even if its input channels have closed. A normal
            // return from an installed ExEx is treated as a critical task failure by Reth.
            () = std::future::pending::<()>() => {}
        }
    }
}

fn readiness_checkpoint(status: &ProjectionStatus) -> Option<ProjectionCheckpoint> {
    match status {
        ProjectionStatus::CatchingUp { checkpoint }
        | ProjectionStatus::MongoUnavailable { checkpoint, .. } => *checkpoint,
        ProjectionStatus::Ready { checkpoint } => Some(*checkpoint),
        ProjectionStatus::Fatal { checkpoint, .. } => *checkpoint,
        ProjectionStatus::Starting => None,
    }
}

#[cfg(test)]
fn publish_progress(
    publisher: &ProjectionReadinessPublisher,
    checkpoint: Option<ProjectionCheckpoint>,
    pending: Option<FinalizedTarget>,
) {
    let caught_up = match (checkpoint, pending) {
        (Some(checkpoint), Some(pending)) => {
            checkpoint.block_number == pending.number && checkpoint.block_hash == pending.hash
        }
        (Some(_), None) => true,
        (None, _) => false,
    };
    publish_status(
        publisher,
        match (caught_up, checkpoint) {
            (true, Some(checkpoint)) => ProjectionStatus::Ready { checkpoint },
            (_, checkpoint) => ProjectionStatus::CatchingUp { checkpoint },
        },
        pending,
    );
}

#[cfg(test)]
fn publish_fatal(
    publisher: &ProjectionReadinessPublisher,
    exit: &tokio::sync::mpsc::UnboundedSender<ProjectionExit>,
    class: ProjectionFailureClass,
    message: impl Into<Arc<str>>,
) {
    let failure = ProjectionFailure::new(class, message);
    publish_projection_failure(publisher, exit, failure);
}

#[cfg(test)]
fn publish_projection_failure(
    publisher: &ProjectionReadinessPublisher,
    exit: &tokio::sync::mpsc::UnboundedSender<ProjectionExit>,
    failure: ProjectionFailure,
) {
    let class = failure.class;
    let checkpoint = readiness_checkpoint(&publisher.current());
    publish_status(
        publisher,
        ProjectionStatus::Fatal {
            checkpoint,
            error: failure.clone(),
        },
        None,
    );
    counter!("outbe_projection_failures_total", "class" => format!("{class:?}")).increment(1);
    let _ = exit.send(ProjectionExit { failure });
}

fn publish_status(
    publisher: &ProjectionReadinessPublisher,
    status: ProjectionStatus,
    target: Option<FinalizedTarget>,
) {
    let (status_code, ready) = match &status {
        ProjectionStatus::Starting => (0.0, 0.0),
        ProjectionStatus::CatchingUp { .. } => (1.0, 0.0),
        ProjectionStatus::MongoUnavailable { .. } => (2.0, 0.0),
        ProjectionStatus::Ready { .. } => (3.0, 1.0),
        ProjectionStatus::Fatal { .. } => (4.0, 0.0),
    };
    gauge!("outbe_projection_status").set(status_code);
    gauge!("outbe_projection_readiness").set(ready);
    gauge!("outbe_projection_validator_participation_gate").set(ready);
    if let Some(checkpoint) = readiness_checkpoint(&status) {
        gauge!("outbe_projection_checkpoint_number").set(checkpoint.block_number as f64);
        if let Some(target) = target {
            gauge!("outbe_projection_lag_blocks")
                .set(target.number.saturating_sub(checkpoint.block_number) as f64);
        }
    }
    if ready > 0.0 {
        gauge!("outbe_projection_storage_reconnect_active").set(0.0);
        gauge!("outbe_projection_storage_reconnect_remaining_seconds").set(0.0);
    }
    publisher.publish(status);
}

#[cfg(test)]
fn projection_is_unavailable(error: &eyre::Report) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<StorageError>()
            .is_some_and(|storage| storage.kind() == StorageErrorKind::Unavailable)
    })
}

#[cfg(test)]
fn projection_failure_class(error: &eyre::Report) -> ProjectionFailureClass {
    if let Some(storage) = error
        .chain()
        .find_map(|source| source.downcast_ref::<StorageError>())
    {
        return match storage.kind() {
            StorageErrorKind::Corruption => ProjectionFailureClass::CorruptBody,
            StorageErrorKind::WriterLeaseLost => ProjectionFailureClass::WriterLeaseLost,
            StorageErrorKind::InvalidArgument => ProjectionFailureClass::StorageInvalidArgument,
            StorageErrorKind::Unavailable => ProjectionFailureClass::StorageUnavailable,
            StorageErrorKind::Backend => ProjectionFailureClass::StorageBackend,
            StorageErrorKind::RequestDeadline => ProjectionFailureClass::StorageRequestDeadline,
        };
    }
    if error.chain().any(|source| {
        source
            .downcast_ref::<outbe_offchain_data::ProjectionError>()
            .is_some()
    }) {
        ProjectionFailureClass::MalformedEvent
    } else if error.chain().any(|source| {
        source
            .downcast_ref::<HistoricalProjectionDataError>()
            .is_some()
    }) {
        ProjectionFailureClass::HistoricalReceiptsUnavailable
    } else {
        ProjectionFailureClass::Other
    }
}

#[cfg(test)]
fn record_finalized_target(
    latest: &mut Option<FinalizedTarget>,
    pending: &mut Option<FinalizedTarget>,
    incoming: FinalizedTarget,
) -> eyre::Result<bool> {
    match *latest {
        Some(current) if incoming.number < current.number => Err(eyre::eyre!(
            "finalized target regressed from {} ({}) to {} ({})",
            current.number,
            current.hash,
            incoming.number,
            incoming.hash
        )),
        Some(current) if incoming.number == current.number && incoming.hash != current.hash => {
            Err(eyre::eyre!(
                "finalized target hash changed at height {}: {} -> {}",
                current.number,
                current.hash,
                incoming.hash
            ))
        }
        Some(current) if incoming == current => Ok(pending.is_some()),
        _ => {
            *latest = Some(incoming);
            *pending = Some(incoming);
            Ok(true)
        }
    }
}

/// During crash recovery Mongo can durably commit finalized block N just before
/// Reth persists its finalized marker for N. Ignore the stale N-1 marker until
/// Reth reaches the already-canonical Mongo checkpoint; never accept a conflict
/// at the checkpoint height.
#[cfg(test)]
fn admit_startup_finalized_target(
    startup_floor: &mut Option<FinalizedTarget>,
    incoming: FinalizedTarget,
) -> eyre::Result<bool> {
    let Some(floor) = *startup_floor else {
        return Ok(true);
    };
    if incoming.number < floor.number {
        return Ok(false);
    }
    if incoming.number == floor.number && incoming.hash != floor.hash {
        bail!(
            "finalized target conflicts with recovered projection checkpoint at height {}: {} != {}",
            floor.number,
            incoming.hash,
            floor.hash
        );
    }
    *startup_floor = None;
    Ok(true)
}

#[cfg(test)]
fn record_or_publish_finalized_target(
    latest: &mut Option<FinalizedTarget>,
    pending: &mut Option<FinalizedTarget>,
    incoming: FinalizedTarget,
    publisher: &ProjectionReadinessPublisher,
    exit: &tokio::sync::mpsc::UnboundedSender<ProjectionExit>,
) -> FinalizedTargetDisposition {
    match record_finalized_target(latest, pending, incoming) {
        Ok(true) => FinalizedTargetDisposition::Attempt,
        Ok(false) => FinalizedTargetDisposition::Unchanged,
        Err(error) => {
            error!(%error, "rejected unsafe finalized projection target");
            publish_fatal(
                publisher,
                exit,
                ProjectionFailureClass::CheckpointMismatch,
                error.to_string(),
            );
            FinalizedTargetDisposition::Rejected
        }
    }
}

#[cfg(test)]
fn project_through_target<P>(
    provider: P,
    runtime: &Mutex<ProjectionRuntime>,
    target: FinalizedTarget,
    logical_checkpoint_tx: &tokio::sync::mpsc::UnboundedSender<FinalizedTarget>,
    durable_write_tx: &tokio::sync::mpsc::UnboundedSender<DurableProjectionWrite>,
    recovery_ack_tx: &tokio::sync::mpsc::UnboundedSender<()>,
) -> eyre::Result<Option<FinalizedTarget>>
where
    P: BlockReader,
{
    // Only one worker is launched at a time. The mutex also makes that ownership explicit and
    // keeps the mutable projector state available across retry attempts.
    let mut runtime = runtime
        .lock()
        .map_err(|_| eyre::eyre!("offchain-data projector lock is poisoned"))?;
    let overlay = runtime.overlay.clone();
    let projector = &mut runtime.projector;
    let state = projector.state();
    let checkpoint = state.checkpoint;
    let start_block = state.start_block;

    if let Some(checkpoint) = checkpoint {
        let canonical_hash = provider
            .block_hash(checkpoint.block_number)
            .wrap_err_with(|| {
                format!(
                    "load canonical hash for restored projection checkpoint {}",
                    checkpoint.block_number
                )
            })?
            .ok_or_else(|| {
                eyre::eyre!(
                    "canonical block {} for restored projection checkpoint is unavailable",
                    checkpoint.block_number
                )
            })?;
        if canonical_hash != checkpoint.block_hash {
            bail!(
                "projection checkpoint hash {} conflicts with canonical hash {} at height {}",
                checkpoint.block_hash,
                canonical_hash,
                checkpoint.block_number
            );
        }
    }
    recovery_ack_tx
        .send(())
        .map_err(|_| eyre::eyre!("projection recovery acknowledgement receiver is closed"))?;

    let first_block = match checkpoint {
        Some(checkpoint) if checkpoint.block_number > target.number => {
            return Err(eyre::eyre!(
                "projection checkpoint {} ({}) is ahead of finalized target {} ({})",
                checkpoint.block_number,
                checkpoint.block_hash,
                target.number,
                target.hash
            ))
        }
        Some(checkpoint)
            if checkpoint.block_number == target.number && checkpoint.block_hash != target.hash =>
        {
            return Err(eyre::eyre!(
                "projection checkpoint hash {} conflicts with finalized hash {} at height {}",
                checkpoint.block_hash,
                target.hash,
                target.number
            ));
        }
        Some(checkpoint) if checkpoint.block_number == target.number => {
            let checkpoint = FinalizedTarget::new(checkpoint.block_number, checkpoint.block_hash);
            logical_checkpoint_tx
                .send(checkpoint)
                .map_err(|_| eyre::eyre!("logical checkpoint receiver is closed"))?;
            return Ok(Some(checkpoint));
        }
        Some(checkpoint) => checkpoint
            .block_number
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("projection checkpoint height overflow"))?,
        None => start_block,
    };

    if first_block > target.number {
        // A fresh projector intentionally does no work before its configured start height. There
        // is no durable checkpoint yet, so the caller must not emit FinishedHeight.
        return Ok(None);
    }

    let mut durable_checkpoint = None;
    for block_number in first_block..=target.number {
        let canonical_hash = provider
            .block_hash(block_number)
            .wrap_err_with(|| format!("load canonical hash for block {block_number}"))?
            .ok_or(HistoricalProjectionDataError::CanonicalBlock { block_number })?;
        let block = provider
            .block_by_hash(canonical_hash)
            .wrap_err_with(|| format!("load canonical block {block_number} ({canonical_hash})"))?
            .ok_or(HistoricalProjectionDataError::CanonicalBlockByHash {
                block_number,
                block_hash: canonical_hash,
            })?;

        if block.header().number() != block_number {
            bail!(
                "provider returned block {} while canonical block {} was requested",
                block.header().number(),
                block_number
            );
        }
        let block_hash = block.header().hash_slow();
        if block_hash != canonical_hash {
            bail!(
                "block loaded for canonical hash {} recomputed to {} at height {}",
                canonical_hash,
                block_hash,
                block_number
            );
        }
        if block_number == target.number && block_hash != target.hash {
            bail!(
                "canonical block hash {} conflicts with finalized hash {} at height {}",
                block_hash,
                target.hash,
                block_number
            );
        }

        let receipts = provider
            .receipts_by_block(block_hash.into())
            .wrap_err_with(|| format!("load receipts for canonical block {block_number}"))?
            .ok_or(HistoricalProjectionDataError::Receipts { block_number })?;
        let normalized = normalize_finalized_block(block_number, block_hash, &block, &receipts)?;

        let prepared = projector
            .prepare_block(&normalized)
            .wrap_err_with(|| format!("project finalized block {block_number}"))?;
        let (projected, durable_batch) = projector
            .apply_prepared_with_batch(prepared)
            .wrap_err_with(|| format!("apply logical finalized block {block_number}"))?;
        let projected = match projected {
            ProjectionOutcome::Applied { checkpoint, .. }
            | ProjectionOutcome::AlreadyApplied(checkpoint) => checkpoint,
        };
        if projected.block_number != block_number || projected.block_hash != block_hash {
            bail!(
                "projector returned checkpoint {} ({}) after projecting {} ({})",
                projected.block_number,
                projected.block_hash,
                block_number,
                block_hash
            );
        }
        durable_checkpoint = Some(FinalizedTarget::new(
            projected.block_number,
            projected.block_hash,
        ));
        let overlay_ack = overlay
            .as_ref()
            .map(|overlay| (Arc::clone(overlay), overlay.current_generation()));
        durable_write_tx
            .send(DurableProjectionWrite {
                checkpoint: FinalizedTarget::new(projected.block_number, projected.block_hash),
                batch: durable_batch,
                overlay_ack,
            })
            .map_err(|_| eyre::eyre!("durable offchain storage writer queue is closed"))?;
        logical_checkpoint_tx
            .send(FinalizedTarget::new(
                projected.block_number,
                projected.block_hash,
            ))
            .map_err(|_| eyre::eyre!("logical checkpoint receiver is closed"))?;
    }

    Ok(durable_checkpoint)
}

fn normalize_finalized_block<B, R>(
    block_number: u64,
    block_hash: B256,
    block: &B,
    receipts: &[R],
) -> eyre::Result<FinalizedBlock>
where
    B: Block,
    R: RethReceipt,
{
    let transactions = block.body().transactions();
    if transactions.len() != receipts.len() {
        bail!(
            "canonical block {} has {} transactions but {} receipts",
            block_number,
            transactions.len(),
            receipts.len()
        );
    }

    let mut normalized_receipts = Vec::with_capacity(receipts.len());
    let mut next_log_index = 0_u64;
    for (transaction_index, (transaction, receipt)) in transactions.iter().zip(receipts).enumerate()
    {
        let transaction_index = u64::try_from(transaction_index)
            .map_err(|_| eyre::eyre!("transaction index does not fit u64"))?;
        let mut logs = Vec::with_capacity(receipt.logs().len());
        for log in receipt.logs() {
            logs.push(FinalizedLog {
                log_index: next_log_index,
                emitter: log.address,
                data: log.data.clone(),
            });
            next_log_index = next_log_index
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("block-global log index overflow"))?;
        }
        normalized_receipts.push(FinalizedReceipt {
            tx_hash: *transaction.tx_hash(),
            transaction_index,
            success: receipt.status(),
            // Every log is retained in receipt order, including unrelated logs, so these indices
            // remain the canonical block-global indices.
            logs,
        });
    }

    Ok(FinalizedBlock {
        number: block_number,
        hash: block_hash,
        receipts: normalized_receipts,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use super::{
        apply_durable_projection_write_before, apply_durable_projection_write_until,
        evaluate_ocomp_projection_containment, prepare_offchain_data_projection,
        project_through_target, projection_failure_class, projection_frame_failure_class,
        record_finalized_target, record_or_publish_finalized_target, require_finalized_checkpoint,
        run_projection_loop, spawn_detached_projection_work, supervise_projection_future,
        validate_projection_network, DurableProjectionWrite, FinalizedProjectionSink,
        FinalizedTarget, FinalizedTargetReconciliationV1, OcompProjectionContainment,
        OffchainDataProjectionConfig, ProjectionRetentionFence, ProjectionRuntime,
        ProjectionRuntimeRecoveryHandle, ProjectionRuntimeRecoveryV1, ProjectionWriteDeadlineError,
        RuntimeBodyFailure, PROJECTION_RECOVERY_DEADLINE,
    };
    use alloy_consensus::Header;
    use alloy_eips::BlockNumHash;
    use alloy_primitives::B256;
    use outbe_offchain_data::{
        FinalizedBlock, OffchainDataProjection, ProjectionConfig, ProjectionFailure,
        ProjectionFailureClass,
    };
    use outbe_offchain_storage::{
        AtomicWriteBatch, AtomicWriteOperation, Key, MemoryStorage, Namespace,
        PendingOverlayStorage, ScanPage, ScanRequest, StorageError, StorageReader,
        StorageReaderHandle, StorageWriter, StorageWriterHandle, StoredValue,
    };
    use reth_ethereum::{exex::ExExEvent, Block};
    use reth_provider::test_utils::MockEthProvider;

    use crate::finalized_frame::{read_bounded_finalized_frames, RethFinalizedFrameSource};

    use outbe_primitives::projection::{
        projection_readiness, ProjectionCheckpoint, ProjectionStatus, WaitOutcome,
    };

    fn checkpoint(number: u64, byte: u8) -> ProjectionCheckpoint {
        ProjectionCheckpoint {
            block_number: number,
            block_hash: B256::repeat_byte(byte),
        }
    }

    #[test]
    fn ocomp_projection_containment_accepts_exact_and_ahead_but_reports_behind() {
        let required = checkpoint(10, 0x10);
        let finalized = FinalizedTarget::new(20, B256::repeat_byte(0x20));

        let behind = checkpoint(9, 0x09);
        assert_eq!(
            evaluate_ocomp_projection_containment(
                behind,
                required,
                finalized,
                Some(behind.block_hash),
                Some(required.block_hash),
            )
            .unwrap(),
            OcompProjectionContainment::Behind {
                checkpoint: behind,
                required,
            }
        );

        for contained in [required, checkpoint(15, 0x15)] {
            assert_eq!(
                evaluate_ocomp_projection_containment(
                    contained,
                    required,
                    finalized,
                    Some(contained.block_hash),
                    Some(required.block_hash),
                )
                .unwrap(),
                OcompProjectionContainment::Contains {
                    checkpoint: contained,
                    required,
                }
            );
        }
    }

    #[test]
    fn ocomp_projection_containment_rejects_unfinalized_or_conflicting_history() {
        let required = checkpoint(10, 0x10);
        let projection = checkpoint(15, 0x15);
        let finalized = FinalizedTarget::new(20, B256::repeat_byte(0x20));

        assert!(evaluate_ocomp_projection_containment(
            projection,
            required,
            finalized,
            Some(B256::repeat_byte(0xEE)),
            Some(required.block_hash),
        )
        .is_err());
        assert!(evaluate_ocomp_projection_containment(
            projection,
            required,
            finalized,
            Some(projection.block_hash),
            Some(B256::repeat_byte(0xEE)),
        )
        .is_err());
        assert!(evaluate_ocomp_projection_containment(
            checkpoint(21, 0x21),
            required,
            finalized,
            Some(B256::repeat_byte(0x21)),
            Some(required.block_hash),
        )
        .is_err());
    }

    #[tokio::test]
    async fn ocomp_ahead_containment_does_not_change_execution_readiness_semantics() {
        let required = checkpoint(10, 0x10);
        let ahead = checkpoint(15, 0x15);
        let (_publisher, readiness) = projection_readiness(
            checkpoint(0, 0x01),
            ProjectionStatus::Ready { checkpoint: ahead },
        );

        assert_eq!(
            readiness.wait_for(required, std::future::pending()).await,
            WaitOutcome::ProjectionAhead
        );
        assert!(matches!(
            evaluate_ocomp_projection_containment(
                ahead,
                required,
                FinalizedTarget::new(20, B256::repeat_byte(0x20)),
                Some(ahead.block_hash),
                Some(required.block_hash),
            )
            .unwrap(),
            OcompProjectionContainment::Contains { .. }
        ));
    }

    #[test]
    fn finalized_targets_coalesce_to_the_latest_height() {
        let first = FinalizedTarget::new(10, B256::repeat_byte(1));
        let second = FinalizedTarget::new(12, B256::repeat_byte(2));
        let mut latest = Some(first);
        let mut pending = Some(first);

        assert!(record_finalized_target(&mut latest, &mut pending, second).unwrap());
        assert_eq!(latest, Some(second));
        assert_eq!(pending, Some(second));
    }

    #[test]
    fn startup_rejects_unavailable_mongodb_before_exex_runs() {
        let started = std::time::Instant::now();
        drop(
            prepare_offchain_data_projection(OffchainDataProjectionConfig {
                chain_id: outbe_primitives::chain::DEVNET_CHAIN_ID,
                genesis_hash: B256::repeat_byte(0x11),
                storage: outbe_offchain_storage::StorageConfig {
                    start_block: 1,
                    backend: outbe_offchain_storage::StorageBackend::MongoDb(outbe_offchain_storage::MongoStorageConfig {
                        uri: "mongodb://127.0.0.1:1/?directConnection=true&serverSelectionTimeoutMS=50".to_owned(),
                        database: "startup_unavailable".to_owned(),
                    }),
                },
            })
            .err()
            .expect("unavailable MongoDB must fail startup preparation"),
        );
        assert!(
            started.elapsed() >= PROJECTION_RECOVERY_DEADLINE,
            "startup returned before the shared reconnect deadline"
        );
        assert!(
            started.elapsed() <= PROJECTION_RECOVERY_DEADLINE + Duration::from_millis(250),
            "startup exceeded the shared reconnect deadline"
        );
    }

    #[test]
    fn finalized_target_regression_is_rejected() {
        let current = FinalizedTarget::new(10, B256::repeat_byte(1));
        let mut latest = Some(current);
        let mut pending = Some(current);

        let error = record_finalized_target(
            &mut latest,
            &mut pending,
            FinalizedTarget::new(9, B256::repeat_byte(2)),
        )
        .unwrap_err();

        assert!(error.to_string().contains("regressed"));
        assert_eq!(latest, Some(current));
        assert_eq!(pending, Some(current));
    }

    #[test]
    fn conflicting_hash_at_same_finalized_height_is_rejected() {
        let current = FinalizedTarget::new(10, B256::repeat_byte(1));
        let mut latest = Some(current);
        let mut pending = Some(current);

        let error = record_finalized_target(
            &mut latest,
            &mut pending,
            FinalizedTarget::new(10, B256::repeat_byte(2)),
        )
        .unwrap_err();

        assert!(error.to_string().contains("hash changed"));
        assert_eq!(latest, Some(current));
        assert_eq!(pending, Some(current));
    }

    #[test]
    fn unchanged_finalized_target_is_retryable_only_while_pending() {
        let current = FinalizedTarget::new(10, B256::repeat_byte(1));
        let mut latest = Some(current);
        let mut pending = Some(current);

        assert!(record_finalized_target(&mut latest, &mut pending, current).unwrap());
        assert_eq!(pending, Some(current));

        pending = None;
        assert!(!record_finalized_target(&mut latest, &mut pending, current).unwrap());

        assert_eq!(latest, Some(current));
        assert_eq!(pending, None);
    }

    #[test]
    fn finalized_target_conflict_publishes_fatal_exit_on_every_ingress_path() {
        let current = FinalizedTarget::new(10, B256::repeat_byte(1));
        let mut latest = Some(current);
        let mut pending = None;
        let checkpoint = ProjectionCheckpoint {
            block_number: current.number,
            block_hash: current.hash,
        };
        let (publisher, readiness) = projection_readiness(
            checkpoint,
            outbe_offchain_data::ProjectionStatus::Ready { checkpoint },
        );
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();

        assert_eq!(
            record_or_publish_finalized_target(
                &mut latest,
                &mut pending,
                FinalizedTarget::new(10, B256::repeat_byte(2)),
                &publisher,
                &exit_tx,
            ),
            super::FinalizedTargetDisposition::Rejected
        );
        assert!(matches!(
            readiness.current(),
            outbe_offchain_data::ProjectionStatus::Fatal { error, .. }
                if error.class == ProjectionFailureClass::CheckpointMismatch
        ));
        assert_eq!(
            exit_rx.try_recv().unwrap().failure.class,
            ProjectionFailureClass::CheckpointMismatch,
        );
    }

    #[test]
    fn startup_checkpoint_floor_ignores_stale_finality_then_releases() {
        let checkpoint = FinalizedTarget::new(4, B256::repeat_byte(0x44));
        let mut floor = Some(checkpoint);

        assert!(!super::admit_startup_finalized_target(
            &mut floor,
            FinalizedTarget::new(3, B256::repeat_byte(0x33)),
        )
        .unwrap());
        assert_eq!(floor, Some(checkpoint));

        let error = super::admit_startup_finalized_target(
            &mut floor,
            FinalizedTarget::new(4, B256::repeat_byte(0x45)),
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts"));
        assert_eq!(floor, Some(checkpoint));

        assert!(super::admit_startup_finalized_target(&mut floor, checkpoint).unwrap());
        assert_eq!(floor, None);
    }

    #[test]
    fn persisted_checkpoint_waits_for_reth_finality_marker_recovery() {
        let checkpoint = ProjectionCheckpoint {
            block_number: 4,
            block_hash: B256::repeat_byte(0x44),
        };
        assert_eq!(
            require_finalized_checkpoint(checkpoint, None).unwrap(),
            None
        );

        assert_eq!(
            require_finalized_checkpoint(
                checkpoint,
                Some(FinalizedTarget::new(3, B256::repeat_byte(0x33))),
            )
            .expect("one-block crash-consistency gap must recover"),
            None,
        );

        assert_eq!(
            require_finalized_checkpoint(
                checkpoint,
                Some(FinalizedTarget::new(2, B256::repeat_byte(0x22))),
            )
            .expect("a transiently stale finality marker must recover"),
            None,
        );

        let error = require_finalized_checkpoint(
            checkpoint,
            Some(FinalizedTarget::new(4, B256::repeat_byte(0x45))),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match local Reth finalized"));

        assert_eq!(
            require_finalized_checkpoint(
                checkpoint,
                Some(FinalizedTarget::new(4, checkpoint.block_hash)),
            )
            .unwrap(),
            Some(FinalizedTarget::new(4, checkpoint.block_hash)),
        );

        let ahead = FinalizedTarget::new(5, B256::repeat_byte(0x55));
        assert_eq!(
            require_finalized_checkpoint(checkpoint, Some(ahead)).unwrap(),
            Some(ahead),
        );
    }

    #[test]
    fn dropping_projection_waiter_never_waits_for_blocked_backend_work() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let receiver = spawn_detached_projection_work("projection-shutdown-test", move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        })
        .unwrap();
        started_rx.recv().unwrap();

        let started = std::time::Instant::now();
        drop(receiver);
        assert!(started.elapsed() < Duration::from_millis(50));
        release_tx.send(()).unwrap();
    }

    #[test]
    fn node_runtime_opens_logical_projection_over_pending_overlay() {
        let durable = Arc::new(MemoryStorage::new());
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        OffchainDataProjection::open(projection_config, durable.clone(), durable.clone()).unwrap();
        let durable_reader: StorageReaderHandle = durable.clone();
        let (overlay, mut projector) =
            super::open_logical_projection(projection_config, durable_reader, None).unwrap();
        let block = FinalizedBlock {
            number: 1,
            hash: B256::repeat_byte(0x22),
            receipts: Vec::new(),
        };

        projector.project_block(&block).unwrap();

        assert_eq!(projector.state().checkpoint.unwrap().block_number, 1);
        assert_eq!(
            outbe_offchain_data::read_projection_state(projection_config, durable)
                .unwrap()
                .unwrap()
                .checkpoint,
            None,
            "the durable Mongo-shaped base must not be written by the logical projector"
        );
        assert_eq!(
            outbe_offchain_data::read_projection_state(projection_config, overlay)
                .unwrap()
                .unwrap()
                .checkpoint
                .unwrap()
                .block_number,
            1
        );
    }

    #[test]
    fn projects_each_intermediate_block_and_reports_each_durable_checkpoint() {
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let first = add_empty_block(&provider, 1);
        let second = add_empty_block(&provider, 2);
        let runtime = initialized_runtime(1);
        let (logical_tx, mut logical_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();
        let (recovery_tx, _recovery_rx) = tokio::sync::mpsc::unbounded_channel();

        let result = project_through_target(
            provider,
            &runtime,
            FinalizedTarget::new(2, second),
            &logical_tx,
            &write_tx,
            &recovery_tx,
        )
        .unwrap();

        assert_eq!(result, Some(FinalizedTarget::new(2, second)));
        assert_eq!(
            logical_rx.try_recv().unwrap(),
            FinalizedTarget::new(1, first)
        );
        assert_eq!(
            logical_rx.try_recv().unwrap(),
            FinalizedTarget::new(2, second)
        );
        assert_eq!(
            write_rx.try_recv().unwrap().checkpoint,
            FinalizedTarget::new(1, first)
        );
        assert_eq!(
            write_rx.try_recv().unwrap().checkpoint,
            FinalizedTarget::new(2, second)
        );
        assert!(write_rx.try_recv().is_err());
        let state = runtime.lock().unwrap();
        let checkpoint = state.projector.state().checkpoint.unwrap();
        assert_eq!(checkpoint.block_number, 2);
        assert_eq!(checkpoint.block_hash, second);
    }

    #[test]
    fn frame_sink_returns_only_after_the_exact_durable_write_finishes() {
        let (durable, write_started, release_write, _write_finished) = BlockingWriteStorage::new();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        OffchainDataProjection::open(projection_config, durable.clone(), durable.clone()).unwrap();
        let overlay = Arc::new(PendingOverlayStorage::new(durable.clone()));
        let reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let durable_writer: StorageWriterHandle = durable.clone();
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), logical_writer)
                .unwrap();
        let (readiness_publisher, _readiness) = projection_readiness(
            ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            ProjectionStatus::Starting,
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let mut sink = FinalizedProjectionSink::from_runtime(ProjectionRuntime {
            projector,
            readiness_publisher,
            projection_config,
            _reader: reader,
            overlay: Some(overlay),
            writer: durable_writer,
            _writer_lease: None,
            runtime_failure_sender: Some(runtime_failure_tx),
            runtime_failure_receiver: Some(runtime_failure_rx),
        });
        let frame = empty_finalized_frame(1, 1);
        durable.block_next_write.store(true, Ordering::Release);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let sink_thread = std::thread::spawn(move || {
            let result = sink.project_frame(&frame);
            let _ = result_tx.send(result);
        });

        write_started
            .recv_timeout(Duration::from_secs(1))
            .expect("the sink must submit the exact durable batch");
        assert!(matches!(
            result_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release_write.send(()).unwrap();
        let checkpoint = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the sink must return after durable commit")
            .unwrap();
        sink_thread.join().unwrap();

        assert_eq!(checkpoint.block_number, 1);
        assert_eq!(
            outbe_offchain_data::read_projection_state(projection_config, durable)
                .unwrap()
                .unwrap()
                .checkpoint,
            Some(checkpoint)
        );
    }

    #[test]
    fn frame_sink_accepts_restart_replay_below_durable_p_and_rejects_conflicting_p() {
        let storage = Arc::new(MemoryStorage::new());
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        OffchainDataProjection::open(projection_config, storage.clone(), storage.clone()).unwrap();
        let overlay = Arc::new(PendingOverlayStorage::new(storage.clone()));
        let reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let durable_writer: StorageWriterHandle = storage.clone();
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), logical_writer)
                .unwrap();
        let (readiness_publisher, readiness) = projection_readiness(
            ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            ProjectionStatus::Starting,
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let mut sink = FinalizedProjectionSink::from_runtime(ProjectionRuntime {
            projector,
            readiness_publisher,
            projection_config,
            _reader: reader,
            overlay: Some(overlay),
            writer: durable_writer,
            _writer_lease: None,
            runtime_failure_sender: Some(runtime_failure_tx),
            runtime_failure_receiver: Some(runtime_failure_rx),
        });
        let first = empty_finalized_frame(1, 1);
        let second = empty_finalized_frame(2, 2);
        let conflicting_second = empty_finalized_frame(2, 3);
        let first_target = ProjectionCheckpoint {
            block_number: first.identity().number,
            block_hash: first.identity().hash,
        };

        assert_eq!(
            sink.reconcile_finalized_target(Some(first_target)).unwrap(),
            FinalizedTargetReconciliationV1::Process {
                target: first_target,
                recovered_floor: None,
            },
        );
        assert_eq!(
            sink.reconcile_finalized_target(None).unwrap(),
            FinalizedTargetReconciliationV1::AwaitingProviderRecovery,
        );
        assert_eq!(
            readiness.current(),
            ProjectionStatus::CatchingUp { checkpoint: None }
        );

        let first_checkpoint = sink.project_frame(&first).unwrap();
        sink.publish_progress(ProjectionCheckpoint {
            block_number: second.identity().number,
            block_hash: second.identity().hash,
        })
        .unwrap();
        assert_eq!(
            readiness.current(),
            ProjectionStatus::CatchingUp {
                checkpoint: Some(first_checkpoint),
            }
        );
        let durable_p = sink.project_frame(&second).unwrap();
        sink.publish_progress(durable_p).unwrap();
        assert_eq!(
            readiness.current(),
            ProjectionStatus::Ready {
                checkpoint: durable_p,
            }
        );

        assert_eq!(
            sink.reconcile_finalized_target(None).unwrap(),
            FinalizedTargetReconciliationV1::AwaitingProviderRecovery,
        );
        assert_eq!(
            readiness.current(),
            ProjectionStatus::CatchingUp {
                checkpoint: Some(durable_p),
            }
        );
        assert_eq!(
            sink.reconcile_finalized_target(Some(first_checkpoint))
                .unwrap(),
            FinalizedTargetReconciliationV1::AwaitingProviderRecovery,
        );
        assert_eq!(
            sink.reconcile_finalized_target(Some(durable_p)).unwrap(),
            FinalizedTargetReconciliationV1::Process {
                target: durable_p,
                recovered_floor: Some(durable_p),
            },
        );
        sink.publish_progress(durable_p).unwrap();
        assert_eq!(
            readiness.current(),
            ProjectionStatus::Ready {
                checkpoint: durable_p,
            }
        );
        assert!(sink
            .reconcile_finalized_target(Some(ProjectionCheckpoint {
                block_number: durable_p.block_number,
                block_hash: B256::repeat_byte(0xff),
            }))
            .is_err());

        assert_eq!(sink.project_frame(&first).unwrap(), durable_p);
        let error = sink.project_frame(&conflicting_second).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicts with durable projection hash"));
        assert_eq!(sink.durable_checkpoint(), Some(durable_p));

        drop(sink);
        let overlay = Arc::new(PendingOverlayStorage::new(storage.clone()));
        let reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let durable_writer: StorageWriterHandle = storage;
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), logical_writer)
                .unwrap();
        let (readiness_publisher, _readiness) = projection_readiness(
            ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            ProjectionStatus::CatchingUp {
                checkpoint: Some(durable_p),
            },
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let mut restarted = FinalizedProjectionSink::from_runtime(ProjectionRuntime {
            projector,
            readiness_publisher,
            projection_config,
            _reader: reader,
            overlay: Some(overlay),
            writer: durable_writer,
            _writer_lease: None,
            runtime_failure_sender: Some(runtime_failure_tx),
            runtime_failure_receiver: Some(runtime_failure_rx),
        });
        let ahead = ProjectionCheckpoint {
            block_number: durable_p.block_number + 1,
            block_hash: B256::repeat_byte(0x33),
        };
        assert_eq!(
            restarted.reconcile_finalized_target(Some(ahead)).unwrap(),
            FinalizedTargetReconciliationV1::Process {
                target: ahead,
                recovered_floor: Some(durable_p),
            },
        );
    }

    #[test]
    fn later_provider_failure_keeps_and_reports_earlier_durable_checkpoint() {
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let first = add_empty_block(&provider, 1);
        let runtime = initialized_runtime(1);
        let (logical_tx, mut logical_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();
        let (recovery_tx, _recovery_rx) = tokio::sync::mpsc::unbounded_channel();

        let error = project_through_target(
            provider,
            &runtime,
            FinalizedTarget::new(2, B256::repeat_byte(2)),
            &logical_tx,
            &write_tx,
            &recovery_tx,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("canonical block 2 is unavailable"));
        assert_eq!(
            projection_failure_class(&error),
            ProjectionFailureClass::HistoricalReceiptsUnavailable
        );
        assert_eq!(
            logical_rx.try_recv().unwrap(),
            FinalizedTarget::new(1, first)
        );
        assert_eq!(
            write_rx.try_recv().unwrap().checkpoint,
            FinalizedTarget::new(1, first)
        );
        assert!(write_rx.try_recv().is_err());
        let state = runtime.lock().unwrap();
        let checkpoint = state.projector.state().checkpoint.unwrap();
        assert_eq!(checkpoint.block_number, 1);
        assert_eq!(checkpoint.block_hash, first);
    }

    #[test]
    fn ambiguous_mongo_result_retries_the_same_batch_before_advancing_durable_height() {
        let storage = Arc::new(AmbiguousFirstWriteStorage::default());
        let overlay = Arc::new(PendingOverlayStorage::new(storage.inner.clone()));
        let writer: StorageWriterHandle = storage.clone();
        let namespace = Namespace::new("records").unwrap();
        let key = Key::new(b"key".to_vec()).unwrap();
        let value = outbe_offchain_storage::Value::new(b"value".to_vec()).unwrap();
        let batch = AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
            namespace.clone(),
            key.clone(),
            value,
        )]);
        let checkpoint = FinalizedTarget::new(7, B256::repeat_byte(0x77));
        let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel();
        let (checkpoint_tx, mut checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
        let writer_thread = std::thread::spawn(move || {
            super::run_durable_projection_writer(writer, write_rx, checkpoint_tx);
        });

        storage.ambiguous_next.store(true, Ordering::Release);
        overlay.apply_atomic(&batch).unwrap();
        let overlay_generation = overlay.current_generation();
        write_tx
            .send(super::DurableProjectionWrite {
                checkpoint,
                batch,
                overlay_ack: Some((overlay.clone(), overlay_generation)),
            })
            .unwrap();
        let durable = checkpoint_rx
            .blocking_recv()
            .expect("the exact batch must be retried after an ambiguous result");

        assert_eq!(durable, checkpoint);
        assert_eq!(storage.attempts.load(Ordering::Acquire), 2);
        assert_eq!(
            storage
                .inner
                .get(namespace.clone(), &key)
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"value"
        );
        storage
            .inner
            .put(
                namespace.clone(),
                &key,
                &outbe_offchain_storage::Value::new(b"base-after-ack".to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            overlay.get(namespace, &key).unwrap().unwrap().as_bytes(),
            b"base-after-ack",
            "durable ACK must retire the acknowledged overlay generation"
        );
        drop(write_tx);
        writer_thread.join().unwrap();
    }

    #[test]
    fn durable_write_deadline_has_a_typed_error_for_lifecycle_classification() {
        let storage = Arc::new(FailAfterStartupStorage::default());
        storage
            .fail_writes_unavailable
            .store(true, Ordering::SeqCst);
        let writer: StorageWriterHandle = storage;
        let checkpoint = FinalizedTarget::new(7, B256::repeat_byte(0x77));
        let batch = AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
            Namespace::new("records").unwrap(),
            Key::new(b"key".to_vec()).unwrap(),
            outbe_offchain_storage::Value::new(b"value".to_vec()).unwrap(),
        )]);

        let report = apply_durable_projection_write_until(
            &writer,
            &DurableProjectionWrite {
                checkpoint,
                batch,
                overlay_ack: None,
            },
            Duration::ZERO,
        )
        .unwrap_err();
        let error = report
            .downcast_ref::<ProjectionWriteDeadlineError>()
            .expect("unavailable storage must preserve the typed recovery deadline");

        assert_eq!(error.block_number, checkpoint.number);
        assert_eq!(error.block_hash, checkpoint.hash);
    }

    #[test]
    fn transient_runtime_read_failure_clears_only_after_a_successful_probe() {
        let storage = Arc::new(FailAfterStartupStorage::default());
        storage
            .fail_writes_unavailable
            .store(true, Ordering::SeqCst);
        let writer: StorageWriterHandle = storage.clone();
        let since = std::time::Instant::now();
        let (failure_sender, failure_receiver) =
            tokio::sync::watch::channel(Some(RuntimeBodyFailure::Unavailable {
                generation: 7,
                since,
            }));
        let recovery = ProjectionRuntimeRecoveryHandle {
            writer,
            failure_sender,
        };

        assert_eq!(
            recovery.reconcile(7),
            ProjectionRuntimeRecoveryV1::Unavailable
        );
        assert_eq!(
            *failure_receiver.borrow(),
            Some(RuntimeBodyFailure::Unavailable {
                generation: 7,
                since,
            })
        );

        storage
            .fail_writes_unavailable
            .store(false, Ordering::SeqCst);
        assert_eq!(
            recovery.reconcile(7),
            ProjectionRuntimeRecoveryV1::Recovered
        );
        assert_eq!(*failure_receiver.borrow(), None);
    }

    #[test]
    fn successful_probe_never_clears_a_newer_runtime_outage() {
        struct BlockingProbeStorage {
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
        }

        impl StorageWriter for BlockingProbeStorage {
            fn verify_transaction_capability(&self) -> Result<(), StorageError> {
                self.entered.wait();
                self.release.wait();
                Ok(())
            }

            fn apply_atomic(&self, _batch: &AtomicWriteBatch) -> Result<(), StorageError> {
                Ok(())
            }
        }

        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let writer: StorageWriterHandle = Arc::new(BlockingProbeStorage {
            entered: entered.clone(),
            release: release.clone(),
        });
        let since = std::time::Instant::now();
        let (failure_sender, failure_receiver) =
            tokio::sync::watch::channel(Some(RuntimeBodyFailure::Unavailable {
                generation: 7,
                since,
            }));
        let recovery = ProjectionRuntimeRecoveryHandle {
            writer,
            failure_sender: failure_sender.clone(),
        };
        let task = std::thread::spawn(move || recovery.reconcile(7));
        entered.wait();
        failure_sender.send_replace(Some(RuntimeBodyFailure::Unavailable {
            generation: 8,
            since,
        }));
        release.wait();

        assert_eq!(
            task.join().unwrap(),
            ProjectionRuntimeRecoveryV1::Unavailable
        );
        assert_eq!(
            *failure_receiver.borrow(),
            Some(RuntimeBodyFailure::Unavailable {
                generation: 8,
                since,
            })
        );
    }

    #[test]
    fn successful_write_after_the_absolute_deadline_never_publishes_progress() {
        struct SlowSuccessfulStorage;

        impl StorageWriter for SlowSuccessfulStorage {
            fn apply_atomic(&self, _batch: &AtomicWriteBatch) -> Result<(), StorageError> {
                std::thread::sleep(Duration::from_millis(10));
                Ok(())
            }
        }

        let writer: StorageWriterHandle = Arc::new(SlowSuccessfulStorage);
        let checkpoint = FinalizedTarget::new(7, B256::repeat_byte(0x78));
        let batch = AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
            Namespace::new("records").unwrap(),
            Key::new(b"key".to_vec()).unwrap(),
            outbe_offchain_storage::Value::new(b"value".to_vec()).unwrap(),
        )]);
        let report = apply_durable_projection_write_before(
            &writer,
            &DurableProjectionWrite {
                checkpoint,
                batch,
                overlay_ack: None,
            },
            std::time::Instant::now() + Duration::from_millis(1),
        )
        .unwrap_err();

        assert_eq!(
            projection_frame_failure_class(&report),
            ProjectionFailureClass::MongoReconnectDeadline
        );
    }

    #[test]
    fn deterministic_projection_storage_failures_are_immediate_and_typed() {
        let checkpoint = FinalizedTarget::new(7, B256::repeat_byte(0x77));
        let batch = || {
            AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
                Namespace::new("records").unwrap(),
                Key::new(b"key".to_vec()).unwrap(),
                outbe_offchain_storage::Value::new(b"value".to_vec()).unwrap(),
            )])
        };

        for (lease_lost, expected) in [
            (false, ProjectionFailureClass::CorruptBody),
            (true, ProjectionFailureClass::WriterLeaseLost),
        ] {
            let storage = Arc::new(FailAfterStartupStorage::default());
            if lease_lost {
                storage.lose_writer_lease.store(true, Ordering::SeqCst);
            } else {
                storage.fail_writes.store(true, Ordering::SeqCst);
            }
            let writer: StorageWriterHandle = storage;
            let started = std::time::Instant::now();
            let report = apply_durable_projection_write_until(
                &writer,
                &DurableProjectionWrite {
                    checkpoint,
                    batch: batch(),
                    overlay_ack: None,
                },
                PROJECTION_RECOVERY_DEADLINE,
            )
            .unwrap_err();
            assert!(started.elapsed() < Duration::from_millis(100));
            assert_eq!(projection_frame_failure_class(&report), expected);
        }
    }

    #[test]
    fn every_storage_failure_kind_has_a_stable_projection_class() {
        let cases = [
            (
                StorageError::InvalidArgument("invalid".to_owned()),
                ProjectionFailureClass::StorageInvalidArgument,
            ),
            (
                StorageError::Unavailable {
                    source: Box::new(std::io::Error::other("unavailable")),
                },
                ProjectionFailureClass::StorageUnavailable,
            ),
            (
                StorageError::Corruption("corrupt".to_owned()),
                ProjectionFailureClass::CorruptBody,
            ),
            (
                StorageError::Backend {
                    source: Box::new(std::io::Error::other("backend")),
                },
                ProjectionFailureClass::StorageBackend,
            ),
            (
                StorageError::RequestDeadline,
                ProjectionFailureClass::StorageRequestDeadline,
            ),
            (
                StorageError::WriterLeaseLost,
                ProjectionFailureClass::WriterLeaseLost,
            ),
        ];
        for (error, expected) in cases {
            let report = eyre::Report::new(error);
            assert_eq!(projection_frame_failure_class(&report), expected);
        }
    }

    #[test]
    fn writer_lease_loss_has_a_distinct_failure_class() {
        let error = eyre::Report::new(StorageError::WriterLeaseLost);

        assert_eq!(
            projection_failure_class(&error),
            ProjectionFailureClass::WriterLeaseLost
        );
    }

    #[tokio::test]
    async fn control_loop_drains_notifications_and_emits_finished_heights_in_order() {
        use futures::{channel::mpsc, SinkExt};

        let provider = MockEthProvider::new();
        let first = add_empty_block(&provider, 1);
        let second = add_empty_block(&provider, 2);
        let runtime = initialized_runtime(1).into_inner().unwrap();
        let (mut notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, _exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            runtime,
            exit_tx,
        ));

        notification_tx.send(Ok(())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), notification_tx.send(Ok(())))
            .await
            .unwrap()
            .unwrap();
        finality_tx
            .unbounded_send(FinalizedTarget::new(2, second))
            .unwrap();

        let first_event = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second_event = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_event, ExExEvent::FinishedHeight((1, first).into()));
        assert_eq!(second_event, ExExEvent::FinishedHeight((2, second).into()));
        assert!(
            !task.is_finished(),
            "the critical projection loop stays alive"
        );
        task.abort();
    }

    #[tokio::test]
    async fn deterministic_projection_failure_reports_exit_while_exex_keeps_draining() {
        use futures::{channel::mpsc, SinkExt};

        let provider = MockEthProvider::new();
        let block_hash = add_empty_block(&provider, 1);
        let storage = Arc::new(FailAfterStartupStorage::default());
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage.clone();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), writer.clone())
                .unwrap();
        storage.fail_writes.store(true, Ordering::SeqCst);

        let (mut notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (readiness_publisher, _readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::repeat_byte(0x11),
            },
            outbe_offchain_data::ProjectionStatus::Starting,
        );
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: reader,
                overlay: None,
                writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));
        finality_tx
            .unbounded_send(FinalizedTarget::new(1, block_hash))
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while storage.failed_writes.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("projection worker must observe the injected storage failure");
        assert!(events_rx.try_recv().is_err());
        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .expect("fatal projection failure must notify the node supervisor")
            .expect("projection exit channel must remain open");
        assert_eq!(
            exit.failure.class,
            outbe_offchain_data::ProjectionFailureClass::CorruptBody
        );

        notification_tx.send(Ok(())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), notification_tx.send(Ok(())))
            .await
            .expect("ExEx must keep draining notifications after projection failure")
            .unwrap();
        assert!(
            !task.is_finished(),
            "projection failure must not stop the node loop"
        );
        task.abort();
    }

    #[tokio::test]
    async fn runtime_body_corruption_reports_exit_while_exex_keeps_draining() {
        use futures::{channel::mpsc, SinkExt};

        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let storage = Arc::new(MemoryStorage::new());
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage;
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), writer.clone())
                .unwrap();
        let (readiness_publisher, _readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            outbe_offchain_data::ProjectionStatus::Starting,
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (mut notification_tx, notification_rx) = mpsc::channel(1);
        let (_finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: reader,
                overlay: None,
                writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx.clone()),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        runtime_failure_tx.send_replace(Some(outbe_offchain_data::RuntimeBodyFailure::Fatal(
            outbe_offchain_data::ProjectionFailure::new(
                outbe_offchain_data::ProjectionFailureClass::CorruptBody,
                "dangling body index",
            ),
        )));
        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .expect("body corruption must notify the node supervisor")
            .expect("projection exit channel must remain open");
        assert_eq!(
            exit.failure.class,
            outbe_offchain_data::ProjectionFailureClass::CorruptBody
        );

        notification_tx.send(Ok(())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), notification_tx.send(Ok(())))
            .await
            .expect("ExEx must keep draining after a fatal runtime read")
            .unwrap();
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn unexpected_exex_return_reports_fatal_and_stays_alive_for_common_shutdown() {
        let (publisher, readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::repeat_byte(0x11),
            },
            outbe_offchain_data::ProjectionStatus::Starting,
        );
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(supervise_projection_future(
            async { Ok(()) },
            publisher,
            exit_tx,
        ));

        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .expect("unexpected return must notify lifecycle owner")
            .expect("exit sender must remain open");
        assert_eq!(
            exit.failure.class,
            outbe_offchain_data::ProjectionFailureClass::ProjectorExited
        );
        assert!(matches!(
            readiness.current(),
            outbe_offchain_data::ProjectionStatus::Fatal { error, .. }
                if error.class == outbe_offchain_data::ProjectionFailureClass::ProjectorExited
        ));
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn runtime_body_unavailability_uses_the_projection_recovery_session() {
        use futures::channel::mpsc;

        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let storage = Arc::new(FailAfterStartupStorage::default());
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage.clone();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), writer.clone())
                .unwrap();
        let (readiness_publisher, readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            outbe_offchain_data::ProjectionStatus::Ready {
                checkpoint: outbe_offchain_data::ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: projection_config.genesis_hash,
                },
            },
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (_notification_tx, notification_rx) = mpsc::channel(1);
        let (_finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: reader,
                overlay: None,
                writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx.clone()),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        storage.fail_reads.store(true, Ordering::SeqCst);
        runtime_failure_tx.send_replace(Some(
            outbe_offchain_data::RuntimeBodyFailure::Unavailable {
                generation: 1,
                since: std::time::Instant::now(),
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(
                    readiness.current(),
                    outbe_offchain_data::ProjectionStatus::MongoUnavailable { .. }
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("read-side outage must immediately disable readiness");
        assert!(exit_rx.try_recv().is_err());

        storage.fail_reads.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    readiness.current(),
                    outbe_offchain_data::ProjectionStatus::Ready { checkpoint }
                        if checkpoint.block_number == 0
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("an acknowledged projector reopen must restore readiness");
        assert!(exit_rx.try_recv().is_err());
        task.abort();
    }

    #[tokio::test]
    async fn unavailable_mongo_write_retries_without_changing_logical_readiness() {
        use futures::channel::mpsc;

        let provider = MockEthProvider::new();
        let block_hash = add_empty_block(&provider, 1);
        let storage = Arc::new(FailAfterStartupStorage::default());
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        OffchainDataProjection::open(projection_config, storage.clone(), storage.clone()).unwrap();
        let overlay = Arc::new(PendingOverlayStorage::new(storage.clone()));
        let reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let durable_writer: StorageWriterHandle = storage.clone();
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), logical_writer)
                .unwrap();
        let (readiness_publisher, readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            outbe_offchain_data::ProjectionStatus::Ready {
                checkpoint: outbe_offchain_data::ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: projection_config.genesis_hash,
                },
            },
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (_notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: reader,
                overlay: Some(overlay.clone()),
                writer: durable_writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        storage
            .fail_writes_unavailable
            .store(true, Ordering::SeqCst);
        finality_tx
            .unbounded_send(FinalizedTarget::new(1, block_hash))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(
                    readiness.current(),
                    outbe_offchain_data::ProjectionStatus::Ready { checkpoint }
                        if checkpoint.block_number == 1 && checkpoint.block_hash == block_hash
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Mongo write failure must not hold back logical readiness");
        assert!(events_rx.try_recv().is_err());
        assert!(exit_rx.try_recv().is_err());

        storage
            .fail_writes_unavailable
            .store(false, Ordering::SeqCst);
        let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .expect("projection must retry after the one-second interval")
            .expect("ExEx event sender remains live");
        assert_eq!(event, ExExEvent::FinishedHeight((1, block_hash).into()));
        assert!(matches!(
            readiness.current(),
            outbe_offchain_data::ProjectionStatus::Ready { checkpoint }
                if checkpoint.block_number == 1 && checkpoint.block_hash == block_hash
        ));
        assert!(exit_rx.try_recv().is_err());
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn blocked_mongo_write_does_not_block_logical_projection_readiness() {
        use futures::channel::mpsc;

        let provider = MockEthProvider::new();
        let block_hash = add_empty_block(&provider, 1);
        let next_block_hash = add_empty_block(&provider, 2);
        let (durable, write_started, release_write, write_finished) = BlockingWriteStorage::new();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        OffchainDataProjection::open(projection_config, durable.clone(), durable.clone()).unwrap();
        let overlay = Arc::new(PendingOverlayStorage::new(durable.clone()));
        let logical_reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let durable_writer: StorageWriterHandle = durable.clone();
        let projector =
            OffchainDataProjection::open(projection_config, logical_reader.clone(), logical_writer)
                .unwrap();
        let checkpoint = ProjectionCheckpoint {
            block_number: 0,
            block_hash: projection_config.genesis_hash,
        };
        let (readiness_publisher, readiness) =
            projection_readiness(checkpoint, ProjectionStatus::Ready { checkpoint });
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (_notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, _exit_rx) = tokio::sync::mpsc::unbounded_channel();
        durable.block_next_write.store(true, Ordering::Release);
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: logical_reader,
                overlay: Some(overlay.clone()),
                writer: durable_writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        finality_tx
            .unbounded_send(FinalizedTarget::new(1, block_hash))
            .unwrap();
        tokio::task::spawn_blocking(move || write_started.recv().unwrap())
            .await
            .unwrap();

        let readiness_advanced = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if matches!(
                    readiness.current(),
                    ProjectionStatus::Ready { checkpoint }
                        if checkpoint.block_number == 1 && checkpoint.block_hash == block_hash
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        finality_tx
            .unbounded_send(FinalizedTarget::new(2, next_block_hash))
            .unwrap();
        let later_readiness_advanced = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if matches!(
                    readiness.current(),
                    ProjectionStatus::Ready { checkpoint }
                        if checkpoint.block_number == 2
                            && checkpoint.block_hash == next_block_hash
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            events_rx.try_recv().is_err(),
            "FinishedHeight must remain tied to the durable Mongo checkpoint"
        );

        release_write.send(()).unwrap();
        tokio::task::spawn_blocking(move || write_finished.recv().unwrap())
            .await
            .unwrap();
        let first_finished = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("first Mongo commit must publish its durable height")
            .expect("ExEx event sender remains live");
        let second_finished = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("queued Mongo commit must follow the first commit")
            .expect("ExEx event sender remains live");
        task.abort();

        assert!(
            readiness_advanced.is_ok(),
            "logical readiness must advance before the blocked Mongo write is acknowledged"
        );
        assert!(
            later_readiness_advanced.is_ok(),
            "a blocked Mongo writer must not stop later finalized blocks from advancing readiness"
        );
        assert_eq!(
            first_finished,
            ExExEvent::FinishedHeight((1, block_hash).into())
        );
        assert_eq!(
            second_finished,
            ExExEvent::FinishedHeight((2, next_block_hash).into())
        );
    }

    #[tokio::test]
    async fn restart_replays_after_the_durable_checkpoint_before_mongo_catches_up() {
        use futures::channel::mpsc;

        let provider = MockEthProvider::new();
        let durable_hash = add_empty_block(&provider, 1);
        let replayed_hash = add_empty_block(&provider, 2);
        let (durable, write_started, release_write, write_finished) = BlockingWriteStorage::new();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        let mut durable_projection =
            OffchainDataProjection::open(projection_config, durable.clone(), durable.clone())
                .unwrap();
        durable_projection
            .project_block(&FinalizedBlock {
                number: 1,
                hash: durable_hash,
                receipts: Vec::new(),
            })
            .unwrap();
        drop(durable_projection);

        let overlay = Arc::new(PendingOverlayStorage::new(durable.clone()));
        let logical_reader: StorageReaderHandle = overlay.clone();
        let logical_writer: StorageWriterHandle = overlay.clone();
        let projector =
            OffchainDataProjection::open(projection_config, logical_reader.clone(), logical_writer)
                .unwrap();
        let durable_checkpoint = ProjectionCheckpoint {
            block_number: 1,
            block_hash: durable_hash,
        };
        let (readiness_publisher, readiness) = projection_readiness(
            ProjectionCheckpoint {
                block_number: 0,
                block_hash: projection_config.genesis_hash,
            },
            ProjectionStatus::Ready {
                checkpoint: durable_checkpoint,
            },
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (_notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        durable.block_next_write.store(true, Ordering::Release);
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: logical_reader,
                overlay: Some(overlay.clone()),
                writer: durable.clone(),
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        finality_tx
            .unbounded_send(FinalizedTarget::new(2, replayed_hash))
            .unwrap();
        tokio::task::spawn_blocking(move || write_started.recv().unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(
                    readiness.current(),
                    ProjectionStatus::Ready { checkpoint }
                        if checkpoint.block_number == 2 && checkpoint.block_hash == replayed_hash
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained finalized receipts must rebuild logical readiness after restart");
        assert_eq!(
            outbe_offchain_data::read_projection_state(projection_config, durable.clone())
                .unwrap()
                .unwrap()
                .checkpoint,
            Some(durable_checkpoint),
            "Mongo checkpoint must remain the restart cursor until the replayed batch commits"
        );
        assert!(events_rx.try_recv().is_err());
        assert!(exit_rx.try_recv().is_err());

        release_write.send(()).unwrap();
        tokio::task::spawn_blocking(move || write_finished.recv().unwrap())
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("replayed batch must eventually commit to Mongo")
            .expect("ExEx event sender remains live");
        assert_eq!(event, ExExEvent::FinishedHeight((2, replayed_hash).into()));
        task.abort();
    }

    #[tokio::test]
    async fn fatal_status_stays_sticky_when_detached_worker_finishes_late() {
        use futures::channel::mpsc;

        let provider = MockEthProvider::new();
        let block_hash = add_empty_block(&provider, 1);
        let (storage, write_started, release_write, write_finished) = BlockingWriteStorage::new();
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage.clone();
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block: 1,
        };
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), writer.clone())
                .unwrap();
        let checkpoint = ProjectionCheckpoint {
            block_number: 0,
            block_hash: projection_config.genesis_hash,
        };
        let (readiness_publisher, readiness) = projection_readiness(
            checkpoint,
            outbe_offchain_data::ProjectionStatus::Ready { checkpoint },
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        let (_notification_tx, notification_rx) = mpsc::channel(1);
        let (finality_tx, finality_rx) = mpsc::unbounded();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel();
        storage.block_next_write.store(true, Ordering::Release);
        let task = tokio::spawn(run_projection_loop(
            provider,
            notification_rx,
            finality_rx,
            events_tx,
            ProjectionRuntime {
                projector,
                readiness_publisher,
                projection_config,
                _reader: reader,
                overlay: None,
                writer,
                _writer_lease: None,
                runtime_failure_sender: Some(runtime_failure_tx.clone()),
                runtime_failure_receiver: Some(runtime_failure_rx),
            },
            exit_tx,
        ));

        finality_tx
            .unbounded_send(FinalizedTarget::new(1, block_hash))
            .unwrap();
        tokio::task::spawn_blocking(move || write_started.recv().unwrap())
            .await
            .unwrap();
        runtime_failure_tx.send_replace(Some(outbe_offchain_data::RuntimeBodyFailure::Fatal(
            ProjectionFailure::new(ProjectionFailureClass::Other, "injected terminal failure"),
        )));
        let exit = tokio::time::timeout(Duration::from_secs(1), exit_rx.recv())
            .await
            .expect("fatal body-read failure must reach the lifecycle owner")
            .expect("exit channel remains open");
        assert_eq!(exit.failure.class, ProjectionFailureClass::Other);

        release_write.send(()).unwrap();
        tokio::task::spawn_blocking(move || write_finished.recv().unwrap())
            .await
            .unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert!(matches!(
            readiness.current(),
            outbe_offchain_data::ProjectionStatus::Fatal { error, .. }
                if error.class == ProjectionFailureClass::Other
        ));
        assert!(events_rx.try_recv().is_err());
        assert!(!task.is_finished());
        task.abort();
    }

    fn add_empty_block(provider: &MockEthProvider, number: u64) -> B256 {
        let header = Header {
            number,
            ..Default::default()
        };
        let hash = header.hash_slow();
        provider.add_block(hash, Block::new(header, Default::default()));
        provider.add_receipts(number, Vec::new());
        hash
    }

    fn empty_finalized_frame(
        number: u64,
        timestamp: u64,
    ) -> crate::finalized_frame::FinalizedFrame {
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let header = Header {
            number,
            timestamp,
            ..Default::default()
        };
        let hash = header.hash_slow();
        provider.add_block(hash, Block::new(header, Default::default()));
        provider.add_receipts(number, Vec::new());
        let source = RethFinalizedFrameSource::new(provider);
        read_bounded_finalized_frames(&source, number, BlockNumHash::new(number, hash))
            .unwrap()
            .unwrap()
            .frames()[0]
            .clone()
    }

    fn initialized_runtime(start_block: u64) -> Mutex<ProjectionRuntime> {
        let storage = Arc::new(MemoryStorage::new());
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage;
        let projection_config = ProjectionConfig {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            start_block,
        };
        let projector =
            OffchainDataProjection::open(projection_config, reader.clone(), writer.clone())
                .unwrap();
        let (readiness_publisher, _readiness) = outbe_offchain_data::projection_readiness(
            outbe_offchain_data::ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::repeat_byte(0x11),
            },
            outbe_offchain_data::ProjectionStatus::Starting,
        );
        let (runtime_failure_tx, runtime_failure_rx) = tokio::sync::watch::channel(None);
        Mutex::new(ProjectionRuntime {
            projector,
            readiness_publisher,
            projection_config,
            _reader: reader,
            overlay: None,
            writer,
            _writer_lease: None,
            runtime_failure_sender: Some(runtime_failure_tx),
            runtime_failure_receiver: Some(runtime_failure_rx),
        })
    }

    struct BlockingWriteStorage {
        inner: MemoryStorage,
        block_next_write: AtomicBool,
        write_started: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        release_write: Mutex<std::sync::mpsc::Receiver<()>>,
        write_finished: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    }

    impl BlockingWriteStorage {
        fn new() -> (
            Arc<Self>,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        ) {
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
            (
                Arc::new(Self {
                    inner: MemoryStorage::new(),
                    block_next_write: AtomicBool::new(false),
                    write_started: Mutex::new(Some(started_tx)),
                    release_write: Mutex::new(release_rx),
                    write_finished: Mutex::new(Some(finished_tx)),
                }),
                started_rx,
                release_tx,
                finished_rx,
            )
        }
    }

    impl StorageReader for BlockingWriteStorage {
        fn get_record(
            &self,
            namespace: Namespace,
            key: &Key,
        ) -> Result<Option<StoredValue>, StorageError> {
            self.inner.get_record(namespace, key)
        }

        fn get_records(
            &self,
            namespace: Namespace,
            keys: &[Key],
        ) -> Result<Vec<Option<StoredValue>>, StorageError> {
            self.inner.get_records(namespace, keys)
        }

        fn scan_prefix(
            &self,
            namespace: Namespace,
            request: ScanRequest<'_>,
        ) -> Result<ScanPage, StorageError> {
            self.inner.scan_prefix(namespace, request)
        }
    }

    impl StorageWriter for BlockingWriteStorage {
        fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
            let blocked = self.block_next_write.swap(false, Ordering::AcqRel);
            if blocked {
                if let Some(started) = self.write_started.lock().unwrap().take() {
                    let _ = started.send(());
                }
                self.release_write.lock().unwrap().recv().unwrap();
            }
            let result = self.inner.apply_atomic(batch);
            if blocked {
                if let Some(finished) = self.write_finished.lock().unwrap().take() {
                    let _ = finished.send(());
                }
            }
            result
        }
    }

    #[derive(Default)]
    struct AmbiguousFirstWriteStorage {
        inner: Arc<MemoryStorage>,
        ambiguous_next: AtomicBool,
        attempts: AtomicUsize,
    }

    impl StorageWriter for AmbiguousFirstWriteStorage {
        fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.apply_atomic(batch)?;
            if self.ambiguous_next.swap(false, Ordering::AcqRel) {
                return Err(StorageError::Unavailable {
                    source: Box::new(std::io::Error::other("injected ambiguous MongoDB result")),
                });
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FailAfterStartupStorage {
        inner: MemoryStorage,
        fail_reads: AtomicBool,
        fail_writes: AtomicBool,
        fail_writes_unavailable: AtomicBool,
        lose_writer_lease: AtomicBool,
        failed_writes: AtomicUsize,
    }

    impl StorageReader for FailAfterStartupStorage {
        fn get_record(
            &self,
            namespace: Namespace,
            key: &Key,
        ) -> Result<Option<StoredValue>, StorageError> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(StorageError::Unavailable {
                    source: std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "injected unavailable read",
                    )
                    .into(),
                });
            }
            self.inner.get_record(namespace, key)
        }

        fn get_records(
            &self,
            namespace: Namespace,
            keys: &[Key],
        ) -> Result<Vec<Option<StoredValue>>, StorageError> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(StorageError::Unavailable {
                    source: std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "injected unavailable read",
                    )
                    .into(),
                });
            }
            self.inner.get_records(namespace, keys)
        }

        fn scan_prefix(
            &self,
            namespace: Namespace,
            request: ScanRequest<'_>,
        ) -> Result<ScanPage, StorageError> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(StorageError::Unavailable {
                    source: std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "injected unavailable read",
                    )
                    .into(),
                });
            }
            self.inner.scan_prefix(namespace, request)
        }
    }

    impl StorageWriter for FailAfterStartupStorage {
        fn verify_transaction_capability(&self) -> Result<(), StorageError> {
            if self.lose_writer_lease.load(Ordering::SeqCst) {
                return Err(StorageError::WriterLeaseLost);
            }
            if self.fail_reads.load(Ordering::SeqCst)
                || self.fail_writes_unavailable.load(Ordering::SeqCst)
            {
                return Err(StorageError::Unavailable {
                    source: Box::new(std::io::Error::other(
                        "injected unavailable transaction capability",
                    )),
                });
            }
            Ok(())
        }

        fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
            if self.lose_writer_lease.load(Ordering::SeqCst) {
                return Err(StorageError::WriterLeaseLost);
            }
            if self.fail_writes_unavailable.load(Ordering::SeqCst) {
                self.failed_writes.fetch_add(1, Ordering::SeqCst);
                return Err(StorageError::Unavailable {
                    source: Box::new(std::io::Error::other(
                        "injected unavailable projection write",
                    )),
                });
            }
            if self.fail_writes.load(Ordering::SeqCst) {
                self.failed_writes.fetch_add(1, Ordering::SeqCst);
                return Err(StorageError::Corruption(
                    "injected post-startup deterministic failure".to_owned(),
                ));
            }
            self.inner.apply_atomic(batch)
        }
    }

    #[test]
    fn projection_network_gate_accepts_known_networks_and_rejects_unknown_ids() {
        for chain_id in [
            outbe_primitives::chain::DEVNET_CHAIN_ID,
            outbe_primitives::chain::TESTNET_CHAIN_ID,
            outbe_primitives::chain::MAINNET_CHAIN_ID,
        ] {
            validate_projection_network(chain_id).unwrap();
        }
        assert!(validate_projection_network(1_000_000_001).is_err());
    }

    #[test]
    fn retained_gc_claim_waits_for_projection_commit_fence() {
        let fence = Arc::new(ProjectionRetentionFence::default());
        let projection = fence
            .projection_guard()
            .expect("projection acquires shared fence");
        let worker_fence = Arc::clone(&fence);
        let (claimed_tx, claimed_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _claim = worker_fence
                .gc_claim_guard()
                .expect("GC acquires exclusive fence");
            claimed_tx.send(()).expect("publish GC claim");
        });

        assert!(claimed_rx.recv_timeout(Duration::from_millis(25)).is_err());
        drop(projection);
        claimed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("GC claim proceeds after projection commit fence is released");
        worker.join().expect("GC fence worker joins");
    }
}
