//! Backend-neutral local projection readiness shared by node and consensus wiring.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::Instant,
};

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Local-only lifetime of one consensus execution request.
///
/// Commonware owns the actual proposal/verification deadline. The application
/// cancels this token when Commonware drops the corresponding response channel,
/// so synchronous Mongo reads inherit the already-running request lifetime
/// without inventing or resetting a wall-clock deadline.
#[derive(Clone, Debug, Default)]
pub struct ExecutionReadBudget {
    cancelled: Arc<AtomicBool>,
}

impl ExecutionReadBudget {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Exact block identity through which one projection view has applied all events.
///
/// The owner defines durability: consensus readiness uses the logical overlay boundary, while
/// MongoDB persists the same identity as its durable replay cursor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionCheckpoint {
    pub block_number: u64,
    pub block_hash: B256,
}

/// Stable class for a deterministic projection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionFailureClass {
    MalformedEvent,
    UnsupportedSchema,
    WrongNetwork,
    CheckpointMismatch,
    UnmanagedData,
    HistoricalReceiptsUnavailable,
    CorruptBody,
    DanglingIndex,
    ProjectorExited,
    ReadinessChannelClosed,
    MongoReconnectDeadline,
    WriterLeaseLost,
    StorageInvalidArgument,
    StorageUnavailable,
    StorageBackend,
    StorageRequestDeadline,
    Other,
}

/// Redacted structured failure published to node lifecycle and observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionFailure {
    pub class: ProjectionFailureClass,
    pub message: Arc<str>,
}

impl ProjectionFailure {
    #[must_use]
    pub fn new(class: ProjectionFailureClass, message: impl Into<Arc<str>>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }
}

/// Current local materialization health and exact logical readiness checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionStatus {
    Starting,
    CatchingUp {
        checkpoint: Option<ProjectionCheckpoint>,
    },
    Ready {
        checkpoint: ProjectionCheckpoint,
    },
    MongoUnavailable {
        checkpoint: Option<ProjectionCheckpoint>,
        since: Instant,
    },
    Fatal {
        checkpoint: Option<ProjectionCheckpoint>,
        error: ProjectionFailure,
    },
}

/// Outcome of one request-scoped exact-parent readiness wait.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Ready,
    BudgetExpired,
    ProjectionAhead,
    Fatal(ProjectionFailure),
}

/// Read-only request-scoped view of projection readiness.
#[derive(Clone, Debug)]
pub struct ProjectionReadinessHandle {
    receiver: watch::Receiver<ProjectionStatus>,
    baseline: ProjectionCheckpoint,
    publisher_liveness: Weak<()>,
}

impl ProjectionReadinessHandle {
    #[must_use]
    pub fn current(&self) -> ProjectionStatus {
        self.receiver.borrow().clone()
    }

    /// Waits for one exact finalized parent without creating or resetting a deadline.
    pub async fn wait_for<F>(
        mut self,
        required: ProjectionCheckpoint,
        budget_expired: F,
    ) -> WaitOutcome
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(budget_expired);
        loop {
            if self.publisher_liveness.upgrade().is_none() {
                return readiness_channel_closed();
            }
            if let Some(outcome) = evaluate(&self.current(), self.baseline, required) {
                return outcome;
            }
            tokio::select! {
                biased;
                () = &mut budget_expired => return WaitOutcome::BudgetExpired,
                changed = self.receiver.changed() => {
                    if changed.is_err() {
                        return readiness_channel_closed();
                    }
                }
            }
        }
    }
}

/// Write authority retained by ExEx and the projection supervisor.
#[derive(Clone, Debug)]
pub struct ProjectionReadinessPublisher {
    sender: watch::Sender<ProjectionStatus>,
    _liveness: Arc<()>,
}

impl ProjectionReadinessPublisher {
    pub fn publish(&self, status: ProjectionStatus) {
        self.sender.send_replace(status);
    }

    #[must_use]
    pub fn current(&self) -> ProjectionStatus {
        self.sender.borrow().clone()
    }
}

/// Creates one local readiness watch with separated read and publish authority.
#[must_use]
pub fn projection_readiness(
    baseline: ProjectionCheckpoint,
    initial: ProjectionStatus,
) -> (ProjectionReadinessPublisher, ProjectionReadinessHandle) {
    let (sender, receiver) = watch::channel(initial);
    let liveness = Arc::new(());
    (
        ProjectionReadinessPublisher {
            sender,
            _liveness: Arc::clone(&liveness),
        },
        ProjectionReadinessHandle {
            receiver,
            baseline,
            publisher_liveness: Arc::downgrade(&liveness),
        },
    )
}

fn evaluate(
    status: &ProjectionStatus,
    baseline: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
) -> Option<WaitOutcome> {
    match status {
        ProjectionStatus::Fatal { error, .. } => Some(WaitOutcome::Fatal(error.clone())),
        ProjectionStatus::MongoUnavailable {
            checkpoint: Some(checkpoint),
            ..
        } => compare_unavailable_checkpoint(*checkpoint, required),
        ProjectionStatus::MongoUnavailable {
            checkpoint: None, ..
        } => None,
        ProjectionStatus::Starting => compare_baseline(baseline, required),
        ProjectionStatus::CatchingUp { checkpoint: None } => compare_baseline(baseline, required),
        ProjectionStatus::CatchingUp {
            checkpoint: Some(checkpoint),
        }
        | ProjectionStatus::Ready { checkpoint } => compare_checkpoint(*checkpoint, required),
    }
}

fn compare_unavailable_checkpoint(
    checkpoint: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
) -> Option<WaitOutcome> {
    match checkpoint.block_number.cmp(&required.block_number) {
        std::cmp::Ordering::Greater => Some(WaitOutcome::ProjectionAhead),
        std::cmp::Ordering::Equal if checkpoint.block_hash != required.block_hash => {
            Some(checkpoint_mismatch(checkpoint, required))
        }
        std::cmp::Ordering::Equal | std::cmp::Ordering::Less => None,
    }
}

fn compare_baseline(
    baseline: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
) -> Option<WaitOutcome> {
    match baseline.block_number.cmp(&required.block_number) {
        std::cmp::Ordering::Greater => Some(WaitOutcome::ProjectionAhead),
        std::cmp::Ordering::Equal if baseline.block_hash == required.block_hash => {
            Some(WaitOutcome::Ready)
        }
        std::cmp::Ordering::Equal => Some(checkpoint_mismatch(baseline, required)),
        std::cmp::Ordering::Less => None,
    }
}

fn compare_checkpoint(
    checkpoint: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
) -> Option<WaitOutcome> {
    match checkpoint.block_number.cmp(&required.block_number) {
        std::cmp::Ordering::Less => None,
        std::cmp::Ordering::Greater => Some(WaitOutcome::ProjectionAhead),
        std::cmp::Ordering::Equal if checkpoint.block_hash == required.block_hash => {
            Some(WaitOutcome::Ready)
        }
        std::cmp::Ordering::Equal => Some(checkpoint_mismatch(checkpoint, required)),
    }
}

fn checkpoint_mismatch(
    actual: ProjectionCheckpoint,
    required: ProjectionCheckpoint,
) -> WaitOutcome {
    WaitOutcome::Fatal(ProjectionFailure::new(
        ProjectionFailureClass::CheckpointMismatch,
        format!(
            "projection checkpoint hash {} conflicts with required parent {} at height {}",
            actual.block_hash, required.block_hash, required.block_number
        ),
    ))
}

fn readiness_channel_closed() -> WaitOutcome {
    WaitOutcome::Fatal(ProjectionFailure::new(
        ProjectionFailureClass::ReadinessChannelClosed,
        "mandatory projection readiness channel closed",
    ))
}
