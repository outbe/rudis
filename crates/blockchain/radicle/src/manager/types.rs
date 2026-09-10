use crate::endpoint::{EndpointAddress, PeerId, VerifiedEndpoint};
use alloy_primitives::{Address, B256};
use outbe_radicleregistry::RepoId;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::mpsc;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FinalizedBlock {
    pub number: u64,
    pub hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedValidator {
    pub address: Address,
    pub peer: PeerId,
    pub node_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedSnapshot {
    pub block: FinalizedBlock,
    pub validators: Vec<FinalizedValidator>,
    pub registry_generation: u64,
    pub repositories: Vec<RepoId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectDisposition {
    Disconnected,
    AlreadyAbsent,
    NotConnected,
    Inbound,
    AddressChanged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlSession {
    pub node_id: [u8; 32],
    pub address: EndpointAddress,
    pub direction: SessionDirection,
    pub connected: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ManagerPhase {
    #[default]
    Disabled,
    JoiningUnbound,
    Ready,
    RuntimeDegraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PhaseError {
    #[error("validator sidecar is unavailable before readiness")]
    SidecarUnavailable,
    #[error("local Heartwood NodeId is unavailable")]
    LocalNodeIdUnavailable,
    #[error("local Heartwood NodeId does not match finalized ValidatorSet binding")]
    BindingMismatch,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagerStatus {
    pub phase: ManagerPhase,
    pub phase_error: Option<PhaseError>,
    pub last_seen_finalized: Option<FinalizedBlock>,
    pub last_converged_finalized: Option<FinalizedBlock>,
    pub desired_repository_count: usize,
    pub available_repository_count: usize,
    pub pending_repository_count: usize,
    pub resolved_peer_count: usize,
    pub unresolved_peer_count: usize,
    pub connected_peer_count: usize,
    pub finality_regressions: u64,
    pub finality_conflicts: u64,
    pub provider_failures: u64,
    pub endpoint_failures: u64,
    pub uds_failures: u64,
    pub tcp_status_failures: u64,
    pub signed_peers: Vec<VerifiedEndpoint>,
}

#[derive(Clone, Debug)]
pub struct ManagerConfig {
    pub self_validator: Address,
    pub local_node_id: [u8; 32],
    pub repair_interval: Duration,
    pub retry: RetryPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max: Duration,
    pub jitter: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(30),
            jitter: Duration::from_millis(250),
        }
    }
}

impl RetryPolicy {
    pub(crate) fn delay(
        self,
        attempt: u32,
        validator: Address,
        target: Option<FinalizedBlock>,
    ) -> Duration {
        let factor = 1_u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        let delay = self.base.saturating_mul(factor).min(self.max);
        let jitter_nanos = self.jitter.as_nanos().min(u128::from(u64::MAX)) as u64;
        if jitter_nanos == 0 {
            return delay;
        }
        let mut validator_tail = [0; 8];
        validator_tail.copy_from_slice(&validator.as_slice()[12..]);
        let mut entropy = u64::from_be_bytes(validator_tail) ^ u64::from(attempt);
        if let Some(target) = target {
            let mut hash_head = [0; 8];
            hash_head.copy_from_slice(&target.hash.as_slice()[..8]);
            entropy ^= target.number ^ u64::from_be_bytes(hash_head);
        }
        entropy ^= entropy << 13;
        entropy ^= entropy >> 7;
        entropy ^= entropy << 17;
        delay.saturating_add(Duration::from_nanos(entropy % (jitter_nanos + 1)))
    }
}

pub struct ManagerDependencies {
    pub finality: Arc<dyn FinalizedFeed>,
    pub snapshots: Arc<dyn SnapshotReader>,
    pub endpoints: Arc<dyn EndpointResolver>,
    pub control: Arc<dyn HeartwoodControl>,
    pub repository_status: Arc<dyn RepositoryStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManagerError {
    #[error("finality source failed: {0}")]
    Finality(String),
    #[error("exact finalized provider failed: {0}")]
    Provider(String),
    #[error("finalized state is inconsistent: {0}")]
    Snapshot(String),
    #[error("endpoint discovery failed: {0}")]
    Endpoint(String),
    #[error("Heartwood control failed: {0}")]
    Control(String),
    #[error("sidecar status failed: {0}")]
    Status(String),
    #[error("manager stopped")]
    Stopped,
    #[error("{0} shutdown deadline exceeded")]
    ShutdownDeadline(&'static str),
    #[error("Radicle task failed: {0}")]
    Task(String),
    #[error("manager shutdown failed: {manager}; endpoint shutdown failed: {endpoint}")]
    Shutdown {
        manager: Box<ManagerError>,
        endpoint: Box<ManagerError>,
    },
}

pub trait FinalizedFeed: Send + Sync + 'static {
    fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<FinalizedBlock>, ManagerError>;
    fn sample(&self) -> BoxFuture<'_, Result<Option<FinalizedBlock>, ManagerError>>;
}

pub trait SnapshotReader: Send + Sync + 'static {
    fn read_exact(&self, block: FinalizedBlock) -> Result<FinalizedSnapshot, ManagerError>;
}

pub trait EndpointResolver: Send + Sync + 'static {
    fn refresh<'a>(
        &'a self,
        snapshot: &'a FinalizedSnapshot,
    ) -> BoxFuture<'a, Result<Vec<VerifiedEndpoint>, ManagerError>>;
}

pub trait HeartwoodControl: Send + Sync + 'static {
    fn node_id(&self) -> BoxFuture<'_, Result<[u8; 32], ManagerError>>;
    fn sessions(&self) -> BoxFuture<'_, Result<Vec<ControlSession>, ManagerError>>;
    fn connect<'a>(
        &'a self,
        node_id: [u8; 32],
        addresses: &'a [EndpointAddress],
    ) -> BoxFuture<'a, Result<EndpointAddress, ManagerError>>;
    fn disconnect<'a>(
        &'a self,
        node_id: [u8; 32],
        expected: &'a EndpointAddress,
    ) -> BoxFuture<'a, Result<DisconnectDisposition, ManagerError>>;
    fn seed(&self, repo: RepoId) -> BoxFuture<'_, Result<(), ManagerError>>;
}

pub trait RepositoryStatus: Send + Sync + 'static {
    fn available(&self, repo: RepoId) -> BoxFuture<'_, Result<bool, ManagerError>>;
}
