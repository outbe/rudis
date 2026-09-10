use crate::manager::{
    BoxFuture, FinalizedBlock, FinalizedFeed, FinalizedValidator, ManagerError, RepositoryStatus,
    SnapshotReader,
};
use crate::{
    integration::SignedEndpointEvidence,
    manager::{FinalizedSnapshot, ManagerPhase, ManagerStatus, PhaseError},
};
use alloy_primitives::Address;
use outbe_radicleregistry::RepoId;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadicleVotingGateError {
    SidecarUnavailable,
    LocalNodeIdUnavailable,
    ActiveBindingMissing,
    BindingMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadicleVotingGate {
    Verifier,
    SignerAllowed,
    Fatal(RadicleVotingGateError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactBindingState {
    SelfAbsent,
    ActiveMissing,
    ActiveMatching,
    ActiveMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VotingGateInput {
    pub binding: ExactBindingState,
    pub manager_phase: ManagerPhase,
    pub phase_error: Option<PhaseError>,
    pub ever_ready: bool,
}

#[must_use]
pub fn evaluate_voting_gate(input: VotingGateInput) -> RadicleVotingGate {
    use ExactBindingState::{ActiveMatching, ActiveMismatch, ActiveMissing, SelfAbsent};
    use RadicleVotingGate::{Fatal, SignerAllowed, Verifier};
    match input.binding {
        ActiveMissing => Fatal(RadicleVotingGateError::ActiveBindingMissing),
        ActiveMismatch => Fatal(RadicleVotingGateError::BindingMismatch),
        SelfAbsent | ActiveMatching if input.phase_error == Some(PhaseError::BindingMismatch) => {
            Fatal(RadicleVotingGateError::BindingMismatch)
        }
        SelfAbsent | ActiveMatching if !input.ever_ready => match input.phase_error {
            Some(PhaseError::SidecarUnavailable) => {
                Fatal(RadicleVotingGateError::SidecarUnavailable)
            }
            Some(PhaseError::LocalNodeIdUnavailable) => {
                Fatal(RadicleVotingGateError::LocalNodeIdUnavailable)
            }
            Some(PhaseError::BindingMismatch) => unreachable!("handled above"),
            None => match input.binding {
                ActiveMatching if input.manager_phase == ManagerPhase::Ready => SignerAllowed,
                _ => Verifier,
            },
        },
        SelfAbsent => Verifier,
        ActiveMatching => SignerAllowed,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadicleRepositoryState {
    Available,
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadicleRepositorySnapshot {
    pub repo_id: RepoId,
    pub state: RadicleRepositoryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadicleStatusSnapshot {
    pub validator: Option<Address>,
    pub local_node_id: Option<[u8; 32]>,
    pub voting_gate: RadicleVotingGate,
    pub manager: ManagerStatus,
    pub repositories: Vec<RadicleRepositorySnapshot>,
    pub signed_peers: Vec<SignedEndpointEvidence>,
    exact_binding: ExactBindingState,
    ever_ready: bool,
    evidence_height: Option<u64>,
    evidence_validators: Vec<FinalizedValidator>,
}

impl Default for RadicleStatusSnapshot {
    fn default() -> Self {
        Self {
            validator: None,
            local_node_id: None,
            voting_gate: RadicleVotingGate::Verifier,
            manager: ManagerStatus::default(),
            repositories: Vec::new(),
            signed_peers: Vec::new(),
            exact_binding: ExactBindingState::SelfAbsent,
            ever_ready: false,
            evidence_height: None,
            evidence_validators: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct RadicleStatusPublisher(watch::Sender<RadicleStatusSnapshot>);

#[derive(Clone)]
pub struct RadicleStatusHandle(watch::Receiver<RadicleStatusSnapshot>);

pub struct RadicleStatusChannel;

impl RadicleStatusChannel {
    #[must_use]
    pub fn enabled(
        validator: Address,
        node_id: [u8; 32],
    ) -> (RadicleStatusPublisher, RadicleStatusHandle) {
        let (publisher, status) = watch::channel(RadicleStatusSnapshot {
            validator: Some(validator),
            local_node_id: Some(node_id),
            manager: ManagerStatus {
                phase: ManagerPhase::JoiningUnbound,
                ..ManagerStatus::default()
            },
            ..RadicleStatusSnapshot::default()
        });
        (
            RadicleStatusPublisher(publisher),
            RadicleStatusHandle(status),
        )
    }

    #[must_use]
    pub fn disabled() -> RadicleStatusHandle {
        let (_publisher, status) = watch::channel(RadicleStatusSnapshot::default());
        RadicleStatusHandle(status)
    }
}

impl RadicleStatusPublisher {
    pub fn observe_snapshot(&self, snapshot: &FinalizedSnapshot) {
        self.0.send_modify(|state| {
            state.signed_peers.retain(|proof| {
                evidence_matches(snapshot.block.number, &snapshot.validators, proof)
            });
            state.evidence_height = Some(snapshot.block.number);
            state.evidence_validators.clone_from(&snapshot.validators);
            state.repositories = snapshot
                .repositories
                .iter()
                .copied()
                .map(|repo_id| RadicleRepositorySnapshot {
                    repo_id,
                    state: RadicleRepositoryState::Pending,
                })
                .collect();
            state.repositories.sort_by_key(|entry| entry.repo_id);
            if let (Some(validator), Some(node_id)) = (state.validator, state.local_node_id) {
                state.exact_binding = match snapshot
                    .validators
                    .iter()
                    .find(|candidate| candidate.address == validator)
                {
                    None => ExactBindingState::SelfAbsent,
                    Some(candidate) if candidate.node_id.is_none() => {
                        ExactBindingState::ActiveMissing
                    }
                    Some(candidate) if candidate.node_id == Some(node_id) => {
                        ExactBindingState::ActiveMatching
                    }
                    Some(_) => ExactBindingState::ActiveMismatch,
                };
                recompute_gate(state);
            }
        });
    }

    pub fn observe_repository(&self, repo_id: RepoId, available: bool) {
        self.0.send_modify(|state| {
            if let Some(repository) = state
                .repositories
                .iter_mut()
                .find(|repository| repository.repo_id == repo_id)
            {
                repository.state = if available {
                    RadicleRepositoryState::Available
                } else {
                    RadicleRepositoryState::Pending
                };
            }
        });
    }

    pub fn observe_manager(&self, manager: ManagerStatus) {
        self.0.send_modify(|state| {
            state.ever_ready |= manager.phase == ManagerPhase::Ready;
            state.manager = manager;
            recompute_gate(state);
        });
    }

    pub fn observe_evidence(&self, signed_peers: Vec<SignedEndpointEvidence>) {
        self.0.send_modify(|state| {
            state.signed_peers = state.evidence_height.map_or_else(Vec::new, |height| {
                signed_peers
                    .into_iter()
                    .filter(|proof| evidence_matches(height, &state.evidence_validators, proof))
                    .collect()
            });
        });
    }

    pub fn set_voting_gate(&self, gate: RadicleVotingGate) {
        self.0.send_modify(|state| state.voting_gate = gate);
    }

    pub fn mark_startup_ready(&self) {
        self.0.send_modify(|state| {
            state.ever_ready = true;
            state.voting_gate = RadicleVotingGate::SignerAllowed;
        });
    }
}

fn evidence_matches(
    height: u64,
    validators: &[FinalizedValidator],
    proof: &SignedEndpointEvidence,
) -> bool {
    let body = proof.response.body();
    body.valid_until > height
        && validators.iter().any(|validator| {
            validator.address == body.validator
                && validator.peer == proof.peer
                && validator.node_id == Some(body.node_id)
        })
}

impl RadicleStatusHandle {
    #[must_use]
    pub fn snapshot(&self) -> RadicleStatusSnapshot {
        self.0.borrow().clone()
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<RadicleStatusSnapshot> {
        self.0.clone()
    }
}

fn recompute_gate(state: &mut RadicleStatusSnapshot) {
    state.voting_gate = evaluate_voting_gate(VotingGateInput {
        binding: state.exact_binding,
        manager_phase: state.manager.phase,
        phase_error: state.manager.phase_error,
        ever_ready: state.ever_ready,
    });
}

#[derive(Clone)]
pub struct ObservedSnapshotReader {
    inner: Arc<dyn SnapshotReader>,
    publisher: RadicleStatusPublisher,
}

impl ObservedSnapshotReader {
    #[must_use]
    pub fn new(inner: Arc<dyn SnapshotReader>, publisher: RadicleStatusPublisher) -> Self {
        Self { inner, publisher }
    }
}

impl SnapshotReader for ObservedSnapshotReader {
    fn read_exact(
        &self,
        block: crate::manager::FinalizedBlock,
    ) -> Result<FinalizedSnapshot, ManagerError> {
        let snapshot = self.inner.read_exact(block)?;
        self.publisher.observe_snapshot(&snapshot);
        Ok(snapshot)
    }
}

#[derive(Clone)]
pub struct GenesisFallbackFinalizedFeed {
    inner: Arc<dyn FinalizedFeed>,
    genesis: FinalizedBlock,
}

impl GenesisFallbackFinalizedFeed {
    #[must_use]
    pub fn new(inner: Arc<dyn FinalizedFeed>, genesis: FinalizedBlock) -> Self {
        Self { inner, genesis }
    }
}

impl FinalizedFeed for GenesisFallbackFinalizedFeed {
    fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<FinalizedBlock>, ManagerError> {
        self.inner.subscribe()
    }

    fn sample(&self) -> BoxFuture<'_, Result<Option<FinalizedBlock>, ManagerError>> {
        Box::pin(async move { Ok(self.inner.sample().await?.or(Some(self.genesis))) })
    }
}

#[derive(Clone)]
pub struct ObservedRepositoryStatus {
    inner: Arc<dyn RepositoryStatus>,
    publisher: RadicleStatusPublisher,
}

impl ObservedRepositoryStatus {
    #[must_use]
    pub fn new(inner: Arc<dyn RepositoryStatus>, publisher: RadicleStatusPublisher) -> Self {
        Self { inner, publisher }
    }
}

impl RepositoryStatus for ObservedRepositoryStatus {
    fn available(&self, repo: RepoId) -> BoxFuture<'_, Result<bool, ManagerError>> {
        Box::pin(async move {
            let result = self.inner.available(repo).await;
            self.publisher
                .observe_repository(repo, result.as_ref().copied().unwrap_or(false));
            result
        })
    }
}
