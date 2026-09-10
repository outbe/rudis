mod lifecycle;
mod metrics;
mod network;
mod sidecar;
mod status;

pub use lifecycle::EndpointTaskOwner;
pub use metrics::RadicleMetrics;
pub use network::{
    shutdown_bounded, EndpointEvidenceHandle, EndpointNetwork, EndpointNetworkService,
    LocalEndpointIdentity, LocalEndpointIdentityChannel, LocalEndpointIdentityHandle,
    LocalEndpointIdentityPublisher, SignedEndpointEvidence,
};
pub use sidecar::{query_sidecar, SidecarError, SidecarInfo};
pub use status::{
    evaluate_voting_gate, ExactBindingState, GenesisFallbackFinalizedFeed,
    ObservedRepositoryStatus, ObservedSnapshotReader, RadicleRepositorySnapshot,
    RadicleRepositoryState, RadicleStatusChannel, RadicleStatusHandle, RadicleStatusPublisher,
    RadicleStatusSnapshot, RadicleVotingGate, RadicleVotingGateError, VotingGateInput,
};

pub const PRODUCTION_REPAIR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
