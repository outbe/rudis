//! `outbe-engine` - bridge layer between pure `outbe-consensus`
//! (Simplex/hybrid/DKG/proof) and the EVM/node side (`outbe-evm`,
//! `outbe-validatorset`, `outbe-node`).
//!
//! Owns:
//! * `stack.rs` - engine startup, epoch loop, reshare monitoring.
//! * `validators.rs` - ValidatorSet storage reader (Reth state -> Commonware
//!   participant set).
//! * `peer_manager/` - P2P peer registration against `outbe-node`.
//! * `args.rs` - `ConsensusArgs` CLI bundle for engine startup.
//! * `bridge.rs` - re-exports for `ConsensusExecutionBridge` wiring.

pub mod application_shutdown;
pub mod args;
pub mod bridge;
pub mod ce_finalizer;
pub mod ce_recovery;
pub(crate) mod follow_transport;
pub mod follower_shutdown;
pub(crate) mod marshal_update_reporter;
pub(crate) mod peer_manager;
pub mod stack;
pub mod tee_bootstrap;
pub mod validators;

pub use args::ConsensusArgs;
pub use stack::{run_consensus_stack, ConsensusStackServices};

/// Read the exact offer-key commitment from the selected certified upstream.
/// Full-node startup uses this narrow adapter before launching execution.
pub async fn read_upstream_tribute_offer_public_key(
    url: &str,
) -> eyre::Result<alloy_primitives::B256> {
    follow_transport::UpstreamRpcClient::new(url)?
        .tribute_offer_public_key()
        .await
}
