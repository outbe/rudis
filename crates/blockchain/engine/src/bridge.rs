//! Re-exports bridge types from `outbe_primitives::consensus`.
//!
//! The actual bridge types live in `outbe-primitives` to avoid circular
//! dependencies between `outbe-consensus` and `outbe-evm`.

pub use outbe_primitives::consensus::{
    ConsensusData, ConsensusExecutionBridge, ConsensusStatus, ParticipationData,
};
