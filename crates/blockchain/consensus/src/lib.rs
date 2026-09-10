//! Outbe consensus integration with Commonware Simplex.
//!
//! Bridges Commonware's Simplex BFT consensus engine with Reth's execution layer.
//!
//! - Phase 1: Static validator set, RoundRobin leader election.
//! - Phase 2: Dynamic validator reading from EVM state.
//! - Phase 3: BLS12-381 threshold VRF scheme, Random leader election.
//! - Phase 4: Hybrid scheme (BLS individual attribution + BLS threshold VRF).

pub mod block;
pub mod bls;
pub mod cli;
pub mod committee_provider;
pub mod config;
pub mod digest;
pub mod dkg;
pub mod dkg_actor;
pub mod dkg_manager;
pub mod epoch_registry;
pub mod epoch_subchannels;
pub mod forfeit;
pub mod hybrid;
pub mod metrics;
pub(crate) mod missed_proposers;
pub mod ocomp_retention;
pub mod proof;
pub mod timing;
pub mod vrf_safety;

/// Re-export of the validator-set data types from `outbe-primitives`. The
/// canonical definitions live in `outbe_primitives::validators`; this alias
/// keeps existing `outbe_consensus::validators::*` (and crate-local
/// `crate::validators::*`) call sites unchanged.
pub use outbe_primitives::validators;

#[cfg(test)]
mod marshal_resolver_p2p_tests;
#[cfg(test)]
mod marshal_tests;
pub mod marshal_types;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod telemetry_label_tests;

#[cfg(any(test, feature = "test-utils"))]
pub mod finalized_admission_test_utils;
#[cfg(any(test, feature = "test-utils"))]
#[path = "test_harness.rs"]
pub mod test_harness;

pub mod ancestry_readiness;
pub mod application;
pub mod executor;
pub mod finalization;
pub mod follow;
pub mod reporter;
pub mod storage_identity;
pub(crate) mod test_faults;
#[cfg(test)]
mod test_fixtures;
pub(crate) mod util;
