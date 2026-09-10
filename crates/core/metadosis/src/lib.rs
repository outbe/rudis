//! Production Metadosis exposes typed reads and purpose-bound commands, but
//! keeps raw schema/state/runtime mutation surfaces crate-private.
//!
//! The `test-utils` feature exposes the opaque semantic scenarios in
//! [`test_support`] and the narrowly typed, pre-launch-only [`genesis`]
//! builder. Raw modules remain inaccessible to external crates in both
//! default and `test-utils` builds.
//!
//! ```compile_fail
//! use outbe_metadosis::schema::MetadosisContract;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::runtime::advance_active_worldwide_days;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::ocomp::expiry::run_lifecycle_begin;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::emission_sink::apply;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::ocomp::expiry::record_certified_parent_finality;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::ocomp::request::run_terminal_request;
//! ```
//!
//! ```compile_fail
//! use outbe_metadosis::schema::MetadosisContract;
//! fn raw_profile_or_fork_initializer(contract: &mut MetadosisContract<'_>) {
//!     let _ = contract.initialize_ocomp_request_profile(todo!(), todo!());
//!     let _ = contract.initialize_ocomp_fork_install(todo!(), 0, todo!());
//! }
//! ```

mod aggregate;
pub mod api;
#[cfg(feature = "bench-utils")]
pub mod bench_support;
pub mod commands;
mod commit;
pub mod config;
pub mod constants;
mod emission_sink;
pub mod errors;
#[cfg(any(test, feature = "test-utils"))]
#[path = "ocomp/test_support.rs"]
mod fixture_kernel;
#[cfg(feature = "test-utils")]
pub mod genesis;
mod lifecycle;
mod ocomp;
pub use ocomp::vote::{
    deadline_passed_result_vote_revert_data, is_deadline_passed_result_vote_revert_data,
    resolve_historical_result_vote_carrier_signer, resolve_historical_result_vote_participant,
};
pub(crate) mod ocomp_budget;
mod pre_admission;
pub mod precompile;
pub mod proof_layout;
mod reducer;
mod runtime;
mod schema;
mod settlement;
mod state;
mod terminal;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_support;

pub use aggregate::{WwdDayType, WwdMembership, WwdProjection, WwdStatus};
pub use ocomp::fork::{OcompForkInstallClassification, OcompForkInstallV1};
pub use pre_admission::MetadosisPreAdmissionProjection;
pub use state::{DayLimitFormationReceipt, OcompDayLimitFormation};

/// Pure in-memory OCOMP FSM model. It carries no storage handle and cannot
/// mutate consensus state.
pub mod model {
    pub use crate::ocomp::state::{
        transition_rules, DayPhase, JobFsmCommand, JobFsmState, JobFsmTransitionKind,
        ReadyAttemptSnapshot, RequestEffectMode,
    };
}

#[cfg(test)]
mod tests;
