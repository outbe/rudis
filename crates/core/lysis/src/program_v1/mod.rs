//! Storage-independent Lysis V1 semantic program.
//!
//! The program consumes request-pinned logical observations and emits typed
//! actions. It owns no storage, node, process, codec or worker dependency.

pub mod artifacts;
mod execute;
pub mod finalizer;
pub mod phases;
pub mod planner;
pub mod reducers;
pub mod result;
mod types;

pub use execute::execute;
pub(crate) use execute::{checked_nominal_step, prepare};
#[cfg(test)]
pub(crate) use execute::{compute_fraction_hash_map, validate_required_gratis};
pub use types::{
    ContributorActionV1, FidelityPhaseV1, LeagueFractionV1, NodActionV1, ObservationValueV1,
    ObservedTributeV1, ProgramErrorV1, ProgramInputV1, ProgramResultV1, SemanticObservationV1,
    TributeInputV1,
};
