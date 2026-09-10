pub mod api;
pub mod constants;
pub mod errors;
pub mod genesis;
pub mod lifecycle;
mod openings;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod scurve;
pub mod state;
pub mod tally;

pub use errors::{OracleError, OracleOcompError};
pub use openings::{
    evaluate_oracle_opening_v1, oracle_count_slot_plan_v1, oracle_opening_slot_plan_v1,
    OracleCountSlotPlanV1, OracleOpeningEvaluationV1, OracleOpeningSlotPlanV1,
    MAX_OCOMP_ACTIVE_SCURVE_ENTRIES, MAX_OCOMP_REFERENCE_CURRENCIES, MAX_OCOMP_REFERENCE_ISOS,
    ORACLE_COUNT_SLOTS_V1,
};

#[cfg(test)]
mod tests;
pub mod types;
