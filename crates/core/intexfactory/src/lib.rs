//! IntexFactory: Intex issuance, settlement (settle / minePromis), and the
//! autonomous Issued -> Qualified -> Called lifecycle. Series state is written to
//! Intex; this module owns the settlement bookkeeping and candidate index.

pub mod api;
pub mod called;
pub mod config;
pub mod constants;
pub mod errors;
pub(crate) mod expired;
pub mod precompile;
pub mod qualified;
pub(crate) mod runtime;
pub mod schema;
pub(crate) mod sol_ext;
pub(crate) mod state;

pub use api::{issue, read_params};
pub use config::IntexParams;
pub use errors::IntexFactoryError;
pub use outbe_intex::SeriesId;
pub use qualified::IntexLifecycle;
pub use runtime::{marked_up, to_wire_price};
pub use schema::{IntexFactoryContract, IssuanceParams};

/// Narrow benchmark-only access to the already-public issuance hand-off type.
#[cfg(feature = "bench-utils")]
pub mod bench_support {
    pub use crate::runtime::IssuanceLeg;
}

#[cfg(test)]
mod tests;
