pub mod certified;
pub mod errors;
pub mod precompile;
pub mod projection;
mod repository;
mod retention;
pub mod runtime;
pub mod schema;
pub mod state;

pub use repository::{
    canonical_body, from_canonical_body, TributePage, TributePageRequest, TributeRepositoryError,
    TributeRepositoryReader, TributeRepositoryWriter,
};
pub use retention::{
    RetainedTributeCursor, RetainedTributePage, RetainedTributePin, RetainedTributeReader,
    RetainedTributeRef, RetainedTributeWriter, OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE,
    OCOMP_RETAINED_TRIBUTES_NAMESPACE,
};
pub use runtime::LoadedTribute;
pub use schema::{DayPreAdmission, DayTotals, TributeContract, TributeData};
pub use state::TributePreAdmissionProjection;

#[cfg(test)]
mod tests;
