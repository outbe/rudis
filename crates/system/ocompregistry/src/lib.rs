//! Standalone on-chain authority for OCOMP protocol bundles.

mod errors;
mod fork;
pub mod precompile;
mod profile;
mod runtime;
pub mod schema;

pub use fork::{
    OcompForkInstallClassification, OcompForkInstallV1, OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
};
pub use profile::{poc_schema_limits, OcompRequestProfile};
pub use runtime::{OcompProtocolAuthorityV1, OcompSuccessorV1};
pub use schema::OcompRegistry;

#[cfg(test)]
mod tests;
