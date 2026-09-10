//! Bounded, permissionless, append-only registry of public Heartwood repositories.

pub mod errors;
pub mod precompile;
pub mod schema;

mod runtime;

pub use runtime::{repo_id_from_storage_key, repo_id_storage_key, RepoId, RepositoryRegistration};
pub use schema::RadicleRegistry;

#[cfg(test)]
mod tests;
