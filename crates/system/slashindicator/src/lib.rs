//! Module-structure standard layout:
//! - `schema.rs` - storage schema for the `SlashIndicator` facade.
//! - `runtime.rs` - slashing use-cases.
//! - `evidence.rs` - byzantine evidence handling.
//! - `hooks.rs` - per-finalized-block guard wrappers.
//! - `precompile.rs` - ABI dispatch.
//!
//! `pub use` re-exports below preserve the old `contract` / `logic`
//! paths for external callers; migrate them opportunistically.
mod evidence;
pub mod hooks;
pub mod metrics;
pub mod precompile;
pub mod runtime;
pub mod schema;
mod seed_partial_evidence;
pub mod vrf_evidence;

#[cfg(test)]
mod tests;

pub mod contract {
    pub use crate::schema::*;
}
pub mod logic {
    pub use crate::runtime::*;
}
