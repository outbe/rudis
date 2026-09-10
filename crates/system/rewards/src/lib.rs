//! - `schema.rs` - storage schema (the `Rewards` `#[contract]` facade).
//! - `runtime.rs` - runtime helpers (genesis anchor, fingerprint,
//!   day-number conversion).
//! - `lifecycle.rs` - block-boundary entrypoint (`begin_block`).
//! - `precompile.rs` - ABI dispatch.
//! - `api.rs` - public cross-module surface used by the Cycle handler.
//! - `finalized_metadata_hook.rs` - per-finalized-block hook called from
//!   the executor's post-exec block.
//!
//! Day-boundary settle was removed from this crate (Phase
//! 6 of the Cycle epic). Daily emission orchestration now lives in
//! `outbe-cycle::handler::run_emission_limit_daily`.
//!
//! `pub use` re-exports below preserve the old `contract` / `logic`
//! paths so external callers (RPC, executor, builder, validator set)
//! keep compiling without a sweeping rename. Migrate call sites
//! opportunistically when next touched, then drop the re-exports.
pub mod api;
pub mod constants;
pub mod finalized_metadata_hook;
pub mod late_settlement;
pub mod lifecycle;
pub mod precompile;
pub mod runtime;
pub mod schema;

// Backward-compat aliases for external callers (deprecate when all
// `outbe_rewards::contract::*` / `outbe_rewards::logic::*` call sites
// are migrated).
pub mod contract {
    pub use crate::schema::*;
}
pub mod logic {
    pub use crate::runtime::*;
}
