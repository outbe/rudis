//! Cross-module API for IntexFactory.
//!
//! `issue` is the clearing engine's (Desis) issuance hand-off - a Rust-to-Rust
//! call, not a precompile selector, mirroring Intex's write API. The
//! user-facing surface (settle / minePromis / setAuthorizedSettler) lives in
//! the precompile.

use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;

use crate::config::{self, IntexParams};
use crate::runtime;
use crate::schema::IssuanceParams;

/// Create a series and enroll it for autonomous qualification, returning what each
/// target chain must be told. Called by the clearing engine after a cleared auction,
/// which packs the day's legs into messages and sends them.
pub fn issue(
    storage: &StorageHandle<'_>,
    params: IssuanceParams,
) -> Result<Vec<runtime::IssuanceLeg>> {
    runtime::issue(storage, params)
}

/// Send a day's issuance legs, packed into as few per-chain messages as the wire allows.
pub fn send_issuance(storage: &StorageHandle<'_>, legs: Vec<runtime::IssuanceLeg>) -> Result<()> {
    runtime::send_issuance(storage, legs)
}

/// Discard a day's contributor map. The clearing engine calls this for a day
/// that issued nothing at all: with no series anywhere, the recorded creator
/// rewards can never be distributed.
pub fn discard_day_contributors(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
) -> Result<()> {
    outbe_intex::api::finalize_proceeds(storage, worldwide_day)
}

/// Resolved IntexFactory protocol parameters (genesis profile). The clearing
/// engine (Desis) reads these to source floor%/call%/call-trigger at auction
/// start, keeping a single source of truth instead of hardcoding them.
pub fn read_params(storage: &StorageHandle<'_>) -> Result<IntexParams> {
    config::read(storage)
}
