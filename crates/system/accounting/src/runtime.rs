//! V2 Phase 1 accounting-progress runtime entrypoints.
//!
//! Two entrypoints:
//!
//! * [`record_phase1_progress`] - writes `last_accounted_block_number = N`
//!   after the V2 Phase 1 system tx for block `N` has successfully
//!   committed. Sole writer for slot 0 of `ACCOUNTING_PROGRESS_ADDRESS`
//!   (INV4). Invoked by the executor reorder.
//! * [`read_last_accounted_block_number`] - read-only accessor for Cycle
//!   and Rewards. Returns `0` on a fresh chain.
//!
//! Monotonicity: this layer rejects regressions defensively, while the
//! Phase 1 precompile enforces the stricter exact-parent sequence.

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use tracing::trace;

use crate::state;

/// Records that V2 Phase 1 for `block_number` has successfully committed.
///
/// **Sole writer** for `ACCOUNTING_PROGRESS_ADDRESS` slot 0 (INV4).
/// Invoked by the V2 executor Phase 1 path. The caller is
/// responsible for ordering: Phase 1 commits an exact-parent successor
/// block, so `block_number` should equal the parent height being
/// accounted for.
pub fn record_phase1_progress(ctx: &BlockRuntimeContext, block_number: u64) -> Result<()> {
    let current = state::last_accounted_block_number(ctx)?;
    if block_number < current {
        return Err(PrecompileError::Revert(format!(
            "last_accounted_block_number regression: current={current}, attempted={block_number}"
        )));
    }
    trace!(
        target: "outbe::accounting",
        block_number,
        "recording V2 Phase 1 accounting progress",
    );
    state::set_last_accounted_block_number(ctx, block_number)
}

/// Reads `last_accounted_block_number` from EVM storage. Returns `0` on a
/// fresh chain that has not yet committed any V2 Phase 1.
pub fn read_last_accounted_block_number(ctx: &BlockRuntimeContext) -> Result<u64> {
    state::last_accounted_block_number(ctx)
}
