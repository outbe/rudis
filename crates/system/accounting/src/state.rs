//! Local storage helpers around [`crate::schema::Accounting`].
//!
//! These helpers are the only sanctioned mutation surface for slot 0
//! (INV4). They are `pub(crate)`-style internals exposed at crate root
//! only through [`crate::runtime`]: external callers must go through the
//! runtime entrypoints so the V2 Phase 1 commit invariant ("only the
//! executor Phase 1 path may write slot 0") stays enforceable from a
//! single place.

use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result;

use crate::schema::Accounting;

/// Reads `last_accounted_block_number` from EVM storage.
///
/// Returns `0` on a fresh chain that has not yet committed any V2 Phase 1
/// (the underlying EVM slot defaults to `U256::ZERO`).
pub(crate) fn last_accounted_block_number(ctx: &BlockRuntimeContext) -> Result<u64> {
    let accounting: Accounting<'_> = ctx.storage.contract::<Accounting<'_>>();
    accounting.last_accounted_block_number.read()
}

/// Writes `last_accounted_block_number` to EVM storage. Intended to be
/// called exclusively by the V2 executor Phase 1 path.
///
/// The function takes a `BlockRuntimeContext` rather than a raw
/// `StorageHandle` so the storage scope is bound to the same block whose
/// Phase 1 is committing - preventing accidental cross-block writes.
pub(crate) fn set_last_accounted_block_number(
    ctx: &BlockRuntimeContext,
    block_number: u64,
) -> Result<()> {
    let accounting: Accounting<'_> = ctx.storage.contract::<Accounting<'_>>();
    accounting.last_accounted_block_number.write(block_number)
}
