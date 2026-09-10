//! : deterministic accounting-window resolution and Phase 2
//! gating helpers used by the Cycle dispatcher.
//!
//! Under V2 Certified-Parent Accounting, Phase 1
//! (`CertifiedParentAccounting`) writes
//! `last_accounted_block_number := parent_block_number` to
//! `ACCOUNTING_PROGRESS_ADDRESS` slot 0 BEFORE Phase 2 (`CycleTick`)
//! executes. This module surfaces that property as an
//! explicit gate so a regression that reorders Phase 1 vs Phase 2 - or
//! adds a Cycle trigger that reads validator-pool state racing the
//! parent-finalization tx - is caught at the dispatcher boundary.
//!
//! ## Resolution contract
//!
//! [`resolve_accounting_window`] is a pure function over
//! `(spec.period_seconds, spec.start_offset_seconds, block.timestamp,
//! block.block_number)`. It returns:
//!
//! * `None` when the trigger opted out of accounting gating
//!   (`spec.requires_accounting_window == false`) OR when the chain has
//!   not yet produced a Phase-1-eligible block (genesis bootstrap:
//!   `block_number <= GENESIS_BOOTSTRAP_BLOCK_NUMBER = 1`).
//! * `Some(AccountingWindow { start_block, end_inclusive })` otherwise.
//!   `end_inclusive == block_number - 1` (the parent block, which Phase 1
//!   must have accounted). `start_block` is informational - derived
//!   deterministically from the period boundary preceding the current
//!   block's timestamp - and is currently NOT consulted by the gate;
//!   it exists for observability and is pinned by the proptest.
//!
//! ## Determinism
//!
//! No wall-clock reads, no RNG, no `HashMap` iteration. All arithmetic
//! is saturating on `u64`. The function is a single pure expression of
//! its inputs; calling it twice with the same arguments returns the same
//! result byte-for-byte. The proptest
//! `cycle_window_resolution_deterministic_from_headers` pins this.

use outbe_primitives::{
    accounting_progress::AccountingProgressView,
    block::{BlockContext, BlockRuntimeContext},
    error::Result,
};

use crate::triggers::TriggerSpec;

/// deterministic accounting window for a Cycle trigger.
///
/// The dispatcher's eligibility check is `last_accounted_block_number
/// >= end_inclusive`. `start_block` is informational.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountingWindow {
    /// First block of the period, computed deterministically from the
    /// period boundary preceding `block.timestamp`. Informational only:
    /// the gate inspects `end_inclusive`, not `start_block`.
    pub start_block: u64,
    /// Last block whose Phase 1 accounting must have committed before the
    /// trigger may fire. For all current triggers this equals the parent
    /// block number (`block.block_number - 1`).
    pub end_inclusive: u64,
}

/// pure window resolver. See module docs for the contract.
///
/// Returns `None` for ungated triggers (`requires_accounting_window ==
/// false`) and for genesis-bootstrap blocks (block number <= 1), where
/// there is no V2 Phase 1 commit to gate on.
pub fn resolve_accounting_window(
    spec: &TriggerSpec,
    block: &BlockContext,
) -> Option<AccountingWindow> {
    if !spec.requires_accounting_window {
        return None;
    }
    // V2 genesis bootstrap: block 0 and block 1 do not
    // run Phase 1, so there is nothing to gate on. Allow the trigger
    // through (the dispatcher's existing first-encounter anchor still
    // defers the first real fire to the next slot).
    if block.block_number <= 1 {
        return None;
    }
    if spec.period_seconds == 0 {
        return None;
    }

    // end_inclusive = parent block. The Phase 1 -> Phase 2 ordering
    // invariant means a correctly-built block has Phase 1
    // committed before this gate runs, so `last_accounted_block_number`
    // is at least `block_number - 1` and the gate passes.
    let end_inclusive = block.block_number.saturating_sub(1);

    // Informational `start_block`: derived from the period boundary
    // preceding `block.timestamp`. We don't have a (timestamp ->
    // block_number) inverse lookup at this scope; use the period start
    // timestamp itself as an opaque deterministic marker. Pinned by the
    // proptest only on the property of determinism, not on a specific
    // numeric meaning.
    let offset_in_period = spec.start_offset_seconds % spec.period_seconds;
    let period_start_ts = block
        .timestamp
        .saturating_sub(offset_in_period)
        .checked_div(spec.period_seconds)
        .unwrap_or(0)
        .saturating_mul(spec.period_seconds)
        .saturating_add(offset_in_period);
    Some(AccountingWindow {
        start_block: period_start_ts,
        end_inclusive,
    })
}

/// returns `true` when the dispatcher must defer firing
/// `spec` because Phase 1 has not yet committed accounting up through
/// `window.end_inclusive`. Returns `false` for ungated triggers and for
/// gated triggers whose accounting has caught up.
pub fn accounting_gate_blocks(
    spec: &TriggerSpec,
    progress: &dyn AccountingProgressView,
    block: &BlockContext,
) -> Result<bool> {
    let Some(window) = resolve_accounting_window(spec, block) else {
        return Ok(false);
    };
    let last_accounted = progress.last_accounted_block_number()?;
    Ok(last_accounted < window.end_inclusive)
}

/// Cycle-internal [`AccountingProgressView`] that reads
/// `last_accounted_block_number` via [`outbe_accounting::read_last_accounted_block_number`].
///
/// Routing the dispatcher's gate through this trait satisfies Scope 1:
/// the handler observes accounting progress via the
/// [`AccountingProgressView`] surface (`outbe-primitives`) rather than
/// reaching into Rewards storage directly.
pub(crate) struct EvmAccountingProgress<'a, 'storage> {
    ctx: &'a BlockRuntimeContext<'storage>,
}

impl<'a, 'storage> EvmAccountingProgress<'a, 'storage> {
    pub(crate) fn new(ctx: &'a BlockRuntimeContext<'storage>) -> Self {
        Self { ctx }
    }
}

impl AccountingProgressView for EvmAccountingProgress<'_, '_> {
    fn last_accounted_block_number(&self) -> Result<u64> {
        outbe_accounting::read_last_accounted_block_number(self.ctx)
    }
}
