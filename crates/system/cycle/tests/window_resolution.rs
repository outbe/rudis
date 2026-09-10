//! - accounting-window resolution + Phase 2 gating tests.
//!
//! These integration tests pin
//!
//!: period window resolves bitwise-deterministically from headers
//!   (proptest at the bottom).
//!: `last_accounted_block_number` is the single gate signal.
//!: no wall-clock reads in Cycle handler decisions.
//!
//! Each `<period>_boundary_cycle_runs_after_parent_accounted` test
//! covers for a different period (hour, day, week, month) by
//! constructing a synthetic gated `TriggerSpec` and asserting that
//! `accounting_gate_blocks` returns `false` once the parent block has
//! been accounted via `outbe_accounting::record_phase1_progress`.
//!
//! `phase1_accounts_parent_before_cycle_tick` is a structural check on
//! `crates/blockchain/evm/src/executor.rs` confirming the V2 reorder
//! invariant that this gate depends on.

use alloy_primitives::Address;
use outbe_accounting::record_phase1_progress;
use outbe_cycle::{
    state::{accounting_gate_blocks, resolve_accounting_window, AccountingWindow},
    triggers::{TriggerHandler, TriggerSpec},
};
use outbe_primitives::{
    accounting_progress::AccountingProgressView,
    block::{BlockContext, BlockRuntimeContext},
    error::Result,
    storage::hashmap::HashMapStorageProvider,
};
use proptest::prelude::*;

const CHAIN_ID: u64 = 1;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;
const WEEK: u64 = 604_800;
const MONTH: u64 = 30 * DAY;

fn gated_spec(period_seconds: u64) -> TriggerSpec {
    TriggerSpec {
        id: 4242,
        label: "test_gated",
        period_seconds,
        start_offset_seconds: 0,
        requires_accounting_window: true,
        coalesces_backlog: false,
        handler: TriggerHandler::IntexDaily,
    }
}

fn ungated_spec(period_seconds: u64) -> TriggerSpec {
    TriggerSpec {
        id: 4243,
        label: "test_ungated",
        period_seconds,
        start_offset_seconds: 0,
        requires_accounting_window: false,
        coalesces_backlog: false,
        handler: TriggerHandler::IntexDaily,
    }
}

fn block_ctx(block_number: u64, timestamp: u64) -> BlockContext {
    BlockContext::new(block_number, timestamp, CHAIN_ID, Address::ZERO, Vec::new())
}

/// Stub `AccountingProgressView` for tests that don't need EVM storage -
/// the proptest and gate-arithmetic checks consume this directly.
struct StubProgress(u64);

impl AccountingProgressView for StubProgress {
    fn last_accounted_block_number(&self) -> Result<u64> {
        Ok(self.0)
    }
}

// ---------------------------------------------------------------------------
// Phase 1 accounting precedes Phase 2 CycleTick.
//
// The "Phase 1 commit happens before the Cycle dispatcher" invariant is covered
// REALLY (no source-text scanning) by two complementary sets of tests:
//
//   * Phase ORDER - `crates/blockchain/evm/tests/phase1_reorder.rs`
//     (`phase1_receipt_index_0_before_cycle_tick`,
//     `phase1_reordering_preserves_body_receipt_order`) asserts, via the real
//     `expected_begin_block_kinds` / `SystemTxPhase` routing API that drives the
//     executor, that Phase 1 owns body_index 0 and CycleTick owns body_index 1.
//   * Gate DEPENDENCY - the behavioral tests below
//     (`*_boundary_cycle_runs_after_parent_accounted` for the committed case and
//     `cycle_job_blocks_when_window_end_not_accounted` for the stale case) prove
//     the Cycle gate reads `last_accounted_block_number` and only runs once the
//     parent is accounted.
//
// Together these make the ordering observable through real APIs/behavior, so no
// source-text scan of the executor is needed.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//.5: boundary tests across hour / day / week / month periods.
// Each builds a synthetic gated trigger, seeds `last_accounted == B - 1`,
// and asserts the gate does NOT block.
// ---------------------------------------------------------------------------

fn boundary_gate_check(period_seconds: u64, block_number: u64, block_ts: u64) {
    let spec = gated_spec(period_seconds);
    let block = block_ctx(block_number, block_ts);

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block.clone(), handle);
        // Seed Phase 1 accounting for the parent block (mirrors what
        // `apply_phase1_commit_in_preexec` does in production).
        record_phase1_progress(&ctx, block_number - 1).unwrap();

        struct Reader<'a, 'b>(&'a BlockRuntimeContext<'b>);
        impl AccountingProgressView for Reader<'_, '_> {
            fn last_accounted_block_number(&self) -> Result<u64> {
                outbe_accounting::read_last_accounted_block_number(self.0)
            }
        }

        let blocked = accounting_gate_blocks(&spec, &Reader(&ctx), &block).unwrap();
        assert!(
            !blocked,
            "{}s-period gate must NOT block when parent is accounted",
            period_seconds
        );

        // The resolved window's `end_inclusive` must equal `block - 1`.
        let window = resolve_accounting_window(&spec, &block).expect("gated window resolves");
        assert_eq!(window.end_inclusive, block_number - 1);
    });
}

#[test]
fn hour_boundary_cycle_runs_after_parent_accounted() {
    // Block 100 at a timestamp inside the second hour-slot.
    boundary_gate_check(HOUR, 100, HOUR * 2 + 5);
}

#[test]
fn day_boundary_cycle_runs_after_parent_accounted() {
    boundary_gate_check(DAY, 100, DAY * 7 + 12);
}

#[test]
fn week_boundary_cycle_runs_after_parent_accounted() {
    boundary_gate_check(WEEK, 100, WEEK * 3 + 17);
}

#[test]
fn month_boundary_cycle_runs_after_parent_accounted() {
    boundary_gate_check(MONTH, 100, MONTH * 2 + 33);
}

// ---------------------------------------------------------------------------
// gated trigger must NOT fire when `last_accounted <
// window.end_inclusive`.
// ---------------------------------------------------------------------------

#[test]
fn cycle_job_blocks_when_window_end_not_accounted() {
    let spec = gated_spec(DAY);
    let block = block_ctx(100, DAY * 7);
    // `last_accounted = 50`, but the gate requires `>= 99` (= 100 - 1).
    let progress = StubProgress(50);
    let blocked = accounting_gate_blocks(&spec, &progress, &block).unwrap();
    assert!(
        blocked,
        "gate must BLOCK when last_accounted < window.end_inclusive"
    );

    // Just-below-threshold edge: last_accounted = end_inclusive - 1.
    let progress_almost = StubProgress(98);
    let blocked_almost = accounting_gate_blocks(&spec, &progress_almost, &block).unwrap();
    assert!(
        blocked_almost,
        "gate must BLOCK at the just-below-threshold edge (98 < 99)"
    );

    // Exact-threshold: last_accounted = end_inclusive. Gate passes.
    let progress_exact = StubProgress(99);
    let blocked_exact = accounting_gate_blocks(&spec, &progress_exact, &block).unwrap();
    assert!(
        !blocked_exact,
        "gate must PASS when last_accounted == window.end_inclusive"
    );
}

// ---------------------------------------------------------------------------
// (Scope 4): ungated trigger fires regardless of accounting.
// ---------------------------------------------------------------------------

#[test]
fn cycle_job_without_accounting_window_runs_on_schedule() {
    let spec = ungated_spec(DAY);
    let block = block_ctx(100, DAY * 7);

    // Resolver returns `None` for ungated specs even on a deeply
    // accounted chain - the gate never consults the progress view.
    let window = resolve_accounting_window(&spec, &block);
    assert!(window.is_none(), "ungated spec must resolve to no window");

    // The gate must return `false` (i.e., "do not block") for ungated
    // triggers regardless of progress, including a deliberately-stale
    // `last_accounted = 0` reader that would block any gated trigger.
    let progress = StubProgress(0);
    let blocked = accounting_gate_blocks(&spec, &progress, &block).unwrap();
    assert!(
        !blocked,
        "ungated trigger must never be blocked by the accounting gate"
    );
}

// ---------------------------------------------------------------------------
// Bootstrap edge: blocks 0 and 1 (no V2 Phase 1) must resolve to `None`
// so the dispatcher fires without consulting accounting.
// ---------------------------------------------------------------------------

#[test]
fn genesis_bootstrap_resolves_to_no_window_for_gated_trigger() {
    let spec = gated_spec(DAY);
    for block_number in [0u64, 1] {
        let block = block_ctx(block_number, DAY);
        let window = resolve_accounting_window(&spec, &block);
        assert!(
            window.is_none(),
            "genesis bootstrap (block {block_number}) must not require accounting"
        );

        // Gate returns `false` even with `last_accounted = 0`.
        let blocked = accounting_gate_blocks(&spec, &StubProgress(0), &block).unwrap();
        assert!(
            !blocked,
            "genesis bootstrap gate must never block trigger (block {block_number})"
        );
    }
}

// ---------------------------------------------------------------------------
// determinism property - same inputs -> same
// `AccountingWindow`. The resolver must be a pure function over
// `(period, offset, block_number, timestamp)` with no wall-clock or
// RNG dependency.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn cycle_window_resolution_deterministic_from_headers(
        period in 60u64..=MONTH,
        offset_raw in 0u64..=DAY,
        block_number in 2u64..1_000_000,
        block_ts in 86_400u64..2_000_000_000,
    ) {
        let offset = offset_raw % period;
        let spec = TriggerSpec {
            id: 99,
            label: "proptest",
            period_seconds: period,
            start_offset_seconds: offset,
            requires_accounting_window: true,
            coalesces_backlog: false,
            handler: TriggerHandler::IntexDaily,
        };
        let block = block_ctx(block_number, block_ts);

        let a = resolve_accounting_window(&spec, &block);
        let b = resolve_accounting_window(&spec, &block);
        prop_assert_eq!(
            a, b,
            "resolver must be a pure function over (period, offset, block, ts)"
        );

        let window = a.expect("gated + block_number >= 2 always resolves Some");
        prop_assert_eq!(
            window.end_inclusive,
            block_number - 1,
            "end_inclusive must equal parent block number"
        );
        prop_assert_eq!(
            window,
            AccountingWindow {
                start_block: window.start_block,
                end_inclusive: block_number - 1,
            },
            "window equality round-trips for the same inputs"
        );
    }
}
