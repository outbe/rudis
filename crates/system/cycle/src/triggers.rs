//! Code-defined trigger registry.
//!
//! Triggers are declared as `const` data - there is no on-chain
//! registration path. Adding, removing, or re-parameterizing a trigger
//! is a hard-fork-coordinated code change. The dispatcher in
//! [`crate::runtime`] iterates this slice on every block and fires any
//! trigger whose next slot has been reached.

use outbe_compressed_entities::{ExecutionScope, ParentBodySource};
use outbe_primitives::{block::BlockRuntimeContext, error::Result};

/// Stable on-chain identifier for each trigger. The numeric values
/// must remain byte-equal forever - they are emitted as the indexed
/// `id` in [`crate::ICycle::CycleTriggerExecuted`] and persisted in
/// the [`crate::schema::Cycle`] mappings. New triggers append; never
/// renumber existing ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TriggerId {
    ProtocolCycle = 0,
    IntexCallDaily = 1,
    /// Reserved historical identifier; no active trigger uses it.
    WwdAdvanceNoon = 2,
    AuctionAdvance = 3,
    GemCallDaily = 4,
    AuctionClearing = 5,
    IntexNotify = 6,
    CredisCallDaily = 7,
    NodCallDaily = 8,
    GemPositionDaily = 9,
}

impl TriggerId {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// One trigger's static configuration plus its handler function
/// pointer. Handlers receive only typed, read-only body capabilities.
#[derive(Clone, Copy)]
pub struct TriggerSpec {
    pub id: u32,
    pub label: &'static str,
    /// Slot length in seconds. `period_seconds = 86_400` => daily.
    pub period_seconds: u64,
    /// Phase offset from unix epoch zero, in `[0, period_seconds)`.
    /// `period_seconds = 86_400, start_offset_seconds = 0` => UTC
    /// midnight slots; `period_seconds = 3600, start_offset_seconds =
    /// 1800` => "every hour at :30".
    pub start_offset_seconds: u64,
    /// when `true`, the dispatcher must additionally verify
    /// that V2 Phase 1 (`CertifiedParentAccounting`) has committed
    /// progress for the parent block - i.e.,
    /// `last_accounted_block_number >= window.end_inclusive` - before
    /// firing the handler. When `false` (e.g., a job that does NOT depend
    /// on parent accounting state) the handler runs on its own schedule
    /// without consulting [`outbe_primitives::accounting_progress::AccountingProgressView`].
    /// Default for the canonical protocol-cycle trigger is `true`.
    pub requires_accounting_window: bool,
    /// When `true` a backlog collapses to the latest due slot instead of
    /// replaying every missed one. ProtocolCycle owns its UTC-day decision,
    /// so replaying every missed hourly slot would duplicate orchestration.
    pub coalesces_backlog: bool,
    /// Handler invoked when a slot fires. Failure rolls back the
    /// trigger's checkpoint and leaves `last_executed_at` unchanged.
    pub handler: TriggerHandler,
}

#[derive(Clone, Copy)]
pub enum TriggerHandler {
    ProtocolCycle,
    IntexDaily,
    AuctionAdvance,
    GemCallDaily,
    AuctionClearing,
    IntexNotify,
    CredisCallDaily,
    NodCallDaily,
    GemPositionDaily,
}

impl TriggerHandler {
    pub(crate) fn run(
        self,
        ctx: &BlockRuntimeContext,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
    ) -> Result<()> {
        match self {
            Self::ProtocolCycle => crate::handler::run_protocol_cycle(ctx, scope, parent),
            Self::IntexDaily => outbe_intexfactory::called::run_daily(ctx),
            Self::AuctionAdvance => outbe_desis::tick_schedule(ctx),
            Self::GemCallDaily => outbe_gem::hooks::run_call_daily(ctx),
            Self::AuctionClearing => outbe_desis::tick_gate(ctx),
            Self::IntexNotify => outbe_intexfactory::qualified::drain_notices(ctx),
            Self::CredisCallDaily => outbe_credisfactory::called::run_daily(ctx),
            Self::NodCallDaily => outbe_nod::called::run_call_daily(ctx, scope, parent),
            Self::GemPositionDaily => outbe_gemfactory::expired::run_daily(ctx),
        }
    }
}

/// Briefs arrive on the hourly protocol cadence, and a brief only becomes a live
/// auction on this tick: a slower cadence would spend the commit window
/// `preflight_brief` reserved on waiting for the start.
///
/// An e2e day is minutes long, so it advances faster still.
#[cfg(not(feature = "e2e-test"))]
const AUCTION_ADVANCE_PERIOD_SECONDS: u64 = 3_600;
#[cfg(feature = "e2e-test")]
const AUCTION_ADVANCE_PERIOD_SECONDS: u64 = 60;

/// The Called sweep is daily in production. An e2e run seeds the days it reads
/// rather than living through them, so it needs the sweep to come round sooner.
#[cfg(not(feature = "e2e-test"))]
const INTEX_CALL_PERIOD_SECONDS: u64 = 86_400;
#[cfg(feature = "e2e-test")]
const INTEX_CALL_PERIOD_SECONDS: u64 = 60;

/// The gem call and position sweeps are daily in production; an e2e run seeds
/// the days they read instead of living through them.
#[cfg(not(feature = "e2e-test"))]
const GEM_CALL_PERIOD_SECONDS: u64 = 86_400;
#[cfg(feature = "e2e-test")]
const GEM_CALL_PERIOD_SECONDS: u64 = 60;
#[cfg(not(feature = "e2e-test"))]
const GEM_POSITION_PERIOD_SECONDS: u64 = 86_400;
#[cfg(feature = "e2e-test")]
const GEM_POSITION_PERIOD_SECONDS: u64 = 60;

/// Cadence of the two outbound polls, shortened for the same reason.
#[cfg(not(feature = "e2e-test"))]
const OUTBOUND_POLL_PERIOD_SECONDS: u64 = 600;
#[cfg(feature = "e2e-test")]
const OUTBOUND_POLL_PERIOD_SECONDS: u64 = 30;

/// Active trigger table. Order is informational only - the dispatcher
/// fires triggers independently per slot.
/// Active trigger table in permanent numeric-id order. The dispatcher walks
/// this order when several handlers are due in the same block.
pub const fn active_triggers(metadosis_advance_interval_seconds: u64) -> [TriggerSpec; 9] {
    [
        TriggerSpec {
            id: TriggerId::ProtocolCycle.as_u32(),
            label: "protocol_cycle",
            period_seconds: metadosis_advance_interval_seconds,
            start_offset_seconds: 0,
            // ProtocolCycle settles a contiguous completed UTC day; it MUST
            // observe the parent block's Phase 1 accounting before
            // firing, otherwise validator-pool top-ups and daily-fee reads would
            // race the parent-finalization tx.
            requires_accounting_window: true,
            // The handler owns the calendar decision, so missed hourly slots
            // collapse to one execution at the latest due boundary.
            coalesces_backlog: true,
            handler: TriggerHandler::ProtocolCycle,
        },
        TriggerSpec {
            id: TriggerId::IntexCallDaily.as_u32(),
            label: "intex_call_daily",
            period_seconds: INTEX_CALL_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Reads finalized oracle VWAP history and marks series Called; no
            // dependency on the parent block's settlement accounting.
            requires_accounting_window: false,
            coalesces_backlog: false,
            handler: TriggerHandler::IntexDaily,
        },
        TriggerSpec {
            id: TriggerId::AuctionAdvance.as_u32(),
            label: "auction_advance",
            period_seconds: AUCTION_ADVANCE_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Gated like emission_limit_1 so the brief it writes and this start
            // land in the same slot.
            requires_accounting_window: true,
            // A poll, not a calendar slot: the handler reads the block clock and
            // sweeps every scheduled day, so replaying a missed slot does nothing
            // the next firing would not already do.
            coalesces_backlog: true,
            handler: TriggerHandler::AuctionAdvance,
        },
        TriggerSpec {
            id: TriggerId::GemCallDaily.as_u32(),
            label: "gem_call_daily",
            period_seconds: GEM_CALL_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Reads finalized oracle VWAP history to force-call / forfeit-burn gems;
            // no dependency on the parent block's settlement accounting.
            requires_accounting_window: false,
            coalesces_backlog: false,
            handler: TriggerHandler::GemCallDaily,
        },
        TriggerSpec {
            id: TriggerId::AuctionClearing.as_u32(),
            label: "auction_clearing",
            // Polls the fan-in gate `auction_advance` arms, so it runs far more
            // often than the stage schedule advances.
            period_seconds: OUTBOUND_POLL_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Clears from bids already ingested and the router's frozen target
            // list; no dependency on the parent block's settlement accounting.
            requires_accounting_window: false,
            // A poll has nothing to replay: a gap collapses to one clearing sweep.
            coalesces_backlog: true,
            handler: TriggerHandler::AuctionClearing,
        },
        TriggerSpec {
            id: TriggerId::IntexNotify.as_u32(),
            label: "intex_notify",
            period_seconds: OUTBOUND_POLL_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Drains a queue the qualify sweep filled; reads no accounting state.
            requires_accounting_window: false,
            // A poll has nothing to replay: a gap collapses to one drain.
            coalesces_backlog: true,
            handler: TriggerHandler::IntexNotify,
        },
        TriggerSpec {
            id: TriggerId::CredisCallDaily.as_u32(),
            label: "credis_call_daily",
            period_seconds: 86_400,
            start_offset_seconds: 0,
            // Reads finalized oracle VWAP history to latch, call and void credis
            // positions; no dependency on the parent block's settlement accounting.
            requires_accounting_window: false,
            coalesces_backlog: false,
            handler: TriggerHandler::CredisCallDaily,
        },
        TriggerSpec {
            id: TriggerId::NodCallDaily.as_u32(),
            label: "nod_call_daily",
            period_seconds: 86_400,
            start_offset_seconds: 0,
            // Reads finalized oracle VWAP history to force-call Nod buckets and
            // forfeit-burn their Nods; no dependency on the parent block's
            // settlement accounting.
            requires_accounting_window: false,
            coalesces_backlog: false,
            handler: TriggerHandler::NodCallDaily,
        },
        TriggerSpec {
            id: TriggerId::GemPositionDaily.as_u32(),
            label: "gem_position_daily",
            period_seconds: GEM_POSITION_PERIOD_SECONDS,
            start_offset_seconds: 0,
            // Walks positions by time alone: no oracle, no settlement accounting.
            requires_accounting_window: false,
            coalesces_backlog: false,
            handler: TriggerHandler::GemPositionDaily,
        },
    ]
}

pub const ACTIVE_TRIGGER_ARRAY: [TriggerSpec; 9] =
    active_triggers(outbe_chain_constants::DEFAULT_METADOSIS_ADVANCE_INTERVAL_SECONDS);
pub const ACTIVE_TRIGGERS: &[TriggerSpec] = &ACTIVE_TRIGGER_ARRAY;

/// Returns the next slot strictly greater than `last_executed_at`.
/// Pure function: same `(period, offset, last)` tuple always returns
/// the same slot. Monotonically non-decreasing in `last_executed_at`
/// (and strictly increasing for `last_executed_at` past the first
/// slot).
///
/// Invariants:
/// * result `>= offset`,
/// * `(result - offset) % period == 0`,
/// * `result > last_executed_at`.
pub fn next_fire_at(period: u64, offset: u64, last_executed_at: u64) -> u64 {
    if last_executed_at < offset {
        return offset;
    }
    let diff = last_executed_at - offset;
    let k = diff / period + 1;
    offset + k * period
}

/// Returns the latest slot at or before `block_ts`. Recording this instead of
/// the first due slot is what collapses a backlog for a poll-style trigger:
/// the next call then sees a slot in the future and stops re-firing.
pub fn last_fire_at(period: u64, offset: u64, block_ts: u64) -> u64 {
    if block_ts < offset {
        return offset;
    }
    offset + (block_ts - offset) / period * period
}

#[cfg(test)]
mod protocol_parameter_tests {
    use super::*;

    #[test]
    fn protocol_cycle_uses_the_genesis_interval() {
        // The gem sweeps are daily in a release build; e2e shortens them.
        #[cfg(not(feature = "e2e-test"))]
        assert_eq!(
            (GEM_CALL_PERIOD_SECONDS, GEM_POSITION_PERIOD_SECONDS),
            (86_400, 86_400)
        );
        let configured = active_triggers(10);
        assert_eq!(configured[0].period_seconds, 10);
        assert_eq!(configured[0].start_offset_seconds, 0);
        assert_eq!(configured[1].period_seconds, 86_400);
        assert_eq!(configured[2].period_seconds, 3_600);
        assert_eq!(configured[2].start_offset_seconds, 0);
        assert_eq!(configured[3].period_seconds, GEM_CALL_PERIOD_SECONDS);
        assert!(matches!(
            configured[3].handler,
            TriggerHandler::GemCallDaily
        ));
        assert_eq!(configured[4].period_seconds, 600);
        assert!(matches!(
            configured[4].handler,
            TriggerHandler::AuctionClearing
        ));
        assert_eq!(configured[6].period_seconds, 86_400);
        assert_eq!(configured[6].start_offset_seconds, 0);
        assert!(matches!(
            configured[6].handler,
            TriggerHandler::CredisCallDaily
        ));
        assert_eq!(configured[7].period_seconds, 86_400);
        assert_eq!(configured[7].start_offset_seconds, 0);
        assert!(matches!(
            configured[7].handler,
            TriggerHandler::NodCallDaily
        ));
        assert_eq!(configured[8].period_seconds, GEM_POSITION_PERIOD_SECONDS);
        assert_eq!(configured[8].start_offset_seconds, 0);
        assert!(matches!(
            configured[8].handler,
            TriggerHandler::GemPositionDaily
        ));

        let defaults =
            active_triggers(outbe_chain_constants::DEFAULT_METADOSIS_ADVANCE_INTERVAL_SECONDS);
        assert_eq!(defaults[0].period_seconds, 3_600);
        assert_eq!(defaults[0].start_offset_seconds, 0);
    }
}
