use outbe_primitives::{
    block::{BlockLifecycle, BlockRuntimeContext},
    error::Result,
    time::{previous_date_key, timestamp_to_date_key},
};

use crate::constants::MAX_UTC_DAY_VWAP_BACKFILL_DAYS;
use crate::schema::OracleContract;
use crate::scurve;
use crate::tally;

pub struct OracleLifecycle;

impl BlockLifecycle for OracleLifecycle {
    type Context<'a, 'storage> = BlockRuntimeContext<'storage>;
    type EndBlockResult = ();

    fn begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
        run_begin_block(ctx)
    }

    fn end_block(_ctx: &BlockRuntimeContext) -> Result<Self::EndBlockResult> {
        Ok(())
    }
}

/// Runs only the slash-window half of Oracle lifecycle.
///
/// The executor calls this through the receipt-visible `OracleSlashWindow`
/// begin-zone system phase after optional `BoundaryOutcome` and before user
/// transactions. This preserves deterministic penalties without hiding
/// operator-critical events outside EVM receipts.
pub fn run_slash_window(ctx: &BlockRuntimeContext) -> Result<()> {
    let mut oracle = OracleContract::new(ctx.storage.clone());
    let block_number = ctx.block.block_number;
    let timestamp = ctx.block.timestamp;

    let initialized = oracle.config_is_initialized.read()?;
    if !initialized {
        return Ok(());
    }

    let slash_window = oracle.config_slash_window.read()?;
    if slash_window > 0 && block_number > 0 && block_number.is_multiple_of(slash_window) {
        tally::slash_and_reset_counters(&mut oracle, timestamp)?;
    }

    Ok(())
}

/// Called from pre-execution hooks every block.
///
/// At vote period boundaries: tallies votes, updates exchange rates, writes
/// price snapshots, and counts miss/success/abstain per validator.
///
/// At UTC day boundaries: runs S-curve peak detection for each registered,
/// active reference-currency COEN pair.
///
/// Slash-window force-exits are deliberately deferred to the receipt-visible
/// `OracleSlashWindow` system phase so a same-block `BoundaryOutcome` can
/// activate its target set before Oracle penalties mark underperformers EXITING.
fn run_begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
    let mut oracle = OracleContract::new(ctx.storage.clone());
    let block_number = ctx.block.block_number;
    let timestamp = ctx.block.timestamp;

    let initialized = oracle.config_is_initialized.read()?;
    if !initialized {
        return Ok(());
    }

    let vote_period = oracle.config_vote_period.read()?;

    // Tally at end of vote period (skip block 0)
    // Block 0 is always skipped (no votes possible during genesis).
    // With vote_period=1, first tally runs at block 1 (one block delay).
    if vote_period > 0 && block_number > 0 && block_number.is_multiple_of(vote_period) {
        tally::run_tally(&mut oracle, block_number, timestamp)?;
    }

    // Daily S-curve processing at UTC day boundary
    let current_day = scurve::truncate_to_day(timestamp);
    let last_processed = oracle.scurve_last_processed_day.read()?;
    if current_day > last_processed && timestamp > 0 {
        for iso_code in oracle.reference_currencies.read_all()? {
            let pair = crate::types::AddressPair::new_coen_to(iso_code);
            if oracle.pair_index_of(pair)? != 0 && oracle.vote_target.read(&pair)? {
                scurve::process_daily_scurve(&mut oracle, pair, timestamp)?;
            }
        }
        oracle.scurve_last_processed_day.write(current_day)?;
    }

    // Finalize per-UTC-day VWAP for every calendar day that has fully closed.
    // `calculate_vwaps` reads the committed daily aggregates for the closed
    // `[midnight, +24h)` window, so the value is identical on proposer and
    // validators. The monotonic `utc_day_vwap_last_finalized` watermark makes
    // this idempotent across the many blocks within a day and bounds catch-up
    // after a gap.
    if timestamp > 0 {
        let current_utc_day = timestamp_to_date_key(timestamp);
        let most_recent_closed = previous_date_key(current_utc_day);
        let last_finalized = oracle.utc_day_vwap_last_finalized.read()?;

        // yyyymmdd keys order chronologically as integers; only step via the
        // calendar-aware helpers (never `+1` on the key).
        if last_finalized < most_recent_closed {
            // On the very first finalization (watermark 0) only close the single
            // most-recent day - do not sweep backward into pre-genesis history
            // that has no data. Otherwise resume from the watermark.
            let lower_bound = if last_finalized == 0 {
                previous_date_key(most_recent_closed)
            } else {
                last_finalized
            };

            // Collect up to the cap of most-recent unfinalized days walking
            // backward, then finalize ascending so writes/events stay
            // chronological. After a gap wider than the cap, the oldest days are
            // skipped - their source aggregates are already evicted past
            // retention, so they could not be recomputed anyway.
            let mut days: Vec<u32> = Vec::new();
            let mut day = most_recent_closed;
            while day > lower_bound && days.len() < MAX_UTC_DAY_VWAP_BACKFILL_DAYS as usize {
                days.push(day);
                day = previous_date_key(day);
            }
            for &d in days.iter().rev() {
                oracle.finalize_utc_day_vwap(d)?;
            }

            oracle
                .utc_day_vwap_last_finalized
                .write(most_recent_closed)?;
        }
    }

    Ok(())
}
