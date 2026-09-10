//! Daily Called scan: force-calls a Qualified series once its COEN VWAP exceeded
//! the call trigger on `call_threshold` of the last `call_window`. Candidates
//! come from the call-trigger bin index; counts are recomputed each run from the
//! Oracle's finalized per-UTC-day VWAPs, which the Oracle begin-block hook
//! closes before the CycleTick that drives this scan. Driven by the Cycle daily
//! trigger.

use std::collections::BTreeMap;

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use outbe_intex::SeriesId;
use outbe_oracle::schema::{OracleContract, PairIndex};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
    math::{constants::MAX_BIN_ID, tree_math},
    storage::StorageHandle,
    time::{previous_date_key, timestamp_to_date_key, SECONDS_PER_DAY},
};

use outbe_intex::IntexState;

use crate::constants::{MAX_SERIES_PER_MARK, ORIGIN_ROUTER_ADDRESS};
use crate::qualified::ScanBudget;
use crate::schema::IntexFactoryContract;
use crate::sol_ext::IOriginRouter;
use crate::state::{Group, QualifiedBinTree};

/// Open a Called sweep over the day the Oracle has just finalized and run its
/// first slice. Returns the number of series force-called in that slice.
pub fn scan_and_call(ctx: &BlockRuntimeContext) -> Result<u32> {
    let oracle = OracleContract::new(ctx.storage.clone());

    // Most recent fully-closed UTC day (finalized VWAP).
    let last_closed_day = previous_date_key(timestamp_to_date_key(ctx.block.timestamp));

    // The Oracle begin-block hook finalizes that day earlier in this same
    // block; a lagging watermark means the ordering broke - skip loudly
    // instead of misreading an unfinalized day as empty.
    // todo use api.rs
    let finalized = oracle.utc_day_vwap_last_finalized.read()?;
    if finalized < last_closed_day {
        tracing::warn!(target: "outbe::intexfactory", last_closed_day, finalized, "call scan: utc-day VWAP not finalized yet, skipping run");
        return Ok(0);
    }

    let factory = IntexFactoryContract::new(ctx.storage.clone());
    factory.call_sweep_day.write(last_closed_day)?;
    // A sweep in flight is superseded: its mid-range cursors would let the new one
    // call itself done over bins it never walked.
    factory.call_currency_cursor.write(0)?;
    for iso_code in outbe_oracle::api::get_all_reference_currencies(ctx)? {
        factory.call_scan_cursor.write(&iso_code, 0)?;
    }
    run_call_slice(ctx)
}

/// Advance an open sweep by one slice, pinned to the day it opened on so blocks
/// of it decide against the same prices. Returns how many series were called.
pub fn run_call_slice(ctx: &BlockRuntimeContext) -> Result<u32> {
    let factory = IntexFactoryContract::new(ctx.storage.clone());
    let pinned_day = factory.call_sweep_day.read()?;
    if pinned_day == 0 {
        return Ok(0);
    }
    let currencies = outbe_oracle::api::get_all_reference_currencies(ctx)?;
    if currencies.is_empty() {
        factory.call_sweep_day.write(0)?;
        return Ok(0);
    }
    let oracle = OracleContract::new(ctx.storage.clone());
    let start =
        crate::qualified::currency_position(&currencies, factory.call_currency_cursor.read()?);

    let mut budget = ScanBudget::for_qualify();
    let mut called: u32 = 0;
    // The first currency left unfinished, so the next slice picks up where this one
    // gave out rather than re-walking the ones already closed behind it.
    let mut resume_at = start;
    let mut resumed = false;
    let mut swept = true;
    for offset in 0..currencies.len() {
        let at = (start + offset) % currencies.len();
        if budget.is_spent() {
            if !resumed {
                resume_at = at;
            }
            swept = false;
            break;
        }
        let iso_code = currencies[at];
        // No registered pair is an answer; a failed read is not.
        let pair_index =
            match outbe_oracle::api::coen_pair_index_opt(ctx.storage.clone(), iso_code)? {
                Some(index) => index,
                None => continue,
            };
        let (calls, finished) =
            call_currency(ctx, &oracle, iso_code, pair_index, pinned_day, &mut budget)?;
        called = called.saturating_add(calls);
        if !finished && !resumed {
            resume_at = at;
            resumed = true;
        }
        swept &= finished;
    }
    factory
        .call_currency_cursor
        .write(u32::from(currencies[resume_at]))?;
    if swept {
        // Nothing left to walk: the next daily trigger opens a fresh sweep.
        factory.call_sweep_day.write(0)?;
    }
    Ok(called)
}

/// Scans one currency's qualified groups on the shared `budget`. Returns the calls
/// made and whether its eligible range was walked to the end.
fn call_currency(
    ctx: &BlockRuntimeContext,
    oracle: &OracleContract,
    iso_code: u16,
    pair_index: PairIndex,
    last_closed_day: u32,
    budget: &mut ScanBudget,
) -> Result<(u32, bool)> {
    let mut factory = IntexFactoryContract::new(ctx.storage.clone());
    let params = crate::config::read_from(&factory, ctx.block.chain_id)?;
    // Widest terms ever issued here, not the live profile: a series keeps the terms
    // it was issued with, and a narrowed profile must not hide it from the search.
    let (window_days, threshold_days) =
        factory.scan_call_terms(iso_code, params.call_window, params.call_threshold)?;

    let mut vwaps = DayVwaps::new(pair_index);
    let Some(window) = call_window(
        oracle,
        &mut vwaps,
        last_closed_day,
        window_days,
        threshold_days,
    )?
    else {
        // Too few priced days for any trigger to be breached often enough.
        return Ok((0, true));
    };

    // Every trigger below `p_star` is breached often enough, so the range ends at
    // its bin. An out-of-range price skips the currency rather than halting.
    let p_bin = match IntexFactoryContract::price_to_bin(window.p_star) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target: "outbe::intexfactory", iso_code, error = ?e, "call scan: window price out of range, skipping currency");
            return Ok((0, true));
        }
    };

    let mut called: u32 = 0;
    let mut finished = true;
    let mut cursor: u32 = factory.call_scan_cursor.read(&iso_code)?;
    'bins: loop {
        if budget.is_spent() {
            // Between bins, so the next slice resumes at a bin it has not opened.
            factory.call_scan_cursor.write(&iso_code, cursor)?;
            finished = false;
            break;
        }
        let next = match tree_math::find_first_left_inclusive(
            &QualifiedBinTree(&factory, iso_code),
            cursor,
        )? {
            Some(b) if b <= p_bin => b,
            _ => {
                // End of the eligible range: the next run sweeps this currency afresh.
                factory.call_scan_cursor.write(&iso_code, 0)?;
                break;
            }
        };

        // Snapshot the bin before mutating: a called group leaves it.
        for worldwide_day in factory.qualified_groups_in_bin(iso_code, next)? {
            let group = factory.qualified_group(iso_code, worldwide_day)?;
            if !budget.admits_actions(group.members.len() as u32) {
                // Called groups have left this bin, so resuming on it redoes nothing.
                factory.call_scan_cursor.write(&iso_code, next)?;
                finished = false;
                break 'bins;
            }
            budget.spend_decision();
            // Isolate per-group: a deterministic Err rolls back the group's checkpoint and is
            // skipped (logged); structural reads above keep `?` so infra errors still propagate.
            let res = ctx.storage.with_checkpoint(|| {
                try_call_group(
                    &ctx.storage,
                    &mut factory,
                    oracle,
                    &mut vwaps,
                    &group,
                    &window,
                    ctx.block.timestamp,
                )
            });
            match res {
                Ok(applied) => {
                    budget.spend_actions(applied);
                    called = called.saturating_add(applied);
                }
                Err(e) => {
                    tracing::warn!(target: "outbe::intexfactory", iso_code, worldwide_day = %worldwide_day, error = ?e, "call scan: skipping group");
                }
            }
        }

        cursor = match next.checked_add(1) {
            Some(c) if c <= MAX_BIN_ID => c,
            _ => {
                factory.call_scan_cursor.write(&iso_code, 0)?;
                break;
            }
        };
    }
    Ok((called, finished))
}

/// Cycle daily-trigger entry: opens the day's Called sweep, discarding the count.
pub fn run_daily(ctx: &BlockRuntimeContext) -> Result<()> {
    scan_and_call(ctx)?;
    Ok(())
}

/// Finalized per-day VWAPs of one oracle pair, read once per scan.
pub(crate) struct DayVwaps {
    pair_index: PairIndex,
    days: BTreeMap<u32, Option<U256>>,
}

impl DayVwaps {
    pub(crate) fn new(pair_index: PairIndex) -> Self {
        Self {
            pair_index,
            days: BTreeMap::new(),
        }
    }

    fn get(&mut self, oracle: &OracleContract, day: u32) -> Result<Option<U256>> {
        if let Some(v) = self.days.get(&day) {
            return Ok(*v);
        }
        let v = oracle.get_utc_day_vwap_for_pair(day, self.pair_index)?;
        self.days.insert(day, v);
        Ok(v)
    }
}

/// The finalized VWAP window one call scan decides against, and the price that
/// summarises it.
pub(crate) struct CallWindow {
    /// Most recent fully-closed UTC day; the window ends here.
    pub(crate) last_day: u32,
    /// Window length and required breach count, both in whole days.
    pub(crate) days: u32,
    pub(crate) threshold: u32,
    /// The `threshold`-th largest VWAP: `trigger < p_star` and "breached on at
    /// least `threshold` days" are one statement, so a group decides by comparison.
    pub(crate) p_star: U256,
    /// The window's first day; a group issued on or before it sees the whole window.
    pub(crate) first_day: u32,
}

/// The window's `threshold`-th largest finalized VWAP. `None` when too few days
/// carry a price for any trigger to be breached often enough.
pub(crate) fn call_window(
    oracle: &OracleContract,
    vwaps: &mut DayVwaps,
    last_day: u32,
    days: u32,
    threshold: u32,
) -> Result<Option<CallWindow>> {
    if days == 0 || threshold == 0 {
        return Ok(None);
    }
    let mut priced: Vec<U256> = Vec::with_capacity(days as usize);
    let mut day = last_day;
    for _ in 0..days {
        if let Some(vwap) = vwaps.get(oracle, day)? {
            priced.push(vwap);
        }
        day = previous_date_key(day);
    }
    if (priced.len() as u32) < threshold {
        return Ok(None);
    }
    priced.sort_unstable_by(|a, b| b.cmp(a));
    let mut first_day = last_day;
    for _ in 1..days {
        first_day = previous_date_key(first_day);
    }
    Ok(Some(CallWindow {
        last_day,
        days,
        threshold,
        p_star: priced[threshold as usize - 1],
        first_day,
    }))
}

/// Breach-days (VWAP > trigger) inside the window, not before issuance.
fn count_breaches(
    oracle: &OracleContract,
    vwaps: &mut DayVwaps,
    last_day: u32,
    days: u32,
    issued_day: u32,
    trigger: U256,
) -> Result<u32> {
    let mut breaches: u32 = 0;
    let mut day = last_day;
    for _ in 0..days {
        if day < issued_day {
            break;
        }
        if let Some(vwap) = vwaps.get(oracle, day)? {
            if vwap > trigger {
                breaches += 1;
            }
        }
        day = previous_date_key(day);
    }
    Ok(breaches)
}

/// Force-call a whole group: its series share trigger, issue time and call
/// parameters, so one read decides them all. Returns how many were called.
pub(crate) fn try_call_group(
    storage: &StorageHandle<'_>,
    factory: &mut IntexFactoryContract,
    oracle: &OracleContract,
    vwaps: &mut DayVwaps,
    group: &Group,
    window: &CallWindow,
    now_ts: u64,
) -> Result<u32> {
    let Some(&first) = group.members.first() else {
        return Ok(0);
    };
    let series = outbe_intex::api::read_series(storage, first)?;
    if series.lifecycle_state()? != IntexState::Qualified {
        return Ok(0);
    }
    let trigger = series.call_price_minor;
    // The scan walks finalized daily VWAPs, so both bounds floor to whole days.
    let secs_per_day = SECONDS_PER_DAY as u32;
    let group_days = series.call_window / secs_per_day;
    let group_threshold = series.call_threshold / secs_per_day;
    if group_days == 0 || group_threshold == 0 {
        return Ok(0);
    }

    let issued_day = timestamp_to_date_key(u64::from(series.issued_at));
    let breached = if issued_day <= window.first_day
        && group_days == window.days
        && group_threshold == window.threshold
    {
        trigger < window.p_star
    } else {
        // A shorter window than the scan's - issued inside it, or different stored
        // parameters - so its own days are counted. Wider stored parameters are only
        // reached under `p_star`; only a profile change on a live chain parts them.
        count_breaches(
            oracle,
            vwaps,
            window.last_day,
            group_days,
            issued_day,
            trigger,
        )? >= group_threshold
    };
    if !breached {
        return Ok(0);
    }

    // u32 timestamp; bounded until 2106 (matches issued_at).
    let called_at = u32::try_from(now_ts)
        .map_err(|_| PrecompileError::Revert("block timestamp exceeds u32".into()))?;
    for &series_id in &group.members {
        outbe_intex::api::mark_called(storage, series_id, called_at)?;
    }
    // Park it with its members: the expiry sweep has no other way back to them.
    factory.remove_qualified_group(group.iso_code, group.worldwide_day)?;
    factory.push_called_group(
        group.iso_code,
        group.worldwide_day,
        u64::from(called_at) + u64::from(series.call_notice_period),
        &group.members,
    )?;

    // A slice of this sweep runs in a block hook, which cannot call contracts, so the notices leave from
    // the `intex_notify` trigger. Each carries its own series: the group has left the index by then.
    for &series_id in &group.members {
        crate::qualified::enqueue_notice(
            factory,
            crate::qualified::NOTICE_CALLED,
            crate::qualified::pack_called_notice(series_id, called_at),
        )?;
    }

    for &series_id in &group.members {
        crate::runtime::emit_event(
            storage,
            crate::precompile::IIntexFactory::SeriesCalled {
                seriesId: series_id.into(),
                calledAt: called_at,
            },
        )?;
    }
    Ok(group.members.len() as u32)
}

/// One message per group, split only where the wire's cap forces it. `called_at`
/// travels so every target derives the same deadline the origin did.
pub(crate) fn notify_called(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    called_at: u32,
    members: &[SeriesId],
) -> Result<()> {
    for chunk in members.chunks(MAX_SERIES_PER_MARK) {
        // Best-effort, and the batch is the unit: a failure loses the mark for every series in it.
        let sent = storage.with_checkpoint(|| {
            // Relay-float-funded: value 0, so the router self-quotes and pays the fee from its float.
            storage.call(
                ORIGIN_ROUTER_ADDRESS,
                U256::ZERO,
                IOriginRouter::sendMarkCalledCall {
                    worldwideDay: worldwide_day.value(),
                    calledAt: called_at,
                    seriesIds: chunk.iter().map(|id| (*id).into()).collect(),
                }
                .abi_encode()
                .into(),
            )?;
            Ok(())
        });
        if let Err(error) = sent {
            tracing::warn!(
                target: "outbe::intexfactory",
                worldwide_day = worldwide_day.value(),
                called_at,
                series = ?chunk.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
                error = ?error,
                "called notice: dropping"
            );
        }
    }
    Ok(())
}
