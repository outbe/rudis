//! Daily call scan: force-calls qualified Nod buckets off the Oracle's
//! finalized per-UTC-day VWAPs, then forfeit-burns the Nods of a bucket whose
//! notice period lapsed. Driven by the Cycle daily trigger.
//!
//! One pass over the dense callable-bucket index applies at most one transition
//! per bucket, in lifecycle order:
//!
//! - *not called* -> *called* when the reference price exceeded the bucket's
//!   call price on at least [`CALL_BREACH_DAYS`] of the trailing
//!   [`CALL_LOOKBACK_DAYS`] days.
//! - *called* -> *forfeited* when [`CALL_NOTICE_PERIOD`] has lapsed with Nods
//!   still unmined. The two can never fire in one pass, since a bucket called
//!   now cannot also be seven days past its call.
//!
//! The breach rule needs no per-bucket streak state: the daily series is global
//! per currency, so one trailing window per currency decides every bucket
//! denominated in it, and the count is recomputed from oracle history on every
//! run rather than carried. Mirrors `outbe_gem::hooks::scan_and_call` and
//! `outbe_credisfactory::called::scan_and_call`, which evaluate the same shape.
//!
//! Unlike qualification - which reads the *live* COEN rate in `hooks.rs` - the
//! call reads the *finalized daily VWAP*. Gem splits the two feeds the same way.

use alloy_primitives::{B256, U256};
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_oracle::schema::OracleContract;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::Result,
    storage::StorageHandle,
    time::{previous_date_key, timestamp_to_date_key},
};

use crate::{
    api,
    constants::{
        CALL_BREACH_DAYS, CALL_LOOKBACK_DAYS, CALL_NOTICE_PERIOD, MAX_NOD_CALL_VISITS,
        MAX_NOD_FORFEITS_PER_RUN,
    },
    precompile::INod,
    schema::NodContract,
};

/// Trailing finalized daily VWAPs of one `COEN/<iso>` pair, newest first.
/// `None` marks a day the pair published no reference price.
type VwapWindow = Vec<(u32, Option<U256>)>;

/// Cycle daily-trigger entry: runs the scan, discarding the count.
pub fn run_call_daily(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<()> {
    scan_and_call(ctx, scope, parent)?;
    Ok(())
}

/// Runs the daily call scan. Returns the number of buckets called plus Nods
/// forfeited.
///
/// Never returns `Err` for missing market data: the Cycle dispatcher propagates
/// a handler error out of the `CycleTick` system transaction, which fails the
/// block, so an unregistered pair, an unpriced currency or an unfinalized day
/// each degrade to "no transition" instead.
pub fn scan_and_call(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<u32> {
    let oracle = OracleContract::new(ctx.storage.clone());

    // Most recent fully-closed UTC day. The call counts plain UTC days, so this
    // is `timestamp_to_date_key`, NOT the UTC+14 `WorldwideDay` key.
    let last_closed_day = previous_date_key(timestamp_to_date_key(ctx.block.timestamp));

    // The Oracle begin-block hook finalizes that day earlier in this same block;
    // a lagging watermark means the ordering broke - skip loudly instead of
    // misreading an unfinalized day as one with no published price.
    let finalized = oracle.utc_day_vwap_last_finalized.read()?;
    if finalized < last_closed_day {
        tracing::warn!(
            target: "outbe::nod",
            last_closed_day,
            finalized,
            "nod call scan: utc-day VWAP not finalized yet, skipping run"
        );
        return Ok(0);
    }

    let mut nod = NodContract::new(ctx.storage.clone());
    let len = nod.callable_buckets.len()?;
    if len == 0 {
        return Ok(0);
    }

    // Stored as `index + 1`; 0 means "start a fresh pass from the top".
    let mut cursor = match nod.call_scan_cursor.read()? {
        0 => len - 1,
        resume => resume.saturating_sub(1).min(len - 1),
    };

    // A VWAP window belongs to one `COEN/<iso>` pair, but the callable index
    // mixes currencies. Cache the windows and keep the single pass; the registry
    // holds a handful of codes, so a linear probe beats a map.
    let mut windows: Vec<(u16, VwapWindow)> = Vec::new();

    let now = ctx.block.timestamp;
    let mut mutated: u32 = 0;
    let mut visited: u32 = 0;
    let mut forfeited: u32 = 0;

    // Descending walk: removing a bucket swap-pops the tail into the hole, and
    // the tail is already behind a descending cursor, so no live entry is
    // skipped and none is visited twice.
    let completed = loop {
        if visited >= MAX_NOD_CALL_VISITS {
            break false;
        }
        if let Some(bucket_key) = nod.callable_buckets.get(cursor)? {
            visited = visited.saturating_add(1);
            let called_at = nod.bucket_called_at.read(&bucket_key)?;
            if called_at == 0 {
                // Structural reads stay on `?` so infra errors still propagate.
                let iso_code = nod.callable_bucket_currency.read(&bucket_key)?;
                let call_price = nod.callable_bucket_call_price.read(&bucket_key)?;
                let start_day = nod.bucket_worldwide_day.read(&bucket_key)?.value();
                let index = window_for(
                    &ctx.storage,
                    &oracle,
                    &mut windows,
                    iso_code,
                    last_closed_day,
                )?;
                if breached_enough(&windows[index].1, call_price, start_day) {
                    // Isolate per-bucket: a deterministic Err rolls back this
                    // bucket's checkpoint and is skipped, so one bad bucket never
                    // halts the daily scan.
                    let res = ctx
                        .storage
                        .with_checkpoint(|| mark_called(&mut nod, bucket_key, now));
                    if res.is_ok() {
                        mutated = mutated.saturating_add(1);
                    }
                }
            } else if now > called_at.saturating_add(CALL_NOTICE_PERIOD) {
                let budget = MAX_NOD_FORFEITS_PER_RUN.saturating_sub(forfeited);
                if budget > 0 {
                    let res = ctx.storage.with_checkpoint(|| {
                        forfeit_members(&ctx.storage, &mut nod, scope, parent, bucket_key, budget)
                    });
                    if let Ok(burned) = res {
                        forfeited = forfeited.saturating_add(burned);
                        mutated = mutated.saturating_add(burned);
                    }
                }
            }
        }
        if cursor == 0 {
            break true;
        }
        cursor -= 1;
    };

    nod.call_scan_cursor.write(if completed {
        0
    } else {
        cursor.saturating_add(1)
    })?;
    Ok(mutated)
}

/// True when the trailing window carries at least [`CALL_BREACH_DAYS`] days
/// strictly above `call_price`.
///
/// Days at or below the call price, and days with no published price, both
/// simply fail to count, so the window absorbs up to
/// `CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS` of either. The walk stops at the
/// first day preceding the bucket's worldwide day so a bucket can never inherit
/// a breach run that predates it - the window is newest-first, so everything
/// beyond that point is older still.
fn breached_enough(window: &[(u32, Option<U256>)], call_price: U256, start_day: u32) -> bool {
    let mut breaches: u32 = 0;
    for (day, vwap) in window.iter().take(CALL_LOOKBACK_DAYS as usize) {
        if *day < start_day {
            break;
        }
        if vwap.is_some_and(|value| value > call_price) {
            breaches = breaches.saturating_add(1);
        }
    }
    breaches >= CALL_BREACH_DAYS
}

/// Stamps the call and opens the settlement window.
fn mark_called(nod: &mut NodContract<'_>, bucket_key: B256, now: u64) -> Result<()> {
    nod.bucket_called_at.write(&bucket_key, now)?;
    nod.emit(INod::NodBucketCalled {
        bucketKey: bucket_key,
        calledAt: now,
        settlementDeadline: now.saturating_add(CALL_NOTICE_PERIOD),
    })
}

/// Forfeit-burns up to `budget` of a lapsed bucket's remaining Nods, newest
/// first. Returns how many were burned.
///
/// A bucket holding more members than the budget resumes on the next run, which
/// cannot change an outcome: the deadline has already passed and mining is
/// closed, so nothing can rescue the remainder. Removing the last member deletes
/// the bucket body and drops it from the callable index.
///
/// Each burned load returns to the Promis Reserve. Lysis drew it out of the day
/// limit and only mining converts it into Gratis, so a load that is destroyed
/// unmined would otherwise leave the reserve with nothing minted against it.
/// The credit is one accumulated write per pass, and the caller's checkpoint
/// makes it atomic with the burns it accounts for.
fn forfeit_members(
    storage: &StorageHandle<'_>,
    nod: &mut NodContract<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    bucket_key: B256,
    budget: u32,
) -> Result<u32> {
    let worldwide_day = nod.bucket_worldwide_day.read(&bucket_key)?;
    let mut burned: u32 = 0;
    let mut credit = U256::ZERO;
    while burned < budget {
        let count = nod.bucket_nod_count.read(&bucket_key)?;
        let Some(last) = count.checked_sub(1) else {
            break;
        };
        let nod_id = nod
            .bucket_nods
            .read(&NodContract::bucket_nod_key(bucket_key, last))?;
        if nod_id.is_zero() {
            return Err(
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod bucket {bucket_key} member slot {last} is empty during forfeit"
                )),
            );
        }
        let item = api::load_item(storage, scope, parent, nod_id)?.ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                "Nod bucket {bucket_key} member {nod_id} has no body during forfeit"
            ))
        })?;
        let owner = item.body().owner;
        let gratis_load_minor = item.body().gratis_load_minor;
        let bucket_id = WwdEntityId::from_day_and_digest(worldwide_day, bucket_key.0);
        let bucket = api::load_bucket(storage, scope, parent, bucket_id)?.ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                "Nod bucket {bucket_key} has no body during forfeit"
            ))
        })?;
        api::remove_nod(storage, scope, item, bucket)?;
        nod.emit(INod::NodForfeited {
            owner,
            nodId: nod_id.to_u256(),
            gratisLoadMinor: gratis_load_minor,
        })?;
        credit = credit.checked_add(gratis_load_minor).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::Revert(
                "Nod forfeit Promis Reserve credit overflow".into(),
            )
        })?;
        burned = burned.saturating_add(1);
    }
    if !credit.is_zero() {
        outbe_promislimit::PromisLimitContract::new(storage.clone())
            .add_to_total_unallocated(credit)?;
    }
    Ok(burned)
}

/// Index into `cache` of the trailing finalized-VWAP window for `COEN/<iso>`,
/// newest first, filling it on first use.
///
/// An unregistered pair caches an empty window: a bucket in that currency can
/// never register a breach, but it must still reach the forfeit arm, so this is
/// a skip of the call check rather than a skip of the bucket.
fn window_for(
    storage: &StorageHandle<'_>,
    oracle: &OracleContract<'_>,
    cache: &mut Vec<(u16, VwapWindow)>,
    iso_code: u16,
    last_closed_day: u32,
) -> Result<usize> {
    if let Some(index) = cache.iter().position(|(code, _)| *code == iso_code) {
        return Ok(index);
    }
    let mut window = Vec::new();
    if let Some(pair_index) = outbe_oracle::api::coen_pair_index_opt(storage.clone(), iso_code)? {
        window.reserve(CALL_LOOKBACK_DAYS as usize);
        let mut day = last_closed_day;
        for _ in 0..CALL_LOOKBACK_DAYS {
            window.push((day, oracle.get_utc_day_vwap_for_pair(day, pair_index)?));
            day = previous_date_key(day);
        }
    }
    cache.push((iso_code, window));
    Ok(cache.len() - 1)
}
