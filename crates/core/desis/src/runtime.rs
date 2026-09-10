//! Desis runtime: auction lifecycle and clearing algorithm.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::time::SECONDS_PER_DAY;
use outbe_primitives::units::{
    NATIVE_UNITS_PER_PROTOCOL_UNIT, PROTOCOL_AMOUNT_DECIMALS, SCALE_1E6_U64,
};
use outbe_promislimit::PromisLimitContract;

use outbe_intexfactory::schema::IssuanceParams;
use outbe_intexfactory::SeriesId;

use crate::constants::{
    BIDS_FANIN_TIMEOUT_SECS, BID_QUANTITY_FLOOR_BPS, COMMIT_WINDOW_SECONDS, DAY_STATE_GREEN,
    DAY_STATE_RED, IGNORED_CONFLICT, IGNORED_NOT_FOUND, IGNORED_OBSOLETE, MAX_BIDS_PER_BATCH,
    MAX_BID_BATCHES, MAX_REFERENCE_PRICES, MAX_REFUND_CHUNKS, MIN_COMMIT_WINDOW_SECONDS,
    ORIGIN_ROUTER_ADDRESS, PROMIS_LOAD_ANCHOR_ISO, PROMIS_LOAD_DEADBAND_BPS,
    PROMIS_LOAD_LAUNCH_EXPONENT, PROMIS_LOAD_OVERRIDE, REFUND_CHUNK_LEN, REVEAL_WINDOW_SECONDS,
    SETTLEMENT_WINDOW_SECONDS,
};
use crate::errors::DesisError;
use crate::precompile::IDesis;
use crate::schema::{
    AuctionConfig, AuctionStage, BidData, ClearingResult, DesisContract, ReferenceCurrencyPrice,
};
use crate::sol_ext::IOriginRouter;

// ---------------------------------------------------------------------------
// Auction lifecycle
// ---------------------------------------------------------------------------

/// Validate every technical prerequisite before the API may classify an
/// oversized supply as the sole committed business rejection. Returns the
/// schedule anchor: the midnight of `now`, or the next one when too little of
/// the commit window would remain.
pub(crate) fn preflight_brief(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    now: u64,
) -> Result<u32> {
    if !worldwide_day.is_valid() {
        return Err(DesisError::InvalidWorldwideDay(worldwide_day).into());
    }
    let contract = storage.contract::<DesisContract>();
    if contract.read_stage(worldwide_day)? != AuctionStage::None {
        return Err(DesisError::InvalidStageTransition.into());
    }
    // Anchor to this midnight while it still leaves the minimum commit window;
    // a late brief (stall past midnight) anchors to the next one instead.
    let midnight = now - now % SECONDS_PER_DAY;
    let elapsed = now.checked_sub(midnight).ok_or_else(|| {
        PrecompileError::Fatal("brief timestamp precedes its UTC midnight".into())
    })?;
    let remaining = COMMIT_WINDOW_SECONDS.saturating_sub(elapsed);
    let anchor_ts = if remaining >= MIN_COMMIT_WINDOW_SECONDS {
        midnight
    } else {
        midnight
            .checked_add(SECONDS_PER_DAY)
            .ok_or_else(|| PrecompileError::Revert("brief anchor timestamp overflow".into()))?
    };
    u32::try_from(anchor_ts).map_err(|_| PrecompileError::Revert("brief anchor exceeds u32".into()))
}

pub(crate) fn record_preflighted_brief(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    supply_promis: u128,
    reference_prices: Vec<ReferenceCurrencyPrice>,
    is_green: bool,
    anchor: u32,
) -> Result<()> {
    let mut contract = storage.contract::<DesisContract>();
    let promis_load_minor = step_promis_load(&mut contract, worldwide_day, &reference_prices)?;
    let reference_prices = choose_reference_prices(&mut contract, worldwide_day, reference_prices)?;
    contract.write_auction_config(
        worldwide_day,
        &AuctionConfig::from_reference_prices(reference_prices, promis_load_minor),
    )?;
    contract.write_stage(worldwide_day, AuctionStage::Briefed)?;
    contract
        .pending_supply_promis
        .write(&worldwide_day, U256::from(supply_promis))?;
    contract
        .brief_green
        .write(&worldwide_day, u8::from(is_green))?;
    contract.auction_at.write(&worldwide_day, anchor)?;
    contract.push_sched_active(worldwide_day)?;
    Ok(())
}

/// Table bound, not a policy: a priced day carries at least one digit, so the rung
/// the ladder can actually reach is `anchor_digits - 1`. Sized past any launch rate
/// the six-decimal scale can carry, so it never truncates that.
const PROMIS_LOAD_MAX_EXPONENT: u32 = 21;

/// One entry past the widest rung: the deadband brackets against the decade above.
const POW10: [u128; PROMIS_LOAD_MAX_EXPONENT as usize + 2] = {
    let mut table = [1u128; PROMIS_LOAD_MAX_EXPONENT as usize + 2];
    let mut i = 1;
    while i < table.len() {
        table[i] = table[i - 1] * 10;
        i += 1;
    }
    table
};

const _: () = assert!(
    POW10[PROMIS_LOAD_LAUNCH_EXPONENT as usize]
        == 100_000 * 10u128.pow(PROTOCOL_AMOUNT_DECIMALS as u32),
    "the launch rung must carry 100 000 PROMIS"
);

pub(crate) fn promis_load_minor(exponent: u32) -> u128 {
    POW10[exponent.min(PROMIS_LOAD_MAX_EXPONENT) as usize]
}

fn decimal_digits(rate: U256) -> u32 {
    if rate.is_zero() {
        return 0;
    }
    let mut digits = 1u32;
    while (digits as usize) < POW10.len() && rate >= U256::from(POW10[digits as usize]) {
        digits += 1;
    }
    digits
}

/// Digits of the launch pair, captured once and never moved again.
pub(crate) fn launch_anchor_digits(rate: U256) -> u32 {
    PROMIS_LOAD_LAUNCH_EXPONENT + decimal_digits(rate)
}

fn anchor_exponent(anchor_digits: u32, rate: U256) -> u32 {
    anchor_digits
        .saturating_sub(decimal_digits(rate))
        .min(PROMIS_LOAD_MAX_EXPONENT)
}

/// The decade a day quoted at `rate` runs on, holding `current` while the rate stays
/// inside it widened by the deadband. Edges are compared scaled up rather than divided
/// down, so the band survives integer division in the narrow decades.
pub(crate) fn promis_load_exponent(anchor_digits: u32, current: Option<u32>, rate: U256) -> u32 {
    let Some(exponent) = current else {
        return anchor_exponent(anchor_digits, rate);
    };
    let exponent = exponent.min(PROMIS_LOAD_MAX_EXPONENT);
    // Independent cells: their difference is not trusted to stay inside the table.
    let decade = anchor_digits
        .saturating_sub(exponent)
        .clamp(1, POW10.len() as u32 - 1) as usize;
    let scaled = rate * U256::from(10_000u32);
    let lo = U256::from(POW10[decade - 1]) * U256::from(10_000 - PROMIS_LOAD_DEADBAND_BPS);
    let hi = U256::from(POW10[decade]) * U256::from(10_000 + PROMIS_LOAD_DEADBAND_BPS);
    if scaled >= lo && scaled < hi {
        exponent
    } else {
        anchor_exponent(anchor_digits, rate)
    }
}

/// Read before `choose_reference_prices` trims the table: either of its rules would
/// drop the anchor currency and the ladder with it.
fn step_promis_load(
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
    reference_prices: &[ReferenceCurrencyPrice],
) -> Result<u128> {
    if let Some(fixed) = PROMIS_LOAD_OVERRIDE {
        return Ok(fixed);
    }
    // A stored zero is "never set": no rate reaches the rung it would stand for.
    let stored = contract.promis_load_exponent.read()?;
    let current = (stored != 0).then_some(stored);
    // Without the anchor currency the ladder holds; nothing is captured, since the
    // launch pair needs a rate to be a pair.
    let Some(rate) = reference_prices
        .iter()
        .find(|row| row.iso_code == PROMIS_LOAD_ANCHOR_ISO)
        .map(|row| row.entry_price_minor)
    else {
        return Ok(promis_load_minor(
            current.unwrap_or(PROMIS_LOAD_LAUNCH_EXPONENT),
        ));
    };
    let anchor_digits = match contract.promis_load_anchor_digits.read()? {
        0 => {
            let digits = launch_anchor_digits(rate);
            contract.promis_load_anchor_digits.write(digits)?;
            digits
        }
        digits => digits,
    };
    let exponent = promis_load_exponent(anchor_digits, current, rate);
    let load = promis_load_minor(exponent);
    match current {
        Some(previous) if previous == exponent => {}
        Some(previous) => {
            contract.emit(IDesis::PromisLoadStepped {
                worldwideDay: worldwide_day.into(),
                previousLoadMinor: promis_load_minor(previous),
                newLoadMinor: load,
                rudisUsdRateMinor: rate,
            })?;
            contract.promis_load_exponent.write(exponent)?;
        }
        // Taking the first position is not a step; the config and START message carry it.
        None => contract.promis_load_exponent.write(exponent)?,
    }
    Ok(load)
}

/// The currencies a day will actually price: one per series-id letter, at most
/// `MAX_REFERENCE_PRICES`. Ordered by currency first, so the two brief paths - which
/// collect prices in different orders - resolve a day to the same table.
fn choose_reference_prices(
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
    mut rows: Vec<ReferenceCurrencyPrice>,
) -> Result<Vec<ReferenceCurrencyPrice>> {
    rows.sort_by_key(|row| row.iso_code);

    let letter_of = |iso_code: u16| SeriesId::currency_code(iso_code).map(|code| code[0]).ok();
    let mut kept: Vec<ReferenceCurrencyPrice> = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(letter) = letter_of(row.iso_code) else {
            continue;
        };
        if let Some(taken) = kept.iter().find(|k| letter_of(k.iso_code) == Some(letter)) {
            contract.emit(IDesis::ReferenceCurrencyLetterTaken {
                worldwideDay: worldwide_day.into(),
                isoCode: row.iso_code,
                takenBy: taken.iso_code,
            })?;
            continue;
        }
        if kept.len() == MAX_REFERENCE_PRICES {
            contract.emit(IDesis::ReferenceCurrencyOverCap {
                worldwideDay: worldwide_day.into(),
                isoCode: row.iso_code,
                cap: MAX_REFERENCE_PRICES as u8,
            })?;
            continue;
        }
        kept.push(row);
    }
    Ok(kept)
}

/// Fold the prior-clearing bid floor and the genesis profile into the config,
/// so the persisted config carries the same values the wire message ships.
fn fold_profile(
    storage: &StorageHandle<'_>,
    contract: &DesisContract<'_>,
    config: &mut AuctionConfig,
) -> Result<outbe_intexfactory::IntexParams> {
    // minBidQty = 4% of the prior clearing's issued count, restated at today's
    // load. The same PROMIS splits into ten times more Intexes one decade down
    // the ladder, so a floor left at yesterday's scale could sit above the whole
    // of today's tirage and clear the day to nothing.
    let min_bid_qty: u16 = {
        let last_worldwide_day = contract.read_last_cleared_worldwide_day()?;
        let today_load = config.promis_load_minor;
        if last_worldwide_day.value() == 0 || today_load == 0 {
            0
        } else {
            let prev_issued = u128::from(contract.read_last_clearing_issued_count()?);
            let prev_load = u128::try_from(
                contract
                    .config_promis_load_minor
                    .read(&last_worldwide_day)?,
            )
            .map_err(|_| DesisError::InvalidWorldwideDay(last_worldwide_day))?;
            let scaled = prev_issued
                .checked_mul(prev_load)
                .and_then(|v| v.checked_mul(u128::from(BID_QUANTITY_FLOOR_BPS)))
                .ok_or_else(|| {
                    PrecompileError::Revert("min bid quantity scaling overflow".into())
                })?;
            let derived = scaled / (10_000 * today_load);
            derived.min(u128::from(u16::MAX)) as u16
        }
    };
    let iparams = outbe_intexfactory::read_params(storage)?;
    config.min_intex_bid_quantity = min_bid_qty;
    config.call_trigger = crate::schema::IntexCallTrigger {
        call_window: iparams.call_window,
        call_threshold: iparams.call_threshold,
        call_notice_period: iparams.call_notice_period,
    };
    config.commit_bond_minor = iparams.commit_bond_minor;
    Ok(iparams)
}

/// Broadcast AUCTION_STAGE_START with the given schedule and day state.
#[allow(clippy::too_many_arguments)]
fn send_stage_start(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    config: &AuctionConfig,
    iparams: &outbe_intexfactory::IntexParams,
    commit_end: u32,
    reveal_end: u32,
    issuance_end: u32,
    day_state: u8,
) -> Result<()> {
    let mut prices = Vec::with_capacity(config.reference_prices.len());
    for row in &config.reference_prices {
        let floor = outbe_intexfactory::marked_up(row.entry_price_minor, iparams.floor_rate)?;
        let call = outbe_intexfactory::marked_up(row.entry_price_minor, iparams.call_rate)?;
        prices.push(IOriginRouter::ReferenceCurrencyPrice {
            isoCode: row.iso_code,
            entryPriceMinor: outbe_intexfactory::to_wire_price(row.entry_price_minor)?,
            floorPriceMinor: outbe_intexfactory::to_wire_price(floor)?,
            callPriceMinor: outbe_intexfactory::to_wire_price(call)?,
        });
    }
    let stage_params = IOriginRouter::AuctionStageStartParams {
        worldwideDay: worldwide_day.into(),
        commitEnd: commit_end,
        revealEnd: reveal_end,
        issuanceEnd: issuance_end,
        promisLoadMinor: config.promis_load_minor,
        minIntexBidRate: config.min_intex_bid_rate,
        prices,
        callNoticePeriod: iparams.call_notice_period,
        callWindow: iparams.call_window,
        callThreshold: iparams.call_threshold,
        minIntexBidQuantity: config.min_intex_bid_quantity,
        commitBondMinor: config.commit_bond_minor,
        dayState: day_state,
    };
    // Relay-float-funded: value 0, so the router self-quotes and pays the bridge fee from its float.
    storage.call(
        ORIGIN_ROUTER_ADDRESS,
        U256::ZERO,
        IOriginRouter::sendAuctionStageStartCall {
            params: stage_params,
        }
        .abi_encode()
        .into(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Schedule tick
// ---------------------------------------------------------------------------

/// Cycle `auction_advance` trigger: advance every scheduled auction. Each day
/// runs in its own checkpoint - an Err rolls that day back (retried next slot).
pub fn tick_schedule(ctx: &BlockRuntimeContext) -> Result<()> {
    schedule_tick(&ctx.storage, ctx.block.timestamp)
}

pub(crate) fn schedule_tick(storage: &StorageHandle<'_>, now: u64) -> Result<()> {
    let count = {
        let contract = storage.contract::<DesisContract>();
        contract.sched_active_count.read()?
    };
    if count == 0 {
        return Ok(());
    }
    // Snapshot the set before iterating: transitions swap-pop it.
    let mut days = Vec::with_capacity(count as usize);
    {
        let contract = storage.contract::<DesisContract>();
        for i in 0..count {
            days.push(contract.sched_active_at.read(&i)?.into());
        }
    }
    for day in days {
        let res = storage.with_checkpoint(|| advance_day(storage, day, now));
        if let Err(e) = res {
            tracing::warn!(target: "outbe::desis", %day, error = ?e, "schedule tick: skipping day");
        }
    }
    Ok(())
}

/// Walk one day's schedule: start at the anchor, flip to Revealing at commit
/// end, arm the clearing gate at reveal end, retire overdue and terminal days.
fn advance_day(storage: &StorageHandle<'_>, worldwide_day: WorldwideDay, now: u64) -> Result<()> {
    loop {
        let mut contract = storage.contract::<DesisContract>();
        let stage = contract.read_stage(worldwide_day)?;
        let stored_anchor = u64::from(contract.auction_at.read(&worldwide_day)?);
        // An e2e day never reaches its production anchor, so a briefed day starts
        // from the tick that observes the brief.
        #[cfg(feature = "e2e-test")]
        let anchor = if stage == AuctionStage::Briefed {
            now
        } else {
            stored_anchor
        };
        #[cfg(not(feature = "e2e-test"))]
        let anchor = stored_anchor;
        let commit_end = anchor.saturating_add(COMMIT_WINDOW_SECONDS);
        let reveal_end = commit_end.saturating_add(u64::from(REVEAL_WINDOW_SECONDS));
        let issuance_end = reveal_end.saturating_add(SETTLEMENT_WINDOW_SECONDS);
        match stage {
            AuctionStage::Cleared | AuctionStage::Cancelled => {
                return contract.remove_sched_active(worldwide_day);
            }
            _ if now >= issuance_end => {
                contract.emit(IDesis::AuctionOverdue {
                    worldwideDay: worldwide_day.into(),
                })?;
                refund_unsold_supply(storage, &mut contract, worldwide_day)?;
                contract.remove_gate_active(worldwide_day)?;
                contract.write_stage(worldwide_day, AuctionStage::Cancelled)?;
                return contract.remove_sched_active(worldwide_day);
            }
            AuctionStage::Briefed if now >= anchor => {
                if let StartOutcome::Retired = start_auction(
                    storage,
                    &mut contract,
                    worldwide_day,
                    commit_end,
                    reveal_end,
                    issuance_end,
                    now,
                )? {
                    return Ok(());
                }
            }
            AuctionStage::Started if now >= commit_end => {
                contract.write_stage(worldwide_day, AuctionStage::Revealing)?;
            }
            AuctionStage::Revealing if now >= reveal_end => {
                return arm_clearing(storage, worldwide_day, now);
            }
            _ => return Ok(()),
        }
    }
}

/// u32 wire timestamp (bounded until 2106).
fn ts32(ts: u64) -> Result<u32> {
    u32::try_from(ts).map_err(|_| PrecompileError::Revert("schedule timestamp exceeds u32".into()))
}

enum StartOutcome {
    /// Auction started; the schedule loop continues from `Started`.
    Started,
    /// Day was cancelled and retired; the schedule loop stops.
    Retired,
}

/// Dispatch the START message for a briefed day: a red day is born cancelled, a
/// day past its commit window is cancelled unstarted, otherwise it starts green.
#[allow(clippy::too_many_arguments)]
fn start_auction(
    storage: &StorageHandle<'_>,
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
    commit_end: u64,
    reveal_end: u64,
    issuance_end: u64,
    now: u64,
) -> Result<StartOutcome> {
    let mut config = contract.read_auction_config(worldwide_day)?;
    let iparams = fold_profile(storage, contract, &mut config)?;
    contract.write_auction_config(worldwide_day, &config)?;
    let (commit, reveal, issuance) = (ts32(commit_end)?, ts32(reveal_end)?, ts32(issuance_end)?);

    // A day nobody could price cannot hold an auction, and ends as a red day does - but
    // unlike a red day it was briefed with supply, which has to go back.
    let unpriced = config.reference_prices.is_empty();
    let red = contract.brief_green.read(&worldwide_day)? == 0;
    if unpriced || red {
        send_stage_start(
            storage,
            worldwide_day,
            &config,
            &iparams,
            commit,
            reveal,
            issuance,
            DAY_STATE_RED,
        )?;
        contract.write_stage(worldwide_day, AuctionStage::Cancelled)?;
        if unpriced {
            contract.emit(IDesis::AuctionCancelledUnpriced {
                worldwideDay: worldwide_day.into(),
            })?;
            refund_unsold_supply(storage, contract, worldwide_day)?;
        } else {
            contract.emit(IDesis::AuctionCancelledRedDay {
                worldwideDay: worldwide_day.into(),
            })?;
        }
        contract.remove_sched_active(worldwide_day)?;
        return Ok(StartOutcome::Retired);
    }
    if now >= commit_end {
        contract.emit(IDesis::AuctionOverdue {
            worldwideDay: worldwide_day.into(),
        })?;
        contract.write_stage(worldwide_day, AuctionStage::Cancelled)?;
        refund_unsold_supply(storage, contract, worldwide_day)?;
        contract.remove_sched_active(worldwide_day)?;
        return Ok(StartOutcome::Retired);
    }
    send_stage_start(
        storage,
        worldwide_day,
        &config,
        &iparams,
        commit,
        reveal,
        issuance,
        DAY_STATE_GREEN,
    )?;
    contract.write_stage(worldwide_day, AuctionStage::Started)?;
    contract.emit(IDesis::AuctionCreated {
        worldwideDay: worldwide_day.into(),
    })?;
    Ok(StartOutcome::Started)
}

/// Return a retiring day's unsold brief supply to PromisLimit. No-op once the
/// supply was consumed at clearing (or for a red day, which briefs zero).
fn refund_unsold_supply(
    storage: &StorageHandle<'_>,
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
) -> Result<()> {
    let supply = contract.pending_supply_promis.read(&worldwide_day)?;
    if supply.is_zero() {
        return Ok(());
    }
    contract
        .pending_supply_promis
        .write(&worldwide_day, U256::ZERO)?;
    contract.emit(IDesis::UnusedSupplyReported {
        worldwideDay: worldwide_day.into(),
        unusedPromis: supply,
    })?;
    PromisLimitContract::new(storage.clone()).add_to_total_unallocated(supply)?;
    Ok(())
}

/// Arm the clearing from the brief supply: convert raw PROMIS to whole Intex
/// units, start the fan-in gate and broadcast the clearing stage.
fn arm_clearing(storage: &StorageHandle<'_>, worldwide_day: WorldwideDay, now: u64) -> Result<()> {
    let mut contract = storage.contract::<DesisContract>();
    let config = contract.read_auction_config(worldwide_day)?;
    if config.promis_load_minor == 0 {
        return Err(DesisError::InvalidWorldwideDay(worldwide_day).into());
    }
    let supply_promis = u128::try_from(contract.pending_supply_promis.read(&worldwide_day)?)
        .map_err(|_| DesisError::InvalidWorldwideDay(worldwide_day))?;
    let supply_intex = (supply_promis / config.promis_load_minor).min(u128::from(u32::MAX)) as u32;

    contract.clearing_initiated.write(&worldwide_day, 1u8)?;
    contract
        .pending_supply_intex
        .write(&worldwide_day, supply_intex)?;
    contract
        .clearing_deadline
        .write(&worldwide_day, now.saturating_add(BIDS_FANIN_TIMEOUT_SECS))?;
    contract.push_gate_active(worldwide_day)?;
    contract.write_stage(worldwide_day, AuctionStage::Clearing)?;

    storage.call(
        ORIGIN_ROUTER_ADDRESS,
        U256::ZERO,
        IOriginRouter::sendAuctionStageClearingCall {
            worldwideDay: worldwide_day.into(),
        }
        .abi_encode()
        .into(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bid ingestion
// ---------------------------------------------------------------------------

/// `Open` while `Revealing`/`Clearing`; `Closed` past clearing and `UnknownDay` for an unbriefed day
/// (both acknowledged, nothing can make them applicable); `Err` before reveal so the transport redelivers.
fn intake_state(stage: AuctionStage) -> Result<Intake> {
    match stage {
        AuctionStage::Revealing | AuctionStage::Clearing => Ok(Intake::Open),
        AuctionStage::Cleared | AuctionStage::Cancelled => Ok(Intake::Closed),
        AuctionStage::None => Ok(Intake::UnknownDay),
        _ => Err(DesisError::InvalidStageTransition.into()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Intake {
    Open,
    Closed,
    UnknownDay,
}

fn emit_inbound_ignored(
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
    src_chain_id: u32,
    reason: u8,
) -> Result<()> {
    contract.emit(IDesis::InboundIgnored {
        worldwideDay: worldwide_day.into(),
        srcChainId: src_chain_id,
        reason,
    })
}

/// Accept a relayed bid batch. Bids accumulate per source chain while the stage is `Revealing`; a
/// higher `generation` supersedes that chain's prior bids. Batches may arrive in any order over the
/// unordered bridge, so completeness is tracked by a per-(chain, generation) bitmap of `batch_index`;
/// the chain finalizes once its BIDS_DONE marker and every batch have arrived (see
/// `try_finalize_chain`). A redelivered batch (its bit already set) is an idempotent no-op, so the
/// transport may safely re-deliver. A batch of a generation a later relay superseded, or for a day this
/// chain never briefed, is acknowledged with `InboundIgnored`: no later state could make it applicable.
#[allow(clippy::too_many_arguments)]
pub fn process_bids_batch(
    storage: StorageHandle<'_>,
    caller: Address,
    worldwide_day: WorldwideDay,
    src_chain_id: u32,
    generation: u32,
    batch_index: u16,
    total_batches: u16,
    bids: Vec<BidData>,
) -> Result<()> {
    require_origin_router(caller)?;
    require_nonzero_worldwide_day(worldwide_day)?;
    // The arrival bitmap is a U256, so at most 256 batches (batch_index 0..=255) are trackable.
    if total_batches == 0 || total_batches > MAX_BID_BATCHES || batch_index >= total_batches {
        return Err(PrecompileError::Revert(
            "processBidsBatch: invalid batch index/total".into(),
        ));
    }
    // Same reason as the currency check below: an over-wide batch is admissible
    // here but not at clearing, where the refund fan-out would reject the day.
    if bids.len() > MAX_BIDS_PER_BATCH {
        return Err(DesisError::BidBatchTooLarge(bids.len(), MAX_BIDS_PER_BATCH).into());
    }
    // Checked here because clearing cannot recover from it: an unspellable code would
    // otherwise surface as a day whose clearing reverts every block.
    if let Some(bad) = bids.iter().find(|bid| {
        SeriesId::currency_code(bid.issuance_currency).is_err()
            || SeriesId::currency_code(bid.reference_currency).is_err()
    }) {
        return Err(DesisError::UnspellableBidCurrency(
            bad.issuance_currency,
            bad.reference_currency,
        )
        .into());
    }
    let mut contract = storage.contract::<DesisContract>();

    match intake_state(contract.read_stage(worldwide_day)?)? {
        Intake::Open => {}
        Intake::Closed => {
            return emit_inbound_ignored(
                &mut contract,
                worldwide_day,
                src_chain_id,
                IGNORED_OBSOLETE,
            );
        }
        Intake::UnknownDay => {
            return emit_inbound_ignored(
                &mut contract,
                worldwide_day,
                src_chain_id,
                IGNORED_NOT_FOUND,
            );
        }
    }

    let chain_key = DesisContract::chain_key(worldwide_day, src_chain_id);
    let last_gen = contract.chain_last_generation.read(&chain_key)?;
    if generation < last_gen {
        return emit_inbound_ignored(&mut contract, worldwide_day, src_chain_id, IGNORED_OBSOLETE);
    }

    if generation > last_gen {
        // New generation supersedes: drop the chain's bids and reset its completeness tracking
        // (including a stale marker and the done flag).
        contract.reset_chain_intake(worldwide_day, src_chain_id)?;
        contract
            .chain_last_generation
            .write(&chain_key, generation)?;
        contract
            .chain_total_batches
            .write(&chain_key, u32::from(total_batches))?;
    }

    // All batches of a generation must agree on total_batches and stay in range, else a bad peer could set an
    // out-of-range bit and false-complete the set with a real batch missing.
    let stored_total = contract.chain_total_batches.read(&chain_key)?;
    if u32::from(total_batches) != stored_total || u32::from(batch_index) >= stored_total {
        return Err(PrecompileError::Revert(
            "processBidsBatch: batch total/index mismatch for generation".into(),
        ));
    }

    let bit = U256::from(1u8) << (batch_index as usize);
    let mask = contract.chain_arrived_mask.read(&chain_key)?;
    if !(mask & bit).is_zero() {
        // This batch of the current generation was already applied; redelivery is idempotent.
        return Ok(());
    }

    for bid in &bids {
        contract.append_bid(worldwide_day, src_chain_id, bid)?;
    }
    contract.chain_arrived_mask.write(&chain_key, mask | bit)?;

    try_finalize_chain(&mut contract, worldwide_day, src_chain_id)
}

/// Accept a chain's BIDS_DONE completeness marker: the source relayed `total_batches` batches with
/// `total_bids` bids for this day/generation. Stage/generation semantics mirror `process_bids_batch`;
/// a marker whose generation is ahead of the chain's batches reverts so the transport redelivers it
/// once the batches have arrived. A marker the generation already recorded is a no-op when it agrees
/// and is acknowledged with `InboundIgnored` when it does not: the first marker stands.
pub fn process_bids_done(
    storage: StorageHandle<'_>,
    caller: Address,
    worldwide_day: WorldwideDay,
    src_chain_id: u32,
    relay_generation: u32,
    total_batches: u16,
    total_bids: u32,
) -> Result<()> {
    require_origin_router(caller)?;
    require_nonzero_worldwide_day(worldwide_day)?;
    if total_batches == 0 || total_batches > 256 {
        return Err(PrecompileError::Revert(
            "processBidsDone: invalid total batches".into(),
        ));
    }
    let mut contract = storage.contract::<DesisContract>();

    match intake_state(contract.read_stage(worldwide_day)?)? {
        Intake::Open => {}
        Intake::Closed => {
            return emit_inbound_ignored(
                &mut contract,
                worldwide_day,
                src_chain_id,
                IGNORED_OBSOLETE,
            );
        }
        Intake::UnknownDay => {
            return emit_inbound_ignored(
                &mut contract,
                worldwide_day,
                src_chain_id,
                IGNORED_NOT_FOUND,
            );
        }
    }

    let chain_key = DesisContract::chain_key(worldwide_day, src_chain_id);
    let last_gen = contract.chain_last_generation.read(&chain_key)?;
    if relay_generation < last_gen {
        return emit_inbound_ignored(&mut contract, worldwide_day, src_chain_id, IGNORED_OBSOLETE);
    }
    if relay_generation > last_gen {
        return Err(PrecompileError::Revert(
            "processBidsDone: marker generation ahead of its batches".into(),
        ));
    }

    let recorded_batches = contract.chain_done_batches.read(&chain_key)?;
    if recorded_batches != 0 {
        let same = recorded_batches == u32::from(total_batches)
            && contract.chain_done_bids.read(&chain_key)? == total_bids;
        if same {
            return Ok(());
        }
        return emit_inbound_ignored(&mut contract, worldwide_day, src_chain_id, IGNORED_CONFLICT);
    }

    contract
        .chain_done_batches
        .write(&chain_key, u32::from(total_batches))?;
    contract.chain_done_bids.write(&chain_key, total_bids)?;

    try_finalize_chain(&mut contract, worldwide_day, src_chain_id)
}

/// Mark the chain done once its BIDS_DONE marker and every batch have arrived with matching totals.
/// Invoked from both arrival paths - either side may land last over the unordered bridge. An
/// integrity mismatch (batch totals vs marker claims) keeps the chain not-done, so the deadline
/// skip excludes it.
fn try_finalize_chain(
    contract: &mut DesisContract<'_>,
    worldwide_day: WorldwideDay,
    chain_id: u32,
) -> Result<()> {
    let key = DesisContract::chain_key(worldwide_day, chain_id);
    if contract.chain_done.read(&key)? != 0 {
        return Ok(());
    }
    let claimed_batches = contract.chain_done_batches.read(&key)?;
    if claimed_batches == 0 {
        return Ok(()); // no marker yet
    }
    let total = contract.chain_total_batches.read(&key)?;
    let mask = contract.chain_arrived_mask.read(&key)?;
    let bid_count = contract.chain_bid_count.read(&key)?;
    if total != claimed_batches
        || mask.count_ones() as u32 != total
        || bid_count != contract.chain_done_bids.read(&key)?
    {
        return Ok(());
    }
    contract.chain_done.write(&key, 1u8)?;
    contract.emit(IDesis::ChainBidsDone {
        worldwideDay: worldwide_day.into(),
        srcChainId: chain_id,
        bidsCount: bid_count,
    })
}

// ---------------------------------------------------------------------------
// Clearing
// ---------------------------------------------------------------------------

/// Tick entry for the fan-in gate: clear once every snapshot chain has finalized,
/// or once the deadline passes (missing chains are excluded and reported via
/// `ChainSkipped`). Returns `None` while the gate is not ready.
pub fn force_clear(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    now: u64,
) -> Result<Option<ClearingResult>> {
    let snapshot = fetch_targets(&storage, worldwide_day)?;
    let (included, skipped) = {
        let contract = storage.contract::<DesisContract>();
        let parts = partition_chains(&contract, worldwide_day, &snapshot)?;
        if !parts.1.is_empty() && now < contract.clearing_deadline.read(&worldwide_day)? {
            return Ok(None);
        }
        parts
    };
    clear_inner(storage, worldwide_day, &snapshot, &included, &skipped).map(Some)
}

/// Cycle `auction_clearing` trigger: attempt to clear every day awaiting the
/// fan-in gate. Each day runs in its own checkpoint - an Err rolls that day
/// back (retried next slot) and never escapes into the trigger chain.
pub fn tick_gate(ctx: &BlockRuntimeContext) -> Result<()> {
    let storage = ctx.storage.clone();
    let count = {
        let contract = storage.contract::<DesisContract>();
        contract.gate_active_count.read()?
    };
    if count == 0 {
        return Ok(());
    }
    let now = ctx.block.timestamp;
    // Snapshot the set before iterating: a successful clear swap-pops it.
    let mut days = Vec::with_capacity(count as usize);
    {
        let contract = storage.contract::<DesisContract>();
        for i in 0..count {
            days.push(contract.gate_active_at.read(&i)?.into());
        }
    }
    for day in days {
        let res = storage.with_checkpoint(|| force_clear(storage.clone(), day, now));
        if let Err(e) = res {
            tracing::warn!(target: "outbe::desis", %day, error = ?e, "clearing gate: skipping day");
        }
    }
    Ok(())
}

/// The day's frozen target snapshot, read from the OriginRouter registry
/// (deterministic: frozen at STAGE_START).
fn fetch_targets(storage: &StorageHandle<'_>, worldwide_day: WorldwideDay) -> Result<Vec<u32>> {
    let ret = storage.staticcall(
        ORIGIN_ROUTER_ADDRESS,
        IOriginRouter::targetsOfCall {
            worldwideDay: worldwide_day.into(),
        }
        .abi_encode()
        .into(),
    )?;
    IOriginRouter::targetsOfCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("targetsOf undecodable".into()))
}

/// Split the snapshot into chains whose intake finalized and chains still missing.
fn partition_chains(
    contract: &DesisContract<'_>,
    worldwide_day: WorldwideDay,
    snapshot: &[u32],
) -> Result<(Vec<u32>, Vec<u32>)> {
    let mut included = Vec::with_capacity(snapshot.len());
    let mut skipped = Vec::new();
    for &chain_id in snapshot {
        if contract
            .chain_done
            .read(&DesisContract::chain_key(worldwide_day, chain_id))?
            != 0
        {
            included.push(chain_id);
        } else {
            skipped.push(chain_id);
        }
    }
    Ok((included, skipped))
}

/// Run the clearing algorithm over the included chains' bids, transition to
/// `Cleared`, hand issuance to IntexFactory, return unused supply to PromisLimit
/// and send the per-chain AUCTION_RESULT / REFUND_INSTRUCTIONS messages.
fn clear_inner(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    snapshot: &[u32],
    included: &[u32],
    skipped: &[u32],
) -> Result<ClearingResult> {
    let mut contract = storage.contract::<DesisContract>();
    require_stage(&contract, worldwide_day, AuctionStage::Clearing)?;

    let supply = contract.pending_supply_intex.read(&worldwide_day)?;
    if contract.clearing_initiated.read(&worldwide_day)? == 0 {
        return Err(DesisError::PendingClearingDataMissing(worldwide_day).into());
    }

    let config = contract.read_auction_config(worldwide_day)?;
    let min_bid_qty = contract.config_min_bid_quantity.read(&worldwide_day)? as u16;
    // Zero bids are valid here: `calculate_clearing` yields 0 issued, the full supply returns
    // to PromisLimit, and a no-sale AuctionResult(0,0,0) is reported to every snapshot chain.
    let bids = contract.read_chains_bids(worldwide_day, included)?;

    let total_demand: u64 = bids.iter().map(|(_, b)| u64::from(b.intex_quantity)).sum();
    let mut sorted = bids;
    sort_bids(&mut sorted);

    let result = calculate_clearing(&sorted, &config, supply, min_bid_qty);

    // Persist clearing outcome and transition.
    contract.write_stage(worldwide_day, AuctionStage::Cleared)?;
    contract.write_last_cleared_worldwide_day(worldwide_day)?;
    contract.write_last_clearing_issued_count(result.issued_intex_count)?;

    // Clear the bid working-set, pending inputs and the gate (CEI: state writes before external calls).
    let supply_promis = contract.pending_supply_promis.read(&worldwide_day)?;
    for &chain_id in snapshot {
        contract.reset_chain_intake(worldwide_day, chain_id)?;
    }
    contract.day_bid_count.write(&worldwide_day, 0)?;
    contract.pending_supply_intex.write(&worldwide_day, 0)?;
    contract
        .pending_supply_promis
        .write(&worldwide_day, U256::ZERO)?;
    contract.clearing_initiated.write(&worldwide_day, 0u8)?;
    contract.clearing_deadline.clear(&worldwide_day)?;
    contract.remove_gate_active(worldwide_day)?;

    for &chain_id in skipped {
        contract.emit(IDesis::ChainSkipped {
            worldwideDay: worldwide_day.into(),
            srcChainId: chain_id,
        })?;
    }

    if result.issued_intex_count == 0 {
        contract.emit(IDesis::AuctionClearedEmpty {
            worldwideDay: worldwide_day.into(),
            totalDemand: total_demand,
        })?;
    } else {
        contract.emit(IDesis::AuctionCleared {
            worldwideDay: worldwide_day.into(),
            issuedIntexCount: result.issued_intex_count,
            clearingRate: result.clearing_rate,
            totalDemand: total_demand,
        })?;
    }

    // Return the unsold Promis (unsold whole units + conversion dust) to PromisLimit.
    let issued_promis =
        U256::from(result.issued_intex_count as u128) * U256::from(config.promis_load_minor);
    let unused_promis = supply_promis.saturating_sub(issued_promis);
    if !unused_promis.is_zero() {
        contract.emit(IDesis::UnusedSupplyReported {
            worldwideDay: worldwide_day.into(),
            unusedPromis: unused_promis,
        })?;
        PromisLimitContract::new(storage.clone()).add_to_total_unallocated(unused_promis)?;
    }

    if result.issued_intex_count == 0 {
        // No series anywhere, so the day's recorded contributor map can never distribute.
        outbe_intexfactory::api::discard_day_contributors(&storage, worldwide_day)?;
    } else {
        let mut legs = Vec::new();
        for group in issuance_groups(&result, &config, worldwide_day, snapshot)? {
            legs.extend(outbe_intexfactory::api::issue(&storage, group)?);
        }

        outbe_intexfactory::api::send_issuance(&storage, legs)?;
    }

    // Send AUCTION_RESULT to every snapshot chain; skipped/zero-winner chains get
    // wonBidsCount 0 so their local auction still completes.
    for &chain_id in snapshot {
        let won_bids_count = result
            .winner_chains
            .iter()
            .filter(|&&c| c == chain_id)
            .count() as u32;
        storage.call(
            ORIGIN_ROUTER_ADDRESS,
            U256::ZERO,
            IOriginRouter::sendAuctionResultCall {
                dstChainId: chain_id,
                worldwideDay: worldwide_day.into(),
                issuedIntexCount: result.issued_intex_count,
                auctionClearingRate: u64::from(result.clearing_rate),
                wonBidsCount: won_bids_count,
            }
            .abi_encode()
            .into(),
        )?;
    }

    // A skipped chain's bidders reclaim through the escrow timeout path instead.
    for &chain_id in included {
        let mut bidders = Vec::new();
        let mut refunded = Vec::new();
        let mut paid = Vec::new();
        for (i, &bidder_chain) in result.bidder_chains.iter().enumerate() {
            if bidder_chain == chain_id {
                bidders.push(result.all_bidders[i]);
                refunded.push(result.refunded_amounts[i]);
                paid.push(result.paid_amounts[i]);
            }
        }
        if bidders.is_empty() {
            continue;
        }
        let total_chunks = refund_chunk_count(bidders.len())?;
        for (chunk_index, start) in (0..bidders.len()).step_by(REFUND_CHUNK_LEN).enumerate() {
            let end = (start + REFUND_CHUNK_LEN).min(bidders.len());
            storage.call(
                ORIGIN_ROUTER_ADDRESS,
                U256::ZERO,
                IOriginRouter::sendRefundInstructionsCall {
                    dstChainId: chain_id,
                    worldwideDay: worldwide_day.into(),
                    chunkIndex: chunk_index as u16,
                    totalChunks: total_chunks as u16,
                    bidders: bidders[start..end].to_vec(),
                    refundedAmounts: refunded[start..end].to_vec(),
                    paidAmounts: paid[start..end].to_vec(),
                }
                .abi_encode()
                .into(),
            )?;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Clearing algorithm (pure)
// ---------------------------------------------------------------------------

/// Sort chain-tagged bids: descending rate, ascending timestamp on tie. The sort is
/// stable, so remaining ties keep the snapshot's chain order - deterministic.
fn sort_bids(bids: &mut [(u32, BidData)]) {
    bids.sort_by(|(_, a), (_, b)| {
        b.intex_bid_rate
            .cmp(&a.intex_bid_rate)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });
}

/// Native/WCOEN escrow amount for `qty` Intexes at `rate` (1e6 fixed-point)
/// against the six-decimal per-Intex escrow basis. The protocol result crosses
/// into 18-decimal payment units exactly once, saturating to u128.
pub(crate) fn rate_lock(qty: u64, basis: u128, rate: u32) -> u128 {
    let amount = (U256::from(qty)
        .saturating_mul(U256::from(basis))
        .saturating_mul(U256::from(rate))
        / U256::from(SCALE_1E6_U64))
    .saturating_mul(NATIVE_UNITS_PER_PROTOCOL_UNIT);
    u128::try_from(amount).unwrap_or(u128::MAX)
}

/// Uniform-rate clearing: allocate sorted bids until `supply` runs out; the
/// clearing rate is the last allocated bid's. lock/pay uses the shared scale-1e6 denominator.
fn calculate_clearing(
    bids: &[(u32, BidData)],
    config: &AuctionConfig,
    supply: u32,
    min_qty: u16,
) -> ClearingResult {
    let len = bids.len();
    let mut winners: Vec<Address> = Vec::with_capacity(len);
    let mut winner_quantities: Vec<alloy_primitives::U256> = Vec::with_capacity(len);
    let mut winner_chains: Vec<u32> = Vec::with_capacity(len);
    let mut winner_currencies: Vec<(u16, u16)> = Vec::with_capacity(len);
    let mut won_by_index: Vec<u32> = vec![0u32; len];

    let escrow_basis = config.escrow_basis_minor();
    let mut total_allocated: u32 = 0;
    let mut clearing_rate: u32 = config.min_intex_bid_rate;

    for (i, (chain_id, bid)) in bids.iter().enumerate() {
        if total_allocated >= supply {
            break;
        }
        if bid.intex_bid_rate < config.min_intex_bid_rate {
            continue;
        }
        if bid.intex_quantity < min_qty {
            continue;
        }

        let allocatable = supply - total_allocated;
        let allocated = (bid.intex_quantity as u32).min(allocatable);

        if allocated > 0 {
            winners.push(bid.bidder_address);
            winner_quantities.push(alloy_primitives::U256::from(allocated));
            winner_chains.push(*chain_id);
            winner_currencies.push((bid.issuance_currency, bid.reference_currency));
            won_by_index[i] = allocated;
            total_allocated += allocated;
            clearing_rate = bid.intex_bid_rate;
        }
    }

    let mut all_bidders: Vec<Address> = Vec::with_capacity(len);
    let mut refunded_amounts: Vec<u128> = Vec::with_capacity(len);
    let mut paid_amounts: Vec<u128> = Vec::with_capacity(len);
    let mut bidder_chains: Vec<u32> = Vec::with_capacity(len);

    for (i, (chain_id, bid)) in bids.iter().enumerate() {
        all_bidders.push(bid.bidder_address);
        bidder_chains.push(*chain_id);

        // locked = quantity * escrow_basis * rate / 1_000_000 (escrowed at bid time).
        let locked = rate_lock(
            u64::from(bid.intex_quantity),
            escrow_basis,
            bid.intex_bid_rate,
        );

        let won = won_by_index[i];
        if won > 0 {
            // Uniform clearing: winners pay at the clearing rate; refund the rest.
            let paid = rate_lock(u64::from(won), escrow_basis, clearing_rate);
            let refunded = locked.saturating_sub(paid);
            paid_amounts.push(paid);
            refunded_amounts.push(refunded);
        } else {
            paid_amounts.push(0);
            refunded_amounts.push(locked);
        }
    }

    ClearingResult {
        issued_intex_count: total_allocated,
        clearing_rate,
        winners,
        winner_quantities,
        winner_chains,
        winner_currencies,
        all_bidders,
        refunded_amounts,
        paid_amounts,
        bidder_chains,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// How many REFUND_INSTRUCTIONS messages one chain's bidders take. Bounded by the
/// codec's arrival set, which is one 256-bit word wide.
pub(crate) fn refund_chunk_count(bidders: usize) -> Result<usize> {
    let chunks = bidders.div_ceil(REFUND_CHUNK_LEN);
    if chunks > MAX_REFUND_CHUNKS {
        return Err(DesisError::RefundFanOutTooLarge(bidders).into());
    }
    Ok(chunks)
}

/// One issuance per distinct winning `(issuance, reference)` pair, in the order
/// the pairs first appear in the ranking. Each group carries its own reference
/// currency's entry price, which is what floor and call derive from.
fn issuance_groups(
    result: &ClearingResult,
    config: &AuctionConfig,
    worldwide_day: WorldwideDay,
    snapshot: &[u32],
) -> Result<Vec<IssuanceParams>> {
    let mut groups: Vec<IssuanceParams> = Vec::new();
    for (i, &(issuance_currency, reference_currency)) in result.winner_currencies.iter().enumerate()
    {
        let at = match groups.iter().position(|g| {
            (g.issuance_currency, g.reference_currency) == (issuance_currency, reference_currency)
        }) {
            Some(at) => at,
            None => {
                // Reveal only accepts a reference the day priced, so a winner
                // without a row means the day's table and its bids disagree.
                let entry_price_minor = config
                    .entry_price_for(reference_currency)
                    .ok_or(DesisError::UnpricedReferenceCurrency(reference_currency))?;
                groups.push(IssuanceParams {
                    series_id: SeriesId::for_pair(
                        worldwide_day,
                        issuance_currency,
                        reference_currency,
                    )?,
                    worldwide_day,
                    issued_intex_count: 0,
                    promis_load_minor: config.promis_load_minor,
                    entry_price_minor,
                    issuance_currency,
                    reference_currency,
                    recipients: Vec::new(),
                    quantities: Vec::new(),
                    recipient_chains: Vec::new(),
                    snapshot_chains: snapshot.to_vec(),
                });
                groups.len() - 1
            }
        };

        let quantity = result.winner_quantities[i];
        let group = &mut groups[at];
        group.issued_intex_count += quantity.saturating_to::<u32>();
        group.recipients.push(result.winners[i]);
        group.quantities.push(quantity);
        group.recipient_chains.push(result.winner_chains[i]);
    }
    Ok(groups)
}

fn require_origin_router(caller: Address) -> Result<()> {
    if caller != ORIGIN_ROUTER_ADDRESS {
        return Err(DesisError::UnauthorizedOrigin(caller).into());
    }
    Ok(())
}

fn require_nonzero_worldwide_day(worldwide_day: WorldwideDay) -> Result<()> {
    if worldwide_day.value() == 0 {
        return Err(DesisError::InvalidWorldwideDay(worldwide_day).into());
    }
    Ok(())
}

fn require_stage(
    contract: &DesisContract<'_>,
    worldwide_day: WorldwideDay,
    expected: AuctionStage,
) -> Result<()> {
    let actual = contract.read_stage(worldwide_day)?;
    if actual != expected {
        return Err(DesisError::InvalidStageTransition.into());
    }
    Ok(())
}
