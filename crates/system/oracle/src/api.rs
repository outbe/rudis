//! Public cross-module API surface for the Oracle module.
//!
//! Exposes read-only helpers that other modules call to validate
//! currency support, without going through the precompile dispatch.

use crate::constants::FX_RATE_MAX_AGE_SECONDS;
use crate::errors::{OracleError, OracleOcompError};
use crate::schema::{OracleContract, PairIndex};
use crate::scurve;

pub use crate::constants::{DAY_TYPE_ISO, DAY_TYPE_PAIR};
pub use crate::types::{currency_address, AddressPair, AssetType, COEN_ASSET};

use alloy_primitives::{Address, U256};

use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::Result,
    storage::StorageHandle,
    time::{previous_date_key, timestamp_to_date_key},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OcompAuctionEntryPriceSource {
    LastClosedDayVwap = 1,
    /// No longer produced; the discriminant is part of a hashed wire enum.
    CurrentVwapFallback = 2,
}

/// Bounded Oracle projection captured before the terminal OCOMP request.
///
/// `oracle_state_version` reuses the authoritative monotonic snapshot stream
/// index: every exchange-rate snapshot advances it, while the WWD and S-curve
/// counters identify the exact derived collections read for this day.
/// One reference currency's frozen auction entry price.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OcompReferenceEntryPrice {
    pub reference_currency: u16,
    pub entry_price_minor: U256,
    pub source: OcompAuctionEntryPriceSource,
    pub source_day: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompOraclePreAdmissionProjection {
    pub profile_ready: bool,
    /// One row per priced reference currency, ascending by currency; an unpriced
    /// currency is absent rather than zero.
    pub auction_entry_prices: Vec<OcompReferenceEntryPrice>,
    pub oracle_state_version: u64,
    /// Registered pairs, i.e. the upper bound on the day-VWAP entries an
    /// opening proof can be asked to cover. Now that the WorldwideDay VWAP
    /// column is keyed by the registry index, the registry size *is* that
    /// bound; there is no separate per-day entry count to read.
    pub wwd_pair_entries: u32,
    pub active_scurve_entries: u32,
}

/// Validates that `iso_code` is registered as a reference currency.
///
/// Returns `Ok(())` if the code is present in `reference_currencies`, or
/// [`OracleError::NotReferenceCurrency`] otherwise.
///
/// Reference currencies are the ISO 4217 numeric codes considered valid
/// for off-chain pricing references. The list is pre-filled at genesis
/// with `[840]` (USD) and may be extended via future protocol upgrades.
pub fn check_reference_currency(ctx: &BlockRuntimeContext, iso_code: u16) -> Result<()> {
    check_reference_currency_with_storage(ctx.storage.clone(), iso_code)
}

pub fn get_all_reference_currencies(ctx: &BlockRuntimeContext) -> Result<Vec<u16>> {
    let oracle: OracleContract<'_> = OracleContract::new(ctx.storage.clone());
    oracle.reference_currencies.read_all()
}

/// Same validation as [`check_reference_currency`] but takes a bare
/// [`StorageHandle`] for callers (e.g. precompile dispatch) that do not have
/// a [`BlockRuntimeContext`] in scope.
pub fn check_reference_currency_with_storage(storage: StorageHandle, iso_code: u16) -> Result<()> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let len = oracle.reference_currencies.len()?;
    for i in 0..len {
        if let Some(code) = oracle.reference_currencies.get(i)? {
            if code == iso_code {
                return Ok(());
            }
        }
    }
    Err(OracleError::NotReferenceCurrency { iso_code }.into())
}

/// Current COEN price to currency `iso_code` in the COEN/ISO six-decimal scale.
///
/// Returns errors when `COEN/<iso_code>` is not a registered pair, or
/// no rates are found.
pub fn coen_rate_for(storage: StorageHandle, iso_code: u16) -> Result<U256> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.get_exchange_rate(COEN_ASSET, currency_address(iso_code))
}

/// `amount`, denominated in `from_iso`, re-expressed in `to_iso`.
///
/// Both currencies are priced against COEN, so the cross rate is the ratio of
/// the two legs: `amount x rate(COEN/to) / rate(COEN/from)`. One rounding,
/// upwards, so a converted charge never undercollects. Equal currencies
/// short-circuit and read no rate at all.
///
/// Reverts when either leg has no registered pair or no published rate.
pub fn currency_cross_rate(
    storage: StorageHandle,
    from_iso: u16,
    to_iso: u16,
    amount: U256,
) -> Result<U256> {
    if from_iso == to_iso || amount.is_zero() {
        return Ok(amount);
    }
    let rate_from = coen_rate_for(storage.clone(), from_iso)?;
    let rate_to = coen_rate_for(storage, to_iso)?;
    let numerator = amount
        .checked_mul(rate_to)
        .ok_or(OracleError::CrossRateOverflow)?;
    Ok(numerator.div_ceil(rate_from))
}

/// Current COEN price to currency `iso_code`, or `None` when the pair is not
/// registered or carries no published rate.
///
/// [`get_all_reference_currencies`] lists currencies independently of whether
/// their `COEN/<iso>` pair has been registered and priced, so a block hook
/// walking that registry needs a read that reports "not priceable yet" instead
/// of reverting and halting the block. Storage faults still propagate.
pub fn coen_rate_for_opt(storage: StorageHandle, iso_code: u16) -> Result<Option<U256>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let index = oracle.pair_index_of(AddressPair::new_coen_to(iso_code))?;
    if index == 0 {
        return Ok(None);
    }
    let stored = oracle.exchange_rate.read(&index)?;
    Ok((!stored.is_zero()).then_some(stored))
}

/// Current COEN price for `iso_code`, accepted only when its canonical
/// publication timestamp is non-zero and no older than six hours.
pub fn fresh_coen_rate_for(storage: StorageHandle, iso_code: u16) -> Result<U256> {
    let (_, index) = require_coen_pair(storage.clone(), iso_code)?;
    fresh_rate_at_index(storage, index)?
        .ok_or_else(|| OracleError::StaleCoenRate { iso_code }.into())
}

/// Hook-safe variant of [`fresh_coen_rate_for`]. An unregistered, unpublished or
/// stale currency is not priceable in this block and therefore returns `None`;
/// storage faults still propagate.
pub fn fresh_coen_rate_for_opt(storage: StorageHandle, iso_code: u16) -> Result<Option<U256>> {
    let oracle = OracleContract::new(storage.clone());
    let index = oracle.pair_index_of(AddressPair::new_coen_to(iso_code))?;
    if index == 0 {
        return Ok(None);
    }
    fresh_rate_at_index(storage, index)
}

/// Freshness-enforcing counterpart of [`currency_cross_rate`] for live economic
/// paths. Equal currencies and zero amounts retain the no-read short circuit.
pub fn fresh_currency_cross_rate(
    storage: StorageHandle,
    from_iso: u16,
    to_iso: u16,
    amount: U256,
) -> Result<U256> {
    if from_iso == to_iso || amount.is_zero() {
        return Ok(amount);
    }
    let rate_from = fresh_coen_rate_for(storage.clone(), from_iso)?;
    let rate_to = fresh_coen_rate_for(storage, to_iso)?;
    let numerator = amount
        .checked_mul(rate_to)
        .ok_or(OracleError::CrossRateOverflow)?;
    Ok(numerator.div_ceil(rate_from))
}

fn fresh_rate_at_index(storage: StorageHandle, index: PairIndex) -> Result<Option<U256>> {
    let now = storage.timestamp()?.to::<u64>();
    let oracle = OracleContract::new(storage);
    let rate = oracle.exchange_rate.read(&index)?;
    let published = oracle.exchange_rate_timestamp.read(&index)?;
    Ok((!rate.is_zero()
        && published != 0
        && now.saturating_sub(published) <= FX_RATE_MAX_AGE_SECONDS)
        .then_some(rate))
}

/// Registry index of the `COEN/<iso_code>` pair, or `None` when it was never registered.
/// Unlike [`require_coen_pair`], which collapses both into an error.
pub fn coen_pair_index_opt(storage: StorageHandle, iso_code: u16) -> Result<Option<PairIndex>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let index = oracle.pair_index_of(AddressPair::new_coen_to(iso_code))?;
    Ok((index != 0).then_some(index))
}

pub fn get_exchange_rate(storage: StorageHandle, base: Address, quote: Address) -> Result<U256> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.get_exchange_rate(base, quote)
}

/// The registered `COEN/<iso_code>` pair and its index, reverting when the
/// pair is not registered.
pub fn require_coen_pair(
    storage: StorageHandle,
    iso_code: u16,
) -> Result<(AddressPair, PairIndex)> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let pair = AddressPair::new_coen_to(iso_code);
    let index = oracle.pair_index_of(pair)?;
    if index == 0 {
        return Err(OracleError::PairNotRegistered { pair }.into());
    }
    Ok((pair, index))
}

pub fn register_pair(storage: StorageHandle, pair: AddressPair) -> Result<PairIndex> {
    let mut oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.register_pair(pair)
}

/// Public Oracle inputs used by the Tribute enclave.
///
/// Both VWAPs are exact WorldwideDay snapshots in the six-decimal COEN/ISO
/// domain. The S-curve belongs only to the independently selected reference
/// currency; the enclave owns the final `max(reference_vwap, reference_curve)`
/// and cross-currency nominal arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePricingInputs {
    pub issuance_wwd_vwap_minor: U256,
    pub reference_wwd_vwap_minor: U256,
    pub reference_scurve_minor: U256,
}

/// Reads the three canonical public pricing inputs for one Tribute.
///
/// `None` means the issuance `COEN/<iso>` pair is not registered. Once the
/// issuance pair exists, missing daily data or a missing reference pair is
/// represented by zero fields so the Tribute host can reject the transient
/// unpriced condition without collapsing it into an unsupported issuance.
pub fn tribute_pricing_inputs(
    storage: StorageHandle,
    issuance_currency: u16,
    reference_currency: u16,
    worldwide_day: WorldwideDay,
) -> Result<Option<TributePricingInputs>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage.clone());
    let issuance_pair = AddressPair::new_coen_to(issuance_currency);
    let issuance_index = oracle.pair_index_of(issuance_pair)?;
    if issuance_index == 0 {
        return Ok(None);
    }
    let issuance_wwd_vwap_minor = oracle
        .get_worldwide_day_vwap_for_pair(worldwide_day, issuance_index)?
        .unwrap_or(U256::ZERO);
    let reference_pair = AddressPair::new_coen_to(reference_currency);
    let reference_index = oracle.pair_index_of(reference_pair)?;
    let reference_wwd_vwap_minor = if reference_index == 0 {
        U256::ZERO
    } else {
        oracle
            .get_worldwide_day_vwap_for_pair(worldwide_day, reference_index)?
            .unwrap_or(U256::ZERO)
    };
    let reference_scurve_minor = if reference_index == 0 {
        U256::ZERO
    } else {
        get_max_active_scurve_value(storage, worldwide_day, reference_pair)?
    };
    Ok(Some(TributePricingInputs {
        issuance_wwd_vwap_minor,
        reference_wwd_vwap_minor,
        reference_scurve_minor,
    }))
}

pub fn set_exchange_rate(
    storage: StorageHandle,
    caller: Address,
    pair: AddressPair,
    rate: U256,
    block_number: u64,
    timestamp: u64,
) -> Result<()> {
    let mut oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.set_exchange_rate(caller, pair, rate, block_number, timestamp)
}

/// Stored WorldwideDay VWAP for the pair registered under `index`, or `None`
/// when the day has no snapshot or that pair had no data in it. Callers get the
/// index from [`require_coen_pair`] or [`register_pair`].
pub fn get_worldwide_day_vwap_for_pair(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
    index: PairIndex,
) -> Result<Option<U256>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.get_worldwide_day_vwap_for_pair(worldwide_day, index)
}

/// Selects the already-stored auction entry prices and the authenticated collection counts;
/// never invokes calculation. One price per reference currency, so the read walks the
/// registry; a currency the last closed UTC day carries no price for is omitted, the
/// day-type currency included.
pub fn ocomp_pre_admission_projection(
    storage: StorageHandle,
    block_timestamp: u64,
) -> Result<OcompOraclePreAdmissionProjection> {
    let oracle = OracleContract::new(storage);
    let profile_ready = oracle.ocomp_profile_ready.read()?;
    let current_utc_day = timestamp_to_date_key(block_timestamp);
    let last_closed_day = previous_date_key(current_utc_day);
    // The day-type currency is priced from the same per-pair day VWAP as every
    // other currency; the OCOMP mirror of it is a copy, written only once the
    // profile is installed, and is not the price source.
    let day_type_index = oracle.pair_index_of(DAY_TYPE_PAIR)?;
    let last_closed_vwap = if day_type_index == 0 {
        None
    } else {
        oracle
            .get_utc_day_vwap_for_pair(last_closed_day, day_type_index)?
            .filter(|value| !value.is_zero())
    };
    let mut auction_entry_prices = Vec::new();
    if let Some(vwap) = last_closed_vwap {
        auction_entry_prices.push(OcompReferenceEntryPrice {
            reference_currency: DAY_TYPE_ISO,
            entry_price_minor: vwap,
            source: OcompAuctionEntryPriceSource::LastClosedDayVwap,
            source_day: last_closed_day,
        });
    }
    for iso_code in oracle.reference_currencies.read_all()? {
        if iso_code == DAY_TYPE_ISO {
            continue;
        }
        let index = oracle.pair_index_of(AddressPair::new_coen_to(iso_code))?;
        if index == 0 {
            continue;
        }
        if let Some(vwap) = oracle
            .get_utc_day_vwap_for_pair(last_closed_day, index)?
            .filter(|value| !value.is_zero())
        {
            auction_entry_prices.push(OcompReferenceEntryPrice {
                reference_currency: iso_code,
                entry_price_minor: vwap,
                source: OcompAuctionEntryPriceSource::LastClosedDayVwap,
                source_day: last_closed_day,
            });
        }
    }
    // Hashed in order, so the order is part of the day's identity.
    auction_entry_prices.sort_by_key(|row| row.reference_currency);
    let scurve_count = oracle.scurve_count.read()?;
    let scurve_oldest = oracle.scurve_oldest_idx.read()?;
    let active_scurve_entries = scurve_count
        .checked_sub(scurve_oldest)
        .ok_or(OracleOcompError::ScurveOldestExceedsWriteCount)?;

    Ok(OcompOraclePreAdmissionProjection {
        profile_ready,
        auction_entry_prices,
        oracle_state_version: oracle.ocomp_state_version.read()?,
        wwd_pair_entries: oracle.pair_count.read()?,
        active_scurve_entries,
    })
}

/// Initializes the fixed Oracle projection on the fresh-devnet OCOMP fork.
///
/// The genesis-bound OCOMP lifecycle is the sole production caller. The
/// initialization is idempotent only when the configured pair and version
/// already match exactly.
pub fn initialize_fresh_ocomp_profile(storage: StorageHandle) -> Result<()> {
    let mut oracle = OracleContract::new(storage);
    oracle.initialize_fresh_ocomp_profile()
}

/// Stored WorldwideDay VWAP for the [`DAY_TYPE_PAIR`] (`COEN/840`), or `None`
/// when the pair is not registered or the day has no snapshot for it.
///
/// This is the single entry point for the day-rate decision: pair resolution and
/// the snapshot lookup live here, behind one typed interface, so callers never
/// touch the oracle's internal `pair_index` map. Genuine storage faults
/// propagate as `Err`, keeping "no data yet" (`Ok(None)` -> caller's RED fallback)
/// distinct from "oracle broken".
pub fn day_type_pair_vwap(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
) -> Result<Option<U256>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let index = oracle.pair_index_of(DAY_TYPE_PAIR)?;
    if index == 0 {
        return Ok(None);
    }
    oracle.get_worldwide_day_vwap_for_pair(worldwide_day, index)
}

/// Computes and stores the WorldwideDay VWAP snapshot for `[start_time,
/// end_time)`. Returns `true` if a snapshot was written, `false` if the window
/// held no oracle data (a deterministic no-op, not an error).
pub fn store_worldwide_day_vwap_snapshot(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
    start_time: u64,
    end_time: u64,
) -> Result<bool> {
    let mut oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.store_worldwide_day_vwap_snapshot(worldwide_day, start_time, end_time)
}

/// Finalized per-UTC-day VWAP for the [`DAY_TYPE_PAIR`] (`COEN/840`), or
/// `None` when the pair is not registered or the day has no finalized value.
pub fn day_type_pair_utc_vwap(storage: StorageHandle, utc_day: u32) -> Result<Option<U256>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let index = oracle.pair_index_of(DAY_TYPE_PAIR)?;
    if index == 0 {
        return Ok(None);
    }
    oracle.get_utc_day_vwap_for_pair(utc_day, index)
}

/// Returns the finalized VWAP for `pair` on the given UTC calendar day
/// (`utc_day` is a yyyymmdd UTC date key, e.g. `20260625`), or `None` if the
/// day is not finalized or had no oracle data for that pair. Distinguishing
/// "not finalized yet" from "finalized, no data" requires comparing `utc_day`
/// against the oracle's `utc_day_vwap_last_finalized` watermark.
pub fn get_utc_day_vwap(
    storage: StorageHandle,
    utc_day: u32,
    index: PairIndex,
) -> Result<Option<U256>> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.get_utc_day_vwap_for_pair(utc_day, index)
}

pub fn get_max_active_scurve_value(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
    pair: AddressPair,
) -> Result<U256> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    let scurve_timestamp = worldwide_day.to_timestamp_utc();
    scurve::get_max_active_scurve_value(&oracle, pair, scurve_timestamp)
}

/// Annualized policy rate (scale `1e6`) for an independently registered ISO
/// 4217 code. Called by the Credis Factory at issuance to pin the position's
/// settlement policy without coupling it to reference-currency membership.
pub fn get_policy_rate(storage: StorageHandle, iso_code: u16) -> Result<U256> {
    let oracle: OracleContract<'_> = OracleContract::new(storage);
    oracle.get_policy_rate(iso_code)
}
