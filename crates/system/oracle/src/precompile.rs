use crate::errors::OracleError;
use crate::schema::OracleContract;
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolEvent, SolInterface};
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::addresses::ORACLE_ADDRESS;
use outbe_primitives::dispatch::{dispatch_call, metadata, mutate_void, reject_value, view};
use outbe_primitives::error::Result;
use outbe_primitives::math::reference_price::pair_scales;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IOracle.sol"
);

/// Splits a pair list into the parallel `(bases, quotes)` columns the ABI
/// returns, preserving each pair's registered orientation so a caller can quote
/// the result straight back into the pair-scoped reads.
fn split_pairs(pairs: &[AddressPair]) -> (Vec<Address>, Vec<Address>) {
    pairs.iter().map(|p| (p.address1(), p.address2())).unzip()
}

/// Dispatches an ABI-encoded call to the Oracle precompile.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_call(data, IOracle::IOracleCalls::abi_decode, |call| {
        let mut oracle = OracleContract::new(storage);
        use IOracle::IOracleCalls::*;
        match call {
            getExchangeRate(c) => view(c, |c| oracle.get_exchange_rate(c.base, c.quote)),
            getExchangeRateData(c) => view(c, |c| {
                let (rate, block, ts) = oracle.get_exchange_rate_data(c.base, c.quote)?;
                Ok((rate, block, ts).into())
            }),
            getRudisExchangeRateFor(c) => view(c, |c| {
                let quote = crate::api::currency_address(c.isoCode);
                oracle.get_exchange_rate(crate::api::COEN_ASSET, quote)
            }),
            currencyCrossRate(c) => view(c, |c| {
                crate::api::currency_cross_rate(
                    oracle.storage.clone(),
                    c.fromIso,
                    c.toIso,
                    c.amount,
                )
            }),
            getVwap(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let now = oracle.storage.timestamp()?.to::<u64>();
                oracle.calculate_vwap_lookback(pair, now, c.lookbackSeconds)
            }),
            getParams(_) => metadata::<IOracle::getParamsCall>(|| {
                let vote_period = oracle.config_vote_period.read()?;
                let reward_band = oracle.config_reward_band.read()?;
                let slash_window = oracle.config_slash_window.read()?;
                let min_valid = oracle.config_min_valid_per_window.read()?;
                let slash_fraction = oracle.config_slash_fraction.read()?;
                let lookback = oracle.config_lookback_duration.read()?;
                let enabled = oracle.config_enabled.read()?;
                Ok((
                    vote_period,
                    reward_band,
                    slash_window,
                    min_valid,
                    slash_fraction,
                    lookback,
                    enabled,
                )
                    .into())
            }),
            getVotePenaltyCounter(c) => view(c, |c| {
                let success = oracle.penalty_success_count.read(&c.validator)?;
                let abstain = oracle.penalty_abstain_count.read(&c.validator)?;
                let miss = oracle.penalty_miss_count.read(&c.validator)?;
                Ok((success, abstain, miss).into())
            }),
            getFeederDelegation(c) => view(c, |c| oracle.get_feeder(&c.validator)),
            isVoteTarget(c) => view(c, |c| oracle.is_vote_target(c.base, c.quote)),
            getPairCount(_) => metadata::<IOracle::getPairCountCall>(|| oracle.pair_count.read()),
            getPairByIndex(c) => view(c, |c| {
                let pair = oracle.require_pair_at(c.index)?;
                let (base_scale, quote_scale) = pair_scales(pair);
                Ok((pair.address1(), pair.address2(), base_scale, quote_scale).into())
            }),
            getVoteTargets(_) => metadata::<IOracle::getVoteTargetsCall>(|| {
                let (bases, quotes) = oracle.get_vote_targets()?;
                Ok((bases, quotes).into())
            }),
            getAggregateVote(c) => view(c, |c| {
                let (exists, bases, quotes, rates, volumes) =
                    oracle.get_aggregate_vote(&c.validator)?;
                Ok((exists, bases, quotes, rates, volumes).into())
            }),
            getSlashWindowProgress(c) => view(c, |c| {
                let (success, abstain, miss, slash_window) =
                    oracle.get_slash_window_progress(&c.validator)?;
                Ok((success, abstain, miss, slash_window).into())
            }),
            getVwapForTimeRange(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                oracle.calculate_vwap(pair, c.startTime, c.endTime)
            }),
            getUtcDayVwap(c) => view(c, |c| {
                let index =
                    oracle.require_pair_index(AddressPair::from_addresses(c.base, c.quote))?;
                match oracle.get_utc_day_vwap_for_pair(c.utcDay, index)? {
                    Some(vwap) => Ok(vwap),
                    None => Err(OracleError::NoFinalizedUtcDayVwap.into()),
                }
            }),
            getScurveValue(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                crate::scurve::get_max_active_scurve_value(&oracle, pair, c.timestamp)
            }),
            setExchangeRate(c) => {
                reject_value(&value)?;
                let base = c.base;
                let quote = c.quote;
                let rate = c.rate;
                mutate_void(c, caller, |sender, c| {
                    // block_number and timestamp are not available in precompile context.
                    // Use 0 for bootstrap writes - tally will overwrite with real values.
                    oracle.set_exchange_rate(
                        sender,
                        AddressPair::from_addresses(c.base, c.quote),
                        c.rate,
                        0,
                        0,
                    )?;
                    let event = IOracle::ExchangeRateSet { base, quote, rate };
                    let _ = oracle
                        .storage
                        .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    Ok(())
                })
            }
            delegateFeederConsent(c) => {
                reject_value(&value)?;
                let feeder = c.feeder;
                mutate_void(c, caller, |sender, c| {
                    oracle.delegate_feeder(sender, c.feeder)?;
                    let event = IOracle::FeederDelegated {
                        validator: sender,
                        feeder,
                    };
                    let _ = oracle
                        .storage
                        .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    Ok(())
                })
            }
            deactivateVoteTarget(c) => {
                reject_value(&value)?;
                let base = c.base;
                let quote = c.quote;
                mutate_void(c, caller, |sender, c| {
                    oracle.deactivate_vote_target(sender, c.base, c.quote)?;
                    let event = IOracle::VoteTargetDeactivated { base, quote };
                    let _ = oracle
                        .storage
                        .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    Ok(())
                })
            }
            activateVoteTarget(c) => {
                reject_value(&value)?;
                let base = c.base;
                let quote = c.quote;
                mutate_void(c, caller, |sender, c| {
                    oracle.activate_vote_target(sender, c.base, c.quote)?;
                    let event = IOracle::VoteTargetActivated { base, quote };
                    let _ = oracle
                        .storage
                        .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    Ok(())
                })
            }
            getPriceSnapshotHistory(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let (timestamps, rates, volumes) =
                    oracle.get_price_snapshot_history(pair, c.count)?;
                Ok(IOracle::getPriceSnapshotHistoryReturn {
                    timestamps,
                    rates,
                    volumes,
                })
            }),
            getAllPriceSnapshotHistory(c) => view(c, |c| {
                let (snapshot_ids, timestamps, bases, quotes, rates, volumes) =
                    oracle.get_all_price_snapshot_history(c.count)?;
                Ok(IOracle::getAllPriceSnapshotHistoryReturn {
                    snapshotIds: snapshot_ids,
                    timestamps,
                    bases,
                    quotes,
                    rates,
                    volumes,
                })
            }),
            getTwap(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let now = oracle.storage.timestamp()?.to::<u64>();
                oracle.calculate_twap(pair, now, c.lookbackSeconds)
            }),
            getTwaps(c) => view(c, |c| {
                let now = oracle.storage.timestamp()?.to::<u64>();
                let (pairs, twaps, lookbacks) = oracle.calculate_twaps(now, c.lookback)?;
                let (bases, quotes) = split_pairs(&pairs);
                Ok(IOracle::getTwapsReturn {
                    bases,
                    quotes,
                    twaps,
                    lookbackSeconds: lookbacks,
                })
            }),
            getDayVwap(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let now = oracle.storage.timestamp()?.to::<u64>();
                oracle.calculate_vwap_lookback(pair, now, 86400)
            }),
            getWorldwideDayVwap(c) => view(c, |c| {
                let (pairs, vwaps, lookbacks) = oracle.calculate_vwaps(c.startTime, c.endTime)?;
                let (bases, quotes) = split_pairs(&pairs);
                Ok(IOracle::getWorldwideDayVwapReturn {
                    bases,
                    quotes,
                    vwaps,
                    lookbackSeconds: lookbacks,
                })
            }),
            getWorldwideDayVwapSnapshot(c) => view(c, |c| {
                let (start_time, end_time, bases, quotes, vwaps, lookbacks) =
                    oracle.get_worldwide_day_vwap_snapshot(c.worldwideDay.into())?;
                Ok(IOracle::getWorldwideDayVwapSnapshotReturn {
                    startTime: start_time,
                    endTime: end_time,
                    bases,
                    quotes,
                    vwaps,
                    lookbackSeconds: lookbacks,
                })
            }),
            getScurveEntries(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let now = oracle.storage.timestamp()?.to::<u64>();
                let (peak_days, peak_prices, current_values) =
                    crate::scurve::get_scurve_entries(&oracle, pair, now)?;
                Ok(IOracle::getScurveEntriesReturn {
                    peakDays: peak_days,
                    peakPrices: peak_prices,
                    currentValues: current_values,
                })
            }),
            getScurveValues(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let target_day = crate::scurve::truncate_to_day(c.timestamp);
                let (peak_days, peak_prices, values) =
                    crate::scurve::get_scurve_entries(&oracle, pair, c.timestamp)?;
                Ok(IOracle::getScurveValuesReturn {
                    targetDay: target_day,
                    peakDays: peak_days,
                    peakPrices: peak_prices,
                    values,
                })
            }),
            getAllScurveData(_) => metadata::<IOracle::getAllScurveDataCall>(|| {
                let (bases, quotes, peak_days, peak_prices) =
                    crate::scurve::get_all_scurve_data(&oracle)?;
                Ok(IOracle::getAllScurveDataReturn {
                    bases,
                    quotes,
                    peakDays: peak_days,
                    peakPrices: peak_prices,
                })
            }),
            getAllScurveDataForPair(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let (peak_days, peak_prices) =
                    crate::scurve::get_all_scurve_data_for_pair(&oracle, pair)?;
                Ok(IOracle::getAllScurveDataForPairReturn {
                    peakDays: peak_days,
                    peakPrices: peak_prices,
                })
            }),
            getReferenceCurrencies(_) => metadata::<IOracle::getReferenceCurrenciesCall>(|| {
                oracle.reference_currencies.read_all()
            }),
            getPolicyRateCurrencies(_) => metadata::<IOracle::getPolicyRateCurrenciesCall>(|| {
                oracle.policy_rate_currencies.read_all()
            }),
            getPolicyRate(c) => view(c, |c| oracle.get_policy_rate(c.isoCode)),
            getNominalPrice(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let (nominal, _, _, _) = oracle.get_nominal_price_components(pair, c.timestamp)?;
                Ok(nominal)
            }),
            getNominalPriceComponents(c) => view(c, |c| {
                let pair = oracle.require_pair_from(c.base, c.quote)?;
                let (nominal_price, vwap, max_scurve, source) =
                    oracle.get_nominal_price_components(pair, c.timestamp)?;
                Ok(IOracle::getNominalPriceComponentsReturn {
                    nominalPrice: nominal_price,
                    vwap,
                    maxScurve: max_scurve,
                    source,
                })
            }),
            submitVote(c) => {
                reject_value(&value)?;
                let tuple_count = c.tuples.len() as u32;
                mutate_void(c, caller, |sender, c| {
                    let tuples: Vec<_> = c
                        .tuples
                        .iter()
                        .map(|t| (t.base, t.quote, t.exchangeRate, t.volume))
                        .collect();
                    let validator = oracle.submit_vote(sender, &tuples)?;
                    // Emit event after successful vote
                    let event = IOracle::VoteSubmitted {
                        validator,
                        tupleCount: tuple_count,
                    };
                    let _ = oracle
                        .storage
                        .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    Ok(())
                })
            }
        }
    })
}
