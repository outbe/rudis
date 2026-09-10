//! Private outer-WWD lifecycle transitions and their ordered effects.

use alloy_primitives::U256;
use outbe_compressed_entities::ExecutionScope;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{block::BlockRuntimeContext, error::Result};
use outbe_promislimit::PromisLimitContract;
use outbe_tribute::TributeContract;

use crate::{
    aggregate::{ValidatedWwdAggregate, WwdDayType, WwdProjection},
    commit::{
        commit_new_wwd, commit_outer_transition, commit_outer_transition_with_rate, NewWwdSchedule,
        WwdRateResolution,
    },
    constants::*,
    ocomp::schema::require_active_ocomp_profile,
    precompile::IMetadosis,
    reducer::{
        reduce_outer_wwd, OuterWwdEvent, OuterWwdTransition, OuterWwdTransitionKind, WwdAdvanceEdge,
    },
    schema::{MetadosisContract, WorldwideDayEntryExt},
    terminal::{CapacityForfeitureReceipt, MissedOfferingReceipt},
};

pub(crate) fn validate_metadosis_timestamp(timestamp: u64) -> Result<()> {
    timestamp
        .checked_add(outbe_primitives::time::UTC_PLUS_14_OFFSET)
        .ok_or_else(|| crate::errors::caller_rejection("Metadosis UTC+14 timestamp overflow"))?;
    Ok(())
}

pub(crate) fn advance_active_worldwide_days(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
) -> Result<()> {
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    require_active_ocomp_profile(&metadosis)?;
    let aggregate = ValidatedWwdAggregate::load_and_validate(ctx.storage.clone())?;
    let retained_count = aggregate.retained_count();
    let mut admission_consumed = false;
    for current in aggregate.active_records() {
        let transition = reduce_outer_wwd(
            Some(current),
            OuterWwdEvent::AdvanceDue {
                block_time: ctx.block.timestamp,
                retained_count,
                admission_available: !admission_consumed,
            },
        )?;
        match transition.kind() {
            OuterWwdTransitionKind::Noop => {}
            OuterWwdTransitionKind::MissedOffering => {
                apply_missed_offering(&mut metadosis, ctx, scope, current, &transition)?;
            }
            OuterWwdTransitionKind::Advance(edges) => {
                let rate_resolution = apply_wwd_advance_edges(
                    &mut metadosis,
                    current.worldwide_day,
                    edges,
                    "outer advance resolved one WWD rate more than once",
                )?;
                commit_outer_transition_with_rate(
                    &mut metadosis,
                    current.worldwide_day,
                    &transition,
                    ctx.block.block_number,
                    rate_resolution,
                )?;
                if edges.last() == Some(&WwdAdvanceEdge::BecomeReady) {
                    admission_consumed = true;
                }
            }
            OuterWwdTransitionKind::CapacityForfeiture { preceding_edges } => {
                aggregate.validate_capacity_victim(current)?;
                let rate_resolution = apply_wwd_advance_edges(
                    &mut metadosis,
                    current.worldwide_day,
                    preceding_edges,
                    "capacity forfeiture resolved one WWD rate more than once",
                )?;
                apply_capacity_forfeiture(
                    &mut metadosis,
                    ctx,
                    scope,
                    current,
                    retained_count,
                    &transition,
                    rate_resolution,
                )?;
                admission_consumed = true;
            }
            unexpected => {
                return Err(crate::errors::storage_corruption(format!(
                    "AdvanceDue produced non-Cycle transition {unexpected:?}"
                )));
            }
        }
    }
    Ok(())
}

fn apply_wwd_advance_edges(
    metadosis: &mut MetadosisContract<'_>,
    wwd: WorldwideDay,
    edges: &[WwdAdvanceEdge],
    duplicate_resolution_message: &'static str,
) -> Result<Option<WwdRateResolution>> {
    let mut rate_resolution = None;
    for edge in edges {
        let edge_resolution = apply_wwd_advance_edge_effect(metadosis, wwd, *edge)?;
        if let Some(resolution) = edge_resolution {
            if rate_resolution.replace(resolution).is_some() {
                return Err(crate::errors::storage_corruption(
                    duplicate_resolution_message.into(),
                ));
            }
        }
    }
    Ok(rate_resolution)
}

pub(crate) fn init_genesis_day(ctx: &BlockRuntimeContext) -> Result<()> {
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    require_active_ocomp_profile(&metadosis)?;
    init_genesis_day_inner(&mut metadosis, ctx)
}

pub(crate) fn init_genesis_day_inner(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
) -> Result<()> {
    initialize_bootstrap_if_needed(metadosis, ctx)?;
    create_initial_worldwide_day_if_needed(metadosis, ctx, ctx.block.timestamp)
}

fn initialize_bootstrap_if_needed(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
) -> Result<()> {
    if metadosis.get_bootstrap_end_time()? == 0 {
        let duration = outbe_chain_constants::get_metadosis_bootstrap_duration_seconds();
        let end_time = ctx.block.timestamp.checked_add(duration).ok_or_else(|| {
            crate::errors::caller_rejection("Metadosis bootstrap end timestamp overflow")
        })?;
        metadosis.set_bootstrap_end_time(end_time)?;
    }
    Ok(())
}

fn create_initial_worldwide_day_if_needed(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
    timestamp: u64,
) -> Result<()> {
    if !metadosis.active_wwd.is_empty()? {
        return Ok(());
    }
    create_worldwide_day_if_needed(metadosis, ctx, timestamp)
}

pub(crate) fn create_worldwide_day_if_needed(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
    timestamp: u64,
) -> Result<()> {
    validate_metadosis_timestamp(timestamp)?;
    let wwd = WorldwideDay::from_timestamp(timestamp);
    create_worldwide_day_for_date(metadosis, ctx, wwd)
}

pub(crate) fn create_worldwide_day_for_date(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
    wwd: WorldwideDay,
) -> Result<()> {
    let aggregate = ValidatedWwdAggregate::load_and_validate(metadosis.storage.clone())?;
    let existing_forming_start = metadosis.worldwide_days.entry(wwd).forming_start().read()?;
    if existing_forming_start != 0 {
        let current = aggregate.record(wwd).ok_or_else(|| {
            crate::errors::storage_corruption(format!(
                "Metadosis WWD {wwd} record exists outside validated membership"
            ))
        })?;
        let transition = reduce_outer_wwd(Some(current), OuterWwdEvent::CreateDay)?;
        return commit_outer_transition(metadosis, wwd, &transition, ctx.block.block_number);
    }

    aggregate.ensure_can_insert_active(wwd)?;
    let forming_start = wwd.start_timestamp();
    let transition = reduce_outer_wwd(None, OuterWwdEvent::CreateDay)?;
    commit_new_wwd(
        metadosis,
        wwd,
        NewWwdSchedule {
            forming_start,
            forming_period_seconds: outbe_chain_constants::get_metadosis_forming_period_seconds(),
            lookback_delay_seconds: outbe_chain_constants::get_metadosis_lookback_delay_seconds(),
            offering_period_seconds: outbe_chain_constants::get_metadosis_offering_period_seconds(),
            waiting_period_seconds: outbe_chain_constants::get_metadosis_waiting_period_seconds(),
        },
        &transition,
    )
}

fn apply_wwd_advance_edge_effect(
    metadosis: &mut MetadosisContract<'_>,
    wwd: WorldwideDay,
    edge: WwdAdvanceEdge,
) -> Result<Option<WwdRateResolution>> {
    match edge {
        WwdAdvanceEdge::ResolveForming => {
            store_worldwide_day_vwap_snapshot(metadosis, wwd)?;
            Ok(Some(resolve_day_rate(metadosis, wwd)?))
        }
        WwdAdvanceEdge::OpenOffering => {
            TributeContract::new(metadosis.storage.clone()).unseal_day(wwd)?;
            Ok(None)
        }
        WwdAdvanceEdge::CloseOffering => {
            TributeContract::new(metadosis.storage.clone()).seal_day(wwd)?;
            Ok(None)
        }
        WwdAdvanceEdge::BecomeReady => Ok(None),
    }
}

fn apply_capacity_forfeiture(
    metadosis: &mut MetadosisContract<'_>,
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
    current: &WwdProjection,
    retained_count: usize,
    transition: &OuterWwdTransition,
    rate_resolution: Option<WwdRateResolution>,
) -> Result<()> {
    if retained_count != MAX_RETAINED_WWDS {
        return Err(crate::errors::storage_corruption(
            "CapacityForfeiture requires the exact retained admission cap".into(),
        ));
    }
    if !metadosis
        .ocomp_fsm_states
        .get_bytes(&current.worldwide_day)
        .is_empty()?
    {
        return Err(crate::errors::storage_corruption(
            "CapacityForfeiture victim already has OCOMP state".into(),
        ));
    }
    if metadosis
        .read_capacity_forfeiture_receipt(current.worldwide_day)?
        .is_some()
    {
        return Err(crate::errors::storage_corruption(
            "active CapacityForfeiture victim already has a receipt".into(),
        ));
    }
    // A day limit is written only together with its formation, so an absent
    // formation must mean an untouched limit; anything else is real corruption.
    match metadosis.ocomp_day_limit_formation(current.worldwide_day)? {
        Some(formation) if formation.day_limit == current.metadosis_limit_amount => {}
        Some(_) => {
            return Err(crate::errors::storage_corruption(
                "CapacityForfeiture formed day limit does not match WWD state".into(),
            ));
        }
        None if current.metadosis_limit_amount.is_zero() => {}
        None => {
            return Err(crate::errors::storage_corruption(
                "CapacityForfeiture has a day limit with no formation".into(),
            ));
        }
    }

    let max_retained_wwds = u32::try_from(MAX_RETAINED_WWDS)
        .map_err(|_| crate::errors::storage_corruption("retained WWD cap exceeds u32".into()))?;
    let retained_count_before = u32::try_from(retained_count)
        .map_err(|_| crate::errors::storage_corruption("retained WWD count exceeds u32".into()))?;
    let storage = metadosis.storage.clone();
    let result = (|| {
        let tribute = TributeContract::new(storage.clone())
            .forfeit_sealed_partition(scope, current.worldwide_day)?;
        let credit = PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(current.metadosis_limit_amount)?;
        let receipt = CapacityForfeitureReceipt {
            worldwide_day: current.worldwide_day,
            max_retained_wwds,
            retained_count_before,
            value_routed: credit.credited,
            carry_over_before: credit.before,
            carry_over_after: credit.after,
            sealed_collection_root: tribute.sealed_root,
            forfeited_count: tribute.forfeited_count,
            forfeited_nominal: tribute.forfeited_nominal,
            source_generation: tribute.source_generation,
            retired_generation: tribute.retired_generation,
            retirement: tribute.retirement_outcome,
            block_number: ctx.block.block_number,
        };
        metadosis.write_capacity_forfeiture_receipt(receipt)?;
        commit_outer_transition_with_rate(
            metadosis,
            current.worldwide_day,
            transition,
            ctx.block.block_number,
            rate_resolution,
        )?;
        metadosis.emit(IMetadosis::WorldwideDayCapacityForfeited {
            worldwideDay: current.worldwide_day.into(),
            maxRetainedWorldwideDays: max_retained_wwds,
            retainedCountBefore: retained_count_before,
            dayMetadosisLimit: receipt.value_routed,
            carryOverBefore: receipt.carry_over_before,
            carryOverAfter: receipt.carry_over_after,
            sealedCollectionRoot: receipt.sealed_collection_root,
            forfeitedTributeCount: receipt.forfeited_count,
            forfeitedTributeNominal: receipt.forfeited_nominal,
            sourceGeneration: receipt.source_generation,
            retiredGeneration: receipt.retired_generation,
            retirementOutcome: match receipt.retirement {
                outbe_compressed_entities::RetirementOutcome::NotPresent => 1,
                outbe_compressed_entities::RetirementOutcome::Requested => 2,
            },
            blockNumber: receipt.block_number,
        })
    })();
    result
}

fn apply_missed_offering(
    metadosis: &mut MetadosisContract<'_>,
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
    current: &WwdProjection,
    transition: &OuterWwdTransition,
) -> Result<()> {
    // A day limit is written only together with its formation, so an absent
    // formation must mean an untouched limit; anything else is real corruption.
    match metadosis.ocomp_day_limit_formation(current.worldwide_day)? {
        Some(formation) if formation.day_limit == current.metadosis_limit_amount => {}
        Some(_) => {
            return Err(crate::errors::storage_corruption(
                "MissedOffering formed day limit does not match WWD state".into(),
            ));
        }
        None if current.metadosis_limit_amount.is_zero() => {}
        None => {
            return Err(crate::errors::storage_corruption(
                "MissedOffering has a day limit with no formation".into(),
            ));
        }
    }
    if metadosis
        .read_missed_offering_receipt(current.worldwide_day)?
        .is_some()
    {
        return Err(crate::errors::storage_corruption(
            "active WWD already has a terminal receipt".into(),
        ));
    }

    let storage = metadosis.storage.clone();
    let result = (|| {
        let credit = PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(current.metadosis_limit_amount)?;
        let retirement = TributeContract::new(storage.clone())
            .retire_empty_missed_offering_partition(scope, current.worldwide_day)?;
        let receipt = MissedOfferingReceipt {
            worldwide_day: current.worldwide_day,
            value_routed: credit.credited,
            carry_over_before: credit.before,
            carry_over_after: credit.after,
            retirement,
            block_number: ctx.block.block_number,
        };
        metadosis.write_missed_offering_receipt(receipt)?;
        commit_outer_transition(
            metadosis,
            current.worldwide_day,
            transition,
            ctx.block.block_number,
        )?;
        metadosis.emit(IMetadosis::WorldwideDayMissedOffering {
            worldwideDay: current.worldwide_day.into(),
            dayMetadosisLimit: receipt.value_routed,
            carryOverBefore: receipt.carry_over_before,
            carryOverAfter: receipt.carry_over_after,
            retirementOutcome: match retirement {
                outbe_compressed_entities::RetirementOutcome::NotPresent => 1,
                outbe_compressed_entities::RetirementOutcome::Requested => 2,
            },
            blockNumber: receipt.block_number,
        })?;
        Ok(())
    })();
    result
}

fn store_worldwide_day_vwap_snapshot(
    metadosis: &mut MetadosisContract,
    wwd: WorldwideDay,
) -> Result<()> {
    let forming_start = metadosis.worldwide_days.entry(wwd).forming_start().read()?;
    let forming_end = metadosis.worldwide_days.entry(wwd).forming_end().read()?;
    outbe_oracle::api::store_worldwide_day_vwap_snapshot(
        metadosis.storage.clone(),
        wwd,
        forming_start,
        forming_end,
    )?;
    Ok(())
}

fn resolve_day_rate(metadosis: &MetadosisContract, wwd: WorldwideDay) -> Result<WwdRateResolution> {
    let current_vwap = outbe_oracle::api::day_type_pair_vwap(metadosis.storage.clone(), wwd)?
        .unwrap_or(U256::ZERO);
    let previous_vwap = if current_vwap.is_zero() {
        U256::ZERO
    } else {
        outbe_oracle::api::day_type_pair_vwap(metadosis.storage.clone(), wwd.previous_date_key())?
            .unwrap_or(U256::ZERO)
    };
    Ok(WwdRateResolution {
        previous_vwap,
        current_vwap,
        day_type: determine_day_type(previous_vwap, current_vwap),
    })
}

fn determine_day_type(previous_vwap: U256, current_vwap: U256) -> WwdDayType {
    if previous_vwap.is_zero() || current_vwap.is_zero() {
        return WwdDayType::Red;
    }
    if current_vwap > previous_vwap {
        WwdDayType::Green
    } else {
        WwdDayType::Red
    }
}
