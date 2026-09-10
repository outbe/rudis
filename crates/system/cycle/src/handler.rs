//! ProtocolCycle calendar orchestration and completed-day emission settlement.
//!
//! This is the natural home of the `Cycle -> EmissionLimit -> AgentReward
//! -> Rewards -> Metadosis` orchestration. Putting
//! it inside `outbe-cycle` (rather than `outbe-emissionlimit`) avoids
//! a `outbe-emissionlimit -> outbe-rewards` dependency edge, which
//! would close the cycle with the existing
//! `outbe-rewards -> outbe-emissionlimit` re-export.

use alloy_primitives::U256;

use outbe_compressed_entities::{ExecutionScope, ParentBodySource};
use outbe_emissionlimit::{
    allocation::{allocate_emission, EmissionSinkId},
    block::dispatch_terminal_remainder_at,
    day_emission::day_emission_limit,
};
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
    time::{date_key_to_utc_timestamp, next_date_key, timestamp_to_date_key},
    units::{checked_protocol_to_native, native_to_protocol_floor},
};

/// Calendar work owned by one hourly ProtocolCycle execution.
///
/// This is intentionally not persisted or exposed through the EVM ABI. It is
/// shared with the executor so command authority is derived from exactly the
/// same calendar decision as the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolDayAction {
    SameDay,
    SettlePrevious { day: u32 },
    SkipMissed { from: u32, to: u32 },
}

/// Selects the daily action for an hourly ProtocolCycle execution.
///
/// Only a contiguous UTC-day transition is settled. If the chain advances by
/// more than one calendar day, every completed day in that gap is deliberately
/// forfeited: no economic state is synthesized after the halt.
pub fn protocol_day_action(active_utc_day: u32, block_utc_day: u32) -> Result<ProtocolDayAction> {
    let valid_date_key = |date_key: u32| {
        let year = date_key / 10_000;
        let month = (date_key / 100) % 100;
        let day = date_key % 100;
        year >= 1970
            && (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && timestamp_to_date_key(date_key_to_utc_timestamp(date_key)) == date_key
    };
    if !valid_date_key(active_utc_day) || !valid_date_key(block_utc_day) {
        return Err(PrecompileError::Fatal(format!(
            "ProtocolCycle received invalid UTC day: active={active_utc_day}, block={block_utc_day}"
        )));
    }
    if active_utc_day > block_utc_day {
        return Err(PrecompileError::Fatal(format!(
            "ProtocolCycle active UTC day {active_utc_day} is after block UTC day {block_utc_day}"
        )));
    }

    if active_utc_day == block_utc_day {
        return Ok(ProtocolDayAction::SameDay);
    }
    if next_date_key(active_utc_day) == block_utc_day {
        return Ok(ProtocolDayAction::SettlePrevious {
            day: active_utc_day,
        });
    }
    Ok(ProtocolDayAction::SkipMissed {
        from: active_utc_day,
        to: block_utc_day,
    })
}

fn gas(ctx: &BlockRuntimeContext) -> u64 {
    ctx.storage.gas_used().unwrap_or(0)
}

/// Applies raw 18-decimal gas fees to a six-decimal validator emission budget,
/// then floors only the remaining native amount back to Gem-load precision.
fn validator_gem_topup_protocol(validator_amount: U256, fees_native: U256) -> Result<U256> {
    let native_budget = checked_protocol_to_native(validator_amount)
        .ok_or_else(|| PrecompileError::Revert("native validator budget overflow".into()))?;
    Ok(native_to_protocol_floor(
        native_budget.saturating_sub(fees_native),
    ))
}

fn wrap(step: &str, r: Result<()>) -> Result<()> {
    r.map_err(|e| {
        let bt = std::backtrace::Backtrace::force_capture();
        tracing::error!(target: "outbe::cycle", step, error = ?e, backtrace = %bt, "emission_limit_daily step failed");
        e
    })
}

/// Settles one explicitly owned, completed UTC day. Calendar selection belongs
/// to [`run_protocol_cycle`]; this function only performs the existing daily
/// economic calculation and commits its idempotency pair.
pub fn settle_emission_day(ctx: &BlockRuntimeContext, prev_day: u32) -> Result<()> {
    let block_ts = ctx.block.timestamp;
    let current_day = timestamp_to_date_key(block_ts);

    if !outbe_rewards::api::day_participation_complete(ctx, prev_day)? {
        return Err(PrecompileError::Fatal(
            "Cycle settlement before reward participation windows close".into(),
        ));
    }

    // idempotency guard. This handler issues the CCA agent pool
    // and re-dispatches terminal Metadosis with no PER-MINT day guard (only the
    // validator topup is independently idempotent via `daily_topup_settled`), so
    // a second invocation for an already-settled `prev_day` would double-mint
    // those pools. That re-fire is reachable whenever more than one CycleTick
    // resolves the same `prev_day` (e.g. several blocks within one UTC day after
    // a forward timestamp advance - bounded but not eliminated by the C-01 drift
    // band). Gate the WHOLE settlement on `daily_settled[prev_day]` so each day
    // settles exactly once regardless of how many times the handler fires.
    let settled = outbe_rewards::api::is_day_settled(ctx, prev_day).map_err(|e| {
        tracing::error!(target: "outbe::cycle", step = "is_day_settled", prev_day, error = ?e, "emission_limit_daily step failed");
        e
    })?;
    let existing_formation =
        outbe_metadosis::api::day_limit_formation_receipt(ctx.storage.clone(), prev_day.into())?;
    match (settled, existing_formation) {
        (true, None) => {
            return Err(PrecompileError::Fatal(
                "Cycle daily_settled marker has no Metadosis day-limit semantic receipt".into(),
            ));
        }
        (false, Some(_)) => {
            return Err(PrecompileError::Fatal(
                "Metadosis day-limit semantic receipt has no Cycle daily_settled marker".into(),
            ));
        }
        (true, Some(_)) => {
            tracing::debug!(
                target: "outbe::cycle",
                prev_day,
                block_number = ctx.block.block_number,
                "emission_limit_daily: prev_day already settled - skipping (idempotent)"
            );
            return Ok(());
        }
        (false, None) => {}
    }

    let genesis = outbe_rewards::runtime::genesis_utc_day(ctx).unwrap_or(0);
    tracing::info!(
        target: "outbe::cycle",
        block_ts,
        current_day,
        prev_day,
        genesis_utc_day = genesis,
        block_number = ctx.block.block_number,
        "emission_limit_daily dates"
    );

    let g0 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", gas_used = g0, prev_day, block_ts, "entry");

    let day_number = outbe_rewards::runtime::day_number_since_genesis(ctx, prev_day)
        .map_err(|e| {
            tracing::error!(target: "outbe::cycle", step = "day_number_since_genesis", prev_day, error = ?e, "emission_limit_daily step failed");
            let _bt = std::backtrace::Backtrace::force_capture();
            tracing::error!(target: "outbe::cycle", backtrace = %_bt, "stacktrace");
            e
        })?;

    let cap = day_emission_limit(day_number);
    if cap.is_zero() {
        return Ok(());
    }

    let allocations = allocate_emission(cap)?;
    let amount_for = |id: EmissionSinkId| -> U256 {
        allocations
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.amount)
            .unwrap_or(U256::ZERO)
    };
    let validator_amount = amount_for(EmissionSinkId::Validator);
    let waa_amount = amount_for(EmissionSinkId::Waa);
    let sra_amount = amount_for(EmissionSinkId::Sra);
    let cca_amount = amount_for(EmissionSinkId::Cca);
    let metadosis_amount = amount_for(EmissionSinkId::Metadosis);

    let g1 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", step_gas = g1 - g0, cumulative = g1, "after allocate_emission");

    let fees = outbe_rewards::api::read_daily_fee_sum_raw(ctx, prev_day)
        .map_err(|e| {
            tracing::error!(target: "outbe::cycle", step = "read_daily_fee_sum_raw", error = ?e, "emission_limit_daily step failed");
            let _bt = std::backtrace::Backtrace::force_capture();
            tracing::error!(target: "outbe::cycle", backtrace = %_bt, "stacktrace");
            e
        })?;
    let voters = outbe_rewards::api::read_voters_for_day(ctx, prev_day)
        .map_err(|e| {
            tracing::error!(target: "outbe::cycle", step = "read_voters_for_day", error = ?e, "emission_limit_daily step failed");
            let _bt = std::backtrace::Backtrace::force_capture();
            tracing::error!(target: "outbe::cycle", backtrace = %_bt, "stacktrace");
            e
        })?;
    let topup = if validator_amount.is_zero() || voters.is_empty() {
        U256::ZERO
    } else {
        validator_gem_topup_protocol(validator_amount, fees)?
    };
    let preparation = outbe_rewards::api::prepare_daily_validator_gem_batch(
        ctx, prev_day, topup, &voters,
    )
    .map_err(|e| {
        tracing::error!(target: "outbe::cycle", step = "prepare_daily_validator_gem_batch", error = ?e, "emission_limit_daily step failed");
        e
    })?;
    let planned_promis_load_amount = match preparation {
        outbe_rewards::api::RewardGemPreparationOutcome::Prepared(batch)
        | outbe_rewards::api::RewardGemPreparationOutcome::AlreadyPrepared(batch)
        | outbe_rewards::api::RewardGemPreparationOutcome::NoPayableShares(batch) => {
            batch.planned_promis_load_amount
        }
    };
    let validator_excess = validator_amount
        .checked_sub(planned_promis_load_amount)
        .ok_or_else(|| {
            PrecompileError::Revert("validator reward Gem plan exceeds allocation".into())
        })?;

    let g2 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", step_gas = g2 - g1, cumulative = g2, voters = voters.len(), "after validator pool");

    use outbe_agentreward::distribution::{distribute_daily, PoolKind};
    let agent_excess = distribute_daily(
        ctx,
        prev_day.into(),
        &[
            (PoolKind::Waa, waa_amount),
            (PoolKind::Sra, sra_amount),
            (PoolKind::Cca, cca_amount),
        ],
    )
    .map_err(|e| {
        tracing::error!(target: "outbe::cycle", step = "distribute_daily", error = ?e, "emission_limit_daily step failed");
        e
    })?;

    let g3 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", step_gas = g3 - g2, cumulative = g3, "after agent distribute");

    let metadosis_total = metadosis_amount
        .checked_add(validator_excess)
        .and_then(|v| v.checked_add(agent_excess))
        .ok_or_else(|| PrecompileError::Revert("metadosis terminal overflow".into()))?;
    let prev_day_ts = date_key_to_utc_timestamp(prev_day);
    wrap(
        "dispatch_terminal_remainder_at",
        dispatch_terminal_remainder_at(ctx, metadosis_total, prev_day_ts),
    )?;
    let formation =
        outbe_metadosis::api::day_limit_formation_receipt(ctx.storage.clone(), prev_day.into())?
            .ok_or_else(|| {
                PrecompileError::Fatal(
                    "Cycle allocation committed without a Metadosis day-limit receipt".into(),
                )
            })?;
    match formation {
        outbe_metadosis::DayLimitFormationReceipt::Formed(formed)
            if formed.worldwide_day.value() == prev_day && formed.base_limit == metadosis_total => {
        }
        outbe_metadosis::DayLimitFormationReceipt::Formed(_) => {
            return Err(PrecompileError::Fatal(
                "Cycle allocation disagrees with the Metadosis day-limit receipt".into(),
            ));
        }
    }

    let g4 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", step_gas = g4 - g3, cumulative = g4, "after terminal dispatch");

    wrap(
        "mark_day_settled",
        outbe_rewards::api::mark_day_settled(ctx, prev_day),
    )?;

    let g5 = gas(ctx);
    tracing::debug!(target: "outbe::cycle::gas", step_gas = g5 - g4, cumulative = g5, total = g5 - g0, "completed");

    tracing::info!(
        target: "outbe::cycle",
        prev_day,
        day_number,
        cap = %cap,
        validator_amount = %validator_amount,
        validator_excess = %validator_excess,
        agent_excess = %agent_excess,
        metadosis_total = %metadosis_total,
        total_gas = g5 - g0,
        "emission_limit_daily handler completed"
    );

    Ok(())
}

/// Runs the single hourly protocol orchestration entry point.
///
/// A contiguous completed UTC day is settled before the existing Metadosis
/// command runs. Multi-day gaps are forfeited and advance the calendar cursor
/// without synthesizing economic state. The existing command then runs exactly
/// once to create the current WWD, advance every active WWD, and process at most
/// one READY WWD.
pub fn run_protocol_cycle(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<()> {
    let block_utc_day = timestamp_to_date_key(ctx.block.timestamp);
    let cycle: crate::schema::Cycle<'_> = ctx.storage.contract::<crate::schema::Cycle<'_>>();
    let active_utc_day = cycle.active_utc_day.read()?;
    if active_utc_day == 0 {
        return Err(PrecompileError::Fatal(
            "ProtocolCycle active UTC day is not initialized in genesis".into(),
        ));
    }

    let day_action = protocol_day_action(active_utc_day, block_utc_day)?;
    match day_action {
        ProtocolDayAction::SameDay => {}
        ProtocolDayAction::SettlePrevious { day } => {
            settle_emission_day(ctx, day)?;
            cycle.active_utc_day.write(block_utc_day)?;
        }
        ProtocolDayAction::SkipMissed { from, to } => {
            cycle.active_utc_day.write(block_utc_day)?;
            tracing::warn!(
                target: "outbe::cycle",
                block_number = ctx.block.block_number,
                block_timestamp = ctx.block.timestamp,
                skipped_from_utc_day = from,
                current_utc_day = to,
                "protocol cycle forfeited missed UTC days after a multi-day chain halt"
            );
        }
    }

    wrap(
        "start_metadosis",
        outbe_metadosis::commands::start_metadosis(ctx, scope, parent),
    )?;

    tracing::info!(
        target: "outbe::cycle",
        block_number = ctx.block.block_number,
        block_timestamp = ctx.block.timestamp,
        active_utc_day,
        block_utc_day,
        day_action = ?day_action,
        "protocol cycle completed"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn run_emission_limit_daily(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<()> {
    settle_emission_day(
        ctx,
        outbe_primitives::time::previous_date_key(timestamp_to_date_key(ctx.block.timestamp)),
    )?;
    outbe_metadosis::commands::start_metadosis(ctx, scope, parent)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use outbe_primitives::units::NATIVE_UNITS_PER_PROTOCOL_UNIT;

    #[test]
    fn validator_fees_stay_native_until_the_remaining_budget_is_floored() {
        let allocation = U256::from(2u64);
        let one_protocol_unit_native = NATIVE_UNITS_PER_PROTOCOL_UNIT;

        assert_eq!(
            validator_gem_topup_protocol(allocation, one_protocol_unit_native - U256::ONE).unwrap(),
            U256::ONE
        );
        assert_eq!(
            validator_gem_topup_protocol(allocation, one_protocol_unit_native + U256::ONE).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            validator_gem_topup_protocol(allocation, one_protocol_unit_native * U256::from(2u64))
                .unwrap(),
            U256::ZERO
        );
    }
}
