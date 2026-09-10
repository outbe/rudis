use crate::runtime::create_worldwide_day_for_date;
use crate::state::{DayLimitFormationReceipt, OcompDayLimitFormation};
use alloy_primitives::U256;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::Result,
    storage::{
        metadosis_cycle_allocation_binding, metadosis_late_settlement_binding,
        MetadosisCertifiedFinality, MetadosisCycleLifecycle,
    },
};
use outbe_promislimit::PromisLimitContract;

use crate::schema::MetadosisContract;

/// Writes the terminal emission allocation into Metadosis-owned state.
pub(crate) fn apply(ctx: &BlockRuntimeContext, amount: U256) -> Result<DayLimitFormationReceipt> {
    let binding = metadosis_cycle_allocation_binding(
        ctx.block.chain_id,
        ctx.block.block_number,
        ctx.block.timestamp,
    );
    crate::commit::commit_transition::<MetadosisCycleLifecycle, _>(
        ctx.storage.clone(),
        binding,
        |_| apply_inner(ctx, amount),
    )
}

fn apply_inner(ctx: &BlockRuntimeContext, amount: U256) -> Result<DayLimitFormationReceipt> {
    crate::runtime::require_active_ocomp_profile(&MetadosisContract::new(ctx.storage.clone()))?;
    apply_ocomp_day_limit(ctx, amount)
}

/// Recycles late-settlement headroom without racing daily OCOMP limit formation.
///
/// The genesis-active OCOMP profile makes the daily Cycle allocation the sole
/// base-limit formation input, so a late residue is a carry-over credit consumed
/// by the next not-yet-formed day limit. Missing profile state is fatal rather
/// than a legacy execution mode.
pub(crate) fn apply_late_settlement_headroom(
    ctx: &BlockRuntimeContext,
    amount: U256,
) -> Result<U256> {
    let binding = metadosis_late_settlement_binding(
        ctx.block.chain_id,
        ctx.block.block_number,
        ctx.block.timestamp,
    );
    crate::commit::commit_transition::<MetadosisCertifiedFinality, _>(
        ctx.storage.clone(),
        binding,
        |_| apply_late_settlement_headroom_inner(ctx, amount),
    )
}

fn apply_late_settlement_headroom_inner(ctx: &BlockRuntimeContext, amount: U256) -> Result<U256> {
    crate::runtime::require_active_ocomp_profile(&MetadosisContract::new(ctx.storage.clone()))?;
    PromisLimitContract::new(ctx.storage.clone()).checked_add_carry_over(amount)?;
    Ok(U256::ZERO)
}

fn apply_ocomp_day_limit(
    ctx: &BlockRuntimeContext,
    base_limit: U256,
) -> Result<DayLimitFormationReceipt> {
    (|| {
        let wwd = WorldwideDay::from_timestamp(ctx.block.timestamp);
        let mut metadosis = MetadosisContract::new(ctx.storage.clone());
        create_worldwide_day_for_date(&mut metadosis, ctx, wwd)?;

        if let Some(formed) = metadosis.ocomp_day_limit_formation(wwd)? {
            if formed.base_limit != base_limit {
                return Err(crate::errors::caller_rejection(
                    "formed OCOMP day limit cannot be replaced",
                ));
            }
            return Ok(DayLimitFormationReceipt::Formed(formed));
        }

        // A day is formed against its own emission. The accumulator is drawn from at the request,
        // where the day's demand is known, so forming one day never strands it for the next.
        let carry_over = PromisLimitContract::new(ctx.storage.clone()).get_total_unallocated()?;
        crate::commit::commit_day_limit_formation(
            &mut metadosis,
            OcompDayLimitFormation {
                worldwide_day: wwd,
                base_limit,
                carry_over_before: carry_over,
                carry_over_taken: U256::ZERO,
                carry_over_after: carry_over,
                day_limit: base_limit,
                block_number: ctx.block.block_number,
            },
        )
    })()
}
