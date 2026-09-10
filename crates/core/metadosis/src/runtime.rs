use outbe_compressed_entities::{ExecutionScope, ParentBodySource};
use outbe_primitives::time::WorldwideDay;
#[cfg(test)]
use outbe_primitives::time::{
    date_key_to_utc_timestamp as primitives_date_key_to_timestamp,
    timestamp_to_date_key as utc_date_key,
};
use outbe_primitives::{block::BlockRuntimeContext, error::Result};

use crate::schema::MetadosisContract;
use crate::{
    aggregate::ValidatedWwdAggregate, lifecycle,
    ocomp::schema::require_active_ocomp_profile as load_active_ocomp_profile,
    settlement::process_ocomp_ready_candidate,
};

/// Converts a unix timestamp to a yyyymmdd date key (UTC).
#[cfg(test)]
pub fn timestamp_to_date_key(timestamp: u64) -> u32 {
    utc_date_key(timestamp)
}

/// Returns the unix timestamp for midnight UTC of a yyyymmdd date key.
///
/// Re-export of [`outbe_primitives::time::date_key_to_utc_timestamp`] for
/// backward compatibility with existing call sites in this crate. New
/// code should depend on `outbe_primitives::time` directly.
#[cfg(test)]
pub fn date_key_to_timestamp(date_key: u32) -> u64 {
    primitives_date_key_to_timestamp(date_key)
}

/// Public entry point invoked once by each hourly ProtocolCycle pass, after an
/// optional contiguous completed UTC day has received its terminal Metadosis
/// credit. Runs the full WWD lifecycle:
/// bootstrap (block 1 only), `create_worldwide_day_if_needed`,
/// exhaustive reducer advancement for active WWDs, then either one closed
/// local terminal outcome or OCOMP pre-admission for a READY WWD.
///
/// Renamed from `run_begin_block` (Phase 5.1 of the
/// Cycle epic): the function used to be wired into a dedicated
/// `MetadosisLifecycle::begin_block` lifecycle hook running on every
/// block; with the Cycle epic the only legitimate caller is the
/// hourly ProtocolCycle handler. The `MetadosisLifecycle` wrapper
/// was deleted altogether in the follow-up cleanup; tests that drive
/// the WWD state machine sub-day call this function directly.
pub fn start_metadosis(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<()> {
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    let timestamp = ctx.block.timestamp;
    lifecycle::validate_metadosis_timestamp(timestamp)?;
    let ocomp_profile = require_active_ocomp_profile(&metadosis)?;

    if ctx.block.block_number == 1 {
        lifecycle::init_genesis_day_inner(&mut metadosis, ctx)?;
    }

    lifecycle::create_worldwide_day_if_needed(&mut metadosis, ctx, timestamp)?;

    lifecycle::advance_active_worldwide_days(ctx, scope)?;

    let aggregate = ValidatedWwdAggregate::load_and_validate(ctx.storage.clone())?;
    let schema_limits = crate::ocomp::schema::poc_schema_limits();

    for current in aggregate.ready_records() {
        let wwd = current.worldwide_day;
        if !metadosis.ocomp_fsm_states.get_bytes(&wwd).is_empty()? {
            metadosis.ocomp_fsm_state(wwd, &schema_limits)?;
            continue;
        }
        process_ocomp_ready_candidate(&mut metadosis, ctx, scope, parent, current, &ocomp_profile)?;
        break;
    }

    // Terminal-day cleanup is no longer a per-tick scan: each COMPLETED/FAILED
    // transition retires the day into the bounded `closed_wwd`
    // delete-queue (see `MetadosisContract::mark_wwd_*`), which evicts and
    // deletes the oldest record past `MAX_RECORDS_KEPT`.

    Ok(())
}

pub(crate) fn require_active_ocomp_profile(
    metadosis: &MetadosisContract<'_>,
) -> Result<crate::ocomp::schema::OcompRequestProfile> {
    load_active_ocomp_profile(metadosis)
}

pub fn advance_active_worldwide_days(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
) -> Result<()> {
    lifecycle::advance_active_worldwide_days(ctx, scope)
}

/// Genesis-block (block 1) metadosis bootstrap: engage the testnet/devnet
/// bootstrap window and create the first worldwide day. Idempotent.
///
/// Wired into the begin-zone CycleTick phase at block 1 via
/// `outbe_cycle::lifecycle::CycleLifecycle::begin_block`. This is required
/// because ProtocolCycle only *anchors* `last_executed_at` on its
/// first encounter (block 1) and therefore never invokes [`start_metadosis`]
/// there; without this entry point the first worldwide day would not exist
/// until the first block after the next UTC-hour boundary.
pub fn init_genesis_day(ctx: &BlockRuntimeContext) -> Result<()> {
    lifecycle::init_genesis_day(ctx)
}

pub fn create_worldwide_day_for_date(
    metadosis: &mut MetadosisContract,
    ctx: &BlockRuntimeContext,
    wwd: WorldwideDay,
) -> Result<()> {
    lifecycle::create_worldwide_day_for_date(metadosis, ctx, wwd)
}
