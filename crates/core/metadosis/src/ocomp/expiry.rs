use alloy_primitives::B256;
use outbe_compressed_entities::ExecutionScope;
use outbe_ocomp_protocol::state::OcompJobStatus;
use outbe_primitives::{block::BlockRuntimeContext, error::Result};

use crate::{
    aggregate::ValidatedWwdAggregate,
    errors::storage_corruption_message,
    precompile::IMetadosis,
    reducer::{reduce_outer_wwd, OuterWwdEvent, OuterWwdTransition},
    schema::MetadosisContract,
};

use super::{
    schema::poc_schema_limits,
    state::{DayPhase, JobFsmProjection},
    vote::{OcompPenaltyMetrics, ResponseWindowCloseV1},
};

/// Records finality for the exact live OCOMP request whose request block is the
/// consensus-certified parent. The lookup is bounded by the canonical retained
/// WorldwideDay population; unrelated finalized parents are a no-op.
pub fn record_certified_parent_finality(
    ctx: &BlockRuntimeContext<'_>,
    finalized_request_block_number: u64,
    finalized_request_block_hash: B256,
    finalized_request_state_root: B256,
) -> Result<bool> {
    let schema_limits = poc_schema_limits();
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    let Some(profile) = metadosis.read_ocomp_request_profile(&schema_limits)? else {
        return Ok(false);
    };
    let mut matched = None;
    for state in metadosis.live_ocomp_fsm_states(&schema_limits)? {
        let intent_id = state
            .projection()
            .live_intent_id
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler has no IntentId"))?;
        let record = metadosis
            .ocomp_job_record(intent_id, &schema_limits)?
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler job is missing"))?;
        if record.intent_height == finalized_request_block_number
            && record.status == OcompJobStatus::AwaitingFinality
            && matched.replace(intent_id).is_some()
        {
            return Err(storage_corruption_message(
                "multiple live OCOMP jobs claim the same request block",
            ));
        }
    }
    let Some(intent_id) = matched else {
        return Ok(false);
    };
    if finalized_request_state_root.is_zero() {
        return Err(storage_corruption_message(
            "OCOMP certified request parent has no authenticated state root",
        ));
    }

    metadosis.record_ocomp_finality(
        intent_id,
        finalized_request_block_hash,
        finalized_request_state_root,
        ctx.block.block_number,
        profile.capacity_profile.result_deadline_blocks,
        &schema_limits,
    )?;
    Ok(true)
}

/// Runs the exact begin-zone expiry key. No WorldwideDay or job scan is
/// permitted on this path.
pub fn run_lifecycle_begin_with_scope(
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
) -> Result<OcompPenaltyMetrics> {
    if let Some(before) = missed_lifecycle_boundary(ctx)? {
        let aggregate = ValidatedWwdAggregate::load_and_validate(ctx.storage.clone())?;
        let current = aggregate.record(before.worldwide_day).ok_or_else(|| {
            storage_corruption_message("overdue OCOMP expiry has no persisted outer WorldwideDay")
        })?;
        let outer_transition = reduce_outer_wwd(Some(current), OuterWwdEvent::OcompExpired)?;
        expire_exact(
            &mut MetadosisContract::new(ctx.storage.clone()),
            ctx,
            scope,
            before,
            &outer_transition,
        )?;
        return Ok(OcompPenaltyMetrics::default());
    }
    run_lifecycle_begin_exact(ctx, scope)
}

fn run_lifecycle_begin_exact(
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
) -> Result<OcompPenaltyMetrics> {
    let schema_limits = poc_schema_limits();
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    let Some(_profile) = metadosis.read_ocomp_request_profile(&schema_limits)? else {
        return Ok(OcompPenaltyMetrics::default());
    };
    metadosis.open_due_ocomp_voting(ctx.block.block_number, &schema_limits)?;
    let aggregate = ValidatedWwdAggregate::load_and_validate(ctx.storage.clone())?;
    let response =
        metadosis.close_due_ocomp_response_window(ctx.block.block_number, &schema_limits)?;
    let metrics = response.metrics;
    match response.close {
        ResponseWindowCloseV1::NotDue | ResponseWindowCloseV1::QuorumPreserved { .. } => Ok(()),
        ResponseWindowCloseV1::NoQuorum { intent_id } => {
            let state = metadosis
                .live_ocomp_fsm_state_by_intent(intent_id, &schema_limits)?
                .ok_or_else(|| {
                    storage_corruption_message("no-quorum OCOMP close has no live job")
                })?;
            let before = state.projection();
            if before.phase != DayPhase::OffchainPending
                || before.live_intent_id != Some(intent_id)
                || before
                    .deadline_height
                    .is_none_or(|deadline| deadline > ctx.block.block_number)
            {
                return Err(storage_corruption_message(
                    "no-quorum OCOMP close/live state mismatch",
                ));
            }
            let current = aggregate.record(before.worldwide_day).ok_or_else(|| {
                storage_corruption_message(
                    "no-quorum OCOMP close has no persisted outer WorldwideDay",
                )
            })?;
            let outer_transition = reduce_outer_wwd(Some(current), OuterWwdEvent::OcompExpired)?;
            expire_exact(&mut metadosis, ctx, scope, before, &outer_transition)
        }
    }?;

    let mut due = None;
    for state in metadosis.live_ocomp_fsm_states(&schema_limits)? {
        let before = state.projection();
        let intent_id = before
            .live_intent_id
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler has no IntentId"))?;
        let record = metadosis
            .ocomp_job_record(intent_id, &schema_limits)?
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler job is missing"))?;
        if record.status != OcompJobStatus::AwaitingFinality || record.finalized.is_some() {
            continue;
        }
        let deadline = before.deadline_height.ok_or_else(|| {
            storage_corruption_message("OCOMP awaiting-finality job has no deadline")
        })?;
        if deadline > ctx.block.block_number {
            continue;
        }
        if deadline < ctx.block.block_number {
            return Err(storage_corruption_message(
                "OCOMP consensus skipped the exact awaiting-finality expiry height",
            ));
        }
        if due.replace(before).is_some() {
            return Err(storage_corruption_message(
                "multiple OCOMP awaiting-finality jobs are due at one height",
            ));
        }
    }
    let Some(before) = due else {
        return Ok(metrics);
    };
    let current = aggregate.record(before.worldwide_day).ok_or_else(|| {
        storage_corruption_message("awaiting-finality expiry has no persisted outer WorldwideDay")
    })?;
    let outer_transition = reduce_outer_wwd(Some(current), OuterWwdEvent::OcompExpired)?;
    expire_exact(&mut metadosis, ctx, scope, before, &outer_transition)?;
    Ok(metrics)
}

fn missed_lifecycle_boundary(ctx: &BlockRuntimeContext<'_>) -> Result<Option<JobFsmProjection>> {
    let schema_limits = poc_schema_limits();
    let metadosis = MetadosisContract::new(ctx.storage.clone());
    let Some(_profile) = metadosis.read_ocomp_request_profile(&schema_limits)? else {
        return Ok(None);
    };
    for state in metadosis.live_ocomp_fsm_states(&schema_limits)? {
        let projection = state.projection();
        let intent_id = projection
            .live_intent_id
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler has no IntentId"))?;
        let record = metadosis
            .ocomp_job_record(intent_id, &schema_limits)?
            .ok_or_else(|| storage_corruption_message("OCOMP live scheduler job is missing"))?;
        match record.status {
            OcompJobStatus::AwaitingFinality => {
                if let Some(finalized) = record.finalized.as_ref() {
                    if ctx.block.block_number >= finalized.deadline_height {
                        return Ok(Some(projection));
                    }
                } else if projection
                    .deadline_height
                    .is_some_and(|deadline| ctx.block.block_number > deadline)
                {
                    return Ok(Some(projection));
                }
            }
            OcompJobStatus::VotingOpen => {}
            _ => {}
        }
    }
    Ok(None)
}

fn expire_exact(
    metadosis: &mut MetadosisContract<'_>,
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
    before: JobFsmProjection,
    outer_transition: &OuterWwdTransition,
) -> Result<()> {
    let intent_id = before
        .live_intent_id
        .ok_or_else(|| storage_corruption_message("pending OCOMP state has no live IntentId"))?;
    let retained_lysis_budget = metadosis.expire_ocomp_job(
        outer_transition,
        intent_id,
        ctx.block.block_number,
        ctx.block.timestamp,
        &poc_schema_limits(),
    )?;
    let expected_budget = before.retained_lysis_budget.ok_or_else(|| {
        storage_corruption_message("terminal OCOMP expiry has no retained budget")
    })?;
    if retained_lysis_budget != expected_budget {
        return Err(storage_corruption_message(
            "terminal OCOMP expiry returned a different retained budget",
        ));
    }
    crate::terminal::fail_expired_ocomp_day(
        ctx.storage.clone(),
        ctx.block.block_number,
        scope,
        before.worldwide_day,
        intent_id,
        retained_lysis_budget,
        outer_transition,
    )?;
    if metadosis.get_wwd_status(before.worldwide_day)? != crate::aggregate::WwdStatus::Failed
        || metadosis
            .read_metadosis_failure_receipt(before.worldwide_day, expected_budget)?
            .is_none()
        || metadosis
            .live_ocomp_fsm_state_by_intent(intent_id, &poc_schema_limits())?
            .is_some()
        || !metadosis
            .ocomp_fsm_states
            .get_bytes(&before.worldwide_day)
            .is_empty()?
    {
        return Err(storage_corruption_message(
            "OCOMP expiry post-state is inconsistent",
        ));
    }
    metadosis.emit(IMetadosis::OffchainJobExpired {
        intentId: intent_id,
        wwd: before.worldwide_day.value(),
        expiredAtHeight: ctx.block.block_number,
    })
}
