use alloy_primitives::B256;
use outbe_compressed_entities::{
    partition_collection_key, ExecutionScope, PartitionRef, SealedCollectionRoot,
};
use outbe_nod::NodContract;
use outbe_ocomp_protocol::{
    intent::{
        ActivationPreconditionsV1, ContributorTargetPreconditionV1, DayType,
        FrozenMetadosisValuesV1, JobIntentV1, MetadosisAttemptPreconditionV1,
        MetadosisExpectedStatus, NodTargetPreconditionV1, TributeInputBindingV1,
    },
    receipts::RequestBudgetSplitReceiptV1,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{block::BlockRuntimeContext, error::Result};
use outbe_tribute::{TributeContract, TributePreAdmissionProjection};

use crate::{
    aggregate::WwdDayType,
    commit::plan_outer_transition,
    errors::storage_corruption_message,
    ocomp_budget::{apply_fresh_request_budget_effect, RequestBudgetEffect},
    pre_admission::{
        evaluate_pre_admission, PreAdmissionContext, PreAdmissionDecision, PreAdmissionInputs,
    },
    precompile::IMetadosis,
    reducer::{OuterWwdEvent, OuterWwdTransition},
    schema::{MetadosisContract, WorldwideDayEntryExt},
};

use super::{
    authority::current_ocomp_attempt_snapshot,
    schema::{poc_schema_limits, OcompRequestProfile},
    state::RequestEffectMode,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalRequestOutcome {
    Inactive,
    NoReadyJob,
    Deferred,
    IntentCreated(B256),
}

#[derive(Clone, Copy)]
struct TerminalRequestContext<'a, 'storage> {
    ctx: &'a BlockRuntimeContext<'storage>,
    profile: &'a OcompRequestProfile,
    wwd: WorldwideDay,
    pending_nonce: u64,
    outer_transition: &'a OuterWwdTransition,
    roots: TerminalRequestRoots,
}

#[derive(Clone, Copy)]
struct TerminalRequestRoots {
    sealed_root: B256,
    tribute: SealedCollectionRoot,
}

#[derive(Clone, Copy)]
enum TerminalRootSource {
    Provisional,
    #[cfg(test)]
    CompletedFixture,
}

/// Executes the bounded end-zone request transition against the executor-owned
/// provisional CE seal while the scope remains active for failure retirement.
pub fn run_terminal_request(ctx: &BlockRuntimeContext<'_>, scope: &ExecutionScope) -> Result<()> {
    run_terminal_request_inner(ctx, scope, TerminalRootSource::Provisional).map(|_| ())
}

/// Compatibility adapter for old unit fixtures that model a previously sealed
/// parent. Production and production-ordering tests must use
/// [`run_terminal_request`].
#[cfg(test)]
pub(crate) fn run_terminal_request_with_completed_fixture(
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
) -> Result<()> {
    run_terminal_request_inner(ctx, scope, TerminalRootSource::CompletedFixture).map(|_| ())
}

pub(crate) fn due_ready_worldwide_day(
    ctx: &BlockRuntimeContext<'_>,
) -> Result<Option<WorldwideDay>> {
    let limits = poc_schema_limits();
    let metadosis = MetadosisContract::new(ctx.storage.clone());
    let Some(_profile) = metadosis.read_ocomp_request_profile(&limits)? else {
        return Ok(None);
    };
    let Some(projection) = metadosis.next_ocomp_ready(&limits)? else {
        return Ok(None);
    };
    Ok(projection
        .next_check_height
        .is_some_and(|height| ctx.block.block_number >= height)
        .then_some(projection.worldwide_day))
}

fn run_terminal_request_inner(
    ctx: &BlockRuntimeContext<'_>,
    scope: &ExecutionScope,
    root_source: TerminalRootSource,
) -> Result<TerminalRequestOutcome> {
    let schema_limits = poc_schema_limits();
    let mut metadosis = MetadosisContract::new(ctx.storage.clone());
    let Some(profile) = metadosis.read_ocomp_request_profile(&schema_limits)? else {
        return Ok(TerminalRequestOutcome::Inactive);
    };
    let Some(projection) = metadosis.next_ocomp_ready(&schema_limits)? else {
        return Ok(TerminalRequestOutcome::NoReadyJob);
    };
    let due_height = projection
        .next_check_height
        .ok_or_else(|| storage_corruption_message("READY OCOMP state has no due height"))?;
    if ctx.block.block_number < due_height {
        return Ok(TerminalRequestOutcome::NoReadyJob);
    }
    if projection.terminal_records != 0 || projection.pending_nonce != 0 {
        return Err(storage_corruption_message(
            "OCOMP READY state contains a prior job attempt",
        ));
    }
    let outer_transition = plan_outer_transition(
        ctx.storage.clone(),
        projection.worldwide_day,
        OuterWwdEvent::OcompRequestCommitted,
    )?;
    let roots = terminal_request_roots(scope, projection.worldwide_day, root_source)?;

    let request = TerminalRequestContext {
        ctx,
        profile: &profile,
        wwd: projection.worldwide_day,
        pending_nonce: projection.pending_nonce,
        outer_transition: &outer_transition,
        roots,
    };

    build_and_commit_request(&mut metadosis, &request)
}

// These are the complete inputs to one atomic terminal-request transition.
// Keeping them explicit prevents an ambient or partially initialized mutation
// context from crossing the commit boundary.
fn build_and_commit_request(
    metadosis: &mut MetadosisContract<'_>,
    request: &TerminalRequestContext<'_, '_>,
) -> Result<TerminalRequestOutcome> {
    let TerminalRequestContext {
        ctx,
        profile,
        wwd,
        pending_nonce,
        outer_transition: _,
        roots,
    } = *request;
    let schema_limits = poc_schema_limits();
    let exact_collection = roots.tribute;
    let ce_sealed_root = roots.sealed_root;

    let mut tribute = TributeContract::new(ctx.storage.clone());
    let stored_tribute_projection = tribute.pre_admission_projection(wwd)?;
    let candidate_tribute_projection =
        candidate_tribute_projection(stored_tribute_projection, exact_collection)?;
    let current_vwap = metadosis.worldwide_days.entry(wwd).current_vwap().read()?;
    let oracle = outbe_oracle::api::ocomp_pre_admission_projection(
        ctx.storage.clone(),
        ctx.block.timestamp,
    )?;
    // The per-owner league snapshot and its root were committed during the
    // active-phase prepare step (`build_fidelity_league_snapshot`). This terminal
    // request runs after the provisional seal and cannot enumerate tributes, so
    // it only reads the committed snapshot root to bind into the envelope.
    let snapshot_root = metadosis.ocomp_fidelity_league_snapshot_root.read(&wwd)?;
    if snapshot_root.is_zero() {
        return Err(storage_corruption_message(
            "OCOMP Fidelity league snapshot missing at terminal request",
        ));
    }
    let pre_admission_context = PreAdmissionContext {
        chain_id: profile.chain_id,
        genesis_hash: profile.genesis_hash,
        fork_id: profile.fork_id,
        correctness_profile_id: profile.correctness_profile_id,
        capacity_profile: profile.capacity_profile.clone(),
    };
    let candidate_decision = evaluate_pre_admission(
        &pre_admission_context,
        &PreAdmissionInputs {
            tribute: candidate_tribute_projection,
            fidelity_league_snapshot_root: snapshot_root,
            oracle,
        },
    )?;
    let PreAdmissionDecision::Eligible(candidate_envelope) = candidate_decision else {
        defer_ready(metadosis, wwd, ctx.block.block_number, profile)?;
        return Ok(TerminalRequestOutcome::Deferred);
    };

    let nod_target = NodContract::new(ctx.storage.clone()).ocomp_target_projection(wwd)?;
    let contributor_target =
        outbe_intex::api::ocomp_contributor_target_projection(&ctx.storage, wwd)?;

    let sealed_tribute_projection = if stored_tribute_projection.is_sealed {
        stored_tribute_projection
    } else {
        tribute.seal_pre_admission(wwd, exact_collection)?
    };
    let sealed_decision = evaluate_pre_admission(
        &pre_admission_context,
        &PreAdmissionInputs {
            tribute: sealed_tribute_projection,
            fidelity_league_snapshot_root: snapshot_root,
            oracle: outbe_oracle::api::ocomp_pre_admission_projection(
                ctx.storage.clone(),
                ctx.block.timestamp,
            )?,
        },
    )?;
    let PreAdmissionDecision::Eligible(sealed_envelope) = sealed_decision else {
        return Err(storage_corruption_message(
            "eligible OCOMP admission changed after exact Tribute seal",
        ));
    };
    if sealed_envelope != candidate_envelope {
        return Err(storage_corruption_message(
            "OCOMP admission envelope changed after exact Tribute seal",
        ));
    }

    let envelope_projection =
        metadosis.commit_pre_admission_envelope(wwd, &sealed_envelope, &schema_limits)?;
    let envelope_hash = sealed_envelope
        .envelope_hash(&schema_limits)
        .map_err(|error| {
            storage_corruption_message(format!("hash OCOMP pre-admission envelope: {error}"))
        })?;
    if envelope_projection.envelope_hash != envelope_hash {
        return Err(storage_corruption_message(
            "stored OCOMP pre-admission envelope hash mismatch",
        ));
    }

    let day_limit = metadosis
        .worldwide_days
        .entry(wwd)
        .metadosis_limit_amount()
        .read()?;
    let calculation = metadosis.calculate_metadosis(
        wwd,
        sealed_tribute_projection.tribute_nominal_amount,
        day_limit,
    )?;
    let lysis_budget = calculation.gratis_allocation;
    let nominal_total = sealed_tribute_projection.tribute_nominal_amount;
    let protocol_day_type = protocol_day_type(metadosis.get_wwd_day_type(wwd)?)?;
    let effect = RequestBudgetEffect {
        protocol_bundle_hash: profile.protocol_bundle_hash,
        wwd: wwd.value(),
        pending_nonce,
        day_type: protocol_day_type,
        day_limit,
        lysis_budget,
        nominal_total,
        auction_entry_prices: sealed_envelope.auction_entry_prices.clone(),
        logical_anchor: ctx.block.timestamp,
    };

    let state = metadosis.ocomp_fsm_state(wwd, &schema_limits)?;
    let mode = state
        .request_effect_mode()
        .map_err(|error| storage_corruption_message(error.to_string()))?;
    let authoritative_receipt = metadosis.request_budget_receipt(wwd, &schema_limits)?;
    let receipt =
        apply_or_validate_budget_effect(ctx, effect, mode, authoritative_receipt.as_ref())?;
    let receipt_hash = receipt.receipt_hash(&schema_limits).map_err(|error| {
        storage_corruption_message(format!("hash OCOMP request receipt: {error}"))
    })?;

    let attempt = u32::try_from(pending_nonce)
        .map_err(|_| storage_corruption_message("OCOMP pending nonce exceeds u32"))?;
    let (_, collection_key) = partition_collection_key(PartitionRef::TributeWwd(wwd))
        .map_err(|error| storage_corruption_message(error.to_string()))?;
    let activation_preconditions = ActivationPreconditionsV1 {
        tribute: TributeInputBindingV1 {
            wwd: wwd.value(),
            source_generation: sealed_tribute_projection.source_generation,
            collection_key: B256::from_slice(collection_key.as_bytes()),
            sealed_collection_root: sealed_tribute_projection.sealed_collection_root,
            exact_count: sealed_tribute_projection.tribute_count,
            exact_nominal_total: sealed_tribute_projection.tribute_nominal_amount,
        },
        nod: NodTargetPreconditionV1 {
            wwd: wwd.value(),
            target_generation: nod_target.target_generation,
            namespace_root_before: nod_target.namespace_root_before,
            max_nod_count: sealed_tribute_projection.tribute_count,
        },
        contributors: ContributorTargetPreconditionV1 {
            worldwide_day: wwd.value(),
            expected_series_version: contributor_target.expected_series_version,
            max_contributor_count: sealed_tribute_projection.tribute_count,
            max_eligible_nominal_total: sealed_tribute_projection.tribute_nominal_amount,
        },
        metadosis: MetadosisAttemptPreconditionV1 {
            wwd: wwd.value(),
            pending_nonce,
            expected_status: MetadosisExpectedStatus::OffchainPending,
            state_version: envelope_projection.state_version,
        },
    };
    let previous_vwap = metadosis.worldwide_days.entry(wwd).previous_vwap().read()?;
    let result_snapshot = current_ocomp_attempt_snapshot(ctx.storage.clone())?;
    let intent = JobIntentV1 {
        chain_id: profile.chain_id,
        genesis_hash: profile.genesis_hash,
        fork_id: profile.fork_id,
        wwd: wwd.value(),
        pending_nonce,
        attempt,
        protocol_bundle_hash: profile.protocol_bundle_hash,
        ce_sealed_root,
        sealed_tribute_collection_key: B256::from_slice(collection_key.as_bytes()),
        sealed_tribute_collection_root: sealed_tribute_projection.sealed_collection_root,
        authenticated_day_count: sealed_tribute_projection.tribute_count,
        authenticated_day_nominal: sealed_tribute_projection.tribute_nominal_amount,
        pre_admission_envelope_hash: envelope_hash,
        source_availability_policy_id: profile.source_availability_policy_id,
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: protocol_day_type,
            // The effective ceiling the day was allowed: its own emission plus what it drew.
            day_limit: receipt.day_limit,
            previous_vwap,
            current_vwap,
            gratis_demand: calculation.gratis_demand,
            gratis_supply: calculation.gratis_supply,
            lysis_budget,
            auction_base: receipt.auction_base,
            auction_entry_prices: sealed_envelope.auction_entry_prices.clone(),
            request_budget_split_receipt_hash: receipt_hash,
        },
        logical_evaluation_height: ctx.block.block_number,
        logical_evaluation_time: ctx.block.timestamp,
        activation_preconditions,
        result_validator_set_epoch: result_snapshot.validator_set_epoch,
        result_committee_set_hash: result_snapshot.committee_set_hash,
        result_ocomp_binding_hash: result_snapshot.ocomp_binding_hash,
        result_member_count: result_snapshot.member_count,
        result_quorum_threshold: result_snapshot.quorum_threshold,
        custody_committee_epoch_hash: None,
    };
    commit_and_emit_request(metadosis, request, &intent, &receipt)
}

fn commit_and_emit_request(
    metadosis: &mut MetadosisContract<'_>,
    request: &TerminalRequestContext<'_, '_>,
    intent: &JobIntentV1,
    receipt: &RequestBudgetSplitReceiptV1,
) -> Result<TerminalRequestOutcome> {
    let schema_limits = poc_schema_limits();
    let intent_id = intent
        .intent_id(&schema_limits)
        .map_err(|error| storage_corruption_message(format!("hash OCOMP intent: {error}")))?;
    let activation_preconditions_hash = intent
        .activation_preconditions
        .activation_preconditions_hash(&schema_limits)
        .map_err(|error| {
            storage_corruption_message(format!("hash OCOMP activation preconditions: {error}"))
        })?;

    request.ctx.with_checkpoint(|| {
        let mut registry = outbe_ocompregistry::OcompRegistry::new(request.ctx.storage.clone());
        if registry.active_authority(&schema_limits)?.is_some() {
            let pinned_bundle = registry.pin_lineage(intent_id, &schema_limits)?;
            if pinned_bundle != intent.protocol_bundle_hash {
                return Err(storage_corruption_message(
                    "OCOMP intent bundle differs from its Registry lineage pin",
                ));
            }
        }

        metadosis.commit_ocomp_request(
            request.outer_transition,
            intent,
            receipt,
            &schema_limits,
        )?;
        metadosis.emit(IMetadosis::OffchainJobRequested {
            intentId: intent_id,
            wwd: request.wwd.value(),
            pendingNonce: request.pending_nonce,
            attempt: intent.attempt,
            activationPreconditionsHash: activation_preconditions_hash,
        })?;
        Ok(TerminalRequestOutcome::IntentCreated(intent_id))
    })
}

fn candidate_tribute_projection(
    mut projection: TributePreAdmissionProjection,
    exact_collection: SealedCollectionRoot,
) -> Result<TributePreAdmissionProjection> {
    if projection.worldwide_day
        != match exact_collection.partition() {
            PartitionRef::TributeWwd(day) => day,
        }
    {
        return Err(storage_corruption_message(
            "OCOMP Tribute projection/partition day mismatch",
        ));
    }
    if projection.is_sealed {
        if projection.sealed_collection_root != exact_collection.root() {
            return Err(storage_corruption_message(
                "stored OCOMP Tribute root differs from provisional CE seal",
            ));
        }
        return Ok(projection);
    }
    projection.is_sealed = true;
    projection.sealed_collection_root = exact_collection.root();
    Ok(projection)
}

fn apply_or_validate_budget_effect(
    ctx: &BlockRuntimeContext<'_>,
    effect: RequestBudgetEffect,
    mode: RequestEffectMode,
    authoritative: Option<&RequestBudgetSplitReceiptV1>,
) -> Result<RequestBudgetSplitReceiptV1> {
    match (mode, authoritative) {
        (RequestEffectMode::Fresh { effect_nonce }, None)
            if effect_nonce == effect.pending_nonce =>
        {
            apply_fresh_request_budget_effect(ctx.storage.clone(), effect)
        }
        _ => Err(storage_corruption_message(
            "authoritative OCOMP receipt disagrees with request effect mode",
        )),
    }
}

fn defer_ready(
    metadosis: &mut MetadosisContract<'_>,
    wwd: WorldwideDay,
    at_height: u64,
    profile: &OcompRequestProfile,
) -> Result<()> {
    let next_check_height = at_height
        .checked_add(profile.capacity_profile.ready_backoff_blocks)
        .ok_or_else(|| storage_corruption_message("OCOMP deferred height overflow"))?;
    metadosis.defer_ocomp_ready(wwd, at_height, next_check_height, &poc_schema_limits())
}

fn protocol_day_type(value: WwdDayType) -> Result<DayType> {
    match value {
        WwdDayType::Green => Ok(DayType::Green),
        WwdDayType::Red => Ok(DayType::Red),
        WwdDayType::Unknown => Err(storage_corruption_message(
            "OCOMP request requires a resolved day type",
        )),
    }
}

fn terminal_request_roots(
    scope: &ExecutionScope,
    worldwide_day: WorldwideDay,
    source: TerminalRootSource,
) -> Result<TerminalRequestRoots> {
    let partition = PartitionRef::TributeWwd(worldwide_day);
    match source {
        TerminalRootSource::Provisional => Ok(TerminalRequestRoots {
            sealed_root: scope.provisional_sealed_root()?,
            tribute: scope.provisional_partition_root(partition)?,
        }),
        #[cfg(test)]
        TerminalRootSource::CompletedFixture => Ok(TerminalRequestRoots {
            sealed_root: scope.completed_sealed_root()?,
            tribute: scope.completed_partition_root(partition)?,
        }),
    }
}
