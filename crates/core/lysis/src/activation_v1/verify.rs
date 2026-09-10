use alloy_primitives::B256;
use outbe_ocomp_protocol::{
    activation::ActivationCallCoreV1,
    intent::JobIntentV1,
    receipts::EffectBindingV1,
    result::{ActivationPayloadV1, LysisResultV1},
    ProtocolError, SchemaLimits,
};

use super::apply_plan::{
    carry_over_apply, contributor_apply, nod_apply, tribute_apply, LysisApplyPlanPartsV1,
    LysisApplyPlanV1, NodGenerationApplyPartsV1, RequestBudgetSplitApplyV1,
};

const RETIRED_TRIBUTE_GENERATION_V1: u64 = 1;

pub fn verify_result(
    intent_id: B256,
    expected_job_id: B256,
    intent: &JobIntentV1,
    activation_payload: &ActivationPayloadV1,
    result: &LysisResultV1,
    limits: &SchemaLimits,
) -> Result<LysisApplyPlanV1, ProtocolError> {
    ensure(
        intent.intent_id(limits)? == intent_id,
        "Lysis apply intent id",
    )?;
    intent.validate_semantics()?;
    intent
        .activation_preconditions
        .validate_for_intent(intent)?;
    result.validate_semantics(limits)?;
    result.validate_finalized_intent(intent)?;
    ensure(result.job_id == expected_job_id, "Lysis apply job id")?;
    let reconstructed_payload = result.activation_payload(limits)?;
    ensure(
        &reconstructed_payload == activation_payload,
        "Lysis apply activation payload",
    )?;
    ensure(
        !result.input_manifest_hash.is_zero()
            && !result.plan_hash.is_zero()
            && !result.unit_artifact_root.is_zero()
            && !result.fidelity_fraction_root.is_zero()
            && !result.gratis_prefix_root.is_zero()
            && !result.roots.nod_root.is_zero()
            && !result.roots.bucket_root.is_zero()
            && !result.roots.contributor_root.is_zero()
            && !result.roots.output_manifest_root.is_zero(),
        "Lysis apply committed roots",
    )?;
    ensure(
        result.counts.nod_count <= intent.activation_preconditions.nod.max_nod_count
            && result.counts.contributor_count
                <= intent
                    .activation_preconditions
                    .contributors
                    .max_contributor_count
            && result.conservation.eligible_nominal_total
                <= intent
                    .activation_preconditions
                    .contributors
                    .max_eligible_nominal_total,
        "Lysis apply target bounds",
    )?;

    let result_digest = result.result_digest(limits)?;
    let activation_preconditions_hash = intent
        .activation_preconditions
        .activation_preconditions_hash(limits)?;
    let call_core = ActivationCallCoreV1 {
        intent_id,
        job_id: expected_job_id,
        attempt: intent.attempt,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        result_digest,
        activation_preconditions_hash,
        terminal_pending_nonce: intent.pending_nonce,
    };
    let binding = EffectBindingV1 {
        intent_id,
        job_id: expected_job_id,
        attempt: intent.attempt,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        result_digest,
        activation_preconditions_hash,
        activation_call_id: call_core.activation_call_id(limits)?,
    };
    binding.validate_call(&call_core, limits)?;

    Ok(LysisApplyPlanPartsV1 {
        call_core,
        binding,
        request_budget_split_receipt_hash: intent
            .frozen_metadosis_values
            .request_budget_split_receipt_hash,
        request_budget_split: RequestBudgetSplitApplyV1 {
            protocol_bundle_hash: intent.protocol_bundle_hash,
            wwd: intent.wwd,
            pending_nonce: intent.pending_nonce,
            day_type: intent.frozen_metadosis_values.day_type,
            day_limit: intent.frozen_metadosis_values.day_limit,
            lysis_budget: intent.frozen_metadosis_values.lysis_budget,
            auction_base: intent.frozen_metadosis_values.auction_base,
            auction_entry_prices: intent.frozen_metadosis_values.auction_entry_prices.clone(),
            logical_anchor: intent.logical_evaluation_time,
        },
        nod: nod_apply(NodGenerationApplyPartsV1 {
            precondition: intent.activation_preconditions.nod.clone(),
            nod_root: result.roots.nod_root,
            bucket_root: result.roots.bucket_root,
            output_manifest_root: result.roots.output_manifest_root,
            exact_counts: result.counts.clone(),
            nod_amount_total: result.conservation.nod_cost_total,
            nod_gratis_consumed: result.conservation.nod_gratis_consumed,
            issued_at: intent.logical_evaluation_time,
        }),
        contributors: contributor_apply(
            intent.activation_preconditions.contributors.clone(),
            result.roots.contributor_root,
            result.counts.contributor_count,
            result.conservation.eligible_nominal_total,
        ),
        tribute: tribute_apply(
            intent.activation_preconditions.tribute.clone(),
            result.counts.tribute_count,
            result.conservation.tribute_nominal_total,
            RETIRED_TRIBUTE_GENERATION_V1,
        ),
        carry_over: carry_over_apply(intent.wwd, result.conservation.unused_lysis),
    }
    .into())
}

fn ensure(condition: bool, invariant: &'static str) -> Result<(), ProtocolError> {
    if condition {
        Ok(())
    } else {
        Err(ProtocolError::InvalidInvariant(invariant))
    }
}
