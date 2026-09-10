//! Closed, storage-independent Lysis V1 result finalization.
//!
//! The process host supplies bounded exact-order cursors over objects it has
//! already reopened and authenticated. This module owns every semantic result
//! field: callers cannot provide a result root, conservation scalar or
//! arithmetic commitment.

use alloy_primitives::{keccak256, B256, U256};
use outbe_ocomp_protocol::{
    hash_framed,
    input::InputManifestV1,
    intent::JobIntentV1,
    result::{
        lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
        CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisResultV1,
        MetadosisCompletionSummaryV1, OutputManifestEntryV1, ResultChunkV1, ResultRootsV1,
    },
    shuffle::ShuffleBucketRecordV1,
    unit::{PlanCommitmentV1, UnitArtifactV1, UnitPhase},
    CanonicalWriter, ListKind, ObjectKind, ProtocolError, SchemaLimits, StreamingOrderedListRoot,
};

use super::{
    artifacts::{
        decode_fixed_reduce_output, decode_gratis_prefix_down_output, GratisPrefixDownOutputV1,
        LysisArtifactErrorV1,
    },
    phases::GratisLeafPrefixV1,
    planner::{LysisPlanTopologyV1, PlannedUnitPositionV1, PlannerErrorV1},
    result::{
        decode_root_reduce_output, LysisListSubtreeCarrierV1, RootReduceOutputV1,
        RootReduceSummaryV1,
    },
    LeagueFractionV1,
};

#[derive(Debug)]
pub enum LysisFinalizationErrorV1 {
    Authority(&'static str),
    Protocol(ProtocolError),
    Artifact(LysisArtifactErrorV1),
    Planner(PlannerErrorV1),
}

impl core::fmt::Display for LysisFinalizationErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Authority(invariant) => {
                write!(
                    formatter,
                    "Lysis finalization authority mismatch: {invariant}"
                )
            }
            Self::Protocol(error) => write!(formatter, "Lysis finalization protocol: {error}"),
            Self::Artifact(error) => write!(formatter, "Lysis finalization artifact: {error}"),
            Self::Planner(error) => write!(formatter, "Lysis finalization planner: {error}"),
        }
    }
}

impl std::error::Error for LysisFinalizationErrorV1 {}

impl From<ProtocolError> for LysisFinalizationErrorV1 {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<LysisArtifactErrorV1> for LysisFinalizationErrorV1 {
    fn from(error: LysisArtifactErrorV1) -> Self {
        Self::Artifact(error)
    }
}

impl From<PlannerErrorV1> for LysisFinalizationErrorV1 {
    fn from(error: PlannerErrorV1) -> Self {
        Self::Planner(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizationUnitArtifactV1 {
    pub plan_ordinal: u32,
    pub position: PlannedUnitPositionV1,
    pub artifact: UnitArtifactV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizationResultChunkV1 {
    pub chunk_ordinal: u32,
    pub summary: RootReduceSummaryV1,
    pub output_manifest_entry: OutputManifestEntryV1,
    pub canonical_chunk_bytes: Vec<u8>,
}

pub struct VerifiedLysisFinalizationInputsV1<'a, U, C, B> {
    pub finalized_job_id: B256,
    pub intent: &'a JobIntentV1,
    pub input_manifest: &'a InputManifestV1,
    pub plan: &'a PlanCommitmentV1,
    pub root_reduce_summary: &'a RootReduceSummaryV1,
    pub unit_artifacts: U,
    pub result_chunks: C,
    pub bucket_records: B,
}

pub fn finalize_v1<U, C, B>(
    inputs: VerifiedLysisFinalizationInputsV1<'_, U, C, B>,
    limits: &SchemaLimits,
) -> Result<LysisResultV1, LysisFinalizationErrorV1>
where
    U: IntoIterator<Item = Result<FinalizationUnitArtifactV1, LysisFinalizationErrorV1>>,
    C: IntoIterator<Item = Result<FinalizationResultChunkV1, LysisFinalizationErrorV1>>,
    B: IntoIterator<Item = Result<ShuffleBucketRecordV1, LysisFinalizationErrorV1>>,
{
    validate_authority(&inputs, limits)?;
    let topology = LysisPlanTopologyV1::new(inputs.plan.primary_work_unit_count)?;
    let plan_hash = inputs.plan.plan_hash(limits)?;
    let exact_unit_count = topology.total_unit_count();
    let final_unit_ordinal = exact_unit_count
        .checked_sub(1)
        .ok_or(LysisFinalizationErrorV1::Authority("non-empty exact plan"))?;
    let mut unit_artifact_root =
        StreamingOrderedListRoot::new(ListKind::UnitSpecificationsArtifacts, final_unit_ordinal)?;
    let mut gratis_prefix_root = StreamingOrderedListRoot::new(
        ListKind::LysisGratisLeafPrefixes,
        inputs.plan.primary_work_unit_count,
    )?;
    let mut final_fractions = None;
    let mut final_summary_from_artifact = None;
    let mut next_unit_ordinal = 0_u32;

    for item in inputs.unit_artifacts {
        let item = item?;
        if item.plan_ordinal != next_unit_ordinal || item.plan_ordinal >= exact_unit_count {
            return Err(LysisFinalizationErrorV1::Authority(
                "exact plan artifact order",
            ));
        }
        let expected_position = topology.plan_position_at(item.plan_ordinal)?;
        if item.position != expected_position
            || item.artifact.protocol_bundle_hash != inputs.plan.protocol_bundle_hash
            || item.artifact.job_id != inputs.finalized_job_id
            || item.artifact.attempt != inputs.plan.attempt
            || item.artifact.phase != expected_position.phase()
        {
            return Err(LysisFinalizationErrorV1::Authority(
                "plan-bound unit artifact",
            ));
        }
        item.artifact.validate_semantics(limits)?;

        if item.plan_ordinal == final_unit_ordinal {
            final_summary_from_artifact = Some(require_final_root_output(
                &item.artifact,
                inputs.plan.primary_work_unit_count,
                limits,
            )?);
        } else {
            unit_artifact_root.push(
                item.artifact.artifact_digest(limits)?.as_slice(),
                B256::len_bytes(),
            )?;
        }

        if is_fixed_reduce_root(item.position, topology) {
            let output = decode_fixed_reduce_output(item.artifact.phase_payload(limits)?, limits)?;
            final_fractions = Some(output.ordered_fractions);
        }
        if let PlannedUnitPositionV1::TreeNode {
            phase: UnitPhase::GratisPrefixDown,
            level: 0,
            index,
        } = item.position
        {
            let GratisPrefixDownOutputV1::Leaf(prefix) =
                decode_gratis_prefix_down_output(item.artifact.phase_payload(limits)?, limits)?
            else {
                return Err(LysisFinalizationErrorV1::Authority(
                    "GratisPrefixDown leaf payload",
                ));
            };
            if prefix.segment_ordinal != index {
                return Err(LysisFinalizationErrorV1::Authority(
                    "GratisPrefixDown segment ordinal",
                ));
            }
            gratis_prefix_root.push(
                &encode_gratis_prefix_record(&prefix, limits)?,
                limits.max_bounded_bytes,
            )?;
        }

        next_unit_ordinal =
            next_unit_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "finalization unit cursor",
                })?;
    }
    if next_unit_ordinal != exact_unit_count {
        return Err(LysisFinalizationErrorV1::Authority(
            "complete exact plan artifacts",
        ));
    }
    let final_summary_from_artifact = final_summary_from_artifact.ok_or(
        LysisFinalizationErrorV1::Authority("final ROOT_REDUCE artifact"),
    )?;
    if &final_summary_from_artifact != inputs.root_reduce_summary {
        return Err(LysisFinalizationErrorV1::Authority(
            "final ROOT_REDUCE summary input",
        ));
    }
    let unit_artifact_root = unit_artifact_root.finish()?;
    let gratis_prefix_root = gratis_prefix_root.finish()?;
    let fractions = final_fractions.ok_or(LysisFinalizationErrorV1::Authority(
        "final Fidelity fraction table",
    ))?;
    let fidelity_fraction_root = fraction_root(&fractions, limits)?;

    let streamed = stream_result_chunks(
        inputs.finalized_job_id,
        inputs.plan,
        inputs.root_reduce_summary,
        plan_hash,
        inputs.result_chunks,
        limits,
    )?;
    let bucket_root =
        stream_bucket_records(inputs.root_reduce_summary, inputs.bucket_records, limits)?;
    if streamed.reduced_summary != *inputs.root_reduce_summary {
        return Err(LysisFinalizationErrorV1::Authority(
            "independently reduced ROOT_REDUCE summary",
        ));
    }
    require_global_nominal_conservation(
        streamed.eligible_nominal_total,
        streamed.tribute_nominal_total,
    )?;

    let frozen = &inputs.intent.frozen_metadosis_values;
    let unused_lysis = frozen
        .lysis_budget
        .checked_sub(streamed.nod_gratis_consumed)
        .ok_or(LysisFinalizationErrorV1::Authority(
            "Lysis consumption within frozen budget",
        ))?;
    let counts = ExactCountsV1 {
        tribute_count: streamed.tribute_count,
        nod_count: streamed.nod_count,
        bucket_count: streamed.bucket_count,
        contributor_count: streamed.contributor_count,
        semantic_event_count: 0,
    };
    let conservation = ConservationTotalsV1 {
        tribute_nominal_total: streamed.tribute_nominal_total,
        eligible_nominal_total: streamed.eligible_nominal_total,
        day_limit: frozen.day_limit,
        gratis_demand: frozen.gratis_demand,
        gratis_supply: frozen.gratis_supply,
        lysis_budget: frozen.lysis_budget,
        auction_base: frozen.auction_base,
        nod_gratis_consumed: streamed.nod_gratis_consumed,
        unused_lysis,
        carry_over_credit: unused_lysis,
        nod_cost_total: streamed.nod_cost_total,
    };
    let roots = ResultRootsV1 {
        nod_root: streamed.nod_root,
        bucket_root,
        contributor_root: streamed.contributor_root,
        output_manifest_root: streamed.output_manifest_root,
    };
    let carry_over_credit = CarryOverCreditActionV1 {
        source_wwd: inputs.intent.wwd,
        reason: CarryOverReason::UnusedLysis,
        amount: unused_lysis,
    };
    let metadosis_completion_summary = MetadosisCompletionSummaryV1 {
        wwd: inputs.intent.wwd,
        pending_nonce: inputs.intent.pending_nonce,
        day_type: frozen.day_type,
        tribute_nominal_total: streamed.tribute_nominal_total,
        day_limit: frozen.day_limit,
        gratis_demand: frozen.gratis_demand,
        gratis_supply: frozen.gratis_supply,
        lysis_budget: frozen.lysis_budget,
        auction_base: frozen.auction_base,
        nod_gratis_consumed: streamed.nod_gratis_consumed,
        unused_lysis,
        carry_over_credit: unused_lysis,
        status: CompletionStatus::Completed,
        logical_evaluation_height: inputs.intent.logical_evaluation_height,
        logical_evaluation_time: inputs.intent.logical_evaluation_time,
    };
    let mut result = LysisResultV1 {
        protocol_bundle_hash: inputs.plan.protocol_bundle_hash,
        job_id: inputs.finalized_job_id,
        attempt: inputs.plan.attempt,
        input_manifest_hash: inputs.plan.input_manifest_hash,
        plan_hash,
        unit_artifact_root,
        fidelity_fraction_root,
        gratis_prefix_root,
        result_chunk_count: inputs.plan.primary_work_unit_count,
        result_chunk_list_root: streamed.result_chunk_list_root,
        carry_over_credit,
        metadosis_completion_summary,
        tribute_count: streamed.tribute_count,
        tribute_nominal_total: streamed.tribute_nominal_total,
        unused_lysis,
        roots,
        counts,
        conservation,
        arithmetic_commitment: B256::ZERO,
        event_summary_hash: lysis_v1_empty_semantic_event_root()?,
    };
    result.arithmetic_commitment = hash_framed(
        outbe_ocomp_protocol::HashDomain::LysisArithmetic,
        &result.arithmetic_summary().encode_canonical(limits)?,
    )?;
    result.validate_semantics(limits)?;
    result.validate_finalized_intent(inputs.intent)?;
    Ok(result)
}

fn validate_authority<U, C, B>(
    inputs: &VerifiedLysisFinalizationInputsV1<'_, U, C, B>,
    limits: &SchemaLimits,
) -> Result<(), LysisFinalizationErrorV1> {
    inputs.intent.validate_semantics()?;
    let manifest_hash = inputs.input_manifest.manifest_hash(limits)?;
    let plan_hash = inputs.plan.plan_hash(limits)?;
    if inputs.finalized_job_id.is_zero()
        || inputs.finalized_job_id != inputs.plan.job_id
        || inputs.finalized_job_id != inputs.input_manifest.job_id
        || inputs.plan.protocol_bundle_hash != inputs.intent.protocol_bundle_hash
        || inputs.plan.protocol_bundle_hash != inputs.input_manifest.protocol_bundle_hash
        || inputs.plan.attempt != inputs.intent.attempt
        || inputs.plan.attempt != inputs.input_manifest.attempt
        || inputs.plan.input_manifest_hash != manifest_hash
        || inputs.plan.wwd != inputs.intent.wwd
        || inputs.plan.wwd != inputs.input_manifest.wwd
        || inputs.plan.lysis_budget != inputs.intent.frozen_metadosis_values.lysis_budget
        || inputs.plan.logical_evaluation_time != inputs.intent.logical_evaluation_time
        || inputs.plan.tribute_count != inputs.intent.authenticated_day_count
        || inputs.plan.tribute_count != inputs.input_manifest.tribute_count
        || inputs.input_manifest.tribute_nominal_total != inputs.intent.authenticated_day_nominal
        || inputs.root_reduce_summary.protocol_bundle_hash != inputs.plan.protocol_bundle_hash
        || inputs.root_reduce_summary.job_id != inputs.finalized_job_id
        || inputs.root_reduce_summary.attempt != inputs.plan.attempt
        || inputs.root_reduce_summary.plan_hash != plan_hash
    {
        return Err(LysisFinalizationErrorV1::Authority(
            "finalized intent, manifest, plan and root summary",
        ));
    }
    Ok(())
}

fn is_fixed_reduce_root(position: PlannedUnitPositionV1, topology: LysisPlanTopologyV1) -> bool {
    matches!(
        position,
        PlannedUnitPositionV1::TreeNode {
            phase: UnitPhase::FixedReduce,
            level,
            index: 0,
        } if level == topology.tree().height()
    )
}

fn require_final_root_output(
    artifact: &UnitArtifactV1,
    primary_count: u32,
    limits: &SchemaLimits,
) -> Result<RootReduceSummaryV1, LysisFinalizationErrorV1> {
    match (
        primary_count,
        decode_root_reduce_output(artifact.phase_payload(limits)?, limits)?,
    ) {
        (
            1,
            RootReduceOutputV1::Leaf {
                summary,
                output_manifest_entry: _,
            },
        ) => Ok(summary),
        (count, RootReduceOutputV1::Node { summary }) if count > 1 => Ok(summary),
        _ => Err(LysisFinalizationErrorV1::Authority(
            "final ROOT_REDUCE LEAF/NODE shape",
        )),
    }
}

fn fraction_root(
    fractions: &[LeagueFractionV1],
    limits: &SchemaLimits,
) -> Result<B256, LysisFinalizationErrorV1> {
    let count = u32::try_from(fractions.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "Fidelity fraction count",
    })?;
    let mut root = StreamingOrderedListRoot::new(ListKind::LysisLeagueFractions, count)?;
    let mut previous = None;
    for fraction in fractions {
        if previous.is_some_and(|league| league >= fraction.league) {
            return Err(LysisFinalizationErrorV1::Authority(
                "strict Fidelity fraction league order",
            ));
        }
        previous = Some(fraction.league);
        let mut record = CanonicalWriter::new(limits.codec);
        record.write_u16(fraction.league)?;
        record.write_u256(fraction.fraction)?;
        root.push(&record.into_bytes(), limits.max_bounded_bytes)?;
    }
    root.finish().map_err(Into::into)
}

fn encode_gratis_prefix_record(
    prefix: &GratisLeafPrefixV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let mut record = CanonicalWriter::new(limits.codec);
    record.write_u32(prefix.segment_ordinal)?;
    record.write_u256(prefix.incoming_remaining)?;
    record.write_u256(prefix.outgoing_remaining)?;
    record.write_option(prefix.first_error_ordinal.as_ref(), |writer, ordinal| {
        writer.write_u32(*ordinal)
    })?;
    Ok(record.into_bytes())
}

struct StreamedResultV1 {
    nod_root: B256,
    contributor_root: B256,
    output_manifest_root: B256,
    result_chunk_list_root: B256,
    reduced_summary: RootReduceSummaryV1,
    tribute_count: u32,
    nod_count: u32,
    bucket_count: u32,
    contributor_count: u32,
    tribute_nominal_total: U256,
    eligible_nominal_total: U256,
    nod_gratis_consumed: U256,
    nod_cost_total: U256,
}

fn stream_result_chunks<C>(
    job_id: B256,
    plan: &PlanCommitmentV1,
    final_summary: &RootReduceSummaryV1,
    plan_hash: B256,
    chunks: C,
    limits: &SchemaLimits,
) -> Result<StreamedResultV1, LysisFinalizationErrorV1>
where
    C: IntoIterator<Item = Result<FinalizationResultChunkV1, LysisFinalizationErrorV1>>,
{
    let mut nod_root =
        StreamingOrderedListRoot::new(ListKind::NodActions, final_summary.nod_count)?;
    let mut contributor_root = StreamingOrderedListRoot::new(
        ListKind::ContributorActions,
        final_summary.contributor_count,
    )?;
    let mut output_manifest_root = StreamingOrderedListRoot::new(
        ListKind::CompleteOutputManifest,
        plan.primary_work_unit_count,
    )?;
    let mut result_chunk_list_root =
        StreamingOrderedListRoot::new(ListKind::ResultChunkHashes, plan.primary_work_unit_count)?;
    let mut summary_frontier = SummaryFrontierV1::new();
    let mut next_chunk = 0_u32;
    let mut next_nod_ordinal = 0_u32;
    let mut previous_tribute = None;
    let mut previous_contributor = None;
    let mut tribute_count = 0_u32;
    let mut nod_count = 0_u32;
    let mut contributor_count = 0_u32;
    let mut tribute_nominal_total = U256::ZERO;
    let mut eligible_nominal_total = U256::ZERO;
    let mut nod_gratis_consumed = U256::ZERO;
    let mut nod_cost_total = U256::ZERO;

    for item in chunks {
        let item = item?;
        if item.chunk_ordinal != next_chunk || next_chunk >= plan.primary_work_unit_count {
            return Err(LysisFinalizationErrorV1::Authority(
                "exact result chunk order",
            ));
        }
        let chunk = ResultChunkV1::decode_canonical(&item.canonical_chunk_bytes, limits)?;
        if chunk.protocol_bundle_hash != plan.protocol_bundle_hash
            || chunk.job_id != job_id
            || chunk.attempt != plan.attempt
            || chunk.chunk_ordinal != next_chunk
            || chunk.first_nod_ordinal != next_nod_ordinal
            || item.output_manifest_entry.chunk_ordinal != next_chunk
            || item
                .output_manifest_entry
                .result_chunk_ref
                .expected_ocb1_kind
                != Some(ObjectKind::ResultChunkV1.tag())
            || item.output_manifest_entry.result_chunk_ref.encoded_bytes
                != u64::try_from(item.canonical_chunk_bytes.len()).map_err(|_| {
                    ProtocolError::IntegerOverflow {
                        what: "canonical ResultChunkV1 bytes",
                    }
                })?
            || item.output_manifest_entry.result_chunk_ref.transport_digest
                != keccak256(&item.canonical_chunk_bytes)
            || item.output_manifest_entry.result_chunk_hash != chunk.result_chunk_hash(limits)?
        {
            return Err(LysisFinalizationErrorV1::Authority(
                "exact result chunk descriptor",
            ));
        }
        let expected_start = next_chunk
            .checked_mul(plan.max_tributes_per_work_shard)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "result chunk start ordinal",
            })?;
        let expected_end = expected_start
            .saturating_add(plan.max_tributes_per_work_shard)
            .min(plan.tribute_count);
        let expected_nod_count =
            expected_end
                .checked_sub(expected_start)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk exact Nod count",
                })?;
        if chunk.first_nod_ordinal != expected_start
            || u32::try_from(chunk.ordered_nod_actions.len()).ok() != Some(expected_nod_count)
        {
            return Err(LysisFinalizationErrorV1::Authority(
                "result chunk primary shard coverage",
            ));
        }

        let mut nod_records = Vec::with_capacity(chunk.ordered_nod_actions.len());
        let mut bucket_records = Vec::with_capacity(chunk.ordered_nod_actions.len());
        for action in &chunk.ordered_nod_actions {
            if previous_tribute.is_some_and(|tribute| tribute >= action.tribute_id) {
                return Err(LysisFinalizationErrorV1::Authority(
                    "global Nod Tribute order",
                ));
            }
            previous_tribute = Some(action.tribute_id);
            let record = action.encode_canonical_record(limits)?;
            nod_root.push(&record, limits.max_bounded_bytes)?;
            nod_records.push(record);
            bucket_records.push(ShuffleBucketRecordV1 {
                bucket_key: action.bucket_key,
                raw_ordinal: action.raw_ordinal,
                tribute_id: action.tribute_id,
                nod_id: action.nod_id,
            });
            nod_gratis_consumed = checked_add(
                nod_gratis_consumed,
                action.gratis_load_minor,
                "Nod Gratis consumed",
            )?;
            nod_cost_total =
                checked_add(nod_cost_total, action.cost_amount_minor, "Nod cost total")?;
        }
        bucket_records.sort_by_key(|record| (record.bucket_key, record.raw_ordinal));
        let bucket_record_bytes = bucket_records
            .iter()
            .map(|record| record.encode_canonical_record(limits))
            .collect::<Result<Vec<_>, _>>()?;

        let mut contributor_records = Vec::with_capacity(chunk.ordered_eligible_contributors.len());
        let mut chunk_eligible = U256::ZERO;
        for action in &chunk.ordered_eligible_contributors {
            let key = (action.owner, action.source_tribute_id);
            if previous_contributor.is_some_and(|previous| previous >= key) {
                return Err(LysisFinalizationErrorV1::Authority(
                    "global contributor order",
                ));
            }
            previous_contributor = Some(key);
            let record = action.encode_canonical_record(limits)?;
            contributor_root.push(&record, limits.max_bounded_bytes)?;
            contributor_records.push(record);
            chunk_eligible = checked_add(
                chunk_eligible,
                action.nominal_amount_minor,
                "eligible nominal total",
            )?;
        }
        eligible_nominal_total = checked_add(
            eligible_nominal_total,
            chunk_eligible,
            "global eligible nominal total",
        )?;

        let manifest_record = item.output_manifest_entry.encode_canonical_record(limits)?;
        output_manifest_root.push(&manifest_record, limits.max_bounded_bytes)?;
        result_chunk_list_root.push(
            item.output_manifest_entry.result_chunk_hash.as_slice(),
            B256::len_bytes(),
        )?;
        require_leaf_summary(
            &item.summary,
            plan,
            plan_hash,
            next_chunk,
            &nod_records,
            &bucket_record_bytes,
            &contributor_records,
            &manifest_record,
            item.output_manifest_entry.result_chunk_hash,
            chunk_eligible,
            &chunk,
            limits,
        )?;
        let chunk_tribute_nominal_total = item.summary.tribute_nominal_total;
        summary_frontier.push(item.summary)?;

        let chunk_nod_count = u32::try_from(chunk.ordered_nod_actions.len()).map_err(|_| {
            ProtocolError::IntegerOverflow {
                what: "chunk Nod count",
            }
        })?;
        let chunk_contributor_count = u32::try_from(chunk.ordered_eligible_contributors.len())
            .map_err(|_| ProtocolError::IntegerOverflow {
                what: "chunk contributor count",
            })?;
        tribute_count =
            tribute_count
                .checked_add(chunk_nod_count)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Tribute count",
                })?;
        nod_count = nod_count
            .checked_add(chunk_nod_count)
            .ok_or(ProtocolError::IntegerOverflow { what: "Nod count" })?;
        contributor_count = contributor_count
            .checked_add(chunk_contributor_count)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "contributor count",
            })?;
        tribute_nominal_total = checked_add(
            tribute_nominal_total,
            chunk_tribute_nominal_total,
            "Tribute nominal total",
        )?;
        next_nod_ordinal = next_nod_ordinal.checked_add(chunk_nod_count).ok_or(
            ProtocolError::IntegerOverflow {
                what: "next Nod ordinal",
            },
        )?;
        next_chunk = next_chunk
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "next result chunk",
            })?;
    }
    if next_chunk != plan.primary_work_unit_count {
        return Err(LysisFinalizationErrorV1::Authority(
            "complete result chunk catalog",
        ));
    }
    let reduced_summary = summary_frontier.finish(
        plan.primary_work_unit_count,
        plan.protocol_bundle_hash,
        job_id,
        plan.attempt,
        plan_hash,
    )?;
    Ok(StreamedResultV1 {
        nod_root: nod_root.finish()?,
        contributor_root: contributor_root.finish()?,
        output_manifest_root: output_manifest_root.finish()?,
        result_chunk_list_root: result_chunk_list_root.finish()?,
        reduced_summary,
        tribute_count,
        nod_count,
        bucket_count: nod_count,
        contributor_count,
        tribute_nominal_total,
        eligible_nominal_total,
        nod_gratis_consumed,
        nod_cost_total,
    })
}

#[allow(clippy::too_many_arguments)]
fn require_leaf_summary(
    summary: &RootReduceSummaryV1,
    plan: &PlanCommitmentV1,
    plan_hash: B256,
    chunk_ordinal: u32,
    nod_records: &[Vec<u8>],
    bucket_records: &[Vec<u8>],
    contributor_records: &[Vec<u8>],
    manifest_record: &[u8],
    result_chunk_hash: B256,
    eligible_nominal_total: U256,
    chunk: &ResultChunkV1,
    limits: &SchemaLimits,
) -> Result<(), LysisFinalizationErrorV1> {
    let expected_nod = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::NodActions,
        chunk_ordinal,
        nod_records,
        limits.max_bounded_bytes,
    )?;
    let expected_bucket = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::BucketRecords,
        chunk_ordinal,
        bucket_records,
        limits.max_bounded_bytes,
    )?;
    let expected_contributor = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ContributorActions,
        chunk_ordinal,
        contributor_records,
        limits.max_bounded_bytes,
    )?;
    let expected_manifest = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::CompleteOutputManifest,
        chunk_ordinal,
        &[manifest_record],
        limits.max_bounded_bytes,
    )?;
    let expected_result_hash = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ResultChunkHashes,
        chunk_ordinal,
        &[result_chunk_hash.as_slice()],
        B256::len_bytes(),
    )?;
    let nod_gratis_consumed = chunk
        .ordered_nod_actions
        .iter()
        .try_fold(U256::ZERO, |total, action| {
            checked_add(total, action.gratis_load_minor, "leaf Nod Gratis")
        })?;
    let nod_cost_total = chunk
        .ordered_nod_actions
        .iter()
        .try_fold(U256::ZERO, |total, action| {
            checked_add(total, action.cost_amount_minor, "leaf Nod cost")
        })?;
    if summary.protocol_bundle_hash != plan.protocol_bundle_hash
        || summary.job_id != plan.job_id
        || summary.attempt != plan.attempt
        || summary.plan_hash != plan_hash
        || summary.covered_primary_start != chunk_ordinal
        || summary.covered_primary_count != 1
        || summary.nod_actions != expected_nod
        || summary.bucket_records != expected_bucket
        || summary.contributor_actions != expected_contributor
        || summary.output_manifest_entries != expected_manifest
        || summary.result_chunk_hashes != expected_result_hash
        || summary.tribute_count != u32::try_from(nod_records.len()).unwrap_or(u32::MAX)
        || summary.nod_count != u32::try_from(nod_records.len()).unwrap_or(u32::MAX)
        || summary.bucket_count != u32::try_from(bucket_records.len()).unwrap_or(u32::MAX)
        || summary.contributor_count != u32::try_from(contributor_records.len()).unwrap_or(u32::MAX)
        || summary.eligible_nominal_total != eligible_nominal_total
        || summary.nod_gratis_consumed != nod_gratis_consumed
        || summary.nod_cost_total != nod_cost_total
        || summary.first_error_ordinal.is_some()
    {
        return Err(LysisFinalizationErrorV1::Authority(
            "ROOT_REDUCE leaf summary from exact chunk",
        ));
    }
    Ok(())
}

fn stream_bucket_records<B>(
    final_summary: &RootReduceSummaryV1,
    records: B,
    limits: &SchemaLimits,
) -> Result<B256, LysisFinalizationErrorV1>
where
    B: IntoIterator<Item = Result<ShuffleBucketRecordV1, LysisFinalizationErrorV1>>,
{
    let mut root =
        StreamingOrderedListRoot::new(ListKind::BucketRecords, final_summary.bucket_count)?;
    let mut previous = None;
    let mut count = 0_u32;
    for record in records {
        let record = record?;
        let key = (record.bucket_key, record.raw_ordinal);
        if previous.is_some_and(|previous| previous >= key) {
            return Err(LysisFinalizationErrorV1::Authority(
                "global Bucket record order",
            ));
        }
        previous = Some(key);
        root.push(
            &record.encode_canonical_record(limits)?,
            limits.max_bounded_bytes,
        )?;
        count = count.checked_add(1).ok_or(ProtocolError::IntegerOverflow {
            what: "Bucket record count",
        })?;
    }
    if count != final_summary.bucket_count {
        return Err(LysisFinalizationErrorV1::Authority(
            "complete Bucket record catalog",
        ));
    }
    root.finish().map_err(Into::into)
}

struct SummaryFrontierV1 {
    levels: [Option<RootReduceSummaryV1>; 33],
}

impl SummaryFrontierV1 {
    fn new() -> Self {
        Self {
            levels: std::array::from_fn(|_| None),
        }
    }

    fn push(&mut self, mut summary: RootReduceSummaryV1) -> Result<(), LysisFinalizationErrorV1> {
        let mut level = usize::from(summary.result_chunk_hashes.subtree_height);
        let mut index = summary.result_chunk_hashes.subtree_index;
        loop {
            if index & 1 == 0 {
                if self.levels[level].replace(summary).is_some() {
                    return Err(LysisFinalizationErrorV1::Authority(
                        "summary frontier duplicate left node",
                    ));
                }
                return Ok(());
            }
            let left = self.levels[level]
                .take()
                .ok_or(LysisFinalizationErrorV1::Authority(
                    "summary frontier missing left node",
                ))?;
            summary = left.merge_adjacent(summary)?;
            index >>= 1;
            level = level
                .checked_add(1)
                .filter(|next| *next < self.levels.len())
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "summary frontier level",
                })?;
        }
    }

    fn finish(
        mut self,
        primary_count: u32,
        protocol_bundle_hash: B256,
        job_id: B256,
        attempt: u32,
        plan_hash: B256,
    ) -> Result<RootReduceSummaryV1, LysisFinalizationErrorV1> {
        let padded_count = if primary_count == 1 {
            1
        } else {
            primary_count
                .checked_next_power_of_two()
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "ROOT_REDUCE padded primary count",
                })?
        };
        for padded_ordinal in primary_count..padded_count {
            self.push(canonical_empty_summary(
                protocol_bundle_hash,
                job_id,
                attempt,
                plan_hash,
                padded_ordinal,
            )?)?;
        }
        let root_level = usize::try_from(padded_count.trailing_zeros()).map_err(|_| {
            ProtocolError::IntegerOverflow {
                what: "ROOT_REDUCE root level",
            }
        })?;
        let root = self.levels[root_level]
            .take()
            .ok_or(LysisFinalizationErrorV1::Authority(
                "complete ROOT_REDUCE summary frontier",
            ))?;
        if self.levels.into_iter().any(|entry| entry.is_some()) {
            return Err(LysisFinalizationErrorV1::Authority(
                "single ROOT_REDUCE summary frontier root",
            ));
        }
        Ok(root)
    }
}

fn canonical_empty_summary(
    protocol_bundle_hash: B256,
    job_id: B256,
    attempt: u32,
    plan_hash: B256,
    padded_ordinal: u32,
) -> Result<RootReduceSummaryV1, LysisFinalizationErrorV1> {
    Ok(RootReduceSummaryV1 {
        protocol_bundle_hash,
        job_id,
        attempt,
        plan_hash,
        covered_primary_start: padded_ordinal,
        covered_primary_count: 0,
        nod_actions: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::NodActions,
            padded_ordinal,
        )?,
        bucket_records: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::BucketRecords,
            padded_ordinal,
        )?,
        contributor_actions: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::ContributorActions,
            padded_ordinal,
        )?,
        output_manifest_entries: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::CompleteOutputManifest,
            padded_ordinal,
        )?,
        result_chunk_hashes: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::ResultChunkHashes,
            padded_ordinal,
        )?,
        tribute_count: 0,
        nod_count: 0,
        bucket_count: 0,
        contributor_count: 0,
        tribute_nominal_total: U256::ZERO,
        eligible_nominal_total: U256::ZERO,
        nod_gratis_consumed: U256::ZERO,
        nod_cost_total: U256::ZERO,
        first_error_ordinal: None,
    })
}

fn checked_add(
    left: U256,
    right: U256,
    what: &'static str,
) -> Result<U256, LysisFinalizationErrorV1> {
    left.checked_add(right)
        .ok_or(ProtocolError::IntegerOverflow { what }.into())
}

fn require_global_nominal_conservation(
    eligible_nominal_total: U256,
    tribute_nominal_total: U256,
) -> Result<(), LysisFinalizationErrorV1> {
    if eligible_nominal_total > tribute_nominal_total {
        return Err(LysisFinalizationErrorV1::Authority(
            "global eligible nominal within Tribute nominal",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_global_nominal_conservation;
    use alloy_primitives::U256;

    #[test]
    fn finalizer_enforces_nominal_conservation_only_at_the_global_root() {
        require_global_nominal_conservation(U256::from(2_000), U256::from(2_570))
            .expect("globally conserved totals");
        require_global_nominal_conservation(U256::from(2_570), U256::from(2_570))
            .expect("all Tribute can be eligible");
        assert!(require_global_nominal_conservation(U256::from(2_571), U256::from(2_570)).is_err());
    }
}
