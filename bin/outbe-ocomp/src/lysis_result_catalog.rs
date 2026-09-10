//! Bounded cold-restart closure of the exact Lysis V1 result-chunk catalog.
//!
//! Entries are discovered only through plan-derived ROOT_REDUCE leaves already
//! present in the durable admission catalog. Each cursor step opens at most one
//! CAS object. The yielded items and `Complete` are evidence inputs for a future
//! finalizer; neither is a result, signature, or finalization capability.

use alloy_primitives::{Address, B256, U256};
use outbe_lysis::program_v1::{
    artifacts::LysisArtifactErrorV1,
    planner::{
        LysisPlanTopologyV1, PaddedBinaryTreeV1, PlannedUnitPositionV1, PlannerErrorV1,
        PrimaryShardV1,
    },
    result::{
        decode_root_reduce_output, LysisListSubtreeCarrierV1, RootReduceOutputV1,
        RootReduceSummaryV1,
    },
};
use outbe_ocomp_protocol::{
    result::{OutputManifestEntryV1, ResultChunkV1},
    unit::UnitPhase,
    ListKind, ObjectKind, ProtocolError, StreamingOrderedListRoot,
};
use thiserror::Error;

use crate::{
    admission_catalog::{
        AdmissionCatalogError, AdmissionDirectoryCursorV1, AdmissionDirectoryStepV1,
    },
    cas::CasError,
    lysis_plan_audit::{ExactLysisPlanError, LocalLysisPlanAuditV1, PlanBoundLysisArtifactV1},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLysisResultChunkV1 {
    plan_ordinal: u32,
    producer_artifact_ref: outbe_ocomp_protocol::CasObjectRefV1,
    summary: RootReduceSummaryV1,
    output_manifest_entry: OutputManifestEntryV1,
    chunk: ResultChunkV1,
    canonical_chunk_bytes: Vec<u8>,
}

/// Opens one exact result chunk through its plan-derived ROOT_REDUCE leaf.
///
/// This addressable path performs no prefix scan. The leaf artifact, admitted
/// manifest entry, CAS object, and decoded chunk are all rebound to the frozen
/// plan before the chunk is returned.
pub fn verified_result_chunk_at(
    audit: &LocalLysisPlanAuditV1<'_>,
    chunk_ordinal: u32,
) -> Result<VerifiedLysisResultChunkV1, LysisResultCatalogError> {
    let topology = LysisPlanTopologyV1::new(audit.plan().primary_work_unit_count)?;
    if chunk_ordinal >= audit.plan().primary_work_unit_count {
        return Err(PlannerErrorV1::PlanPositionOutOfRange {
            ordinal: chunk_ordinal,
            total_unit_count: audit.plan().primary_work_unit_count,
        }
        .into());
    }
    let expected_position = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::RootReduce,
        level: 0,
        index: chunk_ordinal,
    };
    let plan_ordinal = topology.plan_ordinal_of(expected_position)?;
    let item = audit.verified_artifact_at(plan_ordinal)?;
    if item.position() != expected_position {
        return Err(
            ProtocolError::InvalidInvariant("result chunk producer ROOT_REDUCE position").into(),
        );
    }
    let admitted_entry = item
        .admission()
        .result_chunk
        .as_ref()
        .ok_or(ProtocolError::InvalidInvariant(
            "ROOT_REDUCE leaf admitted result entry",
        ))?
        .output_manifest_entry
        .clone();
    let (summary, embedded_entry) = decode_leaf(&item, audit.limits())?;
    if embedded_entry != admitted_entry {
        return Err(
            ProtocolError::InvalidInvariant("ROOT_REDUCE leaf admitted manifest entry").into(),
        );
    }
    let primary_shard = require_leaf_summary(&summary, audit, chunk_ordinal, &admitted_entry)?;
    if admitted_entry.result_chunk_ref.expected_ocb1_kind != Some(ObjectKind::ResultChunkV1.tag()) {
        return Err(ProtocolError::InvalidInvariant("result chunk descriptor object kind").into());
    }
    let object = audit
        .reader()
        .read_verified(&admitted_entry.result_chunk_ref)?;
    let canonical_chunk_bytes = object.bytes().to_vec();
    let chunk = ResultChunkV1::decode_canonical(&canonical_chunk_bytes, audit.limits())?;
    if chunk.protocol_bundle_hash != audit.plan().protocol_bundle_hash
        || chunk.job_id != audit.plan().job_id
        || chunk.attempt != audit.plan().attempt
        || chunk.chunk_ordinal != admitted_entry.chunk_ordinal
        || chunk.first_nod_ordinal != primary_shard.start_ordinal
        || chunk.result_chunk_hash(audit.limits())? != admitted_entry.result_chunk_hash
        || u32::try_from(chunk.ordered_nod_actions.len()).ok() != Some(summary.nod_count)
        || u32::try_from(chunk.ordered_eligible_contributors.len()).ok()
            != Some(summary.contributor_count)
    {
        return Err(ProtocolError::InvalidInvariant("exact result chunk semantic binding").into());
    }
    require_chunk_summary(&chunk, &summary, chunk_ordinal, audit.limits())?;
    Ok(VerifiedLysisResultChunkV1 {
        plan_ordinal,
        producer_artifact_ref: item.admission().artifact_ref.clone(),
        summary,
        output_manifest_entry: admitted_entry,
        chunk,
        canonical_chunk_bytes,
    })
}

impl VerifiedLysisResultChunkV1 {
    #[must_use]
    pub const fn plan_ordinal(&self) -> u32 {
        self.plan_ordinal
    }

    #[must_use]
    pub const fn producer_artifact_ref(&self) -> &outbe_ocomp_protocol::CasObjectRefV1 {
        &self.producer_artifact_ref
    }

    #[must_use]
    pub const fn summary(&self) -> &RootReduceSummaryV1 {
        &self.summary
    }

    #[must_use]
    pub const fn output_manifest_entry(&self) -> &OutputManifestEntryV1 {
        &self.output_manifest_entry
    }

    #[must_use]
    pub const fn chunk(&self) -> &ResultChunkV1 {
        &self.chunk
    }

    #[must_use]
    pub fn canonical_chunk_bytes(&self) -> &[u8] {
        &self.canonical_chunk_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LysisResultCatalogStepV1 {
    RootReduceLeafChecked { chunk_ordinal: u32 },
    Chunk(Box<VerifiedLysisResultChunkV1>),
    AdmissionRecordChecked { plan_ordinal: u32 },
    AdmissionCatalogEntryChecked,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LysisResultCatalogStageV1 {
    RootReduceLeaf,
    ResultChunk,
    AdmissionRecords,
    AdmissionCatalog,
    Complete,
}

struct PendingRootReduceLeafV1 {
    plan_ordinal: u32,
    expected_first_nod_ordinal: u32,
    summary: RootReduceSummaryV1,
    output_manifest_entry: OutputManifestEntryV1,
}

pub struct ExactLysisResultCatalogCursorV1<'a> {
    audit: &'a LocalLysisPlanAuditV1<'a>,
    topology: LysisPlanTopologyV1,
    next_chunk_ordinal: u32,
    next_admission_ordinal: u32,
    pending: Option<PendingRootReduceLeafV1>,
    admission_catalog: Option<AdmissionDirectoryCursorV1<'a>>,
    summary_eligible_nominal_total: U256,
    chunk_eligible_nominal_total: U256,
    previous_nod_tribute_id: Option<B256>,
    previous_contributor_key: Option<(Address, B256)>,
    observed_result_entries: Option<StreamingOrderedListRoot>,
    reloaded_result_entries: Option<StreamingOrderedListRoot>,
    stage: LysisResultCatalogStageV1,
    failed: bool,
}

impl<'a> ExactLysisResultCatalogCursorV1<'a> {
    pub fn open(audit: &'a LocalLysisPlanAuditV1<'a>) -> Result<Self, LysisResultCatalogError> {
        Ok(Self {
            audit,
            topology: LysisPlanTopologyV1::new(audit.plan().primary_work_unit_count)?,
            next_chunk_ordinal: 0,
            next_admission_ordinal: 0,
            pending: None,
            admission_catalog: None,
            summary_eligible_nominal_total: U256::ZERO,
            chunk_eligible_nominal_total: U256::ZERO,
            previous_nod_tribute_id: None,
            previous_contributor_key: None,
            observed_result_entries: Some(StreamingOrderedListRoot::new(
                ListKind::CompleteOutputManifest,
                audit.plan().primary_work_unit_count,
            )?),
            reloaded_result_entries: Some(StreamingOrderedListRoot::new(
                ListKind::CompleteOutputManifest,
                audit.plan().primary_work_unit_count,
            )?),
            stage: LysisResultCatalogStageV1::RootReduceLeaf,
            failed: false,
        })
    }

    fn advance(&mut self) -> Result<LysisResultCatalogStepV1, LysisResultCatalogError> {
        match self.stage {
            LysisResultCatalogStageV1::RootReduceLeaf => self.advance_root_reduce_leaf(),
            LysisResultCatalogStageV1::ResultChunk => self.advance_result_chunk(),
            LysisResultCatalogStageV1::AdmissionRecords => self.advance_admission_record(),
            LysisResultCatalogStageV1::AdmissionCatalog => self.advance_admission_catalog(),
            LysisResultCatalogStageV1::Complete => Err(ProtocolError::InvalidInvariant(
                "result catalog cursor already complete",
            )
            .into()),
        }
    }

    fn advance_root_reduce_leaf(
        &mut self,
    ) -> Result<LysisResultCatalogStepV1, LysisResultCatalogError> {
        let chunk_ordinal = self.next_chunk_ordinal;
        if chunk_ordinal >= self.audit.plan().primary_work_unit_count {
            if self.summary_eligible_nominal_total != self.chunk_eligible_nominal_total {
                return Err(
                    ProtocolError::InvalidInvariant("global eligible nominal total").into(),
                );
            }
            self.stage = LysisResultCatalogStageV1::AdmissionRecords;
            return self.advance_admission_record();
        }

        let expected_position = PlannedUnitPositionV1::TreeNode {
            phase: UnitPhase::RootReduce,
            level: 0,
            index: chunk_ordinal,
        };
        let plan_ordinal = self.topology.plan_ordinal_of(expected_position)?;
        let item = self.audit.verified_artifact_at(plan_ordinal)?;
        if item.position() != expected_position {
            return Err(ProtocolError::InvalidInvariant(
                "result chunk producer ROOT_REDUCE position",
            )
            .into());
        }
        let admitted_entry = item
            .admission()
            .result_chunk
            .as_ref()
            .ok_or(ProtocolError::InvalidInvariant(
                "ROOT_REDUCE leaf admitted result entry",
            ))?
            .output_manifest_entry
            .clone();
        let (summary, embedded_entry) = decode_leaf(&item, self.audit.limits())?;
        if embedded_entry != admitted_entry {
            return Err(ProtocolError::InvalidInvariant(
                "ROOT_REDUCE leaf admitted manifest entry",
            )
            .into());
        }
        self.observed_result_entries
            .as_mut()
            .ok_or(ProtocolError::InvalidInvariant(
                "observed result entry root",
            ))?
            .push(
                &admitted_entry.encode_canonical_record(self.audit.limits())?,
                self.audit.limits().max_bounded_bytes,
            )?;
        let primary_shard =
            require_leaf_summary(&summary, self.audit, chunk_ordinal, &admitted_entry)?;
        self.pending = Some(PendingRootReduceLeafV1 {
            plan_ordinal,
            expected_first_nod_ordinal: primary_shard.start_ordinal,
            summary,
            output_manifest_entry: admitted_entry,
        });
        self.stage = LysisResultCatalogStageV1::ResultChunk;
        Ok(LysisResultCatalogStepV1::RootReduceLeafChecked { chunk_ordinal })
    }

    fn advance_result_chunk(
        &mut self,
    ) -> Result<LysisResultCatalogStepV1, LysisResultCatalogError> {
        let pending = self
            .pending
            .take()
            .ok_or(ProtocolError::InvalidInvariant("pending ROOT_REDUCE leaf"))?;
        let entry = &pending.output_manifest_entry;
        if entry.result_chunk_ref.expected_ocb1_kind != Some(ObjectKind::ResultChunkV1.tag()) {
            return Err(
                ProtocolError::InvalidInvariant("result chunk descriptor object kind").into(),
            );
        }
        let object = self.audit.reader().read_verified(&entry.result_chunk_ref)?;
        let canonical_chunk_bytes = object.bytes().to_vec();
        let chunk = ResultChunkV1::decode_canonical(&canonical_chunk_bytes, self.audit.limits())?;
        if chunk.protocol_bundle_hash != self.audit.plan().protocol_bundle_hash
            || chunk.job_id != self.audit.plan().job_id
            || chunk.attempt != self.audit.plan().attempt
            || chunk.chunk_ordinal != entry.chunk_ordinal
            || chunk.first_nod_ordinal != pending.expected_first_nod_ordinal
            || chunk.result_chunk_hash(self.audit.limits())? != entry.result_chunk_hash
            || u32::try_from(chunk.ordered_nod_actions.len()).ok()
                != Some(pending.summary.nod_count)
            || u32::try_from(chunk.ordered_eligible_contributors.len()).ok()
                != Some(pending.summary.contributor_count)
        {
            return Err(
                ProtocolError::InvalidInvariant("exact result chunk semantic binding").into(),
            );
        }
        self.require_global_order(&chunk)?;
        let chunk_eligible_nominal_total = require_chunk_summary(
            &chunk,
            &pending.summary,
            entry.chunk_ordinal,
            self.audit.limits(),
        )?;
        self.summary_eligible_nominal_total = self
            .summary_eligible_nominal_total
            .checked_add(pending.summary.eligible_nominal_total)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "ROOT_REDUCE eligible nominal total",
            })?;
        self.chunk_eligible_nominal_total = self
            .chunk_eligible_nominal_total
            .checked_add(chunk_eligible_nominal_total)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "result chunk eligible nominal total",
            })?;

        self.next_chunk_ordinal =
            self.next_chunk_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk cursor",
                })?;
        self.stage = LysisResultCatalogStageV1::RootReduceLeaf;
        Ok(LysisResultCatalogStepV1::Chunk(Box::new(
            VerifiedLysisResultChunkV1 {
                plan_ordinal: pending.plan_ordinal,
                producer_artifact_ref: self
                    .audit
                    .plan_bound_admission_at(pending.plan_ordinal)?
                    .artifact_ref,
                summary: pending.summary,
                output_manifest_entry: pending.output_manifest_entry,
                chunk,
                canonical_chunk_bytes,
            },
        )))
    }

    fn require_global_order(
        &mut self,
        chunk: &ResultChunkV1,
    ) -> Result<(), LysisResultCatalogError> {
        for action in &chunk.ordered_nod_actions {
            if self
                .previous_nod_tribute_id
                .is_some_and(|previous| previous >= action.tribute_id)
            {
                return Err(
                    ProtocolError::InvalidInvariant("global result Nod TributeId order").into(),
                );
            }
            self.previous_nod_tribute_id = Some(action.tribute_id);
        }
        for action in &chunk.ordered_eligible_contributors {
            let key = (action.owner, action.source_tribute_id);
            if self
                .previous_contributor_key
                .is_some_and(|previous| previous >= key)
            {
                return Err(
                    ProtocolError::InvalidInvariant("global result contributor order").into(),
                );
            }
            self.previous_contributor_key = Some(key);
        }
        Ok(())
    }

    fn advance_admission_record(
        &mut self,
    ) -> Result<LysisResultCatalogStepV1, LysisResultCatalogError> {
        if self.next_admission_ordinal >= self.topology.total_unit_count() {
            let observed = self
                .observed_result_entries
                .take()
                .ok_or(ProtocolError::InvalidInvariant(
                    "observed result entry root",
                ))?
                .finish()?;
            let reloaded = self
                .reloaded_result_entries
                .take()
                .ok_or(ProtocolError::InvalidInvariant(
                    "reloaded result entry root",
                ))?
                .finish()?;
            if observed != reloaded {
                return Err(ProtocolError::InvalidInvariant(
                    "reloaded result entry content closure",
                )
                .into());
            }
            self.admission_catalog = Some(self.audit.bounded_admission_directory_cursor()?);
            self.stage = LysisResultCatalogStageV1::AdmissionCatalog;
            return self.advance_admission_catalog();
        }
        let plan_ordinal = self.next_admission_ordinal;
        let record = self.audit.plan_bound_admission_at(plan_ordinal)?;
        let position = self.topology.plan_position_at(plan_ordinal)?;
        match (position, record.result_chunk.as_ref()) {
            (
                PlannedUnitPositionV1::TreeNode {
                    phase: UnitPhase::RootReduce,
                    level: 0,
                    index,
                },
                Some(result),
            ) if result.output_manifest_entry.chunk_ordinal == index => {
                self.reloaded_result_entries
                    .as_mut()
                    .ok_or(ProtocolError::InvalidInvariant(
                        "reloaded result entry root",
                    ))?
                    .push(
                        &result
                            .output_manifest_entry
                            .encode_canonical_record(self.audit.limits())?,
                        self.audit.limits().max_bounded_bytes,
                    )?;
            }
            (
                PlannedUnitPositionV1::TreeNode {
                    phase: UnitPhase::RootReduce,
                    level: 0,
                    ..
                },
                _,
            ) => {
                return Err(
                    ProtocolError::InvalidInvariant("ROOT_REDUCE leaf result admission").into(),
                );
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(ProtocolError::InvalidInvariant("non-leaf result admission").into());
            }
        }
        self.next_admission_ordinal =
            self.next_admission_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result admission record cursor",
                })?;
        Ok(LysisResultCatalogStepV1::AdmissionRecordChecked { plan_ordinal })
    }

    fn advance_admission_catalog(
        &mut self,
    ) -> Result<LysisResultCatalogStepV1, LysisResultCatalogError> {
        let step = self
            .admission_catalog
            .as_mut()
            .and_then(Iterator::next)
            .ok_or(ProtocolError::InvalidInvariant(
                "result admission catalog closure",
            ))??;
        match step {
            AdmissionDirectoryStepV1::EntryChecked => {
                Ok(LysisResultCatalogStepV1::AdmissionCatalogEntryChecked)
            }
            AdmissionDirectoryStepV1::Complete => {
                self.stage = LysisResultCatalogStageV1::Complete;
                Ok(LysisResultCatalogStepV1::Complete)
            }
        }
    }
}

impl Iterator for ExactLysisResultCatalogCursorV1<'_> {
    type Item = Result<LysisResultCatalogStepV1, LysisResultCatalogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.stage == LysisResultCatalogStageV1::Complete {
            return None;
        }
        let step = self.advance();
        if step.is_err() {
            self.failed = true;
        }
        Some(step)
    }
}

fn decode_leaf(
    item: &PlanBoundLysisArtifactV1,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> Result<(RootReduceSummaryV1, OutputManifestEntryV1), LysisResultCatalogError> {
    let RootReduceOutputV1::Leaf {
        summary,
        output_manifest_entry,
    } = decode_root_reduce_output(item.artifact().phase_payload(limits)?, limits)?
    else {
        return Err(ProtocolError::InvalidInvariant("ROOT_REDUCE leaf payload").into());
    };
    let header = item.artifact().output_header(limits)?;
    if header.source_coverage_root != summary.result_chunk_hashes.tree_root
        || header.output_coverage_root != summary.result_chunk_hashes.tree_root
        || header.source_coverage_count != 1
        || header.output_coverage_count != 1
    {
        return Err(ProtocolError::InvalidInvariant("ROOT_REDUCE leaf output header").into());
    }
    Ok((summary, output_manifest_entry))
}

fn require_leaf_summary(
    summary: &RootReduceSummaryV1,
    audit: &LocalLysisPlanAuditV1<'_>,
    chunk_ordinal: u32,
    entry: &OutputManifestEntryV1,
) -> Result<PrimaryShardV1, LysisResultCatalogError> {
    let plan = audit.plan();
    let primary_shard = expected_primary_shard(plan.tribute_count, chunk_ordinal)?;
    let expected_count = primary_shard
        .end_ordinal
        .checked_sub(primary_shard.start_ordinal)
        .ok_or(PlannerErrorV1::IntegerOverflow)?;
    if summary.protocol_bundle_hash != plan.protocol_bundle_hash
        || summary.job_id != plan.job_id
        || summary.attempt != plan.attempt
        || summary.plan_hash != plan.plan_hash(audit.limits())?
        || summary.covered_primary_start != chunk_ordinal
        || summary.covered_primary_count != 1
        || summary.tribute_count != expected_count
        || summary.nod_count != expected_count
        || summary.bucket_count != expected_count
        || summary.first_error_ordinal.is_some()
        || entry.chunk_ordinal != chunk_ordinal
    {
        return Err(
            ProtocolError::InvalidInvariant("exact ROOT_REDUCE leaf summary binding").into(),
        );
    }
    Ok(primary_shard)
}

fn expected_primary_shard(
    tribute_count: u32,
    chunk_ordinal: u32,
) -> Result<PrimaryShardV1, PlannerErrorV1> {
    PaddedBinaryTreeV1::for_tribute_count(tribute_count)?.primary_shard(chunk_ordinal)
}

fn require_chunk_summary(
    chunk: &ResultChunkV1,
    summary: &RootReduceSummaryV1,
    chunk_ordinal: u32,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> Result<U256, LysisResultCatalogError> {
    let nod_records = chunk
        .ordered_nod_actions
        .iter()
        .map(|action| action.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    let contributor_records = chunk
        .ordered_eligible_contributors
        .iter()
        .map(|action| action.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    let nod_actions = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::NodActions,
        chunk_ordinal,
        &nod_records,
        limits.max_bounded_bytes,
    )?;
    let contributor_actions = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ContributorActions,
        chunk_ordinal,
        &contributor_records,
        limits.max_bounded_bytes,
    )?;
    let eligible_nominal_total = chunk.ordered_eligible_contributors.iter().try_fold(
        alloy_primitives::U256::ZERO,
        |total, action| {
            total
                .checked_add(action.nominal_amount_minor)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk eligible nominal total",
                })
        },
    )?;
    let nod_gratis_consumed = chunk.ordered_nod_actions.iter().try_fold(
        alloy_primitives::U256::ZERO,
        |total, action| {
            total
                .checked_add(action.gratis_load_minor)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk Nod Gratis total",
                })
        },
    )?;
    let nod_cost_total = chunk.ordered_nod_actions.iter().try_fold(
        alloy_primitives::U256::ZERO,
        |total, action| {
            total
                .checked_add(action.cost_amount_minor)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk Nod cost total",
                })
        },
    )?;
    if summary.nod_actions != nod_actions
        || summary.contributor_actions != contributor_actions
        || summary.nod_gratis_consumed != nod_gratis_consumed
        || summary.nod_cost_total != nod_cost_total
    {
        return Err(
            ProtocolError::InvalidInvariant("result chunk ROOT_REDUCE carrier binding").into(),
        );
    }
    Ok(eligible_nominal_total)
}

#[derive(Debug, Error)]
pub enum LysisResultCatalogError {
    #[error(transparent)]
    Planner(#[from] PlannerErrorV1),
    #[error(transparent)]
    Plan(#[from] ExactLysisPlanError),
    #[error(transparent)]
    Admission(#[from] AdmissionCatalogError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    LysisArtifact(#[from] LysisArtifactErrorV1),
}

#[cfg(test)]
mod tests {
    use super::expected_primary_shard;

    #[test]
    fn last_u32_max_tribute_shard_has_no_artificial_overflow() {
        let tree =
            outbe_lysis::program_v1::planner::PaddedBinaryTreeV1::for_tribute_count(u32::MAX)
                .unwrap();
        let ordinal = tree.primary_leaf_count() - 1;
        let shard = expected_primary_shard(u32::MAX, ordinal).unwrap();
        assert_eq!(shard.start_ordinal, 4_294_967_040);
        assert_eq!(shard.end_ordinal, u32::MAX);
        assert_eq!(shard.end_ordinal - shard.start_ordinal, 255);
    }
}
