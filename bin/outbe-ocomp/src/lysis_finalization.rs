//! Supervisor host for the closed Lysis V1 finalizer.
//!
//! All cursor items originate from cold-reloaded durable admission/CAS state.
//! The returned capability has no public constructor and is the only local
//! value later signing code may accept.

use alloy_primitives::B256;
use outbe_lysis::program_v1::{
    finalizer::{
        finalize_v1, FinalizationResultChunkV1, FinalizationUnitArtifactV1,
        LysisFinalizationErrorV1, VerifiedLysisFinalizationInputsV1,
    },
    planner::LysisPlanTopologyV1,
    result::{decode_root_reduce_output, RootReduceOutputV1},
};
use outbe_ocomp_protocol::{
    intent::JobIntentV1, result::LysisResultV1, shuffle::VerifiedShuffleRecordV1, CasObjectRefV1,
    ObjectKind, ProtocolError, SchemaLimits,
};
use thiserror::Error;

use crate::{
    bucket_shuffle_cursor::{
        authoritative_bucket_shuffle_records, AuthoritativeBucketShuffleError,
    },
    cas::{CasError, FilesystemCas, FilesystemCasReader},
    lysis_plan_audit::{ExactLysisPlanError, LocalLysisPlanAuditV1, LysisPlanAuditStepV1},
    lysis_result_catalog::{
        ExactLysisResultCatalogCursorV1, LysisResultCatalogError, LysisResultCatalogStepV1,
    },
    supervisor::DiscoveryRecord,
};

#[derive(Debug, Error)]
pub enum HostedLysisFinalizationError {
    #[error(transparent)]
    PlanAudit(#[from] ExactLysisPlanError),
    #[error(transparent)]
    ResultCatalog(#[from] LysisResultCatalogError),
    #[error(transparent)]
    BucketCatalog(#[from] AuthoritativeBucketShuffleError),
    #[error(transparent)]
    Finalizer(#[from] LysisFinalizationErrorV1),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("finalized job specification is not the exact audited plan authority")]
    FinalizedJobAuthority,
    #[error("finalizer result did not survive exact content-addressed reload")]
    ResultReloadMismatch,
}

pub struct VerifiedLysisFinalizationV1 {
    result_ref: CasObjectRefV1,
    result: LysisResultV1,
    result_digest: B256,
    canonical_result_bytes: Vec<u8>,
}

impl VerifiedLysisFinalizationV1 {
    #[must_use]
    pub const fn result_ref(&self) -> &CasObjectRefV1 {
        &self.result_ref
    }

    #[must_use]
    pub const fn result(&self) -> &LysisResultV1 {
        &self.result
    }

    #[must_use]
    pub const fn result_digest(&self) -> B256 {
        self.result_digest
    }

    #[must_use]
    pub fn canonical_result_bytes(&self) -> &[u8] {
        &self.canonical_result_bytes
    }
}

pub fn finalize_verified_lysis_v1(
    discovery: &DiscoveryRecord,
    audit: &LocalLysisPlanAuditV1<'_>,
    cas: &FilesystemCas,
    reader: &FilesystemCasReader,
    limits: &SchemaLimits,
) -> Result<VerifiedLysisFinalizationV1, HostedLysisFinalizationError> {
    let plan = audit.plan();
    let summary = &discovery.spec.summary;
    if discovery.cursor != summary.cursor
        || summary.job_id != plan.job_id
        || summary.protocol_bundle_hash != plan.protocol_bundle_hash
        || plan.input_manifest_hash != audit.manifest().manifest_hash(limits)?
    {
        return Err(HostedLysisFinalizationError::FinalizedJobAuthority);
    }
    let intent = JobIntentV1::decode_canonical(&discovery.spec.canonical_job_intent.0, limits)?;

    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)
        .map_err(LysisFinalizationErrorV1::from)?;
    let final_ordinal =
        topology
            .total_unit_count()
            .checked_sub(1)
            .ok_or(LysisFinalizationErrorV1::Authority(
                "non-empty exact Lysis plan",
            ))?;
    let final_artifact = audit.verified_artifact_at(final_ordinal)?;
    let final_summary =
        match decode_root_reduce_output(final_artifact.artifact().phase_payload(limits)?, limits)
            .map_err(LysisFinalizationErrorV1::from)?
        {
            RootReduceOutputV1::Leaf { summary, .. } | RootReduceOutputV1::Node { summary } => {
                summary
            }
        };

    let units = audit.audit_cursor()?.filter_map(|step| match step {
        Ok(LysisPlanAuditStepV1::Artifact(item)) => Some(Ok(FinalizationUnitArtifactV1 {
            plan_ordinal: item.plan_ordinal(),
            position: item.position(),
            artifact: item.artifact().clone(),
        })),
        Ok(_) => None,
        Err(_) => Some(Err(LysisFinalizationErrorV1::Authority(
            "cold-reloaded exact plan audit cursor",
        ))),
    });
    let chunks = ExactLysisResultCatalogCursorV1::open(audit)?.filter_map(|step| match step {
        Ok(LysisResultCatalogStepV1::Chunk(chunk)) => Some(Ok(FinalizationResultChunkV1 {
            chunk_ordinal: chunk.output_manifest_entry().chunk_ordinal,
            summary: chunk.summary().clone(),
            output_manifest_entry: chunk.output_manifest_entry().clone(),
            canonical_chunk_bytes: chunk.canonical_chunk_bytes().to_vec(),
        })),
        Ok(_) => None,
        Err(_) => Some(Err(LysisFinalizationErrorV1::Authority(
            "cold-reloaded exact result catalog cursor",
        ))),
    });
    let buckets =
        authoritative_bucket_shuffle_records(audit.admissions(), reader, limits)?.map(|record| {
            match record {
                Ok(VerifiedShuffleRecordV1::Bucket(bucket)) => Ok(bucket),
                Ok(VerifiedShuffleRecordV1::Owner(_)) => Err(LysisFinalizationErrorV1::Authority(
                    "BucketShuffle cursor record kind",
                )),
                Err(_) => Err(LysisFinalizationErrorV1::Authority(
                    "cold-reloaded authoritative BucketShuffle cursor",
                )),
            }
        });
    let result = finalize_v1(
        VerifiedLysisFinalizationInputsV1 {
            finalized_job_id: summary.job_id,
            intent: &intent,
            input_manifest: audit.manifest(),
            plan,
            root_reduce_summary: &final_summary,
            unit_artifacts: units,
            result_chunks: chunks,
            bucket_records: buckets,
        },
        limits,
    )?;
    let canonical_result_bytes = result.encode_canonical(limits)?;
    let mut result_ref = cas.publish_bytes(&canonical_result_bytes)?;
    result_ref.expected_ocb1_kind = Some(ObjectKind::LysisResultV1.tag());
    let reloaded = reader.read_verified(&result_ref)?;
    let reloaded_result = LysisResultV1::decode_canonical(reloaded.bytes(), limits)?;
    if reloaded.bytes() != canonical_result_bytes || reloaded_result != result {
        return Err(HostedLysisFinalizationError::ResultReloadMismatch);
    }
    let result_digest = result.result_digest(limits)?;
    Ok(VerifiedLysisFinalizationV1 {
        result_ref,
        result,
        result_digest,
        canonical_result_bytes,
    })
}
