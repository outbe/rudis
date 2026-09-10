//! Bounded cold-restart cursor over the final authoritative BucketShuffle run.

use outbe_lysis::program_v1::planner::{LysisPlanTopologyV1, PlannedUnitPositionV1};
use outbe_ocomp_protocol::{
    shuffle::{
        verified_shuffle_run_records, ShuffleRunArtifactV1, ShuffleRunKindV1,
        VerifiedShuffleRecordV1,
    },
    unit::{UnitArtifactV1, UnitPhase},
    ProtocolError, SchemaLimits,
};
use thiserror::Error;

use crate::{
    admission_catalog::{AdmissionCatalogError, VerifiedAdmissionCatalog},
    cas::{CasError, FilesystemCasReader},
};

#[derive(Debug, Error)]
pub enum AuthoritativeBucketShuffleError {
    #[error(transparent)]
    Admission(#[from] AdmissionCatalogError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

pub fn authoritative_bucket_shuffle_records<'a>(
    catalog: &'a VerifiedAdmissionCatalog,
    reader: &'a FilesystemCasReader,
    limits: &'a SchemaLimits,
) -> Result<
    impl Iterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>> + 'a,
    AuthoritativeBucketShuffleError,
> {
    let authority = catalog.plan_authority();
    let topology = LysisPlanTopologyV1::new(authority.primary_work_unit_count)
        .map_err(|_| ProtocolError::InvalidInvariant("BucketShuffle plan topology"))?;
    let phase_unit_count = topology.phase_unit_count(UnitPhase::BucketShuffle);
    let phase_ordinal = phase_unit_count
        .checked_sub(1)
        .ok_or(ProtocolError::InvalidInvariant(
            "final BucketShuffle phase ordinal",
        ))?;
    let position = topology
        .phase_position_at(UnitPhase::BucketShuffle, phase_ordinal)
        .map_err(|_| ProtocolError::InvalidInvariant("final BucketShuffle plan position"))?;
    let PlannedUnitPositionV1::RunSpan {
        start_run, end_run, ..
    } = position
    else {
        return Err(ProtocolError::InvalidInvariant("final BucketShuffle run position").into());
    };
    if start_run != 0 || end_run != authority.primary_work_unit_count {
        return Err(ProtocolError::InvalidInvariant("complete BucketShuffle run span").into());
    }
    let plan_ordinal = topology
        .phase_offset(UnitPhase::BucketShuffle)
        .map_err(|_| ProtocolError::InvalidInvariant("BucketShuffle phase offset"))?
        .checked_add(phase_ordinal)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "final BucketShuffle plan ordinal",
        })?;
    let admission = catalog.read(plan_ordinal)?;
    if admission.protocol_bundle_hash != authority.protocol_bundle_hash
        || admission.job_id != authority.job_id
        || admission.attempt != authority.attempt
        || admission.plan_hash != authority.plan_hash
    {
        return Err(
            ProtocolError::InvalidInvariant("final BucketShuffle admission authority").into(),
        );
    }
    let object = reader.read_verified(&admission.artifact_ref)?;
    let artifact = UnitArtifactV1::decode_canonical(object.bytes(), limits)?;
    artifact.validate_semantics(limits)?;
    if artifact.protocol_bundle_hash != authority.protocol_bundle_hash
        || artifact.job_id != authority.job_id
        || artifact.attempt != authority.attempt
        || artifact.unit_id != admission.unit_id
        || artifact.phase != UnitPhase::BucketShuffle
    {
        return Err(ProtocolError::InvalidInvariant("final BucketShuffle unit artifact").into());
    }
    let root = ShuffleRunArtifactV1::decode_canonical(artifact.phase_payload(limits)?, limits)?;
    root.validate_root_semantics(limits)?;
    let header = artifact.output_header(limits)?;
    if root.protocol_bundle_hash != authority.protocol_bundle_hash
        || root.job_id != authority.job_id
        || root.attempt != authority.attempt
        || root.unit_id != admission.unit_id
        || root.kind != ShuffleRunKindV1::Bucket
        || root.run_span.start_run != 0
        || root.run_span.end_run != authority.primary_work_unit_count
        || root.source_coverage_root != header.source_coverage_root
        || root.source_coverage_count != authority.tribute_count
        || root.source_coverage_count != header.source_coverage_count
        || root.ordered_record_root != header.output_coverage_root
        || root.record_count != authority.tribute_count
        || root.record_count != header.output_coverage_count
    {
        return Err(
            ProtocolError::InvalidInvariant("complete authoritative BucketShuffle root").into(),
        );
    }

    verified_shuffle_run_records(root, limits, move |reference| {
        reader
            .read_verified(reference)
            .map(|child| child.bytes().to_vec())
            .map_err(|_| ProtocolError::InvalidInvariant("authoritative BucketShuffle descendant"))
    })
    .map_err(AuthoritativeBucketShuffleError::from)
}
