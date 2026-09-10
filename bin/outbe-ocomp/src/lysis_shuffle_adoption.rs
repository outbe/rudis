//! Supervisor-side adoption of one verified Lysis shuffle object closure.

use outbe_ocomp_protocol::{
    input::InputManifestV1,
    profile::ProtocolBundleV1,
    shuffle::{verified_shuffle_run_records, ShuffleRunArtifactV1},
    unit::{PlanCommitmentV1, UnitArtifactV1, UnitPhase, UnitSpecV1},
    CasObjectRefV1, ObjectKind, ProtocolError, SchemaLimits, UnitFinishedStatus, UnitFinishedV1,
};
use thiserror::Error;

use crate::{
    admission_catalog::{
        AdmissionCatalogError, AdmissionOutcome, AdmissionPositionV1, VerifiedAdmissionCatalog,
    },
    cas::{CasError, FilesystemCas, FilesystemCasReader},
    inbox::{WorkerInbox, WorkerInboxError},
    worker::{execute_unit, UnitExecutionAuthority},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptedLysisShuffleClosureV1 {
    pub descendant_object_count: u32,
    pub verified_record_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLysisShuffleUnitV1 {
    pub artifact_ref: CasObjectRefV1,
    pub closure: AdoptedLysisShuffleClosureV1,
    pub admission: AdmissionOutcome,
}

#[derive(Debug, Error)]
pub enum LysisShuffleAdoptionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Inbox(#[from] WorkerInboxError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    AdmissionCatalog(#[from] AdmissionCatalogError),
    #[error("worker-independent shuffle replay failed")]
    ReplayExecutionFailed,
    #[error("reported shuffle artifact differs from deterministic replay")]
    ReplayMismatch,
}

/// Re-executes one complete shuffle unit into a supervisor-owned replay inbox
/// and requires the worker's root artifact to match byte-for-byte.
///
/// Descendant adoption remains a separate pass below: replay proves the
/// deterministic transform, while adoption proves the exact reported
/// content-addressed closure is available and well formed.
#[allow(clippy::too_many_arguments)]
pub fn verify_lysis_shuffle_phase_replay(
    plan_ordinal: u32,
    spec: &UnitSpecV1,
    reported: &UnitArtifactV1,
    plan: &PlanCommitmentV1,
    manifest: &InputManifestV1,
    producer_artifacts: &[UnitArtifactV1],
    bundle: &ProtocolBundleV1,
    reader: &FilesystemCasReader,
    replay_inbox: &WorkerInbox,
    limits: &SchemaLimits,
) -> Result<(), LysisShuffleAdoptionError> {
    if !matches!(
        spec.phase,
        UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle
    ) {
        return Err(ProtocolError::InvalidInvariant("shuffle replay phase").into());
    }
    reported.validate_against(spec, limits)?;
    let expected = execute_unit(
        spec,
        UnitExecutionAuthority {
            plan,
            unit_index: plan_ordinal,
            manifest,
            input_chunks: &[],
            producer_artifacts,
            bundle,
            limits,
            reader,
            inbox: replay_inbox,
            cancelled: None,
        },
    )
    .map_err(|_| LysisShuffleAdoptionError::ReplayExecutionFailed)?;
    if expected.encode_canonical(limits)? != reported.encode_canonical(limits)? {
        return Err(LysisShuffleAdoptionError::ReplayMismatch);
    }
    Ok(())
}

/// Makes one reported shuffle unit ready only after its complete descendant
/// closure has been verified and copied into authoritative CAS.
pub fn admit_reported_lysis_shuffle_unit(
    position: AdmissionPositionV1,
    spec: &UnitSpecV1,
    finished: &UnitFinishedV1,
    inbox: &WorkerInbox,
    cas: &FilesystemCas,
    catalog: &mut VerifiedAdmissionCatalog,
    limits: &SchemaLimits,
) -> Result<AdmittedLysisShuffleUnitV1, LysisShuffleAdoptionError> {
    spec.validate_semantics(limits)?;
    let unit_id = spec.unit_id(limits)?;
    if finished.status != UnitFinishedStatus::Success || finished.unit_id != unit_id {
        return Err(ProtocolError::InvalidInvariant("successful shuffle unit report").into());
    }
    let reported = inbox.read_reported(
        finished.unit_id,
        finished.exact_staged_bytes,
        finished.transport_digest,
    )?;
    let artifact = UnitArtifactV1::decode_canonical(reported.bytes(), limits)?;
    artifact.validate_against(spec, limits)?;
    let expected_kind = match spec.phase {
        UnitPhase::OwnerShuffle => outbe_ocomp_protocol::shuffle::ShuffleRunKindV1::Owner,
        UnitPhase::BucketShuffle => outbe_ocomp_protocol::shuffle::ShuffleRunKindV1::Bucket,
        _ => {
            return Err(
                ProtocolError::InvalidInvariant("reported unit is a Lysis shuffle phase").into(),
            );
        }
    };
    let root = ShuffleRunArtifactV1::decode_canonical(artifact.phase_payload(limits)?, limits)?;
    root.validate_root_semantics(limits)?;
    let header = artifact.output_header(limits)?;
    if root.protocol_bundle_hash != spec.protocol_bundle_hash
        || root.job_id != spec.job_id
        || root.attempt != spec.attempt
        || root.unit_id != artifact.unit_id
        || root.kind != expected_kind
        || root.source_coverage_root != header.source_coverage_root
        || root.source_coverage_count != header.source_coverage_count
        || root.ordered_record_root != header.output_coverage_root
        || root.record_count != header.output_coverage_count
    {
        return Err(ProtocolError::InvalidInvariant("reported shuffle root binding").into());
    }

    let closure = adopt_lysis_shuffle_descendants(root.clone(), inbox, cas, limits)?;
    if closure.verified_record_count != root.record_count {
        return Err(ProtocolError::InvalidInvariant("admitted shuffle record count").into());
    }

    let mut artifact_ref = cas.publish_bytes(reported.bytes())?;
    if artifact_ref.transport_digest != finished.transport_digest
        || artifact_ref.encoded_bytes != finished.exact_staged_bytes
    {
        return Err(ProtocolError::InvalidInvariant("published shuffle unit descriptor").into());
    }
    artifact_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    cas.read_verified(&artifact_ref)?;
    let admission = catalog.admit_verified_unit(position, spec, artifact_ref.clone(), None)?;
    Ok(AdmittedLysisShuffleUnitV1 {
        artifact_ref,
        closure,
        admission,
    })
}

/// Verifies the complete bounded page tree from the worker inbox while
/// publishing each digest-valid descendant into the authoritative CAS.
///
/// The root remains embedded in its `UnitArtifactV1`; only referenced
/// descendants are required in CAS. Content-addressed objects published before
/// a later validation failure are unreachable orphans, never an admitted unit.
pub fn adopt_lysis_shuffle_descendants(
    root: ShuffleRunArtifactV1,
    inbox: &WorkerInbox,
    cas: &FilesystemCas,
    limits: &SchemaLimits,
) -> Result<AdoptedLysisShuffleClosureV1, LysisShuffleAdoptionError> {
    let mut descendant_object_count = 0_u32;
    let records = verified_shuffle_run_records(root, limits, |reference| {
        let object = inbox.read_shuffle_object(reference, limits).map_err(|_| {
            ProtocolError::InvalidInvariant("worker shuffle descendant unavailable")
        })?;
        let published = cas.publish_bytes(object.bytes()).map_err(|_| {
            ProtocolError::InvalidInvariant("authoritative shuffle CAS publication")
        })?;
        if published.transport_digest != reference.transport_digest
            || published.encoded_bytes != reference.encoded_bytes
            || reference.expected_ocb1_kind != Some(ObjectKind::ShuffleRunArtifactV1.tag())
        {
            return Err(ProtocolError::InvalidInvariant(
                "published shuffle descendant descriptor",
            ));
        }
        descendant_object_count =
            descendant_object_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "adopted shuffle descendant count",
                })?;
        Ok(object.bytes().to_vec())
    })?;
    let mut verified_record_count = 0_u32;
    for record in records {
        let _ = record?;
        verified_record_count =
            verified_record_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "adopted shuffle record count",
                })?;
    }
    Ok(AdoptedLysisShuffleClosureV1 {
        descendant_object_count,
        verified_record_count,
    })
}
