//! Supervisor-side adoption of one ROOT_REDUCE result chunk.

use outbe_lysis::program_v1::{
    artifacts::LysisArtifactErrorV1,
    result::{decode_root_reduce_output, RootReduceOutputV1},
};
use outbe_ocomp_protocol::{
    input::InputManifestV1,
    profile::ProtocolBundleV1,
    result::ResultChunkV1,
    unit::{
        BinaryReducerNode, PlanCommitmentV1, UnitArtifactV1, UnitInterval, UnitPhase, UnitSpecV1,
    },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptedLysisResultChunkV1 {
    pub chunk_ordinal: u32,
    pub nod_count: u32,
    pub contributor_count: u32,
    pub authoritative_ref: CasObjectRefV1,
    pub output_manifest_entry: outbe_ocomp_protocol::result::OutputManifestEntryV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLysisRootReduceLeafV1 {
    pub artifact_ref: CasObjectRefV1,
    pub chunk: AdoptedLysisResultChunkV1,
    pub admission: AdmissionOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLysisRootReduceNodeV1 {
    pub artifact_ref: CasObjectRefV1,
    pub admission: AdmissionOutcome,
}

#[derive(Debug, Error)]
pub enum LysisResultAdoptionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Inbox(#[from] WorkerInboxError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    LysisArtifact(#[from] LysisArtifactErrorV1),
    #[error(transparent)]
    AdmissionCatalog(#[from] AdmissionCatalogError),
    #[error("worker-independent ROOT_REDUCE replay failed")]
    ReplayExecutionFailed,
    #[error("reported ROOT_REDUCE artifact differs from deterministic replay")]
    ReplayMismatch,
}

/// Re-executes one ROOT_REDUCE unit against exact admitted producer artifacts.
///
/// A leaf writes its expected ResultChunkV1 only into the supervisor-owned
/// replay inbox. Byte equality of the root artifact therefore also proves that
/// the worker-reported manifest entry names the deterministic chunk bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_lysis_root_reduce_phase_replay(
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
) -> Result<(), LysisResultAdoptionError> {
    if spec.phase != UnitPhase::RootReduce {
        return Err(ProtocolError::InvalidInvariant("ROOT_REDUCE replay phase").into());
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
    .map_err(|_| LysisResultAdoptionError::ReplayExecutionFailed)?;
    if expected.encode_canonical(limits)? != reported.encode_canonical(limits)? {
        return Err(LysisResultAdoptionError::ReplayMismatch);
    }
    Ok(())
}

/// Makes one reported ROOT_REDUCE leaf ready only after its manifest-discovered
/// result chunk has been verified and published into authoritative CAS.
pub fn admit_reported_lysis_root_reduce_leaf(
    position: AdmissionPositionV1,
    spec: &UnitSpecV1,
    finished: &UnitFinishedV1,
    inbox: &WorkerInbox,
    cas: &FilesystemCas,
    catalog: &mut VerifiedAdmissionCatalog,
    limits: &SchemaLimits,
) -> Result<AdmittedLysisRootReduceLeafV1, LysisResultAdoptionError> {
    spec.validate_semantics(limits)?;
    let unit_id = spec.unit_id(limits)?;
    if finished.status != UnitFinishedStatus::Success || finished.unit_id != unit_id {
        return Err(ProtocolError::InvalidInvariant("successful ROOT_REDUCE leaf report").into());
    }
    let reported = inbox.read_reported(
        finished.unit_id,
        finished.exact_staged_bytes,
        finished.transport_digest,
    )?;
    let artifact = UnitArtifactV1::decode_canonical(reported.bytes(), limits)?;
    let chunk = adopt_lysis_result_chunk(spec, &artifact, inbox, cas, limits)?;

    let mut artifact_ref = cas.publish_bytes(reported.bytes())?;
    if artifact_ref.transport_digest != finished.transport_digest
        || artifact_ref.encoded_bytes != finished.exact_staged_bytes
    {
        return Err(
            ProtocolError::InvalidInvariant("published ROOT_REDUCE leaf descriptor").into(),
        );
    }
    artifact_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    cas.read_verified(&artifact_ref)?;
    let admission = catalog.admit_verified_unit(
        position,
        spec,
        artifact_ref.clone(),
        Some(chunk.output_manifest_entry.clone()),
    )?;
    Ok(AdmittedLysisRootReduceLeafV1 {
        artifact_ref,
        chunk,
        admission,
    })
}

/// Makes one already-replayed internal ROOT_REDUCE node authoritative.
///
/// Unlike a leaf, an internal node carries no output-manifest entry and
/// therefore must not discover, publish or journal a ResultChunkV1.
pub fn admit_reported_lysis_root_reduce_node(
    position: AdmissionPositionV1,
    spec: &UnitSpecV1,
    finished: &UnitFinishedV1,
    inbox: &WorkerInbox,
    cas: &FilesystemCas,
    catalog: &mut VerifiedAdmissionCatalog,
    limits: &SchemaLimits,
) -> Result<AdmittedLysisRootReduceNodeV1, LysisResultAdoptionError> {
    spec.validate_semantics(limits)?;
    let UnitInterval::BinaryReducerNode(BinaryReducerNode { level, .. }) = spec.interval else {
        return Err(ProtocolError::InvalidInvariant("internal ROOT_REDUCE position").into());
    };
    if spec.phase != UnitPhase::RootReduce || level == 0 {
        return Err(ProtocolError::InvalidInvariant("internal ROOT_REDUCE position").into());
    }
    let unit_id = spec.unit_id(limits)?;
    if finished.status != UnitFinishedStatus::Success || finished.unit_id != unit_id {
        return Err(ProtocolError::InvalidInvariant("successful ROOT_REDUCE node report").into());
    }
    let reported = inbox.read_reported(
        finished.unit_id,
        finished.exact_staged_bytes,
        finished.transport_digest,
    )?;
    let artifact = UnitArtifactV1::decode_canonical(reported.bytes(), limits)?;
    artifact.validate_against(spec, limits)?;
    if !matches!(
        decode_root_reduce_output(artifact.phase_payload(limits)?, limits)?,
        RootReduceOutputV1::Node { .. }
    ) {
        return Err(ProtocolError::InvalidInvariant("internal ROOT_REDUCE NODE payload").into());
    }

    let mut artifact_ref = cas.publish_bytes(reported.bytes())?;
    if artifact_ref.transport_digest != finished.transport_digest
        || artifact_ref.encoded_bytes != finished.exact_staged_bytes
    {
        return Err(
            ProtocolError::InvalidInvariant("published ROOT_REDUCE node descriptor").into(),
        );
    }
    artifact_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    cas.read_verified(&artifact_ref)?;
    let admission = catalog.admit_verified_unit(position, spec, artifact_ref.clone(), None)?;
    Ok(AdmittedLysisRootReduceNodeV1 {
        artifact_ref,
        admission,
    })
}

/// Reopens and verifies the exact typed chunk reported by one admitted
/// ROOT_REDUCE leaf before publishing it into the supervisor's authoritative
/// CAS. No caller-selected path or out-of-band chunk reference is accepted.
pub fn adopt_lysis_result_chunk(
    root_reduce_spec: &UnitSpecV1,
    root_reduce_artifact: &UnitArtifactV1,
    inbox: &WorkerInbox,
    cas: &FilesystemCas,
    limits: &SchemaLimits,
) -> Result<AdoptedLysisResultChunkV1, LysisResultAdoptionError> {
    root_reduce_spec.validate_semantics(limits)?;
    root_reduce_artifact.validate_against(root_reduce_spec, limits)?;
    let UnitInterval::BinaryReducerNode(BinaryReducerNode { level: 0, index }) =
        root_reduce_spec.interval
    else {
        return Err(
            ProtocolError::InvalidInvariant("result chunk producer is ROOT_REDUCE leaf").into(),
        );
    };
    let RootReduceOutputV1::Leaf {
        output_manifest_entry: entry,
        ..
    } = decode_root_reduce_output(root_reduce_artifact.phase_payload(limits)?, limits)?
    else {
        return Err(ProtocolError::InvalidInvariant(
            "result chunk producer carries ROOT_REDUCE LEAF",
        )
        .into());
    };
    if root_reduce_spec.phase != UnitPhase::RootReduce || entry.chunk_ordinal != index {
        return Err(ProtocolError::InvalidInvariant("result chunk ROOT_REDUCE position").into());
    }
    entry.encode_canonical_record(limits)?;

    let object = inbox.read_result_chunk(&entry.result_chunk_ref, limits)?;
    let chunk = ResultChunkV1::decode_canonical(object.bytes(), limits)?;
    if chunk.protocol_bundle_hash != root_reduce_spec.protocol_bundle_hash
        || chunk.job_id != root_reduce_spec.job_id
        || chunk.attempt != root_reduce_spec.attempt
        || chunk.chunk_ordinal != entry.chunk_ordinal
        || chunk.result_chunk_hash(limits)? != entry.result_chunk_hash
    {
        return Err(
            ProtocolError::InvalidInvariant("result chunk semantic manifest binding").into(),
        );
    }

    let published = cas.publish_bytes(object.bytes())?;
    if published.transport_digest != entry.result_chunk_ref.transport_digest
        || published.encoded_bytes != entry.result_chunk_ref.encoded_bytes
        || entry.result_chunk_ref.expected_ocb1_kind != Some(ObjectKind::ResultChunkV1.tag())
    {
        return Err(
            ProtocolError::InvalidInvariant("authoritative result chunk descriptor").into(),
        );
    }
    cas.read_verified(&entry.result_chunk_ref)?;

    Ok(AdoptedLysisResultChunkV1 {
        chunk_ordinal: chunk.chunk_ordinal,
        nod_count: u32::try_from(chunk.ordered_nod_actions.len()).map_err(|_| {
            ProtocolError::IntegerOverflow {
                what: "adopted result chunk Nod count",
            }
        })?,
        contributor_count: u32::try_from(chunk.ordered_eligible_contributors.len()).map_err(
            |_| ProtocolError::IntegerOverflow {
                what: "adopted result chunk contributor count",
            },
        )?,
        authoritative_ref: entry.result_chunk_ref.clone(),
        output_manifest_entry: entry,
    })
}
