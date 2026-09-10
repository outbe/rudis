//! Lysis V1-specific supervisor boundary between worker reports and durable
//! verified admissions.

use outbe_lysis::program_v1::{
    artifacts::LysisArtifactErrorV1,
    planner::{PlannedUnitPositionV1, PlannerErrorV1},
    result::{decode_root_reduce_output, RootReduceOutputV1},
};
use outbe_ocomp_protocol::{
    input::{AuthenticatedInputChunkV1, InputChunkRefV1},
    unit::{UnitArtifactV1, UnitPhase},
    CasObjectRefV1, ObjectKind, ProtocolError, SchemaLimits, UnitFinishedV1,
};
use thiserror::Error;

use crate::{
    admission_catalog::{
        AdmissionCatalogError, AdmissionOutcome, AdmissionPositionV1, VerifiedAdmissionCatalog,
    },
    bundle::PinnedProtocolBundle,
    cas::{CasError, FilesystemCas, FilesystemCasReader},
    inbox::{WorkerInbox, WorkerInboxError},
    input_artifacts::{decode_verified_input_chunk, derive_input_chunk_ref, InputArtifactError},
    input_ref_catalog::VerifiedInputChunkRefCatalog,
    lysis_phase_replay::{
        admit_reported_core_phase_unit, admit_reported_output_finalize_unit, LysisPhaseReplayError,
    },
    lysis_plan_audit::{ExactLysisPlanError, LocalLysisPlanAuditV1},
    lysis_result_adoption::{
        admit_reported_lysis_root_reduce_leaf, admit_reported_lysis_root_reduce_node,
        verify_lysis_root_reduce_phase_replay, AdoptedLysisResultChunkV1, LysisResultAdoptionError,
    },
    lysis_shuffle_adoption::{
        admit_reported_lysis_shuffle_unit, verify_lysis_shuffle_phase_replay,
        LysisShuffleAdoptionError,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLysisUnitV1 {
    pub plan_ordinal: u32,
    pub phase: UnitPhase,
    pub artifact_ref: CasObjectRefV1,
    pub result_chunk: Option<AdoptedLysisResultChunkV1>,
    pub admission: AdmissionOutcome,
}

#[derive(Debug, Error)]
pub enum LysisSchedulerError {
    #[error(transparent)]
    Plan(#[from] ExactLysisPlanError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Planner(#[from] PlannerErrorV1),
    #[error(transparent)]
    LysisArtifact(#[from] LysisArtifactErrorV1),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    Inbox(#[from] WorkerInboxError),
    #[error(transparent)]
    InputArtifact(#[from] InputArtifactError),
    #[error(transparent)]
    CoreReplay(#[from] LysisPhaseReplayError),
    #[error(transparent)]
    Shuffle(#[from] LysisShuffleAdoptionError),
    #[error(transparent)]
    RootReduce(#[from] LysisResultAdoptionError),
    #[error(transparent)]
    Admission(#[from] AdmissionCatalogError),
    #[error("durable Lysis worker request has an invalid typed input shape")]
    InputShape,
}

/// Re-derives the exact plan member and all of its CAS authority after cold
/// restart, semantically replays the worker output, then durably admits it.
///
/// The caller supplies only the plan ordinal and the worker completion report;
/// roots, specs, input references and producer artifacts are not injectable.
#[allow(clippy::too_many_arguments)]
pub fn admit_reported_lysis_unit_v1(
    plan_ordinal: u32,
    finished: &UnitFinishedV1,
    catalog: &mut VerifiedAdmissionCatalog,
    input_refs: &VerifiedInputChunkRefCatalog,
    bundle: &PinnedProtocolBundle,
    reader: &FilesystemCasReader,
    worker_inbox: &WorkerInbox,
    replay_inbox: &WorkerInbox,
    cas: &FilesystemCas,
    limits: &SchemaLimits,
) -> Result<AdmittedLysisUnitV1, LysisSchedulerError> {
    let (request, plan, manifest, position) = {
        let audit = LocalLysisPlanAuditV1::open(catalog, input_refs, reader, bundle, limits)?;
        let request = audit.worker_request_at(plan_ordinal)?;
        let position = outbe_lysis::program_v1::planner::LysisPlanTopologyV1::new(
            audit.plan().primary_work_unit_count,
        )?
        .plan_position_at(plan_ordinal)?;
        (
            request,
            audit.plan().clone(),
            audit.manifest().clone(),
            position,
        )
    };
    let _ = request.encode_body(limits)?;
    let spec = outbe_ocomp_protocol::unit::UnitSpecV1::decode_canonical(
        &request.canonical_unit_spec.0,
        limits,
    )?;
    if finished.unit_id != spec.unit_id(limits)? {
        return Err(LysisSchedulerError::InputShape);
    }

    let loaded = load_request_inputs(&request.ordered_input_refs, bundle, reader, limits)?;
    let input_chunks = loaded.input_chunks;
    let producer_artifacts = loaded.producer_artifacts;
    let reported = worker_inbox.read_reported(
        finished.unit_id,
        finished.exact_staged_bytes,
        finished.transport_digest,
    )?;
    let reported_artifact = UnitArtifactV1::decode_canonical(reported.bytes(), limits)?;
    let admission_position = AdmissionPositionV1 { plan_ordinal };

    let admitted = match spec.phase {
        UnitPhase::Enumerate
        | UnitPhase::FidelityMap
        | UnitPhase::FixedReduce
        | UnitPhase::AmountMap
        | UnitPhase::GratisPrefix
        | UnitPhase::GratisPrefixDown => {
            let admitted = admit_reported_core_phase_unit(
                admission_position,
                &spec,
                finished,
                &plan,
                &manifest,
                &input_chunks,
                &producer_artifacts,
                bundle.bundle(),
                reader,
                worker_inbox,
                cas,
                catalog,
                limits,
            )?;
            AdmittedLysisUnitV1 {
                plan_ordinal,
                phase: spec.phase,
                artifact_ref: admitted.artifact_ref,
                result_chunk: None,
                admission: admitted.admission,
            }
        }
        UnitPhase::OutputFinalize => {
            let PlannedUnitPositionV1::Primary { ordinal, .. } = position else {
                return Err(LysisSchedulerError::InputShape);
            };
            let [amount, prefix] = producer_artifacts.as_slice() else {
                return Err(LysisSchedulerError::InputShape);
            };
            if !input_chunks.is_empty() {
                return Err(LysisSchedulerError::InputShape);
            }
            let admitted = admit_reported_output_finalize_unit(
                admission_position,
                ordinal,
                &spec,
                finished,
                amount,
                prefix,
                &plan,
                &manifest,
                bundle.bundle(),
                worker_inbox,
                cas,
                catalog,
                limits,
            )?;
            AdmittedLysisUnitV1 {
                plan_ordinal,
                phase: spec.phase,
                artifact_ref: admitted.artifact_ref,
                result_chunk: None,
                admission: admitted.admission,
            }
        }
        UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle => {
            if !input_chunks.is_empty() {
                return Err(LysisSchedulerError::InputShape);
            }
            verify_lysis_shuffle_phase_replay(
                plan_ordinal,
                &spec,
                &reported_artifact,
                &plan,
                &manifest,
                &producer_artifacts,
                bundle.bundle(),
                reader,
                replay_inbox,
                limits,
            )?;
            let admitted = admit_reported_lysis_shuffle_unit(
                admission_position,
                &spec,
                finished,
                worker_inbox,
                cas,
                catalog,
                limits,
            )?;
            AdmittedLysisUnitV1 {
                plan_ordinal,
                phase: spec.phase,
                artifact_ref: admitted.artifact_ref,
                result_chunk: None,
                admission: admitted.admission,
            }
        }
        UnitPhase::RootReduce => {
            if !input_chunks.is_empty() {
                return Err(LysisSchedulerError::InputShape);
            }
            verify_lysis_root_reduce_phase_replay(
                plan_ordinal,
                &spec,
                &reported_artifact,
                &plan,
                &manifest,
                &producer_artifacts,
                bundle.bundle(),
                reader,
                replay_inbox,
                limits,
            )?;
            match decode_root_reduce_output(reported_artifact.phase_payload(limits)?, limits)? {
                RootReduceOutputV1::Leaf { .. } => {
                    let admitted = admit_reported_lysis_root_reduce_leaf(
                        admission_position,
                        &spec,
                        finished,
                        worker_inbox,
                        cas,
                        catalog,
                        limits,
                    )?;
                    AdmittedLysisUnitV1 {
                        plan_ordinal,
                        phase: spec.phase,
                        artifact_ref: admitted.artifact_ref,
                        result_chunk: Some(admitted.chunk),
                        admission: admitted.admission,
                    }
                }
                RootReduceOutputV1::Node { .. } => {
                    let admitted = admit_reported_lysis_root_reduce_node(
                        admission_position,
                        &spec,
                        finished,
                        worker_inbox,
                        cas,
                        catalog,
                        limits,
                    )?;
                    AdmittedLysisUnitV1 {
                        plan_ordinal,
                        phase: spec.phase,
                        artifact_ref: admitted.artifact_ref,
                        result_chunk: None,
                        admission: admitted.admission,
                    }
                }
            }
        }
    };
    Ok(admitted)
}

fn load_request_inputs(
    references: &[CasObjectRefV1],
    bundle: &PinnedProtocolBundle,
    reader: &FilesystemCasReader,
    limits: &SchemaLimits,
) -> Result<LoadedLysisWorkerInputsV1, LysisSchedulerError> {
    let mut input_chunks = Vec::new();
    let mut producer_artifacts = Vec::new();
    for reference in references {
        let object = reader.read_verified(reference)?;
        match reference.expected_ocb1_kind {
            Some(kind) if kind == ObjectKind::AuthenticatedInputChunkV1.tag() => {
                input_chunks.push((
                    derive_input_chunk_ref(&object, bundle.bundle(), limits)?.reference,
                    decode_verified_input_chunk(&object, bundle.bundle(), limits)?,
                ));
            }
            Some(kind) if kind == ObjectKind::UnitArtifactV1.tag() => {
                producer_artifacts.push(UnitArtifactV1::decode_canonical(object.bytes(), limits)?);
            }
            _ => return Err(LysisSchedulerError::InputShape),
        }
    }
    Ok(LoadedLysisWorkerInputsV1 {
        input_chunks,
        producer_artifacts,
    })
}

struct LoadedLysisWorkerInputsV1 {
    input_chunks: Vec<(InputChunkRefV1, AuthenticatedInputChunkV1)>,
    producer_artifacts: Vec<UnitArtifactV1>,
}
