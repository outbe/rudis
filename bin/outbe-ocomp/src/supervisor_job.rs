//! Restart-safe composition of the closed Lysis V1 supervisor pipeline.
//!
//! This module does not introduce another scheduler or computation interface.
//! It composes the already verified export, planner, one-unit worker boundary,
//! admission catalog, finalizer and locally signed result-vote submitter.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use alloy_primitives::B256;
use outbe_lysis::program_v1::planner::{
    LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1, PlannedUnitPositionV1,
};
use outbe_ocomp_protocol::{
    input::InputChunkKind, intent::JobIntentV1, UnitFinishedStatus, UnitFinishedV1,
};
use outbe_ocomp_protocol::{RunUnitV1, SchemaLimits};
use thiserror::Error;

use crate::admission_catalog::{AdmissionCatalogError, VerifiedAdmissionCatalog};
use crate::bundle::PinnedProtocolBundle;
use crate::cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader};
use crate::export_binding::VerifiedExportedManifestBinding;
use crate::inbox::{WorkerInbox, WorkerInboxLimits};
use crate::input_artifacts::poc_input_list_limits;
use crate::input_ref_catalog::VerifiedInputChunkRefCatalog;
use crate::lysis_finalization::finalize_verified_lysis_v1;
use crate::lysis_plan_audit::LocalLysisPlanAuditV1;
use crate::lysis_scheduler::admit_reported_lysis_unit_v1;
use crate::payout_artifact::write_contributor_payout_artifact;
use crate::supervisor::DiscoveryRecord;
use crate::worker_transport::{SupervisorWorkerDispatcherV1, MAX_REGISTERED_WORKERS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchWaveV1 {
    Primary(outbe_ocomp_protocol::unit::UnitPhase),
    Level(outbe_ocomp_protocol::unit::UnitPhase, u16),
}

#[derive(Clone, Debug)]
pub struct SupervisorJobRunnerConfigV1 {
    pub cas_root: PathBuf,
    pub cas_limits: CasLimits,
    pub input_ref_root: PathBuf,
    pub job_root: PathBuf,
    pub worker_inbox_root: PathBuf,
    pub worker_inbox_limits: WorkerInboxLimits,
    pub protocol_bundle: PinnedProtocolBundle,
    pub limits: SchemaLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedSupervisorJobV1 {
    pub job_id: B256,
    pub exact_unit_count: u32,
    pub result_digest: B256,
    pub canonical_result: Vec<u8>,
}

pub struct SupervisorJobRunnerV1 {
    config: SupervisorJobRunnerConfigV1,
    cas: FilesystemCas,
    reader: FilesystemCasReader,
    workers: SupervisorWorkerDispatcherV1,
}

impl SupervisorJobRunnerV1 {
    pub fn open(
        config: SupervisorJobRunnerConfigV1,
        workers: SupervisorWorkerDispatcherV1,
    ) -> Result<Self, SupervisorJobRunnerErrorV1> {
        let cas = stage(
            "open supervisor job CAS writer",
            FilesystemCas::open(
                &config.cas_root,
                CasWriterRole::Supervisor,
                config.cas_limits,
            ),
        )?;
        let reader = stage(
            "open supervisor job CAS reader",
            FilesystemCasReader::open(&config.cas_root, config.cas_limits),
        )?;
        Ok(Self {
            workers,
            config,
            cas,
            reader,
        })
    }

    pub fn poll_workers(&self) -> Result<usize, SupervisorJobRunnerErrorV1> {
        stage(
            "read Supervisor connected worker registry",
            self.workers.status(),
        )
        .map(|status| status.connected_workers)
    }

    pub fn run_to_result(
        &self,
        record: &DiscoveryRecord,
        binding: &VerifiedExportedManifestBinding,
        cancelled: &AtomicBool,
    ) -> Result<CompletedSupervisorJobV1, SupervisorJobRunnerErrorV1> {
        require_not_cancelled(cancelled)?;
        let limits = &self.config.limits;
        let job_id = record.spec.summary.job_id;
        if binding.job_id() != job_id {
            return Err(SupervisorJobRunnerErrorV1::Invariant(
                "adopted export belongs to another finalized job",
            ));
        }
        let intent = stage(
            "decode finalized JobIntent",
            JobIntentV1::decode_canonical(&record.spec.canonical_job_intent.0, limits),
        )?;
        let manifest = binding.manifest();
        let manifest_ref = binding.manifest_ref();
        let job_component = hex::encode(job_id.as_slice());
        let input_refs = stage(
            "reopen exact exported input catalog",
            VerifiedInputChunkRefCatalog::reopen(
                self.config.input_ref_root.join(&job_component),
                &self.reader,
                *limits,
                poc_input_list_limits(),
            ),
        )?;
        let tribute_refs = stage(
            "read exact Tribute input references",
            input_refs.exact_cursor(),
        )?
        .filter_map(|reference| match reference {
            Ok(reference) if reference.kind == InputChunkKind::Tribute => Some(Ok(reference)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| stage_error("read exact Tribute input references", error))?;
        require_not_cancelled(cancelled)?;

        let planner = stage(
            "bind Lysis V1 planner",
            LysisPlannerV1::new(LysisPlannerBindingsV1 {
                protocol_bundle_hash: self.config.protocol_bundle.hash(),
                job_id,
                attempt: intent.attempt,
                input_manifest_hash: stage(
                    "hash adopted input manifest",
                    manifest.manifest_hash(limits),
                )?,
                input_manifest_encoded_bytes: manifest_ref.encoded_bytes,
                fidelity_opening_root: manifest.fidelity_opening_root,
                oracle_opening_root: manifest.oracle_opening_root,
                wwd: manifest.wwd,
                lysis_budget: intent.frozen_metadosis_values.lysis_budget,
                logical_evaluation_time: intent.logical_evaluation_time,
                tribute_count: manifest.tribute_count,
                lysis_program_semantics_hash: self
                    .config
                    .protocol_bundle
                    .bundle()
                    .lysis_program_semantics_hash,
                planner_spec_version: self.config.protocol_bundle.bundle().planner_spec_version,
                reducer_spec_version: self.config.protocol_bundle.bundle().reducer_spec_version,
            }),
        )?;
        let plan = stage(
            "commit exact Lysis primary catalog",
            planner.commit_primary_catalog(tribute_refs, limits),
        )?;
        let plan_bytes = stage(
            "encode exact Lysis plan",
            plan.encode_canonical_record(limits),
        )?;
        let plan_ref = stage(
            "publish exact Lysis plan",
            self.cas.publish_bytes(&plan_bytes),
        )?;
        let topology = stage(
            "derive exact Lysis plan topology",
            LysisPlanTopologyV1::new(plan.primary_work_unit_count),
        )?;
        let exact_unit_count = topology.total_unit_count();
        require_not_cancelled(cancelled)?;

        let local_job_root = self.config.job_root.join(&job_component);
        let mut admissions = stage(
            "open exact Lysis admission catalog",
            VerifiedAdmissionCatalog::open(
                local_job_root.join("admissions"),
                &self.cas,
                &plan_ref,
                &manifest_ref,
                *limits,
            ),
        )?;
        let worker_inbox = stage(
            "open worker report inbox",
            WorkerInbox::open(
                &self.config.worker_inbox_root,
                self.config.worker_inbox_limits,
            ),
        )?;
        let replay_inbox = stage(
            "open supervisor replay inbox",
            WorkerInbox::open(
                local_job_root.join("replay-inbox"),
                self.config.worker_inbox_limits,
            ),
        )?;

        let mut next_plan_ordinal = 0;
        while next_plan_ordinal < exact_unit_count {
            require_not_cancelled(cancelled)?;
            while next_plan_ordinal < exact_unit_count {
                match admissions.read(next_plan_ordinal) {
                    Ok(_) => next_plan_ordinal += 1,
                    Err(AdmissionCatalogError::MissingAdmission { .. }) => break,
                    Err(error) => {
                        return Err(stage_error("inspect exact Lysis admission", error));
                    }
                }
            }
            if next_plan_ordinal == exact_unit_count {
                break;
            }

            let first_wave = dispatch_wave(stage(
                "locate exact Lysis dispatch wave",
                topology.plan_position_at(next_plan_ordinal),
            )?);
            let mut batch_ordinals = Vec::with_capacity(MAX_REGISTERED_WORKERS);
            while next_plan_ordinal < exact_unit_count
                && batch_ordinals.len() < MAX_REGISTERED_WORKERS
            {
                let wave = dispatch_wave(stage(
                    "locate exact Lysis dispatch wave",
                    topology.plan_position_at(next_plan_ordinal),
                )?);
                if wave != first_wave {
                    break;
                }
                match admissions.read(next_plan_ordinal) {
                    Ok(_) => {}
                    Err(AdmissionCatalogError::MissingAdmission { .. }) => {
                        batch_ordinals.push(next_plan_ordinal);
                    }
                    Err(error) => {
                        return Err(stage_error("inspect exact Lysis admission", error));
                    }
                }
                next_plan_ordinal += 1;
            }

            let requests = {
                let audit = stage(
                    "open exact Lysis scheduling audit",
                    LocalLysisPlanAuditV1::open(
                        &admissions,
                        &input_refs,
                        &self.reader,
                        &self.config.protocol_bundle,
                        limits,
                    ),
                )?;
                batch_ordinals
                    .iter()
                    .copied()
                    .map(|plan_ordinal| {
                        stage(
                            "derive next exact Lysis worker request",
                            audit.worker_request_at(plan_ordinal),
                        )
                        .map(|request| (plan_ordinal, request))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            require_not_cancelled(cancelled)?;
            let finished_batch = self.execute_worker_batch(requests, cancelled)?;
            for (plan_ordinal, finished) in finished_batch {
                require_not_cancelled(cancelled)?;
                if finished.status != UnitFinishedStatus::Success {
                    return Err(SupervisorJobRunnerErrorV1::WorkerFailed {
                        plan_ordinal,
                        unit_id: finished.unit_id,
                    });
                }
                stage(
                    "admit exact Lysis worker result",
                    admit_reported_lysis_unit_v1(
                        plan_ordinal,
                        &finished,
                        &mut admissions,
                        &input_refs,
                        &self.config.protocol_bundle,
                        &self.reader,
                        &worker_inbox,
                        &replay_inbox,
                        &self.cas,
                        limits,
                    ),
                )?;
            }
        }

        require_not_cancelled(cancelled)?;
        let audit = stage(
            "cold-audit complete Lysis plan",
            LocalLysisPlanAuditV1::open(
                &admissions,
                &input_refs,
                &self.reader,
                &self.config.protocol_bundle,
                limits,
            ),
        )?;
        let finalized = stage(
            "finalize verified Lysis result",
            finalize_verified_lysis_v1(record, &audit, &self.cas, &self.reader, limits),
        )?;
        stage(
            "write contributor payout artifact",
            write_contributor_payout_artifact(&audit, &local_job_root),
        )?;
        Ok(CompletedSupervisorJobV1 {
            job_id,
            exact_unit_count,
            result_digest: finalized.result_digest(),
            canonical_result: finalized.canonical_result_bytes().to_vec(),
        })
    }

    fn execute_worker_batch(
        &self,
        requests: Vec<(u32, RunUnitV1)>,
        cancelled: &AtomicBool,
    ) -> Result<Vec<(u32, UnitFinishedV1)>, SupervisorJobRunnerErrorV1> {
        let dispatcher = self.workers.clone();
        std::thread::scope(|scope| {
            let handles = requests
                .into_iter()
                .map(|(plan_ordinal, request)| {
                    let dispatcher = dispatcher.clone();
                    scope.spawn(move || {
                        dispatcher
                            .dispatch_with_cancel(&request, cancelled)
                            .map(|finished| (plan_ordinal, finished))
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    let result = handle.join().map_err(|_| {
                        SupervisorJobRunnerErrorV1::Invariant("worker dispatch thread panicked")
                    })?;
                    retryable_stage(
                        "dispatch exact Lysis unit through Supervisor Worker transport",
                        result,
                    )
                })
                .collect()
        })
    }
}

const fn dispatch_wave(position: PlannedUnitPositionV1) -> DispatchWaveV1 {
    match position {
        PlannedUnitPositionV1::Primary { phase, .. } => DispatchWaveV1::Primary(phase),
        PlannedUnitPositionV1::TreeNode { phase, level, .. }
        | PlannedUnitPositionV1::RunSpan { phase, level, .. } => {
            DispatchWaveV1::Level(phase, level)
        }
    }
}

fn require_not_cancelled(cancelled: &AtomicBool) -> Result<(), SupervisorJobRunnerErrorV1> {
    if cancelled.load(Ordering::Acquire) {
        Err(SupervisorJobRunnerErrorV1::Cancelled)
    } else {
        Ok(())
    }
}

fn stage<T, E: std::fmt::Display>(
    name: &'static str,
    result: Result<T, E>,
) -> Result<T, SupervisorJobRunnerErrorV1> {
    result.map_err(|error| stage_error(name, error))
}

fn stage_error(name: &'static str, error: impl std::fmt::Display) -> SupervisorJobRunnerErrorV1 {
    SupervisorJobRunnerErrorV1::Stage {
        class: SupervisorJobFailureClassV1::Unrecoverable,
        name,
        detail: error.to_string(),
    }
}

fn retryable_stage<T, E: std::fmt::Display>(
    name: &'static str,
    result: Result<T, E>,
) -> Result<T, SupervisorJobRunnerErrorV1> {
    result.map_err(|error| retryable_stage_error(name, error))
}

fn retryable_stage_error(
    name: &'static str,
    error: impl std::fmt::Display,
) -> SupervisorJobRunnerErrorV1 {
    SupervisorJobRunnerErrorV1::Stage {
        class: SupervisorJobFailureClassV1::Retryable,
        name,
        detail: error.to_string(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorJobFailureClassV1 {
    Retryable,
    Unrecoverable,
}

#[derive(Debug, Error)]
pub enum SupervisorJobRunnerErrorV1 {
    #[error("supervisor Lysis job stage `{name}` failed: {detail}")]
    Stage {
        class: SupervisorJobFailureClassV1,
        name: &'static str,
        detail: String,
    },
    #[error("supervisor Lysis job invariant failed: {0}")]
    Invariant(&'static str),
    #[error("worker failed plan ordinal {plan_ordinal} ({unit_id})")]
    WorkerFailed { plan_ordinal: u32, unit_id: B256 },
    #[error("supervisor Lysis job was superseded by a newer finalized job")]
    Cancelled,
}

impl SupervisorJobRunnerErrorV1 {
    #[must_use]
    pub const fn class(&self) -> SupervisorJobFailureClassV1 {
        match self {
            Self::Stage { class, .. } => *class,
            Self::Invariant(_) => SupervisorJobFailureClassV1::Unrecoverable,
            Self::WorkerFailed { .. } | Self::Cancelled => SupervisorJobFailureClassV1::Retryable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_ocomp_protocol::unit::UnitPhase;

    #[test]
    fn runner_errors_expose_typed_retryability() {
        assert_eq!(
            SupervisorJobRunnerErrorV1::WorkerFailed {
                plan_ordinal: 7,
                unit_id: B256::repeat_byte(0x71),
            }
            .class(),
            SupervisorJobFailureClassV1::Retryable
        );
        assert_eq!(
            SupervisorJobRunnerErrorV1::Invariant("corrupt finalized input").class(),
            SupervisorJobFailureClassV1::Unrecoverable
        );
        assert_eq!(
            retryable_stage_error("dispatch Worker unit", "worker unavailable").class(),
            SupervisorJobFailureClassV1::Retryable
        );
    }

    #[test]
    fn dispatch_waves_parallelize_peers_but_separate_dependency_levels() {
        assert_eq!(
            dispatch_wave(PlannedUnitPositionV1::Primary {
                phase: UnitPhase::Enumerate,
                ordinal: 0,
            }),
            dispatch_wave(PlannedUnitPositionV1::Primary {
                phase: UnitPhase::Enumerate,
                ordinal: 99,
            })
        );
        assert_eq!(
            dispatch_wave(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::FixedReduce,
                level: 2,
                index: 0,
            }),
            dispatch_wave(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::FixedReduce,
                level: 2,
                index: 3,
            })
        );
        assert_ne!(
            dispatch_wave(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::FixedReduce,
                level: 1,
                index: 0,
            }),
            dispatch_wave(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::FixedReduce,
                level: 2,
                index: 0,
            })
        );
    }
}
