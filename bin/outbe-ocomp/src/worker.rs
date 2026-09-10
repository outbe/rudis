//! Axum-registered worker driven by an asynchronous TCP ZeroMQ command channel.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{B256, U256};
use outbe_compressed_entities::{decode_tribute_v1, CanonicalBodyError};
use outbe_lysis::program_v1::artifacts::{
    decode_amount_run, decode_enumerated_run, decode_fidelity_map_output,
    decode_finalized_output_run, decode_fixed_reduce_output, decode_gratis_prefix_down_output,
    decode_gratis_segment_summary, encode_amount_run, encode_enumerated_run,
    encode_fidelity_map_output, encode_fixed_reduce_output, encode_gratis_prefix_down_output,
    encode_gratis_segment_summary, enumerate_tributes, gratis_summary_coverage,
    FixedReduceOutputV1, GratisPrefixDownOutputV1, LysisArtifactErrorV1, RawCoverageCarrierV1,
};
use outbe_lysis::program_v1::phases::{
    amount_map, fidelity_map, fidelity_reduce_pair, finalize_fi_fraction_table, gratis_prefix_down,
    gratis_summary, gratis_summary_reduce_pair, shuffle_buckets, shuffle_owners,
    FidelityReduceValueV1, FinalizedOutputRunV1, GratisLeafPrefixV1, GratisSummaryValueV1,
};
use outbe_lysis::program_v1::planner::{
    LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1, PlannedProducerV1,
    PlannedUnitPositionV1, PlannerErrorV1, PRIMARY_WORK_SHARD_SIZE,
};
use outbe_lysis::program_v1::result::{
    decode_root_reduce_output, encode_root_reduce_output, LysisListSubtreeCarrierV1,
    RootReduceOutputV1, RootReduceSummaryV1,
};
use outbe_lysis::program_v1::{ObservationValueV1, ObservedTributeV1, TributeInputV1};
use outbe_ocomp_protocol::common::BoundedBytes;
use outbe_ocomp_protocol::input::{
    AuthenticatedInputChunkV1, AuthenticatedOpeningV1, InputChunkKind, InputChunkRefV1,
    InputManifestV1, OpeningSourceKind,
};
use outbe_ocomp_protocol::league_snapshot::league_snapshot_slot;
use outbe_ocomp_protocol::unit::{
    BinaryReducerNode, CanonicalInputRefV1, FidelityIndexHalfOpenRange, InputPurpose,
    InputSourceKind, PlanCommitmentV1, UnitArtifactV1, UnitInterval, UnitPhase, UnitSpecV1,
    WorkOutputHeaderV1,
};
use outbe_ocomp_protocol::{
    result::{
        ContributorActionV1 as ProtocolContributorActionV1, NodActionV1 as ProtocolNodActionV1,
        OutputManifestEntryV1, ResultChunkV1,
    },
    shuffle::{
        build_bucket_shuffle_run, build_owner_shuffle_run, merge_verified_shuffle_runs,
        verified_shuffle_run_page, verified_shuffle_run_records, ShuffleBucketRecordV1,
        ShuffleRunArtifactV1, ShuffleRunBuildContextV1, ShuffleRunKindV1, ShuffleSourceCoverageV1,
        VerifiedShuffleRecordV1,
    },
};
use outbe_ocomp_protocol::{
    verify_ordered_list_membership, ListKind, ObjectKind, RunUnitV1, SchemaLimits,
    UnitFinishedStatus, UnitFinishedV1,
};
use outbe_oracle::{evaluate_oracle_opening_v1, OracleOcompError};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;
use zeromq::util::PeerIdentity;
use zeromq::{DealerSocket, Socket, SocketOptions, SocketRecv, SocketSend, ZmqMessage};

use crate::bundle::PinnedProtocolBundle;
use crate::cas::{CasError, CasLimits, FilesystemCasReader};
use crate::control::{poc_schema_limits, ControlError, EndpointIdentity};
use crate::inbox::{WorkerInbox, WorkerInboxError, WorkerInboxLimits};
use crate::input_artifacts::{
    decode_fidelity_subject_key, decode_oracle_subject_key, decode_verified_input_chunk,
    derive_input_chunk_ref, InputArtifactError,
};
use crate::lysis_phase_replay::{replay_output_finalize_artifact, LysisPhaseReplayError};
use crate::worker_observability::{WorkerObservabilityErrorV1, WorkerObservabilityServerV1};
use crate::worker_transport::{
    SupervisorCommandV1, WorkLeaseV1, WorkerCompletionV1, WorkerEventV1, WorkerLeaseRefV1,
    WorkerRegistrationResponseV1, WorkerRegistrationV1,
};

const SUPERVISOR_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const WORKER_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    pub identity: EndpointIdentity,
    pub supervisor_address: SocketAddr,
    pub observability_address: SocketAddr,
    pub cas_root: PathBuf,
    pub cas_limits: CasLimits,
    pub inbox_root: PathBuf,
    pub inbox_limits: WorkerInboxLimits,
    pub protocol_bundle: PinnedProtocolBundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerOutcome {
    pub unit_id: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedPlanBindingsV1 {
    plan_hash: B256,
    protocol_bundle_hash: B256,
    job_id: B256,
    attempt: u32,
    input_manifest_hash: B256,
    wwd: u32,
    tribute_count: u32,
    planner_spec_version: u16,
    reducer_spec_version: u16,
}

pub(crate) struct UnitExecutionAuthority<'a> {
    pub(crate) plan: &'a PlanCommitmentV1,
    pub(crate) unit_index: u32,
    pub(crate) manifest: &'a InputManifestV1,
    pub(crate) input_chunks: &'a [(InputChunkRefV1, AuthenticatedInputChunkV1)],
    pub(crate) producer_artifacts: &'a [UnitArtifactV1],
    pub(crate) bundle: &'a outbe_ocomp_protocol::profile::ProtocolBundleV1,
    pub(crate) limits: &'a SchemaLimits,
    pub(crate) reader: &'a FilesystemCasReader,
    pub(crate) inbox: &'a WorkerInbox,
    pub(crate) cancelled: Option<&'a AtomicBool>,
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error("worker request is not valid OCOMP protocol: {0}")]
    Protocol(#[from] outbe_ocomp_protocol::ProtocolError),
    #[error("worker Supervisor address {0} is not a nonzero loopback registration endpoint")]
    InvalidSupervisorAddress(SocketAddr),
    #[error("worker HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Supervisor worker HTTP endpoint returned {status}: {body}")]
    SupervisorHttp { status: u16, body: String },
    #[error("worker TCP ZeroMQ transport failed: {0}")]
    MessageTransport(String),
    #[error(transparent)]
    Observability(#[from] WorkerObservabilityErrorV1),
    #[error("Supervisor cancelled or expired the active worker lease")]
    LeaseCancelled,
    #[error("worker request binding does not match its canonical UnitSpecV1")]
    UnitBindingMismatch,
    #[error("worker request carries the reserved zero plan hash")]
    ZeroPlanHash,
    #[error("worker pinned protocol bundle does not match endpoint identity")]
    BundleIdentityMismatch,
    #[error(transparent)]
    InputArtifact(#[from] InputArtifactError),
    #[error(transparent)]
    Inbox(#[from] WorkerInboxError),
    #[error(transparent)]
    LysisArtifact(#[from] LysisArtifactErrorV1),
    #[error(transparent)]
    Planner(#[from] PlannerErrorV1),
    #[error(transparent)]
    CanonicalBody(#[from] CanonicalBodyError),
    #[error(transparent)]
    OracleOpening(#[from] OracleOcompError),
    #[error(transparent)]
    LysisPhaseReplay(#[from] LysisPhaseReplayError),
    #[error("worker does not yet implement Lysis phase {0:?}")]
    UnsupportedPhase(UnitPhase),
}

pub fn run_worker(config: WorkerConfig) -> Result<(), WorkerError> {
    if config.protocol_bundle.hash() != config.identity.protocol_bundle_hash {
        return Err(WorkerError::BundleIdentityMismatch);
    }
    if !config.supervisor_address.ip().is_loopback() || config.supervisor_address.port() == 0 {
        return Err(WorkerError::InvalidSupervisorAddress(
            config.supervisor_address,
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(WORKER_HTTP_TIMEOUT)
        .build()?;
    let observability = WorkerObservabilityServerV1::start(config.observability_address)?;
    loop {
        observability.registering();
        if let Err(error) = run_registered_message_loop(&config, &client, &observability) {
            observability.disconnected();
            eprintln!("OCOMP worker registration/message channel retry: {error}");
        }
        std::thread::sleep(SUPERVISOR_RECONNECT_DELAY);
    }
}

fn run_registered_message_loop(
    config: &WorkerConfig,
    client: &reqwest::blocking::Client,
    observability: &WorkerObservabilityServerV1,
) -> Result<(), WorkerError> {
    let limits = poc_schema_limits();
    let base_url = format!("http://{}", config.supervisor_address);
    let registration: WorkerRegistrationResponseV1 = decode_success(
        client
            .post(format!("{base_url}/v1/workers/register"))
            .json(&WorkerRegistrationV1::from_identity(
                config.identity,
                limits,
            ))
            .send()?,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WorkerError::MessageTransport(error.to_string()))?;
    runtime.block_on(run_registered_message_channel(
        config.clone(),
        registration,
        limits,
        observability,
    ))
}

struct ActiveWorkerLease {
    reference: WorkerLeaseRefV1,
    cancelled: Arc<AtomicBool>,
    cancel_on_drop: bool,
}

impl Drop for ActiveWorkerLease {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

struct WorkerExecutionResult {
    reference: WorkerLeaseRefV1,
    finished: UnitFinishedV1,
    cancelled: Arc<AtomicBool>,
}

async fn run_registered_message_channel(
    config: WorkerConfig,
    registration: WorkerRegistrationResponseV1,
    limits: SchemaLimits,
    observability: &WorkerObservabilityServerV1,
) -> Result<(), WorkerError> {
    let peer: PeerIdentity = registration
        .worker_id
        .parse()
        .map_err(|error: zeromq::ZmqError| WorkerError::MessageTransport(error.to_string()))?;
    let mut options = SocketOptions::default();
    options.peer_identity(peer);
    let mut socket = DealerSocket::with_options(options);
    socket
        .connect(&registration.message_endpoint)
        .await
        .map_err(|error| WorkerError::MessageTransport(error.to_string()))?;
    let (mut sender, mut receiver) = socket.split();
    send_worker_event(
        &mut sender,
        &WorkerEventV1::Ready {
            worker_id: registration.worker_id.clone(),
            registry_generation: registration.registry_generation,
        },
    )
    .await?;
    observability.idle(
        registration.worker_id.clone(),
        registration.registry_generation,
    );

    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut active: Option<ActiveWorkerLease> = None;
    let mut heartbeat = tokio::time::interval(WORKER_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = receiver.recv() => {
                let command = command
                    .map_err(|error| WorkerError::MessageTransport(error.to_string()))
                    .and_then(decode_supervisor_command)?;
                observability.touch();
                match command {
                    SupervisorCommandV1::Work { lease, registry_generation } => {
                        require_registration_binding(&registration, &lease.worker_id, registry_generation)?;
                        let reference = lease_reference(&lease);
                        if let Some(current) = active.as_ref() {
                            if current.reference.lease_id == reference.lease_id
                                && current.reference.unit_id == reference.unit_id
                            {
                                send_worker_event(
                                    &mut sender,
                                    &WorkerEventV1::Accepted {
                                        lease: reference,
                                        registry_generation,
                                    },
                                ).await?;
                            }
                            continue;
                        }
                        let body = hex::decode(&lease.run_unit_body_hex)
                            .map_err(|_| WorkerError::UnitBindingMismatch)?;
                        let request = RunUnitV1::decode_body(&body, &limits)?;
                        let unit_id = lease.unit_id.parse::<B256>()
                            .map_err(|_| WorkerError::UnitBindingMismatch)?;
                        send_worker_event(
                            &mut sender,
                            &WorkerEventV1::Accepted {
                                lease: reference.clone(),
                                registry_generation,
                            },
                        ).await?;
                        observability.working(
                            registration.worker_id.clone(),
                            registry_generation,
                            reference.lease_id.clone(),
                            reference.unit_id.clone(),
                        );
                        let cancelled = Arc::new(AtomicBool::new(false));
                        active = Some(ActiveWorkerLease {
                            reference: reference.clone(),
                            cancelled: Arc::clone(&cancelled),
                            cancel_on_drop: true,
                        });
                        let execution_config = config.clone();
                        let execution_reference = reference;
                        let execution_cancelled = Arc::clone(&cancelled);
                        let execution_tx = result_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = execute_claimed_unit(
                                &execution_config,
                                &request,
                                Some(execution_cancelled.as_ref()),
                            );
                            let finished = terminal_completion(unit_id, &execution_reference.lease_id, result);
                            let _ = execution_tx.send(WorkerExecutionResult {
                                reference: execution_reference,
                                finished,
                                cancelled: execution_cancelled,
                            });
                        });
                    }
                    SupervisorCommandV1::Cancel { lease, registry_generation } => {
                        require_registration_binding(&registration, &lease.worker_id, registry_generation)?;
                        if let Some(current) = active.as_ref() {
                            if current.reference.lease_id == lease.lease_id
                                && current.reference.unit_id == lease.unit_id
                            {
                                current.cancelled.store(true, Ordering::Release);
                                observability.cancelling();
                            }
                        }
                    }
                }
            }
            Some(result) = result_rx.recv() => {
                let is_current = active.as_ref().is_some_and(|current| {
                    current.reference.lease_id == result.reference.lease_id
                        && current.reference.unit_id == result.reference.unit_id
                });
                if !is_current {
                    continue;
                }
                if let Some(mut current) = active.take() {
                    current.cancel_on_drop = false;
                }
                if result.cancelled.load(Ordering::Acquire) {
                    send_worker_event(
                        &mut sender,
                        &WorkerEventV1::Ready {
                            worker_id: registration.worker_id.clone(),
                            registry_generation: registration.registry_generation,
                        },
                    ).await?;
                    observability.cancelled();
                    observability.idle(
                        registration.worker_id.clone(),
                        registration.registry_generation,
                    );
                    continue;
                }
                let finished_status = result.finished.status;
                let finished_body = result.finished.encode_body(&limits)?;
                send_worker_event(
                    &mut sender,
                    &WorkerEventV1::Completed {
                        completion: WorkerCompletionV1 {
                            worker_id: result.reference.worker_id,
                            lease_id: result.reference.lease_id,
                            unit_id: result.reference.unit_id,
                            finished_body_hex: hex::encode(finished_body),
                        },
                        registry_generation: registration.registry_generation,
                    },
                ).await?;
                observability.completed(finished_status);
                observability.idle(
                    registration.worker_id.clone(),
                    registration.registry_generation,
                );
            }
            _ = heartbeat.tick() => {
                let event = match active.as_ref() {
                    Some(current) => WorkerEventV1::Heartbeat {
                        lease: current.reference.clone(),
                        registry_generation: registration.registry_generation,
                    },
                    None => WorkerEventV1::Ready {
                        worker_id: registration.worker_id.clone(),
                        registry_generation: registration.registry_generation,
                    },
                };
                send_worker_event(&mut sender, &event).await?;
                observability.touch();
            }
        }
    }
}

fn failed_completion(unit_id: B256) -> UnitFinishedV1 {
    UnitFinishedV1 {
        unit_id,
        status: UnitFinishedStatus::Failed,
        exact_staged_bytes: 0,
        transport_digest: B256::ZERO,
    }
}

fn terminal_completion(
    unit_id: B256,
    lease_id: &str,
    result: Result<UnitFinishedV1, WorkerError>,
) -> UnitFinishedV1 {
    match result {
        Ok(finished) => finished,
        Err(error) => {
            eprintln!(
                "OCOMP worker reports terminal failure for accepted lease {lease_id}: {error}"
            );
            failed_completion(unit_id)
        }
    }
}

fn lease_reference(lease: &WorkLeaseV1) -> WorkerLeaseRefV1 {
    WorkerLeaseRefV1 {
        worker_id: lease.worker_id.clone(),
        lease_id: lease.lease_id.clone(),
        unit_id: lease.unit_id.clone(),
    }
}

fn require_registration_binding(
    registration: &WorkerRegistrationResponseV1,
    worker_id: &str,
    registry_generation: u64,
) -> Result<(), WorkerError> {
    if worker_id == registration.worker_id
        && registry_generation == registration.registry_generation
    {
        Ok(())
    } else {
        Err(WorkerError::UnitBindingMismatch)
    }
}

fn decode_supervisor_command(message: ZmqMessage) -> Result<SupervisorCommandV1, WorkerError> {
    let frames = message.into_vec();
    if frames.len() != 1 {
        return Err(WorkerError::MessageTransport(
            "Supervisor ZeroMQ command must contain exactly one body frame".into(),
        ));
    }
    serde_json::from_slice(&frames[0]).map_err(|_| WorkerError::UnitBindingMismatch)
}

async fn send_worker_event(
    sender: &mut zeromq::DealerSendHalf,
    event: &WorkerEventV1,
) -> Result<(), WorkerError> {
    let body = serde_json::to_vec(event).map_err(|_| WorkerError::UnitBindingMismatch)?;
    sender
        .send(body.into())
        .await
        .map_err(|error| WorkerError::MessageTransport(error.to_string()))
}

fn require_lease_active(cancelled: Option<&AtomicBool>) -> Result<(), WorkerError> {
    if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
        Err(WorkerError::LeaseCancelled)
    } else {
        Ok(())
    }
}

fn decode_success<T: serde::de::DeserializeOwned>(
    response: reqwest::blocking::Response,
) -> Result<T, WorkerError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response.json()?);
    }
    Err(WorkerError::SupervisorHttp {
        status: status.as_u16(),
        body: response.text().unwrap_or_default(),
    })
}

fn execute_claimed_unit(
    config: &WorkerConfig,
    request: &RunUnitV1,
    cancelled: Option<&AtomicBool>,
) -> Result<UnitFinishedV1, WorkerError> {
    require_lease_active(cancelled)?;
    let reader = FilesystemCasReader::open(&config.cas_root, config.cas_limits)?;
    let inbox = WorkerInbox::open(&config.inbox_root, config.inbox_limits)?;
    let limits = poc_schema_limits();
    if request.protocol_bundle_hash != config.identity.protocol_bundle_hash {
        return Err(WorkerError::UnitBindingMismatch);
    }
    if request.plan_hash.is_zero() {
        return Err(WorkerError::ZeroPlanHash);
    }
    let spec = UnitSpecV1::decode_canonical(&request.canonical_unit_spec.0, &limits)?;
    if spec.protocol_bundle_hash != request.protocol_bundle_hash
        || spec.job_id != request.job_id
        || spec.attempt != request.attempt
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let unit_id = spec.unit_id(&limits)?;
    let plan_object = reader.read_verified(&request.plan_ref)?;
    let plan = PlanCommitmentV1::decode_canonical_record(plan_object.bytes(), &limits)?;
    let manifest_object = reader.read_verified(&request.input_manifest_ref)?;
    let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), &limits)?;
    manifest.validate_against_bundle(config.protocol_bundle.bundle(), &limits)?;
    if manifest.job_id != spec.job_id || manifest.attempt != spec.attempt {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let manifest_hash = manifest.manifest_hash(&limits)?;
    require_plan_binding(
        &plan,
        ExpectedPlanBindingsV1 {
            plan_hash: request.plan_hash,
            protocol_bundle_hash: request.protocol_bundle_hash,
            job_id: request.job_id,
            attempt: request.attempt,
            input_manifest_hash: manifest_hash,
            wwd: manifest.wwd,
            tribute_count: manifest.tribute_count,
            planner_spec_version: spec.planner_spec_version,
            reducer_spec_version: spec.reducer_spec_version,
        },
        &limits,
    )?;
    if spec.phase == UnitPhase::Enumerate {
        verify_ordered_list_membership(
            ListKind::UnitSpecificationsArtifacts,
            plan.primary_work_unit_count,
            request.unit_index,
            &request.canonical_unit_spec.0,
            &request.unit_membership_siblings,
            plan.primary_work_unit_root,
        )?;
    } else if !request.unit_membership_siblings.is_empty() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    require_authenticated_input(
        &spec,
        InputPurpose::InputManifest,
        manifest_hash,
        1,
        request.input_manifest_ref.encoded_bytes,
    )?;
    let mut input_chunks = Vec::new();
    let mut producer_artifacts = Vec::new();
    for reference in &request.ordered_input_refs {
        require_lease_active(cancelled)?;
        let object = reader.read_verified(reference)?;
        match reference.expected_ocb1_kind {
            Some(kind) if kind == ObjectKind::AuthenticatedInputChunkV1.tag() => {
                let derived =
                    derive_input_chunk_ref(&object, config.protocol_bundle.bundle(), &limits)?
                        .reference;
                let chunk =
                    decode_verified_input_chunk(&object, config.protocol_bundle.bundle(), &limits)?;
                if chunk.job_id != spec.job_id
                    || chunk.protocol_bundle_hash != spec.protocol_bundle_hash
                {
                    return Err(WorkerError::UnitBindingMismatch);
                }
                input_chunks.push((derived, chunk));
            }
            Some(kind) if kind == ObjectKind::UnitArtifactV1.tag() => {
                producer_artifacts.push(UnitArtifactV1::decode_canonical(object.bytes(), &limits)?);
            }
            _ => return Err(WorkerError::UnitBindingMismatch),
        }
    }

    require_lease_active(cancelled)?;
    let finished = match execute_unit(
        &spec,
        UnitExecutionAuthority {
            plan: &plan,
            unit_index: request.unit_index,
            manifest: &manifest,
            input_chunks: &input_chunks,
            producer_artifacts: &producer_artifacts,
            bundle: config.protocol_bundle.bundle(),
            limits: &limits,
            reader: &reader,
            inbox: &inbox,
            cancelled,
        },
    )
    .and_then(|artifact| {
        require_lease_active(cancelled)?;
        artifact
            .encode_canonical(&limits)
            .map_err(WorkerError::from)
    })
    .and_then(|bytes| {
        require_lease_active(cancelled)?;
        inbox.adopt(unit_id, &bytes).map_err(WorkerError::from)
    }) {
        Ok(staged) => {
            let reference = staged.reference();
            UnitFinishedV1 {
                unit_id,
                status: UnitFinishedStatus::Success,
                exact_staged_bytes: reference.encoded_bytes,
                transport_digest: reference.transport_digest,
            }
        }
        Err(error) => {
            eprintln!(
                "OCOMP worker unit failed: unit={unit_id:#x} phase={:?} index={} error={error}",
                spec.phase, request.unit_index
            );
            UnitFinishedV1 {
                unit_id,
                status: UnitFinishedStatus::Failed,
                exact_staged_bytes: 0,
                transport_digest: B256::ZERO,
            }
        }
    };
    Ok(finished)
}

pub(crate) fn execute_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    require_lease_active(authority.cancelled)?;
    match spec.phase {
        UnitPhase::Enumerate => execute_enumerate_unit(
            spec,
            authority.manifest,
            authority.input_chunks,
            authority.producer_artifacts,
            authority.limits,
            authority.cancelled,
        ),
        UnitPhase::FidelityMap => execute_fidelity_map_unit(spec, authority),
        UnitPhase::FixedReduce => execute_fixed_reduce_unit(spec, authority),
        UnitPhase::AmountMap => execute_amount_map_unit(spec, authority),
        UnitPhase::GratisPrefix => execute_gratis_prefix_unit(spec, authority),
        UnitPhase::GratisPrefixDown => execute_gratis_prefix_down_unit(spec, authority),
        UnitPhase::OutputFinalize => execute_output_finalize_unit(spec, authority),
        UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle => execute_shuffle_unit(spec, authority),
        UnitPhase::RootReduce => execute_root_reduce_unit(spec, authority),
    }
}

fn execute_enumerate_unit(
    spec: &UnitSpecV1,
    manifest: &InputManifestV1,
    input_chunks: &[(InputChunkRefV1, AuthenticatedInputChunkV1)],
    producer_artifacts: &[UnitArtifactV1],
    limits: &SchemaLimits,
    cancelled: Option<&AtomicBool>,
) -> Result<UnitArtifactV1, WorkerError> {
    if !producer_artifacts.is_empty() || input_chunks.len() != 1 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let (reference, chunk) = &input_chunks[0];
    if chunk.kind != InputChunkKind::Tribute {
        return Err(WorkerError::UnitBindingMismatch);
    }
    require_authenticated_input(
        spec,
        InputPurpose::TributeStream,
        reference.semantic_digest,
        reference.record_count,
        reference.encoded_bytes,
    )?;
    let UnitInterval::EntityIdRange(range) = &spec.interval else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let mut tributes = Vec::new();
    tributes
        .try_reserve_exact(chunk.canonical_records_or_openings.len())
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    for record in &chunk.canonical_records_or_openings {
        require_lease_active(cancelled)?;
        let tribute = decode_tribute_v1(&record.0)?;
        let id = *tribute.tribute_id;
        if id < range.start || range.end.is_some_and(|end| id >= end) {
            return Err(WorkerError::UnitBindingMismatch);
        }
        tributes.push(TributeInputV1::from(&tribute));
    }
    if tributes
        .first()
        .map(|tribute| tribute.tribute_id.as_slice())
        != Some(&range.start.0)
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let start_ordinal = chunk
        .ordinal
        .checked_mul(256)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let run = enumerate_tributes(start_ordinal, WorldwideDay::new(manifest.wwd), &tributes)?;
    let coverage_root = run.coverage_root()?;
    let output_count =
        u32::try_from(run.ordered_records.len()).map_err(|_| WorkerError::UnitBindingMismatch)?;
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: output_count,
            output_coverage_count: output_count,
        },
        BoundedBytes(encode_enumerated_run(&run, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_fidelity_map_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    let shard_ordinal = unit_index
        .checked_sub(plan.primary_work_unit_count)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    if shard_ordinal >= plan.primary_work_unit_count || producer_artifacts.len() != 1 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let enumerate_unit_id = exact_unit_output_source(spec, InputPurpose::EnumeratedTributes)?;
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    if planner.fidelity_map_unit_at(shard_ordinal, enumerate_unit_id, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let primary_spec = planner.primary_unit_at(
        shard_ordinal,
        |ordinal| {
            input_chunks
                .iter()
                .find(|(reference, chunk)| {
                    reference.kind == InputChunkKind::Tribute
                        && chunk.kind == InputChunkKind::Tribute
                        && reference.ordinal == ordinal
                })
                .map(|(reference, _)| reference.clone())
        },
        limits,
    )?;
    let producer = &producer_artifacts[0];
    producer.validate_against(&primary_spec, limits)?;
    if producer.unit_id != enumerate_unit_id || producer.phase != UnitPhase::Enumerate {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let enumerated = decode_enumerated_run(producer.phase_payload(limits)?, limits)?;
    let producer_header = producer.output_header(limits)?;
    if enumerated.coverage_root()? != producer_header.output_coverage_root
        || enumerated.ordered_records.len()
            != usize::try_from(producer_header.output_coverage_count)
                .map_err(|_| WorkerError::UnitBindingMismatch)?
    {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let mut leagues = BTreeMap::new();
    let mut fidelity_opening_count = 0_u32;
    let mut fidelity_encoded_bytes = 0_u64;
    for (reference, chunk) in input_chunks {
        require_lease_active(cancelled)?;
        match chunk.kind {
            InputChunkKind::Tribute => {}
            InputChunkKind::Fidelity => {
                fidelity_encoded_bytes = fidelity_encoded_bytes
                    .checked_add(reference.encoded_bytes)
                    .ok_or(WorkerError::UnitBindingMismatch)?;
                for encoded in &chunk.canonical_records_or_openings {
                    require_lease_active(cancelled)?;
                    fidelity_opening_count = fidelity_opening_count
                        .checked_add(1)
                        .ok_or(WorkerError::UnitBindingMismatch)?;
                    let opening =
                        AuthenticatedOpeningV1::decode_canonical_record(&encoded.0, limits)?;
                    if opening.source_kind != OpeningSourceKind::Fidelity {
                        return Err(WorkerError::UnitBindingMismatch);
                    }
                    opening.validate_against_bundle(bundle, limits)?;
                    let raw = opening.decode_and_validate_raw_opening(
                        manifest.checkpoint.finalized_state_root,
                        limits,
                    )?;
                    let owners = decode_fidelity_subject_key(&opening.canonical_subject_key.0)?;
                    let slot_values = raw
                        .ordered_slots
                        .iter()
                        .map(|slot| (slot.slot, slot.value))
                        .collect::<BTreeMap<_, _>>();
                    for owner in &owners {
                        require_lease_active(cancelled)?;
                        // Independently re-derive each owner's snapshot slot rather
                        // than trusting slot order; the MPT-proven value is the
                        // on-chain league Metadosis committed for this day at
                        // prepare time. An absent (zero) or out-of-range word means
                        // the owner was not snapshotted and is rejected.
                        let slot = league_snapshot_slot(manifest.wwd, *owner);
                        let word = slot_values
                            .get(&slot)
                            .copied()
                            .ok_or(WorkerError::UnitBindingMismatch)?;
                        if word.is_zero() || word > U256::from(u16::MAX) {
                            return Err(WorkerError::UnitBindingMismatch);
                        }
                        if leagues.insert(*owner, word.to::<u16>()).is_some() {
                            return Err(WorkerError::UnitBindingMismatch);
                        }
                    }
                }
            }
            InputChunkKind::Oracle => return Err(WorkerError::UnitBindingMismatch),
        }
    }
    require_authenticated_input(
        spec,
        InputPurpose::FidelityOpenings,
        manifest.fidelity_opening_root,
        fidelity_opening_count,
        fidelity_encoded_bytes,
    )?;

    let mut observed = Vec::new();
    observed
        .try_reserve_exact(enumerated.ordered_records.len())
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    for record in &enumerated.ordered_records {
        require_lease_active(cancelled)?;
        let league = leagues
            .get(&record.tribute.owner)
            .copied()
            .ok_or(WorkerError::UnitBindingMismatch)?;
        observed.push(ObservedTributeV1 {
            tribute: record.tribute.clone(),
            first_league: ObservationValueV1::Value(league),
            second_league: ObservationValueV1::Value(league),
            conditional_entry_price_minor: ObservationValueV1::Unavailable,
            nod_target_available: true,
        });
    }
    let output =
        fidelity_map(enumerated.start_ordinal, &observed).map_err(LysisArtifactErrorV1::from)?;
    let output_coverage_root = output.coverage_root()?;
    if output_coverage_root != producer_header.output_coverage_root {
        return Err(WorkerError::UnitBindingMismatch);
    }
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: producer_header.output_coverage_root,
            output_coverage_root,
            source_coverage_count: producer_header.output_coverage_count,
            output_coverage_count: output.aggregate.tribute_count,
        },
        BoundedBytes(encode_fidelity_map_output(&output, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

struct FixedReduceInputV1 {
    value: FidelityReduceValueV1,
    coverage: RawCoverageCarrierV1,
}

fn execute_fixed_reduce_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let fixed_reduce_offset = plan
        .primary_work_unit_count
        .checked_mul(2)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let phase_ordinal = unit_index
        .checked_sub(fixed_reduce_offset)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let position = topology.phase_position_at(UnitPhase::FixedReduce, phase_ordinal)?;
    let PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::FixedReduce,
        level,
        index,
    } = position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let reducer_inputs = spec
        .canonical_ordered_inputs
        .iter()
        .filter(|input| input.purpose == InputPurpose::FidelityPartials)
        .collect::<Vec<_>>();
    if reducer_inputs.len() != 2 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let producer_ids = reducer_inputs
        .iter()
        .map(|input| match input.source_kind {
            InputSourceKind::UnitOutput if !input.source_id.is_zero() => Ok(Some(input.source_id)),
            InputSourceKind::CanonicalEmpty => Ok(None),
            _ => Err(WorkerError::UnitBindingMismatch),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let producer_ids: [Option<B256>; 2] = producer_ids
        .try_into()
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    if planner.fixed_reduce_unit_at(phase_ordinal, producer_ids, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let expected_producers = topology.required_producers(position)?;
    let mut artifacts = producer_artifacts.iter();
    let mut decoded_inputs = Vec::with_capacity(2);
    for (expected, input) in expected_producers.into_iter().zip(reducer_inputs) {
        require_lease_active(cancelled)?;
        match expected {
            PlannedProducerV1::CanonicalEmpty {
                purpose: InputPurpose::FidelityPartials,
                padded_ordinal,
            } => {
                if input.source_kind != InputSourceKind::CanonicalEmpty {
                    return Err(WorkerError::UnitBindingMismatch);
                }
                decoded_inputs.push(FixedReduceInputV1 {
                    value: FidelityReduceValueV1::Empty,
                    coverage: RawCoverageCarrierV1::canonical_empty(
                        plan.tribute_count,
                        padded_ordinal,
                    )?,
                });
            }
            PlannedProducerV1::Unit(producer_position) => {
                if input.source_kind != InputSourceKind::UnitOutput {
                    return Err(WorkerError::UnitBindingMismatch);
                }
                let artifact = artifacts.next().ok_or(WorkerError::UnitBindingMismatch)?;
                decoded_inputs.push(decode_fixed_reduce_producer(
                    artifact,
                    input.source_id,
                    producer_position,
                    spec,
                    plan,
                    limits,
                )?);
            }
            _ => return Err(WorkerError::UnitBindingMismatch),
        }
    }
    if artifacts.next().is_some() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let [left, right]: [FixedReduceInputV1; 2] = decoded_inputs
        .try_into()
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    let single_primary_root = plan.primary_work_unit_count == 1 && level == 1 && index == 0;
    let (value, coverage) = if single_primary_root {
        if !matches!(&right.value, FidelityReduceValueV1::Empty)
            || !matches!(&left.value, FidelityReduceValueV1::Aggregate(_))
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
        (left.value, left.coverage)
    } else {
        (
            fidelity_reduce_pair(left.value, right.value).map_err(LysisArtifactErrorV1::from)?,
            RawCoverageCarrierV1::merge(&left.coverage, &right.coverage)?,
        )
    };
    let is_root = level == topology.tree().height() && index == 0;
    let aggregate = match value {
        FidelityReduceValueV1::Empty => None,
        FidelityReduceValueV1::Aggregate(aggregate) => Some(aggregate),
    };
    let ordered_fractions = if is_root {
        finalize_fi_fraction_table(
            aggregate.as_ref().ok_or(WorkerError::UnitBindingMismatch)?,
            plan.lysis_budget,
        )
        .map_err(LysisArtifactErrorV1::from)?
    } else {
        Vec::new()
    };
    let output_count = aggregate
        .as_ref()
        .map_or(0, |aggregate| aggregate.tribute_count);
    let coverage_root = if is_root {
        coverage.final_root(plan.tribute_count)?
    } else {
        coverage.tree_root
    };
    let output = FixedReduceOutputV1 {
        aggregate,
        coverage,
        ordered_fractions,
    };
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: output_count,
            output_coverage_count: output_count,
        },
        BoundedBytes(encode_fixed_reduce_output(&output, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn decode_fixed_reduce_producer(
    artifact: &UnitArtifactV1,
    expected_unit_id: B256,
    position: PlannedUnitPositionV1,
    consumer_spec: &UnitSpecV1,
    plan: &PlanCommitmentV1,
    limits: &SchemaLimits,
) -> Result<FixedReduceInputV1, WorkerError> {
    artifact.validate_semantics(limits)?;
    if artifact.unit_id != expected_unit_id
        || artifact.protocol_bundle_hash != consumer_spec.protocol_bundle_hash
        || artifact.job_id != consumer_spec.job_id
        || artifact.attempt != consumer_spec.attempt
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let (phase, interval) = match position {
        PlannedUnitPositionV1::Primary {
            phase: UnitPhase::FidelityMap,
            ordinal,
        } => {
            let start = ordinal
                .checked_mul(PRIMARY_WORK_SHARD_SIZE)
                .ok_or(WorkerError::UnitBindingMismatch)?;
            let end = start
                .saturating_add(PRIMARY_WORK_SHARD_SIZE)
                .min(plan.tribute_count);
            (
                UnitPhase::FidelityMap,
                UnitInterval::FidelityIndexRange(FidelityIndexHalfOpenRange { start, end }),
            )
        }
        PlannedUnitPositionV1::TreeNode {
            phase: UnitPhase::FixedReduce,
            level,
            index,
        } => (
            UnitPhase::FixedReduce,
            UnitInterval::BinaryReducerNode(BinaryReducerNode { level, index }),
        ),
        _ => return Err(WorkerError::UnitBindingMismatch),
    };
    let mut interval_binding = consumer_spec.clone();
    interval_binding.phase = phase;
    interval_binding.interval = interval;
    if artifact.phase != phase
        || artifact.interval_commitment != interval_binding.interval_commitment(limits)?
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let header = artifact.output_header(limits)?;
    match phase {
        UnitPhase::FidelityMap => {
            let output = decode_fidelity_map_output(artifact.phase_payload(limits)?, limits)?;
            if output.coverage_root()? != header.output_coverage_root
                || output.aggregate.tribute_count != header.output_coverage_count
            {
                return Err(WorkerError::UnitBindingMismatch);
            }
            let records = output
                .observations
                .iter()
                .map(|observation| (observation.raw_ordinal, observation.tribute_id))
                .collect::<Vec<_>>();
            let coverage = RawCoverageCarrierV1::from_records(plan.tribute_count, &records)?;
            Ok(FixedReduceInputV1 {
                value: FidelityReduceValueV1::Aggregate(output.aggregate),
                coverage,
            })
        }
        UnitPhase::FixedReduce => {
            let output = decode_fixed_reduce_output(artifact.phase_payload(limits)?, limits)?;
            let output_count = output
                .aggregate
                .as_ref()
                .map_or(0, |aggregate| aggregate.tribute_count);
            if !output.ordered_fractions.is_empty()
                || output.coverage.tree_root != header.output_coverage_root
                || output_count != header.output_coverage_count
            {
                return Err(WorkerError::UnitBindingMismatch);
            }
            Ok(FixedReduceInputV1 {
                value: output.aggregate.map_or(
                    FidelityReduceValueV1::Empty,
                    FidelityReduceValueV1::Aggregate,
                ),
                coverage: output.coverage,
            })
        }
        _ => Err(WorkerError::UnitBindingMismatch),
    }
}

fn execute_amount_map_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    if producer_artifacts.len() != 3 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let amount_offset = plan
        .primary_work_unit_count
        .checked_mul(2)
        .and_then(|offset| offset.checked_add(topology.phase_unit_count(UnitPhase::FixedReduce)))
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let shard_ordinal = unit_index
        .checked_sub(amount_offset)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    if shard_ordinal >= plan.primary_work_unit_count {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let enumerate_unit_id = exact_unit_output_source(spec, InputPurpose::EnumeratedTributes)?;
    let fidelity_unit_id = exact_unit_output_source(spec, InputPurpose::FidelityPartials)?;
    let fraction_root_unit_id = exact_unit_output_source(spec, InputPurpose::FiFractionTable)?;

    let primary_spec = planner.primary_unit_at(
        shard_ordinal,
        |ordinal| {
            input_chunks
                .iter()
                .find(|(reference, chunk)| {
                    reference.kind == InputChunkKind::Tribute
                        && chunk.kind == InputChunkKind::Tribute
                        && reference.ordinal == ordinal
                })
                .map(|(reference, _)| reference.clone())
        },
        limits,
    )?;
    if primary_spec.unit_id(limits)? != enumerate_unit_id
        || planner.amount_map_unit_at(
            shard_ordinal,
            &primary_spec,
            fidelity_unit_id,
            fraction_root_unit_id,
            limits,
        )? != spec.clone()
    {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let enumerate_artifact = &producer_artifacts[0];
    enumerate_artifact.validate_against(&primary_spec, limits)?;
    let enumerated = decode_enumerated_run(enumerate_artifact.phase_payload(limits)?, limits)?;
    let enumerate_header = enumerate_artifact.output_header(limits)?;
    if enumerated.coverage_root()? != enumerate_header.output_coverage_root
        || enumerate_header.output_coverage_count
            != u32::try_from(enumerated.ordered_records.len())
                .map_err(|_| WorkerError::UnitBindingMismatch)?
    {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let fidelity_spec = planner.fidelity_map_unit_at(shard_ordinal, enumerate_unit_id, limits)?;
    let fidelity_artifact = &producer_artifacts[1];
    fidelity_artifact.validate_against(&fidelity_spec, limits)?;
    if fidelity_artifact.unit_id != fidelity_unit_id {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let fidelity = decode_fidelity_map_output(fidelity_artifact.phase_payload(limits)?, limits)?;
    let fidelity_header = fidelity_artifact.output_header(limits)?;
    if fidelity.coverage_root()? != fidelity_header.output_coverage_root
        || fidelity_header.output_coverage_root != enumerate_header.output_coverage_root
        || fidelity.aggregate.tribute_count != fidelity_header.output_coverage_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let root_artifact = &producer_artifacts[2];
    root_artifact.validate_semantics(limits)?;
    let root_interval = UnitInterval::BinaryReducerNode(BinaryReducerNode {
        level: topology.tree().height(),
        index: 0,
    });
    let mut root_interval_binding = spec.clone();
    root_interval_binding.phase = UnitPhase::FixedReduce;
    root_interval_binding.interval = root_interval;
    if root_artifact.unit_id != fraction_root_unit_id
        || root_artifact.protocol_bundle_hash != spec.protocol_bundle_hash
        || root_artifact.job_id != spec.job_id
        || root_artifact.attempt != spec.attempt
        || root_artifact.phase != UnitPhase::FixedReduce
        || root_artifact.interval_commitment != root_interval_binding.interval_commitment(limits)?
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let root_output = decode_fixed_reduce_output(root_artifact.phase_payload(limits)?, limits)?;
    let root_header = root_artifact.output_header(limits)?;
    let root_aggregate = root_output
        .aggregate
        .as_ref()
        .ok_or(WorkerError::UnitBindingMismatch)?;
    if root_output.ordered_fractions.is_empty()
        || root_aggregate.tribute_count != plan.tribute_count
        || root_output.coverage.final_root(plan.tribute_count)? != root_header.output_coverage_root
        || root_header.output_coverage_count != plan.tribute_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let oracle_chunks = input_chunks
        .iter()
        .filter(|(_, chunk)| chunk.kind == InputChunkKind::Oracle)
        .collect::<Vec<_>>();
    if oracle_chunks.len() != 1 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let (oracle_reference, oracle_chunk) = oracle_chunks[0];
    if oracle_chunk.canonical_records_or_openings.len() != 1 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    require_authenticated_input(
        spec,
        InputPurpose::OracleOpenings,
        manifest.oracle_opening_root,
        1,
        oracle_reference.encoded_bytes,
    )?;
    let opening = AuthenticatedOpeningV1::decode_canonical_record(
        &oracle_chunk.canonical_records_or_openings[0].0,
        limits,
    )?;
    if opening.source_kind != OpeningSourceKind::Oracle {
        return Err(WorkerError::UnitBindingMismatch);
    }
    opening.validate_against_bundle(bundle, limits)?;
    let (oracle_wwd, reference_isos) = decode_oracle_subject_key(&opening.canonical_subject_key.0)?;
    if oracle_wwd != manifest.wwd {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let raw = opening
        .decode_and_validate_raw_opening(manifest.checkpoint.finalized_state_root, limits)?;
    let raw_slots = raw
        .ordered_slots
        .iter()
        .map(|slot| (slot.slot, slot.value))
        .collect::<Vec<_>>();
    let oracle =
        evaluate_oracle_opening_v1(WorldwideDay::new(manifest.wwd), &reference_isos, &raw_slots)?;
    let mandatory_entry_price = oracle
        .entry_price(840)
        .ok_or(WorkerError::UnitBindingMismatch)?;

    let mut observed = Vec::new();
    observed
        .try_reserve_exact(enumerated.ordered_records.len())
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    for (record, fidelity) in enumerated
        .ordered_records
        .iter()
        .zip(&fidelity.observations)
    {
        require_lease_active(cancelled)?;
        if record.raw_ordinal != fidelity.raw_ordinal
            || record.tribute.tribute_id != fidelity.tribute_id
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
        observed.push(ObservedTributeV1 {
            tribute: record.tribute.clone(),
            first_league: ObservationValueV1::Value(fidelity.pre_distribution_league),
            second_league: ObservationValueV1::Value(fidelity.issuance_league),
            conditional_entry_price_minor: oracle
                .entry_price(record.tribute.reference_currency)
                .map_or(ObservationValueV1::Unavailable, ObservationValueV1::Value),
            nod_target_available: true,
        });
    }
    let amount = amount_map(
        enumerated.start_ordinal,
        &observed,
        &fidelity.observations,
        &root_output.ordered_fractions,
        mandatory_entry_price,
    )
    .map_err(LysisArtifactErrorV1::from)?;
    let output_coverage_root = amount.coverage_root()?;
    if output_coverage_root != enumerate_header.output_coverage_root {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let output_count = u32::try_from(amount.ordered_records.len())
        .map_err(|_| WorkerError::UnitBindingMismatch)?;
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: enumerate_header.output_coverage_root,
            output_coverage_root,
            source_coverage_count: enumerate_header.output_coverage_count,
            output_coverage_count: output_count,
        },
        BoundedBytes(encode_amount_run(&amount, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_gratis_prefix_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let phase_ordinal = unit_index
        .checked_sub(topology.phase_offset(UnitPhase::GratisPrefix)?)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let position = topology.phase_position_at(UnitPhase::GratisPrefix, phase_ordinal)?;
    let PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::GratisPrefix,
        level,
        index,
    } = position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let purpose = if level == 0 {
        InputPurpose::AmountRecords
    } else {
        InputPurpose::GratisPrefixTable
    };
    let producer_inputs = scan_producer_inputs(spec, purpose)?;
    let producer_ids = producer_inputs
        .iter()
        .map(|input| unit_or_empty_id(input))
        .collect::<Result<Vec<_>, _>>()?;
    if planner.gratis_prefix_unit_at(phase_ordinal, &producer_ids, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let expected = topology.required_producers(position)?;
    let resolved = resolve_scan_artifacts(
        spec,
        &expected,
        &producer_inputs,
        producer_artifacts,
        limits,
    )?;

    let (summary, coverage_root, coverage_count) = if level == 0 {
        let amount_artifact = resolved
            .first()
            .and_then(|artifact| *artifact)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        if amount_artifact.phase != UnitPhase::AmountMap {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let amount = decode_amount_run(amount_artifact.phase_payload(limits)?, limits)?;
        let amount_header = amount_artifact.output_header(limits)?;
        let expected_start = index
            .checked_mul(PRIMARY_WORK_SHARD_SIZE)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        if amount.start_ordinal != expected_start
            || amount.end_ordinal > plan.tribute_count
            || amount.coverage_root()? != amount_header.output_coverage_root
            || amount_header.output_coverage_count
                != u32::try_from(amount.ordered_records.len())
                    .map_err(|_| WorkerError::UnitBindingMismatch)?
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let summary = gratis_summary(
            amount.start_ordinal,
            &amount
                .ordered_records
                .iter()
                .map(|record| record.gratis_load_minor)
                .collect::<Vec<_>>(),
        )
        .map_err(LysisArtifactErrorV1::from)?;
        (
            summary,
            amount_header.output_coverage_root,
            amount_header.output_coverage_count,
        )
    } else {
        let mut values = [GratisSummaryValueV1::Empty, GratisSummaryValueV1::Empty];
        let mut child_coverage = [None, None];
        for (child_index, artifact) in resolved.into_iter().enumerate() {
            require_lease_active(cancelled)?;
            let Some(artifact) = artifact else {
                continue;
            };
            let summary = decode_gratis_segment_summary(artifact.phase_payload(limits)?, limits)?;
            let header = artifact.output_header(limits)?;
            if summary.end_ordinal - summary.start_ordinal != header.output_coverage_count {
                return Err(WorkerError::UnitBindingMismatch);
            }
            values[child_index] = GratisSummaryValueV1::Summary(summary);
            child_coverage[child_index] =
                Some((header.output_coverage_root, header.output_coverage_count));
        }
        let summary = match gratis_summary_reduce_pair(values[0].clone(), values[1].clone())
            .map_err(LysisArtifactErrorV1::from)?
        {
            GratisSummaryValueV1::Summary(summary) => summary,
            GratisSummaryValueV1::Empty => return Err(WorkerError::UnitBindingMismatch),
        };
        let coverage = gratis_summary_coverage(spec.interval_commitment(limits)?, child_coverage)?;
        if coverage.count != summary.end_ordinal - summary.start_ordinal {
            return Err(WorkerError::UnitBindingMismatch);
        }
        (summary, coverage.root, coverage.count)
    };

    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: coverage_count,
            output_coverage_count: coverage_count,
        },
        BoundedBytes(encode_gratis_segment_summary(&summary, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_gratis_prefix_down_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let phase_ordinal = unit_index
        .checked_sub(topology.phase_offset(UnitPhase::GratisPrefixDown)?)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let position = topology.phase_position_at(UnitPhase::GratisPrefixDown, phase_ordinal)?;
    let PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::GratisPrefixDown,
        level,
        index,
    } = position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let producer_inputs = scan_producer_inputs(spec, InputPurpose::GratisPrefixTable)?;
    let producer_ids = producer_inputs
        .iter()
        .map(|input| unit_or_empty_id(input))
        .collect::<Result<Vec<_>, _>>()?;
    if planner.gratis_prefix_down_unit_at(phase_ordinal, &producer_ids, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let expected = topology.required_producers(position)?;
    let resolved = resolve_scan_artifacts(
        spec,
        &expected,
        &producer_inputs,
        producer_artifacts,
        limits,
    )?;

    if level == 0 {
        let parent = resolved
            .first()
            .and_then(|artifact| *artifact)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let summary_artifact = resolved
            .get(1)
            .and_then(|artifact| *artifact)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let GratisPrefixDownOutputV1::Branch(children) =
            decode_gratis_prefix_down_output(parent.phase_payload(limits)?, limits)?
        else {
            return Err(WorkerError::UnitBindingMismatch);
        };
        let incoming = children
            [usize::try_from(index & 1).map_err(|_| WorkerError::UnitBindingMismatch)?]
        .as_ref()
        .ok_or(WorkerError::UnitBindingMismatch)?;
        let summary =
            decode_gratis_segment_summary(summary_artifact.phase_payload(limits)?, limits)?;
        let summary_header = summary_artifact.output_header(limits)?;
        if incoming.start_ordinal != summary.start_ordinal
            || incoming.end_ordinal != summary.end_ordinal
            || summary.end_ordinal - summary.start_ordinal != summary_header.output_coverage_count
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let incoming_remaining = incoming
            .incoming_remaining
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let outgoing_remaining = incoming_remaining
            .checked_sub(summary.checked_segment_gratis_total)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let output = GratisPrefixDownOutputV1::Leaf(GratisLeafPrefixV1 {
            segment_ordinal: index,
            incoming_remaining,
            outgoing_remaining,
            first_error_ordinal: None,
        });
        return UnitArtifactV1::from_canonical_output(
            spec,
            WorkOutputHeaderV1 {
                source_coverage_root: summary_header.output_coverage_root,
                output_coverage_root: summary_header.output_coverage_root,
                source_coverage_count: summary_header.output_coverage_count,
                output_coverage_count: summary_header.output_coverage_count,
            },
            BoundedBytes(encode_gratis_prefix_down_output(&output, limits)?),
            limits,
        )
        .map_err(WorkerError::from);
    }

    let is_root = level == topology.tree().height() && index == 0;
    let (incoming_remaining, child_start) = if is_root {
        (Some(plan.lysis_budget), 0)
    } else {
        let parent = resolved
            .first()
            .and_then(|artifact| *artifact)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let GratisPrefixDownOutputV1::Branch(children) =
            decode_gratis_prefix_down_output(parent.phase_payload(limits)?, limits)?
        else {
            return Err(WorkerError::UnitBindingMismatch);
        };
        let incoming = children
            [usize::try_from(index & 1).map_err(|_| WorkerError::UnitBindingMismatch)?]
        .as_ref()
        .ok_or(WorkerError::UnitBindingMismatch)?;
        (incoming.incoming_remaining, 1)
    };
    let mut values = [GratisSummaryValueV1::Empty, GratisSummaryValueV1::Empty];
    let mut child_coverage = [None, None];
    for child_index in 0..2 {
        require_lease_active(cancelled)?;
        let Some(artifact) = resolved
            .get(child_start + child_index)
            .and_then(|artifact| *artifact)
        else {
            continue;
        };
        let summary = decode_gratis_segment_summary(artifact.phase_payload(limits)?, limits)?;
        let header = artifact.output_header(limits)?;
        if summary.end_ordinal - summary.start_ordinal != header.output_coverage_count {
            return Err(WorkerError::UnitBindingMismatch);
        }
        values[child_index] = GratisSummaryValueV1::Summary(summary);
        child_coverage[child_index] =
            Some((header.output_coverage_root, header.output_coverage_count));
    }
    let combined = match gratis_summary_reduce_pair(values[0].clone(), values[1].clone())
        .map_err(LysisArtifactErrorV1::from)?
    {
        GratisSummaryValueV1::Summary(summary) => summary,
        GratisSummaryValueV1::Empty => return Err(WorkerError::UnitBindingMismatch),
    };
    let children = gratis_prefix_down(incoming_remaining, values[0].clone(), values[1].clone())
        .map_err(LysisArtifactErrorV1::from)?;
    if !is_root {
        let parent = resolved[0].ok_or(WorkerError::UnitBindingMismatch)?;
        let GratisPrefixDownOutputV1::Branch(parent_children) =
            decode_gratis_prefix_down_output(parent.phase_payload(limits)?, limits)?
        else {
            return Err(WorkerError::UnitBindingMismatch);
        };
        let assigned = parent_children
            [usize::try_from(index & 1).map_err(|_| WorkerError::UnitBindingMismatch)?]
        .as_ref()
        .ok_or(WorkerError::UnitBindingMismatch)?;
        if assigned.start_ordinal != combined.start_ordinal
            || assigned.end_ordinal != combined.end_ordinal
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
    }
    let mut prefix_spec = spec.clone();
    prefix_spec.phase = UnitPhase::GratisPrefix;
    let coverage =
        gratis_summary_coverage(prefix_spec.interval_commitment(limits)?, child_coverage)?;
    if coverage.count != combined.end_ordinal - combined.start_ordinal {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let output = GratisPrefixDownOutputV1::Branch(children);
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage.root,
            output_coverage_root: coverage.root,
            source_coverage_count: coverage.count,
            output_coverage_count: coverage.count,
        },
        BoundedBytes(encode_gratis_prefix_down_output(&output, limits)?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_output_finalize_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        cancelled,
        ..
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty() || producer_artifacts.len() != 2 {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let shard_ordinal = unit_index
        .checked_sub(topology.phase_offset(UnitPhase::OutputFinalize)?)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    if shard_ordinal >= plan.primary_work_unit_count {
        return Err(WorkerError::UnitBindingMismatch);
    }
    replay_output_finalize_artifact(
        shard_ordinal,
        spec,
        &producer_artifacts[0],
        &producer_artifacts[1],
        plan,
        manifest,
        bundle,
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_shuffle_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        reader,
        inbox,
        cancelled,
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty()
        || !matches!(
            spec.phase,
            UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle
        )
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let phase_offset = topology.phase_offset(spec.phase)?;
    let phase_ordinal = unit_index
        .checked_sub(phase_offset)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let position = topology.phase_position_at(spec.phase, phase_ordinal)?;
    let PlannedUnitPositionV1::RunSpan {
        level,
        start_run,
        end_run,
        ..
    } = position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let run_span = outbe_ocomp_protocol::unit::CanonicalRunSpan { start_run, end_run };
    let purpose = if level == 0 {
        InputPurpose::FinalizedOutputRecords
    } else if spec.phase == UnitPhase::OwnerShuffle {
        InputPurpose::OwnerOrderedRecords
    } else {
        InputPurpose::BucketOrderedRecords
    };
    let producer_inputs = scan_producer_inputs(spec, purpose)?;
    let producer_ids = producer_inputs
        .iter()
        .map(|input| {
            if input.source_kind != InputSourceKind::UnitOutput || input.source_id.is_zero() {
                Err(WorkerError::UnitBindingMismatch)
            } else {
                Ok(input.source_id)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    if planner.shuffle_unit_at(spec.phase, phase_ordinal, &producer_ids, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let expected = topology.required_producers(position)?;
    let resolved = resolve_scan_artifacts(
        spec,
        &expected,
        &producer_inputs,
        producer_artifacts,
        limits,
    )?;
    if resolved.iter().any(Option::is_none) {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let (coverage, owner_records, bucket_records) = if level == 0 {
        if resolved.len() != 1 || end_run != start_run + 1 {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let producer = resolved[0].ok_or(WorkerError::UnitBindingMismatch)?;
        let finalized = decode_finalized_output_run(producer.phase_payload(limits)?, limits)?;
        let header = producer.output_header(limits)?;
        let expected_start = start_run
            .checked_mul(PRIMARY_WORK_SHARD_SIZE)
            .ok_or(WorkerError::UnitBindingMismatch)?;
        let expected_end = end_run
            .checked_mul(PRIMARY_WORK_SHARD_SIZE)
            .ok_or(WorkerError::UnitBindingMismatch)?
            .min(plan.tribute_count);
        if finalized.start_ordinal != expected_start
            || finalized.end_ordinal != expected_end
            || finalized.coverage_root()? != header.output_coverage_root
            || finalized.end_ordinal - finalized.start_ordinal != header.output_coverage_count
        {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let coverage = ShuffleSourceCoverageV1::leaf(
            run_span.clone(),
            header.output_coverage_root,
            header.output_coverage_count,
            limits,
        )?;
        if spec.phase == UnitPhase::OwnerShuffle {
            let owner_run = shuffle_owners(&finalized).map_err(LysisArtifactErrorV1::from)?;
            let records = owner_run
                .ordered_contributors
                .into_iter()
                .map(|record| {
                    Ok(ProtocolContributorActionV1 {
                        owner: record.owner,
                        source_tribute_id: *record.source_tribute_id,
                        nominal_amount_minor: record.nominal_amount_minor,
                    })
                })
                .collect::<Vec<_>>();
            (coverage, Some(records), None)
        } else {
            let bucket_run = shuffle_buckets(&finalized).map_err(LysisArtifactErrorV1::from)?;
            let records = bucket_run
                .ordered_records
                .into_iter()
                .map(|record| {
                    Ok(ShuffleBucketRecordV1 {
                        bucket_key: record.bucket_key,
                        raw_ordinal: record.raw_ordinal,
                        tribute_id: *record.tribute_id,
                        nod_id: *record.nod_id,
                    })
                })
                .collect::<Vec<_>>();
            (coverage, None, Some(records))
        }
    } else {
        if resolved.len() != 2 {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let expected_kind = if spec.phase == UnitPhase::OwnerShuffle {
            ShuffleRunKindV1::Owner
        } else {
            ShuffleRunKindV1::Bucket
        };
        let left = decode_shuffle_producer_root(
            spec,
            resolved[0].ok_or(WorkerError::UnitBindingMismatch)?,
            expected_kind,
            expected[0],
            limits,
        )?;
        let right = decode_shuffle_producer_root(
            spec,
            resolved[1].ok_or(WorkerError::UnitBindingMismatch)?,
            expected_kind,
            expected[1],
            limits,
        )?;
        let coverage = ShuffleSourceCoverageV1::merge(
            &ShuffleSourceCoverageV1 {
                run_span: left.run_span.clone(),
                root: left.source_coverage_root,
                count: left.source_coverage_count,
            },
            &ShuffleSourceCoverageV1 {
                run_span: right.run_span.clone(),
                root: right.source_coverage_root,
                count: right.source_coverage_count,
            },
            limits,
        )?;
        if coverage.run_span != run_span {
            return Err(WorkerError::UnitBindingMismatch);
        }
        let left_records = verified_shuffle_run_records(left, limits, |reference| {
            require_lease_active(cancelled).map_err(|_| {
                outbe_ocomp_protocol::ProtocolError::InvalidInvariant("cancelled shuffle lease")
            })?;
            reader
                .read_verified(reference)
                .map(|object| object.bytes().to_vec())
                .map_err(|_| {
                    outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                        "shuffle producer descendant read",
                    )
                })
        })?;
        let right_records = verified_shuffle_run_records(right, limits, |reference| {
            require_lease_active(cancelled).map_err(|_| {
                outbe_ocomp_protocol::ProtocolError::InvalidInvariant("cancelled shuffle lease")
            })?;
            reader
                .read_verified(reference)
                .map(|object| object.bytes().to_vec())
                .map_err(|_| {
                    outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                        "shuffle producer descendant read",
                    )
                })
        })?;
        let merged = merge_verified_shuffle_runs(expected_kind, left_records, right_records);
        if spec.phase == UnitPhase::OwnerShuffle {
            let records = merged.map(|record| match record? {
                VerifiedShuffleRecordV1::Owner(record) => Ok(record),
                VerifiedShuffleRecordV1::Bucket(_) => {
                    Err(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                        "owner shuffle producer kind",
                    ))
                }
            });
            return build_owner_shuffle_unit_artifact(
                spec, run_span, coverage, records, limits, inbox,
            );
        }
        let records = merged.map(|record| match record? {
            VerifiedShuffleRecordV1::Bucket(record) => Ok(record),
            VerifiedShuffleRecordV1::Owner(_) => {
                Err(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                    "bucket shuffle producer kind",
                ))
            }
        });
        return build_bucket_shuffle_unit_artifact(
            spec, run_span, coverage, records, limits, inbox,
        );
    };

    if let Some(records) = owner_records {
        build_owner_shuffle_unit_artifact(spec, run_span, coverage, records, limits, inbox)
    } else {
        build_bucket_shuffle_unit_artifact(
            spec,
            run_span,
            coverage,
            bucket_records.ok_or(WorkerError::UnitBindingMismatch)?,
            limits,
            inbox,
        )
    }
}

fn build_owner_shuffle_unit_artifact<I>(
    spec: &UnitSpecV1,
    run_span: outbe_ocomp_protocol::unit::CanonicalRunSpan,
    coverage: ShuffleSourceCoverageV1,
    records: I,
    limits: &SchemaLimits,
    inbox: &WorkerInbox,
) -> Result<UnitArtifactV1, WorkerError>
where
    I: IntoIterator<
        Item = Result<ProtocolContributorActionV1, outbe_ocomp_protocol::ProtocolError>,
    >,
{
    if spec.phase != UnitPhase::OwnerShuffle {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let context = ShuffleRunBuildContextV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        unit_id: spec.unit_id(limits)?,
        run_span,
        source_coverage_root: coverage.root,
        source_coverage_count: coverage.count,
    };
    let mut stage = |bytes: &[u8]| {
        inbox.stage_shuffle_object(bytes, limits).map_err(|_| {
            outbe_ocomp_protocol::ProtocolError::InvalidInvariant("shuffle object staging")
        })
    };
    let root = build_owner_shuffle_run(context, records, limits, &mut stage)?;
    finish_shuffle_unit_artifact(spec, root, limits)
}

fn build_bucket_shuffle_unit_artifact<I>(
    spec: &UnitSpecV1,
    run_span: outbe_ocomp_protocol::unit::CanonicalRunSpan,
    coverage: ShuffleSourceCoverageV1,
    records: I,
    limits: &SchemaLimits,
    inbox: &WorkerInbox,
) -> Result<UnitArtifactV1, WorkerError>
where
    I: IntoIterator<Item = Result<ShuffleBucketRecordV1, outbe_ocomp_protocol::ProtocolError>>,
{
    if spec.phase != UnitPhase::BucketShuffle {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let context = ShuffleRunBuildContextV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        unit_id: spec.unit_id(limits)?,
        run_span,
        source_coverage_root: coverage.root,
        source_coverage_count: coverage.count,
    };
    let mut stage = |bytes: &[u8]| {
        inbox.stage_shuffle_object(bytes, limits).map_err(|_| {
            outbe_ocomp_protocol::ProtocolError::InvalidInvariant("shuffle object staging")
        })
    };
    let root = build_bucket_shuffle_run(context, records, limits, &mut stage)?;
    finish_shuffle_unit_artifact(spec, root, limits)
}

fn finish_shuffle_unit_artifact(
    spec: &UnitSpecV1,
    root: ShuffleRunArtifactV1,
    limits: &SchemaLimits,
) -> Result<UnitArtifactV1, WorkerError> {
    let payload = root.encode_canonical(limits)?;
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: root.source_coverage_root,
            output_coverage_root: root.ordered_record_root,
            source_coverage_count: root.source_coverage_count,
            output_coverage_count: root.record_count,
        },
        BoundedBytes(payload),
        limits,
    )
    .map_err(WorkerError::from)
}

fn execute_root_reduce_unit(
    spec: &UnitSpecV1,
    authority: UnitExecutionAuthority<'_>,
) -> Result<UnitArtifactV1, WorkerError> {
    let UnitExecutionAuthority {
        plan,
        unit_index,
        manifest,
        input_chunks,
        producer_artifacts,
        bundle,
        limits,
        reader,
        inbox,
        cancelled,
    } = authority;
    require_lease_active(cancelled)?;
    if !input_chunks.is_empty() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count)?;
    let phase_ordinal = unit_index
        .checked_sub(topology.phase_offset(UnitPhase::RootReduce)?)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let position = topology.phase_position_at(UnitPhase::RootReduce, phase_ordinal)?;
    let PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::RootReduce,
        level,
        ..
    } = position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    if spec
        .canonical_ordered_inputs
        .first()
        .map(|input| input.purpose)
        != Some(InputPurpose::InputManifest)
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let producer_inputs = spec
        .canonical_ordered_inputs
        .iter()
        .skip(1)
        .collect::<Vec<_>>();
    let producer_ids = producer_inputs
        .iter()
        .map(|input| unit_or_empty_id(input))
        .collect::<Result<Vec<_>, _>>()?;
    let planner = planner_from_authority(plan, manifest, bundle, limits)?;
    if planner.root_reduce_unit_at(phase_ordinal, &producer_ids, limits)? != spec.clone() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let expected = topology.required_producers(position)?;
    let resolved = resolve_scan_artifacts(
        spec,
        &expected,
        &producer_inputs,
        producer_artifacts,
        limits,
    )?;
    let plan_hash = plan.plan_hash(limits)?;
    if level == 0 {
        return execute_root_reduce_leaf(
            spec,
            plan,
            manifest,
            phase_ordinal,
            plan_hash,
            &expected,
            &resolved,
            reader,
            inbox,
            limits,
            cancelled,
        );
    }
    if resolved.len() != 2 {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let mut summaries = Vec::with_capacity(2);
    for (producer, artifact) in expected.into_iter().zip(resolved) {
        require_lease_active(cancelled)?;
        match (producer, artifact) {
            (
                position @ PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                    phase: UnitPhase::RootReduce,
                    ..
                }),
                Some(artifact),
            ) => summaries.push(decode_root_reduce_producer(
                spec, position, artifact, plan_hash, limits,
            )?),
            (
                PlannedProducerV1::CanonicalEmpty {
                    purpose: InputPurpose::RootSummary,
                    padded_ordinal,
                },
                None,
            ) => summaries.push(empty_root_reduce_leaf(spec, plan_hash, padded_ordinal)?),
            _ => return Err(WorkerError::UnitBindingMismatch),
        }
    }
    let right = summaries.pop().ok_or(WorkerError::UnitBindingMismatch)?;
    let left = summaries.pop().ok_or(WorkerError::UnitBindingMismatch)?;
    let summary = left.merge_adjacent(right)?;
    require_complete_root_summary(&summary, plan, manifest)?;
    let coverage_root = summary.result_chunk_hashes.tree_root;
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: summary.covered_primary_count,
            output_coverage_count: summary.covered_primary_count,
        },
        BoundedBytes(encode_root_reduce_output(
            &RootReduceOutputV1::Node { summary },
            limits,
        )?),
        limits,
    )
    .map_err(WorkerError::from)
}

#[allow(clippy::too_many_arguments)]
fn execute_root_reduce_leaf(
    spec: &UnitSpecV1,
    plan: &PlanCommitmentV1,
    manifest: &InputManifestV1,
    shard_ordinal: u32,
    plan_hash: B256,
    expected: &[PlannedProducerV1],
    resolved: &[Option<&UnitArtifactV1>],
    reader: &FilesystemCasReader,
    inbox: &WorkerInbox,
    limits: &SchemaLimits,
    cancelled: Option<&AtomicBool>,
) -> Result<UnitArtifactV1, WorkerError> {
    require_lease_active(cancelled)?;
    let [finalized_position @ PlannedProducerV1::Unit(PlannedUnitPositionV1::Primary {
        phase: UnitPhase::OutputFinalize,
        ordinal,
    }), owner_position @ PlannedProducerV1::Unit(PlannedUnitPositionV1::RunSpan {
        phase: UnitPhase::OwnerShuffle,
        ..
    }), bucket_position @ PlannedProducerV1::Unit(PlannedUnitPositionV1::RunSpan {
        phase: UnitPhase::BucketShuffle,
        ..
    })] = expected
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let [Some(finalized_artifact), Some(owner_artifact), Some(bucket_artifact)] = resolved else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    if *ordinal != shard_ordinal {
        return Err(WorkerError::UnitBindingMismatch);
    }

    let finalized = decode_finalized_output_run(finalized_artifact.phase_payload(limits)?, limits)?;
    let finalized_header = finalized_artifact.output_header(limits)?;
    let expected_start = shard_ordinal
        .checked_mul(PRIMARY_WORK_SHARD_SIZE)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let expected_end = expected_start
        .checked_add(PRIMARY_WORK_SHARD_SIZE)
        .ok_or(WorkerError::UnitBindingMismatch)?
        .min(plan.tribute_count);
    let tribute_count = expected_end
        .checked_sub(expected_start)
        .ok_or(WorkerError::UnitBindingMismatch)?;
    require_root_reduce_finalized_binding(
        &finalized,
        finalized_header,
        expected_start,
        expected_end,
        tribute_count,
    )?;
    validate_scan_artifact(
        spec,
        match finalized_position {
            PlannedProducerV1::Unit(position) => *position,
            PlannedProducerV1::CanonicalEmpty { .. } => {
                return Err(WorkerError::UnitBindingMismatch);
            }
        },
        finalized_artifact.unit_id,
        finalized_artifact,
        limits,
    )?;

    let owner_root = decode_shuffle_producer_root(
        spec,
        owner_artifact,
        ShuffleRunKindV1::Owner,
        *owner_position,
        limits,
    )?;
    let bucket_root = decode_shuffle_producer_root(
        spec,
        bucket_artifact,
        ShuffleRunKindV1::Bucket,
        *bucket_position,
        limits,
    )?;
    require_root_reduce_shuffle_population(
        owner_root.source_coverage_count,
        bucket_root.source_coverage_count,
        owner_root.source_coverage_root,
        bucket_root.source_coverage_root,
        owner_root.record_count,
        bucket_root.record_count,
        plan.tribute_count,
    )?;

    let owner_page = verified_shuffle_run_page(owner_root, shard_ordinal, limits, |reference| {
        reader
            .read_verified(reference)
            .map(|object| object.bytes().to_vec())
            .map_err(|_| {
                outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                    "authenticated owner shuffle descendant",
                )
            })
    })?;
    let contributors = owner_page
        .into_iter()
        .map(|record| match record {
            VerifiedShuffleRecordV1::Owner(contributor) => Ok(contributor),
            VerifiedShuffleRecordV1::Bucket(_) => Err(WorkerError::UnitBindingMismatch),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nod_actions = finalized
        .ordered_records
        .iter()
        .map(|record| ProtocolNodActionV1 {
            raw_ordinal: record.raw_ordinal,
            tribute_id: *record.nod_action.source_tribute_id,
            nod_id: *record.nod_action.nod_id,
            owner: record.nod_action.owner,
            wwd: record.nod_action.worldwide_day.value(),
            league_id: record.nod_action.league_id,
            floor_price_minor: record.nod_action.floor_price_minor,
            gratis_load_minor: record.nod_action.gratis_load_minor,
            entry_price_minor: record.nod_action.entry_price_minor,
            cost_amount_minor: record.nod_action.cost_amount_minor,
            issuance_currency: record.nod_action.issuance_currency,
            reference_currency: record.nod_action.reference_currency,
            issued_at: record.nod_action.issued_at,
            bucket_key: record.nod_action.bucket_key,
        })
        .collect::<Vec<_>>();
    let mut buckets = nod_actions
        .iter()
        .map(|action| ShuffleBucketRecordV1 {
            bucket_key: action.bucket_key,
            raw_ordinal: action.raw_ordinal,
            tribute_id: action.tribute_id,
            nod_id: action.nod_id,
        })
        .collect::<Vec<_>>();
    buckets.sort_by_key(|record| (record.bucket_key, record.raw_ordinal));
    let chunk = ResultChunkV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        chunk_ordinal: shard_ordinal,
        first_nod_ordinal: expected_start,
        ordered_nod_actions: nod_actions.clone(),
        ordered_eligible_contributors: contributors.clone(),
    };
    let chunk_hash = chunk.result_chunk_hash(limits)?;
    let chunk_bytes = chunk.encode_canonical(limits)?;
    let chunk_ref = inbox.stage_result_chunk(&chunk_bytes, limits)?;
    let output_manifest_entry = OutputManifestEntryV1 {
        chunk_ordinal: shard_ordinal,
        result_chunk_hash: chunk_hash,
        result_chunk_ref: chunk_ref,
    };

    let nod_records = nod_actions
        .iter()
        .map(|action| action.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    let bucket_records = buckets
        .iter()
        .map(|record| record.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    let contributor_records = contributors
        .iter()
        .map(|action| action.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_records = vec![output_manifest_entry.encode_canonical_record(limits)?];
    let chunk_hash_records = vec![chunk_hash.as_slice().to_vec()];

    let eligible_nominal_total = checked_sum(
        contributors
            .iter()
            .map(|action| action.nominal_amount_minor),
        "root reducer eligible nominal total",
    )?;
    let nod_gratis_consumed = checked_sum(
        nod_actions.iter().map(|action| action.gratis_load_minor),
        "root reducer Nod Gratis total",
    )?;
    let nod_cost_total = checked_sum(
        nod_actions.iter().map(|action| action.cost_amount_minor),
        "root reducer Nod cost total",
    )?;
    let summary = RootReduceSummaryV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        plan_hash,
        covered_primary_start: shard_ordinal,
        covered_primary_count: 1,
        nod_actions: LysisListSubtreeCarrierV1::from_primary_page(
            ListKind::NodActions,
            shard_ordinal,
            &nod_records,
            limits.max_bounded_bytes,
        )?,
        bucket_records: LysisListSubtreeCarrierV1::from_primary_page(
            ListKind::BucketRecords,
            shard_ordinal,
            &bucket_records,
            limits.max_bounded_bytes,
        )?,
        contributor_actions: LysisListSubtreeCarrierV1::from_primary_page(
            ListKind::ContributorActions,
            shard_ordinal,
            &contributor_records,
            limits.max_bounded_bytes,
        )?,
        output_manifest_entries: LysisListSubtreeCarrierV1::from_primary_page(
            ListKind::CompleteOutputManifest,
            shard_ordinal,
            &manifest_records,
            limits.max_bounded_bytes,
        )?,
        result_chunk_hashes: LysisListSubtreeCarrierV1::from_primary_page(
            ListKind::ResultChunkHashes,
            shard_ordinal,
            &chunk_hash_records,
            B256::len_bytes(),
        )?,
        tribute_count,
        nod_count: tribute_count,
        bucket_count: tribute_count,
        contributor_count: u32::try_from(contributors.len())
            .map_err(|_| WorkerError::UnitBindingMismatch)?,
        tribute_nominal_total: finalized.checked_tribute_nominal_total,
        eligible_nominal_total,
        nod_gratis_consumed,
        nod_cost_total,
        first_error_ordinal: None,
    };
    require_complete_root_summary(&summary, plan, manifest)?;
    let coverage_root = summary.result_chunk_hashes.tree_root;
    UnitArtifactV1::from_canonical_output(
        spec,
        WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: 1,
            output_coverage_count: 1,
        },
        BoundedBytes(encode_root_reduce_output(
            &RootReduceOutputV1::Leaf {
                summary,
                output_manifest_entry,
            },
            limits,
        )?),
        limits,
    )
    .map_err(WorkerError::from)
}

fn checked_sum(
    values: impl IntoIterator<Item = U256>,
    what: &'static str,
) -> Result<U256, WorkerError> {
    values.into_iter().try_fold(U256::ZERO, |total, value| {
        total
            .checked_add(value)
            .ok_or(outbe_ocomp_protocol::ProtocolError::IntegerOverflow { what }.into())
    })
}

fn require_root_reduce_finalized_binding(
    finalized: &FinalizedOutputRunV1,
    header: WorkOutputHeaderV1,
    expected_start: u32,
    expected_end: u32,
    expected_count: u32,
) -> Result<(), WorkerError> {
    if finalized.start_ordinal != expected_start
        || finalized.end_ordinal != expected_end
        || u32::try_from(finalized.ordered_records.len()).ok() != Some(expected_count)
        || finalized.coverage_root()? != header.output_coverage_root
        || header.source_coverage_root != header.output_coverage_root
        || header.source_coverage_count != expected_count
        || header.output_coverage_count != expected_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn require_root_reduce_shuffle_population(
    owner_source_count: u32,
    bucket_source_count: u32,
    owner_source_root: B256,
    bucket_source_root: B256,
    owner_record_count: u32,
    bucket_record_count: u32,
    tribute_count: u32,
) -> Result<(), WorkerError> {
    if owner_source_count != tribute_count
        || bucket_source_count != tribute_count
        || owner_source_root != bucket_source_root
        || owner_record_count > tribute_count
        || bucket_record_count != tribute_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(())
}

fn require_complete_root_summary(
    summary: &RootReduceSummaryV1,
    plan: &PlanCommitmentV1,
    manifest: &InputManifestV1,
) -> Result<(), WorkerError> {
    require_complete_root_values(
        summary.covered_primary_start,
        summary.covered_primary_count,
        plan.primary_work_unit_count,
        summary.tribute_count,
        plan.tribute_count,
        manifest.tribute_count,
        summary.tribute_nominal_total,
        summary.eligible_nominal_total,
        manifest.tribute_nominal_total,
    )
}

#[allow(clippy::too_many_arguments)]
fn require_complete_root_values(
    covered_primary_start: u32,
    covered_primary_count: u32,
    primary_work_unit_count: u32,
    summary_tribute_count: u32,
    plan_tribute_count: u32,
    manifest_tribute_count: u32,
    summary_tribute_nominal_total: U256,
    summary_eligible_nominal_total: U256,
    manifest_tribute_nominal_total: U256,
) -> Result<(), WorkerError> {
    if covered_primary_start == 0
        && covered_primary_count == primary_work_unit_count
        && (summary_tribute_count != plan_tribute_count
            || summary_tribute_count != manifest_tribute_count
            || summary_tribute_nominal_total != manifest_tribute_nominal_total
            || summary_eligible_nominal_total > summary_tribute_nominal_total)
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(())
}

fn decode_root_reduce_producer(
    consumer: &UnitSpecV1,
    expected: PlannedProducerV1,
    artifact: &UnitArtifactV1,
    plan_hash: B256,
    limits: &SchemaLimits,
) -> Result<RootReduceSummaryV1, WorkerError> {
    let PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::RootReduce,
        level,
        index,
    }) = expected
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let output = decode_root_reduce_output(artifact.phase_payload(limits)?, limits)?;
    let summary = match (level, output) {
        (0, RootReduceOutputV1::Leaf { summary, .. }) => summary,
        (_, RootReduceOutputV1::Node { summary }) if level > 0 => summary,
        _ => return Err(WorkerError::UnitBindingMismatch),
    };
    let expected_start = index
        .checked_shl(u32::from(level))
        .ok_or(WorkerError::UnitBindingMismatch)?;
    let header = artifact.output_header(limits)?;
    if summary.protocol_bundle_hash != consumer.protocol_bundle_hash
        || summary.job_id != consumer.job_id
        || summary.attempt != consumer.attempt
        || summary.plan_hash != plan_hash
        || summary.covered_primary_start != expected_start
        || summary.result_chunk_hashes.subtree_height != level
        || summary.result_chunk_hashes.subtree_index != index
        || header.source_coverage_root != summary.result_chunk_hashes.tree_root
        || header.output_coverage_root != summary.result_chunk_hashes.tree_root
        || header.source_coverage_count != summary.covered_primary_count
        || header.output_coverage_count != summary.covered_primary_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(summary)
}

fn empty_root_reduce_leaf(
    spec: &UnitSpecV1,
    plan_hash: B256,
    padded_ordinal: u32,
) -> Result<RootReduceSummaryV1, WorkerError> {
    Ok(RootReduceSummaryV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
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

fn decode_shuffle_producer_root(
    consumer: &UnitSpecV1,
    artifact: &UnitArtifactV1,
    expected_kind: ShuffleRunKindV1,
    expected_position: PlannedProducerV1,
    limits: &SchemaLimits,
) -> Result<ShuffleRunArtifactV1, WorkerError> {
    let PlannedProducerV1::Unit(PlannedUnitPositionV1::RunSpan {
        phase,
        start_run,
        end_run,
        ..
    }) = expected_position
    else {
        return Err(WorkerError::UnitBindingMismatch);
    };
    let expected_phase = match expected_kind {
        ShuffleRunKindV1::Owner => UnitPhase::OwnerShuffle,
        ShuffleRunKindV1::Bucket => UnitPhase::BucketShuffle,
    };
    if phase != expected_phase || artifact.phase != expected_phase {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let root = ShuffleRunArtifactV1::decode_canonical(artifact.phase_payload(limits)?, limits)?;
    root.validate_root_semantics(limits)?;
    let header = artifact.output_header(limits)?;
    if root.protocol_bundle_hash != consumer.protocol_bundle_hash
        || root.job_id != consumer.job_id
        || root.attempt != consumer.attempt
        || root.unit_id != artifact.unit_id
        || root.kind != expected_kind
        || root.run_span.start_run != start_run
        || root.run_span.end_run != end_run
        || root.source_coverage_root != header.source_coverage_root
        || root.source_coverage_count != header.source_coverage_count
        || root.ordered_record_root != header.output_coverage_root
        || root.record_count != header.output_coverage_count
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(root)
}

fn scan_producer_inputs(
    spec: &UnitSpecV1,
    purpose: InputPurpose,
) -> Result<Vec<&CanonicalInputRefV1>, WorkerError> {
    if spec
        .canonical_ordered_inputs
        .first()
        .map(|input| input.purpose)
        != Some(InputPurpose::InputManifest)
        || spec
            .canonical_ordered_inputs
            .iter()
            .skip(1)
            .any(|input| input.purpose != purpose)
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(spec.canonical_ordered_inputs.iter().skip(1).collect())
}

fn unit_or_empty_id(input: &CanonicalInputRefV1) -> Result<Option<B256>, WorkerError> {
    match input.source_kind {
        InputSourceKind::UnitOutput if !input.source_id.is_zero() => Ok(Some(input.source_id)),
        InputSourceKind::CanonicalEmpty => Ok(None),
        _ => Err(WorkerError::UnitBindingMismatch),
    }
}

fn resolve_scan_artifacts<'a>(
    consumer: &UnitSpecV1,
    expected: &[PlannedProducerV1],
    inputs: &[&CanonicalInputRefV1],
    artifacts: &'a [UnitArtifactV1],
    limits: &SchemaLimits,
) -> Result<Vec<Option<&'a UnitArtifactV1>>, WorkerError> {
    if expected.len() != inputs.len() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    let mut artifacts = artifacts.iter();
    let mut resolved = Vec::with_capacity(expected.len());
    for (producer, input) in expected.iter().zip(inputs) {
        match producer {
            PlannedProducerV1::CanonicalEmpty { .. } => {
                if input.source_kind != InputSourceKind::CanonicalEmpty {
                    return Err(WorkerError::UnitBindingMismatch);
                }
                resolved.push(None);
            }
            PlannedProducerV1::Unit(position) => {
                let artifact = artifacts.next().ok_or(WorkerError::UnitBindingMismatch)?;
                validate_scan_artifact(consumer, *position, input.source_id, artifact, limits)?;
                resolved.push(Some(artifact));
            }
        }
    }
    if artifacts.next().is_some() {
        return Err(WorkerError::UnitBindingMismatch);
    }
    Ok(resolved)
}

fn validate_scan_artifact(
    consumer: &UnitSpecV1,
    position: PlannedUnitPositionV1,
    expected_unit_id: B256,
    artifact: &UnitArtifactV1,
    limits: &SchemaLimits,
) -> Result<(), WorkerError> {
    artifact.validate_semantics(limits)?;
    if expected_unit_id.is_zero()
        || artifact.unit_id != expected_unit_id
        || artifact.protocol_bundle_hash != consumer.protocol_bundle_hash
        || artifact.job_id != consumer.job_id
        || artifact.attempt != consumer.attempt
        || artifact.phase != position.phase()
    {
        return Err(WorkerError::UnitBindingMismatch);
    }
    if let PlannedUnitPositionV1::TreeNode {
        phase,
        level,
        index,
    } = position
    {
        let mut interval_binding = consumer.clone();
        interval_binding.phase = phase;
        interval_binding.interval =
            UnitInterval::BinaryReducerNode(BinaryReducerNode { level, index });
        if artifact.interval_commitment != interval_binding.interval_commitment(limits)? {
            return Err(WorkerError::UnitBindingMismatch);
        }
    } else if let PlannedUnitPositionV1::RunSpan {
        phase,
        start_run,
        end_run,
        ..
    } = position
    {
        let mut interval_binding = consumer.clone();
        interval_binding.phase = phase;
        interval_binding.interval =
            UnitInterval::CanonicalRunSpan(outbe_ocomp_protocol::unit::CanonicalRunSpan {
                start_run,
                end_run,
            });
        if artifact.interval_commitment != interval_binding.interval_commitment(limits)? {
            return Err(WorkerError::UnitBindingMismatch);
        }
    }
    Ok(())
}

fn planner_from_authority(
    plan: &PlanCommitmentV1,
    manifest: &InputManifestV1,
    bundle: &outbe_ocomp_protocol::profile::ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<LysisPlannerV1, WorkerError> {
    LysisPlannerV1::new(LysisPlannerBindingsV1 {
        protocol_bundle_hash: plan.protocol_bundle_hash,
        job_id: plan.job_id,
        attempt: plan.attempt,
        input_manifest_hash: plan.input_manifest_hash,
        input_manifest_encoded_bytes: u64::try_from(manifest.encode_canonical(limits)?.len())
            .map_err(|_| WorkerError::UnitBindingMismatch)?,
        fidelity_opening_root: manifest.fidelity_opening_root,
        oracle_opening_root: manifest.oracle_opening_root,
        wwd: plan.wwd,
        lysis_budget: plan.lysis_budget,
        logical_evaluation_time: plan.logical_evaluation_time,
        tribute_count: plan.tribute_count,
        lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
        planner_spec_version: plan.planner_spec_version,
        reducer_spec_version: plan.reducer_spec_version,
    })
    .map_err(WorkerError::from)
}

fn exact_unit_output_source(spec: &UnitSpecV1, purpose: InputPurpose) -> Result<B256, WorkerError> {
    let mut matches = spec.canonical_ordered_inputs.iter().filter(|input| {
        input.purpose == purpose && input.source_kind == InputSourceKind::UnitOutput
    });
    let source = matches
        .next()
        .ok_or(WorkerError::UnitBindingMismatch)?
        .source_id;
    if source.is_zero() || matches.next().is_some() {
        Err(WorkerError::UnitBindingMismatch)
    } else {
        Ok(source)
    }
}

fn require_plan_binding(
    plan: &PlanCommitmentV1,
    expected: ExpectedPlanBindingsV1,
    limits: &SchemaLimits,
) -> Result<(), WorkerError> {
    let matches = plan.plan_hash(limits)? == expected.plan_hash
        && plan.protocol_bundle_hash == expected.protocol_bundle_hash
        && plan.job_id == expected.job_id
        && plan.attempt == expected.attempt
        && plan.input_manifest_hash == expected.input_manifest_hash
        && plan.wwd == expected.wwd
        && plan.tribute_count == expected.tribute_count
        && plan.planner_spec_version == expected.planner_spec_version
        && plan.reducer_spec_version == expected.reducer_spec_version;
    if matches {
        Ok(())
    } else {
        Err(WorkerError::UnitBindingMismatch)
    }
}

fn require_authenticated_input(
    spec: &UnitSpecV1,
    purpose: InputPurpose,
    source_id: B256,
    record_count: u32,
    encoded_bytes: u64,
) -> Result<(), WorkerError> {
    let matches = spec
        .canonical_ordered_inputs
        .iter()
        .filter(|input| {
            input.purpose == purpose
                && input.source_kind == InputSourceKind::AuthenticatedRoot
                && input.source_id == source_id
                && input.record_count_limit >= record_count
                && input.max_encoded_bytes >= encoded_bytes
        })
        .count();
    if matches == 1 {
        Ok(())
    } else {
        Err(WorkerError::UnitBindingMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use alloy_primitives::{Address, B256, U256};
    use outbe_compressed_entities::derive_poseidon_entity_id;
    use outbe_lysis::program_v1::phases::{
        output_finalize, AmountRecordV1, AmountRunV1, GratisLeafPrefixV1,
    };
    use outbe_ocomp_protocol::unit::{PlanCommitmentV1, WorkOutputHeaderV1};
    use outbe_primitives::time::WorldwideDay;

    use super::{
        poc_schema_limits, require_complete_root_values, require_lease_active,
        require_plan_binding, require_root_reduce_finalized_binding,
        require_root_reduce_shuffle_population, terminal_completion, ExpectedPlanBindingsV1,
        WorkerError,
    };

    #[test]
    fn zero_mq_cancel_command_stops_work_at_the_next_execution_checkpoint() {
        let cancelled = AtomicBool::new(false);
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            require_lease_active(Some(&cancelled)),
            Err(WorkerError::LeaseCancelled)
        ));
    }

    #[test]
    fn accepted_lease_pre_execution_error_becomes_terminal_failure() {
        let unit_id = B256::repeat_byte(0xA5);
        let finished =
            terminal_completion(unit_id, "test-lease", Err(WorkerError::UnitBindingMismatch));
        assert_eq!(finished.unit_id, unit_id);
        assert_eq!(
            finished.status,
            outbe_ocomp_protocol::UnitFinishedStatus::Failed
        );
        assert_eq!(finished.exact_staged_bytes, 0);
        assert_eq!(finished.transport_digest, B256::ZERO);
    }

    fn plan() -> PlanCommitmentV1 {
        PlanCommitmentV1 {
            protocol_bundle_hash: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 0,
            input_manifest_hash: B256::repeat_byte(4),
            wwd: 20_260_724,
            lysis_budget: U256::from(99_000_000_u64),
            logical_evaluation_time: 1_784_765_900,
            tribute_count: 257,
            max_tributes_per_work_shard: 256,
            primary_work_unit_count: 2,
            primary_work_unit_root: B256::repeat_byte(5),
            planner_spec_version: 1,
            reducer_spec_version: 1,
        }
    }

    #[test]
    fn changed_frozen_plan_context_is_rejected_even_when_job_and_manifest_bindings_match() {
        let limits = poc_schema_limits();
        let committed = plan();
        let expected = ExpectedPlanBindingsV1 {
            plan_hash: committed.plan_hash(&limits).unwrap(),
            protocol_bundle_hash: committed.protocol_bundle_hash,
            job_id: committed.job_id,
            attempt: committed.attempt,
            input_manifest_hash: committed.input_manifest_hash,
            wwd: committed.wwd,
            tribute_count: committed.tribute_count,
            planner_spec_version: committed.planner_spec_version,
            reducer_spec_version: committed.reducer_spec_version,
        };
        require_plan_binding(&committed, expected, &limits).unwrap();

        let mut changed = committed;
        changed.lysis_budget += U256::from(1);
        assert!(require_plan_binding(&changed, expected, &limits).is_err());
    }

    #[test]
    fn root_reduce_rejects_finalized_payload_that_no_longer_matches_coverage_header() {
        let day = WorldwideDay::new(20_260_725);
        let owner = Address::repeat_byte(0x11);
        let tribute_id = derive_poseidon_entity_id(owner, day).unwrap();
        let finalized = output_finalize(
            &AmountRunV1 {
                start_ordinal: 0,
                end_ordinal: 1,
                ordered_records: vec![AmountRecordV1 {
                    raw_ordinal: 0,
                    tribute_id,
                    owner,
                    worldwide_day: day,
                    league_id: 1,
                    nominal_amount_minor: U256::from(10),
                    gratis_fraction_fp: U256::ZERO,
                    gratis_load_minor: U256::from(1),
                    entry_price_minor: U256::from(2),
                    floor_price_minor: U256::from(3),
                    cost_amount_minor: U256::from(4),
                    issuance_currency: 840,
                    reference_currency: 978,
                    exclude_from_intex_issuance: false,
                }],
                checked_segment_gratis_total: U256::from(1),
            },
            &GratisLeafPrefixV1 {
                segment_ordinal: 0,
                incoming_remaining: U256::from(2),
                outgoing_remaining: U256::from(1),
                first_error_ordinal: None,
            },
            2_026_072_500,
        )
        .unwrap();
        let coverage_root = finalized.coverage_root().unwrap();
        let header = WorkOutputHeaderV1 {
            source_coverage_root: coverage_root,
            output_coverage_root: coverage_root,
            source_coverage_count: 1,
            output_coverage_count: 1,
        };
        require_root_reduce_finalized_binding(&finalized, header.clone(), 0, 1, 1).unwrap();

        let mut changed = finalized;
        changed.ordered_records[0].nod_action.source_tribute_id =
            derive_poseidon_entity_id(Address::repeat_byte(0x12), day).unwrap();
        assert!(require_root_reduce_finalized_binding(&changed, header, 0, 1, 1).is_err());
    }

    #[test]
    fn root_reduce_rejects_hidden_shuffle_suffix_or_missing_bucket_record() {
        let source_root = B256::repeat_byte(0x21);
        require_root_reduce_shuffle_population(256, 256, source_root, source_root, 255, 256, 256)
            .unwrap();
        assert!(require_root_reduce_shuffle_population(
            256,
            256,
            source_root,
            source_root,
            257,
            256,
            256,
        )
        .is_err());
        assert!(require_root_reduce_shuffle_population(
            256,
            256,
            source_root,
            source_root,
            255,
            255,
            256,
        )
        .is_err());
    }

    #[test]
    fn complete_root_rejects_manifest_total_mismatch_for_leaf_and_node() {
        for primary_work_unit_count in [1, 2] {
            assert!(require_complete_root_values(
                0,
                primary_work_unit_count,
                primary_work_unit_count,
                257,
                257,
                257,
                U256::from(256),
                U256::from(200),
                U256::from(257),
            )
            .is_err());
        }
        require_complete_root_values(
            0,
            1,
            2,
            256,
            257,
            257,
            U256::from(256),
            U256::from(200),
            U256::from(257),
        )
        .unwrap();
        assert!(require_complete_root_values(
            0,
            2,
            2,
            257,
            257,
            257,
            U256::from(257),
            U256::from(258),
            U256::from(257),
        )
        .is_err());
    }
}
