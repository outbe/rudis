// OCOMP-TEST-ID: OCM-WRK-001
mod support;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, encode_tribute_v1, TributeBodyV1};
use outbe_lysis::program_v1::artifacts::{
    decode_amount_run, decode_enumerated_run, decode_finalized_output_run,
    decode_fixed_reduce_output, decode_gratis_prefix_down_output, decode_gratis_segment_summary,
    encode_enumerated_run, encode_finalized_output_run, GratisPrefixDownOutputV1,
};
use outbe_lysis::program_v1::finalizer::{
    finalize_v1, FinalizationResultChunkV1, FinalizationUnitArtifactV1,
    VerifiedLysisFinalizationInputsV1,
};
use outbe_lysis::program_v1::phases::{
    output_finalize, AmountRecordV1, AmountRunV1, GratisLeafPrefixV1,
};
use outbe_lysis::program_v1::planner::{
    LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1, PlannedUnitPositionV1,
};
use outbe_lysis::program_v1::result::{
    decode_root_reduce_output, encode_root_reduce_output, RootReduceOutputV1,
};
use outbe_ocomp::admission_catalog::{
    AdmissionOutcome, AdmissionPositionV1, VerifiedAdmissionCatalog,
};
use outbe_ocomp::bundle::PinnedProtocolBundle;
use outbe_ocomp::cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader};
use outbe_ocomp::control::{poc_schema_limits, EndpointIdentity};
use outbe_ocomp::inbox::{WorkerInbox, WorkerInboxLimits};
use outbe_ocomp::input_artifacts::{
    decode_verified_input_chunk, derive_input_chunk_ref, poc_input_list_limits,
    publish_input_artifact_set, InputArtifactContents, InputArtifactIdentity,
};
use outbe_ocomp::input_ref_catalog::VerifiedInputChunkRefCatalog;
use outbe_ocomp::lysis_phase_replay::{
    admit_reported_output_finalize_unit, verify_core_phase_replay, verify_output_finalize_replay,
};
use outbe_ocomp::lysis_result_adoption::verify_lysis_root_reduce_phase_replay;
use outbe_ocomp::lysis_scheduler::admit_reported_lysis_unit_v1;
use outbe_ocomp::lysis_shuffle_adoption::{
    adopt_lysis_shuffle_descendants, verify_lysis_shuffle_phase_replay,
};
use outbe_ocomp::worker::{run_worker, WorkerConfig};
use outbe_ocomp::worker_transport::{SupervisorWorkerDispatcherV1, SupervisorWorkerServerV1};
use outbe_ocomp_protocol::common::{BoundedBytes, ProofBytes};
use outbe_ocomp_protocol::input::{
    materialize_authenticated_openings, CheckpointIdentityV1, Compression, InputChunkKind,
    InputManifestV1,
};
use outbe_ocomp_protocol::intent::{
    ActivationPreconditionsV1, AuctionEntryPriceSource, ContributorTargetPreconditionV1, DayType,
    FrozenMetadosisValuesV1, JobIntentV1, MetadosisAttemptPreconditionV1, MetadosisExpectedStatus,
    NodTargetPreconditionV1, ReferenceEntryPriceV1, TributeInputBindingV1,
};
use outbe_ocomp_protocol::league_snapshot::league_snapshot_slot;
use outbe_ocomp_protocol::opening::{
    LysisOpeningsProofV1, OpeningSubjectsV1, RawContractOpeningProofV1, RawStorageSlotV1,
};
use outbe_ocomp_protocol::result::ResultChunkV1;
use outbe_ocomp_protocol::shuffle::{
    verified_shuffle_run_records, ShuffleBucketRecordV1, ShuffleRunArtifactV1, ShuffleRunKindV1,
};
use outbe_ocomp_protocol::unit::{
    CanonicalInputRefV1, EntityIdHalfOpenRange, InputPurpose, InputSourceKind, PlanCommitmentV1,
    UnitArtifactV1, UnitInterval, UnitPhase, UnitSpecV1,
};
use outbe_ocomp_protocol::{
    ordered_list_root, CasObjectRefV1, ListKind, ObjectKind, OrderedListLimits, RunUnitV1,
    SchemaLimits, UnitFinishedStatus, UnitFinishedV1,
};
use outbe_oracle::oracle_opening_slot_plan_v1;
use outbe_primitives::time::WorldwideDay;
use tempfile::tempdir;

struct RunningWorker {
    child: Child,
    client: TestWorkerDispatch,
    unit_id: B256,
}

struct TestWorkerDispatch {
    dispatcher: SupervisorWorkerDispatcherV1,
    pending: Option<mpsc::Receiver<Result<UnitFinishedV1, String>>>,
}

const CHILD_MODE: &str = "OUTBE_OCOMP_TEST_WORKER_CHILD";
const CHILD_CHAIN_ID: &str = "OUTBE_OCOMP_TEST_CHAIN_ID";
const CHILD_GENESIS: &str = "OUTBE_OCOMP_TEST_GENESIS";
const CHILD_BOOT_NONCE: &str = "OUTBE_OCOMP_TEST_BOOT_NONCE";
const CHILD_BUNDLE: &str = "OUTBE_OCOMP_TEST_BUNDLE";
const CHILD_CAS_ROOT: &str = "OUTBE_OCOMP_TEST_CAS_ROOT";
const CHILD_CAS_OBJECT_CAP: &str = "OUTBE_OCOMP_TEST_CAS_OBJECT_CAP";
const CHILD_CAS_TOTAL_CAP: &str = "OUTBE_OCOMP_TEST_CAS_TOTAL_CAP";
const CHILD_INBOX_ROOT: &str = "OUTBE_OCOMP_TEST_INBOX_ROOT";
const CHILD_SUPERVISOR_ADDRESS: &str = "OUTBE_OCOMP_TEST_SUPERVISOR_ADDRESS";

fn supervisor_listener() -> (SupervisorWorkerServerV1, SocketAddr) {
    let server = SupervisorWorkerServerV1::start(
        "127.0.0.1:0".parse().unwrap(),
        identity(0xB0),
        1,
        poc_schema_limits(),
    )
    .expect("start test Supervisor worker transport");
    let address = server.address();
    (server, address)
}

fn accept_registered_worker(
    server: &SupervisorWorkerServerV1,
    _supervisor_identity: EndpointIdentity,
    _generation: u64,
    _limits: SchemaLimits,
) -> TestWorkerDispatch {
    TestWorkerDispatch {
        dispatcher: server.dispatcher(),
        pending: None,
    }
}

impl TestWorkerDispatch {
    fn dispatch_encoded(&mut self, body: Vec<u8>) -> Result<(), String> {
        if self.pending.is_some() {
            return Err("invalid test worker dispatch".to_owned());
        }
        let limits = poc_schema_limits();
        let request = RunUnitV1::decode_body(&body, &limits).map_err(|error| error.to_string())?;
        let dispatcher = self.dispatcher.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = dispatcher
                .dispatch(&request)
                .map_err(|error| error.to_string());
            let _ = tx.send(result);
        });
        self.pending = Some(rx);
        Ok(())
    }

    fn receive_finished(&mut self) -> Result<UnitFinishedV1, String> {
        self.pending
            .take()
            .ok_or("missing test worker result")?
            .recv()
            .map_err(|error| error.to_string())?
    }
}

fn receive_finished(dispatch: &mut TestWorkerDispatch, _limits: &SchemaLimits) -> UnitFinishedV1 {
    dispatch.receive_finished().expect("worker completion")
}

fn identity(boot: u8) -> EndpointIdentity {
    let limits = poc_schema_limits();
    EndpointIdentity {
        chain_id: 41,
        genesis_hash: B256::repeat_byte(0x41),
        boot_nonce: B256::repeat_byte(boot),
        protocol_bundle_hash: support::protocol_bundle()
            .protocol_bundle_hash(&limits)
            .expect("fixture protocol bundle hash"),
    }
}

#[test]
fn real_worker_processes_execute_through_output_finalize() {
    if env::var_os(CHILD_MODE).is_some() {
        run_child_worker();
        return;
    }

    let directory = tempdir().expect("worker fixture");
    let cas_limits = CasLimits {
        max_object_bytes: 1024 * 1024,
        max_total_bytes: 8 * 1024 * 1024,
    };
    let cas = FilesystemCas::open(directory.path(), CasWriterRole::Supervisor, cas_limits)
        .expect("open CAS");
    let inbox_root = directory.path().join("worker-inbox");
    let inbox_limits = WorkerInboxLimits {
        max_artifact_bytes: 1024 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
    };
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let job_id = B256::repeat_byte(0x31);
    let day = WorldwideDay::new(20_260_724);
    let owner = Address::repeat_byte(0x51);
    let finalized_state_root = B256::repeat_byte(0x52);
    let tribute = TributeBodyV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).expect("fixture Tribute id"),
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(9),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(10),
        reference_currency: 978,
        tribute_price_minor: U256::from(2),
        exclude_from_intex_issuance: false,
    };
    let fidelity_raw = RawContractOpeningProofV1 {
        contract_address: Address::repeat_byte(0x54),
        state_root: finalized_state_root,
        // One per-owner league word (a valid league in [1, 4096]) at the Metadosis
        // snapshot slot, keyed by the same wwd the manifest carries.
        ordered_slots: vec![RawStorageSlotV1 {
            slot: league_snapshot_slot(day.value(), owner),
            value: U256::from(1u16),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let oracle_plan = oracle_opening_slot_plan_v1(day, &[840, 978], 2, &[1, 2], 0, 0)
        .expect("fixture Oracle slot plan");
    let coen840_price = U256::from(1_000_000_u64);
    let generic_price_scale = U256::from(1_000_000_000_000_000_000_u64);
    let oracle_values = [
        U256::from(2),   // reference_currencies length
        U256::from(840), // reference_currencies[0]
        U256::from(978), // reference_currencies[1]
        U256::from(1),   // pair_index[COEN/840]
        U256::from(2),   // pair_index[COEN/978]
        U256::from(1),   // wwd_vwap_exists
        // One value word per subject pair, at its registry index.
        coen840_price,                       // wwd_vwap_value[1]
        generic_price_scale * U256::from(2), // wwd_vwap_value[2]
        U256::ZERO,                          // scurve_count
        U256::ZERO,                          // scurve_oldest
    ];
    assert_eq!(oracle_plan.slots.len(), oracle_values.len());
    let oracle_raw = RawContractOpeningProofV1 {
        contract_address: Address::repeat_byte(0x56),
        state_root: finalized_state_root,
        ordered_slots: oracle_plan
            .slots
            .into_iter()
            .zip(oracle_values)
            .map(|(slot, value)| RawStorageSlotV1 { slot, value })
            .collect(),
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let materialized = materialize_authenticated_openings(
        &LysisOpeningsProofV1 {
            protocol_bundle_hash: bundle
                .protocol_bundle_hash(&limits)
                .expect("fixture bundle hash"),
            job_id,
            finalized_block_hash: B256::repeat_byte(0x53),
            finalized_state_root,
            wwd: day.value(),
            subjects: OpeningSubjectsV1 {
                owners: vec![owner],
                reference_isos: vec![840, 978],
            },
            fidelity: fidelity_raw,
            oracle: oracle_raw,
        },
        &bundle,
        &limits,
    )
    .expect("materialize fixture openings");
    let published = publish_input_artifact_set(
        &cas,
        directory.path().join("input-refs"),
        &bundle,
        InputArtifactContents {
            identity: InputArtifactIdentity {
                job_id,
                attempt: 0,
                checkpoint: CheckpointIdentityV1 {
                    finalized_block_number: 90,
                    finalized_block_hash: B256::repeat_byte(0x53),
                    finalized_state_root,
                    finalized_ce_root: B256::repeat_byte(0x58),
                    ce_schema_version: 1,
                },
                wwd: day.value(),
                sealed_tribute_collection_key: B256::repeat_byte(0x59),
                sealed_tribute_collection_root: B256::repeat_byte(0x5a),
            },
            canonical_tributes: vec![
                encode_tribute_v1(&tribute).expect("canonical fixture Tribute")
            ],
            fidelity_openings: vec![materialized.fidelity],
            oracle_opening: materialized.oracle,
        },
        &limits,
        poc_input_list_limits(),
    )
    .expect("publish worker fixture inputs");
    let tribute_ref = published
        .ordered_chunk_refs
        .iter()
        .find(|reference| {
            cas.read_verified(reference)
                .ok()
                .and_then(|object| derive_input_chunk_ref(&object, &bundle, &limits).ok())
                .is_some_and(|derived| derived.reference.kind == InputChunkKind::Tribute)
        })
        .cloned()
        .expect("fixture Tribute input reference");
    let tribute_object = cas
        .read_verified(&tribute_ref)
        .expect("read fixture Tribute chunk");
    let derived_tribute = derive_input_chunk_ref(&tribute_object, &bundle, &limits)
        .expect("derive fixture Tribute reference")
        .reference;
    let canonical_inputs = vec![
        CanonicalInputRefV1 {
            purpose: InputPurpose::InputManifest,
            source_kind: InputSourceKind::AuthenticatedRoot,
            source_id: published.manifest_hash,
            record_count_limit: 1,
            max_encoded_bytes: published.manifest_ref.encoded_bytes,
            max_decoded_bytes: published.manifest_ref.encoded_bytes,
        },
        CanonicalInputRefV1 {
            purpose: InputPurpose::TributeStream,
            source_kind: InputSourceKind::AuthenticatedRoot,
            source_id: derived_tribute.semantic_digest,
            record_count_limit: derived_tribute.record_count,
            max_encoded_bytes: derived_tribute.encoded_bytes,
            max_decoded_bytes: derived_tribute.encoded_bytes,
        },
    ];
    let protocol_bundle_hash = bundle
        .protocol_bundle_hash(&limits)
        .expect("fixture bundle hash");
    let interval_start = *tribute.tribute_id;
    let spec = UnitSpecV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        phase: UnitPhase::Enumerate,
        interval: UnitInterval::EntityIdRange(EntityIdHalfOpenRange {
            start: interval_start,
            end: None,
        }),
        canonical_ordered_inputs: canonical_inputs,
        lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let canonical_spec = spec.encode_canonical(&limits).expect("canonical unit spec");
    let primary_work_unit_root = ordered_list_root(
        ListKind::UnitSpecificationsArtifacts,
        std::slice::from_ref(&canonical_spec),
        OrderedListLimits::new(1, limits.codec.max_body_bytes, 32),
    )
    .expect("primary unit root");
    let plan = PlanCommitmentV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        input_manifest_hash: published.manifest_hash,
        wwd: day.value(),
        lysis_budget: U256::from(99_000_000_u64),
        logical_evaluation_time: 1_784_765_900,
        tribute_count: published.tribute_count,
        max_tributes_per_work_shard: 256,
        primary_work_unit_count: 1,
        primary_work_unit_root,
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let plan_hash = plan.plan_hash(&limits).expect("fixture plan hash");
    let plan_ref = cas
        .publish_bytes(
            &plan
                .encode_canonical_record(&limits)
                .expect("canonical plan commitment"),
        )
        .expect("plan object");
    let (listener, supervisor_address) = supervisor_listener();
    let supervisor_identity = identity(0xB0);
    let mut workers = Vec::new();
    for index in 0_u8..4 {
        let worker_identity = identity(0xA0 + index);
        let mut command = Command::new(env::current_exe().expect("current Rust test binary"));
        command
            .args([
                "--exact",
                "real_worker_processes_execute_through_output_finalize",
                "--nocapture",
            ])
            .env(CHILD_MODE, "1")
            .env(CHILD_CHAIN_ID, worker_identity.chain_id.to_string())
            .env(
                CHILD_GENESIS,
                format!("{:#x}", worker_identity.genesis_hash),
            )
            .env(
                CHILD_BOOT_NONCE,
                format!("{:#x}", worker_identity.boot_nonce),
            )
            .env(
                CHILD_BUNDLE,
                format!("{:#x}", worker_identity.protocol_bundle_hash),
            )
            .env(CHILD_CAS_ROOT, directory.path())
            .env(
                CHILD_CAS_OBJECT_CAP,
                cas_limits.max_object_bytes.to_string(),
            )
            .env(CHILD_CAS_TOTAL_CAP, cas_limits.max_total_bytes.to_string())
            .env(CHILD_INBOX_ROOT, &inbox_root)
            .env(CHILD_SUPERVISOR_ADDRESS, supervisor_address.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = command.spawn().expect("spawn production worker");

        let mut client = accept_registered_worker(&listener, supervisor_identity, 100, limits);

        let unit_id = spec.unit_id(&limits).expect("unit id");
        let request = RunUnitV1 {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            plan_hash,
            unit_index: 0,
            canonical_unit_spec: BoundedBytes(canonical_spec.clone()),
            unit_membership_siblings: Vec::new(),
            plan_ref: plan_ref.clone(),
            input_manifest_ref: published.manifest_ref.clone(),
            ordered_input_refs: vec![tribute_ref.clone()],
        };
        client
            .dispatch_encoded(request.encode_body(&limits).expect("run unit body"))
            .expect("send exact unit");
        workers.push(RunningWorker {
            child,
            client,
            unit_id,
        });
    }

    let registry_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let registry_status = loop {
        let status = listener.status().expect("read four-worker registry");
        if status.registered_workers == 4 && status.connected_workers == 4 {
            break status;
        }
        assert!(
            std::time::Instant::now() < registry_deadline,
            "four distinct workers did not register: {status:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(registry_status.max_workers, 4);

    let mut finished_reports = Vec::new();
    for mut worker in workers {
        let finished = receive_finished(&mut worker.client, &limits);
        assert_eq!(finished.unit_id, worker.unit_id);
        assert_eq!(finished.status, UnitFinishedStatus::Success);
        assert!(finished.exact_staged_bytes > 0);
        assert_ne!(finished.transport_digest, B256::ZERO);
        finished_reports.push(finished);
        worker.child.kill().expect("stop worker listener");
        worker.child.wait().expect("reap worker listener");
    }
    assert!(finished_reports.windows(2).all(|pair| pair[0] == pair[1]));
    let inbox = WorkerInbox::open(&inbox_root, inbox_limits).expect("open worker inbox");
    assert_eq!(inbox.artifact_count().unwrap(), 1);
    let verified = inbox
        .read_reported(
            finished_reports[0].unit_id,
            finished_reports[0].exact_staged_bytes,
            finished_reports[0].transport_digest,
        )
        .expect("read staged unit artifact");
    let artifact = UnitArtifactV1::decode_canonical(verified.bytes(), &limits)
        .expect("decode staged unit artifact");
    artifact.validate_against(&spec, &limits).unwrap();
    let manifest = InputManifestV1::decode_canonical(
        cas.read_verified(&published.manifest_ref)
            .expect("read fixture manifest")
            .bytes(),
        &limits,
    )
    .expect("decode fixture manifest");
    let reader =
        FilesystemCasReader::open(directory.path(), cas_limits).expect("open replay CAS reader");
    let semantic_replay_inbox = WorkerInbox::open(
        directory.path().join("supervisor-semantic-replay-inbox"),
        inbox_limits,
    )
    .expect("open supervisor semantic replay inbox");
    let tribute_chunk = decode_verified_input_chunk(&tribute_object, &bundle, &limits)
        .expect("decode authenticated Tribute chunk");
    let replay_inputs = vec![(derived_tribute.clone(), tribute_chunk)];
    verify_core_phase_replay(
        0,
        &spec,
        &artifact,
        &plan,
        &manifest,
        &replay_inputs,
        &[],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact Enumerate bytes");

    let mut forged_enumerated =
        decode_enumerated_run(artifact.phase_payload(&limits).unwrap(), &limits)
            .expect("decode Enumerate output");
    forged_enumerated.ordered_records[0]
        .tribute
        .nominal_amount_minor += U256::from(1);
    let forged_enumerate_artifact = UnitArtifactV1::from_canonical_output(
        &spec,
        artifact.output_header(&limits).unwrap(),
        BoundedBytes(
            encode_enumerated_run(&forged_enumerated, &limits)
                .expect("encode digest-valid forged Enumerate output"),
        ),
        &limits,
    )
    .expect("build digest-valid forged Enumerate artifact");
    assert!(verify_core_phase_replay(
        0,
        &spec,
        &forged_enumerate_artifact,
        &plan,
        &manifest,
        &replay_inputs,
        &[],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .is_err());

    let mut producer_ref = cas
        .publish_bytes(verified.bytes())
        .expect("publish Enumerate producer artifact");
    producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let fidelity_ref = published
        .ordered_chunk_refs
        .iter()
        .find(|reference| {
            cas.read_verified(reference)
                .ok()
                .and_then(|object| derive_input_chunk_ref(&object, &bundle, &limits).ok())
                .is_some_and(|derived| derived.reference.kind == InputChunkKind::Fidelity)
        })
        .cloned()
        .expect("fixture Fidelity input reference");
    let planner = LysisPlannerV1::new(LysisPlannerBindingsV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        input_manifest_hash: published.manifest_hash,
        input_manifest_encoded_bytes: published.manifest_ref.encoded_bytes,
        fidelity_opening_root: manifest.fidelity_opening_root,
        oracle_opening_root: manifest.oracle_opening_root,
        wwd: day.value(),
        lysis_budget: plan.lysis_budget,
        logical_evaluation_time: plan.logical_evaluation_time,
        tribute_count: published.tribute_count,
        lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
        planner_spec_version: 1,
        reducer_spec_version: 1,
    })
    .expect("fixture planner");
    let fidelity_spec = planner
        .fidelity_map_unit_at(0, artifact.unit_id, &limits)
        .expect("derive Fidelity unit");
    let fidelity_unit_id = fidelity_spec.unit_id(&limits).expect("Fidelity UnitId");
    let (listener, supervisor_address) = supervisor_listener();
    let worker_identity = identity(0xD0);
    let mut command = Command::new(env::current_exe().expect("current Rust test binary"));
    command
        .args([
            "--exact",
            "real_worker_processes_execute_through_output_finalize",
            "--nocapture",
        ])
        .env(CHILD_MODE, "1")
        .env(CHILD_CHAIN_ID, worker_identity.chain_id.to_string())
        .env(
            CHILD_GENESIS,
            format!("{:#x}", worker_identity.genesis_hash),
        )
        .env(
            CHILD_BOOT_NONCE,
            format!("{:#x}", worker_identity.boot_nonce),
        )
        .env(
            CHILD_BUNDLE,
            format!("{:#x}", worker_identity.protocol_bundle_hash),
        )
        .env(CHILD_CAS_ROOT, directory.path())
        .env(
            CHILD_CAS_OBJECT_CAP,
            cas_limits.max_object_bytes.to_string(),
        )
        .env(CHILD_CAS_TOTAL_CAP, cas_limits.max_total_bytes.to_string())
        .env(CHILD_INBOX_ROOT, &inbox_root)
        .env(CHILD_SUPERVISOR_ADDRESS, supervisor_address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn Fidelity worker");
    drop(command);
    let client_identity = EndpointIdentity {
        boot_nonce: B256::repeat_byte(0xD1),
        ..worker_identity
    };
    let mut client = accept_registered_worker(&listener, client_identity, 200, limits);
    client
        .dispatch_encoded(
            RunUnitV1 {
                protocol_bundle_hash,
                job_id,
                attempt: 0,
                plan_hash,
                unit_index: plan.primary_work_unit_count,
                canonical_unit_spec: BoundedBytes(
                    fidelity_spec
                        .encode_canonical(&limits)
                        .expect("canonical Fidelity spec"),
                ),
                unit_membership_siblings: Vec::new(),
                plan_ref: plan_ref.clone(),
                input_manifest_ref: published.manifest_ref.clone(),
                ordered_input_refs: vec![
                    producer_ref.clone(),
                    tribute_ref.clone(),
                    fidelity_ref.clone(),
                ],
            }
            .encode_body(&limits)
            .expect("Fidelity RunUnit body"),
        )
        .expect("send Fidelity unit");
    let finished = receive_finished(&mut client, &limits);
    let mut child = child;
    child.kill().expect("stop Fidelity worker listener");
    child.wait().expect("reap Fidelity worker listener");
    assert_eq!(finished.status, UnitFinishedStatus::Success);
    assert_eq!(finished.unit_id, fidelity_unit_id);
    let fidelity_artifact = UnitArtifactV1::decode_canonical(
        inbox
            .read_reported(
                finished.unit_id,
                finished.exact_staged_bytes,
                finished.transport_digest,
            )
            .expect("read staged Fidelity artifact")
            .bytes(),
        &limits,
    )
    .expect("decode Fidelity artifact");
    fidelity_artifact
        .validate_against(&fidelity_spec, &limits)
        .expect("validate Fidelity artifact");
    let fidelity_object = cas
        .read_verified(&fidelity_ref)
        .expect("read authenticated Fidelity chunk");
    let fidelity_input = (
        derive_input_chunk_ref(&fidelity_object, &bundle, &limits)
            .expect("derive Fidelity reference")
            .reference,
        decode_verified_input_chunk(&fidelity_object, &bundle, &limits)
            .expect("decode authenticated Fidelity chunk"),
    );
    let fidelity_inputs = vec![replay_inputs[0].clone(), fidelity_input];
    verify_core_phase_replay(
        plan.primary_work_unit_count,
        &fidelity_spec,
        &fidelity_artifact,
        &plan,
        &manifest,
        &fidelity_inputs,
        std::slice::from_ref(&artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact FidelityMap bytes");

    let mut fidelity_producer_ref = cas
        .publish_bytes(
            &fidelity_artifact
                .encode_canonical(&limits)
                .expect("canonical Fidelity artifact"),
        )
        .expect("publish Fidelity producer artifact");
    fidelity_producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let reduce_spec = planner
        .fixed_reduce_unit_at(0, [Some(fidelity_artifact.unit_id), None], &limits)
        .expect("derive FixedReduce unit");
    let reduce_unit_id = reduce_spec.unit_id(&limits).expect("FixedReduce UnitId");
    let (listener, supervisor_address) = supervisor_listener();
    let worker_identity = identity(0xE0);
    let mut command = Command::new(env::current_exe().expect("current Rust test binary"));
    command
        .args([
            "--exact",
            "real_worker_processes_execute_through_output_finalize",
            "--nocapture",
        ])
        .env(CHILD_MODE, "1")
        .env(CHILD_CHAIN_ID, worker_identity.chain_id.to_string())
        .env(
            CHILD_GENESIS,
            format!("{:#x}", worker_identity.genesis_hash),
        )
        .env(
            CHILD_BOOT_NONCE,
            format!("{:#x}", worker_identity.boot_nonce),
        )
        .env(
            CHILD_BUNDLE,
            format!("{:#x}", worker_identity.protocol_bundle_hash),
        )
        .env(CHILD_CAS_ROOT, directory.path())
        .env(
            CHILD_CAS_OBJECT_CAP,
            cas_limits.max_object_bytes.to_string(),
        )
        .env(CHILD_CAS_TOTAL_CAP, cas_limits.max_total_bytes.to_string())
        .env(CHILD_INBOX_ROOT, &inbox_root)
        .env(CHILD_SUPERVISOR_ADDRESS, supervisor_address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn FixedReduce worker");
    drop(command);
    let client_identity = EndpointIdentity {
        boot_nonce: B256::repeat_byte(0xE1),
        ..worker_identity
    };
    let mut client = accept_registered_worker(&listener, client_identity, 300, limits);
    client
        .dispatch_encoded(
            RunUnitV1 {
                protocol_bundle_hash,
                job_id,
                attempt: 0,
                plan_hash,
                unit_index: plan.primary_work_unit_count * 2,
                canonical_unit_spec: BoundedBytes(
                    reduce_spec
                        .encode_canonical(&limits)
                        .expect("canonical FixedReduce spec"),
                ),
                unit_membership_siblings: Vec::new(),
                plan_ref: plan_ref.clone(),
                input_manifest_ref: published.manifest_ref.clone(),
                ordered_input_refs: vec![fidelity_producer_ref.clone()],
            }
            .encode_body(&limits)
            .expect("FixedReduce RunUnit body"),
        )
        .expect("send FixedReduce unit");
    let finished = receive_finished(&mut client, &limits);
    let mut child = child;
    child.kill().expect("stop FixedReduce worker listener");
    child.wait().expect("reap FixedReduce worker listener");
    assert_eq!(finished.status, UnitFinishedStatus::Success);
    assert_eq!(finished.unit_id, reduce_unit_id);
    let reduce_artifact = UnitArtifactV1::decode_canonical(
        inbox
            .read_reported(
                finished.unit_id,
                finished.exact_staged_bytes,
                finished.transport_digest,
            )
            .expect("read staged FixedReduce artifact")
            .bytes(),
        &limits,
    )
    .expect("decode FixedReduce artifact");
    reduce_artifact
        .validate_against(&reduce_spec, &limits)
        .expect("validate FixedReduce artifact");
    let reduced =
        decode_fixed_reduce_output(reduce_artifact.phase_payload(&limits).unwrap(), &limits)
            .expect("decode FixedReduce phase output");
    assert_eq!(reduced.aggregate.unwrap().tribute_count, 1);
    assert!(!reduced.ordered_fractions.is_empty());
    verify_core_phase_replay(
        plan.primary_work_unit_count * 2,
        &reduce_spec,
        &reduce_artifact,
        &plan,
        &manifest,
        &[],
        std::slice::from_ref(&fidelity_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact FixedReduce bytes");

    let mut reduce_producer_ref = cas
        .publish_bytes(
            &reduce_artifact
                .encode_canonical(&limits)
                .expect("canonical FixedReduce artifact"),
        )
        .expect("publish FixedReduce producer artifact");
    reduce_producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let amount_spec = planner
        .amount_map_unit_at(
            0,
            &spec,
            fidelity_artifact.unit_id,
            reduce_artifact.unit_id,
            &limits,
        )
        .expect("derive AmountMap unit");
    let amount_unit_id = amount_spec.unit_id(&limits).expect("AmountMap UnitId");
    let oracle_ref = published
        .ordered_chunk_refs
        .iter()
        .find(|reference| {
            cas.read_verified(reference)
                .ok()
                .and_then(|object| derive_input_chunk_ref(&object, &bundle, &limits).ok())
                .is_some_and(|derived| derived.reference.kind == InputChunkKind::Oracle)
        })
        .cloned()
        .expect("fixture Oracle input reference");
    let (listener, supervisor_address) = supervisor_listener();
    let worker_identity = identity(0xF0);
    let mut command = Command::new(env::current_exe().expect("current Rust test binary"));
    command
        .args([
            "--exact",
            "real_worker_processes_execute_through_output_finalize",
            "--nocapture",
        ])
        .env(CHILD_MODE, "1")
        .env(CHILD_CHAIN_ID, worker_identity.chain_id.to_string())
        .env(
            CHILD_GENESIS,
            format!("{:#x}", worker_identity.genesis_hash),
        )
        .env(
            CHILD_BOOT_NONCE,
            format!("{:#x}", worker_identity.boot_nonce),
        )
        .env(
            CHILD_BUNDLE,
            format!("{:#x}", worker_identity.protocol_bundle_hash),
        )
        .env(CHILD_CAS_ROOT, directory.path())
        .env(
            CHILD_CAS_OBJECT_CAP,
            cas_limits.max_object_bytes.to_string(),
        )
        .env(CHILD_CAS_TOTAL_CAP, cas_limits.max_total_bytes.to_string())
        .env(CHILD_INBOX_ROOT, &inbox_root)
        .env(CHILD_SUPERVISOR_ADDRESS, supervisor_address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn AmountMap worker");
    drop(command);
    let client_identity = EndpointIdentity {
        boot_nonce: B256::repeat_byte(0xF1),
        ..worker_identity
    };
    let mut client = accept_registered_worker(&listener, client_identity, 400, limits);
    client
        .dispatch_encoded(
            RunUnitV1 {
                protocol_bundle_hash,
                job_id,
                attempt: 0,
                plan_hash,
                unit_index: 3,
                canonical_unit_spec: BoundedBytes(
                    amount_spec
                        .encode_canonical(&limits)
                        .expect("canonical AmountMap spec"),
                ),
                unit_membership_siblings: Vec::new(),
                plan_ref: plan_ref.clone(),
                input_manifest_ref: published.manifest_ref.clone(),
                ordered_input_refs: vec![
                    producer_ref.clone(),
                    fidelity_producer_ref.clone(),
                    reduce_producer_ref.clone(),
                    tribute_ref.clone(),
                    oracle_ref.clone(),
                ],
            }
            .encode_body(&limits)
            .expect("AmountMap RunUnit body"),
        )
        .expect("send AmountMap unit");
    let finished = receive_finished(&mut client, &limits);
    let mut child = child;
    child.kill().expect("stop AmountMap worker listener");
    child.wait().expect("reap AmountMap worker listener");
    assert_eq!(finished.status, UnitFinishedStatus::Success);
    assert_eq!(finished.unit_id, amount_unit_id);
    let amount_artifact = UnitArtifactV1::decode_canonical(
        inbox
            .read_reported(
                finished.unit_id,
                finished.exact_staged_bytes,
                finished.transport_digest,
            )
            .expect("read staged AmountMap artifact")
            .bytes(),
        &limits,
    )
    .expect("decode AmountMap artifact");
    amount_artifact
        .validate_against(&amount_spec, &limits)
        .expect("validate AmountMap artifact");
    let amount = decode_amount_run(amount_artifact.phase_payload(&limits).unwrap(), &limits)
        .expect("decode AmountMap phase output");
    assert_eq!(amount.ordered_records.len(), 1);
    assert_eq!(
        amount.ordered_records[0].entry_price_minor,
        generic_price_scale * U256::from(2)
    );
    let oracle_object = cas
        .read_verified(&oracle_ref)
        .expect("read authenticated Oracle chunk");
    let oracle_input = (
        derive_input_chunk_ref(&oracle_object, &bundle, &limits)
            .expect("derive Oracle reference")
            .reference,
        decode_verified_input_chunk(&oracle_object, &bundle, &limits)
            .expect("decode authenticated Oracle chunk"),
    );
    let amount_inputs = vec![replay_inputs[0].clone(), oracle_input];
    verify_core_phase_replay(
        3,
        &amount_spec,
        &amount_artifact,
        &plan,
        &manifest,
        &amount_inputs,
        &[
            artifact.clone(),
            fidelity_artifact.clone(),
            reduce_artifact.clone(),
        ],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact AmountMap bytes");

    let topology =
        LysisPlanTopologyV1::new(plan.primary_work_unit_count).expect("fixture plan topology");
    let prefix_offset = plan
        .primary_work_unit_count
        .checked_mul(3)
        .and_then(|offset| offset.checked_add(topology.phase_unit_count(UnitPhase::FixedReduce)))
        .expect("GratisPrefix offset");
    let prefix_down_offset = prefix_offset
        .checked_add(topology.phase_unit_count(UnitPhase::GratisPrefix))
        .expect("GratisPrefixDown offset");

    let mut amount_producer_ref = cas
        .publish_bytes(
            &amount_artifact
                .encode_canonical(&limits)
                .expect("canonical AmountMap artifact"),
        )
        .expect("publish AmountMap producer artifact");
    amount_producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let prefix_leaf_spec = planner
        .gratis_prefix_unit_at(0, &[Some(amount_artifact.unit_id)], &limits)
        .expect("derive GratisPrefix leaf");
    let prefix_leaf_artifact = execute_real_worker_unit(
        500,
        0x91,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &prefix_leaf_spec,
        prefix_offset,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![amount_producer_ref],
    );
    prefix_leaf_artifact
        .validate_against(&prefix_leaf_spec, &limits)
        .expect("validate GratisPrefix leaf artifact");
    verify_core_phase_replay(
        prefix_offset,
        &prefix_leaf_spec,
        &prefix_leaf_artifact,
        &plan,
        &manifest,
        &[],
        std::slice::from_ref(&amount_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact GratisPrefix leaf bytes");
    let leaf_summary = decode_gratis_segment_summary(
        prefix_leaf_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode GratisPrefix leaf");
    assert_eq!(
        leaf_summary.checked_segment_gratis_total,
        amount.checked_segment_gratis_total
    );

    let mut prefix_leaf_ref = cas
        .publish_bytes(
            &prefix_leaf_artifact
                .encode_canonical(&limits)
                .expect("canonical GratisPrefix leaf artifact"),
        )
        .expect("publish GratisPrefix leaf artifact");
    prefix_leaf_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let prefix_root_spec = planner
        .gratis_prefix_unit_at(1, &[Some(prefix_leaf_artifact.unit_id), None], &limits)
        .expect("derive GratisPrefix root");
    let prefix_root_artifact = execute_real_worker_unit(
        501,
        0x93,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &prefix_root_spec,
        prefix_offset + 1,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![prefix_leaf_ref.clone()],
    );
    prefix_root_artifact
        .validate_against(&prefix_root_spec, &limits)
        .expect("validate GratisPrefix root artifact");
    verify_core_phase_replay(
        prefix_offset + 1,
        &prefix_root_spec,
        &prefix_root_artifact,
        &plan,
        &manifest,
        &[],
        std::slice::from_ref(&prefix_leaf_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact GratisPrefix root bytes");
    assert_eq!(
        decode_gratis_segment_summary(
            prefix_root_artifact.phase_payload(&limits).unwrap(),
            &limits,
        )
        .expect("decode GratisPrefix root"),
        leaf_summary
    );

    let prefix_down_root_spec = planner
        .gratis_prefix_down_unit_at(0, &[Some(prefix_leaf_artifact.unit_id), None], &limits)
        .expect("derive GratisPrefixDown root");
    let prefix_down_root_artifact = execute_real_worker_unit(
        502,
        0x95,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &prefix_down_root_spec,
        prefix_down_offset,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![prefix_leaf_ref.clone()],
    );
    prefix_down_root_artifact
        .validate_against(&prefix_down_root_spec, &limits)
        .expect("validate GratisPrefixDown root artifact");
    verify_core_phase_replay(
        prefix_down_offset,
        &prefix_down_root_spec,
        &prefix_down_root_artifact,
        &plan,
        &manifest,
        &[],
        std::slice::from_ref(&prefix_leaf_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact GratisPrefixDown root bytes");
    assert!(matches!(
        decode_gratis_prefix_down_output(
            prefix_down_root_artifact.phase_payload(&limits).unwrap(),
            &limits,
        )
        .expect("decode GratisPrefixDown root"),
        GratisPrefixDownOutputV1::Branch([Some(_), None])
    ));

    let mut prefix_down_root_ref = cas
        .publish_bytes(
            &prefix_down_root_artifact
                .encode_canonical(&limits)
                .expect("canonical GratisPrefixDown root artifact"),
        )
        .expect("publish GratisPrefixDown root artifact");
    prefix_down_root_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let prefix_down_leaf_spec = planner
        .gratis_prefix_down_unit_at(
            1,
            &[
                Some(prefix_down_root_artifact.unit_id),
                Some(prefix_leaf_artifact.unit_id),
            ],
            &limits,
        )
        .expect("derive GratisPrefixDown leaf");
    let prefix_down_leaf_artifact = execute_real_worker_unit(
        503,
        0x97,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &prefix_down_leaf_spec,
        prefix_down_offset + 1,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![prefix_down_root_ref, prefix_leaf_ref],
    );
    prefix_down_leaf_artifact
        .validate_against(&prefix_down_leaf_spec, &limits)
        .expect("validate GratisPrefixDown leaf artifact");
    verify_core_phase_replay(
        prefix_down_offset + 1,
        &prefix_down_leaf_spec,
        &prefix_down_leaf_artifact,
        &plan,
        &manifest,
        &[],
        &[
            prefix_down_root_artifact.clone(),
            prefix_leaf_artifact.clone(),
        ],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact GratisPrefixDown leaf bytes");
    let GratisPrefixDownOutputV1::Leaf(prefix) = decode_gratis_prefix_down_output(
        prefix_down_leaf_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode GratisPrefixDown leaf") else {
        panic!("expected GratisPrefixDown leaf output");
    };
    assert_eq!(prefix.segment_ordinal, 0);
    assert_eq!(prefix.incoming_remaining, plan.lysis_budget);
    assert_eq!(
        prefix.outgoing_remaining,
        plan.lysis_budget - amount.checked_segment_gratis_total
    );

    let mut amount_finalize_ref = cas
        .publish_bytes(
            &amount_artifact
                .encode_canonical(&limits)
                .expect("canonical AmountMap finalize producer"),
        )
        .expect("publish AmountMap finalize producer");
    amount_finalize_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let mut prefix_down_leaf_ref = cas
        .publish_bytes(
            &prefix_down_leaf_artifact
                .encode_canonical(&limits)
                .expect("canonical GratisPrefixDown leaf producer"),
        )
        .expect("publish GratisPrefixDown leaf producer");
    prefix_down_leaf_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let output_finalize_spec = planner
        .output_finalize_unit_at(0, &amount_spec, prefix_down_leaf_artifact.unit_id, &limits)
        .expect("derive OutputFinalize unit");
    let output_finalize_offset = prefix_down_offset
        .checked_add(topology.phase_unit_count(UnitPhase::GratisPrefixDown))
        .expect("OutputFinalize offset");
    let output_finalize_artifact = execute_real_worker_unit(
        504,
        0x99,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &output_finalize_spec,
        output_finalize_offset,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![amount_finalize_ref, prefix_down_leaf_ref],
    );
    output_finalize_artifact
        .validate_against(&output_finalize_spec, &limits)
        .expect("validate OutputFinalize artifact");
    let finalized = decode_finalized_output_run(
        output_finalize_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode OutputFinalize artifact");
    assert_eq!(finalized.ordered_records.len(), 1);
    assert_eq!(
        finalized.checked_tribute_nominal_total,
        tribute.nominal_amount_minor
    );
    assert_eq!(
        finalized.ordered_records[0].nod_action.issued_at,
        plan.logical_evaluation_time
    );
    assert_eq!(
        finalized.ordered_records[0].nod_action.source_tribute_id,
        tribute.tribute_id
    );
    verify_output_finalize_replay(
        0,
        &output_finalize_spec,
        &output_finalize_artifact,
        &amount_artifact,
        &prefix_down_leaf_artifact,
        &plan,
        &manifest,
        &bundle,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact OutputFinalize bytes");
    let output_finalize_bytes = output_finalize_artifact.encode_canonical(&limits).unwrap();
    let output_finalize_finished = UnitFinishedV1 {
        unit_id: output_finalize_artifact.unit_id,
        status: UnitFinishedStatus::Success,
        exact_staged_bytes: u64::try_from(output_finalize_bytes.len()).unwrap(),
        transport_digest: keccak256(&output_finalize_bytes),
    };
    let replay_inbox = WorkerInbox::open(&inbox_root, inbox_limits).unwrap();
    let mut admission_catalog = VerifiedAdmissionCatalog::open(
        directory.path().join("admissions"),
        &cas,
        &plan_ref,
        &published.manifest_ref,
        limits,
    )
    .unwrap();
    let pinned_bundle = PinnedProtocolBundle::decode(
        &bundle.encode_canonical(&limits).unwrap(),
        protocol_bundle_hash,
        &limits,
    )
    .unwrap();
    let input_ref_catalog = VerifiedInputChunkRefCatalog::reopen(
        directory.path().join("input-refs"),
        &reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admitted_enumerate = admit_reported_lysis_unit_v1(
        0,
        &finished_reports[0],
        &mut admission_catalog,
        &input_ref_catalog,
        &pinned_bundle,
        &reader,
        &replay_inbox,
        &semantic_replay_inbox,
        &cas,
        &limits,
    )
    .expect("admit exact supervisor-replayed Enumerate artifact");
    assert_eq!(
        admitted_enumerate.admission,
        AdmissionOutcome::NewlyAdmitted
    );
    assert_eq!(
        admitted_enumerate.artifact_ref.expected_ocb1_kind,
        Some(ObjectKind::UnitArtifactV1.tag())
    );
    let output_finalize_plan_ordinal = [
        UnitPhase::Enumerate,
        UnitPhase::FidelityMap,
        UnitPhase::FixedReduce,
        UnitPhase::AmountMap,
        UnitPhase::GratisPrefix,
        UnitPhase::GratisPrefixDown,
    ]
    .into_iter()
    .map(|phase| topology.phase_unit_count(phase))
    .sum();
    let admitted_output_finalize = admit_reported_output_finalize_unit(
        AdmissionPositionV1 {
            plan_ordinal: output_finalize_plan_ordinal,
        },
        0,
        &output_finalize_spec,
        &output_finalize_finished,
        &amount_artifact,
        &prefix_down_leaf_artifact,
        &plan,
        &manifest,
        &bundle,
        &replay_inbox,
        &cas,
        &mut admission_catalog,
        &limits,
    )
    .expect("admit exact replayed OutputFinalize artifact");
    assert_eq!(
        admitted_output_finalize.artifact_ref.expected_ocb1_kind,
        Some(ObjectKind::UnitArtifactV1.tag())
    );
    assert_eq!(
        admitted_output_finalize.admission,
        AdmissionOutcome::NewlyAdmitted
    );
    assert_eq!(
        cas.read_verified(&admitted_output_finalize.artifact_ref)
            .unwrap()
            .bytes(),
        output_finalize_bytes
    );
    let mut forged_finalized = finalized.clone();
    forged_finalized.checked_tribute_nominal_total += U256::from(1);
    let output_header = output_finalize_artifact.output_header(&limits).unwrap();
    let forged_artifact = UnitArtifactV1::from_canonical_output(
        &output_finalize_spec,
        output_header,
        BoundedBytes(
            encode_finalized_output_run(&forged_finalized, &limits)
                .expect("canonical forged OutputFinalize payload"),
        ),
        &limits,
    )
    .expect("build digest-valid forged OutputFinalize artifact");
    assert!(verify_output_finalize_replay(
        0,
        &output_finalize_spec,
        &forged_artifact,
        &amount_artifact,
        &prefix_down_leaf_artifact,
        &plan,
        &manifest,
        &bundle,
        &limits,
    )
    .is_err());

    let mut finalized_ref = cas
        .publish_bytes(
            &output_finalize_artifact
                .encode_canonical(&limits)
                .expect("canonical OutputFinalize shuffle producer"),
        )
        .expect("publish OutputFinalize shuffle producer");
    finalized_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let owner_spec = planner
        .shuffle_unit_at(
            UnitPhase::OwnerShuffle,
            0,
            &[output_finalize_artifact.unit_id],
            &limits,
        )
        .expect("derive OwnerShuffle leaf");
    let owner_offset = output_finalize_offset
        .checked_add(topology.phase_unit_count(UnitPhase::OutputFinalize))
        .expect("OwnerShuffle offset");
    let owner_artifact = execute_real_worker_unit(
        505,
        0x9A,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &owner_spec,
        owner_offset,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![finalized_ref.clone()],
    );
    owner_artifact
        .validate_against(&owner_spec, &limits)
        .expect("validate OwnerShuffle artifact");
    let owner_root = ShuffleRunArtifactV1::decode_canonical(
        owner_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode OwnerShuffle root");
    owner_root
        .validate_root_semantics(&limits)
        .expect("validate OwnerShuffle root");
    assert_eq!(owner_root.kind, ShuffleRunKindV1::Owner);
    assert_eq!(owner_root.record_count, 1);
    verify_lysis_shuffle_phase_replay(
        owner_offset,
        &owner_spec,
        &owner_artifact,
        &plan,
        &manifest,
        std::slice::from_ref(&output_finalize_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact OwnerShuffle bytes");
    adopt_lysis_shuffle_descendants(owner_root.clone(), &inbox, &cas, &limits)
        .expect("publish exact OwnerShuffle descendants to authoritative CAS");

    let bucket_spec = planner
        .shuffle_unit_at(
            UnitPhase::BucketShuffle,
            0,
            &[output_finalize_artifact.unit_id],
            &limits,
        )
        .expect("derive BucketShuffle leaf");
    let bucket_offset = owner_offset
        .checked_add(topology.phase_unit_count(UnitPhase::OwnerShuffle))
        .expect("BucketShuffle offset");
    let bucket_artifact = execute_real_worker_unit(
        506,
        0x9B,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &bucket_spec,
        bucket_offset,
        plan_hash,
        plan_ref.clone(),
        published.manifest_ref.clone(),
        vec![finalized_ref.clone()],
    );
    bucket_artifact
        .validate_against(&bucket_spec, &limits)
        .expect("validate BucketShuffle artifact");
    let bucket_root = ShuffleRunArtifactV1::decode_canonical(
        bucket_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode BucketShuffle root");
    bucket_root
        .validate_root_semantics(&limits)
        .expect("validate BucketShuffle root");
    assert_eq!(bucket_root.kind, ShuffleRunKindV1::Bucket);
    assert_eq!(bucket_root.record_count, 1);
    verify_lysis_shuffle_phase_replay(
        bucket_offset,
        &bucket_spec,
        &bucket_artifact,
        &plan,
        &manifest,
        std::slice::from_ref(&output_finalize_artifact),
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact BucketShuffle bytes");
    adopt_lysis_shuffle_descendants(bucket_root.clone(), &inbox, &cas, &limits)
        .expect("publish exact BucketShuffle descendants to authoritative CAS");

    let mut owner_ref = cas
        .publish_bytes(
            &owner_artifact
                .encode_canonical(&limits)
                .expect("canonical OwnerShuffle root producer"),
        )
        .expect("publish OwnerShuffle root producer");
    owner_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let mut bucket_ref = cas
        .publish_bytes(
            &bucket_artifact
                .encode_canonical(&limits)
                .expect("canonical BucketShuffle root producer"),
        )
        .expect("publish BucketShuffle root producer");
    bucket_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let root_reduce_spec = planner
        .root_reduce_unit_at(
            0,
            &[
                Some(output_finalize_artifact.unit_id),
                Some(owner_artifact.unit_id),
                Some(bucket_artifact.unit_id),
            ],
            &limits,
        )
        .expect("derive RootReduce leaf");
    let root_reduce_offset = bucket_offset
        .checked_add(topology.phase_unit_count(UnitPhase::BucketShuffle))
        .expect("RootReduce offset");
    let root_reduce_artifact = execute_real_worker_unit(
        507,
        0x9c,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &root_reduce_spec,
        root_reduce_offset,
        plan_hash,
        plan_ref,
        published.manifest_ref,
        vec![finalized_ref, owner_ref, bucket_ref],
    );
    root_reduce_artifact
        .validate_against(&root_reduce_spec, &limits)
        .expect("validate RootReduce leaf artifact");
    verify_lysis_root_reduce_phase_replay(
        root_reduce_offset,
        &root_reduce_spec,
        &root_reduce_artifact,
        &plan,
        &manifest,
        &[
            output_finalize_artifact.clone(),
            owner_artifact.clone(),
            bucket_artifact.clone(),
        ],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .expect("supervisor semantic replay accepts exact RootReduce bytes and ResultChunk");
    let reduced = decode_root_reduce_output(
        root_reduce_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode RootReduce leaf");
    let mut forged_reduced = reduced.clone();
    match &mut forged_reduced {
        RootReduceOutputV1::Leaf { summary, .. } | RootReduceOutputV1::Node { summary } => {
            summary.nod_cost_total += U256::from(1);
        }
    }
    let forged_root_reduce_artifact = UnitArtifactV1::from_canonical_output(
        &root_reduce_spec,
        root_reduce_artifact.output_header(&limits).unwrap(),
        BoundedBytes(
            encode_root_reduce_output(&forged_reduced, &limits)
                .expect("encode digest-valid forged RootReduce output"),
        ),
        &limits,
    )
    .expect("build digest-valid forged RootReduce artifact");
    assert!(verify_lysis_root_reduce_phase_replay(
        root_reduce_offset,
        &root_reduce_spec,
        &forged_root_reduce_artifact,
        &plan,
        &manifest,
        &[
            output_finalize_artifact.clone(),
            owner_artifact.clone(),
            bucket_artifact.clone(),
        ],
        &bundle,
        &reader,
        &semantic_replay_inbox,
        &limits,
    )
    .is_err());
    let RootReduceOutputV1::Leaf {
        summary,
        output_manifest_entry,
    } = reduced
    else {
        panic!("single-shard RootReduce must emit LEAF");
    };
    assert_eq!(summary.tribute_count, 1);
    assert_eq!(summary.nod_count, 1);
    assert_eq!(summary.bucket_count, 1);
    assert_eq!(summary.contributor_count, 1);
    assert_eq!(summary.tribute_nominal_total, tribute.nominal_amount_minor);
    assert_eq!(summary.eligible_nominal_total, tribute.nominal_amount_minor);
    assert_eq!(
        summary.nod_gratis_consumed,
        finalized.ordered_records[0].nod_action.gratis_load_minor
    );

    let inbox = WorkerInbox::open(&inbox_root, inbox_limits).expect("reopen worker inbox");
    let chunk_object = inbox
        .read_result_chunk(&output_manifest_entry.result_chunk_ref, &limits)
        .expect("read staged ResultChunkV1");
    let chunk = ResultChunkV1::decode_canonical(chunk_object.bytes(), &limits)
        .expect("decode staged ResultChunkV1");
    assert_eq!(chunk.chunk_ordinal, 0);
    assert_eq!(chunk.first_nod_ordinal, 0);
    assert_eq!(chunk.ordered_nod_actions.len(), 1);
    assert_eq!(chunk.ordered_eligible_contributors.len(), 1);
    assert_eq!(
        chunk.result_chunk_hash(&limits).unwrap(),
        output_manifest_entry.result_chunk_hash
    );
    assert_eq!(inbox.object_count().expect("count typed objects"), 3);

    let intent = JobIntentV1 {
        chain_id: 41,
        genesis_hash: B256::repeat_byte(0x41),
        fork_id: B256::repeat_byte(0x42),
        wwd: day.value(),
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash,
        ce_sealed_root: manifest.checkpoint.finalized_ce_root,
        sealed_tribute_collection_key: manifest.sealed_tribute_collection_key,
        sealed_tribute_collection_root: manifest.sealed_tribute_collection_root,
        authenticated_day_count: manifest.tribute_count,
        authenticated_day_nominal: manifest.tribute_nominal_total,
        pre_admission_envelope_hash: B256::repeat_byte(0x43),
        source_availability_policy_id: B256::repeat_byte(0x44),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: plan.lysis_budget + U256::from(1_000),
            previous_vwap: U256::from(90),
            current_vwap: U256::from(100),
            gratis_demand: U256::from(25),
            gratis_supply: U256::from(20),
            lysis_budget: plan.lysis_budget,
            auction_base: U256::from(1_000),
            auction_entry_prices: vec![ReferenceEntryPriceV1 {
                reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
                entry_price_minor: U256::from(95),
                source: AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: 6,
            }],
            request_budget_split_receipt_hash: B256::repeat_byte(0x45),
        },
        logical_evaluation_height: manifest.checkpoint.finalized_block_number,
        logical_evaluation_time: plan.logical_evaluation_time,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: day.value(),
                source_generation: 1,
                collection_key: manifest.sealed_tribute_collection_key,
                sealed_collection_root: manifest.sealed_tribute_collection_root,
                exact_count: manifest.tribute_count,
                exact_nominal_total: manifest.tribute_nominal_total,
            },
            nod: NodTargetPreconditionV1 {
                wwd: day.value(),
                target_generation: 1,
                namespace_root_before: B256::repeat_byte(0x46),
                max_nod_count: manifest.tribute_count,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: day.value(),
                expected_series_version: 1,
                max_contributor_count: manifest.tribute_count,
                max_eligible_nominal_total: manifest.tribute_nominal_total,
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: day.value(),
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 1,
            },
        },
        result_validator_set_epoch: 7,
        result_committee_set_hash: B256::repeat_byte(0x47),
        result_ocomp_binding_hash: B256::repeat_byte(0x48),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    };
    let ordered_artifacts = vec![
        artifact,
        fidelity_artifact,
        reduce_artifact,
        amount_artifact,
        prefix_leaf_artifact,
        prefix_root_artifact,
        prefix_down_root_artifact,
        prefix_down_leaf_artifact,
        output_finalize_artifact,
        owner_artifact,
        bucket_artifact,
        root_reduce_artifact,
    ];
    let canonical_chunk_bytes = chunk
        .encode_canonical(&limits)
        .expect("canonical finalization chunk");
    let bucket_record = ShuffleBucketRecordV1 {
        bucket_key: chunk.ordered_nod_actions[0].bucket_key,
        raw_ordinal: chunk.ordered_nod_actions[0].raw_ordinal,
        tribute_id: chunk.ordered_nod_actions[0].tribute_id,
        nod_id: chunk.ordered_nod_actions[0].nod_id,
    };
    let run_finalizer =
        |intent: &JobIntentV1, artifacts: Vec<UnitArtifactV1>, chunk_bytes: Vec<u8>| {
            let units = artifacts
                .into_iter()
                .enumerate()
                .map(|(ordinal, artifact)| {
                    let plan_ordinal = u32::try_from(ordinal).expect("fixture plan ordinal");
                    Ok(FinalizationUnitArtifactV1 {
                        plan_ordinal,
                        position: topology.plan_position_at(plan_ordinal).unwrap_or(
                            PlannedUnitPositionV1::TreeNode {
                                phase: UnitPhase::RootReduce,
                                level: 0,
                                index: 0,
                            },
                        ),
                        artifact,
                    })
                });
            finalize_v1(
                VerifiedLysisFinalizationInputsV1 {
                    finalized_job_id: job_id,
                    intent,
                    input_manifest: &manifest,
                    plan: &plan,
                    root_reduce_summary: &summary,
                    unit_artifacts: units,
                    result_chunks: std::iter::once(Ok(FinalizationResultChunkV1 {
                        chunk_ordinal: 0,
                        summary: summary.clone(),
                        output_manifest_entry: output_manifest_entry.clone(),
                        canonical_chunk_bytes: chunk_bytes,
                    })),
                    bucket_records: std::iter::once(Ok(bucket_record.clone())),
                },
                &limits,
            )
        };
    let result = run_finalizer(
        &intent,
        ordered_artifacts.clone(),
        canonical_chunk_bytes.clone(),
    )
    .expect("typed Lysis finalizer accepts the exact real-worker pipeline");
    result.validate_semantics(&limits).unwrap();
    result.validate_finalized_intent(&intent).unwrap();
    assert_eq!(result.job_id, job_id);
    assert_eq!(result.tribute_count, 1);
    assert_eq!(result.counts.nod_count, 1);
    assert_eq!(result.counts.bucket_count, 1);
    assert_eq!(result.counts.contributor_count, 1);
    assert_eq!(result.result_chunk_count, 1);

    let replay = run_finalizer(
        &intent,
        ordered_artifacts.clone(),
        canonical_chunk_bytes.clone(),
    )
    .expect("exact finalization replay");
    assert_eq!(
        replay.encode_canonical(&limits).unwrap(),
        result.encode_canonical(&limits).unwrap()
    );

    let unit_digests = ordered_artifacts[..ordered_artifacts.len() - 1]
        .iter()
        .map(|artifact| artifact.artifact_digest(&limits).unwrap().to_vec())
        .collect::<Vec<_>>();
    let expected_unit_artifact_root = ordered_list_root(
        ListKind::UnitSpecificationsArtifacts,
        &unit_digests,
        OrderedListLimits::new(
            unit_digests.len(),
            B256::len_bytes(),
            unit_digests.len().next_power_of_two() * B256::len_bytes(),
        ),
    )
    .unwrap();
    assert_eq!(result.unit_artifact_root, expected_unit_artifact_root);
    let all_unit_digests = ordered_artifacts
        .iter()
        .map(|artifact| artifact.artifact_digest(&limits).unwrap().to_vec())
        .collect::<Vec<_>>();
    assert_ne!(
        result.unit_artifact_root,
        ordered_list_root(
            ListKind::UnitSpecificationsArtifacts,
            &all_unit_digests,
            OrderedListLimits::new(
                all_unit_digests.len(),
                B256::len_bytes(),
                all_unit_digests.len().next_power_of_two() * B256::len_bytes(),
            ),
        )
        .unwrap()
    );

    let mut changed_intent = intent.clone();
    changed_intent.frozen_metadosis_values.lysis_budget += U256::from(1);
    changed_intent.frozen_metadosis_values.day_limit += U256::from(1);
    assert!(run_finalizer(
        &changed_intent,
        ordered_artifacts.clone(),
        canonical_chunk_bytes.clone(),
    )
    .is_err());

    let mut changed_chunk = canonical_chunk_bytes;
    let last = changed_chunk
        .last_mut()
        .expect("non-empty canonical ResultChunkV1");
    *last ^= 1;
    assert!(run_finalizer(&intent, ordered_artifacts.clone(), changed_chunk).is_err());

    let mut extra_artifact = ordered_artifacts;
    extra_artifact.push(
        extra_artifact
            .last()
            .expect("final ROOT_REDUCE artifact")
            .clone(),
    );
    assert!(run_finalizer(
        &intent,
        extra_artifact,
        chunk.encode_canonical(&limits).unwrap(),
    )
    .is_err());
}

#[test]
fn real_worker_materializes_and_adopts_two_leaf_shuffle_merges() {
    if env::var_os(CHILD_MODE).is_some() {
        run_child_worker();
        return;
    }

    let directory = tempdir().expect("worker merge fixture");
    let cas_limits = CasLimits {
        max_object_bytes: 1024 * 1024,
        max_total_bytes: 16 * 1024 * 1024,
    };
    let cas = FilesystemCas::open(directory.path(), CasWriterRole::Supervisor, cas_limits)
        .expect("open merge CAS");
    let inbox_root = directory.path().join("worker-inbox");
    let inbox_limits = WorkerInboxLimits {
        max_artifact_bytes: 1024 * 1024,
        max_total_bytes: 8 * 1024 * 1024,
    };
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle
        .protocol_bundle_hash(&limits)
        .expect("merge bundle hash");
    let job_id = B256::repeat_byte(0x71);
    let attempt = 1;
    let day = WorldwideDay::new(20_260_725);
    let tribute_count = 257_u32;
    let tribute_nominal_total =
        U256::from(tribute_count) * U256::from(tribute_count + 1) / U256::from(2);
    let manifest = InputManifestV1 {
        protocol_bundle_hash,
        job_id,
        attempt,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 101,
            finalized_block_hash: B256::repeat_byte(0x72),
            finalized_state_root: B256::repeat_byte(0x73),
            finalized_ce_root: B256::repeat_byte(0x74),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: B256::repeat_byte(0x75),
        sealed_tribute_collection_root: B256::repeat_byte(0x76),
        tribute_count,
        tribute_nominal_total,
        input_chunk_count: 1,
        input_chunk_list_root: B256::repeat_byte(0x77),
        fidelity_opening_root: B256::repeat_byte(0x78),
        oracle_opening_root: B256::repeat_byte(0x79),
        exact_encoded_bytes: 1,
        exact_record_count: tribute_count,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle
            .opening_codec_registry_hash()
            .expect("merge opening registry"),
        compression: Compression::None,
    };
    let manifest_hash = manifest
        .manifest_hash(&limits)
        .expect("merge manifest hash");
    let mut manifest_ref = cas
        .publish_bytes(
            &manifest
                .encode_canonical(&limits)
                .expect("canonical merge manifest"),
        )
        .expect("publish merge manifest");
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());

    let plan = PlanCommitmentV1 {
        protocol_bundle_hash,
        job_id,
        attempt,
        input_manifest_hash: manifest_hash,
        wwd: day.value(),
        lysis_budget: U256::from(10_000),
        logical_evaluation_time: 2_026_072_500,
        tribute_count,
        max_tributes_per_work_shard: 256,
        primary_work_unit_count: 2,
        primary_work_unit_root: B256::repeat_byte(0x7a),
        planner_spec_version: bundle.planner_spec_version,
        reducer_spec_version: bundle.reducer_spec_version,
    };
    let plan_hash = plan.plan_hash(&limits).expect("merge plan hash");
    let plan_ref = cas
        .publish_bytes(
            &plan
                .encode_canonical_record(&limits)
                .expect("canonical merge plan"),
        )
        .expect("publish merge plan");

    let planner = LysisPlannerV1::new(LysisPlannerBindingsV1 {
        protocol_bundle_hash,
        job_id,
        attempt,
        input_manifest_hash: manifest_hash,
        input_manifest_encoded_bytes: manifest_ref.encoded_bytes,
        fidelity_opening_root: manifest.fidelity_opening_root,
        oracle_opening_root: manifest.oracle_opening_root,
        wwd: day.value(),
        lysis_budget: plan.lysis_budget,
        logical_evaluation_time: plan.logical_evaluation_time,
        tribute_count,
        lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
        planner_spec_version: bundle.planner_spec_version,
        reducer_spec_version: bundle.reducer_spec_version,
    })
    .expect("merge planner");
    let topology = LysisPlanTopologyV1::new(2).expect("merge topology");

    let mut identities = (0..tribute_count)
        .map(|ordinal| {
            let mut owner_bytes = [0_u8; 20];
            owner_bytes[16..].copy_from_slice(&(ordinal + 1).to_be_bytes());
            let owner = Address::from(owner_bytes);
            let tribute_id =
                derive_poseidon_entity_id(owner, day).expect("merge synthetic Tribute id");
            (tribute_id, owner)
        })
        .collect::<Vec<_>>();
    identities.sort_by_key(|(tribute_id, _)| *tribute_id);

    let mut finalized_artifacts = Vec::new();
    for shard_ordinal in 0..2_u32 {
        let start = shard_ordinal * 256;
        let end = (start + 256).min(tribute_count);
        let shard = &identities[start as usize..end as usize];
        let amount_records = shard
            .iter()
            .enumerate()
            .map(|(offset, (tribute_id, owner))| {
                let raw_ordinal = start + u32::try_from(offset).expect("merge local ordinal");
                AmountRecordV1 {
                    raw_ordinal,
                    tribute_id: *tribute_id,
                    owner: *owner,
                    worldwide_day: day,
                    league_id: 1,
                    nominal_amount_minor: U256::from(raw_ordinal + 1),
                    gratis_fraction_fp: U256::ZERO,
                    gratis_load_minor: U256::from(1),
                    entry_price_minor: U256::from(2),
                    floor_price_minor: U256::from(3),
                    cost_amount_minor: U256::from(4),
                    issuance_currency: 840,
                    reference_currency: 978,
                    exclude_from_intex_issuance: raw_ordinal == 0,
                }
            })
            .collect::<Vec<_>>();
        let shard_count = end - start;
        let incoming_remaining = U256::from(10_000_u64 - u64::from(start));
        let finalized = output_finalize(
            &AmountRunV1 {
                start_ordinal: start,
                end_ordinal: end,
                ordered_records: amount_records,
                checked_segment_gratis_total: U256::from(shard_count),
            },
            &GratisLeafPrefixV1 {
                segment_ordinal: shard_ordinal,
                incoming_remaining,
                outgoing_remaining: incoming_remaining - U256::from(shard_count),
                first_error_ordinal: None,
            },
            plan.logical_evaluation_time,
        )
        .expect("finalize merge shard");
        let interval = EntityIdHalfOpenRange {
            start: *shard[0].0,
            end: identities
                .get(end as usize)
                .map(|(tribute_id, _)| **tribute_id),
        };
        let output_spec = UnitSpecV1 {
            protocol_bundle_hash,
            job_id,
            attempt,
            phase: UnitPhase::OutputFinalize,
            interval: UnitInterval::EntityIdRange(interval),
            canonical_ordered_inputs: vec![CanonicalInputRefV1 {
                purpose: InputPurpose::InputManifest,
                source_kind: InputSourceKind::AuthenticatedRoot,
                source_id: manifest_hash,
                record_count_limit: 1,
                max_encoded_bytes: manifest_ref.encoded_bytes,
                max_decoded_bytes: manifest_ref.encoded_bytes,
            }],
            lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
            planner_spec_version: bundle.planner_spec_version,
            reducer_spec_version: bundle.reducer_spec_version,
        };
        let coverage_root = finalized.coverage_root().expect("merge shard coverage");
        let output_artifact = UnitArtifactV1::from_canonical_output(
            &output_spec,
            outbe_ocomp_protocol::unit::WorkOutputHeaderV1 {
                source_coverage_root: coverage_root,
                output_coverage_root: coverage_root,
                source_coverage_count: shard_count,
                output_coverage_count: shard_count,
            },
            BoundedBytes(
                encode_finalized_output_run(&finalized, &limits)
                    .expect("encode merge finalized shard"),
            ),
            &limits,
        )
        .expect("build merge finalized artifact");
        finalized_artifacts.push(output_artifact);
    }

    let output_finalize_offset = topology
        .phase_unit_count(UnitPhase::Enumerate)
        .checked_add(topology.phase_unit_count(UnitPhase::FidelityMap))
        .and_then(|value| value.checked_add(topology.phase_unit_count(UnitPhase::FixedReduce)))
        .and_then(|value| value.checked_add(topology.phase_unit_count(UnitPhase::AmountMap)))
        .and_then(|value| value.checked_add(topology.phase_unit_count(UnitPhase::GratisPrefix)))
        .and_then(|value| value.checked_add(topology.phase_unit_count(UnitPhase::GratisPrefixDown)))
        .expect("merge OutputFinalize offset");
    let owner_offset = output_finalize_offset
        .checked_add(topology.phase_unit_count(UnitPhase::OutputFinalize))
        .expect("merge OwnerShuffle offset");
    let mut owner_artifacts = Vec::new();
    for (ordinal, finalized_artifact) in finalized_artifacts.iter().enumerate() {
        let mut producer_ref = cas
            .publish_bytes(
                &finalized_artifact
                    .encode_canonical(&limits)
                    .expect("canonical merge finalized producer"),
            )
            .expect("publish merge finalized producer");
        producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        let owner_spec = planner
            .shuffle_unit_at(
                UnitPhase::OwnerShuffle,
                u32::try_from(ordinal).expect("merge owner ordinal"),
                &[finalized_artifact.unit_id],
                &limits,
            )
            .expect("derive merge owner leaf");
        let artifact = execute_real_worker_unit(
            700 + u64::try_from(ordinal).expect("merge generation"),
            0xa0 + u8::try_from(ordinal).expect("merge boot"),
            directory.path(),
            cas_limits,
            &inbox_root,
            inbox_limits,
            limits,
            &owner_spec,
            owner_offset + u32::try_from(ordinal).expect("merge phase ordinal"),
            plan_hash,
            plan_ref.clone(),
            manifest_ref.clone(),
            vec![producer_ref],
        );
        artifact
            .validate_against(&owner_spec, &limits)
            .expect("validate merge owner leaf artifact");
        owner_artifacts.push(artifact);
    }

    let mut owner_refs = Vec::new();
    for artifact in &owner_artifacts {
        let mut reference = cas
            .publish_bytes(
                &artifact
                    .encode_canonical(&limits)
                    .expect("canonical owner merge producer"),
            )
            .expect("publish owner merge producer");
        reference.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        owner_refs.push(reference);
    }
    let merge_spec = planner
        .shuffle_unit_at(
            UnitPhase::OwnerShuffle,
            2,
            &[owner_artifacts[0].unit_id, owner_artifacts[1].unit_id],
            &limits,
        )
        .expect("derive owner internal merge");
    let merged_artifact = execute_real_worker_unit(
        702,
        0xa2,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &merge_spec,
        owner_offset + 2,
        plan_hash,
        plan_ref.clone(),
        manifest_ref.clone(),
        owner_refs,
    );
    merged_artifact
        .validate_against(&merge_spec, &limits)
        .expect("validate owner internal merge artifact");
    let root = ShuffleRunArtifactV1::decode_canonical(
        merged_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode owner internal merge root");
    assert_eq!(root.kind, ShuffleRunKindV1::Owner);
    assert_eq!(root.run_span.start_run, 0);
    assert_eq!(root.run_span.end_run, 2);
    assert_eq!(root.source_coverage_count, tribute_count);
    assert_eq!(root.record_count, tribute_count - 1);

    let inbox = WorkerInbox::open(&inbox_root, inbox_limits).expect("open merge inbox");
    let adopted = adopt_lysis_shuffle_descendants(root.clone(), &inbox, &cas, &limits)
        .expect("adopt owner internal merge closure");
    assert_eq!(adopted.verified_record_count, tribute_count - 1);
    let records = verified_shuffle_run_records(root, &limits, |reference| {
        cas.read_verified(reference)
            .map(|object| object.bytes().to_vec())
            .map_err(|_| {
                outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                    "adopted owner merge descendant",
                )
            })
    })
    .expect("open adopted owner merge")
    .collect::<Result<Vec<_>, _>>()
    .expect("traverse adopted owner merge");
    assert_eq!(records.len(), (tribute_count - 1) as usize);

    let bucket_offset = owner_offset
        .checked_add(topology.phase_unit_count(UnitPhase::OwnerShuffle))
        .expect("merge BucketShuffle offset");
    let mut bucket_artifacts = Vec::new();
    for (ordinal, finalized_artifact) in finalized_artifacts.iter().enumerate() {
        let mut producer_ref = cas
            .publish_bytes(
                &finalized_artifact
                    .encode_canonical(&limits)
                    .expect("canonical bucket finalized producer"),
            )
            .expect("publish bucket finalized producer");
        producer_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        let bucket_spec = planner
            .shuffle_unit_at(
                UnitPhase::BucketShuffle,
                u32::try_from(ordinal).expect("merge bucket ordinal"),
                &[finalized_artifact.unit_id],
                &limits,
            )
            .expect("derive merge bucket leaf");
        let artifact = execute_real_worker_unit(
            703 + u64::try_from(ordinal).expect("bucket generation"),
            0xa3 + u8::try_from(ordinal).expect("bucket boot"),
            directory.path(),
            cas_limits,
            &inbox_root,
            inbox_limits,
            limits,
            &bucket_spec,
            bucket_offset + u32::try_from(ordinal).expect("bucket phase ordinal"),
            plan_hash,
            plan_ref.clone(),
            manifest_ref.clone(),
            vec![producer_ref],
        );
        artifact
            .validate_against(&bucket_spec, &limits)
            .expect("validate merge bucket leaf artifact");
        bucket_artifacts.push(artifact);
    }

    let mut bucket_refs = Vec::new();
    for artifact in &bucket_artifacts {
        let mut reference = cas
            .publish_bytes(
                &artifact
                    .encode_canonical(&limits)
                    .expect("canonical bucket merge producer"),
            )
            .expect("publish bucket merge producer");
        reference.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        bucket_refs.push(reference);
    }
    let bucket_merge_spec = planner
        .shuffle_unit_at(
            UnitPhase::BucketShuffle,
            2,
            &[bucket_artifacts[0].unit_id, bucket_artifacts[1].unit_id],
            &limits,
        )
        .expect("derive bucket internal merge");
    let merged_bucket_artifact = execute_real_worker_unit(
        705,
        0xa5,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &bucket_merge_spec,
        bucket_offset + 2,
        plan_hash,
        plan_ref.clone(),
        manifest_ref.clone(),
        bucket_refs,
    );
    merged_bucket_artifact
        .validate_against(&bucket_merge_spec, &limits)
        .expect("validate bucket internal merge artifact");
    let bucket_root = ShuffleRunArtifactV1::decode_canonical(
        merged_bucket_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode bucket internal merge root");
    assert_eq!(bucket_root.kind, ShuffleRunKindV1::Bucket);
    assert_eq!(bucket_root.run_span.start_run, 0);
    assert_eq!(bucket_root.run_span.end_run, 2);
    assert_eq!(bucket_root.source_coverage_count, tribute_count);
    assert_eq!(bucket_root.record_count, tribute_count);

    let adopted_bucket =
        adopt_lysis_shuffle_descendants(bucket_root.clone(), &inbox, &cas, &limits)
            .expect("adopt bucket internal merge closure");
    assert_eq!(adopted_bucket.verified_record_count, tribute_count);
    let bucket_records = verified_shuffle_run_records(bucket_root, &limits, |reference| {
        cas.read_verified(reference)
            .map(|object| object.bytes().to_vec())
            .map_err(|_| {
                outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                    "adopted bucket merge descendant",
                )
            })
    })
    .expect("open adopted bucket merge")
    .collect::<Result<Vec<_>, _>>()
    .expect("traverse adopted bucket merge");
    assert_eq!(bucket_records.len(), tribute_count as usize);

    let mut owner_root_ref = cas
        .publish_bytes(
            &merged_artifact
                .encode_canonical(&limits)
                .expect("canonical merged owner root producer"),
        )
        .expect("publish merged owner root producer");
    owner_root_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let mut bucket_root_ref = cas
        .publish_bytes(
            &merged_bucket_artifact
                .encode_canonical(&limits)
                .expect("canonical merged bucket root producer"),
        )
        .expect("publish merged bucket root producer");
    bucket_root_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
    let root_reduce_offset = bucket_offset
        .checked_add(topology.phase_unit_count(UnitPhase::BucketShuffle))
        .expect("RootReduce offset");
    let mut root_reduce_leaf_artifacts = Vec::new();
    for (ordinal, finalized_artifact) in finalized_artifacts.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).expect("root reduce leaf ordinal");
        let leaf_spec = planner
            .root_reduce_unit_at(
                ordinal,
                &[
                    Some(finalized_artifact.unit_id),
                    Some(merged_artifact.unit_id),
                    Some(merged_bucket_artifact.unit_id),
                ],
                &limits,
            )
            .expect("derive root reduce leaf");
        let mut finalized_ref = cas
            .publish_bytes(
                &finalized_artifact
                    .encode_canonical(&limits)
                    .expect("canonical root reduce finalized producer"),
            )
            .expect("publish root reduce finalized producer");
        finalized_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        let artifact = execute_real_worker_unit(
            707 + u64::from(ordinal),
            0xa7 + u8::try_from(ordinal).expect("root reduce boot"),
            directory.path(),
            cas_limits,
            &inbox_root,
            inbox_limits,
            limits,
            &leaf_spec,
            root_reduce_offset + ordinal,
            plan_hash,
            plan_ref.clone(),
            manifest_ref.clone(),
            vec![
                finalized_ref,
                owner_root_ref.clone(),
                bucket_root_ref.clone(),
            ],
        );
        artifact
            .validate_against(&leaf_spec, &limits)
            .expect("validate real root reduce leaf");
        let RootReduceOutputV1::Leaf {
            summary,
            output_manifest_entry,
        } = decode_root_reduce_output(artifact.phase_payload(&limits).unwrap(), &limits)
            .expect("decode real root reduce leaf")
        else {
            panic!("root reduce primary unit must emit LEAF");
        };
        let expected_count = if ordinal == 0 { 256 } else { 1 };
        let expected_contributor_count = if ordinal == 0 { 256 } else { 0 };
        let expected_tribute_nominal = if ordinal == 0 {
            U256::from(256_u32) * U256::from(257_u32) / U256::from(2)
        } else {
            U256::from(257_u32)
        };
        let expected_eligible_nominal = if ordinal == 0 {
            tribute_nominal_total - U256::from(1)
        } else {
            U256::ZERO
        };
        assert_eq!(summary.tribute_count, expected_count);
        assert_eq!(summary.tribute_nominal_total, expected_tribute_nominal);
        assert_eq!(summary.contributor_count, expected_contributor_count);
        assert_eq!(summary.eligible_nominal_total, expected_eligible_nominal);
        let chunk_object = inbox
            .read_result_chunk(&output_manifest_entry.result_chunk_ref, &limits)
            .expect("read real root reduce ResultChunkV1");
        let chunk = ResultChunkV1::decode_canonical(chunk_object.bytes(), &limits)
            .expect("decode real root reduce ResultChunkV1");
        assert_eq!(chunk.chunk_ordinal, ordinal);
        assert_eq!(chunk.ordered_nod_actions.len(), expected_count as usize);
        assert_eq!(
            chunk.ordered_eligible_contributors.len(),
            expected_contributor_count as usize
        );
        root_reduce_leaf_artifacts.push(artifact);
    }

    let mut root_reduce_leaf_refs = Vec::new();
    for artifact in &root_reduce_leaf_artifacts {
        let mut reference = cas
            .publish_bytes(
                &artifact
                    .encode_canonical(&limits)
                    .expect("canonical root reduce leaf producer"),
            )
            .expect("publish root reduce leaf producer");
        reference.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        root_reduce_leaf_refs.push(reference);
    }
    let root_reduce_spec = planner
        .root_reduce_unit_at(
            2,
            &[
                Some(root_reduce_leaf_artifacts[0].unit_id),
                Some(root_reduce_leaf_artifacts[1].unit_id),
            ],
            &limits,
        )
        .expect("derive internal root reduce unit");
    let root_reduce_artifact = execute_real_worker_unit(
        709,
        0xa9,
        directory.path(),
        cas_limits,
        &inbox_root,
        inbox_limits,
        limits,
        &root_reduce_spec,
        root_reduce_offset + 2,
        plan_hash,
        plan_ref,
        manifest_ref,
        root_reduce_leaf_refs,
    );
    root_reduce_artifact
        .validate_against(&root_reduce_spec, &limits)
        .expect("validate internal RootReduce artifact");
    let reduced = decode_root_reduce_output(
        root_reduce_artifact.phase_payload(&limits).unwrap(),
        &limits,
    )
    .expect("decode internal RootReduce output");
    let RootReduceOutputV1::Node { summary: reduced } = reduced else {
        panic!("internal RootReduce must emit NODE");
    };
    assert_eq!(reduced.covered_primary_count, 2);
    assert_eq!(reduced.tribute_count, tribute_count);
    assert_eq!(reduced.tribute_nominal_total, tribute_nominal_total);
    assert_eq!(reduced.contributor_count, tribute_count - 1);
    assert_eq!(
        reduced.eligible_nominal_total,
        tribute_nominal_total - U256::from(1)
    );
    assert_eq!(reduced.result_chunk_hashes.subtree_height, 1);
}

#[allow(clippy::too_many_arguments)]
fn execute_real_worker_unit(
    generation: u64,
    boot: u8,
    cas_root: &std::path::Path,
    cas_limits: CasLimits,
    inbox_root: &std::path::Path,
    inbox_limits: WorkerInboxLimits,
    limits: SchemaLimits,
    spec: &UnitSpecV1,
    unit_index: u32,
    plan_hash: B256,
    plan_ref: CasObjectRefV1,
    input_manifest_ref: CasObjectRefV1,
    ordered_input_refs: Vec<CasObjectRefV1>,
) -> UnitArtifactV1 {
    let (listener, supervisor_address) = supervisor_listener();
    let worker_identity = identity(boot);
    let mut command = Command::new(env::current_exe().expect("current Rust test binary"));
    command
        .args([
            "--exact",
            "real_worker_processes_execute_through_output_finalize",
            "--nocapture",
        ])
        .env(CHILD_MODE, "1")
        .env(CHILD_CHAIN_ID, worker_identity.chain_id.to_string())
        .env(
            CHILD_GENESIS,
            format!("{:#x}", worker_identity.genesis_hash),
        )
        .env(
            CHILD_BOOT_NONCE,
            format!("{:#x}", worker_identity.boot_nonce),
        )
        .env(
            CHILD_BUNDLE,
            format!("{:#x}", worker_identity.protocol_bundle_hash),
        )
        .env(CHILD_CAS_ROOT, cas_root)
        .env(
            CHILD_CAS_OBJECT_CAP,
            cas_limits.max_object_bytes.to_string(),
        )
        .env(CHILD_CAS_TOTAL_CAP, cas_limits.max_total_bytes.to_string())
        .env(CHILD_INBOX_ROOT, inbox_root)
        .env(CHILD_SUPERVISOR_ADDRESS, supervisor_address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn production worker");
    drop(command);

    let client_identity = EndpointIdentity {
        boot_nonce: B256::repeat_byte(boot.wrapping_add(1)),
        ..worker_identity
    };
    let mut client = accept_registered_worker(&listener, client_identity, generation, limits);
    client
        .dispatch_encoded(
            RunUnitV1 {
                protocol_bundle_hash: spec.protocol_bundle_hash,
                job_id: spec.job_id,
                attempt: spec.attempt,
                plan_hash,
                unit_index,
                canonical_unit_spec: BoundedBytes(
                    spec.encode_canonical(&limits)
                        .expect("canonical worker unit spec"),
                ),
                unit_membership_siblings: Vec::new(),
                plan_ref,
                input_manifest_ref,
                ordered_input_refs,
            }
            .encode_body(&limits)
            .expect("worker RunUnit body"),
        )
        .expect("send worker unit");
    let finished = receive_finished(&mut client, &limits);
    let mut child = child;
    child.kill().expect("stop worker listener");
    let output = child.wait_with_output().expect("reap worker listener");
    assert_eq!(
        finished.status,
        UnitFinishedStatus::Success,
        "worker failed phase {:?} at plan ordinal {unit_index}; stderr={}",
        spec.phase,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        finished.unit_id,
        spec.unit_id(&limits).expect("worker UnitId")
    );
    let inbox = WorkerInbox::open(inbox_root, inbox_limits).expect("open worker inbox");
    UnitArtifactV1::decode_canonical(
        inbox
            .read_reported(
                finished.unit_id,
                finished.exact_staged_bytes,
                finished.transport_digest,
            )
            .expect("read staged worker artifact")
            .bytes(),
        &limits,
    )
    .expect("decode worker artifact")
}

fn run_child_worker() {
    let parse_u64 = |name: &str| {
        env::var(name)
            .unwrap_or_else(|_| panic!("missing {name}"))
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("invalid {name}"))
    };
    let parse_b256 = |name: &str| {
        env::var(name)
            .unwrap_or_else(|_| panic!("missing {name}"))
            .parse::<B256>()
            .unwrap_or_else(|_| panic!("invalid {name}"))
    };
    let limits = poc_schema_limits();
    let expected_bundle_hash = parse_b256(CHILD_BUNDLE);
    let canonical_bundle = support::protocol_bundle()
        .encode_canonical(&limits)
        .expect("canonical child protocol bundle");
    run_worker(WorkerConfig {
        identity: EndpointIdentity {
            chain_id: parse_u64(CHILD_CHAIN_ID),
            genesis_hash: parse_b256(CHILD_GENESIS),
            boot_nonce: parse_b256(CHILD_BOOT_NONCE),
            protocol_bundle_hash: expected_bundle_hash,
        },
        supervisor_address: env::var(CHILD_SUPERVISOR_ADDRESS)
            .expect("worker child Supervisor address")
            .parse()
            .expect("valid worker child Supervisor address"),
        observability_address: "127.0.0.1:0".parse().unwrap(),
        cas_root: PathBuf::from(env::var_os(CHILD_CAS_ROOT).expect("worker child CAS root")),
        cas_limits: CasLimits {
            max_object_bytes: parse_u64(CHILD_CAS_OBJECT_CAP),
            max_total_bytes: parse_u64(CHILD_CAS_TOTAL_CAP),
        },
        inbox_root: PathBuf::from(env::var_os(CHILD_INBOX_ROOT).expect("worker child inbox root")),
        inbox_limits: WorkerInboxLimits {
            max_artifact_bytes: 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024,
        },
        protocol_bundle: PinnedProtocolBundle::decode(
            &canonical_bundle,
            expected_bundle_hash,
            &limits,
        )
        .expect("pin child protocol bundle"),
    })
    .expect("production worker function");
}
