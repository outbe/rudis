//! Node-owned assembly of the existing OCOMP Supervisor compute path.
//!
//! Canonical-chain observation remains with `outbe-chain`. This module owns
//! only local capabilities: the Worker endpoint, export adoption, deterministic
//! runner, immutable local result store and (Validator-only) vote submission.

use std::{
    fs::DirBuilder,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, MutexGuard,
    },
    thread,
    time::Duration,
};

#[cfg(feature = "test-protocol-overrides")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
};

use alloy_primitives::B256;
use outbe_node::ocomp::local_result::{
    CommittedLocalLysisResultV1, LoadedLocalLysisResultV1, LocalLysisResultStore,
};
use outbe_ocomp_protocol::{local_control::EndpointIdentity, result::LysisResultV1, SchemaLimits};
use outbe_primitives::signer::OutbeEvmSigner;
use thiserror::Error;

use crate::embedded::EmbeddedJobGenerationV1;
use crate::{
    admission_catalog::VerifiedAdmissionCatalog,
    bundle::PinnedProtocolBundle,
    cas::{CasLimits, FilesystemCasReader},
    control::effective_uid,
    inbox::WorkerInboxLimits,
    input_artifacts::poc_input_list_limits,
    input_ref_catalog::VerifiedInputChunkRefCatalog,
    lysis_plan_audit::LocalLysisPlanAuditV1,
    nod_materialization::{
        build_nod_materialization_batch_with_references, MaterializationReferenceStoreV1,
    },
    nod_materialization_submitter::{
        reconcile_finalized_materialization_references, NodMaterializationSubmissionConfigV1,
        NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmitterV1,
    },
    payout_submitter::{
        LocalPayoutTransactionPreparerV1, PayoutSubmissionConfigV1, PayoutTickOutcomeV1,
        SupervisorPayoutSubmitterV1,
    },
    result_attestation::LocalResultVoteAttesterV1,
    result_signer::OcompSigner,
    sign_once::SignOnceStore,
    supervisor::DiscoveryRecord,
    supervisor_export::{
        SupervisorExportAdoption, SupervisorExportAdoptionConfig, SupervisorExportAdoptionOutcome,
    },
    supervisor_job::{
        CompletedSupervisorJobV1, SupervisorJobFailureClassV1, SupervisorJobRunnerConfigV1,
        SupervisorJobRunnerV1,
    },
    vote_submitter::{
        LocalVoteTransactionPreparerV1, PublicVoteRpcClientV1, SupervisorVoteSubmitterV1,
        VoteSubmissionConfigV1, VoteSubmissionFailureClassV1, VoteSubmissionOutcomeV1,
    },
    worker_transport::SupervisorWorkerServerV1,
};

const CAS_MAX_OBJECT_BYTES: u64 = 1_048_576;
const WORKER_INBOX_MAX_ARTIFACT_BYTES: u64 = 1_048_576;
const WORKER_INBOX_MAX_TOTAL_BYTES: u64 = 67_108_864;
const RPC_MAX_RESPONSE_BYTES: usize = 33_554_432;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "test-protocol-overrides")]
const TEST_MISMATCH_CLAIM_MAGIC: [u8; 8] = *b"OCMMISV1";
#[cfg(feature = "test-protocol-overrides")]
const TEST_MISMATCH_CLAIM_BYTES: usize = TEST_MISMATCH_CLAIM_MAGIC.len() + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedNodePolicyV1 {
    Validator,
    FullNode,
}

#[derive(Clone, Debug)]
pub struct EmbeddedOcompDomainConfigV1 {
    pub domain_root: PathBuf,
    pub registry_generation: u64,
    pub bundles: Vec<EmbeddedOcompBundleConfigV1>,
    pub policy: EmbeddedNodePolicyV1,
    /// Required only for Validator policy. FullNode never opens this URL for
    /// vote submission and never loads either signing key.
    pub validator_rpc_url: Option<String>,
    pub limits: SchemaLimits,
}

#[derive(Clone, Debug)]
pub struct EmbeddedOcompBundleConfigV1 {
    pub worker_address: std::net::SocketAddr,
    pub identity: EndpointIdentity,
    pub protocol_bundle: PinnedProtocolBundle,
}

#[derive(Clone, Debug)]
struct EmbeddedOcompLayoutV1 {
    supervisor_root: PathBuf,
    exporter_root: PathBuf,
    node_root: PathBuf,
    cas_root: PathBuf,
    worker_inbox_root: PathBuf,
    input_ref_root: PathBuf,
    receipt_root: PathBuf,
    binding_root: PathBuf,
    job_root: PathBuf,
    local_result_root: PathBuf,
    vote_submission_root: PathBuf,
    payout_submission_root: PathBuf,
    materialization_reference_root: PathBuf,
    materialization_submission_root: PathBuf,
    sign_once_root: PathBuf,
    evm_key_path: PathBuf,
    result_key_path: PathBuf,
    checkpoint_root: PathBuf,
    fatal_evidence_root: PathBuf,
}

impl EmbeddedOcompLayoutV1 {
    fn from_root(root: &Path) -> Result<Self, EmbeddedOcompRuntimeErrorV1> {
        if !root.is_absolute() || root.parent().is_none() || root == Path::new("/") {
            return Err(EmbeddedOcompRuntimeErrorV1::InvalidDomainRoot);
        }
        let supervisor = root.join("supervisor-v1");
        let exporter = root.join("exporter-v1");
        let node = root.join("node-v1");
        Ok(Self {
            supervisor_root: supervisor.clone(),
            exporter_root: exporter.clone(),
            node_root: node.clone(),
            cas_root: root.join("cas-v1"),
            worker_inbox_root: root.join("worker-inbox-v1"),
            input_ref_root: exporter.join("input-refs"),
            receipt_root: exporter.join("receipts"),
            binding_root: supervisor.join("export-bindings"),
            job_root: supervisor.join("jobs"),
            local_result_root: node.join("local-results"),
            vote_submission_root: supervisor.join("vote-submissions"),
            payout_submission_root: supervisor.join("payout-submissions"),
            materialization_reference_root: supervisor.join("materialization-references"),
            materialization_submission_root: supervisor.join("materialization-submissions"),
            sign_once_root: supervisor.join("sign-once"),
            evm_key_path: root.join("ocomp-evm-key.hex"),
            result_key_path: root.join("ocomp-key-v1.hex"),
            checkpoint_root: node.join("exex-checkpoint"),
            fatal_evidence_root: node.join("fatal-evidence"),
        })
    }
}

struct ValidatorOcompPolicyV1 {
    preparer: Arc<LocalVoteTransactionPreparerV1>,
    materialization_signer: OutbeEvmSigner,
    submission_gate: Arc<ValidatorOcompSubmissionGateV1>,
    ocomp_key_hash: B256,
    rpc_url: String,
    journal_root: PathBuf,
    payout_journal_root: PathBuf,
    materialization_reference_root: PathBuf,
    materialization_submission_root: PathBuf,
    cas_root: PathBuf,
    cas_limits: CasLimits,
    input_ref_root: PathBuf,
    job_root: PathBuf,
    protocol_bundle: PinnedProtocolBundle,
    chain_id: u64,
    sender_address: alloy_primitives::Address,
    limits: SchemaLimits,
}

#[derive(Default)]
struct ValidatorOcompSubmissionGateV1(Mutex<()>);

impl ValidatorOcompSubmissionGateV1 {
    fn acquire(&self) -> Result<MutexGuard<'_, ()>, EmbeddedOcompRuntimeErrorV1> {
        self.0
            .lock()
            .map_err(|_| EmbeddedOcompRuntimeErrorV1::Stage {
                name: "lock Validator OCOMP vote submission",
                detail: "vote submission gate is poisoned".to_owned(),
            })
    }
}

struct EmbeddedOcompBundleLaneV1 {
    _worker_server: SupervisorWorkerServerV1,
    runner: Arc<SupervisorJobRunnerV1>,
    adoption: SupervisorExportAdoptionConfig,
    validator_ocomp: Option<ValidatorOcompPolicyV1>,
}

pub struct EmbeddedOcompDomainV1 {
    lanes: std::collections::BTreeMap<B256, EmbeddedOcompBundleLaneV1>,
    local_results: Arc<LocalLysisResultStore>,
    checkpoint_root: PathBuf,
    fatal_evidence_root: PathBuf,
    #[cfg(feature = "test-protocol-overrides")]
    local_result_mismatch_marker: PathBuf,
}

impl EmbeddedOcompDomainV1 {
    pub fn open(config: EmbeddedOcompDomainConfigV1) -> Result<Self, EmbeddedOcompRuntimeErrorV1> {
        if config.registry_generation == 0 || config.bundles.is_empty() {
            return Err(EmbeddedOcompRuntimeErrorV1::InvalidConfig);
        }
        #[cfg(feature = "test-protocol-overrides")]
        let local_result_mismatch_marker = config
            .domain_root
            .join("test-faults")
            .join("local-result-mismatch.once");
        let layout = EmbeddedOcompLayoutV1::from_root(&config.domain_root)?;
        for private_root in [
            &layout.node_root,
            &layout.supervisor_root,
            &layout.exporter_root,
        ] {
            let mut root_builder = DirBuilder::new();
            root_builder
                .recursive(true)
                .mode(0o700)
                .create(private_root)
                .map_err(|error| stage("create embedded OCOMP private root", error))?;
        }
        let cas_limits = CasLimits {
            max_object_bytes: CAS_MAX_OBJECT_BYTES,
            // CAS is disk-backed and chunked. Capacity is governed by the
            // filesystem/operator, never by a product-level total-job cap.
            max_total_bytes: u64::MAX,
        };
        let local_results = Arc::new(
            LocalLysisResultStore::open(&layout.local_result_root, config.limits)
                .map_err(|error| stage("open embedded OCOMP local result store", error))?,
        );
        if config.policy == EmbeddedNodePolicyV1::FullNode && config.validator_rpc_url.is_some() {
            return Err(EmbeddedOcompRuntimeErrorV1::FullNodeVoteAuthority);
        }
        let submission_gate = Arc::new(ValidatorOcompSubmissionGateV1::default());
        let mut lanes = std::collections::BTreeMap::new();
        let mut worker_addresses = std::collections::BTreeSet::new();
        let mut expected_identity = None;
        let mut expected_key_hash = None;
        for bundle_config in config.bundles {
            if !bundle_config.worker_address.ip().is_loopback()
                || (bundle_config.worker_address.port() != 0
                    && !worker_addresses.insert(bundle_config.worker_address))
                || bundle_config.identity.protocol_bundle_hash
                    != bundle_config.protocol_bundle.hash()
            {
                return Err(EmbeddedOcompRuntimeErrorV1::InvalidConfig);
            }
            let identity_pair = (
                bundle_config.identity.chain_id,
                bundle_config.identity.genesis_hash,
            );
            if expected_identity
                .replace(identity_pair)
                .is_some_and(|expected| expected != identity_pair)
            {
                return Err(EmbeddedOcompRuntimeErrorV1::InvalidConfig);
            }
            let bundle_hash = bundle_config.protocol_bundle.hash();
            let worker_server = SupervisorWorkerServerV1::start(
                bundle_config.worker_address,
                bundle_config.identity,
                config.registry_generation,
                config.limits,
            )
            .map_err(|error| stage("start Node-owned OCOMP Worker endpoint", error))?;
            let runner = Arc::new(
                SupervisorJobRunnerV1::open(
                    SupervisorJobRunnerConfigV1 {
                        cas_root: layout.cas_root.clone(),
                        cas_limits,
                        input_ref_root: layout.input_ref_root.clone(),
                        job_root: layout.job_root.clone(),
                        worker_inbox_root: layout
                            .worker_inbox_root
                            .join(hex::encode(bundle_hash.as_slice())),
                        worker_inbox_limits: WorkerInboxLimits {
                            max_artifact_bytes: WORKER_INBOX_MAX_ARTIFACT_BYTES,
                            max_total_bytes: WORKER_INBOX_MAX_TOTAL_BYTES,
                        },
                        protocol_bundle: bundle_config.protocol_bundle.clone(),
                        limits: config.limits,
                    },
                    worker_server.dispatcher(),
                )
                .map_err(|error| stage("open embedded OCOMP runner", error))?,
            );
            let adoption = SupervisorExportAdoptionConfig {
                cas_root: layout.cas_root.clone(),
                cas_limits,
                input_ref_root: layout.input_ref_root.clone(),
                receipt_root: layout.receipt_root.clone(),
                binding_root: layout.binding_root.clone(),
                protocol_bundle: bundle_config.protocol_bundle.clone(),
                limits: config.limits,
            };
            let validator_ocomp = match config.policy {
                EmbeddedNodePolicyV1::FullNode => None,
                EmbeddedNodePolicyV1::Validator => {
                    reconcile_finalized_materialization_references(
                        &layout.materialization_submission_root,
                        &layout.materialization_reference_root,
                    )
                    .map_err(|error| {
                        stage("reconcile finalized NOD materialization references", error)
                    })?;
                    let rpc_url = config
                        .validator_rpc_url
                        .clone()
                        .ok_or(EmbeddedOcompRuntimeErrorV1::MissingValidatorRpc)?;
                    let owner_uid = effective_uid()
                        .map_err(|error| stage("resolve Node effective uid", error))?;
                    let evm_signer =
                        OutbeEvmSigner::from_strict_file(&layout.evm_key_path, owner_uid)
                            .map_err(|error| stage("open Validator OCOMP EVM key", error))?;
                    let result_signer = OcompSigner::from_file(&layout.result_key_path, owner_uid)
                        .map_err(|error| stage("open Validator OCOMP result key", error))?;
                    let sign_once = SignOnceStore::open(
                        layout.sign_once_root.clone(),
                        owner_uid,
                        config.limits,
                    )
                    .map_err(|error| stage("open Validator OCOMP sign-once store", error))?;
                    let attester = LocalResultVoteAttesterV1::new(
                        bundle_config.identity,
                        bundle_config.protocol_bundle.bundle().fork_id,
                        result_signer,
                        sign_once,
                        config.limits,
                    )
                    .map_err(|error| stage("open Validator OCOMP result attester", error))?;
                    let ocomp_key_hash = attester.ocomp_key_hash();
                    if expected_key_hash
                        .replace(ocomp_key_hash)
                        .is_some_and(|expected| expected != ocomp_key_hash)
                    {
                        return Err(EmbeddedOcompRuntimeErrorV1::InvalidConfig);
                    }
                    let preparer = Arc::new(
                        LocalVoteTransactionPreparerV1::new(
                            evm_signer.clone(),
                            attester,
                            bundle_config.identity.chain_id,
                            config.limits,
                        )
                        .map_err(|error| stage("open Validator OCOMP vote preparer", error))?,
                    );
                    Some(ValidatorOcompPolicyV1 {
                        sender_address: preparer.sender_address(),
                        preparer,
                        materialization_signer: evm_signer,
                        submission_gate: Arc::clone(&submission_gate),
                        ocomp_key_hash,
                        rpc_url,
                        journal_root: layout.vote_submission_root.clone(),
                        payout_journal_root: layout.payout_submission_root.clone(),
                        materialization_reference_root: layout
                            .materialization_reference_root
                            .clone(),
                        materialization_submission_root: layout
                            .materialization_submission_root
                            .clone(),
                        cas_root: layout.cas_root.clone(),
                        cas_limits,
                        input_ref_root: layout.input_ref_root.clone(),
                        job_root: layout.job_root.clone(),
                        protocol_bundle: bundle_config.protocol_bundle.clone(),
                        chain_id: bundle_config.identity.chain_id,
                        limits: config.limits,
                    })
                }
            };
            if lanes
                .insert(
                    bundle_hash,
                    EmbeddedOcompBundleLaneV1 {
                        _worker_server: worker_server,
                        runner,
                        adoption,
                        validator_ocomp,
                    },
                )
                .is_some()
            {
                return Err(EmbeddedOcompRuntimeErrorV1::InvalidConfig);
            }
        }
        Ok(Self {
            lanes,
            local_results,
            checkpoint_root: layout.checkpoint_root,
            fatal_evidence_root: layout.fatal_evidence_root,
            #[cfg(feature = "test-protocol-overrides")]
            local_result_mismatch_marker,
        })
    }

    #[must_use]
    pub fn checkpoint_root(&self) -> &Path {
        &self.checkpoint_root
    }

    #[must_use]
    pub fn fatal_evidence_root(&self) -> &Path {
        &self.fatal_evidence_root
    }

    #[must_use]
    pub fn validator_ocomp_key_hash(&self) -> Option<B256> {
        self.lanes
            .values()
            .find_map(|lane| lane.validator_ocomp.as_ref())
            .map(|policy| policy.ocomp_key_hash)
    }

    #[must_use]
    pub fn validator_sender_address(&self) -> Option<alloy_primitives::Address> {
        self.lanes
            .values()
            .find_map(|lane| lane.validator_ocomp.as_ref())
            .map(|policy| policy.sender_address)
    }

    #[must_use]
    pub fn installed_bundle_hashes(&self) -> Vec<B256> {
        self.lanes.keys().copied().collect()
    }

    pub fn commit_local_result(
        &self,
        completed: &CompletedSupervisorJobV1,
    ) -> Result<CommittedLocalLysisResultV1, EmbeddedOcompRuntimeErrorV1> {
        self.local_results
            .commit(completed.job_id, &completed.canonical_result)
            .map_err(|error| stage("commit embedded OCOMP local result", error))
    }

    pub fn load_local_result(
        &self,
        job_id: B256,
    ) -> Result<Option<LoadedLocalLysisResultV1>, EmbeddedOcompRuntimeErrorV1> {
        self.local_results
            .load(job_id)
            .map_err(|error| stage("load embedded OCOMP local result", error))
    }

    pub fn verify_exact_canonical_result(
        &self,
        job_id: B256,
        canonical: &LysisResultV1,
    ) -> Result<CommittedLocalLysisResultV1, EmbeddedOcompRuntimeErrorV1> {
        self.local_results
            .verify_exact(job_id, canonical)
            .map_err(|error| stage("verify exact FullNode OCOMP result", error))
    }

    pub fn spawn_compute(
        &self,
        record: DiscoveryRecord,
        generation: EmbeddedJobGenerationV1,
        cancelled: Arc<AtomicBool>,
        sender: mpsc::Sender<EmbeddedComputeOutcomeV1>,
    ) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
        let bundle_hash = record.spec.summary.protocol_bundle_hash;
        let lane =
            self.lanes
                .get(&bundle_hash)
                .ok_or_else(|| EmbeddedOcompRuntimeErrorV1::Stage {
                    name: "select pinned OCOMP bundle lane",
                    detail: format!("bundle {bundle_hash:#x} is not installed"),
                })?;
        let runner = Arc::clone(&lane.runner);
        let adoption_config = lane.adoption.clone();
        #[cfg(feature = "test-protocol-overrides")]
        let local_result_mismatch_marker = self.local_result_mismatch_marker.clone();
        #[cfg(feature = "test-protocol-overrides")]
        let mismatch_limits = lane.adoption.limits;
        let job_id = record.spec.summary.job_id;
        thread::Builder::new()
            .name(format!("ocomp-job-{}", short_job(job_id)))
            .spawn(move || loop {
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let adoption = match SupervisorExportAdoption::open(adoption_config.clone()) {
                    Ok(adoption) => adoption,
                    Err(error) => {
                        let _ = sender.send(EmbeddedComputeOutcomeV1::Unrecoverable {
                            job_id,
                            generation,
                            detail: error.to_string(),
                        });
                        return;
                    }
                };
                match adoption.try_adopt(&record) {
                    Ok(SupervisorExportAdoptionOutcome::Pending) => {
                        thread::sleep(RETRY_INTERVAL);
                    }
                    Ok(SupervisorExportAdoptionOutcome::Adopted(binding)) => {
                        match runner.run_to_result(&record, &binding, &cancelled) {
                            Ok(completed) => {
                                #[cfg(feature = "test-protocol-overrides")]
                                let completed = match inject_local_result_mismatch_once(
                                    &local_result_mismatch_marker,
                                    completed.job_id,
                                    &completed.canonical_result,
                                    &mismatch_limits,
                                ) {
                                    Ok(canonical_result) => CompletedSupervisorJobV1 {
                                        canonical_result,
                                        ..completed
                                    },
                                    Err(error) => {
                                        let _ =
                                            sender.send(EmbeddedComputeOutcomeV1::Unrecoverable {
                                                job_id,
                                                generation,
                                                detail: error.to_string(),
                                            });
                                        return;
                                    }
                                };
                                let _ = sender.send(EmbeddedComputeOutcomeV1::Completed {
                                    generation,
                                    completed,
                                });
                                return;
                            }
                            Err(error)
                                if error.class() == SupervisorJobFailureClassV1::Retryable =>
                            {
                                thread::sleep(RETRY_INTERVAL);
                            }
                            Err(error) => {
                                let _ = sender.send(EmbeddedComputeOutcomeV1::Unrecoverable {
                                    job_id,
                                    generation,
                                    detail: error.to_string(),
                                });
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(EmbeddedComputeOutcomeV1::Unrecoverable {
                            job_id,
                            generation,
                            detail: error.to_string(),
                        });
                        return;
                    }
                }
            })
            .map_err(|error| stage("spawn embedded OCOMP compute thread", error))?;
        Ok(())
    }

    /// Drives one payout tick over `days`; without it a node-embedded domain
    /// certifies contributors that nobody ever pays.
    pub fn spawn_validator_payout(
        &self,
        days: Vec<u32>,
        cancelled: Arc<AtomicBool>,
        sender: mpsc::Sender<EmbeddedPayoutOutcomeV1>,
    ) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
        let policy = self
            .lanes
            .values()
            .find_map(|lane| lane.validator_ocomp.as_ref())
            .ok_or(EmbeddedOcompRuntimeErrorV1::FullNodeVoteAuthority)?;
        let signer = policy.materialization_signer.clone();
        let submission_gate = Arc::clone(&policy.submission_gate);
        let rpc_url = policy.rpc_url.clone();
        let config = PayoutSubmissionConfigV1 {
            journal_root: policy.payout_journal_root.clone(),
            job_root: policy.job_root.clone(),
            expected_chain_id: policy.chain_id,
            sender_address: policy.sender_address,
            limits: policy.limits,
        };
        thread::Builder::new()
            .name("ocomp-payout".to_owned())
            .spawn(move || {
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let _submission_permit = match submission_gate.acquire() {
                    Ok(permit) => permit,
                    Err(error) => {
                        let _ = sender.send(EmbeddedPayoutOutcomeV1::Failed(error.to_string()));
                        return;
                    }
                };
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let preparer =
                    match LocalPayoutTransactionPreparerV1::new(signer, config.expected_chain_id) {
                        Ok(preparer) => preparer,
                        Err(error) => {
                            let _ = sender.send(EmbeddedPayoutOutcomeV1::Failed(error.to_string()));
                            return;
                        }
                    };
                let rpc = match PublicVoteRpcClientV1::new(rpc_url, RPC_MAX_RESPONSE_BYTES) {
                    Ok(rpc) => rpc,
                    Err(error) => {
                        let _ = sender.send(EmbeddedPayoutOutcomeV1::Failed(error.to_string()));
                        return;
                    }
                };
                let mut submitter = match SupervisorPayoutSubmitterV1::open(config, rpc) {
                    Ok(submitter) => submitter,
                    Err(error) => {
                        let _ = sender.send(EmbeddedPayoutOutcomeV1::Failed(error.to_string()));
                        return;
                    }
                };
                let outcome = match submitter.tick(&preparer, &days) {
                    Ok(outcome) => EmbeddedPayoutOutcomeV1::Ticked(outcome),
                    Err(error) => EmbeddedPayoutOutcomeV1::Failed(error.to_string()),
                };
                let _ = sender.send(outcome);
            })
            .map_err(|error| stage("spawn embedded OCOMP payout thread", error))?;
        Ok(())
    }

    pub fn spawn_validator_vote(
        &self,
        record: DiscoveryRecord,
        generation: EmbeddedJobGenerationV1,
        result_digest: B256,
        canonical_result: Vec<u8>,
        cancelled: Arc<AtomicBool>,
        sender: mpsc::Sender<EmbeddedVoteOutcomeV1>,
    ) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
        let job_id = record.spec.summary.job_id;
        let policy = self
            .lanes
            .get(&record.spec.summary.protocol_bundle_hash)
            .and_then(|lane| lane.validator_ocomp.as_ref())
            .ok_or(EmbeddedOcompRuntimeErrorV1::FullNodeVoteAuthority)?;
        let preparer = Arc::clone(&policy.preparer);
        let submission_gate = Arc::clone(&policy.submission_gate);
        let rpc_url = policy.rpc_url.clone();
        let config = VoteSubmissionConfigV1 {
            journal_root: policy.journal_root.join(hex::encode(job_id.as_slice())),
            expected_chain_id: policy.chain_id,
            sender_address: policy.sender_address,
            limits: policy.limits,
        };
        thread::Builder::new()
            .name(format!("ocomp-vote-{}", short_job(job_id)))
            .spawn(move || {
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let _submission_permit = match submission_gate.acquire() {
                    Ok(permit) => permit,
                    Err(error) => {
                        let _ = sender.send(EmbeddedVoteOutcomeV1::Unrecoverable {
                            job_id,
                            generation,
                            detail: error.to_string(),
                        });
                        return;
                    }
                };
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let rpc = match PublicVoteRpcClientV1::new(rpc_url, RPC_MAX_RESPONSE_BYTES) {
                    Ok(rpc) => rpc,
                    Err(error) => {
                        let _ = sender.send(EmbeddedVoteOutcomeV1::Unrecoverable {
                            job_id,
                            generation,
                            detail: error.to_string(),
                        });
                        return;
                    }
                };
                let mut submitter = match SupervisorVoteSubmitterV1::open(config, rpc) {
                    Ok(submitter) => submitter,
                    Err(error) => {
                        let _ = sender.send(EmbeddedVoteOutcomeV1::Unrecoverable {
                            job_id,
                            generation,
                            detail: error.to_string(),
                        });
                        return;
                    }
                };
                while !cancelled.load(Ordering::Acquire) {
                    match submitter.reconcile(
                        preparer.as_ref(),
                        job_id,
                        result_digest,
                        &canonical_result,
                        &record.spec,
                    ) {
                        Ok(VoteSubmissionOutcomeV1::Finalized(inclusion)) => {
                            let _ = sender.send(EmbeddedVoteOutcomeV1::Finalized {
                                job_id,
                                generation,
                                success: inclusion.success,
                            });
                            return;
                        }
                        Ok(_) => thread::sleep(RETRY_INTERVAL),
                        Err(error) if error.class() == VoteSubmissionFailureClassV1::Retryable => {
                            metrics::counter!(
                                "outbe_ocomp_vote_submission_failures_total",
                                "class" => "retryable"
                            )
                            .increment(1);
                            thread::sleep(RETRY_INTERVAL);
                        }
                        Err(error) => {
                            metrics::counter!(
                                "outbe_ocomp_vote_submission_failures_total",
                                "class" => "unrecoverable"
                            )
                            .increment(1);
                            let _ = sender.send(EmbeddedVoteOutcomeV1::Unrecoverable {
                                job_id,
                                generation,
                                detail: error.to_string(),
                            });
                            return;
                        }
                    }
                }
            })
            .map_err(|error| stage("spawn embedded OCOMP vote thread", error))?;
        Ok(())
    }

    pub fn spawn_validator_materialization(
        &self,
        protocol_bundle_hash: B256,
        head: outbe_ocomp_protocol::nod_materialization::NodMaterializationHeadV1,
        batch_subtree_height: u8,
        sender: mpsc::Sender<EmbeddedMaterializationOutcomeV1>,
    ) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
        let policy = self
            .lanes
            .get(&protocol_bundle_hash)
            .and_then(|lane| lane.validator_ocomp.as_ref())
            .ok_or(EmbeddedOcompRuntimeErrorV1::FullNodeVoteAuthority)?;
        let job_id = head.job_id;
        let first_nod_ordinal = head.next_nod_ordinal;
        let queue_sequence = head.queue_sequence;
        let submission_gate = Arc::clone(&policy.submission_gate);
        let rpc_url = policy.rpc_url.clone();
        let signer = policy.materialization_signer.clone();
        let sender_address = policy.sender_address;
        let chain_id = policy.chain_id;
        let limits = policy.limits;
        let cas_root = policy.cas_root.clone();
        let cas_limits = policy.cas_limits;
        let input_ref_root = policy.input_ref_root.clone();
        let job_root = policy.job_root.clone();
        let bundle = policy.protocol_bundle.clone();
        let reference_root = policy
            .materialization_reference_root
            .join(hex::encode(job_id.as_slice()))
            .join(first_nod_ordinal.to_string());
        let submission_root = policy
            .materialization_submission_root
            .join(hex::encode(job_id.as_slice()))
            .join(first_nod_ordinal.to_string());
        thread::Builder::new()
            .name(format!("ocomp-nod-{}", short_job(job_id)))
            .spawn(move || {
                let run = || -> Result<bool, EmbeddedOcompRuntimeErrorV1> {
                    let _submission_permit = submission_gate.acquire()?;
                    let reader = FilesystemCasReader::open(&cas_root, cas_limits)
                        .map_err(|error| stage("open NOD materialization CAS", error))?;
                    let job_component = hex::encode(job_id.as_slice());
                    let input_refs = VerifiedInputChunkRefCatalog::reopen(
                        input_ref_root.join(&job_component),
                        &reader,
                        limits,
                        poc_input_list_limits(),
                    )
                    .map_err(|error| stage("open NOD materialization inputs", error))?;
                    let admissions = VerifiedAdmissionCatalog::reopen(
                        job_root.join(&job_component).join("admissions"),
                        &reader,
                        limits,
                    )
                    .map_err(|error| stage("open NOD materialization admissions", error))?;
                    let audit = LocalLysisPlanAuditV1::open(
                        &admissions,
                        &input_refs,
                        &reader,
                        &bundle,
                        &limits,
                    )
                    .map_err(|error| stage("audit NOD materialization plan", error))?;
                    let built = build_nod_materialization_batch_with_references(
                        &audit,
                        &head,
                        batch_subtree_height,
                    )
                    .map_err(|error| stage("build NOD materialization batch", error))?;
                    let references = MaterializationReferenceStoreV1::open(&reference_root)
                        .map_err(|error| stage("open NOD materialization references", error))?;
                    references
                        .pin_exact(job_id, &built.dependencies)
                        .map_err(|error| stage("pin NOD materialization references", error))?;
                    let rpc = PublicVoteRpcClientV1::new(rpc_url, RPC_MAX_RESPONSE_BYTES)
                        .map_err(|error| stage("open NOD materialization RPC", error))?;
                    let mut submitter = NodMaterializationSubmitterV1::open(
                        NodMaterializationSubmissionConfigV1 {
                            journal_root: submission_root,
                            expected_chain_id: chain_id,
                            sender_address,
                            limits,
                        },
                        rpc,
                        signer,
                    )
                    .map_err(|error| stage("open NOD materialization submitter", error))?;
                    loop {
                        match submitter.reconcile(job_id, &built.batch) {
                            Ok(NodMaterializationSubmissionOutcomeV1::Pending) => {
                                thread::sleep(RETRY_INTERVAL);
                            }
                            Ok(NodMaterializationSubmissionOutcomeV1::Finalized { success }) => {
                                references.release(job_id).map_err(|error| {
                                    stage("release NOD materialization references", error)
                                })?;
                                return Ok(success);
                            }
                            Err(_error) => {
                                thread::sleep(RETRY_INTERVAL);
                            }
                        }
                    }
                };
                let outcome = match run() {
                    Ok(success) => EmbeddedMaterializationOutcomeV1::Finalized {
                        job_id,
                        queue_sequence,
                        first_nod_ordinal,
                        success,
                    },
                    Err(error) => EmbeddedMaterializationOutcomeV1::Unavailable {
                        job_id,
                        queue_sequence,
                        first_nod_ordinal,
                        detail: error.to_string(),
                    },
                };
                let _ = sender.send(outcome);
            })
            .map_err(|error| stage("spawn embedded NOD materialization thread", error))?;
        Ok(())
    }
}

#[cfg(feature = "test-protocol-overrides")]
fn inject_local_result_mismatch_once(
    marker: &Path,
    job_id: B256,
    canonical_result: &[u8],
    limits: &SchemaLimits,
) -> Result<Vec<u8>, EmbeddedOcompRuntimeErrorV1> {
    let temp = marker.with_extension("once.tmp");
    if temp
        .try_exists()
        .map_err(|error| stage("inspect OCOMP mismatch marker temp", error))?
    {
        let recovered = read_mismatch_claim(&temp)?;
        fs::rename(&temp, marker)
            .map_err(|error| stage("recover OCOMP mismatch marker claim", error))?;
        sync_test_fault_directory(marker)?;
        if recovered != job_id {
            return Ok(canonical_result.to_vec());
        }
    }
    if !marker
        .try_exists()
        .map_err(|error| stage("inspect OCOMP mismatch marker", error))?
    {
        return Ok(canonical_result.to_vec());
    }

    let state = read_bounded_test_marker(marker)?;
    let claimed = if state.is_empty() {
        persist_mismatch_claim(marker, job_id)?;
        job_id
    } else {
        decode_mismatch_claim(&state)?
    };
    if claimed != job_id {
        return Ok(canonical_result.to_vec());
    }

    let mut result = LysisResultV1::decode_canonical(canonical_result, limits)
        .map_err(|error| stage("decode OCOMP mismatch test result", error))?;
    if result.job_id != job_id {
        return Err(stage(
            "inject OCOMP mismatch test result",
            "canonical result JobId changed",
        ));
    }
    let mut preimage = Vec::with_capacity(32 + 32 + 31);
    preimage.extend_from_slice(b"OUTBE_OCOMP_TEST_MISMATCH_V1");
    preimage.extend_from_slice(job_id.as_slice());
    preimage.extend_from_slice(result.result_chunk_list_root.as_slice());
    let replacement = alloy_primitives::keccak256(preimage);
    if replacement.is_zero() || replacement == result.result_chunk_list_root {
        return Err(stage(
            "inject OCOMP mismatch test result",
            "derived result chunk root is not distinct",
        ));
    }
    result.result_chunk_list_root = replacement;
    result
        .result_digest(limits)
        .map_err(|error| stage("validate OCOMP mismatch test result", error))?;
    result
        .encode_canonical(limits)
        .map_err(|error| stage("encode OCOMP mismatch test result", error))
}

#[cfg(feature = "test-protocol-overrides")]
fn persist_mismatch_claim(marker: &Path, job_id: B256) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
    let temp = marker.with_extension("once.tmp");
    let parent = marker.parent().ok_or_else(|| {
        stage(
            "persist OCOMP mismatch marker claim",
            "marker has no parent directory",
        )
    })?;
    let mut claim = Vec::with_capacity(TEST_MISMATCH_CLAIM_BYTES);
    claim.extend_from_slice(&TEST_MISMATCH_CLAIM_MAGIC);
    claim.extend_from_slice(job_id.as_slice());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|error| stage("create OCOMP mismatch marker claim", error))?;
    file.write_all(&claim)
        .map_err(|error| stage("write OCOMP mismatch marker claim", error))?;
    file.sync_all()
        .map_err(|error| stage("fsync OCOMP mismatch marker claim", error))?;
    fs::rename(&temp, marker)
        .map_err(|error| stage("publish OCOMP mismatch marker claim", error))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| stage("fsync OCOMP mismatch marker directory", error))
}

#[cfg(feature = "test-protocol-overrides")]
fn read_mismatch_claim(path: &Path) -> Result<B256, EmbeddedOcompRuntimeErrorV1> {
    decode_mismatch_claim(&read_bounded_test_marker(path)?)
}

#[cfg(feature = "test-protocol-overrides")]
fn read_bounded_test_marker(path: &Path) -> Result<Vec<u8>, EmbeddedOcompRuntimeErrorV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| stage("open OCOMP mismatch marker", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| stage("inspect OCOMP mismatch marker", error))?;
    if !metadata.file_type().is_file() || metadata.len() > TEST_MISMATCH_CLAIM_BYTES as u64 {
        return Err(stage(
            "inspect OCOMP mismatch marker",
            "marker is not one bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| stage("read OCOMP mismatch marker", error))?;
    Ok(bytes)
}

#[cfg(feature = "test-protocol-overrides")]
fn decode_mismatch_claim(bytes: &[u8]) -> Result<B256, EmbeddedOcompRuntimeErrorV1> {
    if bytes.len() != TEST_MISMATCH_CLAIM_BYTES || bytes[..8] != TEST_MISMATCH_CLAIM_MAGIC {
        return Err(stage(
            "decode OCOMP mismatch marker claim",
            "invalid claim bytes",
        ));
    }
    Ok(B256::from_slice(&bytes[8..]))
}

#[cfg(feature = "test-protocol-overrides")]
fn sync_test_fault_directory(marker: &Path) -> Result<(), EmbeddedOcompRuntimeErrorV1> {
    let parent = marker.parent().ok_or_else(|| {
        stage(
            "fsync OCOMP mismatch marker directory",
            "marker has no parent directory",
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| stage("fsync OCOMP mismatch marker directory", error))
}

pub enum EmbeddedComputeOutcomeV1 {
    Completed {
        generation: EmbeddedJobGenerationV1,
        completed: CompletedSupervisorJobV1,
    },
    Unrecoverable {
        job_id: B256,
        generation: EmbeddedJobGenerationV1,
        detail: String,
    },
}

/// Result of one embedded payout tick.
#[derive(Debug)]
pub enum EmbeddedPayoutOutcomeV1 {
    Ticked(PayoutTickOutcomeV1),
    Failed(String),
}

pub enum EmbeddedVoteOutcomeV1 {
    Finalized {
        job_id: B256,
        generation: EmbeddedJobGenerationV1,
        success: bool,
    },
    Unrecoverable {
        job_id: B256,
        generation: EmbeddedJobGenerationV1,
        detail: String,
    },
}

pub enum EmbeddedMaterializationOutcomeV1 {
    Finalized {
        job_id: B256,
        queue_sequence: u64,
        first_nod_ordinal: u32,
        success: bool,
    },
    Unavailable {
        job_id: B256,
        queue_sequence: u64,
        first_nod_ordinal: u32,
        detail: String,
    },
}

fn short_job(job_id: B256) -> String {
    hex::encode(&job_id.as_slice()[..4])
}

fn stage(name: &'static str, error: impl std::fmt::Display) -> EmbeddedOcompRuntimeErrorV1 {
    EmbeddedOcompRuntimeErrorV1::Stage {
        name,
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    use super::ValidatorOcompSubmissionGateV1;

    #[cfg(feature = "test-protocol-overrides")]
    use alloy_primitives::{B256, U256};
    #[cfg(feature = "test-protocol-overrides")]
    use outbe_ocomp_protocol::{
        hash::hash_framed,
        intent::DayType,
        profile::poc_schema_limits,
        registry::HashDomain,
        result::{
            lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
            CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisArithmeticSummaryV1,
            LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
        },
        SchemaLimits,
    };

    #[cfg(feature = "test-protocol-overrides")]
    use super::inject_local_result_mismatch_once;

    #[cfg(feature = "test-protocol-overrides")]
    fn mismatch_fixture(job_id: B256, limits: &SchemaLimits) -> LysisResultV1 {
        let roots = ResultRootsV1 {
            nod_root: B256::repeat_byte(0x31),
            bucket_root: B256::repeat_byte(0x32),
            contributor_root: B256::repeat_byte(0x33),
            output_manifest_root: B256::repeat_byte(0x34),
        };
        let counts = ExactCountsV1 {
            tribute_count: 1,
            nod_count: 1,
            bucket_count: 0,
            contributor_count: 0,
            semantic_event_count: 0,
        };
        let conservation = ConservationTotalsV1 {
            tribute_nominal_total: U256::ZERO,
            eligible_nominal_total: U256::ZERO,
            day_limit: U256::ZERO,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            nod_gratis_consumed: U256::ZERO,
            unused_lysis: U256::ZERO,
            carry_over_credit: U256::ZERO,
            nod_cost_total: U256::ZERO,
        };
        let summary = LysisArithmeticSummaryV1 {
            input_manifest_hash: B256::repeat_byte(0x35),
            plan_hash: B256::repeat_byte(0x36),
            unit_artifact_root: B256::repeat_byte(0x37),
            fidelity_fraction_root: B256::repeat_byte(0x38),
            gratis_prefix_root: B256::repeat_byte(0x39),
            roots: roots.clone(),
            counts: counts.clone(),
            conservation: conservation.clone(),
            first_error_ordinal: None,
        };
        LysisResultV1 {
            protocol_bundle_hash: B256::repeat_byte(0x20),
            job_id,
            attempt: 0,
            input_manifest_hash: summary.input_manifest_hash,
            plan_hash: summary.plan_hash,
            unit_artifact_root: summary.unit_artifact_root,
            fidelity_fraction_root: summary.fidelity_fraction_root,
            gratis_prefix_root: summary.gratis_prefix_root,
            result_chunk_count: 1,
            result_chunk_list_root: B256::repeat_byte(0x3a),
            carry_over_credit: CarryOverCreditActionV1 {
                source_wwd: 1,
                reason: CarryOverReason::UnusedLysis,
                amount: U256::ZERO,
            },
            metadosis_completion_summary: MetadosisCompletionSummaryV1 {
                wwd: 1,
                pending_nonce: 0,
                day_type: DayType::Green,
                tribute_nominal_total: U256::ZERO,
                day_limit: U256::ZERO,
                gratis_demand: U256::ZERO,
                gratis_supply: U256::ZERO,
                lysis_budget: U256::ZERO,
                auction_base: U256::ZERO,
                nod_gratis_consumed: U256::ZERO,
                unused_lysis: U256::ZERO,
                carry_over_credit: U256::ZERO,
                status: CompletionStatus::Completed,
                logical_evaluation_height: 1,
                logical_evaluation_time: 1,
            },
            tribute_count: 1,
            tribute_nominal_total: U256::ZERO,
            unused_lysis: U256::ZERO,
            roots,
            counts,
            conservation,
            arithmetic_commitment: hash_framed(
                HashDomain::LysisArithmetic,
                &summary.encode_canonical(limits).unwrap(),
            )
            .unwrap(),
            event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
        }
    }

    #[test]
    fn one_validator_signer_serializes_vote_materialization_and_payout() {
        let gate = Arc::new(ValidatorOcompSubmissionGateV1::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_vote_tx, release_vote_rx) = mpsc::channel();
        let (release_materialization_tx, release_materialization_rx) = mpsc::channel();
        let (release_payout_tx, release_payout_rx) = mpsc::channel();

        let first_gate = Arc::clone(&gate);
        let first_entered = entered_tx.clone();
        let first = thread::spawn(move || {
            let _permit = first_gate.acquire().expect("first signer permit");
            first_entered.send(1).expect("first entered signal");
            release_vote_rx.recv().expect("release vote submission");
        });
        assert_eq!(entered_rx.recv().expect("first vote entered"), 1);

        let second_gate = Arc::clone(&gate);
        let second_entered = entered_tx.clone();
        let second = thread::spawn(move || {
            let _permit = second_gate.acquire().expect("second signer permit");
            second_entered
                .send(2)
                .expect("materialization entered signal");
            release_materialization_rx
                .recv()
                .expect("release materialization submission");
        });
        let third_gate = Arc::clone(&gate);
        let third = thread::spawn(move || {
            let _permit = third_gate.acquire().expect("third signer permit");
            entered_tx.send(3).expect("payout entered signal");
            release_payout_rx.recv().expect("release payout submission");
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());

        release_vote_tx.send(()).expect("release vote submission");
        let next = entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("one queued submission entered after vote submission");
        assert!(matches!(next, 2 | 3));
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
        if next == 2 {
            release_materialization_tx
                .send(())
                .expect("release materialization submission");
            assert_eq!(
                entered_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("payout entered after materialization"),
                3
            );
            release_payout_tx
                .send(())
                .expect("release payout submission");
        } else {
            release_payout_tx
                .send(())
                .expect("release payout submission");
            assert_eq!(
                entered_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("materialization entered after payout"),
                2
            );
            release_materialization_tx
                .send(())
                .expect("release materialization submission");
        }
        first.join().expect("first vote thread");
        second.join().expect("materialization thread");
        third.join().expect("payout thread");
    }

    #[cfg(feature = "test-protocol-overrides")]
    #[test]
    fn mismatch_marker_is_valid_same_job_and_restart_idempotent() {
        use std::fs;

        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("local-result-mismatch.once");
        fs::write(&marker, []).unwrap();
        let limits = poc_schema_limits();
        let job_id = B256::repeat_byte(0x51);
        let original = mismatch_fixture(job_id, &limits);
        let original_bytes = original.encode_canonical(&limits).unwrap();
        let original_digest = original.result_digest(&limits).unwrap();

        let injected = inject_local_result_mismatch_once(&marker, job_id, &original_bytes, &limits)
            .expect("inject mismatch");
        let decoded = LysisResultV1::decode_canonical(&injected, &limits).unwrap();
        assert_eq!(decoded.job_id, job_id);
        assert_ne!(decoded.result_digest(&limits).unwrap(), original_digest);

        let replay = inject_local_result_mismatch_once(&marker, job_id, &original_bytes, &limits)
            .expect("replay claimed mismatch after restart");
        assert_eq!(replay, injected);

        let other_job = B256::repeat_byte(0x52);
        let other = mismatch_fixture(other_job, &limits)
            .encode_canonical(&limits)
            .unwrap();
        assert_eq!(
            inject_local_result_mismatch_once(&marker, other_job, &other, &limits)
                .expect("claimed marker ignores later jobs"),
            other
        );
    }

    #[cfg(feature = "test-protocol-overrides")]
    #[test]
    fn mismatch_marker_recovers_a_fsynced_unpublished_claim() {
        use std::fs;

        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("local-result-mismatch.once");
        fs::write(&marker, []).unwrap();
        let job_id = B256::repeat_byte(0x61);
        let mut claim = Vec::from(super::TEST_MISMATCH_CLAIM_MAGIC);
        claim.extend_from_slice(job_id.as_slice());
        fs::write(marker.with_extension("once.tmp"), claim).unwrap();
        let limits = poc_schema_limits();
        let original = mismatch_fixture(job_id, &limits);
        let original_bytes = original.encode_canonical(&limits).unwrap();

        let injected = inject_local_result_mismatch_once(&marker, job_id, &original_bytes, &limits)
            .expect("recover mismatch claim");
        assert_ne!(injected, original_bytes);
        assert!(!marker.with_extension("once.tmp").exists());
        assert_eq!(
            inject_local_result_mismatch_once(&marker, job_id, &original_bytes, &limits)
                .expect("replay recovered claim"),
            injected
        );
    }
}

#[derive(Debug, Error)]
pub enum EmbeddedOcompRuntimeErrorV1 {
    #[error("embedded OCOMP domain root is invalid")]
    InvalidDomainRoot,
    #[error("embedded OCOMP runtime configuration is invalid")]
    InvalidConfig,
    #[error("Validator embedded OCOMP policy requires local RPC")]
    MissingValidatorRpc,
    #[error("FullNode embedded OCOMP policy cannot load or use vote authority")]
    FullNodeVoteAuthority,
    #[error("embedded OCOMP stage `{name}` failed: {detail}")]
    Stage { name: &'static str, detail: String },
}
