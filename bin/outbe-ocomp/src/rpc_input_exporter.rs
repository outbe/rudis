//! Builds one authenticated Lysis input manifest from finalized public RPC data.

use std::path::PathBuf;

use alloy_primitives::{keccak256, B256};
use outbe_compressed_entities::{
    body_commitment, Commitment, ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_node::ocomp::verify_lysis_openings;
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::{BuildLysisOpeningsV1, SNAPSHOT_LEASE_WIRE_BYTES},
    input::{
        materialize_authenticated_openings, AuthenticatedOpeningV1, CheckpointIdentityV1,
        InputChunkKind, InputManifestV1,
    },
    intent::{
        intent_storage_key, FinalizedRequestBindingV1, JobIntentV1, VerifiedFinalizedIntentV1,
    },
    opening::{LysisOpeningsProofV1, OpeningSubjectsV1},
    profile::ProtocolBundleV1,
    SchemaLimits, SnapshotExportCommittedV1, SnapshotHandoffV1,
};
use outbe_offchain_data::{ProjectionConfig, ProjectionState};
use outbe_offchain_storage::{
    StorageConfig, StorageError, StorageErrorKind, StorageProvider, StorageReadSource,
};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::RetainedTributePin;
use thiserror::Error;

use crate::{
    bundle::PinnedProtocolBundle,
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    export_receipt::{
        ExportReceiptError, ExportReceiptPreparation, ExportReceiptReader, ExportReceiptStore,
        VerifiedExportReceipt,
    },
    exporter::FinalizedTributeSource,
    input_artifacts::{
        decode_fidelity_subject_key, decode_oracle_subject_key, poc_input_list_limits,
        validate_verified_input_manifest_semantics_observing, DurableInputArtifactPublisher,
        InputArtifactError, InputArtifactIdentity,
    },
    input_inventory::{
        SealedTributeInventory, TributeInventoryBuilder, TributeInventoryError,
        TributeInventoryRecordV1, TributeInventorySubjectV1, TributeInventoryWorkConfig,
    },
    input_ref_catalog::VerifiedInputChunkRefCatalog,
    opening_stage::{
        DurableOpeningStage, OpeningResolutionV1, OpeningStageError, OpeningStageSubjectV1,
    },
    public_rpc::PublicOcompRpcClientV1,
    supervisor::DiscoveryRecord,
};

// A progress heartbeat, not a capacity limit. The exporter still consumes all
// records and keeps only its existing bounded publisher window in memory.
const EXPORT_PROGRESS_RECORD_HEARTBEAT: u64 = 256;

#[derive(Clone, Debug)]
pub struct RpcInputExporterConfigV1 {
    pub rpc_url: String,
    pub rpc_max_response_bytes: usize,
    pub storage: StorageConfig,
    pub tribute_page_limit: usize,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub protocol_bundle_hash: B256,
    pub cas_root: PathBuf,
    pub cas_limits: CasLimits,
    pub input_ref_root: PathBuf,
    pub receipt_root: PathBuf,
    pub protocol_bundle: PinnedProtocolBundle,
    pub limits: SchemaLimits,
}

pub struct RpcInputExporterV1 {
    config: RpcInputExporterConfigV1,
    rpc: PublicOcompRpcClientV1,
    storage_source: StorageReadSource,
    cas: FilesystemCas,
    reader: FilesystemCasReader,
}

impl RpcInputExporterV1 {
    pub fn open(config: RpcInputExporterConfigV1) -> Result<Self, RpcInputExporterErrorV1> {
        let storage_source = StorageProvider::new(config.storage.clone())
            .and_then(|provider| provider.read_source(&hex::encode(config.protocol_bundle_hash)))
            .map_err(source_open_error)?;
        let rpc =
            PublicOcompRpcClientV1::new(config.rpc_url.clone(), config.rpc_max_response_bytes)?;
        let cas = FilesystemCas::open(
            &config.cas_root,
            CasWriterRole::SnapshotExporter,
            config.cas_limits,
        )
        .map_err(|error| stage("open input CAS", error))?;
        let reader = FilesystemCasReader::open(&config.cas_root, config.cas_limits)
            .map_err(|error| stage("open input CAS reader", error))?;
        Ok(Self {
            config,
            rpc,
            storage_source,
            cas,
            reader,
        })
    }

    /// Idempotently publishes the exact input manifest and its durable local
    /// receipt. Existing receipts are cold-reloaded and accepted only after the
    /// normal manifest validation succeeds.
    pub fn export(
        &mut self,
        discovery: &DiscoveryRecord,
    ) -> Result<VerifiedExportReceipt, RpcInputExporterErrorV1> {
        self.export_observing(discovery, || {})
    }

    pub fn export_observing(
        &mut self,
        discovery: &DiscoveryRecord,
        on_progress: impl Fn(),
    ) -> Result<VerifiedExportReceipt, RpcInputExporterErrorV1> {
        on_progress();
        let job_id = discovery.spec.summary.job_id;
        let job_key = hex::encode(job_id.as_slice());
        let input_ref_catalog_root = self.config.input_ref_root.join(&job_key);
        let work_root = self.config.input_ref_root.join(".work").join(&job_key);
        // Revalidate the durable discovery binding before accepting even an
        // exact local export replay. A valid old receipt must not make a stale
        // or substituted discovery journal authoritative after restart.
        let finalized = verified_discovery_intent(discovery, &self.config)?;
        let expected_input = ExpectedInputAuthorityV1::from_finalized(
            &finalized,
            self.config.protocol_bundle.bundle(),
            &self.config.limits,
        )?;
        if let Some(reader) =
            ExportReceiptReader::try_open(&self.config.receipt_root, job_id, self.config.limits)
                .map_err(|error| stage("inspect input receipt", error))?
        {
            match reader.load_exact(&self.reader) {
                Ok(receipt) => {
                    require_receipt_generation(&receipt, discovery.generation)?;
                    require_replayed_input_authority(
                        &expected_input,
                        receipt.checkpoint(),
                        receipt.manifest(),
                    )?;
                    let catalog = VerifiedInputChunkRefCatalog::reopen(
                        &input_ref_catalog_root,
                        &self.reader,
                        self.config.limits,
                        poc_input_list_limits(),
                    )
                    .map_err(|error| stage("reload input-ref catalog", error))?;
                    catalog
                        .require_manifest_authority(&receipt.manifest_ref(), receipt.manifest())
                        .map_err(|error| stage("bind input-ref catalog to receipt", error))?;
                    validate_verified_input_manifest_semantics_observing(
                        &catalog,
                        &self.reader,
                        self.config.protocol_bundle.bundle(),
                        receipt.manifest(),
                        &self.config.limits,
                        &on_progress,
                    )
                    .map_err(|error| stage("verify replayed input semantics", error))?;
                    verify_replayed_finalized_inputs(
                        &catalog,
                        &self.reader,
                        &work_root,
                        &finalized,
                        &expected_input,
                        self.config.protocol_bundle.bundle(),
                        &self.config.limits,
                        &on_progress,
                    )?;
                    on_progress();
                    return Ok(receipt);
                }
                Err(
                    ExportReceiptError::MissingPreparation | ExportReceiptError::MissingReceipt,
                ) => {}
                Err(error) => return Err(stage("reload input receipt", error)),
            }
        }

        if finalized.job_id != job_id {
            return Err(RpcInputExporterErrorV1::Authority("discovery JobId"));
        }
        let projection_config = ProjectionConfig {
            chain_id: self.config.chain_id,
            genesis_hash: self.config.genesis_hash,
            start_block: self.config.storage.start_block,
        };
        // Keep one caught-up secondary view for the checkpoint and the entire
        // inventory. No read can refresh this session while it is being consumed.
        let storage = self
            .storage_source
            .open_session()
            .map_err(source_open_error)?;
        let tribute_source = FinalizedTributeSource::new(storage, self.config.tribute_page_limit)
            .map_err(|error| stage("open finalized Tribute source", error))?;
        let projection_state = tribute_source
            .projection_state(projection_config)
            .map_err(|error| stage("read finalized projection checkpoint", error))?;
        require_projection_checkpoint(projection_state.as_ref(), &finalized.request)?;
        let pin = RetainedTributePin {
            input_lease_id: finalized
                .intent
                .input_lease_id()
                .map_err(|error| stage("derive Tribute retention pin", error))?,
            worldwide_day: WorldwideDay::new(finalized.intent.wwd),
        };

        let checkpoint = expected_input.checkpoint.clone();
        let inventory_subject = TributeInventorySubjectV1 {
            protocol_bundle_hash: self.config.protocol_bundle_hash,
            job_id,
            attempt: finalized.intent.attempt,
            checkpoint: checkpoint.clone(),
            worldwide_day: WorldwideDay::new(finalized.intent.wwd),
            sealed_tribute_collection_root: finalized.intent.sealed_tribute_collection_root,
            expected_tribute_count: finalized.intent.authenticated_day_count,
            expected_nominal_total: finalized.intent.authenticated_day_nominal,
        };
        let inventory_root = work_root.join("inventory");
        let inventory = match SealedTributeInventory::open_observing(
            &inventory_root,
            inventory_subject.clone(),
            &on_progress,
        ) {
            Ok(inventory) => inventory,
            Err(TributeInventoryError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let mut builder = TributeInventoryBuilder::create(
                    &inventory_root,
                    inventory_subject,
                    TributeInventoryWorkConfig::default(),
                )
                .map_err(|error| stage("create Tribute inventory", error))?;
                let mut stream = tribute_source
                    .reconstruction_stream(
                        pin,
                        finalized.intent.authenticated_day_count,
                        finalized.intent.authenticated_day_nominal,
                    )
                    .map_err(|error| stage("open sealed Tribute stream", error))?;
                let mut records_since_progress = 0_u64;
                while let Some(record) = stream
                    .next_record()
                    .map_err(|error| stage("read sealed Tribute stream", error))?
                {
                    builder
                        .push(TributeInventoryRecordV1 {
                            tribute_id: record.tribute_id,
                            commitment: Commitment::try_from(record.commitment.0)
                                .map_err(|error| stage("decode Tribute commitment", error))?,
                            owner: record.body.owner,
                            reference_iso: record.body.reference_currency,
                            nominal_amount_minor: record.body.nominal_amount_minor,
                            canonical_body: record.canonical_body,
                        })
                        .map_err(|error| stage("spool Tribute inventory", error))?;
                    records_since_progress = records_since_progress.saturating_add(1);
                    if records_since_progress == EXPORT_PROGRESS_RECORD_HEARTBEAT {
                        on_progress();
                        records_since_progress = 0;
                    }
                }
                stream
                    .finish()
                    .map_err(|error| stage("close sealed Tribute stream", error))?;
                builder
                    .finish_observing(&on_progress)
                    .map_err(|error| stage("seal Tribute inventory", error))?
            }
            Err(error) => return Err(stage("reopen Tribute inventory", error)),
        };
        drop(tribute_source);
        on_progress();
        let mut publisher = DurableInputArtifactPublisher::open(
            &self.cas,
            &self.reader,
            &input_ref_catalog_root,
            self.config.protocol_bundle.bundle(),
            InputArtifactIdentity {
                job_id,
                attempt: finalized.intent.attempt,
                checkpoint: checkpoint.clone(),
                wwd: finalized.intent.wwd,
                sealed_tribute_collection_key: finalized.intent.sealed_tribute_collection_key,
                sealed_tribute_collection_root: finalized.intent.sealed_tribute_collection_root,
            },
            self.config.limits,
            poc_input_list_limits(),
        )
        .map_err(|error| stage("open durable input publisher", error))?;
        let mut bodies = inventory
            .tribute_bodies()
            .map_err(|error| stage("open Tribute body spool", error))?;
        let mut bodies_since_progress = 0_u64;
        while let Some(body) = bodies
            .next_body(self.config.limits.max_bounded_bytes)
            .map_err(|error| stage("read Tribute body spool", error))?
        {
            publisher
                .publish_tribute(body)
                .map_err(|error| stage("publish Tribute input chunk", error))?;
            bodies_since_progress = bodies_since_progress.saturating_add(1);
            if bodies_since_progress == EXPORT_PROGRESS_RECORD_HEARTBEAT {
                on_progress();
                bodies_since_progress = 0;
            }
        }
        publisher
            .finish_tributes()
            .map_err(|error| stage("finish Tribute input chunks", error))?;

        let mut opening_stage = DurableOpeningStage::open_or_resume(
            work_root.join("openings"),
            OpeningStageSubjectV1 {
                protocol_bundle_hash: self.config.protocol_bundle_hash,
                job_id,
                attempt: finalized.intent.attempt,
                checkpoint: checkpoint.clone(),
                worldwide_day: finalized.intent.wwd,
                inventory_authority_digest: inventory.authority_digest(),
            },
            self.config.limits,
        )
        .map_err(|error| stage("open durable opening stage", error))?;
        let opening_report = opening_stage
            .run(
                &inventory,
                |subjects| {
                    on_progress();
                    let canonical_request = BuildLysisOpeningsV1 {
                        job_id,
                        subjects: subjects.clone(),
                    }
                    .encode_body(&self.config.limits)
                    .map_err(|error| OpeningStageError::Resolver(error.to_string()))?;
                    let openings = match self
                        .rpc
                        .lysis_openings(finalized.intent_id, &canonical_request)
                        .and_then(|encoded| {
                            LysisOpeningsProofV1::decode_body(&encoded, &self.config.limits)
                                .map_err(|error| crate::public_rpc::PublicRpcError::Malformed {
                                    method: "rudis_getOcompLysisOpeningsV1",
                                    detail: error.to_string(),
                                })
                        }) {
                        Ok(openings) => openings,
                        Err(error) if is_lysis_opening_capacity_error(&error) => {
                            return Ok(OpeningResolutionV1::Split);
                        }
                        Err(error) => {
                            return Err(OpeningStageError::Resolver(error.to_string()));
                        }
                    };
                    verify_lysis_openings(&openings, &finalized, subjects, &self.config.limits)
                        .map_err(|error| OpeningStageError::Resolver(error.to_string()))?;
                    on_progress();
                    let materialized = materialize_authenticated_openings(
                        &openings,
                        self.config.protocol_bundle.bundle(),
                        &self.config.limits,
                    )
                    .map_err(|error| OpeningStageError::Resolver(error.to_string()))?;
                    Ok(OpeningResolutionV1::Complete(Box::new(materialized)))
                },
                |subjects, fidelity, oracle| {
                    on_progress();
                    verify_durable_lysis_openings(
                        fidelity,
                        oracle,
                        &finalized,
                        subjects,
                        self.config.protocol_bundle.bundle(),
                        &self.config.limits,
                    )
                },
                |opening| {
                    on_progress();
                    publisher
                        .publish_fidelity_opening(opening)
                        .map_err(OpeningStageError::from)
                },
            )
            .map_err(|error| stage("acquire and publish Lysis openings", error))?;
        on_progress();
        publisher
            .publish_oracle_opening(opening_report.oracle)
            .map_err(|error| stage("publish Oracle opening", error))?;
        let mut fidelity_cursor =
            opening_stage.fidelity_cursor(opening_report.fidelity_opening_count);
        let published = publisher
            .finish_observing(
                finalized.intent.authenticated_day_count,
                finalized.intent.authenticated_day_nominal,
                opening_report.fidelity_opening_count,
                || {
                    fidelity_cursor
                        .next_opening()
                        .map_err(|error| InputArtifactError::OpeningSource(error.to_string()))
                },
                &on_progress,
            )
            .map_err(|error| stage("seal input artifacts", error))?;
        if published.tribute_count != finalized.intent.authenticated_day_count
            || published.tribute_nominal_total != finalized.intent.authenticated_day_nominal
        {
            return Err(RpcInputExporterErrorV1::Authority(
                "published Tribute conservation",
            ));
        }

        // This is an OCOMP-local publication record, not a node acknowledgement.
        // The legacy envelope remains versioned for crash-safe compatibility.
        let handoff = SnapshotHandoffV1 {
            job_id,
            input_lease_id: pin.input_lease_id,
            pin_generation: discovery.generation,
            lease_generation: 1,
            checkpoint,
            canonical_lease_offer: BoundedBytes(local_publication_lease(job_id)),
        };
        let mut receipt_store =
            ExportReceiptStore::open(&self.config.receipt_root, job_id, self.config.limits)
                .map_err(|error| stage("open input receipt", error))?;
        let (_, prepared) = receipt_store
            .prepare(
                &self.cas,
                &self.reader,
                ExportReceiptPreparation {
                    handoff: &handoff,
                    manifest_ref: &published.manifest_ref,
                    manifest_hash: published.manifest_hash,
                },
            )
            .map_err(|error| stage("prepare input receipt", error))?;
        let committed = SnapshotExportCommittedV1 {
            job_id,
            pin_generation: committed_pin_generation(discovery.generation)?,
            record_hash: keccak256(
                [
                    b"OCOMP_RPC_INPUT_COMMIT_V1".as_slice(),
                    job_id.as_slice(),
                    published.manifest_hash.as_slice(),
                ]
                .concat(),
            ),
        };
        receipt_store
            .record_committed(&self.cas, &self.reader, &prepared, &committed)
            .map_err(|error| stage("commit input receipt", error))?;
        on_progress();
        drop(receipt_store);
        let receipt =
            ExportReceiptReader::open(&self.config.receipt_root, job_id, self.config.limits)
                .map_err(|error| stage("reopen committed input receipt", error))?
                .load_exact(&self.reader)
                .map_err(|error| stage("reload committed input receipt", error))?;
        require_receipt_generation(&receipt, discovery.generation)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedInputAuthorityV1 {
    protocol_bundle_hash: B256,
    job_id: B256,
    attempt: u32,
    checkpoint: CheckpointIdentityV1,
    wwd: u32,
    sealed_tribute_collection_key: B256,
    sealed_tribute_collection_root: B256,
    tribute_count: u32,
    tribute_nominal_total: alloy_primitives::U256,
    body_codec_id: B256,
    opening_codec_registry_hash: B256,
}

impl ExpectedInputAuthorityV1 {
    fn from_finalized(
        finalized: &VerifiedFinalizedIntentV1,
        bundle: &ProtocolBundleV1,
        limits: &SchemaLimits,
    ) -> Result<Self, RpcInputExporterErrorV1> {
        let protocol_bundle_hash = bundle
            .protocol_bundle_hash(limits)
            .map_err(|error| stage("hash protocol bundle", error))?;
        if protocol_bundle_hash != finalized.intent.protocol_bundle_hash {
            return Err(RpcInputExporterErrorV1::Authority(
                "finalized protocol bundle",
            ));
        }
        Ok(Self {
            protocol_bundle_hash,
            job_id: finalized.job_id,
            attempt: finalized.intent.attempt,
            checkpoint: CheckpointIdentityV1 {
                finalized_block_number: finalized.request.block_number,
                finalized_block_hash: finalized.request.block_hash,
                finalized_state_root: finalized.request.state_root,
                finalized_ce_root: finalized.intent.ce_sealed_root,
                ce_schema_version: u16::try_from(
                    outbe_compressed_entities::LOCAL_STORAGE_SCHEMA_VERSION,
                )
                .map_err(|_| RpcInputExporterErrorV1::Authority("CE schema version"))?,
            },
            wwd: finalized.intent.wwd,
            sealed_tribute_collection_key: finalized.intent.sealed_tribute_collection_key,
            sealed_tribute_collection_root: finalized.intent.sealed_tribute_collection_root,
            tribute_count: finalized.intent.authenticated_day_count,
            tribute_nominal_total: finalized.intent.authenticated_day_nominal,
            body_codec_id: bundle.tribute_body_codec_id,
            opening_codec_registry_hash: bundle
                .opening_codec_registry_hash()
                .map_err(|error| stage("hash opening codec registry", error))?,
        })
    }
}

fn require_replayed_input_authority(
    expected: &ExpectedInputAuthorityV1,
    receipt_checkpoint: &CheckpointIdentityV1,
    manifest: &InputManifestV1,
) -> Result<(), RpcInputExporterErrorV1> {
    if receipt_checkpoint != &expected.checkpoint
        || manifest.protocol_bundle_hash != expected.protocol_bundle_hash
        || manifest.job_id != expected.job_id
        || manifest.attempt != expected.attempt
        || manifest.checkpoint != expected.checkpoint
        || manifest.wwd != expected.wwd
        || manifest.sealed_tribute_collection_key != expected.sealed_tribute_collection_key
        || manifest.sealed_tribute_collection_root != expected.sealed_tribute_collection_root
        || manifest.tribute_count != expected.tribute_count
        || manifest.tribute_nominal_total != expected.tribute_nominal_total
        || manifest.body_codec_id != expected.body_codec_id
        || manifest.opening_codec_registry_hash != expected.opening_codec_registry_hash
    {
        return Err(RpcInputExporterErrorV1::Authority(
            "replayed input manifest finalized binding",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_replayed_finalized_inputs(
    catalog: &VerifiedInputChunkRefCatalog,
    reader: &FilesystemCasReader,
    work_root: &std::path::Path,
    finalized: &VerifiedFinalizedIntentV1,
    expected: &ExpectedInputAuthorityV1,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
    on_progress: &impl Fn(),
) -> Result<(), RpcInputExporterErrorV1> {
    let subject = TributeInventorySubjectV1 {
        protocol_bundle_hash: expected.protocol_bundle_hash,
        job_id: expected.job_id,
        attempt: expected.attempt,
        checkpoint: expected.checkpoint.clone(),
        worldwide_day: WorldwideDay::new(expected.wwd),
        sealed_tribute_collection_root: expected.sealed_tribute_collection_root,
        expected_tribute_count: expected.tribute_count,
        expected_nominal_total: expected.tribute_nominal_total,
    };
    let inventory_root = work_root.join("inventory");
    let inventory =
        match SealedTributeInventory::open_observing(&inventory_root, subject.clone(), on_progress)
        {
            Ok(inventory) => inventory,
            Err(TributeInventoryError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let mut builder = TributeInventoryBuilder::create(
                    &inventory_root,
                    subject,
                    TributeInventoryWorkConfig::default(),
                )
                .map_err(|error| stage("create replay Tribute inventory", error))?;
                for verified in catalog
                    .exact_verified_cursor_observing(reader, bundle, on_progress)
                    .map_err(|error| stage("open replay input catalog", error))?
                {
                    let verified =
                        verified.map_err(|error| stage("read replay input catalog", error))?;
                    on_progress();
                    if verified.reference.kind != InputChunkKind::Tribute {
                        continue;
                    }
                    for canonical in verified.chunk.canonical_records_or_openings {
                        let body = outbe_compressed_entities::decode_tribute_v1(&canonical.0)
                            .map_err(|error| stage("decode replay Tribute", error))?;
                        let commitment = body_commitment(
                            ACTIVE_COMMITMENT_SCHEME,
                            BODY_SCHEMA_V1,
                            body.tribute_id,
                            &canonical.0,
                        )
                        .map_err(|error| stage("commit replay Tribute", error))?;
                        builder
                            .push(TributeInventoryRecordV1 {
                                tribute_id: body.tribute_id,
                                commitment,
                                owner: body.owner,
                                reference_iso: body.reference_currency,
                                nominal_amount_minor: body.nominal_amount_minor,
                                canonical_body: canonical.0,
                            })
                            .map_err(|error| stage("spool replay Tribute inventory", error))?;
                        on_progress();
                    }
                }
                builder
                    .finish_observing(on_progress)
                    .map_err(|error| stage("seal replay Tribute inventory", error))?
            }
            Err(error) => return Err(stage("reopen replay Tribute inventory", error)),
        };

    let reference_isos = inventory.reference_isos();
    let mut oracle = None;
    for verified in catalog
        .exact_verified_cursor_observing(reader, bundle, on_progress)
        .map_err(|error| stage("open replay Oracle catalog", error))?
    {
        let verified = verified.map_err(|error| stage("read replay Oracle catalog", error))?;
        on_progress();
        if verified.reference.kind != InputChunkKind::Oracle {
            continue;
        }
        let canonical = verified
            .chunk
            .canonical_records_or_openings
            .into_iter()
            .next()
            .ok_or(RpcInputExporterErrorV1::Authority(
                "replayed Oracle opening",
            ))?;
        if oracle.is_some() {
            return Err(RpcInputExporterErrorV1::Authority(
                "replayed Oracle cardinality",
            ));
        }
        oracle = Some(
            AuthenticatedOpeningV1::decode_canonical_record(&canonical.0, limits)
                .map_err(|error| stage("decode replay Oracle opening", error))?,
        );
    }
    let oracle = oracle.ok_or(RpcInputExporterErrorV1::Authority(
        "replayed Oracle opening",
    ))?;
    let (oracle_wwd, oracle_isos) = decode_oracle_subject_key(&oracle.canonical_subject_key.0)
        .map_err(|error| stage("decode replay Oracle subject", error))?;
    if oracle_wwd != expected.wwd || oracle_isos != reference_isos {
        return Err(RpcInputExporterErrorV1::Authority(
            "replayed Oracle subject",
        ));
    }

    let mut owner_reader = inventory
        .owner_batches()
        .map_err(|error| stage("open replay owner inventory", error))?;
    let mut expected_owners = Vec::new();
    let mut expected_owner_index = 0_usize;
    for verified in catalog
        .exact_verified_cursor_observing(reader, bundle, on_progress)
        .map_err(|error| stage("open replay Fidelity catalog", error))?
    {
        let verified = verified.map_err(|error| stage("read replay Fidelity catalog", error))?;
        on_progress();
        if verified.reference.kind != InputChunkKind::Fidelity {
            continue;
        }
        let canonical = verified
            .chunk
            .canonical_records_or_openings
            .into_iter()
            .next()
            .ok_or(RpcInputExporterErrorV1::Authority(
                "replayed Fidelity opening",
            ))?;
        let fidelity = AuthenticatedOpeningV1::decode_canonical_record(&canonical.0, limits)
            .map_err(|error| stage("decode replay Fidelity opening", error))?;
        let owners = decode_fidelity_subject_key(&fidelity.canonical_subject_key.0)
            .map_err(|error| stage("decode replay Fidelity subject", error))?;
        for owner in &owners {
            if expected_owner_index == expected_owners.len() {
                expected_owners = owner_reader
                    .next_batch(outbe_ocomp_protocol::opening::MAX_FIDELITY_OWNERS_PER_OPENING)
                    .map_err(|error| stage("read replay owner inventory", error))?
                    .ok_or(RpcInputExporterErrorV1::Authority(
                        "replayed Fidelity owner overflow",
                    ))?;
                expected_owner_index = 0;
            }
            if expected_owners.get(expected_owner_index) != Some(owner) {
                return Err(RpcInputExporterErrorV1::Authority(
                    "replayed Fidelity owner coverage",
                ));
            }
            expected_owner_index += 1;
            on_progress();
        }
        verify_durable_lysis_openings(
            &fidelity,
            &oracle,
            finalized,
            &OpeningSubjectsV1 {
                owners,
                reference_isos: reference_isos.clone(),
            },
            bundle,
            limits,
        )
        .map_err(|error| stage("verify replayed finalized openings", error))?;
    }
    if expected_owner_index != expected_owners.len()
        || owner_reader
            .next_batch(outbe_ocomp_protocol::opening::MAX_FIDELITY_OWNERS_PER_OPENING)
            .map_err(|error| stage("close replay owner inventory", error))?
            .is_some()
    {
        return Err(RpcInputExporterErrorV1::Authority(
            "replayed Fidelity owner coverage",
        ));
    }
    Ok(())
}

fn verify_durable_lysis_openings(
    fidelity: &AuthenticatedOpeningV1,
    oracle: &AuthenticatedOpeningV1,
    finalized: &VerifiedFinalizedIntentV1,
    subjects: &OpeningSubjectsV1,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<(), OpeningStageError> {
    fidelity
        .validate_against_bundle(bundle, limits)
        .map_err(|error| OpeningStageError::Verification(error.to_string()))?;
    oracle
        .validate_against_bundle(bundle, limits)
        .map_err(|error| OpeningStageError::Verification(error.to_string()))?;
    let fidelity = fidelity
        .decode_and_validate_raw_opening(finalized.request.state_root, limits)
        .map_err(|error| OpeningStageError::Verification(error.to_string()))?;
    let oracle = oracle
        .decode_and_validate_raw_opening(finalized.request.state_root, limits)
        .map_err(|error| OpeningStageError::Verification(error.to_string()))?;
    verify_lysis_openings(
        &LysisOpeningsProofV1 {
            protocol_bundle_hash: finalized.intent.protocol_bundle_hash,
            job_id: finalized.job_id,
            finalized_block_hash: finalized.request.block_hash,
            finalized_state_root: finalized.request.state_root,
            wwd: finalized.intent.wwd,
            subjects: subjects.clone(),
            fidelity,
            oracle,
        },
        finalized,
        subjects,
        limits,
    )
    .map_err(|error| OpeningStageError::Verification(error.to_string()))
}

fn verified_discovery_intent(
    discovery: &DiscoveryRecord,
    config: &RpcInputExporterConfigV1,
) -> Result<VerifiedFinalizedIntentV1, RpcInputExporterErrorV1> {
    let summary = &discovery.spec.summary;
    let intent =
        JobIntentV1::decode_canonical(&discovery.spec.canonical_job_intent.0, &config.limits)
            .map_err(|error| stage("decode finalized JobIntent", error))?;
    let intent_id = intent
        .intent_id(&config.limits)
        .map_err(|error| stage("hash finalized JobIntent", error))?;
    let job_id = intent
        .job_id(
            summary.finalized_block_hash,
            summary.finalized_state_root,
            &config.limits,
        )
        .map_err(|error| stage("derive finalized JobId", error))?;
    if discovery.cursor != summary.cursor
        || intent_id != summary.intent_id
        || job_id != summary.job_id
        || intent.chain_id != config.chain_id
        || intent.genesis_hash != config.genesis_hash
        || intent.fork_id != config.fork_id
        || intent.protocol_bundle_hash != config.protocol_bundle_hash
        || summary.protocol_bundle_hash != config.protocol_bundle_hash
    {
        return Err(RpcInputExporterErrorV1::Authority(
            "finalized discovery binding",
        ));
    }
    Ok(VerifiedFinalizedIntentV1 {
        intent,
        intent_id,
        intent_storage_key: intent_storage_key(intent_id)
            .map_err(|error| stage("derive finalized intent storage key", error))?,
        job_id,
        request: FinalizedRequestBindingV1 {
            block_number: summary.cursor,
            block_hash: summary.finalized_block_hash,
            state_root: summary.finalized_state_root,
        },
    })
}

fn require_projection_checkpoint(
    state: Option<&ProjectionState>,
    request: &FinalizedRequestBindingV1,
) -> Result<(), RpcInputExporterErrorV1> {
    let checkpoint =
        state
            .and_then(|state| state.checkpoint)
            .ok_or(RpcInputExporterErrorV1::Authority(
                "projection checkpoint missing",
            ))?;
    if checkpoint.block_number < request.block_number
        || (checkpoint.block_number == request.block_number
            && checkpoint.block_hash != request.block_hash)
    {
        return Err(RpcInputExporterErrorV1::Authority(
            "projection checkpoint does not cover finalized request",
        ));
    }
    Ok(())
}

fn committed_pin_generation(source_generation: u64) -> Result<u64, RpcInputExporterErrorV1> {
    source_generation
        .checked_add(1)
        .ok_or(RpcInputExporterErrorV1::Authority(
            "discovery generation overflow",
        ))
}

fn require_receipt_generation(
    receipt: &VerifiedExportReceipt,
    source_generation: u64,
) -> Result<(), RpcInputExporterErrorV1> {
    if receipt.source_pin_generation() != source_generation
        || receipt.committed().pin_generation != committed_pin_generation(source_generation)?
    {
        return Err(RpcInputExporterErrorV1::Authority(
            "export receipt discovery generation",
        ));
    }
    Ok(())
}

fn is_lysis_opening_capacity_error(error: &impl std::fmt::Display) -> bool {
    error
        .to_string()
        .contains("Lysis opening bytes exceeds cap: ")
}

fn local_publication_lease(job_id: B256) -> Vec<u8> {
    let digest = keccak256([b"OCOMP_RPC_INPUT_V1".as_slice(), job_id.as_slice()].concat());
    let mut lease = Vec::with_capacity(SNAPSHOT_LEASE_WIRE_BYTES);
    while lease.len() < SNAPSHOT_LEASE_WIRE_BYTES {
        lease.extend_from_slice(digest.as_slice());
    }
    lease.truncate(SNAPSHOT_LEASE_WIRE_BYTES);
    lease
}

fn stage(stage: &'static str, error: impl std::fmt::Display) -> RpcInputExporterErrorV1 {
    RpcInputExporterErrorV1::Stage {
        stage,
        detail: error.to_string(),
    }
}

fn source_open_error(error: StorageError) -> RpcInputExporterErrorV1 {
    match error.kind() {
        StorageErrorKind::Unavailable | StorageErrorKind::RequestDeadline => {
            RpcInputExporterErrorV1::SourceStorageUnavailable
        }
        _ => stage("open finalized Tribute source", error),
    }
}

#[derive(Debug, Error)]
pub enum RpcInputExporterErrorV1 {
    #[error(transparent)]
    Rpc(#[from] crate::public_rpc::PublicRpcError),
    #[error("OCOMP public input authority mismatch: {0}")]
    Authority(&'static str),
    #[error("OCOMP finalized Tribute source storage is unavailable during startup")]
    SourceStorageUnavailable,
    #[error("OCOMP public input stage `{stage}` failed: {detail}")]
    Stage { stage: &'static str, detail: String },
}

impl RpcInputExporterErrorV1 {
    #[must_use]
    pub const fn is_retryable_startup(&self) -> bool {
        matches!(self, Self::SourceStorageUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U256};
    use outbe_node::ocomp::retention::RetentionError;
    use outbe_ocomp_protocol::input::{CheckpointIdentityV1, Compression, InputManifestV1};
    use outbe_offchain_data::ProjectionState;
    use outbe_primitives::projection::ProjectionCheckpoint;

    use super::{
        committed_pin_generation, is_lysis_opening_capacity_error, require_projection_checkpoint,
        require_replayed_input_authority, ExpectedInputAuthorityV1,
    };

    #[test]
    fn reader_only_projection_checkpoint_must_cover_the_finalized_request() {
        let request = super::FinalizedRequestBindingV1 {
            block_number: 42,
            block_hash: B256::repeat_byte(0x42),
            state_root: B256::repeat_byte(0x24),
        };
        let state = |block_number, block_hash| ProjectionState {
            chain_id: 7,
            genesis_hash: B256::repeat_byte(0x77),
            storage_schema_version: 1,
            start_block: 1,
            checkpoint: Some(ProjectionCheckpoint {
                block_number,
                block_hash,
            }),
        };

        assert!(require_projection_checkpoint(None, &request).is_err());
        assert!(
            require_projection_checkpoint(Some(&state(41, B256::repeat_byte(0x41))), &request)
                .is_err()
        );
        assert!(
            require_projection_checkpoint(Some(&state(42, B256::repeat_byte(0x99))), &request)
                .is_err()
        );
        assert!(
            require_projection_checkpoint(Some(&state(42, request.block_hash)), &request).is_ok()
        );
        assert!(
            require_projection_checkpoint(Some(&state(43, B256::repeat_byte(0x43))), &request)
                .is_ok()
        );
    }

    #[test]
    fn committed_generation_is_the_offer_generation_successor() {
        assert_eq!(committed_pin_generation(7).unwrap(), 8);
        assert!(committed_pin_generation(u64::MAX).is_err());
    }

    #[test]
    fn only_lysis_opening_byte_capacity_triggers_bisection() {
        assert!(is_lysis_opening_capacity_error(&RetentionError::Source(
            "Lysis opening bytes exceeds cap: 317499 > 262144".to_owned(),
        )));
        assert!(!is_lysis_opening_capacity_error(&RetentionError::Source(
            "raw contract opening bytes exceeds cap: 317499 > 262144".to_owned(),
        )));
        assert!(!is_lysis_opening_capacity_error(
            &RetentionError::RetainedTributeStorageUnavailable,
        ));
    }

    #[test]
    fn replayed_manifest_requires_every_finalized_authority_field() {
        let expected = expected_input_authority();
        let manifest = matching_manifest(&expected);
        assert!(
            require_replayed_input_authority(&expected, &expected.checkpoint, &manifest,).is_ok()
        );

        let mut substitutions = Vec::new();
        let mut changed = manifest.clone();
        changed.protocol_bundle_hash = B256::repeat_byte(21);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.job_id = B256::repeat_byte(22);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.attempt += 1;
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.checkpoint.finalized_block_hash = B256::repeat_byte(23);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.wwd += 1;
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.sealed_tribute_collection_key = B256::repeat_byte(24);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.sealed_tribute_collection_root = B256::repeat_byte(25);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.tribute_count += 1;
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.tribute_nominal_total += U256::from(1);
        substitutions.push(changed);
        let mut changed = manifest.clone();
        changed.body_codec_id = B256::repeat_byte(26);
        substitutions.push(changed);
        let mut changed = manifest;
        changed.opening_codec_registry_hash = B256::repeat_byte(27);
        substitutions.push(changed);

        for substituted in substitutions {
            assert!(require_replayed_input_authority(
                &expected,
                &expected.checkpoint,
                &substituted,
            )
            .is_err());
        }

        let mut receipt_checkpoint = expected.checkpoint.clone();
        receipt_checkpoint.finalized_block_number += 1;
        assert!(require_replayed_input_authority(
            &expected,
            &receipt_checkpoint,
            &matching_manifest(&expected),
        )
        .is_err());
    }

    fn expected_input_authority() -> ExpectedInputAuthorityV1 {
        ExpectedInputAuthorityV1 {
            protocol_bundle_hash: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 0,
            checkpoint: CheckpointIdentityV1 {
                finalized_block_number: 4,
                finalized_block_hash: B256::repeat_byte(5),
                finalized_state_root: B256::repeat_byte(6),
                finalized_ce_root: B256::repeat_byte(7),
                ce_schema_version: 8,
            },
            wwd: 20_260_901,
            sealed_tribute_collection_key: B256::repeat_byte(9),
            sealed_tribute_collection_root: B256::repeat_byte(10),
            tribute_count: 11,
            tribute_nominal_total: U256::from(12),
            body_codec_id: B256::repeat_byte(13),
            opening_codec_registry_hash: B256::repeat_byte(14),
        }
    }

    fn matching_manifest(expected: &ExpectedInputAuthorityV1) -> InputManifestV1 {
        InputManifestV1 {
            protocol_bundle_hash: expected.protocol_bundle_hash,
            job_id: expected.job_id,
            attempt: expected.attempt,
            checkpoint: expected.checkpoint.clone(),
            wwd: expected.wwd,
            sealed_tribute_collection_key: expected.sealed_tribute_collection_key,
            sealed_tribute_collection_root: expected.sealed_tribute_collection_root,
            tribute_count: expected.tribute_count,
            tribute_nominal_total: expected.tribute_nominal_total,
            input_chunk_count: 1,
            input_chunk_list_root: B256::repeat_byte(15),
            fidelity_opening_root: B256::repeat_byte(16),
            oracle_opening_root: B256::repeat_byte(17),
            exact_encoded_bytes: 18,
            exact_record_count: 19,
            body_codec_id: expected.body_codec_id,
            opening_codec_registry_hash: expected.opening_codec_registry_hash,
            compression: Compression::None,
        }
    }
}
