mod support;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, encode_tribute_v1, TributeBodyV1};
use outbe_lysis::program_v1::planner::{
    LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1, PlannedUnitPositionV1,
};
use outbe_lysis::program_v1::result::{
    encode_root_reduce_output, LysisListSubtreeCarrierV1, RootReduceOutputV1, RootReduceSummaryV1,
};
use outbe_ocomp::{
    admission_catalog::{AdmissionPositionV1, VerifiedAdmissionCatalog},
    bundle::PinnedProtocolBundle,
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    input_artifacts::{
        poc_input_list_limits, publish_input_artifact_set, InputArtifactContents,
        InputArtifactIdentity,
    },
    input_ref_catalog::{InputRefCatalogError, VerifiedInputChunkRefCatalog},
    lysis_plan_audit::{ExactLysisPlanError, LocalLysisPlanAuditV1, LysisPlanAuditStepV1},
    lysis_result_catalog::{
        verified_result_chunk_at, ExactLysisResultCatalogCursorV1, LysisResultCatalogError,
        LysisResultCatalogStepV1,
    },
    nod_materialization::build_nod_materialization_batch,
    nod_proof::{build_certified_nod_proof, NodProofBuildError},
};
use outbe_ocomp_protocol::{
    common::{BoundedBytes, ProofBytes},
    input::{
        materialize_authenticated_openings, AuthenticatedInputChunkV1, CheckpointIdentityV1,
        InputChunkKind, InputManifestV1,
    },
    list::verify_ordered_list_membership,
    nod_materialization::NodMaterializationHeadV1,
    opening::{
        partition_lysis_opening_subjects, LysisOpeningsProofV1, RawContractOpeningProofV1,
        RawStorageSlotV1,
    },
    registry::ObjectKind,
    result::{
        ActiveNodSetV1, ContributorActionV1, NodActionV1, OutputManifestEntryV1, ResultChunkV1,
    },
    unit::{UnitArtifactV1, UnitPhase, UnitSpecV1, WorkOutputHeaderV1},
    CasObjectRefV1, ListKind, StreamingOrderedListRoot,
};
use outbe_primitives::time::WorldwideDay;

const CAS_LIMITS: CasLimits = CasLimits {
    max_object_bytes: 1_048_576,
    max_total_bytes: 64 * 1_048_576,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

struct Fixture {
    _directory: tempfile::TempDir,
    cas_root: std::path::PathBuf,
    input_ref_root: std::path::PathBuf,
    admission_root: std::path::PathBuf,
    limits: outbe_ocomp_protocol::SchemaLimits,
    bundle: PinnedProtocolBundle,
    target_ordinal: u32,
    expected_count: u32,
    result_chunk_refs: Vec<CasObjectRefV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResultCatalogFault {
    None,
    ContributorCarrier,
    EligibleTotal,
    HeaderCoverage,
    ContributorBoundary,
    NodBoundary,
    AlternateResultChunk,
}

/// Synthetic protocol-shaped catalog fixture.
///
/// Input artifacts and result leaves use production codecs and exact CAS
/// descriptors. Other phase payloads are deliberately minimal and do not
/// claim to be evidence of a real worker-pipeline execution.
fn synthetic_fixture(substitute_bucket_spec: bool, corrupt_fidelity_root: bool) -> Fixture {
    synthetic_fixture_with_options(
        substitute_bucket_spec,
        corrupt_fidelity_root,
        ResultCatalogFault::None,
        257,
    )
}

fn synthetic_fixture_with_result_fault(
    substitute_bucket_spec: bool,
    corrupt_fidelity_root: bool,
    result_fault: ResultCatalogFault,
) -> Fixture {
    synthetic_fixture_with_options(
        substitute_bucket_spec,
        corrupt_fidelity_root,
        result_fault,
        257,
    )
}

fn synthetic_fixture_with_tribute_count(tribute_count: u32) -> Fixture {
    synthetic_fixture_with_options(false, false, ResultCatalogFault::None, tribute_count)
}

fn synthetic_fixture_with_options(
    substitute_bucket_spec: bool,
    corrupt_fidelity_root: bool,
    result_fault: ResultCatalogFault,
    tribute_count: u32,
) -> Fixture {
    let limits = poc_schema_limits();
    let list_limits = poc_input_list_limits();
    let bundle = support::protocol_bundle();
    let bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let pinned_bundle = PinnedProtocolBundle::decode(
        &bundle.encode_canonical(&limits).unwrap(),
        bundle_hash,
        &limits,
    )
    .unwrap();
    let job_id = hash(0x30);
    let day = WorldwideDay::new(20_260_725);

    let mut tributes = (0..tribute_count)
        .map(|index| {
            let mut owner_bytes = [0_u8; 20];
            owner_bytes[16..].copy_from_slice(&(index + 1).to_be_bytes());
            let owner = Address::from(owner_bytes);
            TributeBodyV1 {
                tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
                owner,
                worldwide_day: day,
                issuance_amount_minor: U256::from(1),
                issuance_currency: if index % 2 == 0 { 840 } else { 826 },
                nominal_amount_minor: U256::from((index % 7) + 1),
                reference_currency: if index % 3 == 0 { 978 } else { 392 },
                tribute_price_minor: U256::from(1),
                exclude_from_intex_issuance: false,
            }
        })
        .collect::<Vec<_>>();
    tributes.sort_by_key(|tribute| tribute.tribute_id);
    let mut contributors_by_owner = tributes
        .iter()
        .map(|tribute| ContributorActionV1 {
            owner: tribute.owner,
            source_tribute_id: *tribute.tribute_id,
            nominal_amount_minor: tribute.nominal_amount_minor,
        })
        .collect::<Vec<_>>();
    contributors_by_owner
        .sort_by_key(|contributor| (contributor.owner, contributor.source_tribute_id));
    if result_fault == ResultCatalogFault::ContributorBoundary {
        contributors_by_owner.swap(255, 256);
    }
    let mut nod_action_tributes = tributes.clone();
    if result_fault == ResultCatalogFault::NodBoundary {
        nod_action_tributes.swap(255, 256);
    }
    let owners = tributes
        .iter()
        .map(|tribute| tribute.owner)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut reference_isos = tributes
        .iter()
        .map(|tribute| tribute.reference_currency)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    reference_isos.push(840);
    reference_isos.sort_unstable();
    reference_isos.dedup();
    let finalized_state_root = hash(0x32);
    let raw_opening = |address, slot_byte| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: hash(slot_byte),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let mut fidelity_openings = Vec::new();
    let mut oracle_opening = None;
    for subjects in partition_lysis_opening_subjects(&owners, &reference_isos, &limits).unwrap() {
        let openings = materialize_authenticated_openings(
            &LysisOpeningsProofV1 {
                protocol_bundle_hash: bundle_hash,
                job_id,
                finalized_block_hash: hash(0x31),
                finalized_state_root,
                wwd: day.value(),
                subjects,
                fidelity: raw_opening(Address::repeat_byte(0x63), 0x64),
                oracle: raw_opening(Address::repeat_byte(0x65), 0x66),
            },
            &bundle,
            &limits,
        )
        .unwrap();
        fidelity_openings.push(openings.fidelity);
        match &oracle_opening {
            None => oracle_opening = Some(openings.oracle),
            Some(existing) => assert_eq!(existing, &openings.oracle),
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let cas_root = directory.path().join("cas");
    let input_ref_root = directory.path().join("input-refs");
    let admission_root = directory.path().join("admissions");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::Supervisor, CAS_LIMITS).unwrap();
    let published = publish_input_artifact_set(
        &cas,
        &input_ref_root,
        &bundle,
        InputArtifactContents {
            identity: InputArtifactIdentity {
                job_id,
                attempt: 0,
                checkpoint: CheckpointIdentityV1 {
                    finalized_block_number: 90,
                    finalized_block_hash: hash(0x31),
                    finalized_state_root,
                    finalized_ce_root: hash(0x33),
                    ce_schema_version: 1,
                },
                wwd: day.value(),
                sealed_tribute_collection_key: hash(0x34),
                sealed_tribute_collection_root: hash(0x35),
            },
            canonical_tributes: tributes
                .iter()
                .map(|tribute| encode_tribute_v1(tribute).unwrap())
                .collect(),
            fidelity_openings,
            oracle_opening: oracle_opening.unwrap(),
        },
        &limits,
        list_limits,
    )
    .unwrap();
    let mut manifest = InputManifestV1::decode_canonical(
        cas.read_verified(&published.manifest_ref).unwrap().bytes(),
        &limits,
    )
    .unwrap();
    let input_refs_for_plan = VerifiedInputChunkRefCatalog::open(
        &input_ref_root,
        &cas,
        &published.manifest_ref,
        limits,
        list_limits,
    )
    .unwrap();
    let all_input_refs = input_refs_for_plan
        .exact_cursor()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tribute_refs = all_input_refs
        .iter()
        .filter(|reference| reference.kind == InputChunkKind::Tribute)
        .cloned()
        .collect::<Vec<_>>();
    drop(input_refs_for_plan);
    let (manifest_ref, selected_input_ref_root) = if corrupt_fidelity_root {
        manifest.fidelity_opening_root = hash(0xee);
        let mut manifest_ref = cas
            .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
            .unwrap();
        manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
        let selected_input_ref_root = directory.path().join("input-refs-corrupt-root");
        let mut catalog = VerifiedInputChunkRefCatalog::open(
            &selected_input_ref_root,
            &cas,
            &manifest_ref,
            limits,
            list_limits,
        )
        .unwrap();
        for reference in &all_input_refs {
            catalog.admit(reference).unwrap();
        }
        catalog.exact_cursor().unwrap().for_each(|item| {
            item.unwrap();
        });
        drop(catalog);
        (manifest_ref, selected_input_ref_root)
    } else {
        (published.manifest_ref, input_ref_root)
    };

    let planner = LysisPlannerV1::new(LysisPlannerBindingsV1 {
        protocol_bundle_hash: bundle_hash,
        job_id,
        attempt: 0,
        input_manifest_hash: manifest.manifest_hash(&limits).unwrap(),
        input_manifest_encoded_bytes: manifest_ref.encoded_bytes,
        fidelity_opening_root: manifest.fidelity_opening_root,
        oracle_opening_root: manifest.oracle_opening_root,
        wwd: manifest.wwd,
        lysis_budget: U256::from(200),
        logical_evaluation_time: 1_784_765_900,
        tribute_count: manifest.tribute_count,
        lysis_program_semantics_hash: bundle.lysis_program_semantics_hash,
        planner_spec_version: bundle.planner_spec_version,
        reducer_spec_version: bundle.reducer_spec_version,
    })
    .unwrap();
    let plan = planner
        .commit_primary_catalog(tribute_refs.clone(), &limits)
        .unwrap();
    let plan_ref = cas
        .publish_bytes(&plan.encode_canonical_record(&limits).unwrap())
        .unwrap();

    let reader = FilesystemCasReader::open(&cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &selected_input_ref_root,
        &reader,
        limits,
        list_limits,
    )
    .unwrap();
    let mut admissions =
        VerifiedAdmissionCatalog::open(&admission_root, &cas, &plan_ref, &manifest_ref, limits)
            .unwrap();
    let topology = LysisPlanTopologyV1::new(plan.primary_work_unit_count).unwrap();
    let target_ordinal = topology.phase_offset(UnitPhase::BucketShuffle).unwrap()
        + topology.phase_unit_count(UnitPhase::BucketShuffle)
        - 1;
    let plan_hash = plan.plan_hash(&limits).unwrap();
    let mut result_chunk_refs = Vec::new();

    for plan_ordinal in 0..topology.total_unit_count() {
        let mut spec = {
            let audit = LocalLysisPlanAuditV1::open(
                &admissions,
                &input_refs,
                &reader,
                &pinned_bundle,
                &limits,
            )
            .unwrap();
            audit.candidate_spec_at(plan_ordinal).unwrap()
        };
        if substitute_bucket_spec && plan_ordinal == target_ordinal {
            let producer = spec
                .canonical_ordered_inputs
                .get_mut(1)
                .expect("merged Bucket spec has producer input");
            producer.source_id = hash(0xf1);
            spec.validate_semantics(&limits).unwrap();
        }
        let (artifact, result_entry) = match topology.plan_position_at(plan_ordinal).unwrap() {
            PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::RootReduce,
                level: 0,
                index,
            } => {
                let start = usize::try_from(index * 256).unwrap();
                let end = (start + 256).min(tributes.len());
                let actions = nod_action_tributes[start..end]
                    .iter()
                    .enumerate()
                    .map(|(local, tribute)| {
                        let tribute_id = *tribute.tribute_id;
                        NodActionV1 {
                            raw_ordinal: u32::try_from(start + local).unwrap(),
                            tribute_id,
                            nod_id: tribute_id,
                            owner: tribute.owner,
                            wwd: day.value(),
                            league_id: 1,
                            floor_price_minor: U256::ZERO,
                            gratis_load_minor: U256::from(1),
                            entry_price_minor: U256::ZERO,
                            cost_amount_minor: if result_fault
                                == ResultCatalogFault::AlternateResultChunk
                                && index == 0
                                && local == 0
                            {
                                U256::from(3)
                            } else {
                                U256::from(2)
                            },
                            issuance_currency: tribute.issuance_currency,
                            reference_currency: tribute.reference_currency,
                            issued_at: 1_784_765_900,
                            bucket_key: hash(u8::try_from(local % 251).unwrap()),
                        }
                    })
                    .collect::<Vec<_>>();
                let contributors = contributors_by_owner[start..end].to_vec();
                let chunk = ResultChunkV1 {
                    protocol_bundle_hash: bundle_hash,
                    job_id,
                    attempt: 0,
                    chunk_ordinal: index,
                    first_nod_ordinal: u32::try_from(start).unwrap(),
                    ordered_nod_actions: actions.clone(),
                    ordered_eligible_contributors: contributors.clone(),
                };
                let chunk_hash = chunk.result_chunk_hash(&limits).unwrap();
                let mut chunk_ref = cas
                    .publish_bytes(&chunk.encode_canonical(&limits).unwrap())
                    .unwrap();
                chunk_ref.expected_ocb1_kind = Some(ObjectKind::ResultChunkV1.tag());
                result_chunk_refs.push(chunk_ref.clone());
                let entry = OutputManifestEntryV1 {
                    chunk_ordinal: index,
                    result_chunk_hash: chunk_hash,
                    result_chunk_ref: chunk_ref,
                };
                let nod_records = actions
                    .iter()
                    .map(|action| action.encode_canonical_record(&limits).unwrap())
                    .collect::<Vec<_>>();
                let bucket_records = (start..end)
                    .map(|ordinal| ordinal.to_be_bytes().to_vec())
                    .collect::<Vec<_>>();
                let contributor_records = contributors
                    .iter()
                    .map(|contributor| contributor.encode_canonical_record(&limits).unwrap())
                    .collect::<Vec<_>>();
                let manifest_records = vec![entry.encode_canonical_record(&limits).unwrap()];
                let chunk_hash_records = vec![chunk_hash.as_slice().to_vec()];
                let count = u32::try_from(end - start).unwrap();
                let raw_nominal_total = tributes[start..end]
                    .iter()
                    .fold(U256::ZERO, |total, tribute| {
                        total.checked_add(tribute.nominal_amount_minor).unwrap()
                    });
                let nod_cost_total = actions.iter().fold(U256::ZERO, |total, action| {
                    total.checked_add(action.cost_amount_minor).unwrap()
                });
                let mut summary = RootReduceSummaryV1 {
                    protocol_bundle_hash: bundle_hash,
                    job_id,
                    attempt: 0,
                    plan_hash,
                    covered_primary_start: index,
                    covered_primary_count: 1,
                    nod_actions: LysisListSubtreeCarrierV1::from_primary_page(
                        ListKind::NodActions,
                        index,
                        &nod_records,
                        limits.max_bounded_bytes,
                    )
                    .unwrap(),
                    bucket_records: LysisListSubtreeCarrierV1::from_primary_page(
                        ListKind::BucketRecords,
                        index,
                        &bucket_records,
                        limits.max_bounded_bytes,
                    )
                    .unwrap(),
                    contributor_actions: LysisListSubtreeCarrierV1::from_primary_page(
                        ListKind::ContributorActions,
                        index,
                        &contributor_records,
                        limits.max_bounded_bytes,
                    )
                    .unwrap(),
                    output_manifest_entries: LysisListSubtreeCarrierV1::from_primary_page(
                        ListKind::CompleteOutputManifest,
                        index,
                        &manifest_records,
                        limits.max_bounded_bytes,
                    )
                    .unwrap(),
                    result_chunk_hashes: LysisListSubtreeCarrierV1::from_primary_page(
                        ListKind::ResultChunkHashes,
                        index,
                        &chunk_hash_records,
                        B256::len_bytes(),
                    )
                    .unwrap(),
                    tribute_count: count,
                    nod_count: count,
                    bucket_count: count,
                    contributor_count: u32::try_from(contributors.len()).unwrap(),
                    tribute_nominal_total: raw_nominal_total,
                    eligible_nominal_total: raw_nominal_total,
                    nod_gratis_consumed: U256::from(count),
                    nod_cost_total,
                    first_error_ordinal: None,
                };
                if index == 1 {
                    match result_fault {
                        ResultCatalogFault::ContributorCarrier => {
                            summary.contributor_actions.tree_root = hash(0xed);
                        }
                        ResultCatalogFault::EligibleTotal => {
                            summary.eligible_nominal_total -= U256::from(1);
                        }
                        ResultCatalogFault::None
                        | ResultCatalogFault::HeaderCoverage
                        | ResultCatalogFault::ContributorBoundary
                        | ResultCatalogFault::NodBoundary
                        | ResultCatalogFault::AlternateResultChunk => {}
                    }
                }
                let coverage_root = summary.result_chunk_hashes.tree_root;
                let output_coverage_root =
                    if result_fault == ResultCatalogFault::HeaderCoverage && index == 1 {
                        hash(0xec)
                    } else {
                        coverage_root
                    };
                (
                    UnitArtifactV1::from_canonical_output(
                        &spec,
                        WorkOutputHeaderV1 {
                            source_coverage_root: coverage_root,
                            output_coverage_root,
                            source_coverage_count: 1,
                            output_coverage_count: 1,
                        },
                        BoundedBytes(
                            encode_root_reduce_output(
                                &RootReduceOutputV1::Leaf {
                                    summary,
                                    output_manifest_entry: entry.clone(),
                                },
                                &limits,
                            )
                            .unwrap(),
                        ),
                        &limits,
                    )
                    .unwrap(),
                    Some(entry),
                )
            }
            _ => (
                UnitArtifactV1::from_canonical_output(
                    &spec,
                    WorkOutputHeaderV1 {
                        source_coverage_root: hash(0xa1),
                        output_coverage_root: hash(0xa2),
                        source_coverage_count: 1,
                        output_coverage_count: 1,
                    },
                    BoundedBytes(vec![0x42]),
                    &limits,
                )
                .unwrap(),
                None,
            ),
        };
        let mut artifact_ref = cas
            .publish_bytes(&artifact.encode_canonical(&limits).unwrap())
            .unwrap();
        artifact_ref.expected_ocb1_kind = Some(ObjectKind::UnitArtifactV1.tag());
        admissions
            .admit_verified_unit(
                AdmissionPositionV1 { plan_ordinal },
                &spec,
                artifact_ref,
                result_entry,
            )
            .unwrap();
    }
    drop(admissions);
    drop(input_refs);
    drop(reader);
    drop(cas);

    Fixture {
        _directory: directory,
        cas_root,
        input_ref_root: selected_input_ref_root,
        admission_root,
        limits,
        bundle: pinned_bundle,
        target_ordinal,
        expected_count: topology.total_unit_count(),
        result_chunk_refs,
    }
}

fn result_catalog_error_for_fault(fault: ResultCatalogFault) -> LysisResultCatalogError {
    let fixture = synthetic_fixture_with_result_fault(false, false, fault);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    loop {
        match cursor.next() {
            Some(Ok(LysisResultCatalogStepV1::Complete)) => {
                panic!("faulted result catalog must not complete")
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return error,
            None => panic!("faulted result catalog must fail"),
        }
    }
}

#[test]
fn cold_restart_rejects_a_self_consistent_artifact_for_the_wrong_plan_spec() {
    let fixture = synthetic_fixture(true, false);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let error = audit
        .audit_cursor()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_err();
    assert!(matches!(
        error,
        ExactLysisPlanError::UnexpectedUnitId { plan_ordinal }
            if plan_ordinal == fixture.target_ordinal
    ));
}

#[test]
fn cold_restart_streams_the_complete_exact_plan_when_every_spec_matches() {
    let fixture = synthetic_fixture(false, false);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let mut cursor = audit.audit_cursor().unwrap();
    let first = cursor.next().unwrap().unwrap();
    assert_eq!(
        first,
        LysisPlanAuditStepV1::InputChecked {
            ordinal: 0,
            kind: InputChunkKind::Tribute,
        }
    );
    let mut steps = vec![first];
    steps.extend(cursor.collect::<Result<Vec<_>, _>>().unwrap());
    assert_eq!(steps.last(), Some(&LysisPlanAuditStepV1::Complete));
    let verified = steps
        .iter()
        .filter_map(|step| match step {
            LysisPlanAuditStepV1::Artifact(artifact) => Some(artifact),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        u32::try_from(verified.len()).unwrap(),
        fixture.expected_count
    );
    for (ordinal, item) in verified.iter().enumerate() {
        assert_eq!(item.plan_ordinal(), u32::try_from(ordinal).unwrap());
        assert_eq!(
            item.artifact().unit_id,
            item.spec().unit_id(&fixture.limits).unwrap()
        );
    }
}

#[test]
fn scheduler_prepares_manifest_bound_two_shard_worker_requests_after_cold_restart() {
    let fixture = synthetic_fixture(false, false);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    assert_eq!(audit.plan().tribute_count, 257);
    assert_eq!(audit.plan().primary_work_unit_count, 2);

    for (ordinal, expected_records) in [(0_u32, 256_usize), (1, 1)] {
        let request = audit.worker_request_at(ordinal).unwrap();
        let spec =
            UnitSpecV1::decode_canonical(&request.canonical_unit_spec.0, &fixture.limits).unwrap();
        assert_eq!(spec.phase, UnitPhase::Enumerate);
        verify_ordered_list_membership(
            ListKind::UnitSpecificationsArtifacts,
            2,
            ordinal,
            &request.canonical_unit_spec.0,
            &request.unit_membership_siblings,
            audit.plan().primary_work_unit_root,
        )
        .unwrap();
        assert_eq!(request.ordered_input_refs.len(), 1);
        let chunk = AuthenticatedInputChunkV1::decode_canonical(
            reader
                .read_verified(&request.ordered_input_refs[0])
                .unwrap()
                .bytes(),
            &fixture.limits,
        )
        .unwrap();
        assert_eq!(chunk.kind, InputChunkKind::Tribute);
        assert_eq!(chunk.canonical_records_or_openings.len(), expected_records);
    }

    let topology = LysisPlanTopologyV1::new(2).unwrap();
    let fidelity_request = audit
        .worker_request_at(topology.phase_offset(UnitPhase::FidelityMap).unwrap())
        .unwrap();
    assert!(fidelity_request.unit_membership_siblings.is_empty());
    assert_eq!(
        fidelity_request.ordered_input_refs[0].expected_ocb1_kind,
        Some(ObjectKind::UnitArtifactV1.tag())
    );
    assert!(fidelity_request.ordered_input_refs[1..]
        .iter()
        .all(|reference| reference.expected_ocb1_kind
            == Some(ObjectKind::AuthenticatedInputChunkV1.tag())));
    assert!(
        fidelity_request.ordered_input_refs.len() >= 3,
        "FidelityMap receives its producer, shard, bounded lookahead and Fidelity openings"
    );
    let fidelity_authenticated = fidelity_request.ordered_input_refs[1..]
        .iter()
        .map(|reference| {
            AuthenticatedInputChunkV1::decode_canonical(
                reader.read_verified(reference).unwrap().bytes(),
                &fixture.limits,
            )
            .unwrap()
            .kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        &fidelity_authenticated[..2],
        &[InputChunkKind::Tribute, InputChunkKind::Tribute]
    );

    let amount_request = audit
        .worker_request_at(topology.phase_offset(UnitPhase::AmountMap).unwrap())
        .unwrap();
    assert_eq!(
        amount_request.ordered_input_refs[..3]
            .iter()
            .filter(|reference| {
                reference.expected_ocb1_kind == Some(ObjectKind::UnitArtifactV1.tag())
            })
            .count(),
        3
    );
    let authenticated = amount_request.ordered_input_refs[3..]
        .iter()
        .map(|reference| {
            AuthenticatedInputChunkV1::decode_canonical(
                reader.read_verified(reference).unwrap().bytes(),
                &fixture.limits,
            )
            .unwrap()
            .kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        authenticated,
        vec![
            InputChunkKind::Tribute,
            InputChunkKind::Tribute,
            InputChunkKind::Oracle
        ]
    );
}

#[test]
fn fidelity_membership_search_reports_bounded_progress_before_the_next_input_chunk() {
    let fixture = synthetic_fixture(false, false);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut cursor = audit.audit_cursor().unwrap();
    loop {
        if cursor.next().unwrap().unwrap()
            == (LysisPlanAuditStepV1::InputChecked {
                ordinal: 2,
                kind: InputChunkKind::Fidelity,
            })
        {
            break;
        }
    }

    let mut checked_owners = 0_usize;
    let mut search_probes = 0_usize;
    loop {
        match cursor.next().unwrap().unwrap() {
            LysisPlanAuditStepV1::FidelityOwnerMembershipProbe { .. } => {
                search_probes += 1;
            }
            LysisPlanAuditStepV1::FidelityOwnerMembershipChecked { .. } => {
                checked_owners += 1;
            }
            LysisPlanAuditStepV1::InputChecked {
                ordinal: 3,
                kind: InputChunkKind::Fidelity,
            } => break,
            other => panic!("unexpected audit progress before the next Fidelity input: {other:?}"),
        }
    }
    assert_eq!(checked_owners, 256);
    assert!(search_probes > 0);
}

#[test]
fn cold_restart_rejects_manifest_opening_roots_not_derived_from_the_cas_inputs() {
    let fixture = synthetic_fixture(false, true);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let mut artifact_was_released = false;
    let mut cursor = audit.audit_cursor().unwrap();
    let error = loop {
        match cursor.next() {
            Some(Ok(LysisPlanAuditStepV1::Artifact(_))) => artifact_was_released = true,
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("corrupt Fidelity root must prevent exact closure"),
        }
    };
    assert!(!artifact_was_released);
    assert!(matches!(error, ExactLysisPlanError::AuthorityMismatch(_)));
}

#[test]
fn exact_closure_reports_bounded_progress_before_rejecting_a_later_catalog_tail() {
    let fixture = synthetic_fixture(false, false);
    std::fs::write(
        fixture.input_ref_root.join("unexpected-tail"),
        b"not a catalog record",
    )
    .unwrap();
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let mut cursor = audit.audit_cursor().unwrap();
    assert_eq!(
        cursor.next().unwrap().unwrap(),
        LysisPlanAuditStepV1::InputChecked {
            ordinal: 0,
            kind: InputChunkKind::Tribute,
        }
    );
    let error = loop {
        match cursor.next() {
            Some(Ok(LysisPlanAuditStepV1::Artifact(_))) => {
                panic!("input catalog must close before any artifact is released")
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("unexpected catalog tail must prevent exact closure"),
        }
    };
    assert!(matches!(
        error,
        ExactLysisPlanError::InputRef(InputRefCatalogError::UnexpectedCatalogEntry(_))
    ));
}

#[test]
fn cold_restart_streams_exact_result_chunks_only_from_root_reduce_leaves() {
    let fixture = synthetic_fixture(false, false);

    let first = {
        let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
        let input_refs = VerifiedInputChunkRefCatalog::reopen(
            &fixture.input_ref_root,
            &reader,
            fixture.limits,
            poc_input_list_limits(),
        )
        .unwrap();
        let admissions =
            VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits)
                .unwrap();
        let audit = LocalLysisPlanAuditV1::open(
            &admissions,
            &input_refs,
            &reader,
            &fixture.bundle,
            &fixture.limits,
        )
        .unwrap();
        ExactLysisResultCatalogCursorV1::open(&audit)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(
        first.first(),
        Some(&LysisResultCatalogStepV1::RootReduceLeafChecked { chunk_ordinal: 0 })
    );
    assert_eq!(first.last(), Some(&LysisResultCatalogStepV1::Complete));
    let first_chunks = first
        .iter()
        .filter_map(|step| match step {
            LysisResultCatalogStepV1::Chunk(item) => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(first_chunks.len(), 2);
    assert_eq!(
        first_chunks
            .iter()
            .map(|item| item.chunk().ordered_eligible_contributors.len())
            .sum::<usize>(),
        257
    );
    let mut locally_repartitioned = false;
    for (ordinal, item) in first_chunks.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).unwrap();
        assert_eq!(item.output_manifest_entry().chunk_ordinal, ordinal);
        assert_eq!(item.chunk().chunk_ordinal, ordinal);
        assert_eq!(item.summary().covered_primary_start, ordinal);
        assert_eq!(
            ResultChunkV1::decode_canonical(item.canonical_chunk_bytes(), &fixture.limits).unwrap(),
            *item.chunk()
        );
        let chunk_eligible = item
            .chunk()
            .ordered_eligible_contributors
            .iter()
            .fold(U256::ZERO, |total, contributor| {
                total.checked_add(contributor.nominal_amount_minor).unwrap()
            });
        locally_repartitioned |= chunk_eligible != item.summary().eligible_nominal_total;
    }
    assert!(locally_repartitioned);

    let restarted = {
        let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
        let input_refs = VerifiedInputChunkRefCatalog::reopen(
            &fixture.input_ref_root,
            &reader,
            fixture.limits,
            poc_input_list_limits(),
        )
        .unwrap();
        let admissions =
            VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits)
                .unwrap();
        let audit = LocalLysisPlanAuditV1::open(
            &admissions,
            &input_refs,
            &reader,
            &fixture.bundle,
            &fixture.limits,
        )
        .unwrap();
        ExactLysisResultCatalogCursorV1::open(&audit)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(restarted, first);
}

#[test]
fn one_chunk_nod_generation_builds_exact_first_and_final_batch_paths() {
    let fixture = synthetic_fixture_with_tribute_count(10);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let mut root = StreamingOrderedListRoot::new(ListKind::NodActions, 10).unwrap();
    for step in ExactLysisResultCatalogCursorV1::open(&audit).unwrap() {
        if let LysisResultCatalogStepV1::Chunk(chunk) = step.unwrap() {
            for action in &chunk.chunk().ordered_nod_actions {
                root.push(
                    &action.encode_canonical_record(&fixture.limits).unwrap(),
                    fixture.limits.max_bounded_bytes,
                )
                .unwrap();
            }
        }
    }
    let mut head = NodMaterializationHeadV1 {
        queue_sequence: 9,
        job_id: audit.plan().job_id,
        program_semantics_hash: fixture.bundle.bundle().lysis_program_semantics_hash,
        worldwide_day: audit.plan().wwd,
        generation: 1,
        nod_root: root.finish().unwrap(),
        nod_count: 10,
        next_nod_ordinal: 0,
        last_progress_height: 100,
    };

    let first = build_nod_materialization_batch(&audit, &head, 3).unwrap();
    assert_eq!(first.actions.len(), 8);
    assert_eq!(first.root_path.len(), 1);
    outbe_ocomp_protocol::nod_materialization::verify_nod_materialization_batch(
        &first,
        &head,
        3,
        &fixture.limits,
    )
    .expect("first compact batch verifies");

    head.next_nod_ordinal = 8;
    let final_batch = build_nod_materialization_batch(&audit, &head, 3).unwrap();
    assert_eq!(final_batch.actions.len(), 2);
    assert_eq!(final_batch.root_path.len(), 1);
    outbe_ocomp_protocol::nod_materialization::verify_nod_materialization_batch(
        &final_batch,
        &head,
        3,
        &fixture.limits,
    )
    .expect("padded final compact batch verifies");
}

#[test]
fn cold_reloaded_result_catalog_builds_a_verified_nod_proof_across_shards() {
    let fixture = synthetic_fixture(false, false);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    let mut root = StreamingOrderedListRoot::new(ListKind::NodActions, 257).unwrap();
    for step in ExactLysisResultCatalogCursorV1::open(&audit).unwrap() {
        if let LysisResultCatalogStepV1::Chunk(chunk) = step.unwrap() {
            for action in &chunk.chunk().ordered_nod_actions {
                root.push(
                    &action.encode_canonical_record(&fixture.limits).unwrap(),
                    fixture.limits.max_bounded_bytes,
                )
                .unwrap();
            }
        }
    }
    let authority = ActiveNodSetV1 {
        job_id: audit.plan().job_id,
        program_semantics_hash: fixture.bundle.bundle().lysis_program_semantics_hash,
        worldwide_day: audit.plan().wwd,
        generation: 1,
        nod_root: root.finish().unwrap(),
        nod_count: 257,
    };

    let proof = build_certified_nod_proof(&audit, &authority, 256).unwrap();

    let action = proof.verify_against(&authority, &fixture.limits).unwrap();
    assert_eq!(action.raw_ordinal, 256);
}

#[test]
fn addressable_chunk_and_batch_proof_do_not_scan_preceding_chunks() {
    let fixture = synthetic_fixture(false, false);
    let authority = {
        let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
        let input_refs = VerifiedInputChunkRefCatalog::reopen(
            &fixture.input_ref_root,
            &reader,
            fixture.limits,
            poc_input_list_limits(),
        )
        .unwrap();
        let admissions =
            VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits)
                .unwrap();
        let audit = LocalLysisPlanAuditV1::open(
            &admissions,
            &input_refs,
            &reader,
            &fixture.bundle,
            &fixture.limits,
        )
        .unwrap();
        let mut root = StreamingOrderedListRoot::new(ListKind::NodActions, 257).unwrap();
        for step in ExactLysisResultCatalogCursorV1::open(&audit).unwrap() {
            if let LysisResultCatalogStepV1::Chunk(chunk) = step.unwrap() {
                for action in &chunk.chunk().ordered_nod_actions {
                    root.push(
                        &action.encode_canonical_record(&fixture.limits).unwrap(),
                        fixture.limits.max_bounded_bytes,
                    )
                    .unwrap();
                }
            }
        }
        ActiveNodSetV1 {
            job_id: audit.plan().job_id,
            program_semantics_hash: fixture.bundle.bundle().lysis_program_semantics_hash,
            worldwide_day: audit.plan().wwd,
            generation: 1,
            nod_root: root.finish().unwrap(),
            nod_count: 257,
        }
    };

    let first_digest = hex::encode(fixture.result_chunk_refs[0].transport_digest);
    std::fs::remove_file(
        fixture
            .cas_root
            .join("objects")
            .join(&first_digest[..2])
            .join(&first_digest[2..]),
    )
    .unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    assert_eq!(
        verified_result_chunk_at(&audit, 1)
            .unwrap()
            .chunk()
            .chunk_ordinal,
        1
    );
    let head = NodMaterializationHeadV1 {
        queue_sequence: 9,
        job_id: authority.job_id,
        program_semantics_hash: authority.program_semantics_hash,
        worldwide_day: authority.worldwide_day,
        generation: authority.generation,
        nod_root: authority.nod_root,
        nod_count: authority.nod_count,
        next_nod_ordinal: 256,
        last_progress_height: 100,
    };
    let batch = build_nod_materialization_batch(&audit, &head, 3).unwrap();
    assert_eq!(batch.first_nod_ordinal, 256);
    assert_eq!(batch.actions.len(), 1);
    outbe_ocomp_protocol::nod_materialization::verify_nod_materialization_batch(
        &batch,
        &head,
        3,
        &fixture.limits,
    )
    .expect("final partial batch with canonical empty upper siblings");
}

#[test]
fn missing_result_chunk_makes_the_nod_read_unavailable() {
    let fixture = synthetic_fixture(false, false);
    let authority = {
        let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
        let input_refs = VerifiedInputChunkRefCatalog::reopen(
            &fixture.input_ref_root,
            &reader,
            fixture.limits,
            poc_input_list_limits(),
        )
        .unwrap();
        let admissions =
            VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits)
                .unwrap();
        let audit = LocalLysisPlanAuditV1::open(
            &admissions,
            &input_refs,
            &reader,
            &fixture.bundle,
            &fixture.limits,
        )
        .unwrap();
        let mut root = StreamingOrderedListRoot::new(ListKind::NodActions, 257).unwrap();
        for step in ExactLysisResultCatalogCursorV1::open(&audit).unwrap() {
            if let LysisResultCatalogStepV1::Chunk(chunk) = step.unwrap() {
                for action in &chunk.chunk().ordered_nod_actions {
                    root.push(
                        &action.encode_canonical_record(&fixture.limits).unwrap(),
                        fixture.limits.max_bounded_bytes,
                    )
                    .unwrap();
                }
            }
        }
        ActiveNodSetV1 {
            job_id: audit.plan().job_id,
            program_semantics_hash: fixture.bundle.bundle().lysis_program_semantics_hash,
            worldwide_day: audit.plan().wwd,
            generation: 1,
            nod_root: root.finish().unwrap(),
            nod_count: 257,
        }
    };

    let digest_hex = hex::encode(fixture.result_chunk_refs[1].transport_digest);
    let missing_path = fixture
        .cas_root
        .join("objects")
        .join(&digest_hex[..2])
        .join(&digest_hex[2..]);
    std::fs::remove_file(missing_path).unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();

    assert!(matches!(
        build_certified_nod_proof(&audit, &authority, 256),
        Err(NodProofBuildError::Catalog(_))
    ));
}

#[test]
fn result_catalog_latches_failure_when_a_chunk_changes_after_admission() {
    let fixture = synthetic_fixture(false, false);
    let reference = fixture.result_chunk_refs.first().unwrap();
    let encoded = format!("{:x}", reference.transport_digest);
    let digest = encoded.strip_prefix("0x").unwrap_or(&encoded);
    let path = fixture
        .cas_root
        .join("objects")
        .join(&digest[..2])
        .join(&digest[2..]);
    let mut changed = std::fs::read(&path).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, changed).unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    assert_eq!(
        cursor.next().unwrap().unwrap(),
        LysisResultCatalogStepV1::RootReduceLeafChecked { chunk_ordinal: 0 }
    );
    assert!(matches!(
        cursor.next().unwrap(),
        Err(LysisResultCatalogError::Cas(_))
    ));
    assert!(cursor.next().is_none());
}

#[test]
fn result_catalog_rederives_leaf_carriers_from_exact_chunk_bytes() {
    let fixture =
        synthetic_fixture_with_result_fault(false, false, ResultCatalogFault::ContributorCarrier);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    assert!(matches!(
        cursor.next().unwrap().unwrap(),
        LysisResultCatalogStepV1::RootReduceLeafChecked { chunk_ordinal: 0 }
    ));
    assert!(matches!(
        cursor.next().unwrap().unwrap(),
        LysisResultCatalogStepV1::Chunk(_)
    ));
    assert!(matches!(
        cursor.next().unwrap().unwrap(),
        LysisResultCatalogStepV1::RootReduceLeafChecked { chunk_ordinal: 1 }
    ));
    assert!(matches!(
        cursor.next().unwrap(),
        Err(LysisResultCatalogError::Protocol(
            outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
                "result chunk ROOT_REDUCE carrier binding"
            )
        ))
    ));
    assert!(cursor.next().is_none());
}

#[test]
fn result_catalog_compares_repartitioned_eligible_totals_only_after_all_chunks() {
    let error = result_catalog_error_for_fault(ResultCatalogFault::EligibleTotal);
    assert!(matches!(
        error,
        LysisResultCatalogError::Protocol(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
            "global eligible nominal total"
        ))
    ));
}

#[test]
fn result_catalog_binds_root_reduce_output_header_to_the_leaf_summary() {
    let error = result_catalog_error_for_fault(ResultCatalogFault::HeaderCoverage);
    assert!(matches!(
        error,
        LysisResultCatalogError::Protocol(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
            "ROOT_REDUCE leaf output header"
        ))
    ));
}

#[test]
fn result_catalog_rejects_contributor_reordering_across_chunk_boundaries() {
    let error = result_catalog_error_for_fault(ResultCatalogFault::ContributorBoundary);
    assert!(matches!(
        error,
        LysisResultCatalogError::Protocol(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
            "global result contributor order"
        ))
    ));
}

#[test]
fn result_catalog_rejects_nod_tribute_reordering_across_chunk_boundaries() {
    let error = result_catalog_error_for_fault(ResultCatalogFault::NodBoundary);
    assert!(matches!(
        error,
        LysisResultCatalogError::Protocol(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
            "global result Nod TributeId order"
        ))
    ));
}

#[test]
fn result_catalog_decodes_every_admission_before_directory_eof() {
    let fixture = synthetic_fixture(false, false);
    let ordinal = fixture.expected_count - 1;
    let path = fixture
        .admission_root
        .join(format!("{ordinal:010}.admission"));
    let mut changed = std::fs::read(&path).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, changed).unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut chunks = 0_u32;
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    let error = loop {
        match cursor.next() {
            Some(Ok(LysisResultCatalogStepV1::Chunk(_))) => chunks += 1,
            Some(Ok(LysisResultCatalogStepV1::Complete)) => {
                panic!("corrupt non-leaf admission must prevent closure")
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("corrupt non-leaf admission must fail"),
        }
    };
    assert_eq!(chunks, 2);
    assert!(matches!(error, LysisResultCatalogError::Plan(_)));
    assert!(cursor.next().is_none());
}

#[test]
fn result_catalog_rejects_valid_same_ordinal_entry_substitution_between_passes() {
    let fixture = synthetic_fixture(false, false);
    let alternate =
        synthetic_fixture_with_result_fault(false, false, ResultCatalogFault::AlternateResultChunk);
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    let mut first_leaf_plan_ordinal = None;
    let mut chunk_count = 0_u32;
    while chunk_count < 2 {
        match cursor.next().unwrap().unwrap() {
            LysisResultCatalogStepV1::Chunk(item) => {
                first_leaf_plan_ordinal.get_or_insert(item.plan_ordinal());
                chunk_count += 1;
            }
            LysisResultCatalogStepV1::Complete => {
                panic!("admission replay must follow exact chunks")
            }
            _ => {}
        }
    }

    let ordinal = first_leaf_plan_ordinal.unwrap();
    let name = format!("{ordinal:010}.admission");
    std::fs::copy(
        alternate.admission_root.join(&name),
        fixture.admission_root.join(&name),
    )
    .unwrap();
    let error = loop {
        match cursor.next() {
            Some(Ok(LysisResultCatalogStepV1::Complete)) => {
                panic!("same-ordinal entry substitution must prevent closure")
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("same-ordinal entry substitution must fail"),
        }
    };
    assert!(matches!(
        error,
        LysisResultCatalogError::Protocol(outbe_ocomp_protocol::ProtocolError::InvalidInvariant(
            "reloaded result entry content closure"
        ))
    ));
    assert!(cursor.next().is_none());
}

#[test]
fn result_catalog_requires_admission_directory_eof_after_the_last_chunk() {
    let fixture = synthetic_fixture(false, false);
    std::fs::write(
        fixture.admission_root.join("4294967295.admission"),
        b"late extra admission",
    )
    .unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let input_refs = VerifiedInputChunkRefCatalog::reopen(
        &fixture.input_ref_root,
        &reader,
        fixture.limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let admissions =
        VerifiedAdmissionCatalog::reopen(&fixture.admission_root, &reader, fixture.limits).unwrap();
    let audit = LocalLysisPlanAuditV1::open(
        &admissions,
        &input_refs,
        &reader,
        &fixture.bundle,
        &fixture.limits,
    )
    .unwrap();
    let mut chunks = 0_u32;
    let mut cursor = ExactLysisResultCatalogCursorV1::open(&audit).unwrap();
    let error = loop {
        match cursor.next() {
            Some(Ok(LysisResultCatalogStepV1::Chunk(_))) => chunks += 1,
            Some(Ok(LysisResultCatalogStepV1::Complete)) => {
                panic!("late admission must prevent result catalog closure")
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("late admission must fail the result catalog cursor"),
        }
    };
    assert_eq!(chunks, 2);
    assert!(
        matches!(
            error,
            LysisResultCatalogError::Admission(
                outbe_ocomp::admission_catalog::AdmissionCatalogError::UnexpectedAdmission { .. }
            )
        ),
        "unexpected EOF error: {error:?}"
    );
    assert!(cursor.next().is_none());
}
