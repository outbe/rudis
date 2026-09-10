use alloy_primitives::{Address, B256, U256};
use outbe_ocomp_protocol::{
    common::{BoundedBytes, ProofBytes},
    input::{
        authenticated_opening_root, materialize_authenticated_openings, AuthenticatedOpeningV1,
        CheckpointIdentityV1, Compression, InputManifestV1, OpeningSourceKind,
    },
    opening::{
        partition_lysis_opening_subjects, LysisOpeningsProofV1, OpeningSubjectsV1,
        RawContractOpeningProofV1, RawStorageSlotV1, MAX_FIDELITY_OWNERS_PER_OPENING,
    },
    profile::ProtocolBundleV1,
    registry::{FIDELITY_OPENING_CODEC_ID, ORACLE_OPENING_CODEC_ID, TRIBUTE_BODY_CODEC_ID},
    CodecLimits, OrderedListLimits, ProtocolError, SchemaLimits,
};

const LIMITS: SchemaLimits = SchemaLimits {
    codec: CodecLimits::new(1_048_576, 4_096, 2_097_152),
    max_bounded_bytes: 262_144,
    max_proof_bytes: 262_144,
    max_opening_bytes: 262_144,
    max_collection_items: 4_096,
    max_action_items: 4_096,
    max_chunk_items: 4_096,
    max_unit_inputs: 64,
    max_result_chunk_bytes: 524_288,
    max_control_body_bytes: 262_144,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn bundle() -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(1),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(21),
        release_approval_policy_hash: hash(22),
        release_validator_command_artifact_hash: hash(23),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(24),
        required_upgrade_handler_set_hash: hash(25),
    }
}

fn manifest(bundle: &ProtocolBundleV1) -> InputManifestV1 {
    InputManifestV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&LIMITS).unwrap(),
        job_id: hash(30),
        attempt: 1,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 90,
            finalized_block_hash: hash(31),
            finalized_state_root: hash(32),
            finalized_ce_root: hash(33),
            ce_schema_version: 1,
        },
        wwd: 7,
        sealed_tribute_collection_key: hash(34),
        sealed_tribute_collection_root: hash(35),
        tribute_count: 1,
        tribute_nominal_total: U256::from(100),
        input_chunk_count: 3,
        input_chunk_list_root: hash(36),
        fidelity_opening_root: hash(37),
        oracle_opening_root: hash(38),
        exact_encoded_bytes: 1_024,
        exact_record_count: 3,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash().unwrap(),
        compression: Compression::None,
    }
}

#[test]
fn manifest_accepts_only_the_input_codecs_pinned_by_its_bundle() {
    let bundle = bundle();
    let manifest = manifest(&bundle);
    assert_eq!(manifest.validate_against_bundle(&bundle, &LIMITS), Ok(()));

    let mut wrong_body = manifest.clone();
    wrong_body.body_codec_id = hash(0xee);
    assert_eq!(
        wrong_body.validate_against_bundle(&bundle, &LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "input manifest Tribute body codec binding"
        ))
    );

    let mut wrong_openings = manifest;
    wrong_openings.opening_codec_registry_hash = hash(0xef);
    assert_eq!(
        wrong_openings.validate_against_bundle(&bundle, &LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "input manifest opening codec registry binding"
        ))
    );
}

#[test]
fn authenticated_opening_codec_must_match_its_source_kind() {
    let bundle = bundle();
    let mut opening = AuthenticatedOpeningV1 {
        source_kind: OpeningSourceKind::Fidelity,
        canonical_subject_key: BoundedBytes(vec![1]),
        canonical_value: BoundedBytes(vec![2]),
        opening_codec_id: bundle.fidelity_opening_codec_id,
        canonical_opening: BoundedBytes(vec![3]),
    };
    assert_eq!(opening.validate_against_bundle(&bundle, &LIMITS), Ok(()));

    opening.opening_codec_id = bundle.oracle_opening_codec_id;
    assert_eq!(
        opening.validate_against_bundle(&bundle, &LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "authenticated opening source codec binding"
        ))
    );
}

#[test]
fn authenticated_opening_record_has_one_strict_canonical_encoding() {
    let bundle = bundle();
    let opening = AuthenticatedOpeningV1 {
        source_kind: OpeningSourceKind::Oracle,
        canonical_subject_key: BoundedBytes(vec![1]),
        canonical_value: BoundedBytes(vec![2]),
        opening_codec_id: bundle.oracle_opening_codec_id,
        canonical_opening: BoundedBytes(vec![3]),
    };
    let encoded = opening.encode_canonical_record(&LIMITS).unwrap();
    assert_eq!(
        AuthenticatedOpeningV1::decode_canonical_record(&encoded, &LIMITS).unwrap(),
        opening
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        AuthenticatedOpeningV1::decode_canonical_record(&trailing, &LIMITS),
        Err(ProtocolError::TrailingBytes { .. })
    ));
}

fn owner(index: u32) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[16..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

#[test]
fn owner_257_starts_another_bounded_opening_request() {
    assert_eq!(MAX_FIDELITY_OWNERS_PER_OPENING, 256);
    for (owner_count, expected_batch_sizes) in
        [(255, &[255][..]), (256, &[256][..]), (257, &[256, 1][..])]
    {
        let owners = (1..=owner_count).map(owner).collect::<Vec<_>>();
        let requests = partition_lysis_opening_subjects(&owners, &[840], &LIMITS).unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.owners.len())
                .collect::<Vec<_>>(),
            expected_batch_sizes
        );
        assert_eq!(
            requests
                .iter()
                .flat_map(|request| request.owners.iter().copied())
                .collect::<Vec<_>>(),
            owners
        );
        assert!(requests
            .iter()
            .all(|request| request.reference_isos == [840]));
    }
}

#[test]
fn aggregate_node_proof_materializes_source_specific_records_and_roots() {
    let bundle = bundle();
    let subjects = OpeningSubjectsV1 {
        owners: vec![owner(1)],
        reference_isos: vec![840],
    };
    let raw = |contract_address, slot| RawContractOpeningProofV1 {
        contract_address,
        state_root: hash(32),
        ordered_slots: vec![RawStorageSlotV1 {
            slot,
            value: U256::from(7),
        }],
        account_proof: ProofBytes(vec![1]),
        storage_proof: ProofBytes(vec![2]),
    };
    let aggregate = LysisOpeningsProofV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&LIMITS).unwrap(),
        job_id: hash(30),
        finalized_block_hash: hash(31),
        finalized_state_root: hash(32),
        wwd: 20_260_724,
        subjects,
        fidelity: raw(Address::repeat_byte(0xf1), hash(40)),
        oracle: raw(Address::repeat_byte(0x01), hash(41)),
    };

    let materialized = materialize_authenticated_openings(&aggregate, &bundle, &LIMITS).unwrap();
    assert_eq!(
        materialized.fidelity.opening_codec_id,
        bundle.fidelity_opening_codec_id
    );
    assert_eq!(
        materialized.oracle.opening_codec_id,
        bundle.oracle_opening_codec_id
    );
    assert_eq!(
        &materialized.fidelity.canonical_subject_key.0[..4],
        &1_u32.to_be_bytes()
    );
    assert_eq!(
        &materialized.oracle.canonical_subject_key.0[..6],
        &[1, 53, 39, 116, 0, 1]
    );

    let list_limits = OrderedListLimits::new(16, 262_144, 1_024);
    let fidelity_root = authenticated_opening_root(
        OpeningSourceKind::Fidelity,
        &[materialized.fidelity],
        &bundle,
        &LIMITS,
        list_limits,
    )
    .unwrap();
    let oracle_root = authenticated_opening_root(
        OpeningSourceKind::Oracle,
        &[materialized.oracle],
        &bundle,
        &LIMITS,
        list_limits,
    )
    .unwrap();
    assert_ne!(fidelity_root, oracle_root);
}
