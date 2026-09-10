use alloy_primitives::{keccak256, Address, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use outbe_ocomp_protocol::{
    abi::{
        GET_ACTIVE_LYSIS_GENERATION_SELECTOR, GET_LYSIS_TERMINAL_RECEIPT_SELECTOR,
        GET_OFFCHAIN_JOB_SELECTOR, LYSIS_ACTIVATED_TOPIC0, OCOMP_ACTIVATION_REJECTED_SELECTOR,
        OCOMP_EXPIRED_TOPIC0, OCOMP_REQUESTED_TOPIC0, SUBMIT_LYSIS_RESULT_SELECTOR,
    },
    activation::{ActivationCallCoreV1, SignOncePurpose, SignOnceRecordV1},
    codec::CodecLimits,
    committee::{
        validator_identity_hash_v1, verify_low_s_prehash, OcompKeyRegistrationCoreV1,
        OcompKeyRegistrationV1, RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    common::{BoundedBytes, ProofBytes},
    control::{
        BuildFinalizedIntentProofV1, BuildLysisOpeningsV1, CheckProjectionContainmentV1,
        CommitSnapshotExportV1, FinalizedIntentProofResponseV1, FinalizedJobSpecV1,
        FinalizedJobSummaryV1, GetJobSpecV1, GetSnapshotHandoffV1, ListFinalizedJobsResponseV1,
        ListFinalizedJobsV1, ListSnapshotHandoffsResponseV1, ListSnapshotHandoffsV1,
        OpenSnapshotLeaseV1, PreparedVoteTransactionV1, ProjectionCheckpointV1,
        ProjectionContainedV1, RenewSnapshotLeaseV1, RunUnitV1, SnapshotExportCommittedV1,
        SnapshotHandoffV1, SnapshotLeaseOpenedV1, MAX_FINALIZED_JOBS_PER_RESPONSE,
        MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE, SNAPSHOT_LEASE_WIRE_BYTES,
    },
    hash::hash_framed,
    input::{CheckpointIdentityV1, Compression, InputManifestV1},
    intent::{
        ActivationPreconditionsV1, CertifiedParentAccountingMetadataV2,
        ContributorTargetPreconditionV1, DayType, FinalizedIntentProofV1, FrozenMetadosisValuesV1,
        JobIntentV1, MetadosisAttemptPreconditionV1, MetadosisExpectedStatus,
        NodTargetPreconditionV1, ParentProofKind, PreAdmissionEnvelopeV1, TributeInputBindingV1,
    },
    opening::OpeningSubjectsV1,
    profile::{CapacityProfileV1, CorrectnessProfileV1, ProgramId, ProtocolBundleV1},
    receipts::{
        apply_event_summary_hash, desis_request_brief_hash, empty_apply_event_summary_hash,
        ActivationOutcome, AggregateActivationReceiptV1, BudgetSplitDestination,
        CarryOverReceiptV1, ContributorReceiptV1, EffectBindingV1, NodBatchReceiptV1,
        RequestBudgetSplitReceiptV1, TributeReceiptV1,
    },
    registry::{HashDomain, ListKind, ObjectKind},
    result::{
        lysis_v1_empty_semantic_event_root, ActivationPayloadV1, CarryOverCreditActionV1,
        CarryOverReason, CompletionStatus, ConservationTotalsV1, ExactCountsV1,
        LysisArithmeticSummaryV1, LysisResultV1, MetadosisCompletionSummaryV1, ResultChunkV1,
        ResultRootsV1,
    },
    shuffle::{ShufflePageSpanV1, ShuffleRunArtifactV1, ShuffleRunKindV1, ShuffleRunPayloadV1},
    state::{
        ActiveGenerationV1, LysisTerminalV1, OcompFinalizedJobV1, OcompJobRecordV1, OcompJobStatus,
        OcompTerminalOutcome,
    },
    system_carrier::{
        classify_ocomp_system_carrier, OcompSystemCarrierCandidate, OcompSystemCarrierError,
        OcompSystemCarrierView, MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES,
        MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS, OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
    },
    unit::{
        BinaryReducerNode, EntityIdHalfOpenRange, PlanCommitmentV1, UnitArtifactV1, UnitInterval,
        UnitPhase, UnitSpecV1, WorkOutputHeaderV1,
    },
    vote::{
        decode_submit_lysis_result, decode_submit_lysis_result_prefix, EquivocationEvidenceV1,
        OcompAccountabilitySummaryV1, OcompQuorumV1, OcompVoteAccountabilityV1,
        RecordVoteOutcomeV1, ResultVoteSigningSubjectV1, ResultVoteSlotV1, ResultVoteV1,
    },
    ProtocolError, SchemaLimits,
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

#[derive(Clone)]
struct TestMember {
    ocomp_public_key_sec1: [u8; 33],
    key_epoch: u64,
}

#[derive(Clone)]
struct TestCommittee {
    snapshot_epoch: u64,
    ordered_members: Vec<TestMember>,
}

impl TestCommittee {
    fn snapshot_hash(&self, _limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        Ok(hash(46))
    }
}

fn bundle() -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(1),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: outbe_ocomp_protocol::registry::TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: outbe_ocomp_protocol::registry::FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: outbe_ocomp_protocol::registry::ORACLE_OPENING_CODEC_ID,
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

fn preconditions() -> ActivationPreconditionsV1 {
    ActivationPreconditionsV1 {
        tribute: TributeInputBindingV1 {
            wwd: 7,
            source_generation: 3,
            collection_key: hash(30),
            sealed_collection_root: hash(31),
            exact_count: 1,
            exact_nominal_total: U256::ZERO,
        },
        nod: NodTargetPreconditionV1 {
            wwd: 7,
            target_generation: 5,
            namespace_root_before: hash(32),
            max_nod_count: 1,
        },
        contributors: ContributorTargetPreconditionV1 {
            worldwide_day: 7,
            expected_series_version: 8,
            max_contributor_count: 1,
            max_eligible_nominal_total: U256::ZERO,
        },
        metadosis: MetadosisAttemptPreconditionV1 {
            wwd: 7,
            pending_nonce: 0,
            expected_status: MetadosisExpectedStatus::OffchainPending,
            state_version: 12,
        },
    }
}

fn intent() -> JobIntentV1 {
    JobIntentV1 {
        chain_id: 42,
        genesis_hash: hash(40),
        fork_id: hash(1),
        wwd: 7,
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash: hash(41),
        ce_sealed_root: hash(42),
        sealed_tribute_collection_key: hash(30),
        sealed_tribute_collection_root: hash(31),
        authenticated_day_count: 1,
        authenticated_day_nominal: U256::ZERO,
        pre_admission_envelope_hash: hash(43),
        source_availability_policy_id: hash(44),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: U256::ZERO,
            previous_vwap: U256::ZERO,
            current_vwap: U256::ZERO,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            auction_entry_prices: vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
                reference_currency: 840,
                entry_price_minor: U256::ZERO,
                source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: 6,
            }],
            request_budget_split_receipt_hash: hash(113),
        },
        logical_evaluation_height: 100,
        logical_evaluation_time: 1_000,
        activation_preconditions: preconditions(),
        result_validator_set_epoch: 1,
        result_committee_set_hash: hash(45),
        result_ocomp_binding_hash: hash(46),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    }
}

#[test]
fn single_attempt_identity_rejects_nonzero_attempt_or_nonce() {
    let first = intent();
    let mut invalid = first.clone();
    invalid.attempt = 1;
    invalid.pending_nonce = 1;
    invalid.activation_preconditions.metadosis.pending_nonce = 1;
    assert!(invalid.validate_semantics().is_err());
    assert!(invalid.input_lease_id().is_err());

    let mut changed_input = first.clone();
    changed_input.sealed_tribute_collection_root = hash(0xa1);
    changed_input
        .activation_preconditions
        .tribute
        .sealed_collection_root = hash(0xa1);
    assert_ne!(
        first.input_lease_id().unwrap(),
        changed_input.input_lease_id().unwrap(),
        "a changed authenticated source root must create a different lease"
    );
}

fn finality_proof() -> FinalizedIntentProofV1 {
    let intent = intent();
    FinalizedIntentProofV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        fork_id: intent.fork_id,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        canonical_request_header_rlp: ProofBytes(vec![1, 2]),
        parent_accounting: CertifiedParentAccountingMetadataV2 {
            finalized_block_number: 90,
            finalized_block_hash: hash(46),
            finalized_epoch: 2,
            finalized_view: 3,
            parent_view: 2,
            ordered_committee: vec![BoundedBytes(vec![1])],
            signer_bitmap: BoundedBytes(vec![1]),
            canonical_commonware_finalization_proof: ProofBytes(vec![2]),
            committee_set_hash: hash(47),
            vrf_material_version: 1,
            vrf_group_public_key_hash: hash(48),
            proof_kind: ParentProofKind::Finalization,
            missed_proposers: Vec::new(),
        },
        historical_committee_membership_proof: ProofBytes(vec![3]),
        canonical_job_intent: BoundedBytes(intent.encode_canonical(&LIMITS).unwrap()),
        intent_account_proof: ProofBytes(vec![4]),
        intent_storage_proof: ProofBytes(vec![5]),
    }
}

fn result() -> LysisResultV1 {
    let carry_over_credit = CarryOverCreditActionV1 {
        source_wwd: 7,
        reason: CarryOverReason::UnusedLysis,
        amount: U256::ZERO,
    };
    let metadosis_completion_summary = MetadosisCompletionSummaryV1 {
        wwd: 7,
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
        logical_evaluation_height: 100,
        logical_evaluation_time: 1_000,
    };
    let roots = ResultRootsV1 {
        nod_root: hash(50),
        bucket_root: hash(51),
        contributor_root: hash(52),
        output_manifest_root: hash(53),
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
        input_manifest_hash: hash(54),
        plan_hash: hash(55),
        unit_artifact_root: hash(56),
        fidelity_fraction_root: hash(57),
        gratis_prefix_root: hash(58),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    let arithmetic_commitment = hash_framed(
        HashDomain::LysisArithmetic,
        &summary.encode_canonical(&LIMITS).unwrap(),
    )
    .unwrap();
    LysisResultV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 1,
        result_chunk_list_root: hash(61),
        carry_over_credit,
        metadosis_completion_summary,
        tribute_count: 1,
        tribute_nominal_total: U256::ZERO,
        unused_lysis: U256::ZERO,
        roots,
        counts,
        conservation,
        arithmetic_commitment,
        event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
    }
}

fn signing_key(index: u8) -> SigningKey {
    SigningKey::from_bytes((&outbe_primitives::test_keys::secret((index + 1) as u64)).into())
        .unwrap()
}

fn compressed_key(key: &SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn sign(key: &SigningKey, digest: B256) -> [u8; 64] {
    let signature: Signature = key.sign_prehash(digest.as_slice()).unwrap();
    signature.to_bytes().into()
}

fn registration(index: u8) -> OcompKeyRegistrationV1 {
    let key = signing_key(index);
    let mut registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id: 42,
            genesis_hash: hash(40),
            validator_identity_hash: hash(70 + index),
            ocomp_public_key_sec1: compressed_key(&key),
            key_epoch: 1,
            allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
        },
        proof_of_possession: [0; 64],
    };
    let digest = registration.proof_of_possession_digest(&LIMITS).unwrap();
    registration.proof_of_possession = sign(&key, digest);
    registration
}

#[test]
fn ocomp_registration_is_validator_identity_bound_not_committee_bound() {
    let key = signing_key(0);
    let mut registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id: 42,
            genesis_hash: hash(40),
            validator_identity_hash: hash(70),
            ocomp_public_key_sec1: compressed_key(&key),
            key_epoch: 1,
            allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
        },
        proof_of_possession: [0; 64],
    };
    let digest = registration.proof_of_possession_digest(&LIMITS).unwrap();
    registration.proof_of_possession = sign(&key, digest);

    registration.validate_proof_of_possession(&LIMITS).unwrap();
    let encoded = registration.encode_canonical(&LIMITS).unwrap();
    assert_eq!(
        OcompKeyRegistrationV1::decode_canonical(&encoded, &LIMITS).unwrap(),
        registration
    );
}

#[test]
fn validator_identity_hash_is_address_and_bls_bound_without_committee_index() {
    let address = Address::repeat_byte(0x11);
    let bls_min_pk = [0x22; 48];
    let identity = validator_identity_hash_v1(address, &bls_min_pk).unwrap();

    assert_eq!(
        identity,
        validator_identity_hash_v1(address, &bls_min_pk).unwrap()
    );
    assert_ne!(
        identity,
        validator_identity_hash_v1(Address::repeat_byte(0x12), &bls_min_pk).unwrap()
    );
    assert_ne!(
        identity,
        validator_identity_hash_v1(address, &[0x23; 48]).unwrap()
    );
}

#[test]
fn vote_signing_subject_binds_all_snapshot_coordinates_and_ocomp_key_hash() {
    let subject = ResultVoteSigningSubjectV1 {
        chain_id: 42,
        genesis_hash: hash(40),
        fork_id: hash(1),
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        result_validator_set_epoch: 7,
        result_committee_set_hash: hash(45),
        result_ocomp_binding_hash: hash(46),
        ocomp_key_hash: hash(49),
        key_epoch: 1,
        purpose: SignOncePurpose::ResultSignature as u8,
        result_digest: hash(60),
    };
    let digest = subject.signing_digest().unwrap();

    for changed in [
        ResultVoteSigningSubjectV1 {
            result_validator_set_epoch: 8,
            ..subject
        },
        ResultVoteSigningSubjectV1 {
            result_committee_set_hash: hash(47),
            ..subject
        },
        ResultVoteSigningSubjectV1 {
            result_ocomp_binding_hash: hash(48),
            ..subject
        },
        ResultVoteSigningSubjectV1 {
            ocomp_key_hash: hash(50),
            ..subject
        },
    ] {
        assert_ne!(changed.signing_digest().unwrap(), digest);
    }
}

#[test]
fn dynamic_accountability_uses_supplied_n_quorum_and_lsb0_bitmaps() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let job_id = hash(59);
    let matching_result = vote_result(job_id, 120);
    let mut accountability = OcompVoteAccountabilityV1::empty(
        job_id,
        finalized_intent.result_validator_set_epoch,
        finalized_intent.result_committee_set_hash,
        finalized_intent.result_ocomp_binding_hash,
        9,
        7,
    )
    .unwrap();

    for validator_index in 0_u16..7 {
        let vote = signed_vote(
            validator_index,
            matching_result.clone(),
            &finalized_intent,
            job_id,
            &snapshot,
        );
        accountability
            .record_verified_vote(
                validator_index,
                &vote,
                106 + u64::from(validator_index),
                &LIMITS,
            )
            .unwrap();
    }
    assert_eq!(
        accountability.quorum.as_ref().unwrap().signer_bitmap,
        vec![0b0111_1111, 0]
    );

    let late_vote = signed_vote(8, matching_result, &finalized_intent, job_id, &snapshot);
    accountability
        .record_verified_vote(8, &late_vote, 114, &LIMITS)
        .unwrap();
    let summary = accountability.close(120, &LIMITS).unwrap();
    assert_eq!(summary.timely_bitmap, vec![0b0111_1111, 0b0000_0001]);
    assert_eq!(summary.missing_bitmap, vec![0b1000_0000, 0]);

    let mut invalid_padding = summary;
    invalid_padding.timely_bitmap[1] |= 0b1000_0000;
    assert!(invalid_padding.validate_semantics().is_err());
}

#[test]
fn submit_result_prefix_decoder_is_canonical_bounded_and_panic_free() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let vote = signed_vote(
        3,
        vote_result(hash(59), 120),
        &finalized_intent,
        hash(59),
        &snapshot,
    );
    let calldata =
        outbe_ocomp_protocol::abi::encode_submit_lysis_result_calldata(&vote, &LIMITS).unwrap();
    let prefix = decode_submit_lysis_result_prefix(&calldata, &LIMITS).unwrap();
    assert_eq!(
        decode_submit_lysis_result(&calldata, &LIMITS).unwrap(),
        vote
    );
    assert_eq!(prefix.protocol_bundle_hash, vote.protocol_bundle_hash);
    assert_eq!(prefix.job_id, vote.job_id);
    assert_eq!(prefix.attempt, vote.attempt);
    assert_eq!(
        prefix.result_validator_set_epoch,
        vote.result_validator_set_epoch
    );
    assert_eq!(
        prefix.result_committee_set_hash,
        vote.result_committee_set_hash
    );
    assert_eq!(
        prefix.result_ocomp_binding_hash,
        vote.result_ocomp_binding_hash
    );
    assert_eq!(prefix.ocomp_key_hash, vote.ocomp_key_hash);
    assert_eq!(prefix.key_epoch, vote.key_epoch);

    for truncated_len in [0, 3, 4, 35, 36, 67, 68, calldata.len() - 1] {
        assert!(decode_submit_lysis_result_prefix(&calldata[..truncated_len], &LIMITS).is_err());
    }
    let mut wrong_offset = calldata.clone();
    wrong_offset[35] = 31;
    assert!(decode_submit_lysis_result_prefix(&wrong_offset, &LIMITS).is_err());

    let mut overflowing_length = calldata.clone();
    overflowing_length[36] = 1;
    assert!(decode_submit_lysis_result_prefix(&overflowing_length, &LIMITS).is_err());

    let oversized_len = usize::try_from(
        outbe_ocomp_protocol::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1.max_result_vote_bytes,
    )
    .unwrap()
        + 1;
    let oversized_padded_len = (oversized_len + 31) & !31;
    let mut oversized = vec![0_u8; 68 + oversized_padded_len];
    oversized[..4].copy_from_slice(&outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR);
    oversized[35] = 32;
    oversized[36..68].copy_from_slice(&U256::from(oversized_len).to_be_bytes::<32>());
    assert!(decode_submit_lysis_result_prefix(&oversized, &LIMITS).is_err());

    let mut non_zero_padding = calldata;
    *non_zero_padding.last_mut().unwrap() = 1;
    assert!(decode_submit_lysis_result_prefix(&non_zero_padding, &LIMITS).is_err());
}

#[test]
fn ocomp_system_carrier_classifier_is_exact_and_fail_closed() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let vote = signed_vote(
        3,
        vote_result(hash(60), 120),
        &finalized_intent,
        hash(60),
        &snapshot,
    );
    let calldata =
        outbe_ocomp_protocol::abi::encode_submit_lysis_result_calldata(&vote, &LIMITS).unwrap();
    let canonical = OcompSystemCarrierView {
        is_eip1559: true,
        to: Some(outbe_ocomp_protocol::abi::METADOSIS_ADDRESS),
        value: U256::ZERO,
        input: &calldata,
        gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        max_fee_per_gas: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: Some(0),
    };

    let candidate = classify_ocomp_system_carrier(canonical, &LIMITS)
        .unwrap()
        .expect("canonical carrier");
    let OcompSystemCarrierCandidate::ResultVote { prefix } = candidate else {
        panic!("vote carrier must remain a vote candidate");
    };
    assert_eq!(prefix.ocomp_key_hash, vote.ocomp_key_hash);
    assert_eq!(prefix.job_id, vote.job_id);

    assert!(matches!(
        classify_ocomp_system_carrier(
            OcompSystemCarrierView {
                gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT - 1,
                ..canonical
            },
            &LIMITS,
        ),
        Err(OcompSystemCarrierError::WrongGasLimit { .. })
    ));
    assert!(matches!(
        classify_ocomp_system_carrier(
            OcompSystemCarrierView {
                max_priority_fee_per_gas: Some(1),
                ..canonical
            },
            &LIMITS,
        ),
        Err(OcompSystemCarrierError::NonZeroPriorityFee)
    ));
    assert!(matches!(
        classify_ocomp_system_carrier(
            OcompSystemCarrierView {
                is_eip1559: false,
                ..canonical
            },
            &LIMITS,
        ),
        Err(OcompSystemCarrierError::NotEip1559)
    ));

    let oversized = vec![0_u8; MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES + 1];
    let mut oversized = oversized;
    oversized[..4].copy_from_slice(&outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR);
    assert!(matches!(
        classify_ocomp_system_carrier(
            OcompSystemCarrierView {
                input: &oversized,
                ..canonical
            },
            &LIMITS,
        ),
        Err(OcompSystemCarrierError::CalldataTooLarge { .. })
    ));

    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            to: Some(Address::ZERO),
            ..canonical
        },
        &LIMITS,
    )
    .unwrap()
    .is_none());
    assert!(matches!(
        classify_ocomp_system_carrier(
            OcompSystemCarrierView {
                input: &outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR,
                ..canonical
            },
            &LIMITS,
        ),
        Err(OcompSystemCarrierError::MalformedVote(_))
    ));
}

fn committee() -> TestCommittee {
    TestCommittee {
        snapshot_epoch: 1,
        ordered_members: (0..4)
            .map(|index| {
                let registration = registration(index);
                TestMember {
                    ocomp_public_key_sec1: registration.core.ocomp_public_key_sec1,
                    key_epoch: registration.core.key_epoch,
                }
            })
            .collect(),
    }
}

fn signed_vote(
    validator_index: u16,
    result: LysisResultV1,
    finalized_intent: &JobIntentV1,
    job_id: B256,
    snapshot: &TestCommittee,
) -> ResultVoteV1 {
    let key = signing_key(u8::try_from(validator_index).unwrap());
    let public_key = key.verifying_key().to_encoded_point(true);
    let mut vote = ResultVoteV1 {
        protocol_bundle_hash: finalized_intent.protocol_bundle_hash,
        job_id,
        attempt: finalized_intent.attempt,
        result_validator_set_epoch: snapshot.snapshot_epoch,
        result_committee_set_hash: finalized_intent.result_committee_set_hash,
        result_ocomp_binding_hash: snapshot.snapshot_hash(&LIMITS).unwrap(),
        ocomp_key_hash: keccak256(public_key.as_bytes()),
        key_epoch: 1,
        result,
        signature_rs: [0; 64],
    };
    let signing_digest = vote.signing_digest(finalized_intent, &LIMITS).unwrap();
    vote.signature_rs = sign(&key, signing_digest);
    vote
}

fn verify_vote(
    vote: &ResultVoteV1,
    finalized_intent: &JobIntentV1,
    job_id: B256,
    snapshot: &TestCommittee,
    inclusion_height: u64,
    open_height: u64,
    deadline_height: u64,
) -> Result<(), ProtocolError> {
    if finalized_intent.result_ocomp_binding_hash != snapshot.snapshot_hash(&LIMITS)? {
        return Err(ProtocolError::InvalidInvariant(
            "test historical snapshot binding",
        ));
    }
    let (_, member) = snapshot
        .ordered_members
        .iter()
        .enumerate()
        .find(|(_, member)| keccak256(member.ocomp_public_key_sec1) == vote.ocomp_key_hash)
        .ok_or(ProtocolError::InvalidInvariant("vote OCOMP key hash"))?;
    vote.verify_historical_member(
        finalized_intent,
        job_id,
        u16::try_from(snapshot.ordered_members.len()).unwrap(),
        member.key_epoch,
        &member.ocomp_public_key_sec1,
        inclusion_height,
        open_height,
        deadline_height,
        &LIMITS,
    )
}

fn vote_result(job_id: B256, result_chunk_root: u8) -> LysisResultV1 {
    let mut result = result();
    result.job_id = job_id;
    result.result_chunk_list_root = hash(result_chunk_root);
    result
}

fn binding() -> EffectBindingV1 {
    EffectBindingV1 {
        intent_id: hash(80),
        job_id: hash(59),
        attempt: 0,
        protocol_bundle_hash: hash(41),
        result_digest: hash(81),
        activation_preconditions_hash: hash(82),
        activation_call_id: hash(83),
    }
}

fn conflict_receipt() -> AggregateActivationReceiptV1 {
    AggregateActivationReceiptV1 {
        binding: binding(),
        outcome: ActivationOutcome::ConflictResolved,
        nod_receipt_hash: None,
        contributor_receipt_hash: None,
        tribute_receipt_hash: None,
        carry_over_receipt_hash: None,
        request_budget_split_receipt_hash: hash(113),
        active_generation_hash: None,
        effect_commitment: hash_framed(HashDomain::Effects, &[]).unwrap(),
        event_summary_hash: empty_apply_event_summary_hash().unwrap(),
        activated_at_height: 101,
        activated_at_time: 1_001,
    }
}

#[test]
fn expired_job_has_no_successor_nonce_or_retry_shape() {
    let intent = intent();
    let finalized_request_block_hash = hash(46);
    let finalized_request_state_root = hash(49);
    let finalized = OcompFinalizedJobV1 {
        job_id: intent
            .job_id(
                finalized_request_block_hash,
                finalized_request_state_root,
                &LIMITS,
            )
            .unwrap(),
        finalized_request_block_hash,
        finalized_request_state_root,
        finality_recorded_height: 102,
        open_height: 106,
        deadline_height: 110,
        quorum: None,
    };
    let record = OcompJobRecordV1 {
        intent,
        intent_height: 100,
        status: OcompJobStatus::Expired,
        finalized: Some(finalized),
        terminal: Some(LysisTerminalV1 {
            outcome: OcompTerminalOutcome::Expired,
            terminal_height: 110,
            terminal_time: 1_100,
            completed_binding: None,
        }),
    };

    record.validate_semantics(&LIMITS).unwrap();
}

macro_rules! assert_round_trip {
    ($value:expr, $type:ty, $kind:ident) => {{
        let value: $type = $value;
        let encoded = value.encode_canonical(&LIMITS).unwrap();
        assert_eq!(
            outbe_ocomp_protocol::decode_envelope(&encoded, LIMITS.codec)
                .unwrap()
                .kind,
            ObjectKind::$kind
        );
        assert_eq!(<$type>::decode_canonical(&encoded, &LIMITS).unwrap(), value);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(<$type>::decode_canonical(&trailing, &LIMITS).is_err());
    }};
}

#[test]
fn every_registered_object_round_trips_and_rejects_trailing_bytes() {
    let correctness = CorrectnessProfileV1 {
        profile_id: hash(90),
        program: ProgramId::LysisV1,
        arithmetic_profile_id: hash(91),
        object_codec_registry_hash: hash(92),
        list_root_scheme_id: hash(93),
        result_signature_profile_id: hash(94),
        finality_verifier_profile_id: hash(95),
    };
    let capacity = CapacityProfileV1 {
        profile_id: hash(96),
        max_tributes_per_work_shard: 32,
        max_workers_per_domain: 4,
        max_intents_per_block: 2,
        max_activations_per_block: 2,
        max_ready_inspections_per_block: 4,
        max_expirations_per_block: 4,
        ready_backoff_blocks: 2,
        max_reference_currencies: 16,
        max_oracle_wwd_pair_entries: 128,
        max_active_scurve_entries: 128,
        result_deadline_blocks: 10,
        source_retention_after_terminal_blocks: 100,
        generated_limits_manifest_hash: hash(97),
    };
    let pre_admission = PreAdmissionEnvelopeV1 {
        chain_id: 42,
        genesis_hash: hash(40),
        fork_id: hash(1),
        wwd: 7,
        sealed_tribute_collection_root: hash(31),
        sealed_tribute_count: 0,
        sealed_tribute_canonical_body_bytes: 0,
        distinct_owner_count: 0,
        distinct_reference_currency_count: 0,
        fidelity_league_snapshot_root: hash(41),
        oracle_wwd_pair_entries_observed: 0,
        active_scurve_entries_observed: 0,
        auction_entry_prices: vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
            reference_currency: 840,
            entry_price_minor: U256::ZERO,
            source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
            source_day: 6,
        }],
        oracle_state_version: 1,
        fidelity_opening_upper_bound: 0,
        oracle_opening_upper_bound: 0,
        input_encoded_bytes_upper_bound: 0,
        output_record_upper_bound: 0,
        result_chunk_bytes_upper_bound: 1_024,
        activation_bytes_upper_bound: 2_048,
        retained_bytes_upper_bound: 4_096,
        correctness_profile_id: hash(90),
        capacity_profile_id: hash(96),
    };
    let manifest = InputManifestV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 90,
            finalized_block_hash: hash(46),
            finalized_state_root: hash(98),
            finalized_ce_root: hash(99),
            ce_schema_version: 1,
        },
        wwd: 7,
        sealed_tribute_collection_key: hash(30),
        sealed_tribute_collection_root: hash(31),
        tribute_count: 1,
        tribute_nominal_total: U256::ZERO,
        input_chunk_count: 1,
        input_chunk_list_root: hash(100),
        fidelity_opening_root: hash(101),
        oracle_opening_root: hash(102),
        exact_encoded_bytes: 1,
        exact_record_count: 1,
        body_codec_id: hash(103),
        opening_codec_registry_hash: hash(104),
        compression: Compression::None,
    };
    let chunk = outbe_ocomp_protocol::input::AuthenticatedInputChunkV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        kind: outbe_ocomp_protocol::input::InputChunkKind::Tribute,
        ordinal: 0,
        canonical_records_or_openings: Vec::new(),
    };
    let unit_spec = UnitSpecV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        phase: UnitPhase::Enumerate,
        interval: UnitInterval::EntityIdRange(EntityIdHalfOpenRange {
            start: B256::from([0; 32]),
            end: Some(B256::from([1; 32])),
        }),
        canonical_ordered_inputs: Vec::new(),
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let unit_artifact = UnitArtifactV1::from_canonical_output(
        &unit_spec,
        WorkOutputHeaderV1 {
            source_coverage_root: hash(108),
            output_coverage_root: hash(109),
            source_coverage_count: 1,
            output_coverage_count: 1,
        },
        BoundedBytes(vec![0xa5]),
        &LIMITS,
    )
    .unwrap();
    let result = result();
    let activation_payload = result.activation_payload(&LIMITS).unwrap();
    let result_digest = result.result_digest(&LIMITS).unwrap();
    let snapshot = committee();
    let proof = finality_proof();
    let mut sign_once = SignOnceRecordV1 {
        chain_id: 42,
        genesis_hash: hash(40),
        fork_id: hash(1),
        purpose: SignOncePurpose::ResultSignature,
        job_id: result.job_id,
        attempt: result.attempt,
        protocol_bundle_hash: result.protocol_bundle_hash,
        result_validator_set_epoch: snapshot.snapshot_epoch,
        result_committee_set_hash: hash(45),
        result_ocomp_binding_hash: snapshot.snapshot_hash(&LIMITS).unwrap(),
        ocomp_key_hash: keccak256(snapshot.ordered_members[0].ocomp_public_key_sec1),
        key_epoch: 1,
        result_digest,
        signature_rs: [0; 64],
    };
    sign_once.signature_rs = sign(&signing_key(0), sign_once.signing_digest().unwrap());
    let activation_call = ActivationCallCoreV1 {
        intent_id: hash(80),
        job_id: result.job_id,
        attempt: result.attempt,
        protocol_bundle_hash: result.protocol_bundle_hash,
        result_digest,
        activation_preconditions_hash: hash(82),
        terminal_pending_nonce: 0,
    };
    let nod_receipt = NodBatchReceiptV1 {
        binding: binding(),
        nod_target_precondition: preconditions().nod,
        nod_count: 0,
        nod_root: result.roots.nod_root,
        nod_amount_total: U256::ZERO,
        nod_gratis_consumed: U256::ZERO,
        issued_at: 1_000,
        state_event_digest: hash(110),
    };
    let contributor_receipt = ContributorReceiptV1 {
        binding: binding(),
        contributor_target_precondition: preconditions().contributors,
        contributor_count: 0,
        contributor_root: result.roots.contributor_root,
        eligible_nominal_total: U256::ZERO,
        state_event_digest: hash(111),
    };
    let tribute_receipt = TributeReceiptV1 {
        binding: binding(),
        tribute_input_binding: preconditions().tribute,
        sealed_collection_root: hash(31),
        consumed_count: 0,
        consumed_nominal_total: U256::ZERO,
        retired_generation: 3,
        state_event_digest: hash(112),
    };
    let request_budget_split_receipt = RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash: hash(41),
        wwd: 7,
        pending_nonce: 0,
        day_type: DayType::Green,
        day_limit: U256::ZERO,
        lysis_budget: U256::ZERO,
        auction_base: U256::ZERO,
        destination: BudgetSplitDestination::DesisAuction,
        desis_brief_hash: Some(hash(113)),
        carry_over_credit: U256::ZERO,
        auction_entry_prices: vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
            reference_currency: 840,
            entry_price_minor: U256::ZERO,
            source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
            source_day: 6,
        }],
        logical_anchor: 10,
    };
    let carry_over_receipt = CarryOverReceiptV1 {
        binding: binding(),
        source_wwd: 7,
        before_value: U256::ZERO,
        credited_unused_lysis: U256::ZERO,
        after_value: U256::ZERO,
        state_event_digest: hash(115),
    };
    let active_generation = ActiveGenerationV1 {
        job_id: result.job_id,
        program_semantics_hash: hash(8),
        nod_root: result.roots.nod_root,
        bucket_root: result.roots.bucket_root,
        contributor_root: result.roots.contributor_root,
        output_manifest_root: result.roots.output_manifest_root,
        exact_counts: result.counts.clone(),
        result_evidence_hash: hash(116),
        availability_certificate_hash: None,
    };
    let aggregate = conflict_receipt();
    let job_intent = intent();
    let finalized_request_block_hash = hash(46);
    let finalized_request_state_root = hash(49);
    let finalized_job = OcompFinalizedJobV1 {
        job_id: job_intent
            .job_id(
                finalized_request_block_hash,
                finalized_request_state_root,
                &LIMITS,
            )
            .unwrap(),
        finalized_request_block_hash,
        finalized_request_state_root,
        finality_recorded_height: 102,
        open_height: 106,
        deadline_height: 110,
        quorum: None,
    };
    let terminal = LysisTerminalV1 {
        outcome: OcompTerminalOutcome::Expired,
        terminal_height: 111,
        terminal_time: 1_100,
        completed_binding: None,
    };
    let job_record = OcompJobRecordV1 {
        intent: job_intent,
        intent_height: 100,
        status: OcompJobStatus::Expired,
        finalized: Some(finalized_job),
        terminal: Some(terminal.clone()),
    };
    let shuffle_run = ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        unit_id: hash(117),
        kind: ShuffleRunKindV1::Owner,
        run_span: outbe_ocomp_protocol::unit::CanonicalRunSpan {
            start_run: 0,
            end_run: 1,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 1,
        },
        first_record_ordinal: 0,
        record_count: 0,
        source_coverage_root: hash(118),
        source_coverage_count: 1,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::OwnerLeaf(Vec::new()),
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap();

    assert_round_trip!(bundle(), ProtocolBundleV1, ProtocolBundleV1);
    assert_round_trip!(correctness, CorrectnessProfileV1, CorrectnessProfileV1);
    assert_round_trip!(capacity, CapacityProfileV1, CapacityProfileV1);
    assert_round_trip!(
        pre_admission,
        PreAdmissionEnvelopeV1,
        PreAdmissionEnvelopeV1
    );
    assert_round_trip!(
        preconditions(),
        ActivationPreconditionsV1,
        ActivationPreconditionsV1
    );
    assert_round_trip!(intent(), JobIntentV1, JobIntentV1);
    assert_round_trip!(proof, FinalizedIntentProofV1, FinalizedIntentProofV1);
    assert_round_trip!(manifest, InputManifestV1, InputManifestV1);
    assert_round_trip!(
        chunk,
        outbe_ocomp_protocol::input::AuthenticatedInputChunkV1,
        AuthenticatedInputChunkV1
    );
    assert_round_trip!(unit_spec, UnitSpecV1, UnitSpecV1);
    assert_round_trip!(unit_artifact, UnitArtifactV1, UnitArtifactV1);
    let result_chunk = ResultChunkV1 {
        protocol_bundle_hash: result.protocol_bundle_hash,
        job_id: result.job_id,
        attempt: result.attempt,
        chunk_ordinal: 0,
        first_nod_ordinal: 0,
        ordered_nod_actions: Vec::new(),
        ordered_eligible_contributors: Vec::new(),
    };
    assert_round_trip!(result_chunk, ResultChunkV1, ResultChunkV1);
    assert_round_trip!(result.clone(), LysisResultV1, LysisResultV1);
    assert_round_trip!(activation_payload, ActivationPayloadV1, ActivationPayloadV1);
    assert_round_trip!(
        registration(0),
        OcompKeyRegistrationV1,
        OcompKeyRegistrationV1
    );
    assert_round_trip!(active_generation, ActiveGenerationV1, ActiveGenerationV1);
    assert_round_trip!(
        aggregate,
        AggregateActivationReceiptV1,
        AggregateActivationReceiptV1
    );
    assert_round_trip!(nod_receipt, NodBatchReceiptV1, NodBatchReceiptV1);
    assert_round_trip!(
        contributor_receipt,
        ContributorReceiptV1,
        ContributorReceiptV1
    );
    assert_round_trip!(tribute_receipt, TributeReceiptV1, TributeReceiptV1);
    assert_round_trip!(
        request_budget_split_receipt,
        RequestBudgetSplitReceiptV1,
        RequestBudgetSplitReceiptV1
    );
    assert_round_trip!(carry_over_receipt, CarryOverReceiptV1, CarryOverReceiptV1);
    assert_round_trip!(sign_once, SignOnceRecordV1, SignOnceRecordV1);
    assert_round_trip!(activation_call, ActivationCallCoreV1, ActivationCallCoreV1);
    assert_round_trip!(
        result.arithmetic_summary(),
        LysisArithmeticSummaryV1,
        LysisArithmeticSummaryV1
    );
    assert_round_trip!(job_record, OcompJobRecordV1, OcompJobRecordV1);
    assert_round_trip!(shuffle_run, ShuffleRunArtifactV1, ShuffleRunArtifactV1);
    assert_round_trip!(terminal, LysisTerminalV1, LysisTerminalV1);
    let mut vote_intent = intent();
    vote_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    vote_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let vote = signed_vote(
        0,
        vote_result(hash(59), 120),
        &vote_intent,
        hash(59),
        &snapshot,
    );
    let vote_digest = vote.result_digest(&LIMITS).unwrap();
    let slot = ResultVoteSlotV1 {
        validator_index: 0,
        first_result_digest: vote_digest,
        key_epoch: vote.key_epoch,
        first_signature_rs: vote.signature_rs,
        submitted_height: 106,
        equivocation: None,
    };
    let equivocation = EquivocationEvidenceV1 {
        conflicting_result_digest: hash(122),
        conflicting_key_epoch: 1,
        conflicting_signature_rs: sign(&signing_key(0), hash(122)),
        submitted_height: 107,
    };
    let quorum = OcompQuorumV1 {
        member_count: 4,
        quorum_threshold: 3,
        result_digest: vote_digest,
        quorum_height: 106,
        signer_bitmap: vec![0b0111],
        evidence_hash: hash(121),
    };
    let summary = OcompAccountabilitySummaryV1 {
        closed_height: 120,
        result_validator_set_epoch: vote_intent.result_validator_set_epoch,
        result_committee_set_hash: vote_intent.result_committee_set_hash,
        result_ocomp_binding_hash: vote_intent.result_ocomp_binding_hash,
        member_count: 4,
        quorum_threshold: 3,
        winning_result_digest: Some(vote_digest),
        quorum_evidence_hash: Some(hash(121)),
        timely_bitmap: vec![0b0111],
        matching_bitmap: vec![0b0111],
        divergent_bitmap: vec![0],
        missing_bitmap: vec![0b1000],
        equivocation_bitmap: vec![0],
    };
    assert_round_trip!(vote, ResultVoteV1, ResultVoteV1);
    assert_round_trip!(equivocation, EquivocationEvidenceV1, EquivocationEvidenceV1);
    assert_round_trip!(slot, ResultVoteSlotV1, ResultVoteSlotV1);
    assert_round_trip!(quorum, OcompQuorumV1, OcompQuorumV1);
    assert_round_trip!(
        summary,
        OcompAccountabilitySummaryV1,
        OcompAccountabilitySummaryV1
    );
    let accountability = OcompVoteAccountabilityV1::empty(
        hash(59),
        vote_intent.result_validator_set_epoch,
        vote_intent.result_committee_set_hash,
        vote_intent.result_ocomp_binding_hash,
        vote_intent.result_member_count,
        vote_intent.result_quorum_threshold,
    )
    .unwrap();
    assert_round_trip!(
        accountability,
        OcompVoteAccountabilityV1,
        OcompVoteAccountabilityV1
    );
}

#[test]
fn direct_result_votes_freeze_supplied_quorum_and_keep_late_accountability_separate() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let job_id = hash(59);
    let matching_result = vote_result(job_id, 120);
    let result_digest = matching_result.result_digest(&LIMITS).unwrap();
    let mut accountability = OcompVoteAccountabilityV1::empty(
        job_id,
        finalized_intent.result_validator_set_epoch,
        finalized_intent.result_committee_set_hash,
        finalized_intent.result_ocomp_binding_hash,
        finalized_intent.result_member_count,
        finalized_intent.result_quorum_threshold,
    )
    .unwrap();

    for validator_index in 0..3 {
        let vote = signed_vote(
            validator_index,
            matching_result.clone(),
            &finalized_intent,
            job_id,
            &snapshot,
        );
        verify_vote(
            &vote,
            &finalized_intent,
            job_id,
            &snapshot,
            106 + u64::from(validator_index),
            106,
            120,
        )
        .unwrap();
        assert_eq!(
            accountability
                .record_verified_vote(
                    validator_index,
                    &vote,
                    106 + u64::from(validator_index),
                    &LIMITS,
                )
                .unwrap(),
            RecordVoteOutcomeV1::FirstVote
        );
    }

    let frozen_quorum = accountability.quorum.clone().unwrap();
    assert_eq!(frozen_quorum.result_digest, result_digest);
    assert_eq!(frozen_quorum.quorum_height, 108);
    assert_eq!(frozen_quorum.signer_bitmap, vec![0b0111]);

    let minority = signed_vote(
        3,
        vote_result(job_id, 121),
        &finalized_intent,
        job_id,
        &snapshot,
    );
    verify_vote(
        &minority,
        &finalized_intent,
        job_id,
        &snapshot,
        109,
        106,
        120,
    )
    .unwrap();
    accountability
        .record_verified_vote(3, &minority, 109, &LIMITS)
        .unwrap();
    assert_eq!(accountability.quorum.as_ref(), Some(&frozen_quorum));

    let equivocation = signed_vote(
        3,
        vote_result(job_id, 122),
        &finalized_intent,
        job_id,
        &snapshot,
    );
    assert_eq!(
        accountability
            .record_verified_vote(3, &equivocation, 110, &LIMITS)
            .unwrap(),
        RecordVoteOutcomeV1::EquivocationRecorded
    );
    assert_eq!(accountability.quorum.as_ref(), Some(&frozen_quorum));

    let summary = accountability.close(120, &LIMITS).unwrap();
    assert_eq!(summary.timely_bitmap, vec![0b1111]);
    assert_eq!(summary.matching_bitmap, vec![0b0111]);
    assert_eq!(summary.divergent_bitmap, vec![0b1000]);
    assert_eq!(summary.missing_bitmap, vec![0]);
    assert_eq!(summary.equivocation_bitmap, vec![0b1000]);
    assert_eq!(accountability.quorum.as_ref(), Some(&frozen_quorum));
}

#[test]
fn committee_and_signatures_fail_closed() {
    let digest = hash(120);

    let invalid_key = [0_u8; 33];
    assert_eq!(
        verify_low_s_prehash(&invalid_key, digest, &[0; 64]),
        Err(ProtocolError::InvalidPublicKey)
    );

    let mut high_s = [0_u8; 64];
    high_s[31] = 1;
    high_s[32..].copy_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ]);
    assert_eq!(
        verify_low_s_prehash(&compressed_key(&signing_key(0)), digest, &high_s),
        Err(ProtocolError::HighSignatureS)
    );
}

#[test]
fn typed_caps_and_semantic_invariants_reject_before_acceptance() {
    let tiny = SchemaLimits {
        codec: CodecLimits::new(1_048_576, 4_096, 2_097_152),
        max_bounded_bytes: 1,
        max_proof_bytes: 1,
        max_opening_bytes: 1,
        max_collection_items: 4,
        max_action_items: 1,
        max_chunk_items: 1,
        max_unit_inputs: 1,
        max_result_chunk_bytes: 1,
        max_control_body_bytes: 1,
    };
    let mut proof = finality_proof();
    proof.canonical_request_header_rlp = ProofBytes(vec![1, 2]);
    assert!(matches!(
        proof.encode_canonical(&tiny),
        Err(ProtocolError::InvalidInvariant("proof byte field cap"))
    ));

    let mut invalid_intent = intent();
    invalid_intent.attempt = 2;
    assert!(matches!(
        invalid_intent.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "single-attempt OCOMP identity"
        ))
    ));

    let mut invalid_result = result();
    invalid_result.counts.nod_count = 0;
    assert!(matches!(
        invalid_result.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("result exact counts"))
    ));
}

#[test]
fn lysis_v1_result_requires_canonical_empty_semantic_event_commitment() {
    let mut valid = result();
    valid.event_summary_hash = lysis_v1_empty_semantic_event_root().unwrap();
    valid.validate_semantics(&LIMITS).unwrap();

    let mut wrong_root = valid.clone();
    wrong_root.event_summary_hash = hash(60);
    assert!(matches!(
        wrong_root.validate_semantics(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "LYSIS_V1 empty semantic event commitment"
        ))
    ));
}

#[test]
fn activation_payload_rejects_a_noncanonical_lysis_event_commitment() {
    let mut payload = result().activation_payload(&LIMITS).unwrap();
    payload.event_summary_hash = hash(60);

    assert!(matches!(
        payload.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "LYSIS_V1 empty semantic event commitment"
        ))
    ));
}

#[test]
fn result_and_apply_empty_event_commitments_use_distinct_frozen_domains() {
    assert_eq!(
        lysis_v1_empty_semantic_event_root().unwrap(),
        hash_framed(
            HashDomain::ListEmpty,
            &ListKind::SemanticEventRecords.id().to_be_bytes(),
        )
        .unwrap()
    );
    assert_eq!(
        empty_apply_event_summary_hash().unwrap(),
        hash_framed(HashDomain::ApplyEventSummary, &[]).unwrap()
    );
    assert_ne!(
        lysis_v1_empty_semantic_event_root().unwrap(),
        empty_apply_event_summary_hash().unwrap()
    );
}

#[test]
fn lysis_completion_is_bound_to_the_finalized_job_intent() {
    let finalized_intent = intent();
    let valid = result();
    valid.validate_finalized_intent(&finalized_intent).unwrap();

    let mut wrong_day = valid.clone();
    wrong_day.metadosis_completion_summary.wwd += 1;
    let mut wrong_nonce = valid.clone();
    wrong_nonce.metadosis_completion_summary.pending_nonce += 1;
    let mut wrong_type = valid.clone();
    wrong_type.metadosis_completion_summary.day_type = DayType::Red;
    let mut wrong_height = valid.clone();
    wrong_height
        .metadosis_completion_summary
        .logical_evaluation_height += 1;
    let mut wrong_time = valid.clone();
    wrong_time
        .metadosis_completion_summary
        .logical_evaluation_time += 1;

    for invalid in [wrong_day, wrong_nonce, wrong_type, wrong_height, wrong_time] {
        assert!(matches!(
            invalid.validate_finalized_intent(&finalized_intent),
            Err(ProtocolError::InvalidInvariant(
                "result finalized intent binding"
            ))
        ));
    }
}

#[test]
fn full_result_digest_and_finalized_binding_cover_completion_fields() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let finalized_request_state_root = hash(49);
    let job_id = finalized_intent
        .job_id(
            finality_proof().parent_accounting.finalized_block_hash,
            finalized_request_state_root,
            &LIMITS,
        )
        .unwrap();
    let mut valid_result = result();
    valid_result.job_id = job_id;
    valid_result
        .validate_finalized_intent(&finalized_intent)
        .unwrap();
    let valid_digest = valid_result.result_digest(&LIMITS).unwrap();
    let mut changed = valid_result;
    changed.metadosis_completion_summary.logical_evaluation_time += 1;
    assert_ne!(changed.result_digest(&LIMITS).unwrap(), valid_digest);
    assert!(matches!(
        changed.validate_finalized_intent(&finalized_intent),
        Err(ProtocolError::InvalidInvariant(
            "result finalized intent binding"
        ))
    ));
}

#[test]
fn result_vote_verification_requires_the_finalized_intent_binding() {
    let snapshot = committee();
    let mut finalized_intent = intent();
    finalized_intent.result_validator_set_epoch = snapshot.snapshot_epoch;
    finalized_intent.result_ocomp_binding_hash = snapshot.snapshot_hash(&LIMITS).unwrap();
    let job_id = hash(59);
    let vote = signed_vote(
        0,
        vote_result(job_id, 120),
        &finalized_intent,
        job_id,
        &snapshot,
    );
    verify_vote(&vote, &finalized_intent, job_id, &snapshot, 106, 106, 120).unwrap();

    let mut wrong_intent = finalized_intent;
    wrong_intent.fork_id = hash(99);
    assert!(matches!(
        verify_vote(&vote, &wrong_intent, job_id, &snapshot, 106, 106, 120),
        Err(ProtocolError::InvalidSignature)
    ));
}

#[test]
fn plan_commitment_scales_the_population_into_bounded_work_units_without_a_total_cap() {
    for (tribute_count, expected_units) in [(10_000, 40), (1_000_000_000, 3_906_250)] {
        let plan = PlanCommitmentV1 {
            protocol_bundle_hash: hash(1),
            job_id: hash(2),
            attempt: 0,
            input_manifest_hash: hash(3),
            wwd: 20_260_724,
            lysis_budget: U256::from(99_000_000_u64),
            logical_evaluation_time: 1_784_765_900,
            tribute_count,
            max_tributes_per_work_shard: 256,
            primary_work_unit_count: expected_units,
            primary_work_unit_root: hash(4),
            planner_spec_version: 1,
            reducer_spec_version: 1,
        };
        assert!(plan.plan_hash(&LIMITS).is_ok());

        let encoded = plan.encode_canonical_record(&LIMITS).unwrap();
        assert_eq!(
            PlanCommitmentV1::decode_canonical_record(&encoded, &LIMITS).unwrap(),
            plan
        );
        let committed_hash = plan.plan_hash(&LIMITS).unwrap();
        let mut changed_wwd = plan.clone();
        changed_wwd.wwd += 1;
        let mut changed_budget = plan.clone();
        changed_budget.lysis_budget += U256::from(1);
        let mut changed_time = plan.clone();
        changed_time.logical_evaluation_time += 1;
        for changed in [changed_wwd, changed_budget, changed_time] {
            assert_ne!(changed.plan_hash(&LIMITS).unwrap(), committed_hash);
        }

        let mut missing_unit = plan.clone();
        missing_unit.primary_work_unit_count -= 1;
        assert!(missing_unit.plan_hash(&LIMITS).is_err());
    }

    let prefix_down = UnitSpecV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 0,
        phase: UnitPhase::GratisPrefixDown,
        interval: UnitInterval::BinaryReducerNode(BinaryReducerNode {
            level: 21,
            index: 7,
        }),
        canonical_ordered_inputs: Vec::new(),
        lysis_program_semantics_hash: hash(5),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    assert!(prefix_down.unit_id(&LIMITS).is_ok());
}

#[test]
fn a_split_short_of_the_day_limit_is_accepted() {
    let mut short_intent = intent();
    short_intent.frozen_metadosis_values.day_limit = U256::from(10);
    short_intent.frozen_metadosis_values.lysis_budget = U256::from(3);
    short_intent.frozen_metadosis_values.auction_base = U256::from(2);
    short_intent.encode_canonical(&LIMITS).unwrap();
}

#[test]
fn a_split_receipt_accounts_for_the_day_limit_down_to_the_last_unit() {
    let credited_headroom = RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash: hash(41),
        wwd: 7,
        pending_nonce: 0,
        day_type: DayType::Green,
        day_limit: U256::from(10),
        lysis_budget: U256::from(4),
        auction_base: U256::from(5),
        destination: BudgetSplitDestination::DesisAuction,
        desis_brief_hash: Some(hash(113)),
        carry_over_credit: U256::from(1),
        auction_entry_prices: vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
            reference_currency: 840,
            entry_price_minor: U256::from(2),
            source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
            source_day: 6,
        }],
        logical_anchor: 10,
    };
    credited_headroom.encode_canonical(&LIMITS).unwrap();

    let mut dropped_headroom = credited_headroom.clone();
    dropped_headroom.carry_over_credit = U256::ZERO;
    assert!(matches!(
        dropped_headroom.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("request budget split"))
    ));

    // A red day briefs nothing, so its base returns together with the headroom.
    let mut red_returns_everything = credited_headroom;
    red_returns_everything.day_type = DayType::Red;
    red_returns_everything.destination = BudgetSplitDestination::CarryOver;
    red_returns_everything.carry_over_credit = U256::from(6);
    red_returns_everything.encode_canonical(&LIMITS).unwrap();
}

#[test]
fn split_budget_and_carry_over_invariants_fail_closed() {
    let mut invalid_intent = intent();
    invalid_intent.frozen_metadosis_values.day_limit = U256::from(1);
    invalid_intent.frozen_metadosis_values.auction_base = U256::from(2);
    assert!(matches!(
        invalid_intent.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("Metadosis budget split"))
    ));

    let green_split = RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash: hash(41),
        wwd: 7,
        pending_nonce: 0,
        day_type: DayType::Green,
        day_limit: U256::from(10),
        lysis_budget: U256::from(4),
        auction_base: U256::from(6),
        destination: BudgetSplitDestination::DesisAuction,
        desis_brief_hash: Some(hash(113)),
        carry_over_credit: U256::ZERO,
        auction_entry_prices: vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
            reference_currency: 840,
            entry_price_minor: U256::from(2),
            source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
            source_day: 6,
        }],
        logical_anchor: 10,
    };
    green_split.encode_canonical(&LIMITS).unwrap();

    let mut green_to_carry_over = green_split.clone();
    green_to_carry_over.destination = BudgetSplitDestination::CarryOver;
    green_to_carry_over.desis_brief_hash = None;
    green_to_carry_over.carry_over_credit = green_to_carry_over.auction_base;
    assert!(matches!(
        green_to_carry_over.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "request budget split destination"
        ))
    ));

    let mut red_split = green_split;
    red_split.day_type = DayType::Red;
    red_split.destination = BudgetSplitDestination::CarryOver;
    red_split.carry_over_credit = red_split.auction_base;
    red_split.encode_canonical(&LIMITS).unwrap();

    let mut red_without_brief = red_split.clone();
    red_without_brief.desis_brief_hash = None;
    assert!(matches!(
        red_without_brief.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "request budget split destination"
        ))
    ));

    let mut red_to_desis = red_split;
    red_to_desis.destination = BudgetSplitDestination::DesisAuction;
    red_to_desis.desis_brief_hash = Some(hash(113));
    red_to_desis.carry_over_credit = U256::ZERO;
    assert!(matches!(
        red_to_desis.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "request budget split destination"
        ))
    ));

    let mut invalid_lysis_conservation = result();
    invalid_lysis_conservation.conservation.day_limit = U256::from(1);
    invalid_lysis_conservation.conservation.lysis_budget = U256::from(1);
    assert!(matches!(
        invalid_lysis_conservation.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("Lysis budget conservation"))
    ));

    let mut invalid_carry_over = result();
    invalid_carry_over.conservation.carry_over_credit = U256::from(1);
    assert!(matches!(
        invalid_carry_over.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("carry-over conservation"))
    ));

    let invalid_receipt = CarryOverReceiptV1 {
        binding: binding(),
        source_wwd: 7,
        before_value: U256::from(3),
        credited_unused_lysis: U256::from(4),
        after_value: U256::from(8),
        state_event_digest: hash(115),
    };
    assert!(matches!(
        invalid_receipt.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("carry-over receipt"))
    ));

    let mut partial_conflict = conflict_receipt();
    partial_conflict.nod_receipt_hash = Some(hash(110));
    assert!(matches!(
        partial_conflict.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "aggregate receipt outcome shape"
        ))
    ));
}

#[test]
fn conflict_receipt_requires_the_empty_apply_event_summary() {
    conflict_receipt().validate_semantics().unwrap();

    let mut wrong_summary = conflict_receipt();
    wrong_summary.event_summary_hash = hash(84);
    assert!(matches!(
        wrong_summary.validate_semantics(),
        Err(ProtocolError::InvalidInvariant(
            "conflict receipt empty apply event summary"
        ))
    ));
}

#[test]
fn applied_receipt_validates_the_fixed_owner_event_order() {
    let owner_digests = [hash(110), hash(111), hash(112), hash(115)];
    let receipt_hashes = [hash(120), hash(121), hash(122), hash(123)];
    let mut effect_payload = Vec::with_capacity(128);
    for digest in receipt_hashes {
        effect_payload.extend_from_slice(digest.as_slice());
    }
    let mut receipt = conflict_receipt();
    receipt.outcome = ActivationOutcome::Applied;
    receipt.nod_receipt_hash = Some(receipt_hashes[0]);
    receipt.contributor_receipt_hash = Some(receipt_hashes[1]);
    receipt.tribute_receipt_hash = Some(receipt_hashes[2]);
    receipt.carry_over_receipt_hash = Some(receipt_hashes[3]);
    receipt.active_generation_hash = Some(hash(124));
    receipt.effect_commitment = hash_framed(HashDomain::Effects, &effect_payload).unwrap();
    receipt.event_summary_hash = apply_event_summary_hash(owner_digests).unwrap();

    receipt
        .validate_applied_event_summary(owner_digests)
        .unwrap();

    let reordered = [
        owner_digests[1],
        owner_digests[0],
        owner_digests[2],
        owner_digests[3],
    ];
    assert!(matches!(
        receipt.validate_applied_event_summary(reordered),
        Err(ProtocolError::InvalidInvariant(
            "applied receipt event summary"
        ))
    ));
}

#[test]
fn desis_request_brief_hash_commits_every_frozen_request_field() {
    let protocol_bundle_hash = hash(41);
    let wwd = 7_u32;
    let auction_base = U256::from(6);
    let prices = |price: u64, currency: u16| {
        vec![outbe_ocomp_protocol::intent::ReferenceEntryPriceV1 {
            reference_currency: currency,
            entry_price_minor: U256::from(price),
            source: outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap,
            source_day: 6,
        }]
    };
    let entry_prices = prices(2, 840);
    let logical_anchor = 10_u64;

    let digest = desis_request_brief_hash(
        protocol_bundle_hash,
        wwd,
        auction_base,
        &entry_prices,
        logical_anchor,
    )
    .unwrap();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(protocol_bundle_hash.as_slice());
    preimage.extend_from_slice(&wwd.to_be_bytes());
    preimage.extend_from_slice(&auction_base.to_be_bytes::<32>());
    preimage.extend_from_slice(&1_u16.to_be_bytes());
    preimage.extend_from_slice(&840_u16.to_be_bytes());
    preimage.extend_from_slice(&U256::from(2).to_be_bytes::<32>());
    preimage.push(outbe_ocomp_protocol::intent::AuctionEntryPriceSource::LastClosedDayVwap as u8);
    preimage.extend_from_slice(&6_u32.to_be_bytes());
    preimage.extend_from_slice(&logical_anchor.to_be_bytes());
    assert_eq!(
        digest,
        hash_framed(HashDomain::DesisRequestBrief, &preimage).unwrap()
    );

    // Every frozen field moves the digest, the price table included - its length,
    // its prices and which currency each belongs to.
    let two_rows = {
        let mut rows = prices(2, 840);
        rows.extend(prices(3, 978));
        rows
    };
    for changed in [
        desis_request_brief_hash(hash(42), wwd, auction_base, &entry_prices, logical_anchor)
            .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd + 1,
            auction_base,
            &entry_prices,
            logical_anchor,
        )
        .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd,
            auction_base + U256::from(1),
            &entry_prices,
            logical_anchor,
        )
        .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd,
            auction_base,
            &prices(3, 840),
            logical_anchor,
        )
        .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd,
            auction_base,
            &prices(2, 978),
            logical_anchor,
        )
        .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd,
            auction_base,
            &two_rows,
            logical_anchor,
        )
        .unwrap(),
        desis_request_brief_hash(
            protocol_bundle_hash,
            wwd,
            auction_base,
            &entry_prices,
            logical_anchor + 1,
        )
        .unwrap(),
    ] {
        assert_ne!(changed, digest);
    }
}

#[test]
fn worker_run_unit_body_is_canonical_and_bounded() {
    let request = RunUnitV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 0,
        plan_hash: hash(3),
        unit_index: 0,
        canonical_unit_spec: BoundedBytes(vec![1]),
        unit_membership_siblings: Vec::new(),
        plan_ref: outbe_ocomp_protocol::control::CasObjectRefV1 {
            transport_digest: hash(4),
            encoded_bytes: 10,
            expected_ocb1_kind: None,
        },
        input_manifest_ref: outbe_ocomp_protocol::control::CasObjectRefV1 {
            transport_digest: hash(5),
            encoded_bytes: 20,
            expected_ocb1_kind: Some(ObjectKind::InputManifestV1.tag()),
        },
        ordered_input_refs: Vec::new(),
    };
    let body = request.encode_body(&LIMITS).unwrap();
    assert_eq!(RunUnitV1::decode_body(&body, &LIMITS).unwrap(), request);

    let mut zero_sibling = request.clone();
    zero_sibling.unit_membership_siblings = vec![B256::ZERO];
    assert!(zero_sibling.encode_body(&LIMITS).is_err());

    let mut oversized_proof = request;
    oversized_proof.unit_membership_siblings = vec![hash(6); 33];
    assert!(oversized_proof.encode_body(&LIMITS).is_err());
}

#[test]
fn finalized_discovery_control_pages_multiple_jobs_canonically() {
    let request = ListFinalizedJobsV1 {
        after_cursor: 99,
        limit: MAX_FINALIZED_JOBS_PER_RESPONSE,
    };
    assert_eq!(
        ListFinalizedJobsV1::decode_body(&request.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        request
    );
    for invalid_limit in [0, MAX_FINALIZED_JOBS_PER_RESPONSE + 1] {
        assert!(ListFinalizedJobsV1 {
            after_cursor: 99,
            limit: invalid_limit,
        }
        .encode_body(&LIMITS)
        .is_err());
    }

    let intent = intent();
    let finalized_block_hash = hash(0x92);
    let finalized_state_root = hash(0x93);
    let summary = FinalizedJobSummaryV1 {
        cursor: 100,
        job_id: intent
            .job_id(finalized_block_hash, finalized_state_root, &LIMITS)
            .expect("JobId"),
        intent_id: intent.intent_id(&LIMITS).expect("IntentId"),
        finalized_block_hash,
        finalized_state_root,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        open_height: 100,
        deadline_height: 200,
    };
    let mut second = summary.clone();
    second.cursor += 1;
    second.job_id = hash(0x94);
    let response = ListFinalizedJobsResponseV1 {
        next_cursor: second.cursor,
        jobs: vec![summary.clone(), second],
    };
    assert_eq!(
        ListFinalizedJobsResponseV1::decode_body(&response.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        response
    );
    assert!(ListFinalizedJobsResponseV1 {
        next_cursor: 101,
        jobs: vec![summary.clone(); usize::from(MAX_FINALIZED_JOBS_PER_RESPONSE) + 1],
    }
    .encode_body(&LIMITS)
    .is_err());

    let get = GetJobSpecV1 {
        job_id: summary.job_id,
    };
    assert_eq!(
        GetJobSpecV1::decode_body(&get.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        get
    );
    let spec = FinalizedJobSpecV1 {
        summary,
        canonical_job_intent: BoundedBytes(
            intent.encode_canonical(&LIMITS).expect("canonical intent"),
        ),
    };
    assert_eq!(
        FinalizedJobSpecV1::decode_body(&spec.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        spec
    );
}

#[test]
fn prepared_vote_transaction_carries_bounded_vote_and_raw_transaction() {
    let response = PreparedVoteTransactionV1 {
        canonical_vote: BoundedBytes(vec![1, 2, 3, 4]),
        raw_transaction: BoundedBytes(vec![5, 6, 7]),
        transaction_hash: hash(0x92),
    };
    assert_eq!(
        PreparedVoteTransactionV1::decode_body(&response.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        response
    );

    for invalid in [
        PreparedVoteTransactionV1 {
            canonical_vote: BoundedBytes(Vec::new()),
            ..response.clone()
        },
        PreparedVoteTransactionV1 {
            raw_transaction: BoundedBytes(Vec::new()),
            ..response.clone()
        },
        PreparedVoteTransactionV1 {
            transaction_hash: B256::ZERO,
            ..response
        },
    ] {
        assert!(invalid.encode_body(&LIMITS).is_err());
    }
}

#[test]
fn snapshot_export_control_pages_job_scoped_leases_and_manifests() {
    let job_id = hash(0xa1);
    let checkpoint = CheckpointIdentityV1 {
        finalized_block_number: 100,
        finalized_block_hash: hash(0xa2),
        finalized_state_root: hash(0xa3),
        finalized_ce_root: hash(0xa4),
        ce_schema_version: 1,
    };
    let lease = BoundedBytes(vec![0xa5; SNAPSHOT_LEASE_WIRE_BYTES]);

    let open = OpenSnapshotLeaseV1 { job_id };
    assert_eq!(
        OpenSnapshotLeaseV1::decode_body(&open.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        open
    );
    let handoff = SnapshotHandoffV1 {
        job_id,
        input_lease_id: hash(12),
        pin_generation: 7,
        lease_generation: 11,
        checkpoint,
        canonical_lease_offer: lease.clone(),
    };
    assert_eq!(
        SnapshotHandoffV1::decode_body(&handoff.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        handoff
    );
    let list = ListSnapshotHandoffsV1 {
        after_lease_generation: 0,
        limit: MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE,
    };
    assert_eq!(
        ListSnapshotHandoffsV1::decode_body(&list.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        list
    );
    let mut second_handoff = handoff.clone();
    second_handoff.job_id = hash(0xa6);
    second_handoff.lease_generation += 1;
    let listed = ListSnapshotHandoffsResponseV1 {
        next_lease_generation: second_handoff.lease_generation,
        handoffs: vec![handoff.clone(), second_handoff],
    };
    assert_eq!(
        ListSnapshotHandoffsResponseV1::decode_body(&listed.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        listed
    );
    let get = GetSnapshotHandoffV1 {
        job_id,
        lease_generation: handoff.lease_generation,
    };
    assert_eq!(
        GetSnapshotHandoffV1::decode_body(&get.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        get
    );
    let renew = RenewSnapshotLeaseV1 {
        job_id,
        lease_generation: handoff.lease_generation,
        canonical_open_ack: lease,
    };
    assert_eq!(
        RenewSnapshotLeaseV1::decode_body(&renew.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        renew
    );
    let opened = SnapshotLeaseOpenedV1 {
        job_id,
        lease_generation: handoff.lease_generation,
    };
    assert_eq!(
        SnapshotLeaseOpenedV1::decode_body(&opened.encode_body(&LIMITS).unwrap(), &LIMITS).unwrap(),
        opened
    );

    let proof_request = BuildFinalizedIntentProofV1 { job_id };
    assert_eq!(
        BuildFinalizedIntentProofV1::decode_body(
            &proof_request.encode_body(&LIMITS).unwrap(),
            &LIMITS
        )
        .unwrap(),
        proof_request
    );
    let proof_response = FinalizedIntentProofResponseV1 {
        job_id,
        canonical_proof: BoundedBytes(vec![1]),
    };
    assert_eq!(
        FinalizedIntentProofResponseV1::decode_body(
            &proof_response.encode_body(&LIMITS).unwrap(),
            &LIMITS
        )
        .unwrap(),
        proof_response
    );
    let openings_request = BuildLysisOpeningsV1 {
        job_id,
        subjects: OpeningSubjectsV1 {
            owners: vec![Address::repeat_byte(0xa6)],
            reference_isos: vec![840],
        },
    };
    assert_eq!(
        BuildLysisOpeningsV1::decode_body(&openings_request.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        openings_request
    );
    let projection = ProjectionCheckpointV1 {
        block_number: handoff.checkpoint.finalized_block_number + 5,
        block_hash: hash(0xa9),
    };
    let containment = CheckProjectionContainmentV1 {
        job_id,
        lease_generation: handoff.lease_generation,
        projection_checkpoint: projection.clone(),
    };
    assert_eq!(
        CheckProjectionContainmentV1::decode_body(
            &containment.encode_body(&LIMITS).unwrap(),
            &LIMITS
        )
        .unwrap(),
        containment
    );
    let contained = ProjectionContainedV1 {
        job_id,
        lease_generation: handoff.lease_generation,
        projection_checkpoint: projection,
        required_checkpoint: ProjectionCheckpointV1 {
            block_number: handoff.checkpoint.finalized_block_number,
            block_hash: handoff.checkpoint.finalized_block_hash,
        },
    };
    assert_eq!(
        ProjectionContainedV1::decode_body(&contained.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        contained
    );

    let commit = CommitSnapshotExportV1 {
        job_id,
        pin_generation: handoff.pin_generation,
        lease_generation: handoff.lease_generation,
        manifest_hash: hash(0xa7),
    };
    assert_eq!(
        CommitSnapshotExportV1::decode_body(&commit.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        commit
    );
    let committed = SnapshotExportCommittedV1 {
        job_id,
        pin_generation: handoff.pin_generation + 1,
        record_hash: hash(0xa8),
    };
    assert_eq!(
        SnapshotExportCommittedV1::decode_body(&committed.encode_body(&LIMITS).unwrap(), &LIMITS)
            .unwrap(),
        committed
    );

    for invalid in [
        OpenSnapshotLeaseV1 { job_id: B256::ZERO }
            .encode_body(&LIMITS)
            .is_err(),
        SnapshotHandoffV1 {
            canonical_lease_offer: BoundedBytes(vec![0; SNAPSHOT_LEASE_WIRE_BYTES - 1]),
            ..handoff.clone()
        }
        .encode_body(&LIMITS)
        .is_err(),
        ListSnapshotHandoffsV1 {
            after_lease_generation: 0,
            limit: 0,
        }
        .encode_body(&LIMITS)
        .is_err(),
        ListSnapshotHandoffsResponseV1 {
            next_lease_generation: handoff.lease_generation + 1,
            handoffs: vec![handoff.clone()],
        }
        .encode_body(&LIMITS)
        .is_err(),
        CommitSnapshotExportV1 {
            manifest_hash: B256::ZERO,
            ..commit
        }
        .encode_body(&LIMITS)
        .is_err(),
    ] {
        assert!(invalid);
    }
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes()).0[..4].try_into().unwrap()
}

#[test]
fn public_abi_constants_match_independent_keccak_derivation() {
    assert_eq!(
        selector("submitLysisResult(bytes)"),
        SUBMIT_LYSIS_RESULT_SELECTOR
    );
    assert_eq!(
        selector("getOffchainJob(bytes32)"),
        GET_OFFCHAIN_JOB_SELECTOR
    );
    assert_eq!(
        selector("getActiveLysisGeneration(uint32)"),
        GET_ACTIVE_LYSIS_GENERATION_SELECTOR
    );
    assert_eq!(
        selector("getLysisTerminalReceipt(bytes32)"),
        GET_LYSIS_TERMINAL_RECEIPT_SELECTOR
    );
    assert_eq!(
        selector("OcompActivationRejected(uint16)"),
        OCOMP_ACTIVATION_REJECTED_SELECTOR
    );
    assert_eq!(
        keccak256(b"OffchainJobRequested(bytes32,uint32,uint64,uint32,bytes32)"),
        OCOMP_REQUESTED_TOPIC0
    );
    assert_eq!(
        keccak256(b"OffchainJobExpired(bytes32,uint32,uint64)"),
        OCOMP_EXPIRED_TOPIC0
    );
    assert_eq!(
        keccak256(b"LysisActivated(bytes32,bytes32,bytes32,bytes32,bytes32,uint32)"),
        LYSIS_ACTIVATED_TOPIC0
    );
}

#[test]
fn unit_artifact_constructor_binds_spec_output_and_coverage() {
    let spec = UnitSpecV1 {
        protocol_bundle_hash: hash(41),
        job_id: hash(59),
        attempt: 0,
        phase: UnitPhase::Enumerate,
        interval: UnitInterval::EntityIdRange(EntityIdHalfOpenRange {
            start: B256::from([0; 32]),
            end: Some(B256::from([1; 32])),
        }),
        canonical_ordered_inputs: Vec::new(),
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let artifact = UnitArtifactV1::from_canonical_output(
        &spec,
        WorkOutputHeaderV1 {
            source_coverage_root: hash(108),
            output_coverage_root: hash(109),
            source_coverage_count: 1,
            output_coverage_count: 1,
        },
        BoundedBytes(vec![0x11, 0x22]),
        &LIMITS,
    )
    .unwrap();
    artifact.validate_against(&spec, &LIMITS).unwrap();
    assert_eq!(artifact.phase_payload(&LIMITS).unwrap(), [0x11, 0x22]);
    assert!(UnitArtifactV1::from_canonical_output(
        &spec,
        WorkOutputHeaderV1 {
            source_coverage_root: hash(108),
            output_coverage_root: hash(109),
            source_coverage_count: 1,
            output_coverage_count: 1,
        },
        BoundedBytes(Vec::new()),
        &LIMITS,
    )
    .is_err());

    let mut changed_bytes = artifact.clone();
    changed_bytes.canonical_output_bytes.0[0] ^= 1;
    assert!(changed_bytes.validate_against(&spec, &LIMITS).is_err());

    let mut changed_coverage = artifact.clone();
    changed_coverage.coverage_or_permutation_commitment = hash(110);
    assert!(changed_coverage.validate_against(&spec, &LIMITS).is_err());

    let mut changed_count = artifact;
    changed_count.output_record_count += 1;
    assert!(changed_count.validate_against(&spec, &LIMITS).is_err());

    let empty_reducer_spec = UnitSpecV1 {
        phase: UnitPhase::FixedReduce,
        interval: UnitInterval::BinaryReducerNode(BinaryReducerNode { level: 1, index: 3 }),
        ..spec
    };
    UnitArtifactV1::from_canonical_output(
        &empty_reducer_spec,
        WorkOutputHeaderV1 {
            source_coverage_root: hash(111),
            output_coverage_root: hash(111),
            source_coverage_count: 0,
            output_coverage_count: 0,
        },
        BoundedBytes(vec![0x01]),
        &LIMITS,
    )
    .expect("canonical padded reducer subtree may cover zero real Tribute");
}

#[test]
fn address_is_exactly_twenty_bytes_in_typed_actions() {
    assert_eq!(core::mem::size_of::<Address>(), 20);
}
