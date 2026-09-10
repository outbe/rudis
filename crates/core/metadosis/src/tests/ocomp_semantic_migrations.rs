use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use outbe_ocomp_protocol::{
    receipts::ActivationOutcome, state::OcompJobStatus, vote::OcompVoteAccountabilityV1,
};
use outbe_primitives::{
    addresses::{INTEX_ADDRESS, NOD_ADDRESS, PROMIS_LIMIT_ADDRESS, TRIBUTE_ADDRESS},
    error::PrecompileError,
};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    storage::{MetadosisMutationPurposeTag, StorageHandle},
};
use outbe_tribute::TributeContract;
use outbe_validatorset::{
    contract::ValidatorSet, runtime::status as validator_status, ValidatorHistory,
    ValidatorLifecycle,
};

use crate::{
    fixture_kernel::{
        ActivationFixture, ActivationMetadata, ActivationReceiptFault, TEST_LOGICAL_TIME, TEST_WWD,
    },
    ocomp::schema::poc_schema_limits,
    precompile::IMetadosis,
    schema::MetadosisContract,
    WwdStatus,
};

fn assert_open_job_after_activation_rejection(fixture: &mut ActivationFixture) {
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_wwd_status(TEST_WWD).unwrap(),
            WwdStatus::OffchainPending
        );
        let job = metadosis
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(job.status, OcompJobStatus::VotingOpen);
        assert!(job.terminal.is_none());
        assert!(metadosis
            .read_metadosis_failure_receipt(TEST_WWD, U256::from(60))
            .unwrap()
            .is_none());
    });
}

fn close_completed_response_window(
    fixture: &mut ActivationFixture,
    deadline_height: u64,
) -> outbe_primitives::error::Result<()> {
    fixture.provider.set_block_number(deadline_height);
    fixture.provider.set_timestamp(U256::from(1_011));
    fixture
        .provider
        .enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::OcompLifecycle);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(deadline_height, 1_011, 1),
            storage,
        );
        crate::commands::run_ocomp_lifecycle_begin_with_scope(&ctx, &fixture.scope)
    })
}

/// Retire the completed fixture's V1 through the production Registry lifecycle.
/// Clear the fixture-only authority copy so it cannot hide the missing V1.
fn retire_completed_vote_authority(fixture: &mut ActivationFixture) -> u64 {
    use outbe_ocompregistry::{OcompProtocolAuthorityV1, OcompRegistry, OcompSuccessorV1};

    let proposal_id = U256::from(7);
    let promotion_height = StorageHandle::enter(&mut fixture.provider, |storage| {
        let contract = MetadosisContract::new(storage.clone());
        let initial = OcompProtocolAuthorityV1 {
            request_profile: contract
                .read_ocomp_request_profile(&fixture.limits)
                .unwrap()
                .unwrap(),
            protocol_bundle: contract
                .read_ocomp_activation_authority(&fixture.limits)
                .unwrap()
                .unwrap()
                .bundle,
        };
        let height = storage.block_number().unwrap();
        let mut registry = OcompRegistry::new(storage);
        registry
            .initialize_genesis_authority(
                &initial,
                B256::repeat_byte(0x99),
                height,
                height,
                &fixture.limits,
            )
            .unwrap();
        let mut successor = initial.clone();
        successor.protocol_bundle.protocol_version += 1;
        successor.protocol_bundle.request_semantics_version += 1;
        successor.protocol_bundle.fork_id = B256::repeat_byte(0xA1);
        successor.protocol_bundle.lysis_program_semantics_hash = B256::repeat_byte(0xA2);
        successor.request_profile.fork_id = successor.protocol_bundle.fork_id;
        successor.request_profile.protocol_bundle_hash = successor
            .protocol_bundle
            .protocol_bundle_hash(&fixture.limits)
            .unwrap();
        registry
            .stage_successor(
                proposal_id,
                &OcompSuccessorV1 {
                    activation_height: height + 1,
                    predecessor_protocol_bundle_hash: initial.request_profile.protocol_bundle_hash,
                    authority: successor,
                },
                &fixture.limits,
            )
            .unwrap();
        height + 1
    });
    fixture.provider.set_block_number(promotion_height);
    let bundle_hash = fixture.result.protocol_bundle_hash;
    let retirement_height = StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut registry = OcompRegistry::new(storage.clone());
        registry
            .promote_staged_successor(proposal_id, promotion_height, &fixture.limits)
            .unwrap();
        assert!(registry
            .authority_by_bundle_hash(bundle_hash, &fixture.limits)
            .unwrap()
            .is_some());
        assert!(!registry
            .try_retire_predecessor(promotion_height, &fixture.limits)
            .unwrap());
        MetadosisContract::new(storage)
            .ocomp_active_protocol_bundle
            .clear()
            .unwrap();
        registry.retention_until.read(&bundle_hash).unwrap()
    });
    fixture.provider.set_block_number(retirement_height);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut registry = OcompRegistry::new(storage.clone());
        assert!(registry
            .try_retire_predecessor(retirement_height, &fixture.limits)
            .unwrap());
        assert!(MetadosisContract::new(storage)
            .read_ocomp_activation_authority_for_bundle(bundle_hash, &fixture.limits)
            .unwrap()
            .is_none());
    });
    retirement_height
}

#[test]
fn completed_vote_replay_after_authority_retirement_is_a_noop() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.apply().unwrap();
    retire_completed_vote_authority(&mut fixture);
    let before = fixture.rollback_snapshot();

    assert_eq!(fixture.dispatch_current().unwrap(), Bytes::new());
    assert_eq!(fixture.rollback_snapshot(), before);
}

#[test]
fn fourth_timely_vote_after_authority_retirement_preserves_completed_lysis() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.apply().unwrap();
    let height = retire_completed_vote_authority(&mut fixture);
    let before = fixture.semantic_snapshot();
    let vote = fixture.signed_result_vote(3);
    let quorum_before = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .result_vote_accountability(vote.job_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .quorum
    });

    assert_eq!(
        submit_vote_result(&mut fixture, &vote, height + 1).unwrap(),
        Bytes::new()
    );
    assert_eq!(fixture.semantic_snapshot(), before);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let accountability = MetadosisContract::new(storage)
            .result_vote_accountability(vote.job_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(accountability.quorum, quorum_before);
        assert_eq!(accountability.slots.iter().flatten().count(), 4);
    });
}

#[test]
fn invalid_votes_after_authority_retirement_revert_without_blocking_valid_votes() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.apply().unwrap();
    let height = retire_completed_vote_authority(&mut fixture);
    let valid = fixture.signed_result_vote(2);
    let before = fixture.rollback_snapshot();
    let mut wrong_signature = valid.clone();
    wrong_signature.signature_rs[0] ^= 1;
    let mut wrong_binding = valid.clone();
    wrong_binding.result_ocomp_binding_hash = B256::repeat_byte(0xEE);
    let mut wrong_signer = valid.clone();
    wrong_signer.ocomp_key_hash = B256::repeat_byte(0xEF);
    for vote in [wrong_signature, wrong_binding, wrong_signer] {
        assert!(matches!(
            submit_vote_result(&mut fixture, &vote, height + 1),
            Err(PrecompileError::RevertBytes(_))
        ));
        assert_eq!(fixture.rollback_snapshot(), before);
    }
    assert_eq!(
        submit_vote_result(&mut fixture, &valid, height + 2).unwrap(),
        Bytes::new()
    );
    assert_eq!(fixture.rollback_snapshot(), before);
}

#[test]
fn completed_vote_after_authority_retirement_still_obeys_exclusive_deadline() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.apply().unwrap();
    retire_completed_vote_authority(&mut fixture);
    let vote = fixture.signed_result_vote(2);
    let deadline = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
            .deadline_height
    });
    let before = fixture.rollback_snapshot();
    assert_eq!(
        submit_vote_result(&mut fixture, &vote, deadline - 1).unwrap(),
        Bytes::new()
    );
    assert_eq!(fixture.rollback_snapshot(), before);
    assert!(matches!(
        submit_vote_result(&mut fixture, &vote, deadline),
        Err(PrecompileError::RevertBytes(_))
    ));
    assert_eq!(fixture.rollback_snapshot(), before);

    fixture.seed_ocomp_recovery_stake_for_test();
    close_completed_response_window(&mut fixture, deadline).unwrap();
    let after_close = fixture.rollback_snapshot();
    let error = submit_vote_result(&mut fixture, &vote, deadline + 1).unwrap_err();
    assert!(crate::ocomp::vote::is_deadline_passed_result_vote_revert(
        &error
    ));
    assert_eq!(fixture.rollback_snapshot(), after_close);
}

#[test]
fn subquorum_vote_without_activation_authority_remains_fatal_and_atomic() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_active_protocol_bundle
            .clear()
            .unwrap();
    });
    let before = fixture.rollback_snapshot();
    // Repeating one of the two existing votes does not form quorum.
    let vote = fixture.signed_result_vote(0);
    assert!(
        matches!(submit_vote_result(&mut fixture, &vote, 20), Err(PrecompileError::Fatal(message))
        if message == "OCOMP activation authority is not installed")
    );
    assert_eq!(fixture.rollback_snapshot(), before);
    assert_open_job_after_activation_rejection(&mut fixture);
}

#[test]
fn first_quorum_without_activation_authority_remains_fatal_and_atomic() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_active_protocol_bundle
            .clear()
            .unwrap();
    });
    let before = fixture.rollback_snapshot();
    assert!(
        matches!(fixture.apply(), Err(PrecompileError::Fatal(message))
        if message == "OCOMP activation authority is not installed")
    );
    assert_eq!(fixture.rollback_snapshot(), before);
    assert_open_job_after_activation_rejection(&mut fixture);
}

fn transition_validator_to_status_for_test(
    validators: &mut ValidatorSet<'_>,
    validator: Address,
    target_status: u8,
    freeze_height: u64,
) {
    let survivors: Vec<_> = validators
        .get_active_consensus_set()
        .unwrap()
        .into_iter()
        .map(|record| record.validator_address)
        .filter(|address| *address != validator)
        .collect();
    let boundary_hash = B256::with_last_byte(target_status.saturating_add(1));

    match target_status {
        validator_status::REGISTERED => {
            let record = validators.get_validator(validator).unwrap().unwrap();
            let owner = validators.config_owner.read().unwrap();
            validators.deactivate_validator(owner, validator).unwrap();
            validators
                .test_activate_validated_boundary_set(&survivors, boundary_hash, freeze_height)
                .unwrap();
            validators.complete_unbonding(validator).unwrap();
            validators
                .register_validator(owner, validator, &record.consensus_pubkey)
                .unwrap();
        }
        validator_status::PENDING => validators
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &survivors,
                boundary_hash,
                freeze_height,
                &[validator],
            )
            .unwrap(),
        validator_status::EXITING => {
            let owner = validators.config_owner.read().unwrap();
            validators.deactivate_validator(owner, validator).unwrap();
        }
        validator_status::UNBONDING | validator_status::INACTIVE => {
            let owner = validators.config_owner.read().unwrap();
            validators.deactivate_validator(owner, validator).unwrap();
            validators
                .test_activate_validated_boundary_set(&survivors, boundary_hash, freeze_height)
                .unwrap();
            if target_status == validator_status::INACTIVE {
                validators.complete_unbonding(validator).unwrap();
            }
        }
        validator_status::JAILED => validators.jail_validator(validator).unwrap(),
        other => panic!("unsupported fixture target status {other}"),
    }
}

#[test]
fn finalized_attempt_uses_exact_1800_block_compute_vote_window() {
    let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });

    assert_eq!(finalized.deadline_height - finalized.open_height, 1_800);
}

#[test]
fn deadline_opens_recovery_only_for_the_missing_pinned_validator_after_early_quorum() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.seed_ocomp_recovery_stake_for_test();
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = ValidatorSet::new(storage.clone());
        for index in 0..3_u8 {
            let record = validators
                .get_validator(Address::repeat_byte(0xB0 + index))
                .unwrap()
                .unwrap();
            assert_eq!(record.status, validator_status::ACTIVE);
            assert_eq!(record.slash_count, 0);
        }
        let missing = validators
            .get_validator(Address::repeat_byte(0xB3))
            .unwrap()
            .unwrap();
        assert_eq!(missing.status, validator_status::ACTIVE);
        assert_eq!(missing.slash_count, 0);
        let window = validators
            .ocomp_recovery_window(Address::repeat_byte(0xB3))
            .unwrap()
            .unwrap();
        assert_eq!(window.miss_count, 1);
        assert_eq!(window.recovery_deadline, finalized.deadline_height + 43_200);
        assert_eq!(
            outbe_staking::contract::Staking::new(storage.clone())
                .get_stake(Address::repeat_byte(0xB3))
                .unwrap(),
            U256::from(900)
        );

        let accountability = MetadosisContract::new(storage)
            .result_vote_accountability(finalized.job_id, &fixture.limits)
            .unwrap()
            .unwrap();
        let summary = accountability.closed_summary.unwrap();
        assert_eq!(summary.timely_bitmap, vec![0b0000_0111]);
        assert_eq!(summary.missing_bitmap, vec![0b0000_1000]);
    });

    let after_first_close = fixture.rollback_snapshot();
    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();
    assert_eq!(fixture.rollback_snapshot(), after_first_close);
}

#[test]
fn missing_vote_slashes_bonded_once_and_opens_recovery() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    fixture.seed_ocomp_recovery_stake_for_test();
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    let missed = fixture
        .provider
        .get_ordered_events()
        .iter()
        .find_map(|log| IMetadosis::OcompVoteMissed::decode_log(log).ok())
        .expect("OCOMP miss event");
    assert_eq!(missed.validator, Address::repeat_byte(0xB3));
    assert_eq!(missed.jobId, finalized.job_id);
    assert_eq!(missed.missCount, 1);
    assert_eq!(missed.slashedBonded, U256::from(100));
    assert_eq!(missed.recoveryDeadline, finalized.deadline_height + 43_200);
    assert!(missed.firstInWindow);

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let missing = Address::repeat_byte(0xB3);
        let validators = ValidatorSet::new(storage.clone());
        assert!(matches!(
            validators.validator_lifecycle(missing).unwrap(),
            ValidatorLifecycle::Active(_)
        ));
        let window = validators.ocomp_recovery_window(missing).unwrap().unwrap();
        assert_eq!(window.miss_count, 1);
        assert_eq!(window.recovery_deadline, finalized.deadline_height + 43_200);
        assert_eq!(
            outbe_staking::contract::Staking::new(storage)
                .get_stake(missing)
                .unwrap(),
            U256::from(900)
        );
    });
}

#[test]
fn every_pinned_validator_can_vote_after_quorum_until_the_exclusive_deadline() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });
    let last_vote = fixture.signed_result_vote(3);
    fixture
        .provider
        .set_block_number(finalized.deadline_height - 1);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .record_ocomp_result_vote(
                &last_vote,
                finalized.deadline_height - 1,
                &fixture.scope,
                &fixture.limits,
            )
            .unwrap();
    });

    let at_deadline = fixture.signed_result_vote(3);
    fixture.provider.set_block_number(finalized.deadline_height);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        assert!(matches!(
            MetadosisContract::new(storage).record_ocomp_result_vote(
                &at_deadline,
                finalized.deadline_height,
                &fixture.scope,
                &fixture.limits,
            ),
            Err(PrecompileError::Revert(_))
        ));
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = ValidatorSet::new(storage.clone());
        for index in 0..4_u8 {
            let record = validators
                .get_validator(Address::repeat_byte(0xB0 + index))
                .unwrap()
                .unwrap();
            assert_eq!(record.status, validator_status::ACTIVE);
            assert_eq!(record.slash_count, 0);
        }
        let accountability = MetadosisContract::new(storage)
            .result_vote_accountability(finalized.job_id, &fixture.limits)
            .unwrap()
            .unwrap();
        let summary = accountability.closed_summary.unwrap();
        assert_eq!(summary.timely_bitmap, vec![0b0000_1111]);
        assert_eq!(summary.missing_bitmap, vec![0]);
    });
}

#[test]
fn q_forming_validator_quorum_is_canonical_without_node_local_result() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);

    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    assert_eq!(fixture.terminal_outcome(), ActivationOutcome::Applied);
}

#[test]
fn no_quorum_deadline_opens_recovery_for_every_missing_validator_and_expires_attempt() {
    let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
    fixture.seed_ocomp_recovery_stake_for_test();
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = ValidatorSet::new(storage.clone());
        for index in 0..4_u8 {
            let record = validators
                .get_validator(Address::repeat_byte(0xB0 + index))
                .unwrap()
                .unwrap();
            assert_eq!(record.status, validator_status::ACTIVE);
            assert_eq!(record.slash_count, 0);
            let validator = Address::repeat_byte(0xB0 + index);
            let window = validators.ocomp_recovery_window(validator).unwrap();
            let stake = outbe_staking::contract::Staking::new(storage.clone())
                .get_stake(validator)
                .unwrap();
            if index == 2 {
                assert!(window.is_none());
                assert_eq!(stake, U256::from(1_000));
            } else {
                assert_eq!(window.unwrap().miss_count, 1);
                assert_eq!(stake, U256::from(900));
            }
        }
        let contract = MetadosisContract::new(storage);
        let record = contract
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(record.status, OcompJobStatus::Expired);
        let summary = contract
            .result_vote_accountability(finalized.job_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .closed_summary
            .unwrap();
        assert_eq!(summary.timely_bitmap, vec![0b0000_0100]);
        assert_eq!(summary.missing_bitmap, vec![0b0000_1011]);
    });
}

#[test]
fn authentic_carrier_after_deadline_resolves_pinned_signer_and_returns_deadline_revert() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });
    let late_vote = fixture.signed_result_vote(3);
    let prefix = late_vote.prefix();

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_participant(
                storage,
                &prefix,
                &fixture.limits,
            )
            .unwrap(),
            Some(Address::repeat_byte(0xB3))
        );
    });
    let error = submit_vote_result(&mut fixture, &late_vote, finalized.deadline_height)
        .expect_err("late authentic carrier must fail as a transaction");
    assert!(crate::ocomp::vote::is_deadline_passed_result_vote_revert(
        &error
    ));
}

#[test]
fn deadline_is_replay_safe_for_missing_validators_already_jailed_or_exiting() {
    let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
    fixture.seed_ocomp_recovery_stake_for_test();
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });
    fixture
        .provider
        .set_block_number(finalized.deadline_height - 1);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut validators = ValidatorSet::new(storage);
        validators
            .jail_validator(Address::repeat_byte(0xB0))
            .unwrap();
        validators
            .deactivate_validator(Address::repeat_byte(0xB1), Address::repeat_byte(0xB1))
            .unwrap();
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = ValidatorSet::new(storage.clone());
        let already_jailed = validators
            .get_validator(Address::repeat_byte(0xB0))
            .unwrap()
            .unwrap();
        assert_eq!(already_jailed.status, validator_status::JAILED);
        assert_eq!(already_jailed.slash_count, 1);
        let already_exiting = validators
            .get_validator(Address::repeat_byte(0xB1))
            .unwrap()
            .unwrap();
        assert_eq!(already_exiting.status, validator_status::EXITING);
        assert_eq!(already_exiting.slash_count, 0);
        let timely = validators
            .get_validator(Address::repeat_byte(0xB2))
            .unwrap()
            .unwrap();
        assert_eq!(timely.status, validator_status::ACTIVE);
        assert_eq!(timely.slash_count, 0);
        let newly_recovering = validators
            .get_validator(Address::repeat_byte(0xB3))
            .unwrap()
            .unwrap();
        assert_eq!(newly_recovering.status, validator_status::ACTIVE);
        assert_eq!(newly_recovering.slash_count, 0);
        assert_eq!(
            validators
                .ocomp_recovery_window(Address::repeat_byte(0xB3))
                .unwrap()
                .unwrap()
                .miss_count,
            1
        );
        assert_eq!(
            outbe_staking::contract::Staking::new(storage)
                .get_stake(Address::repeat_byte(0xB3))
                .unwrap(),
            U256::from(900)
        );
    });

    let after_first_close = fixture.rollback_snapshot();
    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();
    assert_eq!(fixture.rollback_snapshot(), after_first_close);
}

#[test]
fn deadline_records_missing_pending_validator_without_mutating_or_fatal() {
    let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });
    fixture
        .provider
        .set_block_number(finalized.deadline_height - 1);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut validators = ValidatorSet::new(storage);
        validators
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &[
                    Address::repeat_byte(0xB1),
                    Address::repeat_byte(0xB2),
                    Address::repeat_byte(0xB3),
                ],
                B256::repeat_byte(0x51),
                finalized.deadline_height - 1,
                &[Address::repeat_byte(0xB0)],
            )
            .unwrap();
        let pending = validators
            .get_validator(Address::repeat_byte(0xB0))
            .unwrap()
            .unwrap();
        assert_eq!(pending.status, validator_status::PENDING);
        assert_eq!(pending.slash_count, 0);
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = ValidatorSet::new(storage.clone());
        let pending = validators
            .get_validator(Address::repeat_byte(0xB0))
            .unwrap()
            .unwrap();
        assert_eq!(pending.status, validator_status::PENDING);
        assert_eq!(pending.slash_count, 0);

        let accountability = MetadosisContract::new(storage)
            .result_vote_accountability(finalized.job_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(
            accountability.closed_summary.unwrap().missing_bitmap,
            vec![0b0000_1011]
        );
    });
}

#[test]
fn deadline_keeps_every_non_active_missing_status_unchanged() {
    for current_status in [
        validator_status::REGISTERED,
        validator_status::PENDING,
        validator_status::EXITING,
        validator_status::UNBONDING,
        validator_status::INACTIVE,
        validator_status::JAILED,
    ] {
        let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
        assert_eq!(fixture.apply().unwrap(), Bytes::new());
        let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
            MetadosisContract::new(storage)
                .ocomp_job_record(fixture.intent_id, &fixture.limits)
                .unwrap()
                .unwrap()
                .finalized
                .unwrap()
        });
        let missing = Address::repeat_byte(0xB0);
        fixture
            .provider
            .set_block_number(finalized.deadline_height - 1);
        StorageHandle::enter(&mut fixture.provider, |storage| {
            let mut validators = ValidatorSet::new(storage);
            transition_validator_to_status_for_test(
                &mut validators,
                missing,
                current_status,
                finalized.deadline_height - 1,
            );
            let transitioned = validators.get_validator(missing).unwrap().unwrap();
            validators
                .test_set_history(
                    missing,
                    ValidatorHistory::new(
                        transitioned.joined_at_height,
                        (transitioned.deactivated_at_height != 0)
                            .then_some(transitioned.deactivated_at_height),
                        7,
                        transitioned.missed_blocks,
                        transitioned.missed_votes,
                        transitioned.blocks_proposed,
                    ),
                )
                .unwrap();
        });

        close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

        StorageHandle::enter(&mut fixture.provider, |storage| {
            let validators = ValidatorSet::new(storage.clone());
            let after = validators.get_validator(missing).unwrap().unwrap();
            assert_eq!(after.status, current_status);
            assert_eq!(after.slash_count, 7);

            let summary = MetadosisContract::new(storage)
                .result_vote_accountability(finalized.job_id, &fixture.limits)
                .unwrap()
                .unwrap()
                .closed_summary
                .unwrap();
            assert_eq!(summary.missing_bitmap, vec![0b0000_1011]);
        });
    }
}

#[test]
fn deadline_records_missing_removed_validator_without_fatal() {
    let mut fixture = ActivationFixture::new_voting(20, 1_010, true);
    assert_eq!(fixture.apply().unwrap(), Bytes::new());
    let finalized = StorageHandle::enter(&mut fixture.provider, |storage| {
        MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .finalized
            .unwrap()
    });
    let removed = Address::repeat_byte(0xB0);
    fixture
        .provider
        .set_block_number(finalized.deadline_height - 1);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut validators = ValidatorSet::new(storage);
        transition_validator_to_status_for_test(
            &mut validators,
            removed,
            validator_status::INACTIVE,
            finalized.deadline_height - 1,
        );
        assert_eq!(validators.cleanup_inactive_validators(1).unwrap(), 1);
        assert!(validators.get_validator(removed).unwrap().is_none());
    });

    close_completed_response_window(&mut fixture, finalized.deadline_height).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let summary = MetadosisContract::new(storage)
            .result_vote_accountability(finalized.job_id, &fixture.limits)
            .unwrap()
            .unwrap()
            .closed_summary
            .unwrap();
        assert_eq!(summary.missing_bitmap, vec![0b0000_1011]);
    });
}

// OCOMP-TEST-ID: OCM-APL-002
// OCOMP-TEST-ID: OCM-E2E-006
#[test]
fn q_forming_faults_restore_all_state_and_exact_retry_matches_clean_execution() {
    for (owner, address) in [
        ("Nod", NOD_ADDRESS),
        ("Contributor", INTEX_ADDRESS),
        ("Tribute", TRIBUTE_ADDRESS),
        ("CarryOver", PROMIS_LIMIT_ADDRESS),
    ] {
        let mut fixture = ActivationFixture::new(20, 1_010, true);
        let before = fixture.rollback_snapshot();
        fixture.provider.fail_mutation_at_address(address);

        let error = fixture
            .apply()
            .expect_err("q-forming owner fault must abort the whole command");
        assert!(
            matches!(
                error,
                PrecompileError::Storage(_)
                    | PrecompileError::Fatal(_)
                    | PrecompileError::Revert(_)
                    | PrecompileError::RevertBytes(_)
            ),
            "{owner} failure returned the wrong error class"
        );
        fixture.provider.clear_mutation_failure();
        assert_eq!(fixture.rollback_snapshot(), before);
        assert_eq!(fixture.apply().unwrap(), Bytes::new());
        assert_eq!(fixture.terminal_outcome(), ActivationOutcome::Applied);
    }

    for fault in [
        ActivationReceiptFault::Nod,
        ActivationReceiptFault::Contributor,
        ActivationReceiptFault::Tribute,
        ActivationReceiptFault::CarryOver,
        ActivationReceiptFault::RequestSplit,
    ] {
        let mut fixture = ActivationFixture::new(20, 1_010, true);
        let before = fixture.rollback_snapshot();
        let error = fixture
            .apply_with_receipt_fault(fault)
            .expect_err("invalid activation receipt must reject the forming vote");
        assert!(
            matches!(error, PrecompileError::Revert(_)),
            "invalid activation receipt returned the wrong error class: {error}"
        );
        assert_eq!(fixture.rollback_snapshot(), before);
        assert_open_job_after_activation_rejection(&mut fixture);
        assert_eq!(fixture.apply().unwrap(), Bytes::new());
        assert_eq!(fixture.terminal_outcome(), ActivationOutcome::Applied);
    }

    let mut control = ActivationFixture::new(20, 1_010, true);
    control.provider.fail_after_mutation_at(usize::MAX);
    assert_eq!(control.apply().unwrap(), Bytes::new());
    let mutation_count = control.provider.clear_mutation_failure();
    assert!(
        mutation_count >= 10,
        "q-forming must cross vote, quorum, owner, terminal, index, receipt and event boundaries"
    );
    let clean_after = control.rollback_snapshot();

    for operation in 0..mutation_count {
        let mut fixture = ActivationFixture::new(20, 1_010, true);
        let before = fixture.rollback_snapshot();
        fixture.provider.fail_after_mutation_at(operation);

        assert!(matches!(fixture.apply(), Err(PrecompileError::Storage(_))));
        assert_eq!(
            fixture.provider.clear_mutation_failure(),
            operation + 1,
            "q-forming fault must occur at the selected persistent mutation"
        );
        assert_eq!(
            fixture.rollback_snapshot(),
            before,
            "q-forming mutation fault {operation} leaked state, events, or CE work"
        );

        assert_eq!(fixture.apply().unwrap(), Bytes::new());
        assert_eq!(
            fixture.rollback_snapshot(),
            clean_after,
            "q-forming retry after mutation fault {operation} diverged from clean execution"
        );
        assert_eq!(fixture.terminal_outcome(), ActivationOutcome::Applied);
    }
}

#[test]
fn changed_activation_preconditions_reject_quorum_commit_without_closing_the_job() {
    let prepare_conflicted = || {
        let mut fixture = ActivationFixture::new(20, 1_010, true);
        StorageHandle::enter(&mut fixture.provider, |storage| {
            let tribute = TributeContract::new(storage);
            let mut admission = tribute
                .day_pre_admission
                .get(TEST_WWD)
                .unwrap()
                .expect("seeded Tribute pre-admission must exist");
            admission.source_generation += 1;
            tribute.day_pre_admission.update(&admission).unwrap();
        });
        fixture
    };

    let mut fixture = prepare_conflicted();
    let before = fixture.rollback_snapshot();
    let PrecompileError::RevertBytes(expected) =
        crate::errors::result_vote_rejection(crate::errors::vote_rejection_code::PROTOCOL_VOTE)
    else {
        unreachable!("activation rejection is encoded bytes")
    };

    let PrecompileError::RevertBytes(actual) = fixture.apply().unwrap_err() else {
        panic!("changed activation preconditions returned the wrong error class")
    };
    assert_eq!(actual, expected);
    assert_eq!(fixture.rollback_snapshot(), before);
    let PrecompileError::RevertBytes(actual) = fixture.apply().unwrap_err() else {
        panic!("replayed changed activation preconditions returned the wrong error class")
    };
    assert_eq!(actual, expected);
    assert_eq!(fixture.rollback_snapshot(), before);

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let job = MetadosisContract::new(storage)
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(job.status, OcompJobStatus::VotingOpen);
        assert!(job.terminal.is_none());
    });
}

#[test]
fn quorum_preserved_response_close_rolls_back_every_mutation_and_retries_exactly() {
    let prepare = || {
        let mut fixture = ActivationFixture::new(20, 1_010, true);
        assert_eq!(fixture.apply().unwrap(), Bytes::new());
        let deadline_height = StorageHandle::enter(&mut fixture.provider, |storage| {
            MetadosisContract::new(storage)
                .ocomp_job_record(fixture.intent_id, &fixture.limits)
                .unwrap()
                .unwrap()
                .finalized
                .unwrap()
                .deadline_height
        });
        (fixture, deadline_height)
    };

    let (mut control, deadline_height) = prepare();
    control.provider.fail_after_mutation_at(usize::MAX);
    close_completed_response_window(&mut control, deadline_height).unwrap();
    let mutation_count = control.provider.clear_mutation_failure();
    assert!(
        mutation_count >= 2,
        "quorum-preserved close must persist accountability and remove the deadline key"
    );
    let clean_after = control.rollback_snapshot();

    for operation in 0..mutation_count {
        let (mut fixture, deadline_height) = prepare();
        let before = fixture.rollback_snapshot();
        fixture.provider.fail_after_mutation_at(operation);

        assert!(matches!(
            close_completed_response_window(&mut fixture, deadline_height),
            Err(PrecompileError::Storage(_))
        ));
        assert_eq!(fixture.provider.clear_mutation_failure(), operation + 1);
        assert_eq!(fixture.rollback_snapshot(), before);

        close_completed_response_window(&mut fixture, deadline_height).unwrap();
        assert_eq!(fixture.rollback_snapshot(), clean_after);
        assert_eq!(fixture.terminal_outcome(), ActivationOutcome::Applied);
    }
}

// OCOMP-TEST-ID: OCM-TIM-001
#[test]
fn request_pinned_semantics_are_identical_at_different_activation_heights() {
    let mut first = ActivationFixture::new(20, 1_010, true);
    let first_calldata = first.calldata();
    first.apply().expect("first q-forming vote must apply");
    assert_eq!(first.terminal_outcome(), ActivationOutcome::Applied);
    let first_semantics = first.semantic_snapshot();
    let first_metadata = first.activation_metadata();
    let first_state = first.rollback_snapshot();

    let mut second = ActivationFixture::new(40, 2_020, true);
    assert_eq!(
        second.calldata(),
        first_calldata,
        "activation height is not part of the request-pinned computation"
    );
    second.apply().expect("second q-forming vote must apply");
    assert_eq!(second.terminal_outcome(), ActivationOutcome::Applied);
    let mut second_semantics = second.semantic_snapshot();
    let second_metadata = second.activation_metadata();
    let second_state = second.rollback_snapshot();

    assert_eq!(first_semantics.nod.last_progress_height, 20);
    assert_eq!(second_semantics.nod.last_progress_height, 40);
    second_semantics.nod.last_progress_height = first_semantics.nod.last_progress_height;
    assert_eq!(first_semantics, second_semantics);
    assert_eq!(first_semantics.nod.issued_at, TEST_LOGICAL_TIME);
    assert_eq!(
        first_metadata,
        ActivationMetadata {
            activated_at_height: 20,
            activated_at_time: 1_010,
        }
    );
    assert_eq!(
        second_metadata,
        ActivationMetadata {
            activated_at_height: 40,
            activated_at_time: 2_020,
        }
    );
    assert_ne!(first_state, second_state);
}

fn result_digest(fixture: &ActivationFixture) -> B256 {
    fixture.result.result_digest(&fixture.limits).unwrap()
}

fn submit_vote_result(
    fixture: &mut ActivationFixture,
    vote: &outbe_ocomp_protocol::vote::ResultVoteV1,
    height: u64,
) -> outbe_primitives::error::Result<Bytes> {
    fixture.provider.set_block_number(height);
    fixture.provider.enable_lysis_activation_frame();
    fixture
        .provider
        .enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::VerifiedResultVote);
    let vote_bytes = vote.encode_canonical(&fixture.limits).unwrap();
    let calldata = IMetadosis::submitLysisResultCall {
        resultVoteV1: Bytes::from(vote_bytes),
    }
    .abi_encode();
    StorageHandle::enter(&mut fixture.provider, |storage| {
        crate::commands::submit_verified_result_vote(
            storage,
            &fixture.scope,
            &calldata,
            U256::ZERO,
            false,
        )
    })
}

fn submit_vote(fixture: &mut ActivationFixture, validator_index: u8, height: u64) {
    let vote = fixture.signed_result_vote(validator_index);
    assert_eq!(
        submit_vote_result(fixture, &vote, height).unwrap(),
        Bytes::new()
    );
}

fn assert_public_dispatch_uses_pinned_dynamic_membership(
    member_count: u8,
    quorum_threshold: u16,
    quorum_bitmap: Vec<u8>,
) {
    let mut fixture =
        ActivationFixture::new_voting_with_member_count(14, 1_010, true, member_count);
    let job_id = fixture.result.job_id;
    let intent_id = fixture.intent_id;
    let expected_result_digest = result_digest(&fixture);

    for index in 0..member_count {
        submit_vote(&mut fixture, index, 14 + u64::from(index));
    }

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let limits = poc_schema_limits();
        let contract = MetadosisContract::new(storage.clone());
        let record = contract
            .ocomp_job_record(intent_id, &limits)
            .unwrap()
            .unwrap();
        assert_eq!(record.status, OcompJobStatus::Completed);
        assert_eq!(record.intent.result_member_count, u16::from(member_count));
        assert_eq!(record.intent.result_quorum_threshold, quorum_threshold);
        let quorum = record.finalized.unwrap().quorum.unwrap();
        assert_eq!(quorum.result_digest, expected_result_digest);
        assert_eq!(quorum.signer_bitmap, quorum_bitmap);

        let encoded = crate::precompile::dispatch(
            storage,
            &IMetadosis::getOffchainVoteAccountabilityCall { jobId: job_id }.abi_encode(),
            Address::repeat_byte(0x41),
            U256::ZERO,
        )
        .unwrap();
        let public =
            IMetadosis::getOffchainVoteAccountabilityCall::abi_decode_returns(&encoded).unwrap();
        let accountability =
            OcompVoteAccountabilityV1::decode_canonical(public.as_ref(), &limits).unwrap();
        assert_eq!(accountability.slots.len(), usize::from(member_count));
        assert_eq!(
            accountability.slots.iter().flatten().count(),
            usize::from(member_count)
        );
        assert_eq!(accountability.quorum.unwrap(), quorum);
    });
}

// OCOMP-TEST-ID: OCM-VOT-001
#[test]
fn public_dispatch_uses_pinned_dynamic_membership_and_quorum() {
    assert_public_dispatch_uses_pinned_dynamic_membership(4, 3, vec![0b0000_0111]);
    assert_public_dispatch_uses_pinned_dynamic_membership(5, 4, vec![0b0000_1111]);
}

#[test]
fn historical_vote_participant_resolution_does_not_consult_current_active_status() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let vote = fixture.signed_result_vote(1);
    let prefix = vote.prefix();
    let historical_validator = Address::repeat_byte(0xB1);

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        let freeze_height = storage.block_number().unwrap();
        transition_validator_to_status_for_test(
            &mut validators,
            historical_validator,
            validator_status::INACTIVE,
            freeze_height,
        );

        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_participant(
                storage,
                &prefix,
                &fixture.limits,
            )
            .unwrap(),
            Some(historical_validator)
        );
    });
}

#[test]
fn system_carrier_signer_is_bound_to_the_historical_validator_or_its_delegate() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let vote = fixture.signed_result_vote(1);
    let prefix = vote.prefix();
    let historical_validator = Address::repeat_byte(0xB1);
    let delegate = Address::repeat_byte(0xD1);

    StorageHandle::enter(&mut fixture.provider, |storage| {
        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_carrier_signer(
                storage.clone(),
                &prefix,
                historical_validator,
                &fixture.limits,
            )
            .unwrap(),
            Some(historical_validator)
        );
        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_carrier_signer(
                storage.clone(),
                &prefix,
                delegate,
                &fixture.limits,
            )
            .unwrap(),
            None
        );

        let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        validators
            .set_delegate(
                historical_validator,
                outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                delegate,
            )
            .unwrap();

        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_carrier_signer(
                storage.clone(),
                &prefix,
                historical_validator,
                &fixture.limits,
            )
            .unwrap(),
            None,
            "an explicit delegate disables direct carrier submission"
        );
        assert_eq!(
            crate::ocomp::vote::resolve_historical_result_vote_carrier_signer(
                storage,
                &prefix,
                delegate,
                &fixture.limits,
            )
            .unwrap(),
            Some(historical_validator)
        );
    });
}

#[test]
fn vote_binding_mismatch_is_rejected_before_historical_snapshot_lookup() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let mut vote = fixture.signed_result_vote(1);
    let snapshot_key = outbe_validatorset::committee_snapshot_key(
        vote.result_validator_set_epoch,
        vote.result_committee_set_hash,
    );
    vote.result_ocomp_binding_hash = B256::repeat_byte(0xEE);

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        validators
            .committee_snapshot_exists
            .write(&snapshot_key, false)
            .unwrap();

        let error = MetadosisContract::new(storage)
            .record_ocomp_result_vote(&vote, 14, &fixture.scope, &fixture.limits)
            .unwrap_err();
        assert!(matches!(
            error,
            PrecompileError::Revert(message)
                if message == "OCOMP result vote does not match pinned job binding"
        ));
    });
}

#[test]
fn public_vote_rejects_every_pinned_identity_and_signature_mismatch() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let base = fixture.signed_result_vote(1);
    let mut cases = Vec::new();

    let mut wrong = base.clone();
    wrong.protocol_bundle_hash = B256::repeat_byte(0xA1);
    cases.push(("protocol bundle", wrong));
    let mut wrong = base.clone();
    wrong.attempt = wrong.attempt.saturating_add(1);
    cases.push(("attempt", wrong));
    let mut wrong = base.clone();
    wrong.result_validator_set_epoch = wrong.result_validator_set_epoch.saturating_add(1);
    cases.push(("ValidatorSet epoch", wrong));
    let mut wrong = base.clone();
    wrong.result_committee_set_hash = B256::repeat_byte(0xA2);
    cases.push(("consensus snapshot hash", wrong));
    let mut wrong = base.clone();
    wrong.result_ocomp_binding_hash = B256::repeat_byte(0xA3);
    cases.push(("OCOMP binding hash", wrong));
    let mut wrong = base.clone();
    wrong.ocomp_key_hash = B256::repeat_byte(0xA4);
    cases.push(("OCOMP key hash", wrong));
    let mut wrong = base.clone();
    wrong.key_epoch = wrong.key_epoch.saturating_add(1);
    cases.push(("key epoch", wrong));
    let mut wrong = base;
    wrong.signature_rs[0] ^= 1;
    cases.push(("signature", wrong));

    for (label, vote) in cases {
        assert!(
            matches!(
                submit_vote_result(&mut fixture, &vote, 14),
                Err(PrecompileError::RevertBytes(_))
            ),
            "{label} mismatch must be a public vote rejection"
        );
    }
}

#[test]
fn old_job_keeps_its_four_member_snapshot_across_a_four_to_five_boundary() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let next_snapshot = fixture.activate_additional_validator_for_test(4);
    assert_eq!(next_snapshot.member_count, 5);

    let old_participant_vote = fixture.signed_result_vote(3);
    assert_eq!(
        submit_vote_result(&mut fixture, &old_participant_vote, 14).unwrap(),
        Bytes::new()
    );

    let new_validator_vote = fixture.signed_result_vote(4);
    assert!(matches!(
        submit_vote_result(&mut fixture, &new_validator_vote, 15),
        Err(PrecompileError::RevertBytes(_))
    ));
}

#[test]
fn missing_pinned_snapshot_reverts_public_vote_without_changing_the_job() {
    let mut fixture = ActivationFixture::new_voting(14, 1_010, true);
    let vote = fixture.signed_result_vote(0);
    let snapshot_key = outbe_validatorset::committee_snapshot_key(
        vote.result_validator_set_epoch,
        vote.result_committee_set_hash,
    );
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let validators = outbe_validatorset::contract::ValidatorSet::new(storage);
        validators
            .committee_snapshot_exists
            .write(&snapshot_key, false)
            .unwrap();
    });

    assert!(matches!(
        submit_vote_result(&mut fixture, &vote, 14),
        Err(PrecompileError::RevertBytes(_))
    ));
    StorageHandle::enter(&mut fixture.provider, |storage| {
        let contract = MetadosisContract::new(storage);
        let record = contract
            .ocomp_job_record(fixture.intent_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert_eq!(record.status, OcompJobStatus::VotingOpen);
        let accountability = contract
            .result_vote_accountability(vote.job_id, &fixture.limits)
            .unwrap()
            .unwrap();
        assert!(accountability.slots.iter().all(Option::is_none));
        assert!(accountability.quorum.is_none());
    });
}
