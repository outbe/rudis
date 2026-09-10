use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::GOVERNANCE_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_vote::constants::VOTING_WINDOW_BLOCKS;
use outbe_vote::handlers::{VoteTarget, VoteTargetRegistry};
use outbe_vote::schema::ProposalStatus;
use outbe_vote::schema::Vote;

use crate::precompile::IGovernance;
use crate::schema::GovernanceContract;
use crate::status;
use crate::vote_target::GovernanceVoteTarget;
use crate::vote_target::{GovernanceVotePayload, ProposalKind};

static GOVERNANCE_VOTE_TARGET: GovernanceVoteTarget = GovernanceVoteTarget;
static VOTE_HANDLERS: &[&dyn VoteTarget] = &[&GOVERNANCE_VOTE_TARGET];
static VOTE_TARGET_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(VOTE_HANDLERS);

const PROPOSER: Address = address!("0x1111111111111111111111111111111111111111");
const VOTER_A: Address = address!("0x2222222222222222222222222222222222222222");
const VOTER_B: Address = address!("0x3333333333333333333333333333333333333333");

const KINDS: [ProposalKind; 2] = [ProposalKind::Oip, ProposalKind::Gip];

fn block_ctx(storage: StorageHandle, block_number: u64) -> BlockRuntimeContext {
    BlockRuntimeContext::new(BlockContext::empty_for_tests(block_number, 0, 1), storage)
}

fn with_vote_provider<F: FnOnce(StorageHandle)>(f: F) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(1);
    {
        let storage = StorageHandle::new(&mut provider);
        setup_validators(storage.clone());
        f(storage);
    }
    provider
}

fn with_vote<F: FnOnce(StorageHandle)>(f: F) {
    let _ = with_vote_provider(f);
}

fn setup_validators(storage: StorageHandle) {
    let owner = address!("0xffffffffffffffffffffffffffffffffffffffff");
    for (addr, seed) in [(PROPOSER, 1u8), (VOTER_A, 2), (VOTER_B, 3)] {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.config_owner.write(owner).unwrap();
        vs.set_config_max_validators(100).unwrap();
        let mut pk = [0u8; 48];
        pk[0] = seed;
        vs.register_validator(owner, addr, &pk).unwrap();
        vs.activate_validator_via_boundary_for_test(addr).unwrap();
    }
}

fn process_begin_block_test(storage: StorageHandle, block_number: u64) {
    let ctx = block_ctx(storage.clone(), block_number);
    Vote::new(storage)
        .process_begin_block(&ctx, &VOTE_TARGET_REGISTRY)
        .unwrap();
}

fn create_and_pass(vote: &mut Vote<'_>, kind: ProposalKind, text: &str, current: u64) -> U256 {
    let proposal_id = vote
        .create_proposal(
            PROPOSER,
            GOVERNANCE_ADDRESS,
            &GovernanceVotePayload::encode(kind, text),
            current,
            &VOTE_TARGET_REGISTRY,
        )
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_B, true, current + 2)
        .unwrap();
    proposal_id
}

fn submitted_sig(kind: ProposalKind) -> B256 {
    match kind {
        ProposalKind::Oip => IGovernance::OipSubmitted::SIGNATURE_HASH,
        ProposalKind::Gip => IGovernance::GipSubmitted::SIGNATURE_HASH,
    }
}

fn assert_approved(gov: &GovernanceContract<'_>, kind: ProposalKind, text: &str) {
    let id = U256::from(1);
    let (record_status, author, body, listed) = match kind {
        ProposalKind::Oip => {
            let p = gov.get_oip(id).unwrap().unwrap();
            let listed = gov
                .oips_by_status(status::APPROVED, U256::ZERO, U256::from(10))
                .unwrap();
            (p.status, p.author, p.text, listed)
        }
        ProposalKind::Gip => {
            let p = gov.get_gip(id).unwrap().unwrap();
            let listed = gov
                .gips_by_status(status::APPROVED, U256::ZERO, U256::from(10))
                .unwrap();
            (p.status, p.author, p.text, listed)
        }
    };
    assert_eq!(record_status, status::APPROVED);
    assert_eq!(author, PROPOSER);
    assert_eq!(body, text);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
}

fn assert_absent(gov: &GovernanceContract<'_>, kind: ProposalKind) {
    let id = U256::from(1);
    match kind {
        ProposalKind::Oip => {
            assert!(gov.get_oip(id).unwrap().is_none());
            assert_eq!(gov.oip_count().unwrap(), 0);
        }
        ProposalKind::Gip => {
            assert!(gov.get_gip(id).unwrap().is_none());
            assert_eq!(gov.gip_count().unwrap(), 0);
        }
    }
}

#[test]
fn approved_vote_creates_approved_proposal() {
    for kind in KINDS {
        let text = match kind {
            ProposalKind::Oip => "oip body",
            ProposalKind::Gip => "gip body",
        };
        let provider = with_vote_provider(|storage| {
            let mut vote = Vote::new(storage.clone());
            let current = 100u64;
            let proposal_id = create_and_pass(&mut vote, kind, text, current);
            process_begin_block_test(storage.clone(), current + VOTING_WINDOW_BLOCKS + 1);

            assert_eq!(
                vote.proposals
                    .get(proposal_id)
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Approved
            );
            assert_approved(&GovernanceContract::new(storage), kind, text);
        });
        assert!(provider
            .get_events(GOVERNANCE_ADDRESS)
            .iter()
            .any(|log| log.topics().first() == Some(&submitted_sig(kind))));
    }
}

#[test]
fn invalid_json_payload_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let err = vote
            .create_proposal(
                PROPOSER,
                GOVERNANCE_ADDRESS,
                "not-json",
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("invalid proposal payload")
        ));
    });
}

#[test]
fn unknown_kind_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let err = vote
            .create_proposal(
                PROPOSER,
                GOVERNANCE_ADDRESS,
                r#"{"kind":"xip","text":"body"}"#,
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("invalid vote payload")
        ));
    });
}

#[test]
fn empty_text_is_rejected_at_creation() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let err = vote
            .create_proposal(
                PROPOSER,
                GOVERNANCE_ADDRESS,
                r#"{"kind":"oip","text":""}"#,
                200,
                &VOTE_TARGET_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Revert(msg) if msg.contains("text must not be empty")
        ));
    });
}

#[test]
fn expired_governance_proposal_does_not_create_record() {
    for kind in KINDS {
        with_vote(|storage| {
            let mut vote = Vote::new(storage.clone());
            let current = 400u64;
            let proposal_id = vote
                .create_proposal(
                    PROPOSER,
                    GOVERNANCE_ADDRESS,
                    &GovernanceVotePayload::encode(kind, "should not land"),
                    current,
                    &VOTE_TARGET_REGISTRY,
                )
                .unwrap();
            vote.cast_vote_approve(proposal_id, VOTER_A, true, current + 1)
                .unwrap();

            process_begin_block_test(storage.clone(), current + VOTING_WINDOW_BLOCKS + 1);
            assert_eq!(
                vote.proposals
                    .get(proposal_id)
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Expired
            );
            assert_absent(&GovernanceContract::new(storage), kind);
        });
    }
}
