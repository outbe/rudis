use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolError, SolEvent};
use outbe_primitives::{
    addresses::{UPDATE_ADDRESS, VOTE_ADDRESS},
    block::{BlockContext, BlockRuntimeContext},
    error::{PrecompileError, Result},
    stablecoin_fork::MAX_PENDING_PUBLIC_BONDED_PROPOSALS,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};
use serde_json::Value;

use crate::{
    constants::VOTING_WINDOW_BLOCKS,
    handlers::{
        TargetAdmission, TargetExecutionOutcome, VoteTarget, VoteTargetContext, VoteTargetRegistry,
    },
    precompile::IVote,
    schema::{BondSettlement, ProposalStatus, Vote},
};

use super::{
    create_proposal_test, setup_default_validators, test_vote_registry, PROPOSER, VOTER_A,
};

struct RejectingApprovedTarget;

impl VoteTarget for RejectingApprovedTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, payload: &[u8], _context: VoteTargetContext) -> Result<()> {
        if serde_json::from_slice::<Value>(payload).is_ok_and(|value| value.is_object()) {
            Ok(())
        } else {
            Err(PrecompileError::Revert("expected object".into()))
        }
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        _payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        ctx.storage
            .sstore(UPDATE_ADDRESS, U256::from(999u64), U256::from(1u64))?;
        Ok(TargetExecutionOutcome::Error {
            reason: "characterized target failure".into(),
        })
    }
}

static REJECTING_TARGET: RejectingApprovedTarget = RejectingApprovedTarget;
static REJECTING_HANDLERS: &[&dyn VoteTarget] = &[&REJECTING_TARGET];
static REJECTING_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(REJECTING_HANDLERS);

struct TechnicallyFailingTarget;

impl VoteTarget for TechnicallyFailingTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, payload: &[u8], _context: VoteTargetContext) -> Result<()> {
        if serde_json::from_slice::<Value>(payload).is_ok_and(|value| value.is_object()) {
            Ok(())
        } else {
            Err(PrecompileError::Revert("expected object".into()))
        }
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        _payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        ctx.storage
            .sstore(UPDATE_ADDRESS, U256::from(999u64), U256::from(1u64))?;
        Err(PrecompileError::Fatal(
            "characterized infrastructure failure".into(),
        ))
    }
}

static TECHNICALLY_FAILING_TARGET: TechnicallyFailingTarget = TechnicallyFailingTarget;
static TECHNICALLY_FAILING_HANDLERS: &[&dyn VoteTarget] = &[&TECHNICALLY_FAILING_TARGET];
static TECHNICALLY_FAILING_REGISTRY: VoteTargetRegistry =
    VoteTargetRegistry::new(TECHNICALLY_FAILING_HANDLERS);

const RAW_PAYLOAD: &str = "{ \"z\":1, \"a\": [2, 3] }";

struct RawContextTarget;

impl VoteTarget for RawContextTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, payload: &[u8], context: VoteTargetContext) -> Result<()> {
        if payload != RAW_PAYLOAD.as_bytes()
            || context.proposer != PROPOSER
            || context.attached_value != U256::ZERO
            || context.block_number != 10
            || context.chain_id != 1
        {
            return Err(PrecompileError::Revert(
                "raw payload or target context changed".into(),
            ));
        }
        Ok(())
    }

    fn handle_approved(
        &self,
        _ctx: &BlockRuntimeContext,
        proposal_id: U256,
        payload: &[u8],
        context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        let expected_height = 10 + VOTING_WINDOW_BLOCKS + 1;
        if proposal_id != U256::from(1u64)
            || payload != RAW_PAYLOAD.as_bytes()
            || context.proposer != PROPOSER
            || context.attached_value != U256::ZERO
            || context.block_number != expected_height
            || context.chain_id != 1
        {
            return Err(PrecompileError::Fatal(
                "execution payload or target context changed".into(),
            ));
        }
        Ok(TargetExecutionOutcome::Applied)
    }
}

static RAW_CONTEXT_TARGET: RawContextTarget = RawContextTarget;
static RAW_CONTEXT_HANDLERS: &[&dyn VoteTarget] = &[&RAW_CONTEXT_TARGET];
static RAW_CONTEXT_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(RAW_CONTEXT_HANDLERS);
static DUPLICATE_HANDLERS: &[&dyn VoteTarget] = &[&RAW_CONTEXT_TARGET, &RAW_CONTEXT_TARGET];
static DUPLICATE_REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(DUPLICATE_HANDLERS);

struct PublicBondedTarget;

impl VoteTarget for PublicBondedTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn admission(&self) -> TargetAdmission {
        TargetAdmission::PublicBonded {
            amount: U256::from(123u64),
        }
    }

    fn validate(&self, _payload: &[u8], context: VoteTargetContext) -> Result<()> {
        if context.attached_value != U256::from(123u64) {
            return Err(PrecompileError::Fatal(
                "public bonded target received the wrong attached value".into(),
            ));
        }
        Ok(())
    }

    fn reserve(
        &self,
        storage: StorageHandle<'_>,
        proposal_id: U256,
        payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<()> {
        if payload == b"fail" {
            storage.sstore(UPDATE_ADDRESS, U256::from(998u64), U256::from(1u64))?;
            return Err(PrecompileError::Revert(
                "characterized public reservation failure".into(),
            ));
        }
        if payload == b"execution-error" {
            storage.sstore(UPDATE_ADDRESS, U256::from(997u64), proposal_id)?;
        }
        if payload == b"applied-write" {
            storage.sstore(UPDATE_ADDRESS, U256::from(994u64), proposal_id)?;
        }
        Ok(())
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        payload: &[u8],
        context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        if context.attached_value != U256::from(123u64) {
            return Err(PrecompileError::Fatal(
                "public bonded target lost its attached value at execution".into(),
            ));
        }
        if payload == b"execution-error" {
            ctx.storage
                .sstore(UPDATE_ADDRESS, U256::from(996u64), U256::from(1u64))?;
            return Ok(TargetExecutionOutcome::Error {
                reason: "characterized public target execution error".into(),
            });
        }
        if payload == b"applied-write" {
            ctx.storage
                .sstore(UPDATE_ADDRESS, U256::from(995u64), U256::from(1u64))?;
        }
        Ok(TargetExecutionOutcome::Applied)
    }
}

static PUBLIC_BONDED_TARGET: PublicBondedTarget = PublicBondedTarget;
static PUBLIC_BONDED_HANDLERS: &[&dyn VoteTarget] = &[&PUBLIC_BONDED_TARGET];
pub(super) static PUBLIC_BONDED_REGISTRY: VoteTargetRegistry =
    VoteTargetRegistry::new(PUBLIC_BONDED_HANDLERS);

struct FailingReserveTarget;

impl VoteTarget for FailingReserveTarget {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }

    fn validate(&self, _payload: &[u8], _context: VoteTargetContext) -> Result<()> {
        Ok(())
    }

    fn reserve(
        &self,
        storage: StorageHandle<'_>,
        _proposal_id: U256,
        _payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<()> {
        storage.sstore(UPDATE_ADDRESS, U256::from(999u64), U256::from(1u64))?;
        Err(PrecompileError::Revert(
            "characterized reservation failure".into(),
        ))
    }

    fn handle_approved(
        &self,
        _ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        _payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        Ok(TargetExecutionOutcome::Applied)
    }
}

static FAILING_RESERVE_TARGET: FailingReserveTarget = FailingReserveTarget;
static FAILING_RESERVE_HANDLERS: &[&dyn VoteTarget] = &[&FAILING_RESERVE_TARGET];
static FAILING_RESERVE_REGISTRY: VoteTargetRegistry =
    VoteTargetRegistry::new(FAILING_RESERVE_HANDLERS);

fn block_context(storage: StorageHandle<'_>, block_number: u64) -> BlockRuntimeContext<'_> {
    BlockRuntimeContext::new(BlockContext::empty_for_tests(block_number, 0, 1), storage)
}

fn public_bonded_finalization_fixture() -> (HashMapStorageProvider, U256, u64) {
    let owner = Address::repeat_byte(0x99);
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(130u64));
    provider.set_balance(owner, U256::from(11u64));
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage);
        proposal_id = vote
            .create_proposal_with_value(
                owner,
                UPDATE_ADDRESS,
                "applied-write",
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();
    }
    provider.clear_mutation_failure();
    (provider, proposal_id, 10 + VOTING_WINDOW_BLOCKS)
}

#[test]
fn creation_preserves_original_payload_bytes_in_state_and_log() {
    let mut provider = HashMapStorageProvider::new(1);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage);
        proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                &RAW_CONTEXT_REGISTRY,
            )
            .unwrap();
        let record = vote.proposals.get(proposal_id).unwrap().unwrap();
        assert_eq!(record.payload, RAW_PAYLOAD);
    }

    let created = provider
        .get_events(VOTE_ADDRESS)
        .iter()
        .find(|log| log.topics().first() == Some(&IVote::ProposalCreated::SIGNATURE_HASH))
        .expect("ProposalCreated log");
    let decoded = IVote::ProposalCreated::decode_log_data(created).unwrap();
    assert_eq!(decoded.proposalId, proposal_id);
    assert_eq!(decoded.payload, RAW_PAYLOAD);
}

#[test]
fn target_reservation_failure_rolls_back_proposal_target_state_and_log() {
    let mut provider = HashMapStorageProvider::new(1);
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        assert!(vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                &FAILING_RESERVE_REGISTRY,
            )
            .is_err());
        assert_eq!(vote.proposal_count.read().unwrap(), U256::ZERO);
        assert_eq!(vote.pending_proposal_ids.len().unwrap(), 0);
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(999u64)).unwrap(),
            U256::ZERO
        );
    }
    assert!(provider.get_events(VOTE_ADDRESS).is_empty());
}

#[test]
fn execution_receives_original_payload_and_exact_context() {
    let mut provider = HashMapStorageProvider::new(1);
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    let mut vote = Vote::new(storage.clone());
    let proposal_id = vote
        .create_proposal(
            PROPOSER,
            UPDATE_ADDRESS,
            RAW_PAYLOAD,
            10,
            &RAW_CONTEXT_REGISTRY,
        )
        .unwrap();
    vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
        .unwrap();

    let finalize_height = 10 + VOTING_WINDOW_BLOCKS + 1;
    vote.process_begin_block(
        &block_context(storage, finalize_height),
        &RAW_CONTEXT_REGISTRY,
    )
    .unwrap();

    assert_eq!(
        vote.proposals
            .get(proposal_id)
            .unwrap()
            .unwrap()
            .proposal_status()
            .unwrap(),
        ProposalStatus::Approved
    );
}

#[test]
fn registry_rejects_duplicate_target_modules() {
    assert!(matches!(
        DUPLICATE_REGISTRY.lookup(UPDATE_ADDRESS),
        Err(PrecompileError::Revert(message)) if message.contains("duplicate")
    ));
}

#[test]
fn public_bonded_admission_records_only_its_exact_liability() {
    assert_eq!(
        PUBLIC_BONDED_REGISTRY
            .lookup(UPDATE_ADDRESS)
            .unwrap()
            .admission(),
        TargetAdmission::PublicBonded {
            amount: U256::from(123u64)
        }
    );

    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(130u64));
    let storage = StorageHandle::new(&mut provider);
    let proposal_id = {
        let mut vote = Vote::new(storage);
        vote.create_proposal_with_value(
            Address::repeat_byte(0x99),
            UPDATE_ADDRESS,
            RAW_PAYLOAD,
            10,
            U256::from(123u64),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap()
    };
    let vote = Vote::new(StorageHandle::new(&mut provider));
    assert_eq!(
        vote.proposal_bond(proposal_id).unwrap().settlement,
        BondSettlement::Unsettled
    );
    assert_eq!(vote.bond_liabilities().unwrap(), U256::from(123u64));
    drop(vote);
    assert_eq!(provider.get_balance(VOTE_ADDRESS), U256::from(130u64));
}

#[test]
fn public_bonded_value_identity_and_global_caps_fail_before_allocation() {
    let outsider = Address::repeat_byte(0x99);

    let mut invalid_provider = HashMapStorageProvider::new(1);
    {
        let storage = StorageHandle::new(&mut invalid_provider);
        let mut vote = Vote::new(storage);
        for actual in [U256::ZERO, U256::from(122u64), U256::from(124u64)] {
            match vote
                .create_proposal_with_value(
                    outsider,
                    UPDATE_ADDRESS,
                    RAW_PAYLOAD,
                    10,
                    actual,
                    &PUBLIC_BONDED_REGISTRY,
                )
                .unwrap_err()
            {
                PrecompileError::RevertBytes(bytes) => {
                    assert_eq!(&bytes[..4], IVote::InvalidProposalBond::SELECTOR)
                }
                other => panic!("expected InvalidProposalBond, got {other:?}"),
            }
        }
        assert_eq!(vote.proposal_count.read().unwrap(), U256::ZERO);
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
    }
    assert!(invalid_provider.storage.is_empty());
    assert!(invalid_provider.get_events(VOTE_ADDRESS).is_empty());

    let mut identity_provider = HashMapStorageProvider::new(1);
    identity_provider.set_balance(VOTE_ADDRESS, U256::from(246u64));
    {
        let storage = StorageHandle::new(&mut identity_provider);
        let mut vote = Vote::new(storage);
        vote.create_proposal_with_value(
            outsider,
            UPDATE_ADDRESS,
            RAW_PAYLOAD,
            10,
            U256::from(123u64),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
        assert!(matches!(
            vote.create_proposal_with_value(
                outsider,
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            ),
            Err(PrecompileError::Revert(message))
                if message == "proposer already has a pending public bonded proposal"
        ));
        assert_eq!(vote.proposal_count.read().unwrap(), U256::from(1u64));
        assert_eq!(vote.bond_liabilities().unwrap(), U256::from(123u64));
    }

    let mut cap_provider = HashMapStorageProvider::new(1);
    let cap = MAX_PENDING_PUBLIC_BONDED_PROPOSALS;
    cap_provider.set_balance(VOTE_ADDRESS, U256::from(123u64) * U256::from(cap + 1));
    {
        let storage = StorageHandle::new(&mut cap_provider);
        let mut vote = Vote::new(storage);
        for index in 0..cap {
            vote.create_proposal_with_value(
                Address::from_word(U256::from(index + 1).into()),
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();
        }
        assert!(matches!(
            vote.create_proposal_with_value(
                Address::repeat_byte(0xaa),
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            ),
            Err(PrecompileError::Revert(message))
                if message == "too many pending public bonded proposals"
        ));
        assert_eq!(vote.proposal_count.read().unwrap(), U256::from(cap));
        assert_eq!(
            vote.bond_liabilities().unwrap(),
            U256::from(123u64) * U256::from(cap)
        );
    }
}

#[test]
fn public_reservation_failure_rolls_back_proposal_liability_and_logs() {
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(123u64));
    {
        let storage = StorageHandle::new(&mut provider);
        let mut vote = Vote::new(storage.clone());
        assert!(vote
            .create_proposal_with_value(
                Address::repeat_byte(0x99),
                UPDATE_ADDRESS,
                "fail",
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .is_err());
        assert_eq!(vote.proposal_count.read().unwrap(), U256::ZERO);
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(998u64)).unwrap(),
            U256::ZERO
        );
    }
    assert!(provider.storage.is_empty());
    assert!(provider.get_events(VOTE_ADDRESS).is_empty());
}

#[test]
fn public_bonded_execution_error_rolls_back_target_only_and_retains_bond_and_reservation() {
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(123u64));
    let storage = StorageHandle::new(&mut provider);
    setup_default_validators(storage.clone());
    let mut vote = Vote::new(storage.clone());
    let proposal_id = vote
        .create_proposal_with_value(
            Address::repeat_byte(0x99),
            UPDATE_ADDRESS,
            "execution-error",
            10,
            U256::from(123u64),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
    vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
        .unwrap();
    vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
        .unwrap();

    let deadline = 10 + VOTING_WINDOW_BLOCKS;
    vote.process_begin_block(
        &block_context(storage.clone(), deadline + 1),
        &PUBLIC_BONDED_REGISTRY,
    )
    .unwrap();

    assert_eq!(
        vote.proposals
            .get(proposal_id)
            .unwrap()
            .unwrap()
            .proposal_status()
            .unwrap(),
        ProposalStatus::Error
    );
    assert_eq!(vote.list_pending_proposal_ids().unwrap(), vec![proposal_id]);
    assert_eq!(
        vote.proposal_bond(proposal_id).unwrap().settlement,
        BondSettlement::Unsettled
    );
    assert_eq!(vote.bond_liabilities().unwrap(), U256::from(123u64));
    assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), U256::from(123u64));
    assert_eq!(
        storage.balance(Address::repeat_byte(0x99)).unwrap(),
        U256::ZERO
    );
    assert_eq!(
        storage.sload(UPDATE_ADDRESS, U256::from(997u64)).unwrap(),
        proposal_id,
        "admission reservation must survive target execution rollback"
    );
    assert_eq!(
        storage.sload(UPDATE_ADDRESS, U256::from(996u64)).unwrap(),
        U256::ZERO,
        "partial target execution must roll back"
    );
}

#[test]
fn approved_public_bond_refunds_once_and_preserves_forced_surplus() {
    let owner = Address::repeat_byte(0x99);
    let forced_surplus = U256::from(7u64);
    let starting_owner_balance = U256::from(11u64);
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(123u64) + forced_surplus);
    provider.set_balance(owner, starting_owner_balance);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = vote
            .create_proposal_with_value(
                owner,
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        vote.process_begin_block(
            &block_context(storage.clone(), deadline + 1),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Approved
        );
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Refunded
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
        assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
        assert_eq!(
            storage.balance(owner).unwrap(),
            starting_owner_balance + U256::from(123u64)
        );

        vote.process_begin_block(
            &block_context(storage.clone(), deadline + 2),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
        assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
        assert_eq!(
            storage.balance(owner).unwrap(),
            starting_owner_balance + U256::from(123u64)
        );
    }

    let refunds = provider
        .get_events(VOTE_ADDRESS)
        .iter()
        .filter(|log| log.topics().first() == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH))
        .collect::<Vec<_>>();
    assert_eq!(refunds.len(), 1);
    let refund = IVote::ProposalBondRefunded::decode_log_data(refunds[0]).unwrap();
    assert_eq!(refund.proposalId, proposal_id);
    assert_eq!(refund.owner, owner);
    assert_eq!(refund.amount, U256::from(123u64));
}

#[test]
fn expired_public_bond_burns_once_and_preserves_forced_surplus() {
    let owner = Address::repeat_byte(0x99);
    let forced_surplus = U256::from(7u64);
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(123u64) + forced_surplus);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = vote
            .create_proposal_with_value(
                owner,
                UPDATE_ADDRESS,
                RAW_PAYLOAD,
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        vote.process_begin_block(
            &block_context(storage.clone(), deadline + 1),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Expired
        );
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Burned
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
        assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
        assert_eq!(storage.balance(owner).unwrap(), U256::ZERO);

        vote.process_begin_block(
            &block_context(storage.clone(), deadline + 2),
            &PUBLIC_BONDED_REGISTRY,
        )
        .unwrap();
        assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
    }

    let burns = provider
        .get_events(VOTE_ADDRESS)
        .iter()
        .filter(|log| log.topics().first() == Some(&IVote::ProposalBondBurned::SIGNATURE_HASH))
        .collect::<Vec<_>>();
    assert_eq!(burns.len(), 1);
    let burn = IVote::ProposalBondBurned::decode_log_data(burns[0]).unwrap();
    assert_eq!(burn.proposalId, proposal_id);
    assert_eq!(burn.owner, owner);
    assert_eq!(burn.amount, U256::from(123u64));
}

#[test]
fn insufficient_escrow_rolls_back_target_status_index_accounting_and_events() {
    let owner = Address::repeat_byte(0x99);
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(VOTE_ADDRESS, U256::from(123u64));
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = vote
            .create_proposal_with_value(
                owner,
                UPDATE_ADDRESS,
                "applied-write",
                10,
                U256::from(123u64),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();
        storage
            .decrease_balance(VOTE_ADDRESS, U256::from(1u64))
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        assert!(matches!(
            vote.process_begin_block(
                &block_context(storage.clone(), deadline + 1),
                &PUBLIC_BONDED_REGISTRY,
            ),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending
        );
        assert_eq!(vote.list_pending_proposal_ids().unwrap(), vec![proposal_id]);
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Unsettled
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::from(123u64));
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(994u64)).unwrap(),
            proposal_id,
            "admission reservation must survive failed settlement"
        );
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(995u64)).unwrap(),
            U256::ZERO,
            "target execution must roll back with failed settlement"
        );
        assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), U256::from(122u64));
        assert_eq!(storage.balance(owner).unwrap(), U256::ZERO);
    }

    let logs = provider.get_events(VOTE_ADDRESS);
    assert_eq!(
        logs.iter()
            .filter(|log| {
                log.topics().first() == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
            })
            .count(),
        0
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.topics().first() == Some(&IVote::ProposalApproved::SIGNATURE_HASH))
            .count(),
        0
    );
}

#[test]
fn failure_after_every_approved_finalization_mutation_rolls_back_everything() {
    let (mut baseline, baseline_id, deadline) = public_bonded_finalization_fixture();
    {
        let storage = StorageHandle::new(&mut baseline);
        Vote::new(storage.clone())
            .process_begin_block(
                &block_context(storage, deadline + 1),
                &PUBLIC_BONDED_REGISTRY,
            )
            .unwrap();
    }
    let mutation_count = baseline.clear_mutation_failure();
    assert!(mutation_count > 0);
    assert_eq!(baseline_id, U256::from(1u64));

    for failure_point in 0..mutation_count {
        let (mut provider, proposal_id, deadline) = public_bonded_finalization_fixture();
        provider.fail_after_mutation_at(failure_point);
        {
            let storage = StorageHandle::new(&mut provider);
            let error = Vote::new(storage.clone())
                .process_begin_block(
                    &block_context(storage, deadline + 1),
                    &PUBLIC_BONDED_REGISTRY,
                )
                .unwrap_err();
            assert!(
                matches!(error, PrecompileError::Storage(_)),
                "failure point {failure_point} returned {error:?}"
            );
        }
        provider.clear_mutation_failure();

        let storage = StorageHandle::new(&mut provider);
        let vote = Vote::new(storage.clone());
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending,
            "failure point {failure_point}"
        );
        assert_eq!(
            vote.list_pending_proposal_ids().unwrap(),
            vec![proposal_id],
            "failure point {failure_point}"
        );
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Unsettled,
            "failure point {failure_point}"
        );
        assert_eq!(
            vote.bond_liabilities().unwrap(),
            U256::from(123u64),
            "failure point {failure_point}"
        );
        assert_eq!(
            storage.balance(VOTE_ADDRESS).unwrap(),
            U256::from(130u64),
            "failure point {failure_point}"
        );
        assert_eq!(
            storage.balance(Address::repeat_byte(0x99)).unwrap(),
            U256::from(11u64),
            "failure point {failure_point}"
        );
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(994u64)).unwrap(),
            proposal_id,
            "failure point {failure_point}"
        );
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(995u64)).unwrap(),
            U256::ZERO,
            "failure point {failure_point}"
        );
        drop(vote);
        drop(storage);
        assert_eq!(
            provider
                .get_events(VOTE_ADDRESS)
                .iter()
                .filter(|log| {
                    log.topics().first() == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
                })
                .count(),
            0,
            "failure point {failure_point}"
        );
        assert_eq!(
            provider
                .get_events(VOTE_ADDRESS)
                .iter()
                .filter(|log| {
                    log.topics().first() == Some(&IVote::ProposalApproved::SIGNATURE_HASH)
                })
                .count(),
            0,
            "failure point {failure_point}"
        );
    }
}

#[test]
fn approved_handler_failure_rolls_back_target_and_records_error_without_replay() {
    let mut provider = HashMapStorageProvider::new(1);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                "{\"kind\":\"legacy\"}",
                10,
                &REJECTING_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        vote.process_begin_block(
            &block_context(storage.clone(), deadline + 1),
            &REJECTING_REGISTRY,
        )
        .unwrap();
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Error
        );
        assert_eq!(vote.list_pending_proposal_ids().unwrap(), vec![proposal_id]);
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(999u64)).unwrap(),
            U256::ZERO
        );

        vote.process_begin_block(&block_context(storage, deadline + 2), &REJECTING_REGISTRY)
            .unwrap();
    }

    let errored_count = provider
        .get_events(VOTE_ADDRESS)
        .iter()
        .filter(|log| log.topics().first() == Some(&IVote::ProposalErrored::SIGNATURE_HASH))
        .count();
    assert_eq!(errored_count, 1, "error replay emitted a second log");
}

#[test]
fn infrastructure_failure_rolls_back_target_and_aborts_without_changing_proposal() {
    let mut provider = HashMapStorageProvider::new(1);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = vote
            .create_proposal(
                PROPOSER,
                UPDATE_ADDRESS,
                "{\"kind\":\"legacy\"}",
                10,
                &TECHNICALLY_FAILING_REGISTRY,
            )
            .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        let err = vote
            .process_begin_block(
                &block_context(storage.clone(), deadline + 1),
                &TECHNICALLY_FAILING_REGISTRY,
            )
            .unwrap_err();
        assert!(matches!(err, PrecompileError::Fatal(_)));
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending
        );
        assert_eq!(vote.list_pending_proposal_ids().unwrap(), vec![proposal_id]);
        assert_eq!(
            storage.sload(UPDATE_ADDRESS, U256::from(999u64)).unwrap(),
            U256::ZERO
        );
    }

    let logs = provider.get_events(VOTE_ADDRESS);
    assert_eq!(
        logs.iter()
            .filter(|log| log.topics().first() == Some(&IVote::ProposalErrored::SIGNATURE_HASH))
            .count(),
        0
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.topics().first() == Some(&IVote::ProposalApproved::SIGNATURE_HASH))
            .count(),
        0
    );
}

#[test]
fn outer_hook_checkpoint_revert_restores_pending_state_index_and_logs() {
    let mut provider = HashMapStorageProvider::new(1);
    let proposal_id;
    {
        let storage = StorageHandle::new(&mut provider);
        setup_default_validators(storage.clone());
        let mut vote = Vote::new(storage.clone());
        proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            "{\"version\":\"1.2\"}",
            10,
        )
        .unwrap();
        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 11)
            .unwrap();

        let deadline = 10 + VOTING_WINDOW_BLOCKS;
        let result: Result<()> = storage.with_checkpoint(|| {
            vote.process_begin_block(
                &block_context(storage.clone(), deadline + 1),
                test_vote_registry(),
            )?;
            assert_eq!(
                vote.proposals
                    .get(proposal_id)?
                    .expect("proposal")
                    .proposal_status()?,
                ProposalStatus::Approved
            );
            Err(PrecompileError::Fatal("forced late hook failure".into()))
        });
        assert!(matches!(result, Err(PrecompileError::Fatal(_))));
        assert_eq!(
            vote.proposals
                .get(proposal_id)
                .unwrap()
                .unwrap()
                .proposal_status()
                .unwrap(),
            ProposalStatus::Pending
        );
        assert_eq!(vote.list_pending_proposal_ids().unwrap(), vec![proposal_id]);
    }

    let logs = provider.get_events(VOTE_ADDRESS);
    assert_eq!(
        logs.iter()
            .filter(|log| log.topics().first() == Some(&IVote::ProposalApproved::SIGNATURE_HASH))
            .count(),
        0
    );
    assert_eq!(
        logs.iter()
            .filter(|log| log.topics().first() == Some(&IVote::ProposalCreated::SIGNATURE_HASH))
            .count(),
        1
    );
}

/// Vote is a payable route, so the boundary credits value to its address. Its
/// dispatch must refuse value for every selector outside `PAYABLE_SELECTORS`, or
/// a funded call to any other selector would strand native value at an address
/// whose only outward path is the proposal-bond accounting.
///
/// Characterization: the negative-match block this replaced already covered
/// these selectors with the same message, so the test pins current behavior
/// rather than proving a fix. Its value is catching a future removal of the
/// guard.
#[test]
fn unpublished_selectors_refuse_native_value() {
    use alloy_sol_types::SolCall;

    use crate::precompile::{dispatch_with_handlers, IVote};

    let calls = [
        IVote::castVoteCall {
            proposalId: U256::ZERO,
            approve: true,
        }
        .abi_encode(),
        IVote::getProposalCall {
            proposalId: U256::ZERO,
        }
        .abi_encode(),
    ];

    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        for data in &calls {
            let funded = dispatch_with_handlers(
                storage.clone(),
                data,
                Address::ZERO,
                U256::from(1u64),
                &REJECTING_REGISTRY,
            );
            assert!(
                matches!(
                    funded,
                    Err(PrecompileError::Revert(ref message))
                        if message == "non-payable function called with value"
                ),
                "unpublished selector must refuse value, got {funded:?}"
            );
        }
    });
}
