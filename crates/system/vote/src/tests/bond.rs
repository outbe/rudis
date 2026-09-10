use alloy_primitives::U256;
use outbe_primitives::addresses::{UPDATE_ADDRESS, VOTE_ADDRESS};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::dsl::StorageRecord;
use outbe_primitives::storage::types::StorageKey;

use crate::errors::VoteError;
use crate::schema::{BondSettlement, ProposalRecord, ProposalStatus, Vote};

use super::{
    create_proposal_test, empty_update_payload, with_vote, VoteTestExt, PROPOSER, VOTER_A,
};

#[test]
fn bond_layout_appends_after_the_v0_vote_schema() {
    with_vote(|storage| {
        let vote = Vote::new(storage);
        assert_eq!(vote.proposal_count.slot(), U256::ZERO);
        vote.pending_proposal_ids.push(U256::from(7u64)).unwrap();
        assert_eq!(
            vote.storage.sload(VOTE_ADDRESS, U256::from(1u64)).unwrap(),
            U256::from(1u64)
        );
        assert_eq!(vote.proposals.base_slot(), U256::from(2u64));
        assert_eq!(vote.votes_map.base_slot(), U256::from(8u64));
        assert_eq!(vote.proposal_voters.base_slot(), U256::from(9u64));
        assert_eq!(vote.proposal_bond_amount.base_slot(), U256::from(10u64));
        assert_eq!(vote.proposal_bond_settlement.base_slot(), U256::from(11u64));
        assert_eq!(vote.unsettled_bond_liabilities.slot(), U256::from(12u64));
        assert_eq!(<ProposalRecord as StorageRecord>::SLOTS, 6);
    });
}

#[test]
fn raw_v0_proposal_reads_as_no_bond_and_tallies_after_the_append() {
    with_vote(|storage| {
        let proposal_id = U256::from(1u64);
        let proposal_base = U256::from(2u64);
        storage
            .sstore(VOTE_ADDRESS, U256::ZERO, proposal_id)
            .unwrap();
        storage
            .sstore(
                VOTE_ADDRESS,
                proposal_id.mapping_slot(proposal_base),
                U256::from_be_slice(PROPOSER.as_slice()),
            )
            .unwrap();
        storage
            .sstore(
                VOTE_ADDRESS,
                proposal_id.mapping_slot(proposal_base + U256::from(1u64)),
                U256::from_be_slice(UPDATE_ADDRESS.as_slice()),
            )
            .unwrap();
        storage
            .sstore(
                VOTE_ADDRESS,
                proposal_id.mapping_slot(proposal_base + U256::from(3u64)),
                U256::from(10u64),
            )
            .unwrap();
        storage
            .sstore(
                VOTE_ADDRESS,
                proposal_id.mapping_slot(proposal_base + U256::from(4u64)),
                U256::from(20u64),
            )
            .unwrap();
        storage
            .sstore(
                VOTE_ADDRESS,
                proposal_id.mapping_slot(proposal_base + U256::from(5u64)),
                U256::from(ProposalStatus::Pending.to_u8()),
            )
            .unwrap();

        let mut vote = Vote::new(storage.clone());
        vote.pending_proposal_ids.push(proposal_id).unwrap();
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::NoBond
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);

        vote.cast_vote_approve(proposal_id, PROPOSER, true, 11)
            .unwrap();
        vote.cast_vote_approve(proposal_id, VOTER_A, true, 12)
            .unwrap();
        vote.process_begin_block_test(21).unwrap();

        assert_eq!(
            vote.get_proposal(proposal_id).unwrap().unwrap().status,
            ProposalStatus::Approved
        );
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap(),
            crate::state::ProposalBond {
                amount: U256::ZERO,
                settlement: BondSettlement::NoBond,
            }
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
    });
}

#[test]
fn bond_accounting_is_checked_and_exactly_once() {
    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(10),
            10,
        )
        .unwrap();

        vote.record_proposal_bond(proposal_id, U256::from(10u64))
            .unwrap();
        assert_eq!(vote.bond_liabilities().unwrap(), U256::from(10u64));
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Unsettled
        );
        assert!(matches!(
            vote.record_proposal_bond(proposal_id, U256::from(10u64)),
            Err(PrecompileError::Revert(_))
        ));

        assert_eq!(
            vote.settle_proposal_bond_accounting(proposal_id, BondSettlement::Refunded)
                .unwrap(),
            U256::from(10u64)
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Refunded
        );
        assert!(matches!(
            vote.settle_proposal_bond_accounting(proposal_id, BondSettlement::Burned),
            Err(PrecompileError::Revert(_))
        ));
    });

    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(10),
            10,
        )
        .unwrap();
        vote.unsettled_bond_liabilities.write(U256::MAX).unwrap();
        assert!(matches!(
            vote.record_proposal_bond(proposal_id, U256::from(1u64)),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::NoBond
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::MAX);
    });

    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(10),
            10,
        )
        .unwrap();
        vote.record_proposal_bond(proposal_id, U256::from(10u64))
            .unwrap();
        vote.unsettled_bond_liabilities
            .write(U256::from(9u64))
            .unwrap();
        assert!(matches!(
            vote.settle_proposal_bond_accounting(proposal_id, BondSettlement::Burned),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            vote.proposal_bond(proposal_id).unwrap().settlement,
            BondSettlement::Unsettled
        );
        assert_eq!(vote.bond_liabilities().unwrap(), U256::from(9u64));
    });
}

#[test]
fn invalid_bond_enum_and_proposal_counter_exhaustion_are_typed() {
    assert_eq!(
        BondSettlement::from_u8(4).unwrap_err().to_string(),
        VoteError::InvalidBondSettlement.to_string()
    );

    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        let proposal_id = create_proposal_test(
            &mut vote,
            PROPOSER,
            UPDATE_ADDRESS,
            &empty_update_payload(10),
            10,
        )
        .unwrap();
        vote.proposal_bond_settlement
            .write(&proposal_id, 4)
            .unwrap();
        assert!(matches!(
            vote.proposal_bond(proposal_id),
            Err(PrecompileError::Fatal(_))
        ));
    });

    with_vote(|storage| {
        let mut vote = Vote::new(storage);
        vote.proposal_count.write(U256::MAX).unwrap();
        assert!(matches!(
            vote.peek_next_proposal_id(),
            Err(PrecompileError::Revert(message))
                if message == VoteError::ProposalCounterExhausted.to_string()
        ));
        assert!(matches!(
            create_proposal_test(
                &mut vote,
                PROPOSER,
                UPDATE_ADDRESS,
                &empty_update_payload(10),
                10,
            ),
            Err(PrecompileError::Revert(message))
                if message == VoteError::ProposalCounterExhausted.to_string()
        ));
        assert_eq!(vote.proposal_count.read().unwrap(), U256::MAX);
    });
}
