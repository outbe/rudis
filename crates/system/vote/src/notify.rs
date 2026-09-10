//! Canonical on-chain Vote event emission.

use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;

use crate::abi::IVote;
use crate::schema::{ProposalRecord, Vote};
use crate::state::VoteTally;

/// Terminal outcome of a proposal after voting closes.
pub(crate) enum ProposalFinalization {
    Approved,
    Expired,
    Error,
}

fn abi_vote_tally(tally: &VoteTally) -> IVote::VoteTally {
    IVote::VoteTally {
        yes: tally.yes,
        no: tally.no,
    }
}

impl Vote<'_> {
    /// Emits canonical `ProposalCreated` receipt evidence.
    pub(crate) fn notify_proposal_created(
        &mut self,
        proposal_id: U256,
        proposer: Address,
        target_module: Address,
        payload: &str,
        voting_deadline_height: u64,
    ) -> Result<()> {
        self.emit(IVote::ProposalCreated {
            proposalId: proposal_id,
            proposer,
            targetModule: target_module,
            payload: payload.to_string(),
            votingDeadlineHeight: voting_deadline_height,
        })
    }

    /// Emits canonical `VoteCast` receipt evidence.
    pub(crate) fn notify_vote_cast(
        &mut self,
        proposal_id: U256,
        voter: Address,
        approve: bool,
    ) -> Result<()> {
        self.emit(IVote::VoteCast {
            proposalId: proposal_id,
            validator: voter,
            approve,
        })
    }

    /// Emits canonical evidence that a proposal bond became an unsettled liability.
    pub(crate) fn notify_proposal_bond_escrowed(
        &mut self,
        proposal_id: U256,
        owner: Address,
        amount: U256,
    ) -> Result<()> {
        self.emit(IVote::ProposalBondEscrowed {
            proposalId: proposal_id,
            owner,
            amount,
        })
    }

    pub(crate) fn notify_proposal_bond_refunded(
        &mut self,
        proposal_id: U256,
        owner: Address,
        amount: U256,
    ) -> Result<()> {
        self.emit(IVote::ProposalBondRefunded {
            proposalId: proposal_id,
            owner,
            amount,
        })
    }

    pub(crate) fn notify_proposal_bond_burned(
        &mut self,
        proposal_id: U256,
        owner: Address,
        amount: U256,
    ) -> Result<()> {
        self.emit(IVote::ProposalBondBurned {
            proposalId: proposal_id,
            owner,
            amount,
        })
    }

    /// Emits canonical terminal proposal receipt evidence.
    pub(crate) fn notify_proposal_finalized(
        &mut self,
        proposal: &ProposalRecord,
        tally: &VoteTally,
        outcome: ProposalFinalization,
    ) -> Result<()> {
        let proposal_id = proposal.id;
        let vote_tally = abi_vote_tally(tally);

        match outcome {
            ProposalFinalization::Approved => self.emit(IVote::ProposalApproved {
                proposalId: proposal_id,
                state: vote_tally,
            }),
            ProposalFinalization::Expired => self.emit(IVote::ProposalExpired {
                proposalId: proposal_id,
                state: vote_tally,
            }),
            ProposalFinalization::Error => self.emit(IVote::ProposalErrored {
                proposalId: proposal_id,
                state: vote_tally,
            }),
        }
    }
}
