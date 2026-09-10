use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolError;
use outbe_primitives::error::PrecompileError;

use crate::abi::IVote;

/// Vote module errors.
#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("caller is not an active validator")]
    NotValidator,
    #[error("proposal not found")]
    ProposalNotFound,
    #[error("proposal is not pending")]
    NotPending,
    #[error("proposal voting window is closed")]
    VotingClosed,
    #[error("validator has already voted on proposal")]
    AlreadyVoted,
    #[error("too many pending proposals")]
    TooManyPending,
    #[error("validator has too many pending proposals")]
    TooManyPendingByValidator,
    #[error("too many pending public bonded proposals")]
    TooManyPendingPublicBonded,
    #[error("proposer already has a pending public bonded proposal")]
    TooManyPendingPublicBondedByProposer,
    #[error("invalid proposal status")]
    InvalidProposalStatus,
    #[error("invalid vote kind")]
    InvalidVoteKind,
    #[error("invalid proposal bond settlement")]
    InvalidBondSettlement,
    #[error("proposal counter is exhausted")]
    ProposalCounterExhausted,
    #[error("proposal bond amount must be nonzero")]
    InvalidBondAmount,
    #[error("proposal bond is already recorded")]
    ProposalBondAlreadyRecorded,
    #[error("proposal bond is not unsettled")]
    ProposalBondNotUnsettled,
    #[error("proposal bond liability overflow")]
    BondLiabilityOverflow,
    #[error("proposal bond liability underflow")]
    BondLiabilityUnderflow,
    #[error("invalid proposal bond: expected {expected}, got {actual}")]
    InvalidProposalBond { expected: U256, actual: U256 },
    #[error("proposal bond liabilities {liabilities} exceed Vote balance {balance}")]
    BondLiabilityInvariant { balance: U256, liabilities: U256 },
    #[error("invalid proposal payload")]
    InvalidPayload,
    #[error("unknown vote target module")]
    UnknownTargetModule,
    #[error("duplicate vote target module handler")]
    DuplicateTargetModule,
}

impl From<VoteError> for PrecompileError {
    fn from(err: VoteError) -> Self {
        match err {
            VoteError::InvalidProposalBond { expected, actual } => PrecompileError::RevertBytes(
                Bytes::from(IVote::InvalidProposalBond { expected, actual }.abi_encode()),
            ),
            VoteError::InvalidBondSettlement
            | VoteError::BondLiabilityOverflow
            | VoteError::BondLiabilityUnderflow
            | VoteError::BondLiabilityInvariant { .. } => PrecompileError::Fatal(err.to_string()),
            _ => PrecompileError::Revert(err.to_string()),
        }
    }
}
