// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IVote
/// @notice Generic on-chain proposal/voting precompile at 0x000000000000000000000000000000000000EE0C
interface IVote {
    enum ProposalStatus {
        Pending,
        Approved,
        Rejected,
        Expired,
        Error
    }

    enum BondSettlement {
        NoBond,
        Unsettled,
        Refunded,
        Burned
    }

    struct VoteTally {
        uint64 yes;
        uint64 no;
    }

    struct ProposalInfo {
        uint256 proposalId;
        address proposer;
        address targetModule;
        string payload;
        uint64 createdHeight;
        uint64 votingDeadlineHeight;
        ProposalStatus status;
        /// @notice Results of voting (if it would have been calculated now).
        /// The actual state may differ, e.g. if validator set changes before voting deadline.
        VoteTally state;
        /// @dev The full list of voters is not transmitted, and can be retrieved using `getProposalVoters`.
        uint256 votersCount;
    }

    /// @notice New proposal was created.
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address targetModule,
        string payload,
        uint64 votingDeadlineHeight
    );

    /// @notice Validator voted on a proposal.
    event VoteCast(uint256 indexed proposalId, address indexed validator, bool approve);

    /// @notice Proposal was rejected by conflict with another approved proposal.
    event ProposalRejected(uint256 indexed proposalId, VoteTally state, uint256 indexed conflictingproposalId);

    /// @notice Proposal was expired by voting deadline.
    event ProposalExpired(uint256 indexed proposalId, VoteTally state);

    /// @notice Proposal was cancelled by the proposer.
    event ProposalCancelled(uint256 indexed proposalId, address indexed proposer);

    /// @notice Proposal was approved by majority (2/3).
    event ProposalApproved(uint256 indexed proposalId, VoteTally state);

    /// @notice Approved target execution returned an error and its target effects were rolled back.
    event ProposalErrored(uint256 indexed proposalId, VoteTally state);

    /// @notice A target-specific proposal bond was recorded as an unsettled liability.
    event ProposalBondEscrowed(uint256 indexed proposalId, address indexed owner, uint256 amount);

    /// @notice A successful target execution refunded its recorded proposal bond.
    event ProposalBondRefunded(uint256 indexed proposalId, address indexed owner, uint256 amount);

    /// @notice An expired proposal burned its recorded proposal bond.
    event ProposalBondBurned(uint256 indexed proposalId, address indexed owner, uint256 amount);

    error InvalidProposalBond(uint256 expected, uint256 actual);
    error ProposalBondAlreadySettled(uint256 proposalId, BondSettlement settlement);
    error ProposalBondSettlementFailed(uint256 proposalId);
    error ProposalBondLiabilityInvariant(uint256 balance, uint256 liabilities);

    /// @notice Creates a generic proposal.
    /// @param targetModule Target system module precompile address.
    /// @param payload JSON payload decoded only by the target module handler.
    function createProposal(address targetModule, string calldata payload) external payable returns (uint256 proposalId);

    /// @notice Casts a vote on a pending proposal.
    /// @dev Only active validators may vote.
    function castVote(uint256 proposalId, bool approve) external;

    // ===============================================
    // VIEW API
    // ===============================================

    /// @notice Returns proposal details.
    function getProposal(uint256 proposalId) external view returns (ProposalInfo memory);

    /// @notice Returns the recorded bond amount and settlement state for a proposal.
    function getProposalBond(uint256 proposalId) external view returns (uint256 amount, BondSettlement settlement);

    /// @notice Returns the aggregate amount of all recorded unsettled bond liabilities.
    function unsettledBondLiabilities() external view returns (uint256);

    /// @notice Returns a slice of voters for a proposal, with pagination, to prevent bloating the response.
    function getProposalVoters(uint256 proposalId, uint256 index, uint256 count)
        external
        view
        returns (address[] memory);

    /// @notice Returns all tracked proposal ids.
    function listProposals(uint256 index, uint256 count) external view returns (uint256[] memory);

    /// @notice Returns proposal ids filtered by status.
    function listProposalsByStatus(ProposalStatus status, uint256 index, uint256 count)
        external
        view
        returns (uint256[] memory);
}
