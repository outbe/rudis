// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title ISlashIndicator
/// @notice Slash indicator precompile at 0x000000000000000000000000000000000000EE01
interface ISlashIndicator {
    /// Emitted when a proposer miss triggers a felony (forced exit + slash).
    event ProposerFelony(address indexed validator, uint64 missCount, uint64 felonyCount);

    /// Emitted when a proposer miss reaches the misdemeanor threshold.
    event ProposerMisdemeanor(address indexed validator, uint64 missCount);

    /// Emitted when a voter miss reaches the misdemeanor threshold.
    event VoterMisdemeanor(address indexed validator, uint64 missCount);

    /// Emitted when a voter miss triggers a felony (forced exit + slash).
    event VoterFelony(address indexed validator, uint64 missCount, uint64 felonyCount);

    /// Emitted when evidence-based felony is applied (forced exit + slash + reward).
    event EvidenceFelonyApplied(
        address indexed validator, address indexed submitter, uint256 slashedAmount, uint256 submitterReward
    );

    /// Emitted when byzantine behavior is detected by the consensus layer
    /// (equivocation: ConflictingNotarize/ConflictingFinalize/NullifyFinalize).
    event ByzantineFelony(address indexed validator, uint256 slashedAmount, uint64 felonyCount);

    /// Emitted when `submitInvalidVrfProofEvidence` accepts a VRF-class
    /// verifier failure and applies the felony to the child block's Phase 1
    /// tx signer. `failureCode` is the canonical class re-derived from
    /// `verify_v2_proof` (NOT the submitter's hint).
    event InvalidVrfProofEvidenceApplied(
        address indexed proposer, address indexed submitter, bytes32 indexed childBlockHash, uint16 failureCode
    );

    /// Emitted when `submitSeedPartialEquivocationEvidence` accepts proof that a
    /// validator identity-signed two different VRF seed partials for the same
    /// `(round, vrf_material_version)` and applies the felony.
    event SeedPartialEquivocationApplied(
        address indexed validator, address indexed submitter, uint64 roundEpoch, uint64 roundView, uint64 vrfVersion
    );

    /// Emitted when `submitInvalidSeedPartialEvidence` accepts proof that a
    /// validator identity-signed a VRF seed partial that fails verification
    /// against the committee polynomial, and applies the felony.
    event InvalidSeedPartialApplied(
        address indexed validator, address indexed submitter, uint64 roundEpoch, uint64 roundView, uint64 vrfVersion
    );

    function submitDoubleProposalEvidence(bytes calldata block1, bytes calldata block2) external;
    function submitConflictingVoteEvidence(bytes calldata vote1, bytes calldata vote2) external;
    /// `ConflictingNotarize`: same signer notarized two different proposals in one view.
    function submitConflictingNotarizeEvidence(bytes calldata block1, bytes calldata block2) external;
    /// `ConflictingFinalize`: same signer finalized two different proposals in one view.
    function submitConflictingFinalizeEvidence(bytes calldata block1, bytes calldata block2) external;
    /// `NullifyFinalize`: same signer both nullified and finalized the same view.
    function submitNullifyFinalizeEvidence(bytes calldata nullifyBlock, bytes calldata finalizeBlock) external;
    /// Submit evidence of an invalid threshold VRF proof in a child
    /// block's Phase 1 system transaction. `evidence` is the wire form of
    /// `InvalidVrfProofEvidence` (see `vrf_evidence.rs`).
    function submitInvalidVrfProofEvidence(bytes calldata evidence) external;
    /// Submit evidence that a validator equivocated on its VRF seed partial:
    /// two different identity-signed partials for the same round/version.
    /// `evidence` is the wire form of `SeedPartialEquivocationEvidence`
    /// (see `seed_partial_evidence.rs`).
    function submitSeedPartialEquivocationEvidence(bytes calldata evidence) external;
    /// Submit evidence that a validator emitted a single INVALID VRF seed
    /// partial (identity-signed, fails verification against the committee
    /// polynomial). `evidence` is the wire form of `InvalidSeedPartialEvidence`.
    function submitInvalidSeedPartialEvidence(bytes calldata evidence) external;
    function getProposerMissCount(address validator) external view returns (uint64);
    function getVoterMissCount(address validator) external view returns (uint64);
    function getFelonyCount(address validator) external view returns (uint64);
}
