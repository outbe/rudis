// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title OCOMP protocol authority registry
/// @notice Read-only projection of the active OCOMP protocol policy.
interface IOcompRegistry {
    event OcompProtocolAuthorityInstalled(
        bytes32 indexed protocolBundleHash, bytes32 indexed installHash, uint64 activationHeight
    );
    event OcompSuccessorStaged(uint256 indexed proposalId, bytes32 indexed protocolBundleHash, uint64 activationHeight);
    event OcompSuccessorActivated(
        uint256 indexed proposalId,
        bytes32 indexed predecessorProtocolBundleHash,
        bytes32 indexed protocolBundleHash,
        uint64 activationHeight
    );
    event OcompProtocolAuthorityRetired(bytes32 indexed protocolBundleHash, uint64 retiredAt);

    function initialized() external view returns (bool);
    function activeProtocolBundleHash() external view returns (bytes32);
    function activeRequestProfile() external view returns (bytes memory);
    function activeProtocolBundle() external view returns (bytes memory);
    function stagedSuccessor() external view returns (uint256 proposalId, bytes memory canonicalSuccessor);
    function retiringProtocolBundleHash() external view returns (bytes32);
    function lineageProtocolBundleHash(bytes32 lineage) external view returns (bytes32);
    function liveLineageCount(bytes32 protocolBundleHash) external view returns (uint32);
    function retentionUntil(bytes32 protocolBundleHash) external view returns (uint64);
}
