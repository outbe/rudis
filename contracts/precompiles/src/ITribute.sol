// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface ITribute {
    event TributeBodyStored(
        uint256 tributeId,
        uint32 commitmentSchemeVersion,
        uint32 schemaVersion,
        bytes32 previousCommitment,
        bytes32 newCommitment,
        bytes canonicalPayload
    );

    event TributeBodyDeleted(uint256 tributeId, bytes32 previousCommitment);

    event TributeIssued(
        address indexed owner,
        uint256 tributeId,
        uint32 worldwideDay,
        uint256 issuanceAmountMinor,
        uint16 settlementCurrency,
        uint256 nominalAmountMinor
    );

    event TributeBurned(uint256 tributeId, address owner, uint32 worldwideDay);

    event TributeWorldwideDaySealed(uint32 indexed worldwideDay, bool isSealed);

    /// @notice Canonical projection event for certified Lysis retirement and
    /// the two closed Metadosis terminal authorities (empty missed OFFERING or
    /// exact-aggregate capacity forfeiture). No arbitrary FAILED day may emit it.
    event TributePartitionRetired(uint32 indexed worldwideDay);

    event CertifiedTributePartitionRetired(
        bytes32 indexed activationCallId,
        uint32 indexed worldwideDay,
        uint64 sourceGeneration,
        bytes32 sealedCollectionRoot,
        uint32 consumedCount,
        uint256 consumedNominalTotal,
        uint64 retiredGeneration,
        bytes32 stateEventDigest
    );

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function totalSupply() external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tributeId) external view returns (address);
    function tokenURI(uint256 tributeId) external view returns (string memory);
    function getDayTotals(uint32 worldwideDay)
        external
        view
        returns (uint32 tributeCount, uint256 tributeNominalAmount, bool isSealed);
    function getTributesByOwner(address owner) external view returns (uint256[] memory tributeIds);
    function getTributesByDay(uint32 worldwideDay) external view returns (uint256[] memory tributeIds);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
