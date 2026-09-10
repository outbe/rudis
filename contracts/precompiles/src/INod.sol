// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface INod {
    event NodBodyStored(
        uint256 nodId,
        uint32 commitmentSchemeVersion,
        uint32 schemaVersion,
        bytes32 previousCommitment,
        bytes32 newCommitment,
        bytes canonicalPayload
    );

    event NodBodyDeleted(uint256 nodId, bytes32 previousCommitment);

    event NodBucketBodyStored(
        uint256 bucketId,
        uint32 commitmentSchemeVersion,
        uint32 schemaVersion,
        bytes32 previousCommitment,
        bytes32 newCommitment,
        bytes canonicalPayload
    );

    event NodBucketBodyDeleted(uint256 bucketId, bytes32 previousCommitment);

    event NodBucketQualified(
        bytes32 indexed bucketKey, uint256 worldwideDay, uint256 floorPriceMinor, uint16 referenceCurrency
    );

    /// Qualified bucket force-called by the daily Call scan: the reference price
    /// exceeded the bucket's call price on enough of the trailing window. Every
    /// Nod in the bucket must be settled and mined by `settlementDeadline` or it
    /// is forfeit-burned.
    event NodBucketCalled(bytes32 indexed bucketKey, uint64 calledAt, uint64 settlementDeadline);

    /// Nod burned by the Call scan because its bucket's settlement deadline
    /// lapsed while the Nod was still unmined. No Gratis is minted.
    event NodForfeited(address indexed owner, uint256 nodId, uint256 gratisLoadMinor);

    struct NodData {
        uint256 nodId;
        address owner;
        uint32 worldwideDay;
        uint16 leagueId;
        uint256 floorPriceMinor;
        uint256 gratisLoadMinor;
        uint256 costOfGratisMinor;
        uint256 costAmountMinor;
        bool isQualified;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint64 issuedAt;
        /// Block timestamp the Nod's bucket was force-called; `0` while not
        /// called. The settlement deadline is this plus the call notice period.
        uint64 calledAt;
    }

    /// Finalized on-chain commitment to one activated OCOMP Nod generation.
    ///
    /// Individual Nod bodies remain in content-addressed storage and are
    /// accepted only with a Merkle proof against `nodRoot`.
    struct CertifiedGenerationData {
        bool exists;
        uint32 worldwideDay;
        uint64 generation;
        bytes32 nodRoot;
        bytes32 bucketRoot;
        bytes32 outputManifestRoot;
        uint32 tributeCount;
        uint32 nodCount;
        uint32 bucketCount;
        uint256 nodAmountTotal;
        uint256 nodGratisConsumed;
        uint64 issuedAt;
    }

    // ERC-165
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    // Identity and ownership reads (32-byte entity IDs, carried as uint256)
    function balanceOf(address owner) external view returns (uint256 balance);
    function ownerOf(uint256 nodId) external view returns (address);

    // Metadata reads
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 nodId) external view returns (string memory);

    // Enumeration reads
    function totalSupply() external view returns (uint256);
    function tokenByIndex(uint256 index) external view returns (uint256);
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);

    // outbe-specific
    function nodData(uint256 nodId) external view returns (NodData memory);
    function certifiedGeneration(uint32 worldwideDay) external view returns (CertifiedGenerationData memory);
}
