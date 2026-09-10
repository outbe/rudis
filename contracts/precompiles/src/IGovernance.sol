// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IGovernance {
    // --- proposal types (OIP / GIP have their own events) ---

    struct Oip {
        uint256 id;
        uint8 status;
        address author;
        uint64 createdBlock;
        uint64 updatedBlock;
        bytes32 textHash;
        string text;
    }

    // Identical to Oip today; a distinct type so GIP can diverge later.
    struct Gip {
        uint256 id;
        uint8 status;
        address author;
        uint64 createdBlock;
        uint64 updatedBlock;
        bytes32 textHash;
        string text;
    }

    // Listing projection - a proposal without its text body.
    struct ProposalMeta {
        uint256 id;
        uint8 status;
        address author;
        uint64 createdBlock;
        uint64 updatedBlock;
        bytes32 textHash;
    }

    event MetaCanonUpdated(uint64 indexed version, bytes32 hash);
    event CanonUpdated(uint64 indexed version, bytes32 hash);

    event OipSubmitted(uint256 indexed id, address indexed author, bytes32 textHash);
    event OipTextUpdated(uint256 indexed id, bytes32 textHash);
    event OipStatusChanged(uint256 indexed id, uint8 oldStatus, uint8 newStatus);

    event GipSubmitted(uint256 indexed id, address indexed author, bytes32 textHash);
    event GipTextUpdated(uint256 indexed id, bytes32 textHash);
    event GipStatusChanged(uint256 indexed id, uint8 oldStatus, uint8 newStatus);

    // --- canon / meta-canon: read ---
    function getMetaCanon() external view returns (string memory text, uint64 version, bytes32 hash);
    function getCanon() external view returns (string memory text, uint64 version, bytes32 hash);
    function getMetaCanonRevisionHash(uint64 version) external view returns (bytes32);
    function getCanonRevisionHash(uint64 version) external view returns (bytes32);

    // --- canon / meta-canon: full-overwrite write (authorities-gated) ---
    function updateMetaCanon(string calldata text) external returns (uint64 newVersion);
    function updateCanon(string calldata text) external returns (uint64 newVersion);

    // --- proposals: OIP ---
    function submitOip(string calldata text) external returns (uint256 id);
    function getOip(uint256 id) external view returns (Oip memory);
    function updateOipText(uint256 id, string calldata text) external;
    function setOipStatus(uint256 id, uint8 newStatus) external;
    function oipCount() external view returns (uint64);
    function getOipDiff(uint256 id, uint8 base) external view returns (string memory);
    // index-backed listings (metadata only, paginated [offset, offset+limit)):
    // by author, by status. Companion *Count getters size the pages.
    function getOipsByAuthor(address author, uint256 offset, uint256 limit)
        external
        view
        returns (ProposalMeta[] memory);
    function getOipsByStatus(uint8 status, uint256 offset, uint256 limit) external view returns (ProposalMeta[] memory);
    function oipCountByAuthor(address author) external view returns (uint256);
    function oipCountByStatus(uint8 status) external view returns (uint256);

    // --- proposals: GIP ---
    function submitGip(string calldata text) external returns (uint256 id);
    function getGip(uint256 id) external view returns (Gip memory);
    function updateGipText(uint256 id, string calldata text) external;
    function setGipStatus(uint256 id, uint8 newStatus) external;
    function gipCount() external view returns (uint64);
    function getGipDiff(uint256 id, uint8 base) external view returns (string memory);
    // index-backed listings (metadata only, paginated [offset, offset+limit)):
    // by author, by status. Companion *Count getters size the pages.
    function getGipsByAuthor(address author, uint256 offset, uint256 limit)
        external
        view
        returns (ProposalMeta[] memory);
    function getGipsByStatus(uint8 status, uint256 offset, uint256 limit) external view returns (ProposalMeta[] memory);
    function gipCountByAuthor(address author) external view returns (uint256);
    function gipCountByStatus(uint8 status) external view returns (uint256);

    // --- authorities (PoC scaffolding) ---
    function isAuthority(address who) external view returns (bool);
}
