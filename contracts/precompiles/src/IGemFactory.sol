// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IGemFactory {
    /// @notice Park the caller's Intex series `sourceIntexId` (burning `amount`
    ///         units via IntexNFT1155) and issue a GemPosition NFT to the caller.
    ///         Returns the new `positionId`.
    function issueGemPosition(bytes14 sourceIntexId, uint256 amount) external returns (uint256 positionId);
    /// @notice Issue one Merchant gem to `owner`, draining the position's
    ///         capacity. Only the position's merchant (the caller) may call.
    function issueGem(uint256 positionId, address owner, uint256 promisLoad) external returns (uint256 gemId);

    /// @notice Settle a gem by spending a PayNote for its cost.
    /// @dev Moves no tokens: the underlying assets reached the Reserve when the
    ///      note was deposited.
    /// @param payNoteProof `outbe.paynote` spend proof. Must name the caller as its
    ///        spender, carry a settlement asset the gem accepts, and cover the cost.
    function settleGem(uint256 gemId, bytes calldata payNoteProof) external;
    /// @notice Burn a settled gem and mint confidential Promis to the caller,
    ///         gated by off-chain proof of work. Authorized by the caller's Promis
    ///         modify key: `mac = HMAC(modifyKey, op-preimage)` where `opNonce`
    ///         MUST equal the caller's current on-chain promis op-nonce (fetch via
    ///         `rudis_deriveKeys` + `IPromis.opNonceOf`) and the bound amount is the
    ///         gem's load. Returns the minted Promis amount.
    function minePromis(uint256 gemId, uint64 nonce, bytes32 mac, uint64 opNonce) external returns (uint256);
    /// @notice Cumulative totals since genesis. `totalIntexParked` counts every
    ///         Promis unit ever parked; it is not reduced when a position drains
    ///         or expires.
    function getStatistics() external view returns (uint256 totalGemsIssued, uint256 totalIntexParked);

    /// @notice What settling `gemId` with `asset` costs, and which of the gem's
    ///         two currencies that asset settles on. Reverts for an asset the
    ///         gem does not accept.
    /// @return settlementCurrency ISO 4217 code the payment is denominated in.
    /// @return payableUnits Amount to pay, in `asset`'s own minor units.
    function quoteSettlement(uint256 gemId, address asset)
        external
        view
        returns (uint16 settlementCurrency, uint256 payableUnits);

    // --- GemPosition NFT (ERC-721-style, non-transferable; owner = merchant) ---
    /// @notice Number of GemPositions owned by `owner`.
    function balanceOf(address owner) external view returns (uint256);
    /// @notice Merchant that owns the position `positionId`.
    function ownerOf(uint256 positionId) external view returns (address);
    /// @notice Metadata URI for the position `positionId`.
    function tokenURI(uint256 positionId) external view returns (string memory);
    /// @notice `positionId` at `index` within `owner`'s positions.
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);
    /// @notice Full terms of the position `positionId`.
    function getPosition(uint256 positionId) external view returns (PositionData memory);

    /// @notice A merchant's parked Intex: the pool Merchant gems are drawn from.
    struct PositionData {
        uint256 positionId;
        address merchant;
        bytes14 sourceIntexId;
        uint256 remainingCapacity;
        uint256 sourceEntryPrice;
        uint256 sourceFloorPrice;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint64 parkedAt;
        /// @notice When the position stops issuing and returns its remainder.
        uint64 expiresAt;
    }

    // --- Events (emitted by the GemFactory precompile) ---
    /// @notice A new gem was issued (agent reward, merchant, or genesis flow).
    event GemIssued(
        uint256 indexed gemId,
        uint8 gemType,
        address owner,
        uint256 promisLoad,
        uint256 entryPrice,
        uint256 floorPrice,
        uint16 issuanceCurrency,
        uint16 referenceCurrency,
        uint64 issuedAt
    );
    /// @notice A gem's Cost Amount was settled into the Reserve.
    event GemSettled(uint256 indexed gemId, address owner, uint256 amountPaid, uint16 settlementCurrency);
    /// @notice A settled gem was burned to mine confidential Promis.
    event GemMined(uint256 indexed gemId, address owner, uint256 promisLoad);
    /// @notice A position ended its validity with capacity it never issued.
    event GemPositionExpired(
        uint256 indexed positionId, address indexed merchant, bytes14 sourceIntexId, uint256 returnedCapacity
    );
}
