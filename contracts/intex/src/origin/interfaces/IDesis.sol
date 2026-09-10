// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title IDesis
/// @notice Inbound call surface for the Desis runtime precompile.
///         This is the minimal interface used by OriginRouter to call the precompile;
///         the authoritative source lives in contracts/precompiles/src/IDesis.sol.
interface IDesis {
    /// @notice Auction lifecycle stages. Values map 1:1 to the Rust `AuctionStage` enum.
    enum AuctionStage {
        None,
        Briefed,
        Started,
        Revealing,
        Clearing,
        Cleared,
        Cancelled
    }

    function processBidsBatch(
        uint32 worldwideDay,
        uint32 srcChainId,
        uint32 relayGeneration,
        uint16 batchIndex,
        uint16 totalBatches,
        address[] calldata bidderAddresses,
        uint256[] calldata packedBids
    ) external;

    /// @notice Per-chain completeness marker: the source relayed `totalBatches`/`totalBids` for this day/generation.
    function processBidsDone(
        uint32 worldwideDay,
        uint32 srcChainId,
        uint32 relayGeneration,
        uint16 totalBatches,
        uint32 totalBids
    ) external;

    function getAuctionStage(uint32 worldwideDay) external view returns (AuctionStage);
    function getBidsCount(uint32 worldwideDay) external view returns (uint256);
}
