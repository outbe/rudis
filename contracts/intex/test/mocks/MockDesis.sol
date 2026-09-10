// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IDesis} from "@contracts/origin/interfaces/IDesis.sol";

/// @notice Minimal stand-in that advertises the `IDesis` interface via ERC-165.
/// @dev Lets `OriginRouter.wire` accept it during tests without pulling in the full
///      `Desis` dependency graph. Outbound-direction tests prank the wired address; the
///      bid-processing path is never invoked, so the interface methods are not implemented
///      (we intentionally avoid `is IDesis` so the mock stays light).
contract MockDesis {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IDesis).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @dev Accepts every BIDS_BATCH delivery and discards it. Tests that exercise the inbound
    ///      OM dispatch path rely on this no-op so `_handleBidsBatch` can complete without
    ///      pulling in the full Desis dependency graph.
    function processBidsBatch(
        uint32, /* worldwideDay */
        uint32, /* srcChainId */
        uint32, /* relayGeneration */
        uint16, /* batchIndex */
        uint16, /* totalBatches */
        address[] calldata, /* bidderAddresses */
        uint16[] calldata, /* intexQuantities */
        uint32[] calldata, /* intexBidRates */
        uint32[] calldata /* timestamps */
    ) external {}

    /// @dev Accepts every BIDS_DONE completeness marker and discards it, mirroring `processBidsBatch`.
    function processBidsDone(
        uint32, /* worldwideDay */
        uint32, /* srcChainId */
        uint32, /* relayGeneration */
        uint16, /* totalBatches */
        uint32 /* totalBids */
    ) external {}

    function getAuctionStage(
        uint32 /* seriesId */
    )
        external
        pure
        returns (IDesis.AuctionStage)
    {
        return IDesis.AuctionStage.None;
    }

    function getBidsCount(
        uint32 /* seriesId */
    )
        external
        pure
        returns (uint256)
    {
        return 0;
    }
}
