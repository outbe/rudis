// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {BidPackLib} from "../helpers/BidPackLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IDesis} from "@contracts/origin/interfaces/IDesis.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @notice Desis stub that reverts `NotReady` on `processBidsBatch` until `enable()` is called - a stand-in for an
///         inbound prerequisite that has not yet landed. Advertises `IDesis` via ERC-165 so `OriginRouter.wire`
///         accepts it.
contract GatedDesis {
    error NotReady();

    bool public ready;

    function enable() external {
        ready = true;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IDesis).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    function processBidsBatch(uint32, uint32, uint32, uint16, uint16, address[] calldata, uint256[] calldata)
        external
        view
    {
        if (!ready) revert NotReady();
    }

    function getAuctionStage(uint32) external pure returns (IDesis.AuctionStage) {
        return IDesis.AuctionStage.None;
    }
}

/// @title InboundRevertAndRedeliverTest
/// @notice Under ERC-7786 the routers no longer swallow a failed inbound (there is no ORDERED lane to keep
///         moving). A premature message - one whose on-chain prerequisite has not yet landed - REVERTS, the bridge
///         rolls back, and the transport redelivers it later. Once the prerequisite lands, re-delivering the same
///         message SUCCEEDS. This preserves the old out-of-order resilience with the new revert-and-redeliver
///         mechanism.
/// @dev Delivery goes through the loopback bridge as the authenticated peer.
contract InboundRevertAndRedeliverTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;

    uint32 internal constant SERIES_ID_DAY = 20250101;
    bytes14 internal constant SERIES_ID = "20250101-USD-U";

    TargetRouter internal bnbRouter;
    OriginRouter internal outbeRouter;
    GatedDesis internal desis;
    IntexAuction internal auction;
    IntexNFT1155 internal intex;
    address internal intexFactory;
    address internal admin = address(this);

    function setUp() public {
        _setUpBridge();

        desis = new GatedDesis();
        intexFactory = makeAddr("factory");
        auction = DeployProxy.intexAuction(admin, admin);
        intex = DeployProxy.intexNFT1155(admin, admin);

        bnbRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        outbeRouter = DeployProxy.originRouter(address(bridge), admin);

        bnbRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(outbeRouter)));
        outbeRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(bnbRouter)));

        // TM drives the local Intex on markCalled.
        bnbRouter.wire(address(auction), address(intex), admin);
        auction.grantRole(auction.RELAYER_ROLE(), address(bnbRouter));
        intex.grantRole(intex.RELAYER_ROLE(), address(bnbRouter));

        outbeRouter.wire(address(desis), intexFactory);
        outbeRouter.addTarget(BNB_CHAIN_ID);
    }

    /// @dev Freeze `day`'s target snapshot (as the DESIS_ROLE holder) so its bids pass the inbound
    ///      snapshot-membership check. The mock bridge records the broadcast without delivering it.
    function _freezeSnapshot(uint32 day) internal {
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = day;
        p.dayState = 1;
        vm.prank(address(desis));
        outbeRouter.sendAuctionStageStart(p);
    }

    function _deliverToTM(bytes memory packet) internal {
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function _deliverToOM(bytes memory packet) internal {
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), packet);
    }

    // ---------------------------------------------------------------
    // TargetRouter - premature MARK_CALLED waits in the series' slot, then applies once the series lands
    // ---------------------------------------------------------------

    /// @notice MARK_CALLED for a series the BNB intex has never seen waits in its slot rather than rejecting:
    ///         a batch carries several series, and one of them missing must not reject the message.
    function test_TM_PrematureMarkCalled_Parks() public {
        bytes memory packet =
            BridgeMsgCodec.encodeMarkCalled(SERIES_ID_DAY, uint32(block.timestamp), MarkBatchLib.one(SERIES_ID));
        _deliverToTM(packet);

        assertEq(bnbRouter.pendingMark(SERIES_ID), BridgeMsgCodec.MSG_MARK_CALLED, "the mark waits for its series");
    }

    /// @notice Once the prerequisite (the series) lands, applying the slotted mark flips the series to
    ///         Called - the out-of-order arrival resolves without a redelivery.
    function test_TM_ParkedMarkCalledFlushesAfterSeriesLands() public {
        bytes memory packet =
            BridgeMsgCodec.encodeMarkCalled(SERIES_ID_DAY, uint32(block.timestamp), MarkBatchLib.one(SERIES_ID));

        // Premature: no series yet -> slotted.
        _deliverToTM(packet);

        // Prerequisite lands (the ISSUANCE that would have created the series).
        intex.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, 10_000, 0));

        bnbRouter.applyPendingMark(SERIES_ID);

        IIntexNFT1155.SeriesData memory data = intex.readData(SERIES_ID);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Called), "series flipped to Called on flush");
    }

    // ---------------------------------------------------------------
    // OriginRouter - premature BIDS_BATCH reverts, then redeliver succeeds
    // ---------------------------------------------------------------

    /// @notice A BIDS_BATCH whose downstream (Desis) prerequisite has not landed reverts; once Desis is ready,
    ///         re-delivering the same batch succeeds. The router no longer drops it to keep a lane moving.
    function test_OM_PrematureBidsBatch_RevertsThenRedeliverSucceeds() public {
        _freezeSnapshot(42); // BNB is in the day's snapshot; the revert below is Desis-not-ready, not membership
        bytes memory bids =
            BridgeMsgCodec.encodeBidsBatch(42, BNB_CHAIN_ID, 1, 0, 1, new address[](0), new uint256[](0));

        // Premature: Desis not ready -> revert propagates out of the bridge.
        vm.expectRevert(GatedDesis.NotReady.selector);
        _deliverToOM(bids);

        // Prerequisite lands.
        desis.enable();

        // Redelivery of the identical batch now lands (BidsBatchReceived).
        vm.expectEmit(true, true, false, true, address(outbeRouter));
        emit IOriginRouter.BidsBatchReceived(BNB_CHAIN_ID, 42, 0);
        _deliverToOM(bids);
    }
}
