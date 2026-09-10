// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {Vm} from "forge-std/Vm.sol";

import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @notice Stub Auction that synthesises `bidCount` revealed bids (default 1) on `getAuctionDetails`.
///         Used by the TM bids-relay tests to drive `_doSendBidsToOutbe`'s chunked send loop and the
///         defer/flush path. `bidCount = 0` exercises the no-bid -> single empty final batch path.
contract StubAuctionWithBids {
    uint256 public bidCount = 1;

    function setBidCount(uint256 n) external {
        bidCount = n;
    }

    function auctionStart(
        uint32,
        IIntexAuction.WorldwideDayState,
        IIntexAuction.AuctionSchedule calldata,
        IIntexAuction.AuctionParams calldata
    ) external {}
    function startClearingStage(uint32) external {}
    function executeAuctionClearing(uint32, uint32, uint64, uint32) external {}

    function getAuctionDetails(uint32)
        external
        view
        returns (IIntexAuction.AuctionData memory data, IIntexAuction.SubmittedBidData[] memory bids)
    {
        bids = new IIntexAuction.SubmittedBidData[](bidCount);
        for (uint256 i = 0; i < bidCount; i++) {
            bids[i] = IIntexAuction.SubmittedBidData({
                bidderAddress: address(uint160(0xCAFE + i)),
                intexQuantity: 1,
                intexBidRate: 100e6,
                timestamp: uint32(block.timestamp),
                issuanceCurrency: 840,
                referenceCurrency: 840
            });
        }
        // `data` left default - TM's `_doSendBidsToOutbe` drops the first tuple component.
        data;
    }
}

/// @title PatternADeferTest
/// @notice Behavioural coverage of Pattern A on `TargetRouter`: the inbound clearing/mark-called handlers fire an
///         outbound relay (bids batch / holders bridge) that parks on failure and is retried permissionlessly via
///         `flushPending*`. Failure is forced by starving the relay float - a positive bridge fee with a zero native
///         balance makes `_send` revert `NotEnoughNative`; topping the float up lets the flush land.
contract PatternADeferTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;

    /// @dev Fee the loopback bridge charges; the relay must have this in native float to send.
    uint256 internal constant BRIDGE_FEE = 0.001 ether;

    TargetRouter internal bnbRouter;
    IntexNFT1155Bridge internal nftBridge;
    IntexNFT1155Bridge internal nftBridgeOutbe;
    IntexNFT1155 internal intex;
    IntexNFT1155 internal intexOutbe;
    StubAuctionWithBids internal stubAuction;

    address internal admin = address(this);
    // Registered peer standing in for the Outbe-side router; delivery is authenticated against this address.
    address internal outbePeer = makeAddr("outbePeer");
    uint32 internal constant SERIES_ID_DAY = 20260301;
    bytes14 internal constant SERIES_ID = "20260301-USD-U";
    uint256 internal constant TOKEN_ID = uint256(uint112(SERIES_ID));

    function setUp() public {
        _setUpBridge();
        // A positive fee with an unfunded relay float is what forces the inbound-triggered relays to defer.
        bridge.setFee(BRIDGE_FEE);

        intex = DeployProxy.intexNFT1155(admin, admin);
        intexOutbe = DeployProxy.intexNFT1155(admin, admin);

        bnbRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);
        nftBridgeOutbe = DeployProxy.intexNFT1155Bridge(address(intexOutbe), address(bridge), admin);

        // Register remote messengers so inbound authentication passes and the outbound relay has a destination.
        bnbRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, outbePeer));
        nftBridge.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(nftBridgeOutbe)));

        stubAuction = new StubAuctionWithBids();
        bnbRouter.wire(address(stubAuction), address(intex), admin);

        // The bridge burns on the local Intex.
        intex.grantRole(intex.RELAYER_ROLE(), address(nftBridge));
        intex.grantRole(intex.RELAYER_ROLE(), address(bnbRouter));

        // Series so markCalled + holder enumeration work.
        intex.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, 10_000, 0));
        intex.markQualified(SERIES_ID);
    }

    /// @dev Deliver an inbound packet to the router from the registered Outbe peer.
    function _deliverBridge(bytes memory message) internal {
        _deliver(OUTBE_CHAIN_ID, outbePeer, address(bnbRouter), message);
    }

    // ---------------------------------------------------------------
    // TargetRouter - bids relay defer + flush
    // ---------------------------------------------------------------

    function test_TM_BidsRelayDeferredOnInsufficientBalance() public {
        // TM has zero native float but the bridge charges a fee, so `_send` reverts when relaying bids.
        assertEq(address(bnbRouter).balance, 0);

        _deliverBridge(BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY));

        // First parked slot.
        (uint32 worldwideDay, bool exists, bool done) = bnbRouter.pendingBidsRelays(0);
        assertEq(worldwideDay, SERIES_ID_DAY, "deferred worldwideDay");
        assertTrue(exists);
        assertFalse(done);
        assertEq(bnbRouter.nextPendingBidsRelayIdx(), 1);
    }

    function test_TM_FlushBidsRelaySucceedsAfterTopUp() public {
        _deliverBridge(BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY));

        // Top up TM float generously so the retry can pay the bridge fee.
        vm.deal(address(bnbRouter), 10 ether);

        bnbRouter.flushPendingBidsRelay(0);

        (,, bool done) = bnbRouter.pendingBidsRelays(0);
        assertTrue(done, "flushed slot marked done");
    }

    function test_TM_FlushBidsRelayDoubleFlushRevertsAlreadyFlushed() public {
        _deliverBridge(BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY));
        vm.deal(address(bnbRouter), 10 ether);
        bnbRouter.flushPendingBidsRelay(0);

        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.AlreadyFlushed.selector, 0));
        bnbRouter.flushPendingBidsRelay(0);
    }

    function test_TM_FlushBidsRelayUnknownIdxReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.NoSuchPendingBidsRelay.selector, 42));
        bnbRouter.flushPendingBidsRelay(42);
    }

    function test_TM_RelayBidsToOutbe_ExternalCallerRevertsNotSelf() public {
        vm.expectRevert(ITargetRouter.NotSelf.selector);
        bnbRouter.relayBidsToRudis(SERIES_ID_DAY);
    }

    // a zero-bid auction still emits one empty final batch (the no-bid completion signal),
    // instead of the old early-return that sent nothing.
    function test_TM_BidsRelay_ZeroBids_SendsOneEmptyFinalBatch() public {
        stubAuction.setBidCount(0);
        _deliverBridge(BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY));
        vm.deal(address(bnbRouter), 10 ether);

        vm.recordLogs();
        bnbRouter.flushPendingBidsRelay(0);
        uint256[] memory sizes = _bidsBatchSentSizes(vm.getRecordedLogs());

        assertEq(sizes.length, 1, "exactly one batch even with no bids");
        assertEq(sizes[0], 0, "the batch is empty");
    }

    // a reveal set larger than MAX_PAYLOAD_ARRAY_LEN is split into multiple batches; the
    // final chunk carries the remainder. (130 bids -> 64 + 64 + 2.)
    function test_TM_BidsRelay_ChunksAboveCap() public {
        stubAuction.setBidCount(130);
        _deliverBridge(BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY));
        vm.deal(address(bnbRouter), 10 ether);

        vm.recordLogs();
        bnbRouter.flushPendingBidsRelay(0);
        uint256[] memory sizes = _bidsBatchSentSizes(vm.getRecordedLogs());

        assertEq(sizes.length, 3, "ceil(130 / 64) = 3 chunks");
        assertEq(sizes[0], 64, "chunk 0 at cap");
        assertEq(sizes[1], 64, "chunk 1 at cap");
        assertEq(sizes[2], 2, "chunk 2 remainder");
    }

    /// @dev Extract the `bidsCount` of every `BidsBatchSent` log, in emission order.
    function _bidsBatchSentSizes(Vm.Log[] memory logs) internal pure returns (uint256[] memory sizes) {
        bytes32 topic = keccak256("BidsBatchSent(bytes32,uint32,uint256)");
        uint256 n;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length != 0 && logs[i].topics[0] == topic) n++;
        }
        sizes = new uint256[](n);
        uint256 j;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length != 0 && logs[i].topics[0] == topic) {
                sizes[j++] = abi.decode(logs[i].data, (uint256));
            }
        }
    }
}
