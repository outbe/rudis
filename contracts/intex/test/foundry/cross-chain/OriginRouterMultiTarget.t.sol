// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BidPackLib} from "../helpers/BidPackLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {Vm} from "forge-std/Vm.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {InboundReason} from "@contracts/shared/libs/InboundReason.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

/// @dev Multi-target OriginRouter behavior: registry, broadcast fan-out over the frozen day snapshot, addressed-send
///      membership, per-leg parking + flush, and inbound BIDS_DONE. Delivery is off (sends only record).
contract OriginRouterMultiTargetTest is CrossChainTest {
    uint32 internal constant TARGET_A = 3;
    uint32 internal constant TARGET_B = 4;
    uint32 internal constant DAY = 20_260_716;
    bytes32 internal constant STAGE_SENT_SIG = keccak256("AuctionStageSent(bytes32,uint32,uint8)");

    OriginRouter internal origin;
    address internal desis;
    address internal factory = makeAddr("factory");
    address internal peerA = makeAddr("peerA");
    address internal peerB = makeAddr("peerB");
    address internal admin = address(this);

    function setUp() public {
        _setUpBridge();
        origin = DeployProxy.originRouter(address(bridge), admin);
        desis = address(new MockDesis());
        origin.wire(desis, factory);
        origin.setRemoteMessenger(TARGET_A, _interop(TARGET_A, peerA));
        origin.setRemoteMessenger(TARGET_B, _interop(TARGET_B, peerB));
        origin.addTarget(TARGET_A);
        origin.addTarget(TARGET_B);
    }

    function _params(uint32 day) internal pure returns (IOriginRouter.AuctionStageStartParams memory p) {
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = day;
        p.dayState = 1;
    }

    function _fireStart(uint32 day) internal {
        vm.prank(desis);
        origin.sendAuctionStageStart(_params(day));
    }

    /// @dev Count `AuctionStageSent` emissions in the recorded logs (one per fan-out leg).
    function _countStageSent() internal returns (uint256 n) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == STAGE_SENT_SIG) n++;
        }
    }

    // --- Registry ---
    function test_registry_views() public view {
        assertTrue(origin.isTarget(TARGET_A));
        assertTrue(origin.isTarget(TARGET_B));
        assertEq(origin.targets().length, 2);
    }

    function test_addTarget_revert_noPeer() public {
        vm.expectRevert(abi.encodeWithSelector(ERC7786MessengerBase.RemoteMessengerNotSet.selector, uint32(9)));
        origin.addTarget(9);
    }

    function test_addTarget_revert_duplicate() public {
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.TargetAlreadyRegistered.selector, TARGET_A));
        origin.addTarget(TARGET_A);
    }

    function test_removeTarget_swapPop() public {
        origin.removeTarget(TARGET_A);
        assertFalse(origin.isTarget(TARGET_A));
        assertTrue(origin.isTarget(TARGET_B));
        uint32[] memory t = origin.targets();
        assertEq(t.length, 1);
        assertEq(t[0], TARGET_B); // swap-pop moved B into A's slot
    }

    function test_removeTarget_revert_notRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.TargetNotRegistered.selector, uint32(9)));
        origin.removeTarget(9);
    }

    // --- Broadcast fan-out + snapshot ---
    function test_stageStart_snapshotsEveryTarget() public {
        _fireStart(DAY);
        uint32[] memory snap = origin.targetsOf(DAY);
        assertEq(snap.length, 2);
        assertEq(snap[0], TARGET_A);
        assertEq(snap[1], TARGET_B);
    }

    function test_stageStart_fansOutToEveryTarget() public {
        vm.recordLogs();
        _fireStart(DAY);
        assertEq(_countStageSent(), 2, "one leg per target");
    }

    function test_stageStart_revert_noTargets() public {
        origin.removeTarget(TARGET_A);
        origin.removeTarget(TARGET_B);
        vm.prank(desis);
        vm.expectRevert(IOriginRouter.NoTargets.selector);
        origin.sendAuctionStageStart(_params(DAY));
    }

    function test_clearing_broadcastsOverSnapshot_notLiveRegistry() public {
        _fireStart(DAY);
        origin.removeTarget(TARGET_B); // a mid-day removal must not shrink an in-flight fan-out
        vm.recordLogs();
        vm.prank(desis);
        origin.sendAuctionStageClearing(DAY);
        assertEq(_countStageSent(), 2, "clearing still fans to the frozen snapshot");
    }

    // --- Addressed-send membership ---
    function test_addressed_membership_enforced() public {
        _fireStart(DAY);
        vm.prank(desis);
        origin.sendAuctionResult(TARGET_A, DAY, 100, 1e6, 5); // in snapshot: ok

        vm.prank(desis);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.NotSeriesTarget.selector, DAY, uint32(9)));
        origin.sendAuctionResult(9, DAY, 100, 1e6, 5);
    }

    function test_addressed_removedButSnapshotted_stillRoutes() public {
        _fireStart(DAY);
        origin.removeTarget(TARGET_B); // gone from the registry, still in the day's snapshot
        vm.prank(desis);
        origin.sendAuctionResult(TARGET_B, DAY, 100, 1e6, 5); // must not revert
    }

    // --- Per-leg park + flush ---
    function test_leg_parksOnMissingPeer_thenFlush() public {
        origin.setRemoteMessenger(TARGET_B, ""); // drop B's peer so its leg fails; A still routes
        _fireStart(DAY);

        IOriginRouter.ParkedSend memory p = origin.parkedSend(0);
        assertEq(p.dstChainId, TARGET_B);
        assertEq(p.sent, false);
        assertGt(p.payload.length, 0);

        origin.setRemoteMessenger(TARGET_B, _interop(TARGET_B, peerB));
        origin.flushPendingSend(0);
        assertTrue(origin.parkedSend(0).sent);
    }

    function test_flush_revert_unknown() public {
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.NoParkedSend.selector, uint256(0)));
        origin.flushPendingSend(0);
    }

    // --- Inbound BIDS_DONE ---
    function test_inbound_bidsDone_dispatches() public {
        _fireStart(DAY); // freeze the day's snapshot so TARGET_A is an accepted source
        bytes memory pkt = BridgeMsgCodec.encodeBidsDone(DAY, TARGET_A, 1, 2, 7);
        vm.expectEmit(true, true, false, true, address(origin));
        emit IOriginRouter.BidsDoneReceived(TARGET_A, DAY, 2, 7);
        _deliver(TARGET_A, peerA, address(origin), pkt);
    }

    function test_inbound_bids_ignoreNonSnapshotSource() public {
        _fireStart(DAY); // snapshot = {TARGET_A, TARGET_B}; chain 9 is a registered peer but not a target
        origin.setRemoteMessenger(9, _interop(9, address(0x9999)));
        bytes32 key = bytes32((uint256(DAY) << 32) | 9);
        bytes memory batch = BridgeMsgCodec.encodeBidsBatch(DAY, 9, 1, 0, 1, new address[](0), new uint256[](0));
        vm.expectEmit(true, true, true, true, address(origin));
        emit IOriginRouter.InboundMessageIgnored(9, BridgeMsgCodec.MSG_BIDS_BATCH, key, InboundReason.NOT_FOUND);
        _deliver(9, address(0x9999), address(origin), batch);

        bytes memory done = BridgeMsgCodec.encodeBidsDone(DAY, 9, 1, 1, 0);
        vm.expectEmit(true, true, true, true, address(origin));
        emit IOriginRouter.InboundMessageIgnored(9, BridgeMsgCodec.MSG_BIDS_DONE, key, InboundReason.NOT_FOUND);
        _deliver(9, address(0x9999), address(origin), done);
    }
}
