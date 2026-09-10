// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {InboundReason} from "@contracts/shared/libs/InboundReason.sol";

/// Auction-stage messages are acknowledged whatever the day's state: a START the day already has, a
/// CLEARING or RESULT for a day that is past them or was never opened here, and a RESULT that fails the
/// auction's permanent bounds all execute without effect and report why. Only a transition that time or a
/// missing prerequisite will still make valid keeps reverting, so the bridge redelivers it.
contract TargetRouterInboundIdempotencyTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant DAY = 20_250_101;
    uint128 internal constant PROMIS_LOAD_MINOR = 1e6;
    uint64 internal constant ENTRY_PRICE = 100e6;
    uint64 internal constant FLOOR_PRICE = 40e6;

    TargetRouter internal router;
    IntexAuction internal auction;
    IntexNFT1155 internal intex;
    address internal originSender = makeAddr("originSender");
    bytes32 internal dayKey = bytes32(uint256(DAY));

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(address(this), address(this));
        auction = DeployProxy.intexAuction(address(this), address(this));
        router = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);

        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
        router.wire(address(auction), address(intex), makeAddr("escrow"));
        auction.grantRole(auction.RELAYER_ROLE(), address(router));
        intex.grantRole(intex.RELAYER_ROLE(), address(router));
    }

    // --- helpers ---

    function _deliver(bytes memory packet) internal {
        _deliver(OUTBE_CHAIN_ID, originSender, address(router), packet);
    }

    function _start(uint32 day, uint32 commitEnd, uint32 minRate, uint8 dayState) internal pure returns (bytes memory) {
        return BridgeMsgCodec.encodeAuctionStageStart(
            day,
            commitEnd,
            commitEnd + 1 days,
            commitEnd + 2 days,
            PROMIS_LOAD_MINOR,
            minRate,
            ReferenceCurrencyPriceLib.one(840, ENTRY_PRICE, FLOOR_PRICE, ENTRY_PRICE),
            0,
            0,
            0,
            1,
            0,
            dayState
        );
    }

    function _greenStart(uint32 commitEnd) internal pure returns (bytes memory) {
        return _start(DAY, commitEnd, 60e6, uint8(IIntexAuction.WorldwideDayState.Green));
    }

    function _openGreenDay() internal returns (uint32 commitEnd) {
        commitEnd = uint32(block.timestamp + 1 days);
        _deliver(_greenStart(commitEnd));
    }

    function _expectIgnored(uint8 msgType, uint8 reason) internal {
        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(OUTBE_CHAIN_ID, msgType, dayKey, reason);
    }

    // --- START ---

    function test_ARepeatedStartIsADuplicate() public {
        uint32 commitEnd = _openGreenDay();
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_START, InboundReason.DUPLICATE);
        _deliver(_greenStart(commitEnd));
        assertEq(uint8(auction.getAuctionStage(DAY)), uint8(IIntexAuction.AuctionStage.CommittingBids), "unchanged");
    }

    function test_ARepeatedStartAfterClearingSnappedRevealEndIsStillADuplicate() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1);
        _deliver(BridgeMsgCodec.encodeAuctionStageClearing(DAY)); // snaps revealEnd to now

        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_START, InboundReason.DUPLICATE);
        _deliver(_greenStart(commitEnd));
    }

    function test_AStartWithOtherTermsIsAConflict() public {
        uint32 commitEnd = _openGreenDay();
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_START, InboundReason.CONFLICT);
        _deliver(_start(DAY, commitEnd, 70e6, uint8(IIntexAuction.WorldwideDayState.Green)));
        assertEq(auction.getAuctionInfo(DAY).params.minIntexBidRate, 60e6, "the first START stands");
    }

    function test_ALateGreenStartIsDroppedWithoutARecord() public {
        uint32 commitEnd = uint32(block.timestamp + 1 days);
        vm.warp(commitEnd + 1);
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_START, InboundReason.LATE);
        _deliver(_greenStart(commitEnd));
        vm.expectRevert(IIntexAuction.AuctionNotFound.selector);
        auction.getAuctionInfo(DAY);
    }

    function test_AMalformedScheduleIsInvalid() public {
        uint32 commitEnd = uint32(block.timestamp + 1 days);
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            DAY,
            commitEnd,
            commitEnd, // revealEnd must be strictly after commitEnd
            commitEnd + 2 days,
            PROMIS_LOAD_MINOR,
            60e6,
            ReferenceCurrencyPriceLib.one(840, ENTRY_PRICE, FLOOR_PRICE, ENTRY_PRICE),
            0,
            0,
            0,
            1,
            0,
            uint8(IIntexAuction.WorldwideDayState.Green)
        );
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_START, InboundReason.INVALID);
        _deliver(packet);
    }

    // --- CLEARING ---

    function test_AClearingAfterTheResultIsObsolete() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1 days + 1);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));
        assertEq(uint8(auction.getAuctionStage(DAY)), uint8(IIntexAuction.AuctionStage.Completed), "cleared");

        vm.recordLogs();
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING, InboundReason.OBSOLETE);
        _deliver(BridgeMsgCodec.encodeAuctionStageClearing(DAY));
        assertEq(_countTopic(ITargetRouter.BidsDoneSent.selector), 0, "no relay for a cleared day");
    }

    function test_AClearingForACancelledDayIsObsolete() public {
        _deliver(_start(DAY, uint32(block.timestamp + 1 days), 60e6, uint8(IIntexAuction.WorldwideDayState.Red)));
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING, InboundReason.OBSOLETE);
        _deliver(BridgeMsgCodec.encodeAuctionStageClearing(DAY));
    }

    function test_AClearingForADayNeverOpenedHereIsUnknown() public {
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING, InboundReason.NOT_FOUND);
        _deliver(BridgeMsgCodec.encodeAuctionStageClearing(DAY));
    }

    function test_AnEarlyClearingStillRevertsSoTheBridgeRedelivers() public {
        _openGreenDay(); // still CommittingBids
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.RevealingBids,
                IIntexAuction.AuctionStage.CommittingBids
            )
        );
        _deliver(BridgeMsgCodec.encodeAuctionStageClearing(DAY));
    }

    // --- RESULT ---

    function test_ARepeatedResultIsADuplicate() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1 days + 1);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));

        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_RESULT, InboundReason.DUPLICATE);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));
    }

    function test_AResultWithOtherNumbersIsAConflict() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1 days + 1);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));

        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_RESULT, InboundReason.CONFLICT);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 5, 60e6, 0));
        assertEq(auction.getAuctionInfo(DAY).result.issuedIntexCount, 0, "the first RESULT stands");
    }

    function test_AResultFailingAPermanentBoundIsInvalid() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1 days + 1);
        // Nobody revealed, yet the result claims a winner: WonBidsExceedRevealed, forever.
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_RESULT, InboundReason.INVALID);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 1, 60e6, 1));
        assertEq(uint8(auction.getAuctionStage(DAY)), uint8(IIntexAuction.AuctionStage.Issuance), "not cleared");
    }

    function test_AResultForACancelledDayIsObsolete() public {
        _deliver(_start(DAY, uint32(block.timestamp + 1 days), 60e6, uint8(IIntexAuction.WorldwideDayState.Red)));
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_RESULT, InboundReason.OBSOLETE);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));
    }

    function test_AResultForADayNeverOpenedHereIsUnknown() public {
        _expectIgnored(BridgeMsgCodec.MSG_AUCTION_RESULT, InboundReason.NOT_FOUND);
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));
    }

    function test_AResultBeforeRevealClosedStillRevertsSoTheBridgeRedelivers() public {
        uint32 commitEnd = _openGreenDay();
        vm.warp(commitEnd + 1); // RevealingBids
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.Issuance,
                IIntexAuction.AuctionStage.RevealingBids
            )
        );
        _deliver(BridgeMsgCodec.encodeAuctionResult(DAY, 0, 0, 0));
    }

    function test_AWiringErrorStillRevertsSoItCanBeFixedAndRedelivered() public {
        auction.revokeRole(auction.RELAYER_ROLE(), address(router));
        vm.expectRevert();
        _deliver(_greenStart(uint32(block.timestamp + 1 days)));
    }
}
