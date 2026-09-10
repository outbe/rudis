// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {MockAuctionEscrow} from "@test-mocks/MockAuctionEscrow.sol";

/// @dev Schedule snap on the bridge clearing signal: an early signal pulls `revealEnd`
///      forward; a late signal leaves the schedule untouched.
contract IntexAuctionScheduleSnapTest is Test {
    IntexAuction auction;
    MockAuctionEscrow escrow;

    address admin = address(1);
    address bridger = address(2);

    uint32 constant COMMIT_OFFSET = 100;
    uint32 constant REVEAL_OFFSET = 200;
    uint32 constant ISSUANCE_OFFSET = 300;

    function setUp() public {
        auction = DeployProxy.intexAuction(admin, bridger);
        escrow = new MockAuctionEscrow();
        vm.startPrank(admin);
        auction.grantRole(auction.RELAYER_ROLE(), bridger);
        auction.wire(address(escrow));
        vm.stopPrank();
    }

    function _start(uint32 worldwideDay) internal {
        IIntexAuction.AuctionSchedule memory s = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
        IIntexAuction.AuctionParams memory p = IIntexAuction.AuctionParams({
            promisLoadMinor: 1000,
            minIntexBidRate: 10,
            prices: ReferenceCurrencyPriceLib.onePriced(840, 100, 100, 100),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: 0
        });
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, s, p);
    }

    function test_ClearingSignal_Early_SnapsRevealEnd() public {
        uint32 worldwideDay = 20250201;
        _start(worldwideDay);
        IIntexAuction.AuctionData memory b = auction.getAuctionInfo(worldwideDay);
        vm.warp(b.schedule.commitEnd + 1);

        uint32 signalTs = b.schedule.commitEnd + 20;
        vm.warp(signalTs);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        IIntexAuction.AuctionData memory a = auction.getAuctionInfo(worldwideDay);
        assertEq(a.schedule.revealEnd, signalTs);
        assertLt(a.schedule.revealEnd, b.schedule.revealEnd);
        assertEq(a.schedule.issuanceEnd, b.schedule.issuanceEnd);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Issuance));
    }

    function test_ClearingSignal_Late_LeavesRevealEnd() public {
        uint32 worldwideDay = 20250202;
        _start(worldwideDay);
        IIntexAuction.AuctionData memory b = auction.getAuctionInfo(worldwideDay);

        vm.warp(b.schedule.revealEnd + 5);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        IIntexAuction.AuctionData memory a = auction.getAuctionInfo(worldwideDay);
        assertEq(a.schedule.revealEnd, b.schedule.revealEnd);
        assertEq(a.schedule.issuanceEnd, b.schedule.issuanceEnd);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Issuance));
    }
}
