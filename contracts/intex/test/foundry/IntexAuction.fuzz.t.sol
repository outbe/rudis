// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {MockAuctionEscrow} from "@test-mocks/MockAuctionEscrow.sol";

/// @dev Property tests for the reveal lock-amount overflow guard and the clearing sanity bounds.
contract IntexAuctionFuzzTest is Test {
    uint16 internal constant ISSUANCE_CCY = 840;
    uint16 internal constant REFERENCE_CCY = 840;

    IntexAuction internal auction;
    MockAuctionEscrow internal escrow;

    address internal admin = address(1);
    address internal bridger = address(2);

    uint256 internal iba1Pk = 0x100;
    uint256 internal iba2Pk = 0x200;
    address internal iba1;
    address internal iba2;

    bytes32 internal constant REVEAL_BID_TYPEHASH = keccak256(
        "RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,uint16 issuanceCurrency,uint16 referenceCurrency)"
    );
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    uint32 internal constant COMMIT_OFFSET = 100;
    uint32 internal constant REVEAL_OFFSET = 200;
    uint32 internal constant ISSUANCE_OFFSET = 300;

    uint16 internal constant MIN_QTY = 1;
    uint32 internal constant MIN_RATE = 10;
    uint32 internal constant SCALE_1E6 = 1_000_000;
    uint128 internal constant PROMIS_LOAD_MINOR = 100_000 * 1e6;
    // Escrow basis == promis_load per Intex; lock = qty * ESCROW_BASIS * rate / 1e6.
    uint64 internal constant ENTRY_PRICE = 1e6;
    uint128 internal constant ESCROW_BASIS = PROMIS_LOAD_MINOR;

    function setUp() public {
        iba1 = vm.addr(iba1Pk);
        iba2 = vm.addr(iba2Pk);

        auction = DeployProxy.intexAuction(admin, bridger);
        escrow = new MockAuctionEscrow();

        vm.startPrank(admin);
        auction.grantRole(auction.RELAYER_ROLE(), bridger);
        auction.wire(address(escrow));
        vm.stopPrank();
    }

    function test_Fuzz_RevealBid_RejectsRateAboveMax(uint256 qSeed, uint256 rSeed) public {
        uint16 quantity = uint16(bound(qSeed, MIN_QTY, type(uint16).max));
        uint32 rate = uint32(bound(rSeed, uint256(SCALE_1E6) + 1, type(uint32).max));

        uint32 worldwideDay = 20260201;
        _start(worldwideDay);
        bytes memory sig = _signFor(iba1Pk, worldwideDay, iba1, quantity, rate);
        _commit(worldwideDay, iba1, sig);
        _enterReveal(worldwideDay);

        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.BidRateAboveMax.selector, rate));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, quantity, rate, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);
    }

    function test_Fuzz_RevealBid_ValidProductLocksExactAmount(uint256 qSeed, uint256 rSeed) public {
        uint16 quantity = uint16(bound(qSeed, MIN_QTY, type(uint16).max));
        uint32 rate = uint32(bound(rSeed, MIN_RATE, SCALE_1E6));
        uint128 expected = uint128(uint256(quantity) * ESCROW_BASIS * rate / SCALE_1E6 * 1e12);

        uint32 worldwideDay = 20260202;
        _start(worldwideDay);
        bytes memory sig = _signFor(iba1Pk, worldwideDay, iba1, quantity, rate);
        _commit(worldwideDay, iba1, sig);
        _enterReveal(worldwideDay);

        vm.prank(iba1);
        auction.revealBid(worldwideDay, quantity, rate, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);

        assertEq(
            escrow.lockedFunds(worldwideDay, iba1),
            expected,
            "locked == protocol escrow amount converted to 18-decimal WCOEN"
        );
    }

    function test_Fuzz_ExecuteClearing_BoundsMatchPredicate(uint32 issued, uint256 rateSeed, uint256 wonSeed) public {
        uint32 worldwideDay = 20260203;
        uint32 revealed = _setupIssuanceWithTwoReveals(worldwideDay);

        uint64 clearingRate = uint64(bound(rateSeed, 0, type(uint64).max));
        uint32 wonBidsCount = uint32(bound(wonSeed, 0, revealed + 3));

        if (issued > 0 && clearingRate == 0) {
            vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroValue.selector, "auctionClearingRate"));
            vm.prank(bridger);
            auction.executeAuctionClearing(worldwideDay, issued, clearingRate, wonBidsCount);
        } else if (wonBidsCount > revealed) {
            vm.expectRevert(
                abi.encodeWithSelector(IIntexAuction.WonBidsExceedRevealed.selector, wonBidsCount, revealed)
            );
            vm.prank(bridger);
            auction.executeAuctionClearing(worldwideDay, issued, clearingRate, wonBidsCount);
        } else if (issued > 0 && clearingRate < MIN_RATE) {
            vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ClearingRateBelowMin.selector, clearingRate, MIN_RATE));
            vm.prank(bridger);
            auction.executeAuctionClearing(worldwideDay, issued, clearingRate, wonBidsCount);
        } else {
            vm.prank(bridger);
            auction.executeAuctionClearing(worldwideDay, issued, clearingRate, wonBidsCount);
            IIntexAuction.AuctionData memory a = auction.getAuctionInfo(worldwideDay);
            assertEq(a.result.issuedIntexCount, issued, "issuedIntexCount");
            assertEq(a.result.auctionClearingRate, clearingRate, "clearingRate");
            assertEq(a.result.wonBidsCount, wonBidsCount, "wonBidsCount");
        }
    }

    function test_ExecuteClearing_IssuedCountHasNoUpperBound() public {
        uint32 worldwideDay = 20260204;
        uint32 revealed = _setupIssuanceWithTwoReveals(worldwideDay);

        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, type(uint32).max, MIN_RATE, revealed);

        IIntexAuction.AuctionData memory a = auction.getAuctionInfo(worldwideDay);
        assertEq(a.result.issuedIntexCount, type(uint32).max, "issuedIntexCount accepted unbounded");
    }

    // --- Helpers ---

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("IntexAuction")),
                keccak256(bytes("1")),
                block.chainid,
                address(auction)
            )
        );
    }

    function _signFor(uint256 pk, uint32 worldwideDay, address bidder, uint16 qty, uint32 rate)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(REVEAL_BID_TYPEHASH, worldwideDay, bidder, qty, rate, ISSUANCE_CCY, REFERENCE_CCY)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _start(uint32 worldwideDay) internal {
        IIntexAuction.AuctionSchedule memory schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
        IIntexAuction.AuctionParams memory params = IIntexAuction.AuctionParams({
            promisLoadMinor: PROMIS_LOAD_MINOR,
            minIntexBidRate: MIN_RATE,
            prices: ReferenceCurrencyPriceLib.onePriced(840, ENTRY_PRICE, 100, 200),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: MIN_QTY,
            commitBondMinor: 0
        });
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, schedule, params);
    }

    function _commit(uint32 worldwideDay, address bidder, bytes memory sig) internal {
        vm.prank(bidder);
        auction.commitBid(worldwideDay, keccak256(sig));
    }

    function _enterReveal(uint32) internal {
        vm.warp(block.timestamp + COMMIT_OFFSET + 1);
    }

    function _setupIssuanceWithTwoReveals(uint32 worldwideDay) internal returns (uint32 revealed) {
        _start(worldwideDay);
        bytes memory s1 = _signFor(iba1Pk, worldwideDay, iba1, 5, 50);
        bytes memory s2 = _signFor(iba2Pk, worldwideDay, iba2, 5, 50);
        _commit(worldwideDay, iba1, s1);
        _commit(worldwideDay, iba2, s2);
        _enterReveal(worldwideDay);
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), s1);
        vm.prank(iba2);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), s2);
        vm.warp(block.timestamp + 120);
        return 2;
    }
}
