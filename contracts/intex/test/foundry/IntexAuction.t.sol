// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {MockAuctionEscrow} from "@test-mocks/MockAuctionEscrow.sol";
import {NotWhitelisted, Whitelist} from "@shared/Whitelist.sol";

contract AuctionTest is Test {
    uint16 internal constant ISSUANCE_CCY = 840;
    uint16 internal constant REFERENCE_CCY = 840;

    IntexAuction auction;
    MockAuctionEscrow escrow;

    address admin = address(1);
    address bridger = address(2);

    // Private keys for signing
    uint256 iba1PrivateKey;
    uint256 iba2PrivateKey;
    uint256 outsiderPrivateKey;

    address iba1; // Derived from iba1PrivateKey
    address iba2; // Derived from iba2PrivateKey
    address outsider; // Derived from outsiderPrivateKey

    // EIP-712 typehash mirrors `IntexAuction.REVEAL_BID_TYPEHASH`.
    bytes32 internal constant REVEAL_BID_TYPEHASH = keccak256(
        "RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,uint16 issuanceCurrency,uint16 referenceCurrency)"
    );

    uint32 internal constant SCALE_1E6 = 1_000_000;
    // WCOEN escrow: the per-Intex escrow basis is PROMIS_LOAD_MINOR (constant COEN), so the lock is
    // `qty * PROMIS_LOAD_MINOR * rate / 1e6`. ENTRY_PRICE feeds only floor/call now.
    uint128 internal constant PROMIS_LOAD_MINOR = 100_000 * 1e6;
    uint64 internal constant ENTRY_PRICE = 1e6;

    // Schedule offsets relative to the auction-start timestamp.
    uint32 constant COMMIT_OFFSET = 100;
    uint32 constant REVEAL_OFFSET = 200;
    uint32 constant ISSUANCE_OFFSET = 300;

    function setUp() public {
        // Derive addresses from private keys
        (iba1, iba1PrivateKey) = makeAddrAndKey("iba1");
        (iba2, iba2PrivateKey) = makeAddrAndKey("iba2");
        (outsider, outsiderPrivateKey) = makeAddrAndKey("outsider");

        auction = DeployProxy.intexAuction(admin, bridger);
        escrow = new MockAuctionEscrow();

        vm.startPrank(admin);
        auction.grantRole(auction.RELAYER_ROLE(), bridger);
        auction.wire(address(escrow));
        vm.stopPrank();
    }

    // --- Helpers ---

    /// @dev Build a valid, strictly-increasing, in-the-future schedule.
    function _schedule() internal view returns (IIntexAuction.AuctionSchedule memory) {
        return IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
    }

    /// @dev Build auction params with the given minimum bid rate and entry price.
    function _paramsEntry(uint32 minIntexBidRate, uint64 entryPrice, uint16 minIntexBidQuantity)
        internal
        pure
        returns (IIntexAuction.AuctionParams memory)
    {
        return IIntexAuction.AuctionParams({
            promisLoadMinor: PROMIS_LOAD_MINOR,
            minIntexBidRate: minIntexBidRate,
            prices: ReferenceCurrencyPriceLib.onePriced(840, entryPrice, 100, 200),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: minIntexBidQuantity,
            commitBondMinor: 0
        });
    }

    /// @dev Build auction params at the canonical entry price.
    function _params(uint32 minIntexBidRate, uint16 minIntexBidQuantity)
        internal
        pure
        returns (IIntexAuction.AuctionParams memory)
    {
        return _paramsEntry(minIntexBidRate, ENTRY_PRICE, minIntexBidQuantity);
    }

    /// @dev Create and start a green-day auction as the relayer. The schedule is anchored to
    ///      the current `block.timestamp` via `_schedule()`.
    function _start(uint32 worldwideDay, uint32 minIntexBidRate, uint16 minIntexBidQuantity) internal {
        vm.prank(bridger);
        auction.auctionStart(
            worldwideDay,
            IIntexAuction.WorldwideDayState.Green,
            _schedule(),
            _params(minIntexBidRate, minIntexBidQuantity)
        );
    }

    /// @dev Warp past `commitEnd` so the timestamp-computed stage is `RevealingBids`.
    function _enterRevealStage(uint32, uint256 startTs) internal {
        vm.warp(startTs + COMMIT_OFFSET + 1);
    }

    /// @dev Build an EIP-712 reveal signature against the deployed `auction` instance and the
    ///      current `block.chainid`.
    function _createSignature(uint32 worldwideDay, address sender, uint16 qty, uint32 rate, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(REVEAL_BID_TYPEHASH, worldwideDay, sender, qty, rate, ISSUANCE_CCY, REFERENCE_CCY)
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IntexAuction")),
                keccak256(bytes("1")),
                block.chainid,
                address(auction)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _commit(uint32 worldwideDay, address bidder, uint16 qty, uint32 rate, uint256 privateKey) internal {
        bytes memory signature = _createSignature(worldwideDay, bidder, qty, rate, privateKey);
        bytes32 commitHash = keccak256(signature);
        vm.prank(bidder);
        auction.commitBid(worldwideDay, commitHash);
    }

    function _reveal(uint32 worldwideDay, address bidder, uint16 qty, uint32 rate, uint256 privateKey) internal {
        bytes memory signature = _createSignature(worldwideDay, bidder, qty, rate, privateKey);
        vm.prank(bidder);
        auction.revealBid(worldwideDay, qty, rate, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), signature);
    }

    function test_Lifecycle_FullFlow() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250115; // yyyymmdd format
        uint32 floor = 50;
        uint16 bidMinimumQuantity = 1;
        _start(worldwideDay, floor, bidMinimumQuantity);

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.CommittingBids));

        IIntexAuction.AuctionData memory info = auction.getAuctionInfo(worldwideDay);
        assertEq(info.params.minIntexBidRate, floor);
        assertEq(info.params.promisLoadMinor, PROMIS_LOAD_MINOR);

        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _commit(worldwideDay, iba2, 40, 70, iba2PrivateKey);

        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));
        assertTrue(auction.committedBidsByHash(worldwideDay, iba2) != bytes32(0));

        _enterRevealStage(worldwideDay, startTs);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.RevealingBids));

        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _reveal(worldwideDay, iba2, 40, 70, iba2PrivateKey);

        // Protocol-scale lock converted into 18-decimal WCOEN.
        assertEq(
            uint256(escrow.lockedFunds(worldwideDay, iba1)), uint256(30) * PROMIS_LOAD_MINOR * 80 / SCALE_1E6 * 1e12
        );
        assertEq(
            uint256(escrow.lockedFunds(worldwideDay, iba2)), uint256(40) * PROMIS_LOAD_MINOR * 70 / SCALE_1E6 * 1e12
        );

        (, IIntexAuction.SubmittedBidData[] memory bids) = auction.getAuctionDetails(worldwideDay);
        (, uint32 revealedBidsCount) = auction.auctionRunningCounts(worldwideDay);
        assertEq(revealedBidsCount, 2);
        assertEq(bids.length, 2);

        // Past-revealEnd clearing signal: schedule already closed reveal, signal only advances stage.
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Issuance));

        vm.expectEmit(true, false, false, true);
        emit IIntexAuction.AuctionClearingExecuted(worldwideDay, 75, 100);
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 100, 75, 2);

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Completed));
        IIntexAuction.AuctionData memory fin = auction.getAuctionInfo(worldwideDay);
        assertEq(fin.result.auctionClearingRate, 75);
        assertEq(fin.result.issuedIntexCount, 100);
        assertEq(fin.result.wonBidsCount, 2);
        assertEq(fin.params.promisLoadMinor, PROMIS_LOAD_MINOR);
        // issuedIntexLoadedPromis is derived on-chain as issuedIntexCount * promisLoadMinor.
        assertEq(fin.result.issuedIntexLoadedPromis, uint128(100) * PROMIS_LOAD_MINOR);
    }

    function test_CommitCancel_And_Reverts() public {
        uint32 worldwideDay = 20250116;
        _start(worldwideDay, 10, 1);

        // commit + cancel
        _commit(worldwideDay, iba1, 5, 11, iba1PrivateKey);
        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));
        vm.prank(iba1);
        auction.cancelCommit(worldwideDay);
        assertEq(auction.committedBidsByHash(worldwideDay, iba1), bytes32(0));

        // cancel when no commit
        vm.expectRevert(IIntexAuction.BidNotFound.selector);
        vm.prank(iba1);
        auction.cancelCommit(worldwideDay);
    }

    function test_CommitBid_UngatedUntilWhitelistIsSet() public {
        assertEq(auction.whitelist(), address(0));

        uint32 worldwideDay = 20250117;
        _start(worldwideDay, 10, 1);

        // iba1 is on no list; commitBid must still work while the gate is unset.
        _commit(worldwideDay, iba1, 5, 11, iba1PrivateKey);
    }

    function test_CommitBid_GatedOnceWhitelistIsSet() public {
        address[] memory allowed = new address[](1);
        allowed[0] = iba2;
        Whitelist registry = new Whitelist(admin, allowed);

        vm.prank(admin);
        auction.setWhitelist(address(registry));

        uint32 worldwideDay = 20250117;
        _start(worldwideDay, 10, 1);

        bytes memory signature = _createSignature(worldwideDay, iba1, 5, 11, iba1PrivateKey);
        vm.expectRevert(abi.encodeWithSelector(NotWhitelisted.selector, iba1));
        vm.prank(iba1);
        auction.commitBid(worldwideDay, keccak256(signature));

        _commit(worldwideDay, iba2, 5, 11, iba2PrivateKey);
    }

    function test_SetWhitelist_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(iba1);
        auction.setWhitelist(address(1));
    }

    function test_CommitBid_RevertsZeroCommitHash() public {
        // B5.8: a degenerate zero commitHash must not occupy a bid slot.
        uint32 worldwideDay = 20250117;
        _start(worldwideDay, 10, 1);

        vm.expectRevert(IIntexAuction.InvalidCommitHash.selector);
        vm.prank(iba1);
        auction.commitBid(worldwideDay, bytes32(0));
    }

    function test_CommitBid_RevertsAtCommitEnd() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250120;
        _start(worldwideDay, 10, 1);

        // Window is [start, commitEnd): at commitEnd the computed stage is already RevealingBids.
        vm.warp(startTs + COMMIT_OFFSET);

        bytes memory signature = _createSignature(worldwideDay, iba1, 5, 11, iba1PrivateKey);
        bytes32 commitHash = keccak256(signature);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.CommittingBids,
                IIntexAuction.AuctionStage.RevealingBids
            )
        );
        vm.prank(iba1);
        auction.commitBid(worldwideDay, commitHash);
    }

    function test_CancelCommit_RevertsAtCommitEnd() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250121;
        _start(worldwideDay, 10, 1);

        _commit(worldwideDay, iba1, 5, 11, iba1PrivateKey);
        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));

        // Past commitEnd a sealed commit must not be withdrawable.
        vm.warp(startTs + COMMIT_OFFSET);

        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.CommittingBids,
                IIntexAuction.AuctionStage.RevealingBids
            )
        );
        vm.prank(iba1);
        auction.cancelCommit(worldwideDay);

        // The commit survives the rejected cancel.
        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));
    }

    function test_CommitBid_AllowedAtLastSecondBeforeCommitEnd() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250122;
        _start(worldwideDay, 10, 1);

        // commitEnd - 1 is the last valid second of the window.
        vm.warp(uint256(startTs + COMMIT_OFFSET) - 1);
        _commit(worldwideDay, iba1, 5, 11, iba1PrivateKey);
        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));
    }

    function test_Reveal_Reverts() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250117;
        _start(worldwideDay, 100, 1);

        _commit(worldwideDay, iba1, 10, 120, iba1PrivateKey);

        _enterRevealStage(worldwideDay, startTs);

        // wrong rate -> hash mismatch
        vm.expectRevert(IIntexAuction.RevealHashMismatch.selector);
        _reveal(worldwideDay, iba1, 10, 999, iba1PrivateKey);

        // ok reveal
        _reveal(worldwideDay, iba1, 10, 120, iba1PrivateKey);

        // double reveal
        vm.expectRevert(IIntexAuction.BidAlreadyRevealed.selector);
        _reveal(worldwideDay, iba1, 10, 120, iba1PrivateKey);
    }

    function test_Reveal_BelowFloor() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250118;
        _start(worldwideDay, 100, 1);

        // Commit a below-floor bid during commit stage
        _commit(worldwideDay, iba1, 10, 90, iba1PrivateKey);

        _enterRevealStage(worldwideDay, startTs);

        // below floor - try to reveal the below-floor bid
        vm.expectRevert(IIntexAuction.BidBelowMinIntexBidRate.selector);
        _reveal(worldwideDay, iba1, 10, 90, iba1PrivateKey);
    }

    function test_Reveal_BelowMinQuantity() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250140;
        // minIntexBidRate = 100, minIntexBidQuantity = 5
        _start(worldwideDay, 100, 5);

        // Commit a below-minimum-quantity bid (qty 4 < 5) at an above-floor rate.
        _commit(worldwideDay, iba1, 4, 120, iba1PrivateKey);

        _enterRevealStage(worldwideDay, startTs);

        // Quantity below the published minimum is rejected at reveal.
        vm.expectRevert(IIntexAuction.BidBelowMinIntexBidQuantity.selector);
        _reveal(worldwideDay, iba1, 4, 120, iba1PrivateKey);
    }

    function test_Reveal_AtMinQuantity_Succeeds() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250141;
        _start(worldwideDay, 100, 5);

        // Quantity exactly at the minimum is accepted (boundary is inclusive).
        _commit(worldwideDay, iba1, 5, 120, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 5, 120, iba1PrivateKey);

        assertTrue(auction.revealedBidsByBidder(worldwideDay, iba1));
    }

    function test_Reveal_AboveMaxRate() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250142;
        _start(worldwideDay, 1, 1);

        uint32 rate = SCALE_1E6 + 1;
        _commit(worldwideDay, iba1, 10, rate, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);

        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.BidRateAboveMax.selector, rate));
        _reveal(worldwideDay, iba1, 10, rate, iba1PrivateKey);
    }

    function test_Reveal_AtMaxRate_Succeeds() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250143;
        _start(worldwideDay, 1, 1);

        uint16 qty = 3;
        uint32 rate = SCALE_1E6;
        _commit(worldwideDay, iba1, qty, rate, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, qty, rate, iba1PrivateKey);

        assertTrue(auction.revealedBidsByBidder(worldwideDay, iba1));
        assertEq(
            uint256(escrow.lockedFunds(worldwideDay, iba1)), uint256(qty) * PROMIS_LOAD_MINOR * rate / SCALE_1E6 * 1e12
        );
    }

    function test_Reveal_WithoutCommit() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250119;
        _start(worldwideDay, 100, 1);

        _enterRevealStage(worldwideDay, startTs);

        // reveal without commit
        vm.expectRevert(IIntexAuction.BidNotFound.selector);
        _reveal(worldwideDay, iba2, 5, 120, iba2PrivateKey);
    }

    function test_RedDay_AuctionBornCancelled() public {
        uint32 worldwideDay = 20250120;
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Red, _schedule(), _params(1, 1));

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Cancelled));

        bytes memory signature = _createSignature(worldwideDay, iba1, 1, 1, iba1PrivateKey);
        bytes32 commitHash = keccak256(signature);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.CommittingBids,
                IIntexAuction.AuctionStage.Cancelled
            )
        );
        vm.prank(iba1);
        auction.commitBid(worldwideDay, commitHash);
    }

    function test_Views_BySeriesId() public {
        uint32 worldwideDay = 20250121;
        _start(worldwideDay, 5, 1);

        IIntexAuction.AuctionData memory a = auction.getAuctionInfo(worldwideDay);
        assertEq(a.params.minIntexBidRate, 5);
        assertEq(uint8(a.worldwideDayState), uint8(IIntexAuction.WorldwideDayState.Green));

        (IIntexAuction.AuctionData memory b, IIntexAuction.SubmittedBidData[] memory bids) =
            auction.getAuctionDetails(worldwideDay);
        assertEq(b.params.promisLoadMinor, PROMIS_LOAD_MINOR);
        assertEq(bids.length, 0);
    }

    function test_Stage_TimingTransitions() public {
        uint32 worldwideDay = 20250122;
        _start(worldwideDay, 1, 1);

        IIntexAuction.AuctionData memory d = auction.getAuctionInfo(worldwideDay);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.CommittingBids));

        // No bridge message: the stage flips exactly at the stored schedule boundaries.
        vm.warp(d.schedule.commitEnd - 1);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.CommittingBids));
        vm.warp(d.schedule.commitEnd);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.RevealingBids));

        vm.warp(d.schedule.revealEnd - 1);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.RevealingBids));
        vm.warp(d.schedule.revealEnd);
        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Issuance));
    }

    // --- Access Control Tests ---
    function test_AccessControl_Wire() public {
        vm.expectRevert();
        vm.prank(iba1);
        auction.wire(address(0xBEEF));

        vm.expectRevert();
        vm.prank(bridger);
        auction.wire(address(0xBEEF));
    }

    function test_Wire_RevertsWhileLocksOutstanding() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250201;
        _start(worldwideDay, 50, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);

        MockAuctionEscrow escrow2 = new MockAuctionEscrow();
        vm.prank(admin);
        vm.expectRevert(IIntexAuction.EscrowHasLiveLocks.selector);
        auction.wire(address(escrow2));
    }

    function test_Wire_SucceedsAfterLocksCleared() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250202;
        _start(worldwideDay, 50, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);

        escrow.releaseAllLocks();
        MockAuctionEscrow escrow2 = new MockAuctionEscrow();
        vm.prank(admin);
        auction.wire(address(escrow2));
        assertEq(address(auction.escrowContract()), address(escrow2));
    }

    function test_ReapAuction_ClearsRevealedBidsInPages() public {
        uint32 worldwideDay = 20250220;
        _start(worldwideDay, 50, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _commit(worldwideDay, iba2, 40, 70, iba2PrivateKey);
        IIntexAuction.AuctionSchedule memory sched = auction.getAuctionInfo(worldwideDay).schedule;

        vm.warp(uint256(sched.commitEnd) + 1);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _reveal(worldwideDay, iba2, 40, 70, iba2PrivateKey);

        vm.warp(uint256(sched.revealEnd) + 1);
        vm.startPrank(bridger);
        auction.startClearingStage(worldwideDay);
        auction.executeAuctionClearing(worldwideDay, 100, 75, 2);
        vm.stopPrank();

        vm.expectRevert(IIntexAuction.TooEarlyToReap.selector);
        auction.reapAuction(worldwideDay, 10);

        vm.warp(uint256(sched.issuanceEnd) + 1);
        auction.reapAuction(worldwideDay, 1);
        (, IIntexAuction.SubmittedBidData[] memory afterPage1) = auction.getAuctionDetails(worldwideDay);
        assertEq(afterPage1.length, 1);
        auction.reapAuction(worldwideDay, 10);
        (, IIntexAuction.SubmittedBidData[] memory afterPage2) = auction.getAuctionDetails(worldwideDay);
        assertEq(afterPage2.length, 0);
    }

    function test_ReapAuction_RevertsBeforeTerminal() public {
        uint32 worldwideDay = 20250221;
        _start(worldwideDay, 50, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        IIntexAuction.AuctionSchedule memory sched = auction.getAuctionInfo(worldwideDay).schedule;
        vm.warp(uint256(sched.issuanceEnd) + 1);

        // Green, past revealEnd, never cleared -> Issuance stage, not terminal.
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.Completed,
                IIntexAuction.AuctionStage.Issuance
            )
        );
        auction.reapAuction(worldwideDay, 10);
    }

    function test_RevealBid_FreesCommitSlot() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250230;
        _start(worldwideDay, 50, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        assertTrue(auction.committedBidsByHash(worldwideDay, iba1) != bytes32(0));

        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);

        assertEq(auction.committedBidsByHash(worldwideDay, iba1), bytes32(0));
    }

    function test_AccessControl_AuctionStart() public {
        uint32 worldwideDay = 20250123;

        vm.expectRevert();
        vm.prank(admin);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(10, 1));

        vm.expectRevert();
        vm.prank(iba1);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(10, 1));
    }

    function test_AccessControl_StartClearingStage() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250125;
        _start(worldwideDay, 10, 1);
        _enterRevealStage(worldwideDay, startTs);

        vm.expectRevert();
        vm.prank(admin);
        auction.startClearingStage(worldwideDay);

        vm.expectRevert();
        vm.prank(iba1);
        auction.startClearingStage(worldwideDay);
    }

    function test_AccessControl_ExecuteAuctionClearing() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250126;
        _start(worldwideDay, 10, 1);
        _enterRevealStage(worldwideDay, startTs);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        vm.expectRevert();
        vm.prank(admin);
        auction.executeAuctionClearing(worldwideDay, 100, 75, 1);

        vm.expectRevert();
        vm.prank(iba1);
        auction.executeAuctionClearing(worldwideDay, 100, 75, 1);
    }

    // --- Clearing sanity-floor ---

    function test_ExecuteAuctionClearing_RevertsWonBidsExceedRevealed() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250127;
        uint32 floor = 50;
        _start(worldwideDay, floor, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _commit(worldwideDay, iba2, 40, 70, iba2PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _reveal(worldwideDay, iba2, 40, 70, iba2PrivateKey);
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // 2 bids revealed; a clearing claiming 3 winners is rejected.
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.WonBidsExceedRevealed.selector, uint32(3), uint32(2)));
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 100, 75, 3);
    }

    function test_ExecuteAuctionClearing_RevertsPromisOverflow() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250199;
        uint32 floor = 50;

        IIntexAuction.AuctionParams memory params = _params(floor, 1);
        params.promisLoadMinor = type(uint128).max; // ceiling so the clearing product overflows uint128
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), params);

        _enterRevealStage(worldwideDay, startTs);
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        vm.expectRevert(
            abi.encodeWithSelector(IIntexAuction.IssuedPromisOverflow.selector, type(uint32).max, type(uint128).max)
        );
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, type(uint32).max, floor, 0);
    }

    function test_ExecuteAuctionClearing_RevertsClearingRateBelowMin() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250128;
        uint32 floor = 50;
        _start(worldwideDay, floor, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // Clearing rate below the configured minimum is rejected.
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ClearingRateBelowMin.selector, uint64(floor - 1), floor));
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 100, floor - 1, 1);
    }

    /// @dev No-sale auction: Desis floors the clearing rate at `minIntexBidRate`, so a clearing
    ///      with zero winners still carries a non-zero rate. This must be accepted as a valid
    ///      result - the real invariant is `clearingRate >= minIntexBidRate`, NOT the (incorrect)
    ///      `clearingRate == 0 <=> winners == 0`. Guards against re-introducing that wrong rule.
    function test_ExecuteAuctionClearing_NoSale_ZeroWinnersAtFloor() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250144;
        uint32 floor = 50;
        _start(worldwideDay, floor, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // Zero winners, zero issued, clearing rate at the floor (non-zero): a valid No-sale result.
        vm.expectEmit(true, false, false, true);
        emit IIntexAuction.AuctionClearingExecuted(worldwideDay, floor, 0);
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 0, floor, 0);

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Completed));
        IIntexAuction.AuctionData memory fin = auction.getAuctionInfo(worldwideDay);
        assertEq(fin.result.wonBidsCount, 0);
        assertEq(fin.result.issuedIntexCount, 0);
        assertEq(fin.result.auctionClearingRate, floor);
        assertEq(fin.result.issuedIntexLoadedPromis, 0);
    }

    /// @dev No-sale with no supply: even when `minIntexBidRate > 0`, the clearing rate can be 0
    ///      (nothing was allocated because supply was exhausted/zero). It must still complete -
    ///      full refund is handled via REFUND_INSTRUCTIONS, nothing is issued - and NOT revert
    ///      `ZeroValue`/`ClearingRateBelowMin`. The `cleared` flag drives the Completed stage.
    function test_ExecuteAuctionClearing_NoSale_ZeroRate() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250145;
        uint32 floor = 50; // minIntexBidRate > 0
        _start(worldwideDay, floor, 1);
        _commit(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);
        _reveal(worldwideDay, iba1, 30, 80, iba1PrivateKey);
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // issued=0, clearingRate=0, won=0 - accepted despite floor=50 (no supply was available).
        vm.expectEmit(true, false, false, true);
        emit IIntexAuction.AuctionClearingExecuted(worldwideDay, 0, 0);
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 0, 0, 0);

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Completed));
        IIntexAuction.AuctionData memory fin = auction.getAuctionInfo(worldwideDay);
        assertEq(fin.result.auctionClearingRate, 0);
        assertEq(fin.result.issuedIntexCount, 0);
        assertEq(fin.result.wonBidsCount, 0);
        assertEq(fin.result.issuedIntexLoadedPromis, 0);

        // Idempotent: re-clearing a completed auction is rejected on the stage gate.
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexAuction.StageRequired.selector,
                IIntexAuction.AuctionStage.Issuance,
                IIntexAuction.AuctionStage.Completed
            )
        );
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 0, 0, 0);
    }

    // --- Validation Tests ---
    function test_AuctionStart_Validation() public {
        uint32 worldwideDay = 20250127;

        // Schedule with commitEnd in the past.
        IIntexAuction.AuctionSchedule memory pastSchedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp),
            revealEnd: uint32(block.timestamp + 200),
            issuanceEnd: uint32(block.timestamp + 300)
        });
        vm.expectRevert(IIntexAuction.InvalidSchedule.selector);
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, pastSchedule, _params(10, 1));

        // Schedule not strictly increasing (revealEnd <= commitEnd).
        IIntexAuction.AuctionSchedule memory nonIncreasing = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + 200),
            revealEnd: uint32(block.timestamp + 200),
            issuanceEnd: uint32(block.timestamp + 300)
        });
        vm.expectRevert(IIntexAuction.InvalidSchedule.selector);
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, nonIncreasing, _params(10, 1));

        // Valid start succeeds.
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(10, 1));

        // AuctionAlreadyExists
        vm.expectRevert(IIntexAuction.AuctionAlreadyExists.selector);
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(10, 1));
    }

    function test_AuctionStart_RevertWhen_UnknownDayState() public {
        vm.expectRevert(IIntexAuction.InvalidDayState.selector);
        vm.prank(bridger);
        auction.auctionStart(20250135, IIntexAuction.WorldwideDayState.Unknown, _schedule(), _params(10, 1));
    }

    function test_AuctionStart_RedDay_AllowsPastCommitEnd() public {
        uint32 worldwideDay = 20250136;
        IIntexAuction.AuctionSchedule memory pastSchedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp),
            revealEnd: uint32(block.timestamp + 200),
            issuanceEnd: uint32(block.timestamp + 300)
        });
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Red, pastSchedule, _params(10, 1));

        assertEq(uint8(auction.getAuctionStage(worldwideDay)), uint8(IIntexAuction.AuctionStage.Cancelled));
    }

    function test_Wire_Validation() public {
        IntexAuction newAuction = DeployProxy.intexAuction(admin, bridger);
        vm.startPrank(admin);
        newAuction.grantRole(newAuction.RELAYER_ROLE(), bridger);

        // Zero escrow address
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroAddress.selector, "escrowContract"));
        newAuction.wire(address(0));

        vm.stopPrank();
    }

    function test_ExecuteAuctionClearing_Validation() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250128;
        _start(worldwideDay, 10, 1);
        _enterRevealStage(worldwideDay, startTs);
        // Reach the Issuance stage (time-derived: now >= revealEnd).
        vm.warp(startTs + REVEAL_OFFSET + 1);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // Zero auctionClearingRate
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroValue.selector, "auctionClearingRate"));
        vm.prank(bridger);
        auction.executeAuctionClearing(worldwideDay, 100, 0, 1);
    }

    function test_RevealBid_Validation() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250129;
        _start(worldwideDay, 10, 1);
        _commit(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);

        // Zero quantity
        bytes memory sig = _createSignature(worldwideDay, iba1, 0, 20, iba1PrivateKey);
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroValue.selector, "quantity/bidRate"));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 0, 20, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);

        // Zero bidRate
        sig = _createSignature(worldwideDay, iba1, 10, 0, iba1PrivateKey);
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroValue.selector, "quantity/bidRate"));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 10, 0, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);

        // Wrong chainId - caller's chainId param does not match block.chainid -> WrongChain.
        uint64 wrongChainId = 999;
        sig = _createSignature(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.WrongChain.selector, block.chainid, uint256(wrongChainId)));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 10, 20, ISSUANCE_CCY, REFERENCE_CCY, wrongChainId, sig);
    }

    function test_StartClearingStage_AlreadyClearing() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250130;
        _start(worldwideDay, 10, 1);
        _enterRevealStage(worldwideDay, startTs);
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);

        // Call again when already in the issuance stage: idempotent, re-emits the stage update.
        vm.expectEmit(true, false, false, true);
        emit IIntexAuction.AuctionStageUpdated(
            worldwideDay, IIntexAuction.AuctionStage.Issuance, uint32(block.timestamp), ""
        );
        vm.prank(bridger);
        auction.startClearingStage(worldwideDay);
    }

    function test_ViewFunctions_NotFound() public {
        uint32 nonExistentSeries = 99999999; // non-existent series

        vm.expectRevert(IIntexAuction.AuctionNotFound.selector);
        auction.getAuctionInfo(nonExistentSeries);

        vm.expectRevert(IIntexAuction.AuctionNotFound.selector);
        auction.getAuctionDetails(nonExistentSeries);

        vm.expectRevert(IIntexAuction.AuctionNotFound.selector);
        auction.getAuctionStage(nonExistentSeries);
    }

    function test_RevealBid_WrongSigner() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250131;
        _start(worldwideDay, 10, 1);
        _commit(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);

        // Try to reveal with signature from iba1 but call from iba2
        // This will fail with BidNotFound because iba2 has no commit
        bytes memory sig = _createSignature(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        vm.expectRevert(IIntexAuction.BidNotFound.selector);
        vm.prank(iba2);
        auction.revealBid(worldwideDay, 10, 20, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);
    }

    /// @dev Reentrancy probe: arm the escrow mock to call back into `revealBid` during
    ///      `lockFunds`. With `nonReentrant` in place the inner call reverts with
    ///      `ReentrancyGuardReentrantCall`, which propagates and unwinds all state.
    ///      Removing `nonReentrant` from `revealBid` makes this test fail (reentry succeeds,
    ///      attacker double-records the bid) - i.e. it is a true red->green test of the guard.
    function test_RevealBid_reentrancyBlocked() public {
        uint256 startTs = block.timestamp;
        uint32 worldwideDay = 20250201;
        _start(worldwideDay, 10, 1);
        _commit(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        _enterRevealStage(worldwideDay, startTs);

        bytes memory sig = _createSignature(worldwideDay, iba1, 10, 20, iba1PrivateKey);
        bytes memory reentrantCall = abi.encodeCall(
            IIntexAuction.revealBid, (worldwideDay, 10, 20, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig)
        );
        escrow.armReentry(auction, reentrantCall);

        bytes4 reentrancyGuard = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        vm.expectRevert(reentrancyGuard);
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 10, 20, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);

        // Tx unwound: no reveal recorded, no bid pushed.
        assertFalse(auction.revealedBidsByBidder(worldwideDay, iba1));
        (, IIntexAuction.SubmittedBidData[] memory bids) = auction.getAuctionDetails(worldwideDay);
        assertEq(bids.length, 0);
        (, uint32 revealedBidsCount) = auction.auctionRunningCounts(worldwideDay);
        assertEq(revealedBidsCount, 0);
    }
}
