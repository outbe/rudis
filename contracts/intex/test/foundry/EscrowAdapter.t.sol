// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {IAllocator} from "@contracts/vendor/the-compact/interfaces/IAllocator.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

contract EscrowAdapterTest is Test {
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address auction = address(3);
    address bidder1 = address(5);
    address bidder2 = address(6);
    address outsider = address(7);
    address proceedsRecipient = address(8);

    uint32 worldwideDay1 = 1;
    uint32 worldwideDay2 = 2;

    uint128 constant LOCK_AMOUNT = 1000 * 10 ** 6;

    /// @dev Stand-in for the inbound bridge message id that carries refund instructions. Threaded
    ///      through `finalizeAuction`/`retryFinalize` into the emitted events.
    bytes32 constant RECEIVE_ID = bytes32(uint256(0xDEADBEEF));

    /// @dev Live ERC6909 balance held by the escrow in The Compact for the active lockId.
    function _liveCompactBalance() internal view returns (uint256) {
        return IERC6909(address(compact)).balanceOf(address(escrow), escrow.lockId());
    }

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        // Wire dependencies (no allow-list precondition anymore).
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
        vm.prank(admin);
        escrow.setProceedsRecipient(proceedsRecipient);

        // Set reset period to 0 for immediate withdrawal in tests
        compact.setResetPeriodSeconds(0);

        // Fund bidders
        paymentToken.mint(bidder1, 10000 * 10 ** 6);
        paymentToken.mint(bidder2, 10000 * 10 ** 6);

        // Approve escrow to spend bidder tokens
        vm.prank(bidder1);
        paymentToken.approve(address(escrow), type(uint256).max);
        vm.prank(bidder2);
        paymentToken.approve(address(escrow), type(uint256).max);
    }

    // --- Constructor Tests ---
    function test_Constructor() public {
        EscrowAdapter newEscrow = DeployProxy.escrowAdapter(admin, bridger);
        assertTrue(newEscrow.hasRole(newEscrow.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(newEscrow.hasRole(newEscrow.RELAYER_ROLE(), bridger));
    }

    function test_Constructor_ZeroAdmin() public {
        EscrowAdapter impl = new EscrowAdapter();
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "defaultAdmin"));
        new ERC1967Proxy(address(impl), abi.encodeCall(EscrowAdapter.initialize, (address(0))));
    }

    // --- Wire Tests ---
    function test_Wire() public view {
        assertEq(escrow.intexAuctionContract(), auction);
        assertEq(address(escrow.compact()), address(compact));
        assertEq(address(escrow.paymentToken()), address(paymentToken));
        assertTrue(escrow.hasRole(escrow.AUCTION_ROLE(), auction));
        assertTrue(escrow.allocatorId() > 0);
    }

    function test_Wire_ResetsAllocatorOnCompactRotation() public {
        uint96 allocatorBefore = escrow.allocatorId();
        bytes12 lockTagBefore = escrow.lockTag();
        assertTrue(allocatorBefore > 0);

        // Rotate to a new Compact (setUp opened no locks). Bump its counter so a fresh
        // registration yields a distinct allocatorId.
        MockTheCompact compact2 = new MockTheCompact();
        compact2.setResetPeriodSeconds(0);
        compact2.__registerAllocator(address(0xDEAD), "");

        vm.prank(admin);
        escrow.wire(auction, address(compact2), address(paymentToken));

        assertTrue(escrow.allocatorId() != allocatorBefore);
        assertTrue(escrow.lockTag() != lockTagBefore);
    }

    function test_HasOutstandingLocks_ReflectsLockState() public {
        assertFalse(escrow.hasOutstandingLocks());
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        assertTrue(escrow.hasOutstandingLocks());
    }

    function test_Wire_RevertsRotatingCompactWithLiveLocks() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        MockTheCompact compact2 = new MockTheCompact();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.LiveLocksOutstanding.selector, uint256(LOCK_AMOUNT)));
        escrow.wire(auction, address(compact2), address(paymentToken));
    }

    function test_Wire_ZeroAuction() public {
        EscrowAdapter newEscrow = DeployProxy.escrowAdapter(admin, bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "intexAuction"));
        vm.prank(admin);
        newEscrow.wire(address(0), address(compact), address(paymentToken));
    }

    function test_Wire_ZeroCompact() public {
        EscrowAdapter newEscrow = DeployProxy.escrowAdapter(admin, bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "compact"));
        vm.prank(admin);
        newEscrow.wire(auction, address(0), address(paymentToken));
    }

    function test_Wire_ZeroPaymentToken() public {
        EscrowAdapter newEscrow = DeployProxy.escrowAdapter(admin, bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "paymentToken"));
        vm.prank(admin);
        newEscrow.wire(auction, address(compact), address(0));
    }

    function test_Wire_EmitsWired_OnInitial() public {
        EscrowAdapter freshEscrow = DeployProxy.escrowAdapter(admin, bridger);
        // Initial wire: every `*Old` field is the zero address.
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.Wired(address(0), auction, address(0), address(compact), address(0), address(paymentToken));
        vm.prank(admin);
        freshEscrow.wire(auction, address(compact), address(paymentToken));
    }

    function test_Wire_EmitsWired_OnRotation() public {
        // Rotate the auction address (no LiveLocksOutstanding constraint - no locks opened in setUp).
        // `escrow` was wired in setUp with (auction, compact, paymentToken); only the auction
        // rotates, so its old value is non-zero and the rest carry their prior addresses.
        address newAuction = address(0xBEEF);
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.Wired(
            auction, newAuction, address(compact), address(compact), address(paymentToken), address(paymentToken)
        );
        vm.prank(admin);
        escrow.wire(newAuction, address(compact), address(paymentToken));
    }

    function test_Wire_OnlyAdmin() public {
        EscrowAdapter newEscrow = DeployProxy.escrowAdapter(admin, bridger);
        vm.expectRevert();
        vm.prank(outsider);
        newEscrow.wire(auction, address(compact), address(paymentToken));
    }

    // --- LockFunds Tests ---
    function test_LockFunds() public {
        uint256 balanceBefore = paymentToken.balanceOf(bidder1);

        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        // Check bidder balance decreased
        assertEq(paymentToken.balanceOf(bidder1), balanceBefore - LOCK_AMOUNT);

        // Check lock data
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(lock.lockedAmount, LOCK_AMOUNT);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Locked));
        assertTrue(lock.lockedAt > 0);

        // Check auction stats
        (bool hasLocks, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(hasLocks);
        assertFalse(isFinalized);
        assertEq(totalLocked, LOCK_AMOUNT);
        assertEq(_liveCompactBalance(), LOCK_AMOUNT);
    }

    function test_LockFunds_MultipleBidders() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT * 2);

        // Check auction stats
        (bool hasLocks, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(hasLocks);
        assertFalse(isFinalized);
        assertEq(totalLocked, LOCK_AMOUNT * 3);
        assertEq(_liveCompactBalance(), LOCK_AMOUNT * 3);
    }

    function test_LockFunds_ZeroBidder() public {
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "bidder"));
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, address(0), LOCK_AMOUNT);
    }

    function test_LockFunds_ZeroAmount() public {
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroValue.selector, "amount"));
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, 0);
    }

    /// @notice cheap sanity floor on `worldwideDay`. The `AUCTION_ROLE` gate already guarantees
    ///         a real series, but a zero id is obviously bogus and is rejected before any state write.
    function test_LockFunds_ZeroWorldwideDay() public {
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroValue.selector, "worldwideDay"));
        vm.prank(auction);
        escrow.lockFunds(0, bidder1, LOCK_AMOUNT);
    }

    function test_LockFunds_AlreadyLocked() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.expectRevert(IEscrowAdapter.BidAlreadyLocked.selector);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
    }

    function test_LockFunds_OnlyAuctionRole() public {
        vm.expectRevert();
        vm.prank(outsider);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.expectRevert();
        vm.prank(admin);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.expectRevert();
        vm.prank(bridger);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
    }

    // --- FinalizeAuction Tests ---
    function test_FinalizeAuction_FullRefund() public {
        // Lock funds
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 bidderBalanceBefore = paymentToken.balanceOf(bidder1);

        // Finalize with full refund
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Check bidder received refund
        assertEq(paymentToken.balanceOf(bidder1), bidderBalanceBefore + LOCK_AMOUNT);

        // Check auction status
        (bool hasLocks, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(hasLocks); // Count stays, but amount is 0
        assertTrue(isFinalized);
        assertEq(totalLocked, 0);
        assertEq(_liveCompactBalance(), 0);

        // Check lock status
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Finalized));
    }

    // --- post-finalize abandon refund for omitted/mismatched bidders ---

    // Finalize the series settling bidder2 only; bidder1 is omitted, left Locked with no split.
    function _finalizeOmittingBidder1() internal {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder2, refundedAmount: LOCK_AMOUNT, paidAmount: 0});
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_OmittedBidder_RevertsBeforeAbandon() public {
        _finalizeOmittingBidder1();
        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY() + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.SplitNotRecorded.selector, worldwideDay1, bidder1));
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_OmittedBidder_RecoversAfterAbandon() public {
        _finalizeOmittingBidder1();
        uint256 balBefore = paymentToken.balanceOf(bidder1);

        vm.warp(block.timestamp + escrow.NO_SPLIT_REFUND_DELAY() + 1);
        escrow.claimRefund(worldwideDay1, bidder1); // permissionless

        assertEq(paymentToken.balanceOf(bidder1), balBefore + LOCK_AMOUNT, "full principal refunded");
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Finalized), "lock finalized");
        (,, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertEq(totalLocked, 0, "totalLocked cleared (bidder2 refunded at finalize, bidder1 at abandon)");

        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_RetryFinalizePreemptsAbandon() public {
        _finalizeOmittingBidder1();

        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY() + 1);
        IEscrowAdapter.FinalizationInstruction memory inst =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, RECEIVE_ID, inst);

        // bidder1 settled -> abandon path can never fire.
        vm.warp(block.timestamp + escrow.NO_SPLIT_REFUND_DELAY() + 1);
        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_FinalizeAuction_FullClaim() public {
        // Lock funds
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 recipientBalanceBefore = paymentToken.balanceOf(proceedsRecipient);

        // Finalize with full claim (winning bid)
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT});

        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.AuctionEscrowFinalized(RECEIVE_ID, worldwideDay1, 0, LOCK_AMOUNT, 1);

        vm.prank(bridger);
        uint128 routed = escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Proceeds handed to the configured recipient for cross-chain routing, not the caller.
        assertEq(routed, LOCK_AMOUNT);
        assertEq(paymentToken.balanceOf(proceedsRecipient), recipientBalanceBefore + LOCK_AMOUNT);
        assertEq(paymentToken.balanceOf(bridger), 0);

        // Check accounting cleared
        (, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(isFinalized);
        assertEq(totalLocked, 0);
    }

    function test_FinalizeAuction_PartialRefundAndClaim() public {
        // Lock funds
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 bidderBalanceBefore = paymentToken.balanceOf(bidder1);
        uint256 recipientBalanceBefore = paymentToken.balanceOf(proceedsRecipient);
        uint128 refundedAmount = LOCK_AMOUNT * 30 / 100; // 30% refund
        uint128 paidAmount = LOCK_AMOUNT - refundedAmount; // 70% claim

        // Finalize with partial refund and claim
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1, refundedAmount: refundedAmount, paidAmount: paidAmount
        });

        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.AuctionEscrowFinalized(RECEIVE_ID, worldwideDay1, refundedAmount, paidAmount, 1);

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Bidder refunded their portion; proceeds handed to the configured recipient.
        assertEq(paymentToken.balanceOf(bidder1), bidderBalanceBefore + refundedAmount);
        assertEq(paymentToken.balanceOf(proceedsRecipient), recipientBalanceBefore + paidAmount);
    }

    function test_FinalizeAuction_MultipleBidders() public {
        // Lock funds for multiple bidders
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT * 2);

        // Finalize: bidder1 gets full refund, bidder2 gets a 50/50 split.
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](2);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});
        instructions[1] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder2, refundedAmount: LOCK_AMOUNT, paidAmount: LOCK_AMOUNT
        });

        // totalRefunded = LOCK_AMOUNT (b1) + LOCK_AMOUNT (b2) = 2*LOCK_AMOUNT
        // totalPaid = 0 (b1) + LOCK_AMOUNT (b2) = LOCK_AMOUNT
        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.AuctionEscrowFinalized(RECEIVE_ID, worldwideDay1, LOCK_AMOUNT * 2, LOCK_AMOUNT, 2);

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // All escrow drained for the series.
        (, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(isFinalized);
        assertEq(totalLocked, 0);
        assertEq(_liveCompactBalance(), 0);
    }

    function test_FinalizeAuction_EmptyInstructions() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](0);

        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroValue.selector, "instructions"));
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_FinalizeAuction_AlreadyFinalized() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Try to finalize again
        vm.expectRevert(IEscrowAdapter.AlreadyFinalized.selector);
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_FinalizeAuction_ZeroBidder_EmitsBidderRefundFailed() public {
        // A zero-address bidder fails inside the per-bidder try/catch and emits BidderRefundFailed;
        // the outer call still succeeds (with zero totals because the single iteration failed).
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: address(0), refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.expectEmit(true, true, true, false);
        emit IEscrowAdapter.BidderRefundFailed(RECEIVE_ID, worldwideDay1, address(0), "");
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // bidder1's lock is still recoverable via retryFinalize (relayer) / claimRefund.
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Locked));
    }

    function test_FinalizeAuction_LockNotActive_EmitsBidderRefundFailed() public {
        // Series has zero locks: the single instruction's bidder has no active lock, so the
        // per-bidder try/catch catches LockNotActive and emits BidderRefundFailed.
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.expectEmit(true, true, true, false);
        emit IEscrowAdapter.BidderRefundFailed(RECEIVE_ID, worldwideDay1, bidder1, "");
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_FinalizeAuction_OneFailure_OthersSucceed() public {
        // Two bidders: bidder1's instruction has an amount mismatch (fails), bidder2's is valid.
        // Fail-safe loop: bidder1 emits BidderRefundFailed, bidder2 finalizes normally.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](2);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1,
            refundedAmount: LOCK_AMOUNT / 2,
            paidAmount: LOCK_AMOUNT / 2 - 1 // mismatch - will fail
        });
        instructions[1] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder2,
            refundedAmount: LOCK_AMOUNT,
            paidAmount: 0 // full refund, valid
        });

        uint256 bidder2BalanceBefore = paymentToken.balanceOf(bidder2); // after lockFunds crosschainBurn

        vm.expectEmit(true, true, true, false);
        emit IEscrowAdapter.BidderRefundFailed(RECEIVE_ID, worldwideDay1, bidder1, "");
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // bidder1's lock unchanged (still Locked); bidder2's finalized + refunded.
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Locked));
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder2).status), uint8(IEscrowAdapter.LockStatus.Finalized));
        assertEq(paymentToken.balanceOf(bidder2), bidder2BalanceBefore + LOCK_AMOUNT);
    }

    function test_FinalizeAuction_AmountMismatch_EmitsBidderRefundFailed() public {
        // A bidder whose refund + payout doesn't match the locked amount fails inside the per-bidder
        // try/catch and emits BidderRefundFailed; the outer call still succeeds.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1,
            refundedAmount: LOCK_AMOUNT / 2,
            paidAmount: LOCK_AMOUNT / 2 - 1 // Missing 1 unit
        });

        vm.expectEmit(true, true, true, false);
        emit IEscrowAdapter.BidderRefundFailed(RECEIVE_ID, worldwideDay1, bidder1, "");
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Lock remains active for recovery.
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Locked));
    }

    function test_FinalizeAuction_AllFail_EmitsFinalizationNoOp() public {
        // Every instruction fails (here: amount mismatch on the only bidder) -> zero settled. The
        // series is finalized but degenerate; FinalizationNoOp surfaces it instead of a silent no-op.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT - 1});

        vm.expectEmit(true, false, false, true, address(escrow));
        emit IEscrowAdapter.FinalizationNoOp(worldwideDay1, 1);
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_FinalizeAuction_OnlyBridgeRole() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.expectRevert();
        vm.prank(outsider);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        vm.expectRevert();
        vm.prank(admin);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        vm.expectRevert();
        vm.prank(auction);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    // --- IAllocator Tests ---
    function test_Attest_ValidLockId() public {
        // First lock some funds to set lockId
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 lockId = escrow.lockId();
        bytes4 result = escrow.attest(address(0), address(0), address(0), lockId, 0);
        assertEq(result, IAllocator.attest.selector);
    }

    function test_Attest_InvalidLockId() public {
        // First lock some funds to set lockId
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.UnexpectedLockId.selector, uint256(999)));
        escrow.attest(address(0), address(0), address(0), 999, 0);
    }

    function test_AuthorizeClaim_AlwaysReverts() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](0);
        vm.expectRevert(IEscrowAdapter.ClaimAuthorizationUnsupported.selector);
        escrow.authorizeClaim(bytes32(0), address(0), address(0), 0, 0, idsAndAmounts, "");
    }

    function test_IsClaimAuthorized_AlwaysFalse() public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](0);
        bool result = escrow.isClaimAuthorized(bytes32(0), address(0), address(0), 0, 0, idsAndAmounts, "");
        assertFalse(result);
    }

    // --- View Functions Tests ---
    function test_GetBidLock() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(lock.lockedAmount, LOCK_AMOUNT);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.Locked));
    }

    function test_GetBidLock_NonExistent() public view {
        IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay1, bidder1);
        assertEq(lock.lockedAmount, 0);
        assertEq(uint8(lock.status), uint8(IEscrowAdapter.LockStatus.None));
    }

    function test_GetAuctionStatus() public {
        // Before any locks
        (bool hasLocks, bool isFinalized, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertFalse(hasLocks);
        assertFalse(isFinalized);
        assertEq(totalLocked, 0);

        // After lock
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        (hasLocks, isFinalized, totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertTrue(hasLocks);
        assertFalse(isFinalized);
        assertEq(totalLocked, LOCK_AMOUNT);
    }

    // --- SupportsInterface Tests ---
    function test_SupportsInterface() public view {
        assertTrue(escrow.supportsInterface(type(IAllocator).interfaceId));
    }

    // --- Events Tests ---
    function test_Events_FundsLocked() public {
        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.FundsLocked(worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
    }

    function test_Events_FundsRefunded() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.FundsRefunded(RECEIVE_ID, worldwideDay1, bidder1, LOCK_AMOUNT);

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    function test_Events_AuctionEscrowFinalized() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1, refundedAmount: LOCK_AMOUNT / 2, paidAmount: LOCK_AMOUNT / 2
        });

        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.AuctionEscrowFinalized(RECEIVE_ID, worldwideDay1, LOCK_AMOUNT / 2, LOCK_AMOUNT / 2, 1);

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
    }

    // --- Payment Token Rotation Tests ---
    function test_Wire_RotatePaymentToken_RejectedWithLiveLocks() public {
        // Lock funds with the current paymentToken
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        // Rewire targeting a new token while locks are still in flight - must revert
        MockWCOEN rotated = new MockWCOEN();
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.LiveLocksOutstanding.selector, uint256(LOCK_AMOUNT)));
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(rotated));
    }

    function test_Wire_RotatePaymentToken_AllowedWhenNoLocks() public {
        // Swap active token when no locks are held.
        MockWCOEN rotated = new MockWCOEN();
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(rotated));

        assertEq(address(escrow.paymentToken()), address(rotated));
    }

    function test_Wire_RewireSameTokenStaysAllowedWithLocks() public {
        // Active locks must not block re-wiring with the same token (e.g. rotating the auction).
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        address newAuction = address(0xBEEF);
        vm.prank(admin);
        escrow.wire(newAuction, address(compact), address(paymentToken));
        assertEq(escrow.intexAuctionContract(), newAuction);
    }

    // --- claimRefund ---

    function test_ClaimRefund_AfterDelay_Succeeds() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 balanceBefore = paymentToken.balanceOf(bidder1);

        vm.warp(block.timestamp + escrow.UNFINALIZED_REFUND_DELAY());

        // Permissionless caller (an outsider) triggers the refund; funds go to bidder1.
        // claimRefund is not bridge-triggered, so the emitted receiveId is the zero sentinel.
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.FundsRefunded(bytes32(0), worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(outsider);
        escrow.claimRefund(worldwideDay1, bidder1);

        assertEq(paymentToken.balanceOf(bidder1), balanceBefore + LOCK_AMOUNT);
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Finalized));
    }

    function test_ClaimRefund_BeforeDelay_Reverts() public {
        uint32 lockedAt = uint32(block.timestamp);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        // One second before the delay elapses.
        uint32 claimableAt = lockedAt + escrow.UNFINALIZED_REFUND_DELAY();
        vm.warp(claimableAt - 1);

        vm.expectRevert(
            abi.encodeWithSelector(IEscrowAdapter.RefundNotYetClaimable.selector, claimableAt, claimableAt - 1)
        );
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_NotLocked_Reverts() public {
        // No lock exists for bidder1.
        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_DoubleClaim_Reverts() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.warp(block.timestamp + escrow.UNFINALIZED_REFUND_DELAY());

        escrow.claimRefund(worldwideDay1, bidder1);

        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_ZeroBidder_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "bidder"));
        escrow.claimRefund(worldwideDay1, address(0));
    }

    function test_ClaimRefund_ForcedWithdrawalReturnsFalse_Reverts() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.warp(block.timestamp + escrow.UNFINALIZED_REFUND_DELAY());

        // The Compact's forced withdrawal returns false (e.g. reset period not elapsed); the
        // adapter must surface this as the dedicated ForcedWithdrawalFailed, not a generic error.
        compact.setForcedWithdrawalShouldFail(true);

        vm.expectRevert(IEscrowAdapter.ForcedWithdrawalFailed.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_PostFinalize_GateAnchorsAtFinalizeNotLock() public {
        // Lock, then finalize a day later with a failing instruction (BidderRefundFailed leaves
        // lock Locked).
        uint32 lockedAt = uint32(block.timestamp);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        // via-ir CSEs TIMESTAMP across vm.warp, so derive finalizedAt instead of re-reading it.
        uint32 finalizedAt = lockedAt + 1 days;
        vm.warp(finalizedAt);
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1,
            refundedAmount: 0,
            paidAmount: LOCK_AMOUNT - 1 // mismatch, fails inside try/catch
        });
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // The pre-finalize window (lockedAt + UNFINALIZED_REFUND_DELAY) has elapsed, but the
        // series is finalized, so the finalizedAt-anchored post-finalize gate governs and blocks.
        uint32 nowAt = lockedAt + escrow.UNFINALIZED_REFUND_DELAY();
        uint32 claimableAt = finalizedAt + escrow.POST_FINALIZE_REFUND_DELAY();
        vm.warp(nowAt);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.RefundNotYetClaimable.selector, claimableAt, nowAt));
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_PostFinalize_RevertsSplitNotRecorded() public {
        // An amount-mismatch failure records no valid split, so claimRefund cannot pay out - the
        // relayer must retryFinalize with a correct split.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT - 1});
        uint32 finalizedAt = uint32(block.timestamp);
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        vm.warp(finalizedAt + escrow.POST_FINALIZE_REFUND_DELAY());
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.SplitNotRecorded.selector, worldwideDay1, bidder1));
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    function test_ClaimRefund_AfterRetry_RevertsLockNotActive() public {
        // Retry moves lock to Finalized; subsequent claimRefund must revert.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1,
            refundedAmount: 0,
            paidAmount: LOCK_AMOUNT - 1 // mismatch
        });
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Relayer retries with the correct split.
        vm.prank(bridger);
        escrow.retryFinalize(
            worldwideDay1,
            RECEIVE_ID,
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0})
        );

        // 7d later, claimRefund must still revert (already Finalized).
        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY());
        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        escrow.claimRefund(worldwideDay1, bidder1);
    }

    // --- retryFinalize ---

    function test_RetryFinalize_HappyPath_AfterFailedIteration() public {
        // Two bidders: bidder1's initial finalize iteration fails (amount mismatch); bidder2 succeeds.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](2);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1,
            refundedAmount: LOCK_AMOUNT / 2,
            paidAmount: LOCK_AMOUNT / 2 - 1 // mismatch - will fail
        });
        instructions[1] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder2, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // bidder1 stayed Locked; bidder2 finalized.
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Locked));

        // Relayer retries bidder1 with the correct split.
        IEscrowAdapter.FinalizationInstruction memory retryInst = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1, refundedAmount: LOCK_AMOUNT / 2, paidAmount: LOCK_AMOUNT - LOCK_AMOUNT / 2
        });

        uint256 bidder1BalanceBefore = paymentToken.balanceOf(bidder1);

        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.BidderRetried(
            RECEIVE_ID, worldwideDay1, bidder1, retryInst.refundedAmount, retryInst.paidAmount
        );
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, RECEIVE_ID, retryInst);

        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Finalized));
        assertEq(paymentToken.balanceOf(bidder1), bidder1BalanceBefore + retryInst.refundedAmount);
    }

    function test_RetryFinalize_Reverts_BeforeFinalize() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction memory inst =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.NotFinalizedYet.selector, worldwideDay1));
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, RECEIVE_ID, inst);
    }

    function test_RetryFinalize_Reverts_OnAlreadyFinalizedLock() public {
        // Successful finalize moves lock to Finalized; retrying it reverts LockNotActive.
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        vm.expectRevert(IEscrowAdapter.LockNotActive.selector);
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, RECEIVE_ID, instructions[0]);
    }

    function test_RetryFinalize_OnlyRelayer() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT - 1});
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);

        // Now bidder1 sits in Locked (the iteration failed on amount mismatch). Outsider can't retry.
        vm.expectRevert();
        vm.prank(outsider);
        escrow.retryFinalize(
            worldwideDay1,
            RECEIVE_ID,
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0})
        );
    }

    // --- message-id threading ---

    /// @dev A single finalize call must stamp the same inbound bridge message id onto every fund-movement
    ///      event it emits (FundsRefunded) and the summary (AuctionEscrowFinalized),
    ///      so an indexer can attribute the whole batch to one cross-chain packet.
    function test_GuidThreading_AllFinalizeEvents_CarryPacketGuid() public {
        bytes32 packet = keccak256("inbound-packet-A");

        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT); // refunded bidder
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder2, LOCK_AMOUNT); // paid (winning) bidder

        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](2);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});
        instructions[1] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder2, refundedAmount: 0, paidAmount: LOCK_AMOUNT});

        // Both finalize events must carry `packet` as the indexed receiveId (topic1).
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.FundsRefunded(packet, worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.AuctionEscrowFinalized(packet, worldwideDay1, LOCK_AMOUNT, LOCK_AMOUNT, 2);

        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, packet, instructions, true);
    }

    /// @dev A relayer retry is its own inbound packet: `retryFinalize` must stamp the retry's RECEIVE_ID
    ///      (not the original finalize RECEIVE_ID) onto its events, so a re-sent packet is independently
    ///      attributable. Proves the receiveId is the threaded argument, not an echoed constant.
    function test_GuidThreading_RetryCarriesItsOwnGuid() public {
        bytes32 originalPacket = keccak256("inbound-packet-original");
        bytes32 retryPacket = keccak256("inbound-packet-retry");

        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        // First finalize fails on an amount mismatch (lock stays Locked), stamped with originalPacket.
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT - 1});
        vm.expectEmit(true, true, true, false);
        emit IEscrowAdapter.BidderRefundFailed(originalPacket, worldwideDay1, bidder1, "");
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, originalPacket, instructions, true);

        // Relayer retries under a distinct bridge message id; the retry events must carry retryPacket.
        IEscrowAdapter.FinalizationInstruction memory fixInst =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: LOCK_AMOUNT, paidAmount: 0});
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.FundsRefunded(retryPacket, worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.expectEmit(true, true, true, true);
        emit IEscrowAdapter.BidderRetried(retryPacket, worldwideDay1, bidder1, LOCK_AMOUNT, 0);
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, retryPacket, fixInst);
    }
}
