// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev Burn-instead-of-vault recovery paths: an undistributable winning portion (the series was
///      already routed on Outbe) is sent to the canonical dead address, terminally and in a
///      single transaction - no parked state, no vault dependency.
contract EscrowAdapterBurnTest is Test {
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address auction = address(3);
    address bidder1 = address(5);
    address outsider = address(7);
    address proceedsRecipient = address(8);

    uint32 worldwideDay1 = 1;
    uint128 constant LOCK_AMOUNT = 1000 * 10 ** 6;
    bytes32 constant RECEIVE_ID = bytes32(uint256(0xDEADBEEF));

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
        vm.prank(admin);
        escrow.setProceedsRecipient(proceedsRecipient);
        compact.setResetPeriodSeconds(0);

        paymentToken.mint(bidder1, 10_000 * 10 ** 6);
        vm.prank(bidder1);
        paymentToken.approve(address(escrow), type(uint256).max);
    }

    function _liveCompactBalance() internal view returns (uint256) {
        return IERC6909(address(compact)).balanceOf(address(escrow), escrow.lockId());
    }

    /// @dev Strand bidder1 at finalize with a valid refund/paid split recorded.
    function _strandWithSplit(uint128 refundPortion, uint128 paidPortion) internal {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        compact.setForcedWithdrawalShouldFail(true);
        IEscrowAdapter.FinalizationInstruction[] memory instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidder1, refundedAmount: refundPortion, paidAmount: paidPortion
        });
        vm.prank(bridger);
        escrow.finalizeAuction(worldwideDay1, RECEIVE_ID, instructions, true);
        compact.setForcedWithdrawalShouldFail(false);
    }

    function test_RetryFinalize_BurnsResidual() public {
        _strandWithSplit(0, LOCK_AMOUNT);

        IEscrowAdapter.FinalizationInstruction memory inst =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder1, refundedAmount: 0, paidAmount: LOCK_AMOUNT});

        vm.expectEmit(true, true, false, true, address(escrow));
        emit IEscrowAdapter.ProceedsBurned(worldwideDay1, bidder1, LOCK_AMOUNT);
        vm.prank(bridger);
        escrow.retryFinalize(worldwideDay1, RECEIVE_ID, inst);

        assertEq(paymentToken.balanceOf(escrow.BURN_ADDRESS()), LOCK_AMOUNT, "residual burned");
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Finalized));
        assertEq(_liveCompactBalance(), 0, "Compact drained");
    }

    function test_ClaimRefund_PostFinalize_RefundsBidderAndBurnsRemainder_OneTx() public {
        uint128 refundPortion = LOCK_AMOUNT * 30 / 100;
        uint128 paidPortion = LOCK_AMOUNT - refundPortion;
        _strandWithSplit(refundPortion, paidPortion);

        uint256 balanceBefore = paymentToken.balanceOf(bidder1);
        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY());

        vm.expectEmit(true, true, true, true, address(escrow));
        emit IEscrowAdapter.FundsRefunded(bytes32(0), worldwideDay1, bidder1, refundPortion);
        vm.expectEmit(true, true, false, true, address(escrow));
        emit IEscrowAdapter.ProceedsBurned(worldwideDay1, bidder1, paidPortion);
        vm.prank(outsider);
        escrow.claimRefund(worldwideDay1, bidder1);

        // Terminal in one transaction: bidder paid exactly the validated portion, remainder burned,
        // nothing left parked in the escrow accounting or The Compact.
        assertEq(paymentToken.balanceOf(bidder1), balanceBefore + refundPortion, "bidder refunded");
        assertEq(paymentToken.balanceOf(escrow.BURN_ADDRESS()), paidPortion, "remainder burned");
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Finalized));
        (,, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay1);
        assertEq(totalLocked, 0, "no parked state survives");
        assertEq(_liveCompactBalance(), 0, "Compact drained");
    }

    function test_ClaimRefund_PostFinalize_FullRefundSplit_BurnsNothing() public {
        _strandWithSplit(LOCK_AMOUNT, 0);
        uint256 balanceBefore = paymentToken.balanceOf(bidder1);

        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY());
        escrow.claimRefund(worldwideDay1, bidder1);

        assertEq(paymentToken.balanceOf(bidder1), balanceBefore + LOCK_AMOUNT, "full principal refunded");
        assertEq(paymentToken.balanceOf(escrow.BURN_ADDRESS()), 0, "nothing to burn");
        assertEq(uint8(escrow.getBidLock(worldwideDay1, bidder1).status), uint8(IEscrowAdapter.LockStatus.Finalized));
    }

    /// @dev Token conservation with the dead address as a sink: every minted token is either with
    ///      the bidder, the proceeds recipient, pooled in The Compact, or burned.
    function test_Conservation_BurnAddressIsTheOnlySink() public {
        uint256 minted = paymentToken.balanceOf(bidder1);
        uint128 refundPortion = LOCK_AMOUNT / 4;
        uint128 paidPortion = LOCK_AMOUNT - refundPortion;
        _strandWithSplit(refundPortion, paidPortion);

        vm.warp(block.timestamp + escrow.POST_FINALIZE_REFUND_DELAY());
        escrow.claimRefund(worldwideDay1, bidder1);

        uint256 sum = paymentToken.balanceOf(bidder1) + paymentToken.balanceOf(proceedsRecipient)
            + paymentToken.balanceOf(address(escrow)) + paymentToken.balanceOf(address(compact))
            + paymentToken.balanceOf(escrow.BURN_ADDRESS());
        assertEq(sum, minted, "conservation across bidder + recipient + escrow + Compact + burn sink");
    }
}
