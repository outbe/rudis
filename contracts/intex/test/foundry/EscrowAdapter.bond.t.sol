// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockERC20} from "@test-mocks/MockERC20.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev Commit-bond custody: lock/release under AUCTION_ROLE, the escrow-local
///      abandoned-bond safety valve, and the shared-lockId accounting with bid escrow.
contract EscrowAdapterBondTest is Test {
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address auction = address(3);
    address bidder1 = address(5);
    address outsider = address(7);

    uint32 worldwideDay1 = 1;

    uint128 constant BOND_AMOUNT = 100e18;

    /// @dev Live ERC6909 balance held by the escrow in The Compact for the active lockId.
    function _liveCompactBalance() internal view returns (uint256) {
        return IERC6909(address(compact)).balanceOf(address(escrow), escrow.lockId());
    }

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
        compact.setResetPeriodSeconds(0);

        paymentToken.mint(bidder1, 1000e18);
        vm.prank(bidder1);
        paymentToken.approve(address(escrow), type(uint256).max);
    }

    function _lockBond() internal {
        vm.prank(auction);
        escrow.lockCommitBond(worldwideDay1, bidder1, BOND_AMOUNT);
    }

    // --- lockCommitBond ---

    function test_LockCommitBond() public {
        uint256 balanceBefore = paymentToken.balanceOf(bidder1);

        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.CommitBondLocked(worldwideDay1, bidder1, BOND_AMOUNT);
        _lockBond();

        IEscrowAdapter.CommitBond memory bond = escrow.getCommitBond(worldwideDay1, bidder1);
        assertEq(bond.amount, BOND_AMOUNT, "bond amount");
        assertEq(bond.lockedAt, uint32(block.timestamp), "bond lockedAt");
        assertEq(paymentToken.balanceOf(bidder1), balanceBefore - BOND_AMOUNT, "bidder debited");
        assertEq(_liveCompactBalance(), BOND_AMOUNT, "bond held in The Compact");
    }

    function test_LockCommitBond_RevertsOnZeroInputs() public {
        vm.startPrank(auction);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroValue.selector, "worldwideDay"));
        escrow.lockCommitBond(0, bidder1, BOND_AMOUNT);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroAddress.selector, "bidder"));
        escrow.lockCommitBond(worldwideDay1, address(0), BOND_AMOUNT);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.ZeroValue.selector, "amount"));
        escrow.lockCommitBond(worldwideDay1, bidder1, 0);
        vm.stopPrank();
    }

    function test_LockCommitBond_RevertsOnDoubleLock() public {
        _lockBond();
        vm.prank(auction);
        vm.expectRevert(IEscrowAdapter.CommitBondAlreadyLocked.selector);
        escrow.lockCommitBond(worldwideDay1, bidder1, BOND_AMOUNT);
    }

    function test_LockCommitBond_OnlyAuctionRole() public {
        vm.prank(outsider);
        vm.expectRevert();
        escrow.lockCommitBond(worldwideDay1, bidder1, BOND_AMOUNT);
    }

    // --- releaseCommitBond ---

    function test_ReleaseCommitBond() public {
        _lockBond();
        uint256 balanceBefore = paymentToken.balanceOf(bidder1);

        vm.expectEmit(true, true, false, true);
        emit IEscrowAdapter.CommitBondReleased(worldwideDay1, bidder1, BOND_AMOUNT);
        vm.prank(auction);
        escrow.releaseCommitBond(worldwideDay1, bidder1);

        assertEq(escrow.getCommitBond(worldwideDay1, bidder1).amount, 0, "bond deleted");
        assertEq(paymentToken.balanceOf(bidder1), balanceBefore + BOND_AMOUNT, "bidder repaid");
        assertEq(_liveCompactBalance(), 0, "Compact drained");
    }

    function test_ReleaseCommitBond_RevertsWhenMissing() public {
        vm.prank(auction);
        vm.expectRevert(IEscrowAdapter.CommitBondNotFound.selector);
        escrow.releaseCommitBond(worldwideDay1, bidder1);
    }

    function test_ReleaseCommitBond_OnlyAuctionRole() public {
        _lockBond();
        vm.prank(outsider);
        vm.expectRevert();
        escrow.releaseCommitBond(worldwideDay1, bidder1);
    }

    /// @dev commit -> cancel -> commit again within the same series must re-lock cleanly.
    function test_RelockAfterRelease() public {
        _lockBond();
        vm.prank(auction);
        escrow.releaseCommitBond(worldwideDay1, bidder1);

        _lockBond();
        assertEq(escrow.getCommitBond(worldwideDay1, bidder1).amount, BOND_AMOUNT, "re-locked");
    }

    // --- claimAbandonedCommitBond ---

    function test_ClaimAbandonedCommitBond_RevertsBeforeWindow() public {
        _lockBond();
        uint32 claimableAt = uint32(block.timestamp) + escrow.COMMIT_BOND_ABANDON_DELAY();

        vm.warp(claimableAt - 1);
        vm.prank(outsider);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrowAdapter.CommitBondNotYetAbandoned.selector, claimableAt, claimableAt - 1)
        );
        escrow.claimAbandonedCommitBond(worldwideDay1, bidder1);
    }

    function test_ClaimAbandonedCommitBond_RevertsWhenMissing() public {
        vm.expectRevert(IEscrowAdapter.CommitBondNotFound.selector);
        escrow.claimAbandonedCommitBond(worldwideDay1, bidder1);
    }

    /// @dev Permissionless and pays the stored bidder, never the caller.
    function test_ClaimAbandonedCommitBond_PaysBidderNotCaller() public {
        _lockBond();
        uint256 bidderBefore = paymentToken.balanceOf(bidder1);
        uint256 outsiderBefore = paymentToken.balanceOf(outsider);

        vm.warp(block.timestamp + escrow.COMMIT_BOND_ABANDON_DELAY());
        vm.prank(outsider);
        escrow.claimAbandonedCommitBond(worldwideDay1, bidder1);

        assertEq(paymentToken.balanceOf(bidder1), bidderBefore + BOND_AMOUNT, "bidder repaid");
        assertEq(paymentToken.balanceOf(outsider), outsiderBefore, "caller gets nothing");
        assertEq(escrow.getCommitBond(worldwideDay1, bidder1).amount, 0, "bond deleted");

        // Terminal: a second claim has nothing to pay.
        vm.expectRevert(IEscrowAdapter.CommitBondNotFound.selector);
        escrow.claimAbandonedCommitBond(worldwideDay1, bidder1);
    }

    /// @dev The valve is auction-independent by design: a bond locked before the auction
    ///      contract is rotated away stays recoverable straight from the escrow.
    function test_ClaimAbandonedCommitBond_SurvivesAuctionRotation() public {
        _lockBond();

        // Rotate the auction wiring (same compact/token, so no LiveLocksOutstanding guard).
        address newAuction = address(0xA0C71012);
        vm.prank(admin);
        escrow.wire(newAuction, address(compact), address(paymentToken));

        // The old auction lost AUCTION_ROLE; the new one has no knowledge of the bond.
        vm.prank(auction);
        vm.expectRevert();
        escrow.releaseCommitBond(worldwideDay1, bidder1);

        vm.warp(block.timestamp + escrow.COMMIT_BOND_ABANDON_DELAY());
        vm.prank(outsider);
        escrow.claimAbandonedCommitBond(worldwideDay1, bidder1);
        assertEq(paymentToken.balanceOf(bidder1), 1000e18, "full principal recovered");
    }

    /// @dev Any bond amount round-trips lock -> release without residue in The Compact.
    function testFuzz_LockRelease_RoundTrips(uint128 amount) public {
        amount = uint128(bound(amount, 1, 1000e18));

        vm.prank(auction);
        escrow.lockCommitBond(worldwideDay1, bidder1, amount);
        assertEq(_liveCompactBalance(), amount, "custodied");

        vm.prank(auction);
        escrow.releaseCommitBond(worldwideDay1, bidder1);
        assertEq(_liveCompactBalance(), 0, "no residue");
        assertEq(paymentToken.balanceOf(bidder1), 1000e18, "principal intact");
    }

    // --- shared-lockId accounting ---

    /// @dev A live bond alone must register as an outstanding lock, so the wire() rotation
    ///      guard on paymentToken/compact covers bonds without extra bookkeeping.
    function test_HasOutstandingLocks_CoversBonds() public {
        assertFalse(escrow.hasOutstandingLocks(), "clean slate");
        _lockBond();
        assertTrue(escrow.hasOutstandingLocks(), "bond counts as outstanding");

        address otherToken = address(new MockERC20("X", "X", 18));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.LiveLocksOutstanding.selector, BOND_AMOUNT));
        escrow.wire(auction, address(compact), otherToken);

        vm.prank(auction);
        escrow.releaseCommitBond(worldwideDay1, bidder1);
        assertFalse(escrow.hasOutstandingLocks(), "released bond clears the guard");
    }
}
