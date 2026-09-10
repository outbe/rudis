// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev Property test for the per-series escrow invariant:
///   sum bidLocks[worldwideDay][bidder].lockedAmount, status == Locked
///     == auctionEscrowState[worldwideDay].totalLocked
/// Holds across every state transition (lock, finalize, emergency refund).
contract EscrowAdapterInvariantsTest is Test {
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address auction = address(3);
    address bidderA = address(5);
    address bidderB = address(6);
    address bidderC = address(7);

    uint32 s1 = 1;
    uint32 s2 = 2;

    uint128 constant LOCK_A = 100 * 10 ** 6;
    uint128 constant LOCK_B = 250 * 10 ** 6;
    uint128 constant LOCK_C = 75 * 10 ** 6;

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
        vm.prank(admin);
        escrow.setProceedsRecipient(bridger);
        compact.setResetPeriodSeconds(0);

        address[3] memory bidders = [bidderA, bidderB, bidderC];
        for (uint256 i = 0; i < bidders.length; i++) {
            paymentToken.mint(bidders[i], 10_000 * 10 ** 6);
            vm.prank(bidders[i]);
            paymentToken.approve(address(escrow), type(uint256).max);
        }
    }

    function _assertSeriesInvariant(uint32 worldwideDay, address[3] memory bidders) internal view {
        uint128 sum = 0;
        for (uint256 i = 0; i < bidders.length; i++) {
            IEscrowAdapter.BidLock memory lock = escrow.getBidLock(worldwideDay, bidders[i]);
            if (lock.status == IEscrowAdapter.LockStatus.Locked) {
                sum += lock.lockedAmount;
            }
        }
        (,, uint128 totalLocked) = escrow.getAuctionStatus(worldwideDay);
        assertEq(sum, totalLocked, "per-series totalLocked drift");
    }

    function test_Invariant_HoldsAcrossLockFinalizeAndRefund() public {
        address[3] memory bidders = [bidderA, bidderB, bidderC];

        // Empty state.
        _assertSeriesInvariant(s1, bidders);
        _assertSeriesInvariant(s2, bidders);

        // Mixed locks across two series.
        vm.prank(auction);
        escrow.lockFunds(s1, bidderA, LOCK_A);
        _assertSeriesInvariant(s1, bidders);

        vm.prank(auction);
        escrow.lockFunds(s1, bidderB, LOCK_B);
        _assertSeriesInvariant(s1, bidders);

        vm.prank(auction);
        escrow.lockFunds(s2, bidderC, LOCK_C);
        _assertSeriesInvariant(s1, bidders);
        _assertSeriesInvariant(s2, bidders);

        // Permissionless refund of one lock on s1 after the 72h safety window.
        vm.warp(block.timestamp + escrow.UNFINALIZED_REFUND_DELAY());
        escrow.claimRefund(s1, bidderA);
        _assertSeriesInvariant(s1, bidders);
        _assertSeriesInvariant(s2, bidders);

        // Finalize the remaining s1 lock with a partial split.
        IEscrowAdapter.FinalizationInstruction[] memory s1Instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        s1Instructions[0] = IEscrowAdapter.FinalizationInstruction({
            bidder: bidderB, refundedAmount: LOCK_B / 2, paidAmount: LOCK_B - LOCK_B / 2
        });
        vm.prank(bridger);
        escrow.finalizeAuction(s1, bytes32(uint256(0x5151)), s1Instructions, true);
        _assertSeriesInvariant(s1, bidders);
        _assertSeriesInvariant(s2, bidders);

        // Finalize s2 with a full claim.
        IEscrowAdapter.FinalizationInstruction[] memory s2Instructions = new IEscrowAdapter.FinalizationInstruction[](1);
        s2Instructions[0] =
            IEscrowAdapter.FinalizationInstruction({bidder: bidderC, refundedAmount: 0, paidAmount: LOCK_C});
        vm.prank(bridger);
        escrow.finalizeAuction(s2, bytes32(uint256(0x5252)), s2Instructions, true);
        _assertSeriesInvariant(s1, bidders);
        _assertSeriesInvariant(s2, bidders);
    }

    /// @dev Sanity check that the invariant helper catches injected drift.
    function test_Invariant_CatchesInjectedDrift() public {
        address[3] memory bidders = [bidderA, bidderB, bidderC];

        vm.prank(auction);
        escrow.lockFunds(s1, bidderA, LOCK_A);

        // auctionEscrowState mapping slot lookup: keccak256(abi.encode(s1, baseSlot)).
        // We bump `totalLocked` (low 8 bytes of the packed slot) without touching bidLocks
        // to confirm the helper fires when the two sides diverge.
        bytes32 baseSlot = bytes32(_auctionEscrowStateSlot());
        bytes32 entrySlot = keccak256(abi.encode(uint256(s1), uint256(baseSlot)));
        bytes32 packed = vm.load(address(escrow), entrySlot);
        // Add 1 to the uint128 totalLocked field (low 64 bits).
        bytes32 corrupted = bytes32(uint256(packed) + 1);
        vm.store(address(escrow), entrySlot, corrupted);

        vm.expectRevert();
        this._externalAssertInvariant(s1, bidders);
    }

    function _externalAssertInvariant(uint32 worldwideDay, address[3] memory bidders) external view {
        _assertSeriesInvariant(worldwideDay, bidders);
    }

    /// @dev Storage slot of the `auctionEscrowState` mapping inside the contract's ERC-7201
    /// namespaced struct (`erc7201:outbe.intex.EscrowAdapter`). Field offset 6: four address/uint
    /// slots, the packed allocatorId+lockTag slot, then the bidLocks mapping precede it.
    function _auctionEscrowStateSlot() internal pure returns (uint256) {
        uint256 base = uint256(
            keccak256(abi.encode(uint256(keccak256("outbe.intex.EscrowAdapter")) - 1)) & ~bytes32(uint256(0xff))
        );
        return base + 6;
    }
}
