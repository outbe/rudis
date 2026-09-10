// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

contract EscrowAdapterOptionDTest is Test {
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address auction = address(3);
    address bidder1 = address(5);

    uint32 worldwideDay1 = 1;
    uint64 constant LOCK_AMOUNT = 1000 * 10 ** 6;

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));

        compact.setResetPeriodSeconds(0);

        paymentToken.mint(bidder1, 10000 * 10 ** 6);
        vm.prank(bidder1);
        paymentToken.approve(address(escrow), type(uint256).max);
    }

    /// @dev Rotation guard must derive `outstanding` from the live ERC6909 balance held
    ///      by the escrow in The Compact, not from a local mirror slot.
    function test_Wire_Rotation_RevertsOnLiveERC6909Balance() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        uint256 liveBalance = IERC6909(address(compact)).balanceOf(address(escrow), escrow.lockId());
        assertEq(liveBalance, LOCK_AMOUNT, "precondition: ERC6909 balance equals locked amount");

        MockWCOEN rotated = new MockWCOEN();
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.LiveLocksOutstanding.selector, uint256(LOCK_AMOUNT)));
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(rotated));
    }

    /// @dev Fresh adapter (lockId == 0) must short-circuit the ERC6909 balance read in the
    ///      rotation guard. Poison the mock's balance for id == 0 so that, if the short-circuit
    ///      ever stopped firing, the rotation would revert with `LiveLocksOutstanding`.
    function test_Wire_LockIdZeroShortCircuit_SkipsERC6909Read() public {
        assertEq(escrow.lockId(), 0, "precondition: fresh adapter has lockId == 0");

        compact.setBalance(0, address(escrow), 999);

        MockWCOEN rotated = new MockWCOEN();
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(rotated));

        assertEq(address(escrow.paymentToken()), address(rotated), "rotation must succeed despite poisoned balance");
    }

    /// @dev Rotation guard must trigger when `_compact` (not `_paymentToken`) rotates while
    ///      live locks exist. Cross-checks the second branch of the `rotatingCompact` predicate.
    function test_Wire_RotateCompact_RevertsOnLiveBalance() public {
        vm.prank(auction);
        escrow.lockFunds(worldwideDay1, bidder1, LOCK_AMOUNT);

        MockTheCompact compact2 = new MockTheCompact();
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.LiveLocksOutstanding.selector, uint256(LOCK_AMOUNT)));
        vm.prank(admin);
        escrow.wire(auction, address(compact2), address(paymentToken));
    }
}
