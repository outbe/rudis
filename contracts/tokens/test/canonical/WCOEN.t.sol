// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {WCOEN} from "../../src/canonical/WCOEN.sol";

contract StorageWritingReceiver {
    uint256 public received;

    receive() external payable {
        received += msg.value;
    }
}

contract RevertingReceiver {
    receive() external payable {
        revert("nope");
    }
}

contract WCOENTest is Test {
    uint256 internal constant COEN_UNIT = 1 ether;

    WCOEN internal token;

    function test_PublicMetadataUsesRudis() public view {
        assertEq(token.name(), "Wrapped Rudis");
        assertEq(token.symbol(), "wrudis");
        assertEq(token.decimals(), 18);
    }

    function setUp() public {
        token = new WCOEN();
    }

    function test_Metadata_UsesEighteenDecimals() public view {
        assertEq(token.decimals(), 18);
    }

    function test_DepositAndWithdraw_UpdateSupply() public {
        address alice = makeAddr("alice");

        vm.deal(alice, 2 * COEN_UNIT);
        vm.prank(alice);
        token.deposit{value: 2 * COEN_UNIT}();

        assertEq(token.balanceOf(alice), 2 * COEN_UNIT);
        assertEq(token.totalSupply(), 2 * COEN_UNIT);
        assertEq(address(token).balance, 2 * COEN_UNIT);

        vm.prank(alice);
        token.withdraw(COEN_UNIT);

        assertEq(token.balanceOf(alice), COEN_UNIT);
        assertEq(token.totalSupply(), COEN_UNIT);
        assertEq(address(token).balance, COEN_UNIT);
    }

    function test_Receive_DepositsNativeCoin() public {
        address alice = makeAddr("alice");

        vm.deal(alice, COEN_UNIT);
        vm.prank(alice);
        (bool success,) = address(token).call{value: COEN_UNIT}("");

        assertTrue(success);
        assertEq(token.balanceOf(alice), COEN_UNIT);
        assertEq(token.totalSupply(), COEN_UNIT);
        assertEq(address(token).balance, COEN_UNIT);
    }

    function testFuzz_DepositAndWithdraw_RestoresSupply(address account, uint256 amount) public {
        vm.assume(account != address(0));
        vm.assume(account != address(token));
        vm.assume(uint160(account) > 0xffff);
        vm.assume(account.code.length == 0);
        vm.assume(amount <= type(uint128).max);

        vm.deal(account, amount);
        vm.startPrank(account);
        token.deposit{value: amount}();
        token.withdraw(amount);
        vm.stopPrank();

        assertEq(token.balanceOf(account), 0);
        assertEq(token.totalSupply(), 0);
        assertEq(address(token).balance, 0);
    }

    function test_Withdraw_SucceedsForContractRecipient() public {
        StorageWritingReceiver recipient = new StorageWritingReceiver();

        vm.deal(address(recipient), COEN_UNIT);
        vm.prank(address(recipient));
        token.deposit{value: COEN_UNIT}();

        vm.prank(address(recipient));
        token.withdraw(COEN_UNIT);

        assertEq(recipient.received(), COEN_UNIT);
        assertEq(token.balanceOf(address(recipient)), 0);
    }

    function test_RevertWhen_WithdrawSendFails() public {
        RevertingReceiver recipient = new RevertingReceiver();

        vm.deal(address(recipient), COEN_UNIT);
        vm.prank(address(recipient));
        token.deposit{value: COEN_UNIT}();

        vm.prank(address(recipient));
        vm.expectRevert(abi.encodeWithSelector(WCOEN.NativeTransferFailed.selector, address(recipient), COEN_UNIT));
        token.withdraw(COEN_UNIT);
    }

    function test_IncreaseDecreaseAllowance() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        vm.startPrank(alice);
        token.approve(bob, 100);
        token.increaseAllowance(bob, 50);
        assertEq(token.allowance(alice, bob), 150);

        token.decreaseAllowance(bob, 30);
        assertEq(token.allowance(alice, bob), 120);
        vm.stopPrank();
    }

    function test_RevertWhen_DecreaseAllowanceBelowZero() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        vm.startPrank(alice);
        token.approve(bob, 10);
        vm.expectRevert();
        token.decreaseAllowance(bob, 20);
        vm.stopPrank();
    }
}
