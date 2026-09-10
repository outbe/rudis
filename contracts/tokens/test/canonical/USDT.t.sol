// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {USDT} from "../../src/canonical/USDT.sol";

contract USDTTest is Test {
    USDT internal token;

    function setUp() public {
        token = new USDT();
    }

    function test_Decimals_IsSix() public view {
        assertEq(token.decimals(), 6);
    }

    function test_Mint_IncreasesBalance() public {
        address alice = makeAddr("alice");
        token.mint(alice, 1_000_000);
        assertEq(token.balanceOf(alice), 1_000_000);
    }

    function testFuzz_Mint_IncreasesSupply(address recipient, uint256 amount) public {
        vm.assume(recipient != address(0));
        vm.assume(amount <= type(uint128).max);

        uint256 supplyBefore = token.totalSupply();
        token.mint(recipient, amount);

        assertEq(token.totalSupply(), supplyBefore + amount);
        assertEq(token.balanceOf(recipient), amount);
    }
}
