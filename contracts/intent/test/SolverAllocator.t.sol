// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {IAllocator} from "the-compact/src/interfaces/IAllocator.sol";

import {SolverAllocator} from "../src/allocators/SolverAllocator.sol";

import {MockTheCompact} from "./mocks/MockTheCompact.sol";

contract SolverAllocatorTest is Test {
    MockTheCompact internal compact;
    SolverAllocator internal allocator;

    address internal owner;
    address internal arbiterAddr;
    address internal solver;

    event ArbiterSet(address indexed arbiter);

    function setUp() public {
        owner = address(this); // deployer = test contract
        arbiterAddr = makeAddr("arbiter");
        solver = makeAddr("solver");

        compact = new MockTheCompact();
        allocator = new SolverAllocator(address(compact));
    }

    // ============ constructor ============

    function test_constructor_setsState() public view {
        assertEq(address(allocator.COMPACT()), address(compact));
        assertGt(uint256(allocator.ALLOCATOR_ID()), 0, "allocatorId > 0");
        assertEq(allocator.OWNER(), owner);
        assertEq(allocator.arbiter(), address(0), "arbiter starts unset");
    }

    // ============ setArbiter ============

    function test_setArbiter_works() public {
        vm.expectEmit(true, false, false, false);
        emit ArbiterSet(arbiterAddr);

        allocator.setArbiter(arbiterAddr);

        assertEq(allocator.arbiter(), arbiterAddr);
    }

    function test_setArbiter_onlyOwner_reverts() public {
        vm.prank(solver);
        vm.expectRevert(SolverAllocator.UnauthorizedOwner.selector);
        allocator.setArbiter(arbiterAddr);
    }

    function test_setArbiter_alreadySet_reverts() public {
        allocator.setArbiter(arbiterAddr);

        vm.expectRevert(SolverAllocator.ArbiterAlreadySet.selector);
        allocator.setArbiter(makeAddr("other"));
    }

    // ============ attest ============

    function test_attest_blocked() public {
        vm.expectRevert(SolverAllocator.DirectTransferBlocked.selector);
        allocator.attest(solver, solver, address(1), 0, 100);
    }

    function test_attest_thirdParty_blocked() public {
        address operator = makeAddr("operator");
        vm.expectRevert(SolverAllocator.DirectTransferBlocked.selector);
        allocator.attest(operator, solver, address(1), 0, 100);
    }

    // ============ authorizeClaim ============

    function test_authorizeClaim_arbiter_works() public {
        allocator.setArbiter(arbiterAddr);

        uint256[2][] memory idsAndAmounts = new uint256[2][](0);

        bytes4 result =
            allocator.authorizeClaim(bytes32(0), arbiterAddr, solver, 0, type(uint256).max, idsAndAmounts, "");
        assertEq(result, IAllocator.authorizeClaim.selector);
    }

    function test_authorizeClaim_selfWithdraw_blocked() public {
        allocator.setArbiter(arbiterAddr);

        uint256[2][] memory idsAndAmounts = new uint256[2][](0);

        // claimArbiter == sponsor (self-withdrawal) - now blocked
        vm.expectRevert(SolverAllocator.UnauthorizedArbiter.selector);
        allocator.authorizeClaim(bytes32(0), solver, solver, 0, type(uint256).max, idsAndAmounts, "");
    }

    function test_authorizeClaim_unauthorized_reverts() public {
        allocator.setArbiter(arbiterAddr);

        address randomArbiter = makeAddr("random");
        uint256[2][] memory idsAndAmounts = new uint256[2][](0);

        vm.expectRevert(SolverAllocator.UnauthorizedArbiter.selector);
        allocator.authorizeClaim(bytes32(0), randomArbiter, solver, 0, type(uint256).max, idsAndAmounts, "");
    }
}
