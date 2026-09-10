// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";
import {Scope} from "the-compact/src/types/Scope.sol";

import {MockERC20} from "../mocks/MockERC20.sol";
import {MockTheCompact} from "../mocks/MockTheCompact.sol";
import {SolverAllocator} from "../../src/allocators/SolverAllocator.sol";
import {SolverEscrow} from "../../src/SolverEscrow.sol";
import {SolverEscrowHandler} from "./handlers/SolverEscrowHandler.sol";

/// @title SolverEscrowInvariant
/// @notice Custody accounting: the escrow's ERC6909 balance is exactly the collateral it holds --
///         the live locks attributed to solvers plus the slashed pool.
contract SolverEscrowInvariant is Test {
    MockTheCompact internal compact;
    ERC20 internal token;
    SolverEscrow internal escrow;
    SolverEscrowHandler internal handler;

    function setUp() public {
        token = new MockERC20("Test Token", "TT");
        compact = new MockTheCompact();
        SolverAllocator allocator = new SolverAllocator(address(compact));
        bytes12 lockTag = allocator.buildLockTag(Scope.ChainSpecific, ResetPeriod.TenMinutes);
        escrow = new SolverEscrow(address(compact), lockTag, 1000);
        allocator.setArbiter(address(escrow));

        handler = new SolverEscrowHandler(escrow, compact, token);
        escrow.setAuthorizedCaller(address(handler));

        targetContract(address(handler));
    }

    /// @dev balanceOf(escrow, id) == sum_solver totalLocked(solver, id) + slashedPool(id).
    function invariant_escrowBalanceEqualsLockedPlusPool() public view {
        uint256 id = handler.tokenId();

        uint256 lockedSum;
        uint256 count = handler.solverCount();
        for (uint256 i = 0; i < count; i++) {
            lockedSum += escrow.totalLocked(handler.solvers(i), id);
        }

        assertEq(
            compact.balanceOf(address(escrow), id),
            lockedSum + escrow.slashedPool(id),
            "escrow balance must equal live locks plus slashed pool"
        );
    }
}
