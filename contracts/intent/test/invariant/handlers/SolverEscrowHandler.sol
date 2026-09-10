// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {SolverEscrow} from "../../../src/SolverEscrow.sol";
import {MockTheCompact} from "../../mocks/MockTheCompact.sol";

/// @dev Drives lock/unlock/slash/withdraw/forced-withdrawal against the escrow so the invariant
///      test can assert escrow custody accounting holds across arbitrary interleavings.
contract SolverEscrowHandler is Test {
    SolverEscrow internal immutable escrow;
    MockTheCompact internal immutable compact;
    ERC20 internal immutable token;
    uint256 internal immutable id;

    address[] public solvers;
    bytes32[] internal liveOrders; // orders with a currently-held lock
    uint256 internal orderNonce;

    constructor(SolverEscrow _escrow, MockTheCompact _compact, ERC20 _token) {
        escrow = _escrow;
        compact = _compact;
        token = _token;
        id = _escrow.lockId(address(_token));

        for (uint256 i = 0; i < 3; i++) {
            address s = makeAddr(string(abi.encode("invariantSolver", i)));
            solvers.push(s);
            vm.prank(s);
            compact.setOperator(address(escrow), true);
        }
    }

    function _actor(uint256 seed) internal view returns (address) {
        return solvers[seed % solvers.length];
    }

    function deposit(uint256 actorSeed, uint256 amount) external {
        address solver = _actor(actorSeed);
        amount = bound(amount, 1, 1e24);
        deal(address(token), solver, amount);
        vm.startPrank(solver);
        token.approve(address(escrow), amount);
        escrow.deposit(address(token), amount);
        vm.stopPrank();
    }

    function lock(uint256 actorSeed, uint256 amount) external {
        address solver = _actor(actorSeed);
        uint256 free = compact.balanceOf(solver, id);
        if (free == 0) return;
        amount = bound(amount, 1, free);
        bytes32 orderId = keccak256(abi.encode("invOrder", orderNonce++));
        vm.prank(address(this));
        escrow.lockCollateral(orderId, solver, address(token), amount);
        liveOrders.push(orderId);
    }

    function unlock(uint256 seed) external {
        bytes32 orderId = _takeLiveOrder(seed);
        if (orderId == bytes32(0)) return;
        vm.prank(address(this));
        escrow.unlockCollateral(orderId);
    }

    function slash(uint256 seed) external {
        bytes32 orderId = _takeLiveOrder(seed);
        if (orderId == bytes32(0)) return;
        vm.prank(address(this));
        escrow.slashCollateral(orderId);
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        address solver = _actor(actorSeed);
        uint256 free = compact.balanceOf(solver, id);
        if (free == 0) return;
        amount = bound(amount, 1, free);
        deal(address(token), address(compact), amount); // fund underlying release
        vm.prank(solver);
        escrow.withdraw(address(token), amount);
    }

    function forcedWithdraw(uint256 actorSeed, uint256 amount) external {
        address solver = _actor(actorSeed);
        uint256 free = compact.balanceOf(solver, id);
        if (free == 0) return;
        amount = bound(amount, 1, free);
        deal(address(token), address(compact), amount);
        vm.startPrank(solver);
        compact.enableForcedWithdrawal(id);
        compact.forcedWithdrawal(id, solver, amount);
        vm.stopPrank();
    }

    /// @dev Removes and returns a live order by seed (swap-and-pop); zero if none remain.
    function _takeLiveOrder(uint256 seed) internal returns (bytes32) {
        if (liveOrders.length == 0) return bytes32(0);
        uint256 i = seed % liveOrders.length;
        bytes32 orderId = liveOrders[i];
        liveOrders[i] = liveOrders[liveOrders.length - 1];
        liveOrders.pop();
        return orderId;
    }

    function tokenId() external view returns (uint256) {
        return id;
    }

    function solverCount() external view returns (uint256) {
        return solvers.length;
    }
}
