// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";
import {Scope} from "the-compact/src/types/Scope.sol";

import {SolverAllocator} from "../src/allocators/SolverAllocator.sol";
import {ISolverEscrow} from "../src/interfaces/ISolverEscrow.sol";
import {SolverEscrow} from "../src/SolverEscrow.sol";

import {MockTheCompact} from "./mocks/MockTheCompact.sol";

contract SolverEscrowTest is Test {
    ERC20 internal token;
    MockTheCompact internal compact;
    SolverAllocator internal allocator;
    SolverEscrow internal escrow;

    address internal solver;
    address internal authorizedCaller;
    bytes12 internal lockTag;
    uint256 internal constant COLLATERAL_BPS = 1000; // 10%

    event Deposited(address indexed solver, address indexed token, uint256 amount);
    event Withdrawn(address indexed solver, address indexed token, uint256 amount);
    event CollateralSlashed(bytes32 indexed orderId, address indexed solver, address token, uint256 amount);
    event CollateralBpsUpdated(uint256 oldBps, uint256 newBps);
    event RewardDistributed(address indexed receiver, address indexed token, uint256 amount);

    function setUp() public {
        solver = makeAddr("solver");
        authorizedCaller = makeAddr("authorizedCaller");
        token = new MockERC20("Test Token", "TT");

        // Deploy stack: Compact -> Allocator -> Escrow -> wire arbiter
        compact = new MockTheCompact();
        allocator = new SolverAllocator(address(compact));
        lockTag = allocator.buildLockTag(Scope.ChainSpecific, ResetPeriod.TenMinutes);
        escrow = new SolverEscrow(address(compact), lockTag, COLLATERAL_BPS);
        escrow.setAuthorizedCaller(authorizedCaller);
        allocator.setArbiter(address(escrow));

        // Solver approves escrow as ERC6909 operator (required for transferFrom)
        vm.prank(solver);
        compact.setOperator(address(escrow), true);

        // Fund solver
        deal(address(token), solver, 1_000_000);
        deal(solver, 1_000_000);
    }

    // ============ deposit ERC20 ============

    function test_deposit_ERC20_works() public {
        uint256 amount = 500;

        vm.startPrank(solver);
        token.approve(address(escrow), amount);

        vm.expectEmit(true, true, false, true);
        emit Deposited(solver, address(token), amount);

        escrow.deposit(address(token), amount);
        vm.stopPrank();

        uint256 id = escrow.lockId(address(token));
        assertEq(compact.balanceOf(solver, id), amount, "ERC6909 balance should match deposit");
    }

    function test_deposit_ERC20_multipleDeposits() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 1000);

        vm.expectEmit(true, true, false, true);
        emit Deposited(solver, address(token), 300);
        escrow.deposit(address(token), 300);

        vm.expectEmit(true, true, false, true);
        emit Deposited(solver, address(token), 200);
        escrow.deposit(address(token), 200);

        vm.stopPrank();

        uint256 id = escrow.lockId(address(token));
        assertEq(compact.balanceOf(solver, id), 500, "cumulative ERC6909 balance");
    }

    function test_deposit_ERC20_zeroAmount_reverts() public {
        vm.prank(solver);
        vm.expectRevert(SolverEscrow.InvalidAmount.selector);
        escrow.deposit(address(token), 0);
    }

    function test_deposit_withoutOperator_reverts() public {
        address noOperatorSolver = makeAddr("noOperatorSolver");
        deal(address(token), noOperatorSolver, 1000);

        vm.prank(noOperatorSolver);
        vm.expectRevert(SolverEscrow.OperatorNotApproved.selector);
        escrow.deposit(address(token), 100);
    }

    // ============ deposit native ============

    function test_deposit_native_works() public {
        uint256 amount = 1000;

        vm.startPrank(solver);

        vm.expectEmit(true, true, false, true);
        emit Deposited(solver, address(0), amount);

        escrow.deposit{value: amount}(address(0), 0);
        vm.stopPrank();

        uint256 id = escrow.lockId(address(0));
        assertEq(compact.balanceOf(solver, id), amount, "ERC6909 native balance");
    }

    function test_deposit_native_zeroValue_reverts() public {
        vm.prank(solver);
        vm.expectRevert(SolverEscrow.InvalidAmount.selector);
        escrow.deposit{value: 0}(address(0), 0);
    }

    // ============ depositFor ============

    function test_depositFor_creditsSolverAndChargesPayer() public {
        address payer = makeAddr("payer");
        deal(address(token), payer, 1000);
        uint256 amount = 500;

        vm.startPrank(payer);
        token.approve(address(escrow), amount);

        vm.expectEmit(true, true, false, true);
        emit Deposited(solver, address(token), amount);

        escrow.depositFor(solver, address(token), amount);
        vm.stopPrank();

        uint256 id = escrow.lockId(address(token));
        assertEq(compact.balanceOf(solver, id), amount, "collateral must be credited to the solver");
        assertEq(compact.balanceOf(payer, id), 0, "payer must not receive collateral");
        assertEq(token.balanceOf(payer), 500, "payer funds the deposit");
    }

    /// @dev Operator approval must come from the recipient, not the payer: the escrow moves the
    ///      solver's ERC6909 on lock/withdraw, so crediting a solver without it would strand it.
    function test_depositFor_recipientWithoutOperator_reverts() public {
        address payer = solver; // payer has operator set, recipient does not
        address newSolver = makeAddr("newSolver");

        vm.startPrank(payer);
        token.approve(address(escrow), 100);
        vm.expectRevert(SolverEscrow.OperatorNotApproved.selector);
        escrow.depositFor(newSolver, address(token), 100);
        vm.stopPrank();
    }

    function test_depositFor_zeroSolver_reverts() public {
        vm.prank(solver);
        vm.expectRevert(SolverEscrow.ZeroAddress.selector);
        escrow.depositFor(address(0), address(token), 100);
    }

    // ============ withdraw ERC20 ============

    function test_withdraw_ERC20_works() public {
        uint256 amount = 500;

        vm.startPrank(solver);
        token.approve(address(escrow), amount);
        escrow.deposit(address(token), amount);

        uint256 balanceBefore = token.balanceOf(solver);

        vm.expectEmit(true, true, false, true);
        emit Withdrawn(solver, address(token), amount);

        escrow.withdraw(address(token), amount);
        vm.stopPrank();

        assertEq(token.balanceOf(solver) - balanceBefore, amount, "tokens returned to solver");
        assertEq(compact.balanceOf(solver, escrow.lockId(address(token))), 0, "ERC6909 burned");
    }

    function test_withdraw_ERC20_zeroMeansAll() public {
        uint256 amount = 500;

        vm.startPrank(solver);
        token.approve(address(escrow), amount);
        escrow.deposit(address(token), amount);

        escrow.withdraw(address(token), 0);
        vm.stopPrank();

        assertEq(compact.balanceOf(solver, escrow.lockId(address(token))), 0, "all withdrawn");
    }

    // ============ withdraw native ============

    function test_withdraw_native_works() public {
        uint256 amount = 1000;

        vm.startPrank(solver);
        escrow.deposit{value: amount}(address(0), 0);

        uint256 balanceBefore = solver.balance;

        vm.expectEmit(true, true, false, true);
        emit Withdrawn(solver, address(0), amount);

        escrow.withdraw(address(0), amount);
        vm.stopPrank();

        assertEq(solver.balance - balanceBefore, amount, "ETH returned to solver");
        assertEq(compact.balanceOf(solver, escrow.lockId(address(0))), 0, "ERC6909 burned");
    }

    // ============ withdraw insufficient ============

    function test_withdraw_insufficientBalance_reverts() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 100);
        escrow.deposit(address(token), 100);

        vm.expectRevert(ISolverEscrow.InsufficientAvailableBalance.selector);
        escrow.withdraw(address(token), 200);
        vm.stopPrank();
    }

    // ============ lockCollateral ============

    function test_lockCollateral_works() public {
        uint256 amount = 500;
        bytes32 orderId = keccak256("order1");

        // Deposit first
        vm.startPrank(solver);
        token.approve(address(escrow), amount);
        escrow.deposit(address(token), amount);
        vm.stopPrank();

        // Lock
        vm.prank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);

        // Check state
        (address lockSolver, address lockToken, uint256 lockAmount) = escrow.locks(orderId);
        assertEq(lockSolver, solver);
        assertEq(lockToken, address(token));
        assertEq(lockAmount, 100);

        uint256 id = escrow.lockId(address(token));
        assertEq(escrow.totalLocked(solver, id), 100);
    }

    function test_lockCollateral_onlyAuthorizedCaller_reverts() public {
        vm.prank(solver);
        vm.expectRevert(SolverEscrow.UnauthorizedCaller.selector);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 100);
    }

    function test_lockCollateral_insufficientBalance_reverts() public {
        vm.prank(authorizedCaller);
        vm.expectRevert(ISolverEscrow.InsufficientAvailableBalance.selector);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 100);
    }

    function test_lockCollateral_duplicateOrder_reverts() public {
        bytes32 orderId = keccak256("order1");

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.startPrank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);

        vm.expectRevert(ISolverEscrow.LockAlreadyExists.selector);
        escrow.lockCollateral(orderId, solver, address(token), 100);
        vm.stopPrank();
    }

    // ============ unlockCollateral ============

    function test_unlockCollateral_works() public {
        bytes32 orderId = keccak256("order1");

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.startPrank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);

        escrow.unlockCollateral(orderId);
        vm.stopPrank();

        // Lock removed, totalLocked decremented
        (,, uint256 lockAmount) = escrow.locks(orderId);
        assertEq(lockAmount, 0);
        assertEq(escrow.totalLocked(solver, escrow.lockId(address(token))), 0);
    }

    function test_unlockCollateral_notFound_reverts() public {
        vm.prank(authorizedCaller);
        vm.expectRevert(ISolverEscrow.LockNotFound.selector);
        escrow.unlockCollateral(keccak256("nonexistent"));
    }

    // ============ slashCollateral ============

    function test_slashCollateral_works() public {
        bytes32 orderId = keccak256("order1");
        uint256 depositAmount = 500;
        uint256 lockAmount = 100;

        vm.startPrank(solver);
        token.approve(address(escrow), depositAmount);
        escrow.deposit(address(token), depositAmount);
        vm.stopPrank();

        vm.startPrank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), lockAmount);

        vm.expectEmit(true, true, false, true);
        emit CollateralSlashed(orderId, solver, address(token), lockAmount);
        escrow.slashCollateral(orderId);
        vm.stopPrank();

        // Lock removed, totalLocked decremented
        (,, uint256 amt) = escrow.locks(orderId);
        assertEq(amt, 0);
        assertEq(escrow.totalLocked(solver, escrow.lockId(address(token))), 0);

        // ERC6909 moved from solver to escrow
        uint256 id = escrow.lockId(address(token));
        assertEq(compact.balanceOf(solver, id), depositAmount - lockAmount, "solver balance reduced");
        assertEq(compact.balanceOf(address(escrow), id), lockAmount, "escrow received slashed ERC6909");
    }

    // ============ withdraw with locked funds ============

    function test_withdraw_lockedFunds_partialAvailable() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        // Lock 200 of 500
        vm.prank(authorizedCaller);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 200);

        // Can withdraw up to 300
        vm.startPrank(solver);
        escrow.withdraw(address(token), 300);

        // Can't withdraw more
        vm.expectRevert(ISolverEscrow.InsufficientAvailableBalance.selector);
        escrow.withdraw(address(token), 1);
        vm.stopPrank();
    }

    // ============ hasMinCollateral with locks ============

    function test_hasMinCollateral_accountsForLocked() public {
        // Deposit 100, lock 50 -> available = 50
        vm.startPrank(solver);
        token.approve(address(escrow), 100);
        escrow.deposit(address(token), 100);
        vm.stopPrank();

        vm.prank(authorizedCaller);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 50);

        // 10% of 500 = 50 -> available 50 >= 50 -> true
        assertTrue(escrow.hasMinCollateral(solver, address(token), 500));
        // 10% of 501 = 50.1 -> rounds to 50 -> true (integer division)
        assertTrue(escrow.hasMinCollateral(solver, address(token), 501));
        // 10% of 510 = 51 -> available 50 < 51 -> false
        assertFalse(escrow.hasMinCollateral(solver, address(token), 510));
    }

    function test_hasMinCollateral_sufficient() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 100);
        escrow.deposit(address(token), 100);
        vm.stopPrank();

        assertTrue(escrow.hasMinCollateral(solver, address(token), 1000), "100 >= 10% of 1000");
    }

    function test_hasMinCollateral_insufficient() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 99);
        escrow.deposit(address(token), 99);
        vm.stopPrank();

        assertFalse(escrow.hasMinCollateral(solver, address(token), 1000), "99 < 10% of 1000");
    }

    function test_hasMinCollateral_noDeposit() public view {
        assertFalse(escrow.hasMinCollateral(solver, address(token), 1000), "no deposit = 0 balance");
    }

    // ============ getBalance / getBalances ============

    function test_getBalance_works() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.prank(authorizedCaller);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 200);

        (uint256 total, uint256 locked, uint256 available) = escrow.getBalance(solver, address(token));
        assertEq(total, 500);
        assertEq(locked, 200);
        assertEq(available, 300);
    }

    function test_getBalances_works() public {
        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        address[] memory tokens = new address[](2);
        tokens[0] = address(token);
        tokens[1] = address(0);

        ISolverEscrow.BalanceInfo[] memory infos = escrow.getBalances(solver, tokens);
        assertEq(infos.length, 2);
        assertEq(infos[0].total, 500);
        assertEq(infos[0].available, 500);
        assertEq(infos[1].total, 0);
    }

    // ============ setCollateralBps ============

    function test_setCollateralBps_works() public {
        vm.expectEmit(false, false, false, true);
        emit CollateralBpsUpdated(COLLATERAL_BPS, 2000);
        escrow.setCollateralBps(2000);

        assertEq(escrow.collateralBps(), 2000);
    }

    function test_setCollateralBps_onlyOwner_reverts() public {
        vm.prank(solver);
        vm.expectRevert();
        escrow.setCollateralBps(2000);
    }

    function test_setCollateralBps_invalidBps_reverts() public {
        vm.expectRevert(SolverEscrow.InvalidBps.selector);
        escrow.setCollateralBps(10_001);
    }

    // ============ distributeReward ============

    function _slashSolver(uint256 depositAmount, uint256 lockAmount) internal returns (bytes32 orderId) {
        orderId = keccak256("slashOrder");

        vm.startPrank(solver);
        token.approve(address(escrow), depositAmount);
        escrow.deposit(address(token), depositAmount);
        vm.stopPrank();

        vm.startPrank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), lockAmount);
        escrow.slashCollateral(orderId);
        vm.stopPrank();
    }

    function test_distributeReward_works() public {
        // Slash 1000 tokens -> escrow holds 1000 ERC6909
        _slashSolver(5000, 1000);

        address receiver = makeAddr("receiver");
        uint256 orderAmountIn = 10_000;
        uint256 expectedReward = (orderAmountIn * 150) / 10_000; // 1.5% = 150

        // Fund compact so allocatedTransfer can pay out underlying
        deal(address(token), address(compact), 10_000);

        vm.prank(authorizedCaller);
        vm.expectEmit(true, true, false, true);
        emit RewardDistributed(receiver, address(token), expectedReward);
        uint256 reward = escrow.distributeReward(address(token), orderAmountIn, receiver);

        assertEq(reward, expectedReward, "reward amount");
        assertEq(token.balanceOf(receiver), expectedReward, "receiver got underlying tokens");

        // Escrow ERC6909 decreased
        uint256 id = escrow.lockId(address(token));
        assertEq(compact.balanceOf(address(escrow), id), 1000 - expectedReward, "escrow ERC6909 decreased");
    }

    function test_distributeReward_exactSlashedBalance() public {
        // Slash exactly 150 tokens -> 1.5% of 10_000 = 150 -> exact match
        _slashSolver(5000, 150);
        deal(address(token), address(compact), 10_000);

        address receiver = makeAddr("receiver");
        uint256 id = escrow.lockId(address(token));

        vm.prank(authorizedCaller);
        uint256 reward = escrow.distributeReward(address(token), 10_000, receiver);

        assertEq(reward, 150, "exact match reward");
        assertEq(compact.balanceOf(address(escrow), id), 0, "escrow fully drained");
        assertEq(token.balanceOf(receiver), 150, "receiver got reward");
    }

    // ============ custody ============

    function test_lockCollateral_movesCustodyToEscrow() public {
        uint256 id = escrow.lockId(address(token));

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.prank(authorizedCaller);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 100);

        // Collateral has left the solver's balance: nothing left there to revoke or force-withdraw.
        assertEq(compact.balanceOf(solver, id), 400, "solver keeps only the unlocked remainder");
        assertEq(compact.balanceOf(address(escrow), id), 100, "escrow custodies the locked collateral");
    }

    function test_unlockCollateral_returnsCustodyToSolver() public {
        uint256 id = escrow.lockId(address(token));
        bytes32 orderId = keccak256("order1");

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.startPrank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);
        escrow.unlockCollateral(orderId);
        vm.stopPrank();

        assertEq(compact.balanceOf(solver, id), 500, "solver balance restored in full");
        assertEq(compact.balanceOf(address(escrow), id), 0, "escrow holds nothing after unlock");
        assertEq(escrow.slashedPool(id), 0, "unlock does not credit the slashed pool");
    }

    /// @dev A slash must not depend on a grant the solver can revoke: the collateral is already
    ///      in escrow custody, so revoking the operator after the claim changes nothing.
    function test_slashCollateral_afterOperatorRevoked_succeeds() public {
        uint256 id = escrow.lockId(address(token));
        bytes32 orderId = keccak256("order1");

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.prank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);

        vm.prank(solver);
        compact.setOperator(address(escrow), false);

        vm.prank(authorizedCaller);
        vm.expectEmit(true, true, false, true);
        emit CollateralSlashed(orderId, solver, address(token), 100);
        escrow.slashCollateral(orderId);

        assertEq(escrow.slashedPool(id), 100, "slashed pool credited despite the revoked grant");
        assertEq(escrow.totalLocked(solver, id), 0, "lock consumed");
    }

    /// @dev The escrow's balance holds live locks and slashed funds on the same id. A reward must
    ///      only ever spend the slashed part, or a later unlock could not be honored.
    function test_distributeReward_doesNotConsumeLiveLock() public {
        uint256 id = escrow.lockId(address(token));
        bytes32 liveOrder = keccak256("liveOrder");

        // 150 slashed (exactly the reward for a 10_000 order) + 1000 still locked for a live order.
        _slashSolver(5000, 150);

        vm.prank(authorizedCaller);
        escrow.lockCollateral(liveOrder, solver, address(token), 1000);

        assertEq(compact.balanceOf(address(escrow), id), 1150, "escrow holds slashed + live lock");

        deal(address(token), address(compact), 10_000);
        address receiver = makeAddr("receiver");

        vm.prank(authorizedCaller);
        uint256 reward = escrow.distributeReward(address(token), 10_000, receiver);

        assertEq(reward, 150, "reward paid from the slashed pool");
        assertEq(escrow.slashedPool(id), 0, "slashed pool drained");

        // The live lock survived and can still be returned in full.
        vm.prank(authorizedCaller);
        escrow.unlockCollateral(liveOrder);
        assertEq(compact.balanceOf(solver, id), 5000 - 150, "solver got the live lock back untouched");
        assertEq(compact.balanceOf(address(escrow), id), 0, "escrow drained");
    }

    /// @dev A second reward exceeding the slashed pool must pay nothing rather than dip into a lock.
    function test_distributeReward_insufficientPool_paysNothing() public {
        uint256 id = escrow.lockId(address(token));

        _slashSolver(5000, 100);

        vm.prank(authorizedCaller);
        escrow.lockCollateral(keccak256("liveOrder"), solver, address(token), 1000);

        deal(address(token), address(compact), 10_000);

        vm.prank(authorizedCaller);
        uint256 reward = escrow.distributeReward(address(token), 10_000, makeAddr("receiver"));

        assertEq(reward, 0, "reward of 150 exceeds the 100 slashed pool");
        assertEq(escrow.slashedPool(id), 100, "slashed pool untouched");
        assertEq(compact.balanceOf(address(escrow), id), 1100, "escrow balance untouched");
    }

    /// @dev Forced withdrawal is allocator-independent, but it can only burn the solver's own free
    ///      balance. Locked collateral already sits in escrow custody, so the slash still seizes it.
    function test_slashCollateral_afterForcedWithdrawal_succeeds() public {
        uint256 id = escrow.lockId(address(token));
        bytes32 orderId = keccak256("order1");

        vm.startPrank(solver);
        token.approve(address(escrow), 500);
        escrow.deposit(address(token), 500);
        vm.stopPrank();

        vm.prank(authorizedCaller);
        escrow.lockCollateral(orderId, solver, address(token), 100);

        // Solver drains everything reachable via the forced-withdrawal escape (only the free 400).
        deal(address(token), address(compact), 500);
        vm.startPrank(solver);
        compact.enableForcedWithdrawal(id);
        compact.forcedWithdrawal(id, solver, 400);
        vm.stopPrank();

        assertEq(compact.balanceOf(solver, id), 0, "solver's free balance force-withdrawn");
        assertEq(compact.balanceOf(address(escrow), id), 100, "locked collateral untouched by the escape");

        vm.prank(authorizedCaller);
        escrow.slashCollateral(orderId);

        assertEq(escrow.slashedPool(id), 100, "slash still seizes the custodied collateral");
    }

    function test_lockCollateral_zeroAmount_reverts() public {
        vm.prank(authorizedCaller);
        vm.expectRevert(SolverEscrow.InvalidAmount.selector);
        escrow.lockCollateral(keccak256("order1"), solver, address(token), 0);
    }

    function test_lockCollateral_zeroSolver_reverts() public {
        vm.prank(authorizedCaller);
        vm.expectRevert(SolverEscrow.ZeroAddress.selector);
        escrow.lockCollateral(keccak256("order1"), address(0), address(token), 100);
    }

    // ============ lockId ============

    function test_lockId_encoding() public view {
        uint256 expected = (uint256(uint96(lockTag)) << 160) | uint160(address(token));
        assertEq(escrow.lockId(address(token)), expected, "lockId encoding");
    }
}
