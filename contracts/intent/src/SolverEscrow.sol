// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IERC6909} from "the-compact/lib/forge-std/src/interfaces/IERC6909.sol";
import {AllocatedTransfer} from "the-compact/src/types/Claims.sol";
import {Component} from "the-compact/src/types/Components.sol";

import {ISolverEscrow} from "./interfaces/ISolverEscrow.sol";

/// @title SolverEscrow
/// @notice Deposit, withdraw, lock, and slash solver collateral managed via The Compact.
/// @dev Solver holds ERC6909 tokens directly while unlocked; the escrow custodies them while locked.
///      Escrow acts as an ERC6909 operator (solver must call COMPACT.setOperator(escrow, true) once).
///      The SolverAllocator.attest() allows transfers where operator == arbiter (escrow).
///
/// Flow:
///   deposit:   Solver -> Escrow -> Compact.depositERC20(recipient=solver) -> ERC6909 on solver
///   withdraw:  Solver -> Escrow -> transferFrom(solver->escrow) -> allocatedTransfer(escrow->solver)
///   lock:      DestinationSettler -> Escrow.lockCollateral -> transferFrom(solver->escrow)
///   unlock:    DestinationSettler -> Escrow.unlockCollateral -> transfer(escrow->solver)
///   slash:     DestinationSettler -> Escrow.slashCollateral -> credits slashedPool
///
/// Invariant: balanceOf(escrow, id) == sum(live locks on id) + slashedPool[id]
///
/// Setup:
///   1. Deploy SolverAllocator(_compact)
///   2. lockTag = allocator.buildLockTag(Scope.ChainSpecific, ResetPeriod.ThirtyDays)
///   3. Deploy SolverEscrow(_compact, lockTag, collateralBps)
///   4. allocator.setArbiter(address(escrow))
///   5. Deploy Router
///   6. escrow.setAuthorizedCaller(address(router))
///   7. Each solver: COMPACT.setOperator(address(escrow), true)
contract SolverEscrow is ISolverEscrow, Ownable2Step {
    using SafeERC20 for IERC20;

    // ============ Constants ============

    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant REWARD_BPS = 150; // 1.5%

    // ============ Immutables ============

    ITheCompact public immutable COMPACT;
    bytes12 public immutable LOCK_TAG;

    /// @notice Authorized caller for lock/unlock/slash (Router). Set once via setAuthorizedCaller().
    address public AUTHORIZED_CALLER;

    // ============ State ============

    uint256 private _nextNonce;
    uint256 public collateralBps;

    struct Lock {
        address solver;
        address token;
        uint256 amount;
    }

    mapping(bytes32 orderId => Lock) public locks;

    /// @notice ERC6909 held by the escrow on a solver's behalf while locked.
    mapping(address solver => mapping(uint256 id => uint256)) public totalLocked;

    /// @notice Per-id pool of slashed collateral, the only source distributeReward pays from.
    mapping(uint256 id => uint256) public slashedPool;

    // ============ Events ============

    event Deposited(address indexed solver, address indexed token, uint256 amount);
    event Withdrawn(address indexed solver, address indexed token, uint256 amount);
    event CollateralSlashed(bytes32 indexed orderId, address indexed solver, address token, uint256 amount);
    event CollateralBpsUpdated(uint256 oldBps, uint256 newBps);
    event RewardDistributed(address indexed receiver, address indexed token, uint256 amount);
    event SlashedPoolSwept(address indexed token, address indexed to, uint256 amount);

    // ============ Errors ============

    /// @notice Thrown when deposit or withdrawal amount is zero
    error InvalidAmount();
    /// @notice Thrown when caller is not the authorized caller (DestinationSettler)
    error UnauthorizedCaller();
    /// @notice Thrown when collateral bps is zero or exceeds 10000
    error InvalidBps();
    /// @notice Thrown when solver has not approved escrow as ERC6909 operator
    error OperatorNotApproved();
    /// @notice Thrown when native token withdrawal fails
    error WithdrawalFailed();
    /// @notice Thrown when authorized caller has already been set
    error AuthorizedCallerAlreadySet();
    /// @notice Thrown when a zero address is supplied where one is not allowed
    error ZeroAddress();

    // ============ Modifiers ============

    modifier onlyAuthorizedCaller() {
        _onlyAuthorizedCaller();
        _;
    }

    function _onlyAuthorizedCaller() internal view {
        if (msg.sender != AUTHORIZED_CALLER) revert UnauthorizedCaller();
    }

    // ============ Constructor ============

    constructor(address _compact, bytes12 _lockTag, uint256 _collateralBps) Ownable(msg.sender) {
        if (_collateralBps == 0 || _collateralBps > BPS_DENOMINATOR) revert InvalidBps();
        COMPACT = ITheCompact(_compact);
        LOCK_TAG = _lockTag;
        collateralBps = _collateralBps;
    }

    // ============ Admin ============

    /// @notice Set the authorized caller (Router). Can only be called once by owner.
    /// @param _caller The Router contract address.
    function setAuthorizedCaller(address _caller) external onlyOwner {
        if (AUTHORIZED_CALLER != address(0)) revert AuthorizedCallerAlreadySet();
        if (_caller == address(0)) revert ZeroAddress();
        AUTHORIZED_CALLER = _caller;
    }

    /// @notice Update collateral requirement in basis points (e.g. 1000 = 10%)
    function setCollateralBps(uint256 _collateralBps) external onlyOwner {
        if (_collateralBps == 0 || _collateralBps > BPS_DENOMINATOR) revert InvalidBps();
        uint256 oldBps = collateralBps;
        collateralBps = _collateralBps;
        emit CollateralBpsUpdated(oldBps, _collateralBps);
    }

    // ============ Deposit ============

    /// @notice Deposit tokens as solver collateral.
    /// @dev Solver must have called COMPACT.setOperator(address(this), true) beforehand.
    /// @param token  ERC20 token address, or address(0) for native ETH
    /// @param amount Amount to deposit (ERC20 only; ignored for native -- use msg.value)
    function deposit(address token, uint256 amount) external payable {
        _deposit(msg.sender, token, amount);
    }

    /// @notice Deposit tokens as collateral credited to another solver.
    /// @dev Funds come from msg.sender, but the collateral belongs to `solver` and cannot be
    ///      reclaimed by the payer. `solver` must have called COMPACT.setOperator(address(this), true).
    /// @param solver Address credited with the collateral
    /// @param token  ERC20 token address, or address(0) for native ETH
    /// @param amount Amount to deposit (ERC20 only; ignored for native -- use msg.value)
    function depositFor(address solver, address token, uint256 amount) external payable {
        if (solver == address(0)) revert ZeroAddress();
        _deposit(solver, token, amount);
    }

    function _deposit(address solver, address token, uint256 amount) private {
        if (!IERC6909(address(COMPACT)).isOperator(solver, address(this))) revert OperatorNotApproved();

        if (token == address(0)) {
            _depositNative(solver);
        } else {
            _depositERC20(solver, token, amount);
        }
    }

    // ============ Withdraw ============

    /// @notice Withdraw available (unlocked) collateral.
    /// @dev Takes ERC6909 from solver via transferFrom, then releases underlying via allocatedTransfer.
    /// @param token  Token address (address(0) for ETH)
    /// @param amount Amount to withdraw, or 0 for max available
    function withdraw(address token, uint256 amount) external {
        uint256 id = _lockId(token);
        uint256 available = IERC6909(address(COMPACT)).balanceOf(msg.sender, id);

        uint256 withdrawAmount = amount == 0 ? available : amount;
        if (withdrawAmount == 0 || withdrawAmount > available) revert InsufficientAvailableBalance();

        // Step 1: Take ERC6909 from solver to escrow
        IERC6909(address(COMPACT)).transferFrom(msg.sender, address(this), id, withdrawAmount);

        // Step 2: Release underlying tokens to solver via allocatedTransfer
        // claimant = uint160(solver) -> zero upper bits -> zero lockTag -> withdrawal of underlying
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({claimant: uint160(msg.sender), amount: withdrawAmount});

        COMPACT.allocatedTransfer(
            AllocatedTransfer({
                allocatorData: "", nonce: _nextNonce++, expires: type(uint256).max, id: id, recipients: recipients
            })
        );

        uint256 solverBalAfter = IERC6909(address(COMPACT)).balanceOf(msg.sender, id);
        if (solverBalAfter > available - withdrawAmount) revert WithdrawalFailed();

        emit Withdrawn(msg.sender, token, withdrawAmount);
    }

    // ============ Lock / Unlock / Slash ============

    /// @inheritdoc ISolverEscrow
    /// @dev Takes custody: the collateral moves from the solver's ERC6909 balance to the escrow.
    function lockCollateral(bytes32 orderId, address solver, address token, uint256 amount)
        external
        onlyAuthorizedCaller
    {
        if (amount == 0) revert InvalidAmount();
        if (solver == address(0)) revert ZeroAddress();
        if (locks[orderId].amount != 0) revert LockAlreadyExists();

        uint256 id = _lockId(token);
        if (IERC6909(address(COMPACT)).balanceOf(solver, id) < amount) revert InsufficientAvailableBalance();

        locks[orderId] = Lock({solver: solver, token: token, amount: amount});
        totalLocked[solver][id] += amount;

        IERC6909(address(COMPACT)).transferFrom(solver, address(this), id, amount);
    }

    /// @inheritdoc ISolverEscrow
    /// @dev Returns custody of the collateral to the solver.
    function unlockCollateral(bytes32 orderId) external onlyAuthorizedCaller {
        Lock memory lock = _consumeLock(orderId);

        IERC6909(address(COMPACT)).transfer(lock.solver, _lockId(lock.token), lock.amount);
    }

    /// @inheritdoc ISolverEscrow
    /// @dev Accounting only: the escrow already holds the collateral, so it is reclassified into
    ///      slashedPool. Performs no external call.
    function slashCollateral(bytes32 orderId) external onlyAuthorizedCaller {
        Lock memory lock = _consumeLock(orderId);

        slashedPool[_lockId(lock.token)] += lock.amount;

        emit CollateralSlashed(orderId, lock.solver, lock.token, lock.amount);
    }

    /// @inheritdoc ISolverEscrow
    /// @dev Distributes REWARD_BPS (1.5%) of orderAmountIn from slashed pool as underlying tokens.
    ///      Returns 0 if insufficient slashed balance (all-or-nothing).
    function distributeReward(address token, uint256 orderAmountIn, address receiver)
        external
        onlyAuthorizedCaller
        returns (uint256 reward)
    {
        reward = (orderAmountIn * REWARD_BPS) / BPS_DENOMINATOR;
        uint256 id = _lockId(token);

        // Only slashed collateral is payable -- the escrow's balance also holds live locks.
        if (slashedPool[id] < reward) return 0;
        slashedPool[id] -= reward;

        // Release underlying tokens to receiver via allocatedTransfer
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({claimant: uint160(receiver), amount: reward});

        COMPACT.allocatedTransfer(
            AllocatedTransfer({
                allocatorData: "", nonce: _nextNonce++, expires: type(uint256).max, id: id, recipients: recipients
            })
        );

        emit RewardDistributed(receiver, token, reward);
    }

    // ============ View ============

    /// @inheritdoc ISolverEscrow
    function getCollateralAmount(uint256 outputAmount) public view returns (uint256) {
        return (outputAmount * collateralBps) / BPS_DENOMINATOR;
    }

    /// @inheritdoc ISolverEscrow
    function hasMinCollateral(address solver, address token, uint256 outputAmount) external view returns (bool) {
        uint256 required = getCollateralAmount(outputAmount);
        uint256 available = IERC6909(address(COMPACT)).balanceOf(solver, _lockId(token));
        return available >= required;
    }

    /// @inheritdoc ISolverEscrow
    function getBalance(address owner, address token)
        external
        view
        returns (uint256 total, uint256 locked, uint256 available)
    {
        uint256 id = _lockId(token);
        available = IERC6909(address(COMPACT)).balanceOf(owner, id);
        locked = totalLocked[owner][id];
        total = available + locked;
    }

    /// @inheritdoc ISolverEscrow
    function getBalances(address owner, address[] calldata tokens) external view returns (BalanceInfo[] memory) {
        BalanceInfo[] memory infos = new BalanceInfo[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 id = _lockId(tokens[i]);
            uint256 available = IERC6909(address(COMPACT)).balanceOf(owner, id);
            uint256 locked = totalLocked[owner][id];
            infos[i] = BalanceInfo({token: tokens[i], total: available + locked, locked: locked, available: available});
        }
        return infos;
    }

    /// @notice Returns the ERC6909 token ID for a given underlying token.
    function lockId(address token) external view returns (uint256) {
        return _lockId(token);
    }

    // ============ Internal ============

    /// @dev Validates the lock exists, decrements totalLocked, deletes the lock, and returns it.
    function _consumeLock(bytes32 orderId) private returns (Lock memory lock) {
        lock = locks[orderId];
        if (lock.amount == 0) revert LockNotFound();

        totalLocked[lock.solver][_lockId(lock.token)] -= lock.amount;
        delete locks[orderId];
    }

    function _depositNative(address solver) private {
        if (msg.value == 0) revert InvalidAmount();

        COMPACT.depositNative{value: msg.value}(LOCK_TAG, solver);

        emit Deposited(solver, address(0), msg.value);
    }

    function _depositERC20(address solver, address token, uint256 amount) private {
        if (amount == 0) revert InvalidAmount();
        if (msg.value != 0) revert InvalidAmount();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(token).forceApprove(address(COMPACT), amount);

        COMPACT.depositERC20(token, LOCK_TAG, amount, solver);

        emit Deposited(solver, token, amount);
    }

    function _lockId(address token) internal view returns (uint256) {
        return (uint256(uint96(LOCK_TAG)) << 160) | uint160(token);
    }
}
