// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IAllocator} from "the-compact/src/interfaces/IAllocator.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IdLib} from "the-compact/src/lib/IdLib.sol";
import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";
import {Scope} from "the-compact/src/types/Scope.sol";

/// @title SolverAllocator
/// @notice Allocator for The Compact that manages solver collateral resource locks.
/// @dev Roles:
///      - Standard ERC6909 transfers (attest): blocked - solvers must use escrow.withdraw().
///      - Allocated transfers / claims (authorizeClaim): only arbiter (escrow) is authorized.
///
/// Deploy order:
///   1. Deploy SolverAllocator(_compact)
///   2. lockTag = allocator.buildLockTag(Scope.ChainSpecific, ResetPeriod.TenMinutes)
///   3. Deploy SolverEscrow(_compact, lockTag)
///   4. allocator.setArbiter(address(escrow))
contract SolverAllocator is IAllocator {
    // ============ Constants ============

    string public constant VERSION = "1.0.0";

    // ============ Immutables ============

    /// @notice The Compact contract
    ITheCompact public immutable COMPACT;

    /// @notice Allocator ID assigned by The Compact on registration
    uint96 public immutable ALLOCATOR_ID;

    /// @notice Deployer address - can call setArbiter() once
    address public immutable OWNER;

    // ============ State ============

    /// @notice Authorized arbiter for withdrawals and slashing (SolverEscrow).
    ///         Set once by OWNER after escrow is deployed.
    address public arbiter;

    // ============ Events ============

    event ArbiterSet(address indexed arbiter);

    // ============ Errors ============

    /// @notice Thrown when attest() is called (direct ERC6909 transfers are blocked)
    error DirectTransferBlocked();
    /// @notice Thrown when caller is not the authorized arbiter
    error UnauthorizedArbiter();
    /// @notice Thrown when caller is not the contract owner
    error UnauthorizedOwner();
    /// @notice Thrown when arbiter has already been set
    error ArbiterAlreadySet();
    /// @notice Thrown when a zero address is supplied as the arbiter
    error ZeroArbiter();
    /// @notice Thrown when a claim has expired
    error ClaimExpired(uint256 expires, uint256 currentTime);

    // ============ Constructor ============

    /// @param _compact The Compact contract address
    constructor(address _compact) {
        COMPACT = ITheCompact(_compact);
        ALLOCATOR_ID = COMPACT.__registerAllocator(address(this), "");
        OWNER = msg.sender;
    }

    // ============ Admin ============

    /// @notice Set the arbiter contract address. Can only be called once by OWNER.
    /// @param _arbiter SolverEscrow contract address
    function setArbiter(address _arbiter) external {
        if (msg.sender != OWNER) revert UnauthorizedOwner();
        if (_arbiter == address(0)) revert ZeroArbiter();
        if (arbiter != address(0)) revert ArbiterAlreadySet();
        arbiter = _arbiter;
        emit ArbiterSet(_arbiter);
    }

    // ============ View ============

    /// @notice Build a lockTag using this allocator's ID.
    function buildLockTag(Scope scope, ResetPeriod resetPeriod) external view returns (bytes12) {
        return IdLib.toLockTag(ALLOCATOR_ID, scope, resetPeriod);
    }

    // ============ IAllocator ============

    /// @inheritdoc IAllocator
    /// @dev Allows ERC6909 transfers only when the operator is the arbiter (escrow).
    ///      All other direct transfers are blocked - solvers must use escrow.withdraw().
    function attest(
        address operator,
        address, /* from */
        address, /* to */
        uint256, /* id */
        uint256 /* amount */
    )
        external
        view
        override
        returns (bytes4)
    {
        if (operator != arbiter) revert DirectTransferBlocked();
        return IAllocator.attest.selector;
    }

    /// @inheritdoc IAllocator
    /// @dev Called by The Compact during allocatedTransfer() and claim() processing.
    function authorizeClaim(
        bytes32 claimHash,
        address claimArbiter,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint256[2][] calldata idsAndAmounts,
        bytes calldata allocatorData
    ) external view override returns (bytes4) {
        if (block.timestamp > expires) revert ClaimExpired(expires, block.timestamp);
        if (!isClaimAuthorized(claimHash, claimArbiter, sponsor, nonce, expires, idsAndAmounts, allocatorData)) {
            revert UnauthorizedArbiter();
        }
        return IAllocator.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32, /* claimHash */
        address claimArbiter,
        address, /* sponsor */
        uint256, /* nonce */
        uint256 expires,
        uint256[2][] calldata, /* idsAndAmounts */
        bytes calldata /* allocatorData */
    ) public view override returns (bool) {
        // Only the arbiter (escrow) can claim - solvers must go through escrow - and not past expiry.
        return claimArbiter == arbiter && block.timestamp <= expires;
    }
}
