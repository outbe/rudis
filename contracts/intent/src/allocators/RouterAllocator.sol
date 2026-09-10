// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {IAllocator} from "the-compact/src/interfaces/IAllocator.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IdLib} from "the-compact/src/lib/IdLib.sol";
import {Scope} from "the-compact/src/types/Scope.sol";
import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";

/// @title RouterAllocator
/// @notice Allocator for The Compact that authorizes claims from registered router operators.
/// @dev Pure validation contract - no token operations. Registers itself with The Compact on deploy.
///      Authorized operators (LayerZeroRouter, HyperlaneRouter, etc.) are added post-deploy via addOperator().
contract RouterAllocator is IAllocator, Ownable2Step {
    // ============ Constants ============

    string public constant VERSION = "1.0.0";

    // ============ Immutables ============

    /// @notice The Compact contract
    ITheCompact public immutable COMPACT;

    /// @notice Allocator ID assigned by The Compact on registration
    uint96 public immutable ALLOCATOR_ID;

    // ============ State ============

    /// @notice Authorized router operators (one per chain per messaging layer)
    /// @dev operator = msg.sender of allocatedTransfer() on The Compact = router address
    mapping(address => bool) public authorizedOperators;

    // ============ Events ============

    event OperatorAdded(address indexed operator);
    event OperatorRemoved(address indexed operator);

    // ============ Errors ============

    /// @notice Thrown when the operator is not registered for this allocator
    error UnauthorizedOperator(address operator);
    /// @notice Thrown when a claim has expired
    error ClaimExpired(uint256 expires, uint256 currentTime);
    /// @notice Thrown when a zero address is supplied as an operator
    error ZeroOperator();

    // ============ Constructor ============

    /// @param _compact The Compact contract address
    constructor(address _compact) Ownable(msg.sender) {
        COMPACT = ITheCompact(_compact);

        // Register this contract as an allocator. The Compact verifies that address(this) has code.
        // Returns the unique allocatorId used to build lockTags.
        ALLOCATOR_ID = COMPACT.__registerAllocator(address(this), "");
    }

    // ============ Owner Functions ============

    /// @notice Authorize a router contract to trigger allocations
    /// @dev Call after deploying LayerZeroRouter (or any other router) - pass its address here
    function addOperator(address _operator) external onlyOwner {
        if (_operator == address(0)) revert ZeroOperator();
        authorizedOperators[_operator] = true;
        emit OperatorAdded(_operator);
    }

    /// @notice Revoke operator authorization
    function removeOperator(address _operator) external onlyOwner {
        authorizedOperators[_operator] = false;
        emit OperatorRemoved(_operator);
    }

    // ============ View ============

    /// @notice Build a lockTag for the given scope and reset period using this allocator's ID.
    /// @dev Call to get LOCK_TAG before configuring a router via setCompactConfig().
    ///      Example: buildLockTag(Scope.Multichain, ResetPeriod.OneDay)
    function buildLockTag(Scope scope, ResetPeriod resetPeriod) external view returns (bytes12) {
        return IdLib.toLockTag(ALLOCATOR_ID, scope, resetPeriod);
    }

    function getId(bytes12 lockTag, address token) public pure returns (uint256) {
        return (uint256(uint96(bytes12(lockTag))) << 160) | uint160(token);
    }

    // ============ IAllocator ============

    /// @inheritdoc IAllocator
    /// @dev Called by The Compact before every allocatedTransfer().
    ///      operator = the address that called allocatedTransfer() = our router.
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
        if (!authorizedOperators[operator]) revert UnauthorizedOperator(operator);
        return IAllocator.attest.selector;
    }

    /// @inheritdoc IAllocator
    /// @dev Called by The Compact during claim processing.
    ///      arbiter = the address that called claim() = our router.
    function authorizeClaim(
        bytes32, /* claimHash */
        address arbiter,
        address, /* sponsor */
        uint256, /* nonce */
        uint256 expires,
        uint256[2][] calldata, /* idsAndAmounts */
        bytes calldata /* allocatorData */
    ) external view override returns (bytes4) {
        if (block.timestamp > expires) revert ClaimExpired(expires, block.timestamp);
        if (!authorizedOperators[arbiter]) revert UnauthorizedOperator(arbiter);
        return IAllocator.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    /// @dev Off-chain check before submitting a claim.
    function isClaimAuthorized(
        bytes32, /* claimHash */
        address arbiter,
        address, /* sponsor */
        uint256, /* nonce */
        uint256 expires,
        uint256[2][] calldata, /* idsAndAmounts */
        bytes calldata /* allocatorData */
    ) external view override returns (bool) {
        return authorizedOperators[arbiter] && block.timestamp <= expires;
    }
}
