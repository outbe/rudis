// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITheCompact} from "../../src/vendor/the-compact/interfaces/ITheCompact.sol";
import {Scope} from "../../src/vendor/the-compact/types/Scope.sol";
import {ResetPeriod} from "../../src/vendor/the-compact/types/ResetPeriod.sol";

/**
 * @title MockTheCompact
 * @notice Mock implementation of The Compact protocol for testing
 */
contract MockTheCompact is ITheCompact {
    uint96 private _nextAllocatorId = 1;
    uint256 private _nextLockId = 1;

    // Track deposits: lockId => depositor => balance
    mapping(uint256 => mapping(address => uint256)) public balances;
    // Track forced withdrawal enabled
    mapping(uint256 => mapping(address => bool)) public forcedWithdrawalEnabled;
    // Track forced withdrawal timestamp (when it becomes available)
    mapping(uint256 => mapping(address => uint256)) public withdrawableAt;
    // Lock details
    mapping(uint256 => LockDetails) public locks;

    struct LockDetails {
        address token;
        address allocator;
        ResetPeriod resetPeriod;
        Scope scope;
        bytes12 lockTag;
    }

    // Control forced withdrawal behavior for testing
    bool public forcedWithdrawalShouldFail;
    uint256 public resetPeriodSeconds = 60; // 1 minute default

    function setForcedWithdrawalShouldFail(bool shouldFail) external {
        forcedWithdrawalShouldFail = shouldFail;
    }

    function setResetPeriodSeconds(uint256 seconds_) external {
        resetPeriodSeconds = seconds_;
    }

    // Map lockTag to lockId for consistent lockId per allocator
    mapping(bytes12 => uint256) public lockTagToId;

    function depositERC20(address token, bytes12 lockTag, uint256 amount, address recipient)
        external
        override
        returns (uint256 id)
    {
        // Transfer tokens from sender
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // Use existing lockId for this lockTag, or create new one
        id = lockTagToId[lockTag];
        if (id == 0) {
            id = _nextLockId;
            _nextLockId++;
            lockTagToId[lockTag] = id;
            locks[id] = LockDetails({
                token: token,
                allocator: msg.sender,
                resetPeriod: ResetPeriod.OneMinute,
                scope: Scope.ChainSpecific,
                lockTag: lockTag
            });
        }

        balances[id][recipient] += amount;
        return id;
    }

    function enableForcedWithdrawal(uint256 id) external override returns (uint256) {
        forcedWithdrawalEnabled[id][msg.sender] = true;
        uint256 availableAt = block.timestamp + resetPeriodSeconds;
        withdrawableAt[id][msg.sender] = availableAt;
        return availableAt;
    }

    function forcedWithdrawal(uint256 id, address recipient, uint256 amount) external override returns (bool) {
        if (forcedWithdrawalShouldFail) return false;
        if (!forcedWithdrawalEnabled[id][msg.sender]) return false;
        if (block.timestamp < withdrawableAt[id][msg.sender]) return false;
        if (balances[id][msg.sender] < amount) return false;

        balances[id][msg.sender] -= amount;

        address token = locks[id].token;
        IERC20(token).transfer(recipient, amount);

        return true;
    }

    function __registerAllocator(
        address allocator,
        bytes calldata /* proof */
    )
        external
        override
        returns (uint96 allocatorId)
    {
        allocatorId = _nextAllocatorId;
        _nextAllocatorId++;
        return allocatorId;
    }

    function getLockDetails(uint256 id)
        external
        view
        override
        returns (address token, address allocator, ResetPeriod resetPeriod, Scope scope, bytes12 lockTag)
    {
        LockDetails memory details = locks[id];
        return (details.token, details.allocator, details.resetPeriod, details.scope, details.lockTag);
    }

    // Helper for testing: directly set balance
    function setBalance(uint256 lockId, address account, uint256 amount) external {
        balances[lockId][account] = amount;
    }

    // Helper for testing: get balance
    function getBalance(uint256 lockId, address account) external view returns (uint256) {
        return balances[lockId][account];
    }

    /// @notice ERC6909-style balance query - The Compact issues ERC6909 receipts keyed by lockId.
    function balanceOf(address owner, uint256 id) external view returns (uint256) {
        return balances[id][owner];
    }
}
