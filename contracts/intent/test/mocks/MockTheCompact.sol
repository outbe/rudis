// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AllocatedTransfer, Claim} from "the-compact/src/types/Claims.sol";

/// @notice Mock for The Compact contract.
/// @dev Supports both Router flows (depositERC20/depositNative/allocatedTransfer)
///      and Escrow flows (depositERC20AndRegisterFor/depositNativeAndRegisterFor/claim/balanceOf).
///      Also supports ERC6909 operator approval and transferFrom.
contract MockTheCompact {
    using SafeERC20 for IERC20;

    // ============ ERC6909 balances ============

    mapping(address owner => mapping(uint256 id => uint256)) public balanceOf;

    // ============ ERC6909 operator approvals ============

    mapping(address owner => mapping(address operator => bool)) public isOperator;

    // ============ Forced withdrawal (allocator-independent escape) ============

    mapping(address owner => mapping(uint256 id => uint256)) public forcedWithdrawalEnabledAt;

    // ============ Nonce tracking (for claim) ============

    mapping(uint256 => bool) public nonceConsumed;

    // ============ Allocator registry ============

    uint96 private _nextAllocatorId = 1;

    receive() external payable {}

    // ============ Test helpers ============

    /// @dev Directly set ERC6909 balance for test setup (bypasses deposit)
    function __setBalance(address owner, uint256 id, uint256 amount) external {
        balanceOf[owner][id] = amount;
    }

    // ============ Allocator registration ============

    function __registerAllocator(
        address,
        /* allocator */
        bytes calldata /* proof */
    )
        external
        returns (uint96 allocatorId)
    {
        allocatorId = _nextAllocatorId++;
    }

    // ============ ERC6909 operator ============

    function setOperator(address operator, bool approved) external returns (bool) {
        isOperator[msg.sender][operator] = approved;
        return true;
    }

    // ============ ERC6909 transferFrom ============

    function transferFrom(address from, address to, uint256 id, uint256 amount) external returns (bool) {
        if (from != msg.sender) {
            require(isOperator[from][msg.sender], "MockTheCompact: not operator");
        }
        require(balanceOf[from][id] >= amount, "MockTheCompact: insufficient balance");
        balanceOf[from][id] -= amount;
        balanceOf[to][id] += amount;
        return true;
    }

    function transfer(address to, uint256 id, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender][id] >= amount, "MockTheCompact: insufficient balance");
        balanceOf[msg.sender][id] -= amount;
        balanceOf[to][id] += amount;
        return true;
    }

    // ============ Forced withdrawal (bypasses allocator and operator checks) ============

    /// @dev ponytail: no reset-period timer; arms immediately. The property under test is that
    ///      forced withdrawal can only touch the caller's own free balance, not escrow-held collateral.
    function enableForcedWithdrawal(uint256 id) external returns (uint256 withdrawableAt) {
        withdrawableAt = block.timestamp;
        forcedWithdrawalEnabledAt[msg.sender][id] = withdrawableAt;
    }

    function forcedWithdrawal(uint256 id, address recipient, uint256 amount) external returns (bool) {
        require(forcedWithdrawalEnabledAt[msg.sender][id] != 0, "MockTheCompact: forced withdrawal not enabled");
        require(balanceOf[msg.sender][id] >= amount, "MockTheCompact: insufficient balance");
        balanceOf[msg.sender][id] -= amount;

        address token = address(uint160(id));
        if (token == address(0)) {
            (bool success,) = recipient.call{value: amount}("");
            require(success, "MockTheCompact: ETH transfer failed");
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
        return true;
    }

    // ============ Deposits (with ERC6909 balance tracking) ============

    /// @notice Pull ERC20 tokens from caller, credit ERC6909 to recipient.
    function depositERC20(address token, bytes12 lockTag, uint256 amount, address recipient)
        external
        returns (uint256 id)
    {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        id = _toId(lockTag, token);
        balanceOf[recipient][id] += amount;
    }

    /// @notice Accept native ETH and credit ERC6909 to recipient.
    function depositNative(bytes12 lockTag, address recipient) external payable returns (uint256 id) {
        id = _toId(lockTag, address(0));
        balanceOf[recipient][id] += msg.value;
    }

    // ============ Escrow-style deposits (with registration - kept for Router tests) ============

    function depositERC20AndRegisterFor(
        address recipient,
        address token,
        bytes12 lockTag,
        uint256 amount,
        address, /* arbiter */
        uint256, /* nonce */
        uint256, /* expires */
        bytes32, /* typehash */
        bytes32 /* witness */
    ) external returns (uint256 id, bytes32 claimHash, uint256 registeredAmount) {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        id = _toId(lockTag, token);
        balanceOf[recipient][id] += amount;
        return (id, bytes32(0), amount);
    }

    function depositNativeAndRegisterFor(
        address recipient,
        bytes12 lockTag,
        address, /* arbiter */
        uint256, /* nonce */
        uint256, /* expires */
        bytes32, /* typehash */
        bytes32 /* witness */
    ) external payable returns (uint256 id, bytes32 claimHash) {
        id = _toId(lockTag, address(0));
        balanceOf[recipient][id] += msg.value;
        return (id, bytes32(0));
    }

    // ============ Claim (escrow withdrawal - kept for Router tests) ============

    function claim(Claim calldata claimPayload) external returns (bytes32) {
        require(!nonceConsumed[claimPayload.nonce], "MockTheCompact: nonce already consumed");
        nonceConsumed[claimPayload.nonce] = true;

        uint256 id = claimPayload.id;
        address sponsor = claimPayload.sponsor;
        require(balanceOf[sponsor][id] >= claimPayload.allocatedAmount, "MockTheCompact: insufficient balance");
        balanceOf[sponsor][id] -= claimPayload.allocatedAmount;

        address token = address(uint160(id));

        for (uint256 i = 0; i < claimPayload.claimants.length; i++) {
            address recipient = address(uint160(claimPayload.claimants[i].claimant));
            uint256 amount = claimPayload.claimants[i].amount;

            if (token == address(0)) {
                (bool success,) = recipient.call{value: amount}("");
                require(success, "MockTheCompact: ETH transfer failed");
            } else {
                IERC20(token).safeTransfer(recipient, amount);
            }
        }

        return bytes32(0);
    }

    // ============ AllocatedTransfer ============

    /// @notice Burns ERC6909 from msg.sender, releases underlying to recipients.
    function allocatedTransfer(AllocatedTransfer calldata transfer) external returns (bool) {
        uint256 id = transfer.id;
        address token = address(uint160(id));

        for (uint256 i = 0; i < transfer.recipients.length; i++) {
            address recipient = address(uint160(transfer.recipients[i].claimant));
            uint256 amount = transfer.recipients[i].amount;

            // Burn ERC6909 from msg.sender
            require(balanceOf[msg.sender][id] >= amount, "MockTheCompact: insufficient balance");
            balanceOf[msg.sender][id] -= amount;

            // Release underlying tokens
            if (token == address(0)) {
                (bool success,) = recipient.call{value: amount}("");
                require(success, "MockTheCompact: ETH transfer failed");
            } else {
                IERC20(token).safeTransfer(recipient, amount);
            }
        }
        return true;
    }

    // ============ Internal ============

    function _toId(bytes12 lockTag, address token) internal pure returns (uint256) {
        return (uint256(uint96(lockTag)) << 160) | uint160(token);
    }
}
