// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {OnchainCrossChainOrder, ResolvedCrossChainOrder} from "./OrderTypes.sol";

/// @title IOriginSettler
/// @notice Interface for settlement contracts on the origin chain
interface IOriginSettler {
    /// @notice Signals that an order has been opened
    /// @param orderId A unique order identifier within this settlement system
    /// @param resolvedOrder Resolved order that would be returned by resolve if called instead of open
    event Open(bytes32 indexed orderId, ResolvedCrossChainOrder resolvedOrder);

    /// @notice Emitted when an order is settled
    /// @param orderId The ID of the settled order
    /// @param receiver The address of the order's input token receiver
    event Settled(bytes32 orderId, address receiver);

    /// @notice Emitted when an order is refunded
    /// @param orderId The ID of the refunded order
    /// @param receiver The address of the order's input token receiver
    event Refunded(bytes32 orderId, address receiver);

    // ============ Errors ============

    /// @notice Thrown when a nonce has already been used
    error InvalidNonce();

    /// @notice Thrown when the order type doesn't match the expected type
    error InvalidOrderType(bytes32 orderType);

    /// @notice Thrown when the origin domain doesn't match the local domain
    error InvalidOriginDomain(uint32 originDomain);

    /// @notice Thrown when fillDeadline leaves too little time to run the auction and fill the order
    /// @dev The deadline must be at least commit + reveal + claim/fill periods ahead of the creation block
    error InvalidFillDeadline();

    // ============ Functions ============

    /// @notice Opens a cross-chain order
    /// @dev To be called by the user. This method must emit the Open event
    /// @param order The OnchainCrossChainOrder definition
    function open(OnchainCrossChainOrder calldata order) external payable;

    /// @notice Resolves a specific OnchainCrossChainOrder into a generic ResolvedCrossChainOrder
    /// @dev Intended to improve standardized integration of various order types and settlement contracts
    /// @param order The OnchainCrossChainOrder definition
    /// @return ResolvedCrossChainOrder hydrated order data including the inputs and outputs of the order
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory);

    /// @notice Invalidates a nonce for the caller, preventing its future use
    /// @param nonce The nonce to invalidate
    function invalidateNonces(uint256 nonce) external;

    /// @notice Checks whether a given nonce is still valid (unused) for an address
    /// @param from The address whose nonce validity is being checked
    /// @param nonce The nonce to check
    /// @return True if the nonce is valid (unused), false otherwise
    function isValidNonce(address from, uint256 nonce) external view returns (bool);
}
