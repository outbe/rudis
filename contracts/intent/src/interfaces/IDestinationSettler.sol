// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {OnchainCrossChainOrder} from "./OrderTypes.sol";

/// @title IDestinationSettler
/// @notice Interface for settlement contracts on the destination chain
interface IDestinationSettler {
    /// @notice Emitted when an order is filled
    /// @param orderId The ID of the filled order
    /// @param originData The origin-specific data for the order
    /// @param fillerData The filler-specific data for the order
    event Filled(bytes32 indexed orderId, bytes originData, bytes fillerData);

    /// @notice Emitted when a batch of orders is settled
    /// @param orderIds The IDs of the orders being settled
    /// @param ordersFillerData The filler data for the settled orders
    event Settle(bytes32[] orderIds, bytes[] ordersFillerData);

    /// @notice Emitted when an order is claimed by the winning solver
    /// @param orderId The ID of the claimed order
    /// @param winner The address of the winning solver
    /// @param outputAmount The winning output amount
    event OrderClaimed(bytes32 indexed orderId, address indexed winner, uint256 outputAmount);

    /// @notice Emitted when a batch of orders is refunded
    /// @param orderIds The IDs of the refunded orders
    event Refund(bytes32[] orderIds);

    // ============ Errors ============

    /// @notice Thrown when an order has an invalid status for the requested operation
    error InvalidOrderStatus();

    /// @notice Thrown when the order ID doesn't match the computed ID
    error InvalidOrderId();

    /// @notice Thrown when attempting to fill an expired order
    error OrderFillExpired();

    /// @notice Thrown when the order's destination domain doesn't match the local domain
    error InvalidOrderDomain();

    /// @notice Thrown when a non-winner tries to fill an order
    error NotAWinner();

    /// @notice Thrown when quote output is below order minimum
    error BelowMinimumOutput();

    /// @notice Thrown when the order origin is invalid
    error InvalidOrderOrigin();

    /// @notice Thrown when trying to refund an order that hasn't expired yet
    error OrderFillNotExpired();

    // ============ Functions ============

    /// @notice Claims an auction-won order, locking the winning solver's collateral
    /// @param orderId Unique order identifier for this order
    /// @param originData Data emitted on the origin to parameterize the fill
    function claimOrder(bytes32 orderId, bytes calldata originData) external;

    /// @notice Fills a single leg of a particular order on the destination chain
    /// @param orderId Unique order identifier for this order
    /// @param originData Data emitted on the origin to parameterize the fill
    /// @param fillerData Data provided by the filler to inform the fill or express their preferences
    function fill(bytes32 orderId, bytes calldata originData, bytes calldata fillerData) external payable;

    /// @notice Settles a batch of filled orders
    /// @dev Pays the filler the amount locked when the orders were opened
    /// @param orderIds An array of IDs for the orders to settle
    function settle(bytes32[] calldata orderIds) external payable;

    /// @notice Refunds a batch of expired orders
    /// @dev Returns funds to users for orders that were not filled before deadline
    /// @param orders An array of OnchainCrossChainOrders to refund
    function refund(OnchainCrossChainOrder[] calldata orders) external payable;
}
