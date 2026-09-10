// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {OnchainCrossChainOrder} from "../../interfaces/OrderTypes.sol";
import {IDestinationSettler} from "../../interfaces/IDestinationSettler.sol";
import {OrderStatusStorage} from "../common/OrderStatusStorage.sol";
import {RouterAccessors} from "../common/RouterAccessors.sol";

/**
 * @title DestinationSettlerBase
 * @notice Base implementation for destination chain settlement contracts
 * @dev Handles order filling, settlement, and refunds on the destination chain
 */
abstract contract DestinationSettlerBase is OrderStatusStorage, RouterAccessors, IDestinationSettler {
    // ============ Structs ============

    /**
     * @dev Represents data for an order that has been filled
     * @param originData The origin-specific data for the order
     * @param fillerData The filler-specific data for the order
     */
    struct FilledOrder {
        bytes originData;
        bytes fillerData;
    }

    // ============ Public Storage ============

    /// @notice Tracks filled orders and their associated data
    mapping(bytes32 orderId => FilledOrder filledOrder) public filledOrders;

    // ============ External Functions ============

    /**
     * @notice Fills a single leg of a particular order on the destination chain
     * @param _orderId Unique order identifier for this order
     * @param _originData Data emitted on the origin to parameterize the fill
     * @param _fillerData Data provided by the filler to inform the fill or express their preferences
     */
    function fill(bytes32 _orderId, bytes calldata _originData, bytes calldata _fillerData) external payable virtual {
        if (destinationOrderStatus[_orderId] != CLAIMED) revert InvalidOrderStatus();

        destinationOrderStatus[_orderId] = FILLED;
        filledOrders[_orderId] = FilledOrder({originData: _originData, fillerData: _fillerData});

        _fillOrder(_orderId, _originData, _fillerData);

        _onFilled(_orderId);

        emit Filled(_orderId, _originData, _fillerData);
    }

    /**
     * @notice Settles a batch of filled orders
     * @dev Pays the filler the amount locked when the orders were opened
     * @param _orderIds An array of IDs for the orders to settle
     */
    function settle(bytes32[] calldata _orderIds) external payable {
        bytes[] memory ordersOriginData = new bytes[](_orderIds.length);
        bytes[] memory ordersFillerData = new bytes[](_orderIds.length);

        for (uint256 i = 0; i < _orderIds.length; i++) {
            if (destinationOrderStatus[_orderIds[i]] != FILLED) {
                revert InvalidOrderStatus();
            }

            ordersOriginData[i] = filledOrders[_orderIds[i]].originData;
            ordersFillerData[i] = filledOrders[_orderIds[i]].fillerData;
        }

        _settleOrders(_orderIds, ordersOriginData, ordersFillerData);

        emit Settle(_orderIds, ordersFillerData);
    }

    /**
     * @notice Refunds a batch of expired orders
     * @dev Returns funds to users for orders that were not filled before deadline
     * @param _orders An array of OnchainCrossChainOrders to refund
     */
    function refund(OnchainCrossChainOrder[] calldata _orders) external payable {
        bytes32[] memory orderIds = new bytes32[](_orders.length);

        for (uint256 i = 0; i < _orders.length; i++) {
            bytes32 orderId = _getOrderId(_orders[i]);
            orderIds[i] = orderId;

            bytes32 status = destinationOrderStatus[orderId];
            if (!_isNotProcessed(status) && status != CLAIMED) revert InvalidOrderStatus();
            if (block.timestamp <= _orders[i].fillDeadline) {
                revert OrderFillNotExpired();
            }

            if (status == CLAIMED) {
                _onSlashed(orderId);
            }
        }

        _refundOrders(_orders, orderIds);

        emit Refund(orderIds);
    }

    // ============ Internal Functions ============

    /**
     * @notice Fills an order with specific origin and filler data
     * @dev To be implemented by the inheriting contract
     * @param _orderId The unique identifier for the order to fill
     * @param _originData Data emitted on the origin chain to parameterize the fill
     * @param _fillerData Data provided by the filler
     */
    function _fillOrder(bytes32 _orderId, bytes calldata _originData, bytes calldata _fillerData) internal virtual;

    /**
     * @notice Settles a batch of orders using their origin and filler data
     * @dev To be implemented by the inheriting contract
     * @param _orderIds An array of order IDs to settle
     * @param _ordersOriginData The origin data for the orders being settled
     * @param _ordersFillerData The filler data for the orders being settled
     */
    function _settleOrders(
        bytes32[] calldata _orderIds,
        bytes[] memory _ordersOriginData,
        bytes[] memory _ordersFillerData
    ) internal virtual;

    /**
     * @notice Refunds a batch of OnchainCrossChainOrders
     * @dev To be implemented by the inheriting contract
     * @param _orders An array of OnchainCrossChainOrders to refund
     * @param _orderIds An array of IDs for the orders to refund
     */
    function _refundOrders(OnchainCrossChainOrder[] calldata _orders, bytes32[] memory _orderIds) internal virtual;

    /**
     * @notice Computes the unique identifier for an OnchainCrossChainOrder
     * @dev To be implemented by the inheriting contract
     * @param _order The OnchainCrossChainOrder to compute the ID for
     * @return The unique identifier for the order
     */
    function _getOrderId(OnchainCrossChainOrder calldata _order) internal pure virtual returns (bytes32);

    /// @notice Hook called after an order is successfully filled (unlock collateral)
    function _onFilled(bytes32 _orderId) internal virtual {}

    /// @notice Hook called when a claimed order is refunded (slash collateral)
    function _onSlashed(bytes32 _orderId) internal virtual {}

    /// @notice Hook called when an order is claimed (lock collateral)
    /// @return locked False if the collateral could not be locked and the claim must not proceed.
    function _onClaimed(bytes32 _orderId, address _solver, bytes calldata _originData)
        internal
        virtual
        returns (bool locked)
    {
        return true;
    }
}
