// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OriginSettlerBase} from "./OriginSettlerBase.sol";
import {OrderData, OrderEncoder} from "../../libs/OrderEncoder.sol";
import {TypeCasts} from "../../libs/TypeCasts.sol";
import {
    OnchainCrossChainOrder,
    ResolvedCrossChainOrder,
    Output,
    FillInstruction
} from "../../interfaces/OrderTypes.sol";
import {AllocatedTransfer} from "the-compact/src/types/Claims.sol";
import {Component} from "the-compact/src/types/Components.sol";
import {ISolverEscrow} from "../../interfaces/ISolverEscrow.sol";

/// @title OriginSettler
/// @notice Origin chain settlement contract for cross-chain swaps
/// @dev Extends OriginSettlerBase to provide order resolution and settlement/refund handling
abstract contract OriginSettler is OriginSettlerBase {
    // ========== MESSAGE HANDLERS ==========

    /**
     * @dev Handles settling an individual order, should be called by the inheriting contract when receiving a setting
     * instruction from a remote chain.
     * @param _messageOrigin The domain from which the message originates.
     * @param _messageSender The address of the sender on the origin domain.
     * @param _orderId The ID of the order to settle.
     * @param _receiver The receiver address (encoded as bytes32).
     */
    function _handleSettleOrder(uint32 _messageOrigin, bytes32 _messageSender, bytes32 _orderId, bytes32 _receiver)
        internal
        virtual
    {
        (bool isEligible, OrderData memory orderData) = _checkOrderEligibility(_messageOrigin, _messageSender, _orderId);

        if (!isEligible) return;

        orderStatus[_orderId] = SETTLED;

        address receiver = TypeCasts.bytes32ToAddress(_receiver);
        address inputToken = TypeCasts.bytes32ToAddress(orderData.inputToken);

        _allocatedTransfer(inputToken, receiver, orderData.amountIn, _orderId, "settle");

        // Distribute reward from slashed pool if available
        ISolverEscrow escrow = _solverEscrow();
        if (address(escrow) != address(0)) {
            escrow.distributeReward(inputToken, orderData.amountIn, receiver);
        }

        // Terminal status reached: the stored order bytes are dead weight; reclaim the slot.
        delete openOrders[_orderId];

        emit Settled(_orderId, receiver);
    }

    /**
     * @dev Handles refunding an individual order, should be called by the inheriting contract when receiving a
     * refunding instruction from a remote chain.
     * @param _messageOrigin The domain from which the message originates.
     * @param _messageSender The address of the sender on the origin domain.
     * @param _orderId The ID of the order to refund.
     */
    function _handleRefundOrder(uint32 _messageOrigin, bytes32 _messageSender, bytes32 _orderId) internal virtual {
        (bool isEligible, OrderData memory orderData) = _checkOrderEligibility(_messageOrigin, _messageSender, _orderId);

        if (!isEligible) return;

        orderStatus[_orderId] = REFUNDED;

        address orderSender = TypeCasts.bytes32ToAddress(orderData.sender);
        address inputToken = TypeCasts.bytes32ToAddress(orderData.inputToken);

        _allocatedTransfer(inputToken, orderSender, orderData.amountIn, _orderId, "refund");

        // Terminal status reached: the stored order bytes are dead weight; reclaim the slot.
        delete openOrders[_orderId];

        emit Refunded(_orderId, orderSender);
    }

    /// @dev TEMPORARY: releases an open order's input when a remote chain is down and no delivery
    ///      can trigger the normal refund. Expose behind the inheriting contract's access control.
    ///      TODO: remove before production, with `Router.emergencyWithdraw`.
    function _emergencyWithdraw(bytes32 _orderId, address _to) internal {
        require(orderStatus[_orderId] == OPENED, "order not open");

        (, bytes memory raw) = abi.decode(openOrders[_orderId], (bytes32, bytes));
        OrderData memory orderData = OrderEncoder.decode(raw);

        orderStatus[_orderId] = REFUNDED;
        _allocatedTransfer(
            TypeCasts.bytes32ToAddress(orderData.inputToken), _to, orderData.amountIn, _orderId, "refund"
        );
        delete openOrders[_orderId];
    }

    // ========== INTERNAL FUNCTIONS ==========

    /**
     * @notice Releases tokens from The Compact resource lock to a recipient.
     * @dev claimant = uint256(uint160(recipient)) - zero lockTag triggers withdrawal
     *      (underlying tokens sent directly, not ERC6909).
     *      Nonce derived from orderId + label to ensure uniqueness without extra storage.
     * @param _token    The underlying token address (address(0) for native ETH).
     * @param _to       The recipient address.
     * @param _amount   The amount to release.
     * @param _orderId  The order ID (used to derive a unique nonce).
     * @param _label    "settle" or "refund" - makes nonce unique per operation.
     */
    function _allocatedTransfer(address _token, address _to, uint256 _amount, bytes32 _orderId, bytes32 _label)
        internal
    {
        // lockId = lockTag (upper 96 bits) | tokenAddress (lower 160 bits)
        // For native ETH, token = address(0) so lockId = uint256(bytes32(lockTag))
        uint256 lockId = uint256(bytes32(_lockTag())) | uint160(_token);

        // claimant with zero lockTag = withdrawal: underlying tokens sent to _to directly
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({claimant: uint256(uint160(_to)), amount: _amount});

        // Nonce derived from orderId + label - unique per operation, no extra storage needed
        uint256 nonce = uint256(keccak256(abi.encode(_orderId, _label)));

        _compact()
            .allocatedTransfer(
                AllocatedTransfer({
                    allocatorData: "", nonce: nonce, expires: type(uint256).max, id: lockId, recipients: recipients
                })
            );
    }

    /**
     * @notice Checks if order is eligible for settlement or refund.
     * @param _messageOrigin The origin domain of the message.
     * @param _messageSender The sender identifier of the message.
     * @param _orderId The unique identifier of the order.
     * @return A boolean indicating if the order is valid, and the decoded OrderData structure.
     */
    function _checkOrderEligibility(uint32 _messageOrigin, bytes32 _messageSender, bytes32 _orderId)
        internal
        virtual
        returns (bool, OrderData memory)
    {
        OrderData memory orderData;

        if (orderStatus[_orderId] != OPENED) return (false, orderData);

        (, bytes memory _orderData) = abi.decode(openOrders[_orderId], (bytes32, bytes));
        orderData = OrderEncoder.decode(_orderData);

        if (orderData.destinationDomain != _messageOrigin || orderData.destinationSettler != _messageSender) {
            return (false, orderData);
        }

        return (true, orderData);
    }

    // ========== BASE OVERRIDES ==========

    /**
     * @notice Resolves a OnchainCrossChainOrder.
     * @param _order The OnchainCrossChainOrder to resolve.
     * @return A ResolvedCrossChainOrder structure.
     * @return The order ID.
     * @return The order nonce.
     */
    function _resolveOrder(OnchainCrossChainOrder memory _order)
        internal
        view
        virtual
        override
        returns (ResolvedCrossChainOrder memory, bytes32, uint256)
    {
        return _resolvedOrder(_order.orderDataType, msg.sender, _order.fillDeadline, _order.orderData);
    }

    /**
     * @dev Resolves an order into a ResolvedCrossChainOrder structure.
     * @param _orderType The type of the order.
     * @param _sender The sender of the order.
     * @param _fillDeadline The fill deadline of the order.
     * @param _orderData The data of the order.
     * @return resolvedOrder A ResolvedCrossChainOrder structure.
     * @return orderId The order ID.
     * @return nonce The order nonce.
     */
    function _resolvedOrder(bytes32 _orderType, address _sender, uint32 _fillDeadline, bytes memory _orderData)
        internal
        view
        returns (ResolvedCrossChainOrder memory resolvedOrder, bytes32 orderId, uint256 nonce)
    {
        if (_orderType != OrderEncoder.orderDataType()) {
            revert InvalidOrderType(_orderType);
        }

        OrderData memory orderData = OrderEncoder.decode(_orderData);

        if (orderData.originDomain != _localDomain()) {
            revert InvalidOriginDomain(orderData.originDomain);
        }

        orderData.fillDeadline = _fillDeadline;
        orderData.sender = TypeCasts.addressToBytes32(_sender);

        Output[] memory maxSpent = new Output[](1);
        maxSpent[0] = Output({
            token: orderData.outputToken,
            amount: orderData.amountOut,
            recipient: orderData.destinationSettler,
            chainId: orderData.destinationDomain
        });

        Output[] memory minReceived = new Output[](1);
        minReceived[0] = Output({
            token: orderData.inputToken,
            amount: orderData.amountIn,
            recipient: bytes32(0),
            chainId: orderData.originDomain
        });

        FillInstruction[] memory fillInstructions = new FillInstruction[](1);
        fillInstructions[0] = FillInstruction({
            destinationChainId: orderData.destinationDomain,
            destinationSettler: orderData.destinationSettler,
            originData: OrderEncoder.encode(orderData)
        });

        orderId = OrderEncoder.id(orderData);

        resolvedOrder = ResolvedCrossChainOrder({
            user: _sender,
            originChainId: _localDomain(),
            fillDeadline: _fillDeadline,
            orderId: orderId,
            minReceived: minReceived,
            maxSpent: maxSpent,
            fillInstructions: fillInstructions
        });

        nonce = orderData.senderNonce;
    }
}
