// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OrderData} from "../interfaces/OrderTypes.sol";
import {IDestinationSettler} from "../interfaces/IDestinationSettler.sol";
import {OrderEncoder} from "./OrderEncoder.sol";

/// @title OrderValidator
/// @notice Shared decode-and-check helper for callers that receive ABI-encoded OrderData
library OrderValidator {
    /// @notice Decode `originData` and assert: orderId hash matches, fillDeadline is in the future,
    ///         and `outputAmount` is at least the user's `amountOut` floor.
    /// @dev Reverts with errors declared on IDestinationSettler so all order-level errors share one source of truth.
    function decodeAndCheck(bytes calldata originData, bytes32 orderId, uint256 outputAmount)
        internal
        view
        returns (OrderData memory orderData)
    {
        orderData = OrderEncoder.decode(originData);
        if (OrderEncoder.id(orderData) != orderId) revert IDestinationSettler.InvalidOrderId();
        if (block.timestamp > orderData.fillDeadline) revert IDestinationSettler.OrderFillExpired();
        if (outputAmount < orderData.amountOut) revert IDestinationSettler.BelowMinimumOutput();
    }
}
