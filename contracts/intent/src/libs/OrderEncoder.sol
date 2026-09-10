// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {OrderData} from "../interfaces/OrderTypes.sol";

library OrderEncoder {
    bytes constant ORDER_DATA_TYPE = abi.encodePacked(
        "OrderData(",
        "bytes32 sender,",
        "bytes32 recipient,",
        "bytes32 inputToken,",
        "bytes32 outputToken,",
        "uint256 amountIn,",
        "uint256 amountOut,",
        "uint256 senderNonce,",
        "uint32 originDomain,",
        "uint32 destinationDomain,",
        "bytes32 destinationSettler,",
        "uint32 fillDeadline,",
        "bytes data)"
    );

    bytes32 constant ORDER_DATA_TYPE_HASH = keccak256(ORDER_DATA_TYPE);

    function orderDataType() internal pure returns (bytes32) {
        return ORDER_DATA_TYPE_HASH;
    }

    function id(OrderData memory order) internal pure returns (bytes32) {
        // TODO fix note[asm-keccak256]: use of inefficient hashing mechanism; consider using inline assembly
        return keccak256(encode(order));
    }

    function encode(OrderData memory order) internal pure returns (bytes memory) {
        return abi.encode(order);
    }

    function decode(bytes memory orderBytes) internal pure returns (OrderData memory) {
        (OrderData memory orderData) = abi.decode(orderBytes, (OrderData));

        return orderData;
    }
}
