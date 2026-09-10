// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

library RouterMessage {
    /**
     * @notice Encodes a settle or refund message for cross-chain dispatch.
     * @param _settle           True for settle, false for refund.
     * @param _orderIds         Order IDs to settle or refund.
     * @param _ordersFillerData Per-order filler data (bytes32-encoded receiver address for settle).
     * @return Encoded message bytes.
     */
    function encode(bool _settle, bytes32[] memory _orderIds, bytes[] memory _ordersFillerData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(_settle, _orderIds, _ordersFillerData);
    }

    /**
     * @notice Decodes a cross-chain message.
     * @param _message The encoded message.
     * @return settle        True if settle, false if refund.
     * @return orderIds      Order IDs.
     * @return fillerData    Per-order filler data.
     */
    function decode(bytes calldata _message) internal pure returns (bool, bytes32[] memory, bytes[] memory) {
        return abi.decode(_message, (bool, bytes32[], bytes[]));
    }

    function encodeSettle(bytes32[] memory _orderIds, bytes[] memory _ordersFillerData)
        internal
        pure
        returns (bytes memory)
    {
        return encode(true, _orderIds, _ordersFillerData);
    }

    function encodeRefund(bytes32[] memory _orderIds) internal pure returns (bytes memory) {
        return encode(false, _orderIds, new bytes[](0));
    }
}
