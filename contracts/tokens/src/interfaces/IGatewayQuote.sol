// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @dev Fee-quoting extension exposed by the ERC-7786 bridge hub.
interface IGatewayQuote {
    function quote(bytes calldata recipient, bytes calldata payload) external view returns (uint256 nativeFee);

    function quote(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        external
        view
        returns (uint256 nativeFee);
}
