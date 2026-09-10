// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Fee-quoting extension for ERC-7786 gateways (not part of the ERC-7786 core, which leaves fee discovery to the
 * transport). Mirrors the interface exposed by the `crosschain` hub's `ERC7786Bridge`, so the intent router can
 * ask the bridge for the native fee before sending. Vendored because OpenZeppelin does not ship it.
 */
interface IGatewayQuote {
    /// @dev Native fee required to deliver `payload` to `recipient` (an ERC-7930 interoperable address).
    function quote(bytes calldata recipient, bytes calldata payload) external view returns (uint256 nativeFee);
}
