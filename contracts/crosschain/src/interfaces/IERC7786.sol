// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

/**
 * @dev ERC-7786 cross-chain messaging interfaces, vendored locally so the project has a single source of truth for
 * all cross-chain interfaces. Kept byte-compatible with the standard (and with OpenZeppelin's `draft-IERC7786.sol`):
 * the function selectors and event signatures are identical, so contracts using these interfaces interoperate with
 * any ERC-7786 gateway/recipient regardless of which declaration it was compiled against.
 *
 * See ERC-7786 for the full specification.
 */
interface IERC7786GatewaySource {
    /**
     * @dev Event emitted when a message is created. If `sendId` is zero, no further processing is necessary. If
     * `sendId` is not zero, then further (gateway specific, and non-standardized) action is required.
     */
    event MessageSent(
        bytes32 indexed sendId,
        bytes sender, // Binary Interoperable Address
        bytes recipient, // Binary Interoperable Address
        bytes payload,
        uint256 value,
        bytes[] attributes
    );

    /// @dev This error is thrown when a message creation fails because of an unsupported attribute being specified.
    error UnsupportedAttribute(bytes4 selector);

    /// @dev Getter to check whether an attribute is supported or not.
    function supportsAttribute(bytes4 selector) external view returns (bool);

    /**
     * @dev Endpoint for creating a new message. If the message requires further (gateway specific) processing before
     * it can be sent to the destination chain, then a non-zero `sendId` must be returned. Otherwise, the
     * message MUST be sent and this function must return 0.
     *
     * * MUST emit a {MessageSent} event.
     *
     * If any of the `attributes` is not supported, this function SHOULD revert with an {UnsupportedAttribute} error.
     * Other errors SHOULD revert with errors not specified in ERC-7786.
     */
    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        external
        payable
        returns (bytes32 sendId);
}

interface IERC7786Recipient {
    /**
     * @dev Endpoint for receiving cross-chain message.
     *
     * This function may be called directly by the gateway.
     */
    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        external
        payable
        returns (bytes4);
}

/**
 * @dev Fee-quoting extension for ERC-7786 gateways.
 *
 * ERC-7786 itself does not standardize fee discovery (it is transport-specific). This minimal interface lets a
 * facade expose a uniform `quote` to applications while delegating the actual estimate to the active gateway adapter,
 * which knows the underlying protocol's pricing.
 */
interface IGatewayQuote {
    /// @dev Native fee required to deliver `payload` to `recipient` (an ERC-7930 interoperable address).
    function quote(bytes calldata recipient, bytes calldata payload) external view returns (uint256 nativeFee);

    /// @dev As above, but honoring `attributes` (e.g. a per-message execution gas limit) so the estimate matches
    /// {IERC7786GatewaySource-sendMessage}.
    function quote(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        external
        view
        returns (uint256 nativeFee);
}
