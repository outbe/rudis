// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

/**
 * @dev Minimal Hyperlane interfaces, vendored locally (single source of truth for cross-chain interfaces, like
 * {IERC7786}). Only the subset used by {HyperlaneGatewayAdapter} is declared; selectors match Hyperlane's core
 * contracts so calls interoperate with the real Mailbox.
 *
 * See https://docs.hyperlane.xyz for the full specification.
 */
interface IMailbox {
    /// @dev Local Hyperlane domain id of this mailbox.
    function localDomain() external view returns (uint32);

    /// @dev Dispatches a message to `recipientAddress` on `destinationDomain` using the default hook. Returns the
    /// message id. The native fee (see {quoteDispatch}) must be supplied as `msg.value`.
    function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        external
        payable
        returns (bytes32 messageId);

    /// @dev Native fee required by {dispatch} for the same arguments.
    function quoteDispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        external
        view
        returns (uint256 fee);

    /// @dev {dispatch} variant carrying post-dispatch hook `metadata` (e.g. a per-message destination gas
    /// override via StandardHookMetadata). The native fee (see the matching {quoteDispatch}) must be `msg.value`.
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata
    ) external payable returns (bytes32 messageId);

    /// @dev Native fee required by the metadata-carrying {dispatch} for the same arguments.
    function quoteDispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata
    ) external view returns (uint256 fee);
}

interface IMessageRecipient {
    /// @dev Called by the local Mailbox to deliver a verified message from `_origin`/`_sender`.
    function handle(uint32 _origin, bytes32 _sender, bytes calldata _message) external payable;
}
