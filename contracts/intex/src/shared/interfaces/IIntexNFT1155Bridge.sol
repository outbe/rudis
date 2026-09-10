// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @notice Parameters for sending a batch of tokens to a SINGLE recipient.
struct BatchSendParam {
    uint32 dstChainId;
    bytes32 to;
    uint256[] tokenIds;
    uint256[] amounts;
}

/// @notice Parameters for sending tokens to MULTIPLE recipients in one transaction.
/// @dev Each recipient can receive different token IDs and amounts.
struct MultiRecipientSendParam {
    uint32 dstChainId;
    bytes32[] recipients;
    uint256[] tokenIds;
    uint256[] amounts;
}

/// @notice Parameters for sending a SINGLE token type to one recipient (encoded as a 1-item batch).
struct SendParam {
    uint32 dstChainId;
    bytes32 to;
    uint256 tokenId;
    uint256 amount;
}

/// @title IIntexNFT1155Bridge
/// @author Outbe
/// @notice Interface for batch cross-chain ERC1155 transfers over the protocol-agnostic ERC-7786 bridge.
/// @dev Supports single-recipient batch and multi-recipient modes. Sends burn on the source and mint on the
///      paired adapter registered as the remote messenger for a
///      chainId. `send*` return the bridge `sendId`; `quote*` return the native fee.
interface IIntexNFT1155Bridge {
    // --- Events ---
    /// @notice Emitted when a batch of tokens is sent to one recipient.
    /// @param sendId Bridge send identifier.
    /// @param dstChainId Destination chainId.
    /// @param from Sender address.
    /// @param tokenIds Array of token IDs sent.
    /// @param amounts Corresponding amounts for each token ID.
    event BatchBridged(
        bytes32 indexed sendId, uint32 dstChainId, address indexed from, uint256[] tokenIds, uint256[] amounts
    );

    /// @notice Emitted when a single token type is sent to one recipient.
    /// @param sendId Bridge send identifier.
    /// @param dstChainId Destination chainId.
    /// @param from Sender address.
    /// @param tokenId Token ID sent.
    /// @param amount Amount sent.
    event Bridged(bytes32 indexed sendId, uint32 dstChainId, address indexed from, uint256 tokenId, uint256 amount);

    /// @notice Emitted when tokens are sent to multiple recipients.
    /// @param sendId Bridge send identifier.
    /// @param dstChainId Destination chainId.
    /// @param from Sender address.
    /// @param recipients Array of recipient addresses (bytes32-encoded).
    /// @param tokenIds Array of token IDs sent.
    /// @param amounts Corresponding amounts for each recipient.
    event MultiBridged(
        bytes32 indexed sendId,
        uint32 dstChainId,
        address indexed from,
        bytes32[] recipients,
        uint256[] tokenIds,
        uint256[] amounts
    );

    /// @notice Emitted when a batch of tokens is received for one recipient.
    /// @param receiveId Bridge message identifier.
    /// @param srcChainId Source chainId.
    /// @param to Recipient address.
    /// @param tokenIds Array of token IDs received.
    /// @param amounts Corresponding amounts for each token ID.
    event BatchReceived(
        bytes32 indexed receiveId, uint32 srcChainId, address indexed to, uint256[] tokenIds, uint256[] amounts
    );

    /// @notice Emitted when tokens are received for multiple recipients.
    /// @param receiveId Bridge message identifier.
    /// @param srcChainId Source chainId.
    /// @param recipients Array of recipient addresses (bytes32-encoded).
    /// @param tokenIds Array of token IDs received.
    /// @param amounts Corresponding amounts for each recipient.
    event MultiReceived(
        bytes32 indexed receiveId, uint32 srcChainId, bytes32[] recipients, uint256[] tokenIds, uint256[] amounts
    );

    /// @notice Emitted when residual pre-funded native tokens are swept to an admin recipient.
    /// @param to Recipient address the native tokens were swept to.
    /// @param amount Amount in wei swept.
    event NativeSwept(address indexed to, uint256 amount);

    /// @notice Emitted when one item in an inbound batch reverts `token.crosschainMint`.
    /// @param srcChainId Source chainId.
    /// @param receiveId Inbound bridge message id.
    /// @param idx Position of the failed item in the original batch.
    /// @param to Recipient address.
    /// @param tokenId ERC-1155 token id.
    /// @param amount Amount that failed to crosschainMint.
    /// @param reason Raw revert bytes from `token.crosschainMint`.
    event CrosschainMintFailed(
        uint32 indexed srcChainId,
        bytes32 indexed receiveId,
        uint256 idx,
        address indexed to,
        uint256 tokenId,
        uint256 amount,
        bytes reason
    );

    /// @notice Emitted when `retryCrosschainMint` successfully mints a previously failed item.
    /// @param receiveId Inbound bridge message id where the crosschainMint originally failed.
    /// @param idx Position of the retried item in the original batch.
    event CrosschainMintRetried(bytes32 indexed receiveId, uint256 indexed idx);

    /// @notice Emitted when a terminally-failed item is reclaimed to its origin chain for re-mint.
    /// @param receiveId Inbound bridge message id whose item was reclaimed.
    /// @param idx Position of the reclaimed item in the original batch.
    /// @param srcChainId Origin chainId the reverse transfer was sent to.
    /// @param to Holder re-minted on the origin chain.
    /// @param tokenId Token ID reclaimed.
    /// @param amount Amount reclaimed.
    event CrosschainMintReclaimed(
        bytes32 indexed receiveId,
        uint256 indexed idx,
        uint32 indexed srcChainId,
        address to,
        uint256 tokenId,
        uint256 amount
    );

    // --- Errors ---
    /// @notice Receiver address is zero.
    error InvalidReceiver();
    /// @notice Array lengths do not match.
    error ArrayLengthMismatch();
    /// @notice Empty batch provided.
    error EmptyBatch();
    /// @notice Native-token sweep transfer failed.
    error NativeSweepFailed();
    /// @notice Native-token balance is insufficient for the requested sweep.
    /// @param available Current contract balance.
    /// @param requested Amount the admin attempted to sweep.
    error NativeBalanceInsufficient(uint256 available, uint256 requested);
    /// @notice Zero address provided.
    /// @param field Field name.
    error ZeroAddress(string field);
    /// @notice Inbound `msgType` is not in the SEND / SEND_MULTI set.
    /// @dev Wire-format reverts (`UnsupportedBodyVersion`, `MalformedAddress`, `BatchTooLarge`,
    ///      `InvalidPayloadLength`, `ArrayLengthMismatch`) are owned by `IntexNFT1155BridgeCodec`.
    /// @param got The unsupported message-type tag received.
    error UnknownMsgType(uint8 got);
    /// @notice Inbound message with this `receiveId` has already been minted.
    /// @param receiveId Inbound bridge message id that was already processed.
    error AlreadyProcessed(bytes32 receiveId);
    /// @notice `crosschainMintOne` was invoked by an external caller; only `address(this)` is allowed.
    /// @dev `crosschainMintOne` is a self-call shim used by the inbound handler to isolate per-item
    ///      `token.crosschainMint` reverts. Exposing it externally would let anyone mint tokens for arbitrary
    ///      recipients.
    error NotSelf();
    /// @notice No failed-crosschainMint entry exists for `(receiveId, idx)`.
    /// @param receiveId Inbound bridge message id being retried.
    /// @param idx Position in the original batch with no parked failed-crosschainMint slot.
    error NoSuchFailedCrosschainMint(bytes32 receiveId, uint256 idx);
    /// @notice Parked entry carries no origin chainId (pre-upgrade entry); reclaim cannot route back.
    /// @param receiveId Inbound bridge message id being reclaimed.
    /// @param idx Position in the original batch.
    error NoReclaimSource(bytes32 receiveId, uint256 idx);

    /// @notice Register (or clear) the matching adapter on `chainId` as an ERC-7930 interoperable address.
    /// @param chainId Destination/source chainId.
    /// @param interop ERC-7930 interoperable address (empty to clear).
    function setRemoteMessenger(uint32 chainId, bytes calldata interop) external;

    /// @notice Sweep residual pre-funded native tokens back to an admin recipient.
    /// @param to Recipient address (must be non-zero).
    /// @param amount Amount in wei to sweep; must be <= contract balance.
    function sweepNative(address payable to, uint256 amount) external;

    // --- Single-recipient batch ---
    /// @notice Quotes the native fee for a batch cross-chain transfer.
    /// @param _sendParam Batch send parameters.
    /// @notice Native fee to send a single token type to one recipient.
    /// @param _sendParam Single send parameters.
    /// @return fee Native fee the bridge requires.
    function quoteSend(SendParam calldata _sendParam) external view returns (uint256 fee);

    /// @notice Sends a single token type to one recipient on another chain. Caller funds the fee via `msg.value`.
    /// @param _sendParam Single send parameters.
    /// @return sendId Bridge send identifier.
    function send(SendParam calldata _sendParam) external payable returns (bytes32 sendId);

    /// @return fee Native fee the bridge requires.
    function quoteBatchSend(BatchSendParam calldata _sendParam) external view returns (uint256 fee);

    /// @notice Sends multiple token types to one recipient on another chain. Caller funds the fee via `msg.value`.
    /// @param _sendParam Batch send parameters.
    /// @return sendId Bridge send identifier.
    function batchSend(BatchSendParam calldata _sendParam) external payable returns (bytes32 sendId);

    // --- Multi-recipient ---
    /// @notice Quotes the native fee for a multi-recipient cross-chain transfer.
    /// @param _sendParam Multi-recipient send parameters.
    /// @return fee Native fee the bridge requires.
    function quoteMultiSend(MultiRecipientSendParam calldata _sendParam) external view returns (uint256 fee);

    /// @notice Sends tokens to multiple recipients on another chain. Caller funds the fee via `msg.value`.
    /// @param _sendParam Multi-recipient send parameters.
    /// @return sendId Bridge send identifier.
    function multiSend(MultiRecipientSendParam calldata _sendParam) external payable returns (bytes32 sendId);
}
