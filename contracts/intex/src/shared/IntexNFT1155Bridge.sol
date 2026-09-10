// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1155Bridgeable} from "./interfaces/IERC1155Bridgeable.sol";
import {
    IIntexNFT1155Bridge,
    SendParam,
    BatchSendParam,
    MultiRecipientSendParam
} from "./interfaces/IIntexNFT1155Bridge.sol";
import {IntexNFT1155BridgeCodec} from "./libs/IntexNFT1155BridgeCodec.sol";
import {ERC7786MessengerBase} from "./ERC7786MessengerBase.sol";
import {IntexGas} from "./libs/IntexGas.sol";

/// @title IntexNFT1155Bridge
/// @author Outbe
/// @notice Batch cross-chain ERC-1155 adapter over the protocol-agnostic ERC-7786 bridge: burns on the source and
///         mints on the paired adapter registered as the remote messenger for a chainId.
/// @dev UUPS upgradeable; the bridge and bridged token are implementation immutables. Modes: single-recipient batch
///      and multi-recipient.
contract IntexNFT1155Bridge is
    IIntexNFT1155Bridge,
    ERC7786MessengerBase,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    UUPSUpgradeable
{
    uint16 public constant SEND = IntexNFT1155BridgeCodec.SEND;
    uint16 public constant SEND_MULTI = IntexNFT1155BridgeCodec.SEND_MULTI;
    uint8 public constant BODY_VERSION_V2 = IntexNFT1155BridgeCodec.BODY_VERSION_V2;
    uint256 public constant MAX_BATCH_SIZE = IntexNFT1155BridgeCodec.MAX_BATCH_SIZE;

    /// @notice The bridgeable ERC-1155 this adapter burns on send and mints on receive.
    IERC1155Bridgeable public immutable token;

    /// @notice Snapshot of one batch item whose `token.crosschainMint` reverted; `exists` distinguishes
    ///         never-failed from failed-and-retried.
    struct FailedCrosschainMint {
        address to;
        uint256 tokenId;
        uint256 amount;
        uint32 srcChainId;
        bytes reason;
        bool exists;
    }

    /// @custom:storage-location erc7201:outbe.intex.IntexNFT1155Bridge
    struct IntexNFT1155BridgeStorage {
        /// @dev Inbound message ids already minted (defence-in-depth; the hub also dedups).
        mapping(bytes32 receiveId => bool) processed;
        /// @dev Per-message map of items whose `token.crosschainMint` reverted.
        mapping(bytes32 receiveId => mapping(uint256 idx => FailedCrosschainMint)) failedCrosschainMints;
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.IntexNFT1155Bridge")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT = 0x769097ec453d253ed110328ac911e291d0940836557f2ebb5d6ffb80fa001500;

    function _bs() private pure returns (IntexNFT1155BridgeStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            $.slot := _STORAGE_SLOT
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address _token, address bridge_) ERC7786MessengerBase(bridge_) {
        if (_token == address(0)) revert ZeroAddress("token");
        token = IERC1155Bridgeable(_token);
        _disableInitializers();
    }

    /// @notice Initializes the proxy admin.
    function initialize(address _delegate) external initializer {
        if (_delegate == address(0)) revert ZeroAddress("delegate");
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _delegate);
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Failed crosschainMint snapshot for item `idx` of the message `receiveId`.
    function failedCrosschainMints(bytes32 receiveId, uint256 idx)
        external
        view
        returns (address to, uint256 tokenId, uint256 amount, bytes memory reason, bool exists)
    {
        FailedCrosschainMint storage f = _bs().failedCrosschainMints[receiveId][idx];
        return (f.to, f.tokenId, f.amount, f.reason, f.exists);
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        return interfaceId == type(IIntexNFT1155Bridge).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IIntexNFT1155Bridge
    function setRemoteMessenger(uint32 chainId, bytes calldata interop) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setRemoteMessenger(chainId, interop);
    }

    // --- Single transfer ---
    /// @inheritdoc IIntexNFT1155Bridge
    function quoteSend(SendParam calldata _sendParam) external view returns (uint256) {
        return _quoteFee(_sendParam.dstChainId, _buildSingleMsg(_sendParam), IntexGas.nftMint(1));
    }

    /// @inheritdoc IIntexNFT1155Bridge
    function send(SendParam calldata _sendParam) external payable nonReentrant returns (bytes32 sendId) {
        bytes memory message = _buildSingleMsg(_sendParam);
        token.crosschainBurn(msg.sender, _toAddress(_sendParam.to), _sendParam.tokenId, _sendParam.amount);
        sendId = _send(_sendParam.dstChainId, message, IntexGas.nftMint(1));
        emit Bridged(sendId, _sendParam.dstChainId, msg.sender, _sendParam.tokenId, _sendParam.amount);
    }

    /// @dev `assertAddress` has already rejected anything not address-shaped by the time this narrows one.
    function _toAddress(bytes32 recipient) internal pure returns (address) {
        return address(uint160(uint256(recipient)));
    }

    /// @dev A single transfer is a 1-item `SEND` batch: it shares the batch wire format and receive path.
    function _buildSingleMsg(SendParam calldata _sendParam) internal pure returns (bytes memory) {
        // reject a malformed recipient before burning; the receive path rejects it too
        IntexNFT1155BridgeCodec.assertAddress(_sendParam.to);
        if (_sendParam.to == bytes32(0)) revert InvalidReceiver();
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = _sendParam.tokenId;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = _sendParam.amount;
        return IntexNFT1155BridgeCodec.encodeBatch(
            IntexNFT1155BridgeCodec.BatchPayload({to: _sendParam.to, tokenIds: tokenIds, amounts: amounts})
        );
    }

    // --- Single-recipient batch ---
    /// @inheritdoc IIntexNFT1155Bridge
    function quoteBatchSend(BatchSendParam calldata _sendParam) external view returns (uint256) {
        return
            _quoteFee(_sendParam.dstChainId, _buildBatchMsg(_sendParam), IntexGas.nftMint(_sendParam.tokenIds.length));
    }

    /// @inheritdoc IIntexNFT1155Bridge
    function batchSend(BatchSendParam calldata _sendParam) external payable nonReentrant returns (bytes32 sendId) {
        if (_sendParam.tokenIds.length == 0) revert EmptyBatch();
        if (_sendParam.tokenIds.length != _sendParam.amounts.length) revert ArrayLengthMismatch();

        // Build first: the zero-`to` and `MAX_BATCH_SIZE` guards fail fast before any burn.
        bytes memory message = _buildBatchMsg(_sendParam);
        for (uint256 i = 0; i < _sendParam.tokenIds.length; i++) {
            token.crosschainBurn(msg.sender, _toAddress(_sendParam.to), _sendParam.tokenIds[i], _sendParam.amounts[i]);
        }

        sendId = _send(_sendParam.dstChainId, message, IntexGas.nftMint(_sendParam.tokenIds.length));
        emit BatchBridged(sendId, _sendParam.dstChainId, msg.sender, _sendParam.tokenIds, _sendParam.amounts);
    }

    function _buildBatchMsg(BatchSendParam calldata _sendParam) internal pure returns (bytes memory) {
        IntexNFT1155BridgeCodec.assertAddress(_sendParam.to);
        if (_sendParam.to == bytes32(0)) revert InvalidReceiver();
        if (_sendParam.tokenIds.length > MAX_BATCH_SIZE) {
            revert IntexNFT1155BridgeCodec.BatchTooLarge(_sendParam.tokenIds.length, MAX_BATCH_SIZE);
        }
        return IntexNFT1155BridgeCodec.encodeBatch(
            IntexNFT1155BridgeCodec.BatchPayload({
                to: _sendParam.to, tokenIds: _sendParam.tokenIds, amounts: _sendParam.amounts
            })
        );
    }

    // --- Multi-recipient batch ---
    /// @inheritdoc IIntexNFT1155Bridge
    function quoteMultiSend(MultiRecipientSendParam calldata _sendParam) external view returns (uint256) {
        return
            _quoteFee(_sendParam.dstChainId, _buildMultiMsg(_sendParam), IntexGas.nftMint(_sendParam.recipients.length));
    }

    /// @inheritdoc IIntexNFT1155Bridge
    function multiSend(MultiRecipientSendParam calldata _sendParam)
        external
        payable
        nonReentrant
        returns (bytes32 sendId)
    {
        uint256 len = _sendParam.recipients.length;
        if (len == 0) revert EmptyBatch();
        if (len != _sendParam.tokenIds.length || len != _sendParam.amounts.length) revert ArrayLengthMismatch();

        bytes memory message = _buildMultiMsg(_sendParam);
        for (uint256 i = 0; i < len; i++) {
            IntexNFT1155BridgeCodec.assertAddress(_sendParam.recipients[i]);
            if (_sendParam.recipients[i] == bytes32(0)) revert InvalidReceiver();
            token.crosschainBurn(
                msg.sender, _toAddress(_sendParam.recipients[i]), _sendParam.tokenIds[i], _sendParam.amounts[i]
            );
        }

        sendId = _send(_sendParam.dstChainId, message, IntexGas.nftMint(_sendParam.recipients.length));
        emit MultiBridged(
            sendId, _sendParam.dstChainId, msg.sender, _sendParam.recipients, _sendParam.tokenIds, _sendParam.amounts
        );
    }

    function _buildMultiMsg(MultiRecipientSendParam calldata _sendParam) internal pure returns (bytes memory) {
        if (_sendParam.recipients.length > MAX_BATCH_SIZE) {
            revert IntexNFT1155BridgeCodec.BatchTooLarge(_sendParam.recipients.length, MAX_BATCH_SIZE);
        }
        return IntexNFT1155BridgeCodec.encodeMulti(
            IntexNFT1155BridgeCodec.MultiPayload({
                recipients: _sendParam.recipients, tokenIds: _sendParam.tokenIds, amounts: _sendParam.amounts
            })
        );
    }

    // --- Receive ---
    /// @inheritdoc ERC7786MessengerBase
    /// @dev nonReentrant guards against crosschainMint-callback re-entry.
    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        public
        payable
        override
        nonReentrant
        returns (bytes4)
    {
        return super.receiveMessage(receiveId, sender, payload);
    }

    function _dispatch(uint32 srcChainId, bytes32 receiveId, bytes calldata message) internal override {
        IntexNFT1155BridgeStorage storage $ = _bs();
        if ($.processed[receiveId]) revert AlreadyProcessed(receiveId);
        $.processed[receiveId] = true;

        if (message.length < IntexNFT1155BridgeCodec.HEADER_LEN) {
            revert IntexNFT1155BridgeCodec.InvalidPayloadLength(message.length, IntexNFT1155BridgeCodec.HEADER_LEN);
        }
        uint8 version = uint8(message[0]);
        if (version != BODY_VERSION_V2) revert IntexNFT1155BridgeCodec.UnsupportedBodyVersion(version);
        uint8 msgType = uint8(message[1]);

        if (msgType == SEND) {
            _handleBatchReceive(srcChainId, receiveId, message);
        } else if (msgType == SEND_MULTI) {
            _handleMultiReceive(srcChainId, receiveId, message);
        } else {
            revert UnknownMsgType(msgType);
        }
    }

    function _handleBatchReceive(uint32 srcChainId, bytes32 receiveId, bytes calldata message) internal {
        IntexNFT1155BridgeCodec.BatchPayload memory p = IntexNFT1155BridgeCodec.decodeBatch(message);

        IntexNFT1155BridgeCodec.assertAddress(p.to);
        if (p.to == bytes32(0)) revert InvalidReceiver();
        address toAddress = address(uint160(uint256(p.to)));

        for (uint256 i = 0; i < p.tokenIds.length; i++) {
            _tryCrosschainMintOne(srcChainId, receiveId, i, toAddress, p.tokenIds[i], p.amounts[i]);
        }

        emit BatchReceived(receiveId, srcChainId, toAddress, p.tokenIds, p.amounts);
    }

    function _handleMultiReceive(uint32 srcChainId, bytes32 receiveId, bytes calldata message) internal {
        IntexNFT1155BridgeCodec.MultiPayload memory p = IntexNFT1155BridgeCodec.decodeMulti(message);

        for (uint256 i = 0; i < p.recipients.length; i++) {
            IntexNFT1155BridgeCodec.assertAddress(p.recipients[i]);
            if (p.recipients[i] == bytes32(0)) revert InvalidReceiver();
            address toAddress = address(uint160(uint256(p.recipients[i])));
            _tryCrosschainMintOne(srcChainId, receiveId, i, toAddress, p.tokenIds[i], p.amounts[i]);
        }

        emit MultiReceived(receiveId, srcChainId, p.recipients, p.tokenIds, p.amounts);
    }

    /// @dev Isolate a per-item `token.crosschainMint` revert: park a snapshot for `retryCrosschainMint`
    ///      instead of failing the whole batch.
    function _tryCrosschainMintOne(
        uint32 srcChainId,
        bytes32 receiveId,
        uint256 idx,
        address to,
        uint256 tokenId,
        uint256 amount
    ) internal {
        try this.crosschainMintOne(to, tokenId, amount) {
        // ok
        }
        catch (bytes memory reason) {
            _bs().failedCrosschainMints[receiveId][idx] = FailedCrosschainMint({
                to: to, tokenId: tokenId, amount: amount, srcChainId: srcChainId, reason: reason, exists: true
            });
            emit CrosschainMintFailed(srcChainId, receiveId, idx, to, tokenId, amount, reason);
        }
    }

    /// @notice Self-call shim so a per-item mint revert lands in `_tryCrosschainMintOne`'s catch. Self-only.
    function crosschainMintOne(address to, uint256 tokenId, uint256 amount) external {
        if (msg.sender != address(this)) revert NotSelf();
        token.crosschainMint(to, tokenId, amount);
    }

    /// @notice Permissionless retry of a previously-failed crosschainMint; the entry is cleared on success.
    function retryCrosschainMint(bytes32 receiveId, uint256 idx) external nonReentrant {
        IntexNFT1155BridgeStorage storage $ = _bs();
        FailedCrosschainMint memory f = $.failedCrosschainMints[receiveId][idx];
        if (!f.exists) revert NoSuchFailedCrosschainMint(receiveId, idx);
        delete $.failedCrosschainMints[receiveId][idx];
        token.crosschainMint(f.to, f.tokenId, f.amount);
        emit CrosschainMintRetried(receiveId, idx);
    }

    /// @notice Permissionless reclaim of a batch item the destination gate rejects terminally: re-mints the holder
    ///         on the origin chain via a reverse one-item transfer, the only exit that does not re-hit the
    ///         destination lifecycle gate. Caller-funded; consumes the entry once (CEI delete first).
    /// @param receiveId Inbound message id where the item's crosschainMint is stranded.
    /// @param idx Position of the stranded item in that batch.
    function reclaimToSource(bytes32 receiveId, uint256 idx) external payable nonReentrant returns (bytes32 sendId) {
        IntexNFT1155BridgeStorage storage $ = _bs();
        FailedCrosschainMint memory f = $.failedCrosschainMints[receiveId][idx];
        if (!f.exists) revert NoSuchFailedCrosschainMint(receiveId, idx);
        if (f.srcChainId == 0) revert NoReclaimSource(receiveId, idx);
        delete $.failedCrosschainMints[receiveId][idx];

        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = bytes32(uint256(uint160(f.to)));
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = f.tokenId;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = f.amount;
        bytes memory message = IntexNFT1155BridgeCodec.encodeMulti(
            IntexNFT1155BridgeCodec.MultiPayload({recipients: recipients, tokenIds: tokenIds, amounts: amounts})
        );
        sendId = _send(f.srcChainId, message, IntexGas.nftMint(1));
        emit CrosschainMintReclaimed(receiveId, idx, f.srcChainId, f.to, f.tokenId, f.amount);
    }

    /// @inheritdoc IIntexNFT1155Bridge
    function sweepNative(address payable to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress("to");
        uint256 balance = address(this).balance;
        if (amount > balance) revert NativeBalanceInsufficient(balance, amount);

        // admin-only native recovery; arbitrary destination is intentional
        // slither-disable-next-line arbitrary-send-eth
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeSweepFailed();

        emit NativeSwept(to, amount);
    }
}
