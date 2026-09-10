// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IGatewayQuote} from "./interfaces/IGatewayQuote.sol";

/// @title ERC7786MessengerBase
/// @author Outbe
/// @notice Shared base for intex cross-chain clients that speak to the protocol-agnostic ERC-7786 bridge (the
///         `crosschain` hub's `ERC7786Bridge`). The active transport is selected on the bridge ({setGateway} there).
/// @dev Provides the immutable bridge reference, an ERC-7930 remote-messenger registry keyed by chainId, a
///      relay-float-aware {_send}, a fee {_quoteFee}, and an authenticated {receiveMessage} that dispatches to the
///      abstract {_dispatch}. A base (rather than inlining like intent's single-client Router) avoids duplicating
///      this across the four intex clients (both messengers + both NFT bridge clients).
///
///      Upgrade-safe: the bridge is an implementation immutable, so every upgrade must pass the same bridge to the
///      constructor; the registry lives in erc7201 namespaced storage.
abstract contract ERC7786MessengerBase is IERC7786Recipient {
    using InteroperableAddress for bytes;

    /// @notice The ERC-7786 bridge this client sends through and accepts deliveries from. Fixed at deploy; the
    ///         cross-chain protocol is swapped on the bridge itself (its `setGateway`), not by repointing here.
    IERC7786GatewaySource public immutable BRIDGE;

    /// @custom:storage-location erc7201:outbe.intex.ERC7786MessengerBase
    struct MessengerStorage {
        /// @dev ERC-7930 interoperable address of the matching messenger on a given chainId.
        mapping(uint32 chainId => bytes interop) remoteMessenger;
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.ERC7786MessengerBase")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _MESSENGER_STORAGE_SLOT =
        0x6702aa1076aac9174f7ad82f658a24b43715e5376566adbcf76ac99f64da8e00;

    /// @dev ERC-7786 attribute selector for a per-message destination gas limit. Matches the crosschain hub's
    ///      `GasLimitAttribute.SELECTOR`; redeclared here (not imported) to keep the intex build hub-decoupled.
    bytes4 private constant _GAS_LIMIT_SELECTOR = bytes4(keccak256("executionGasLimit(uint256)"));

    event RemoteMessengerRegistered(uint32 indexed chainId, bytes interop);

    error InvalidBridge();
    error UnauthorizedBridge(address caller);
    error UnauthorizedSourceMessenger(uint32 chainId, bytes sender);
    error RemoteMessengerNotSet(uint32 chainId);
    error RemoteMessengerChainMismatch(uint32 chainId, uint256 embeddedChainId);
    error NotEnoughNative(uint256 balance);
    error MsgValueBelowFee(uint256 provided, uint256 required);
    error RefundFailed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address bridge_) {
        if (bridge_ == address(0)) revert InvalidBridge();
        BRIDGE = IERC7786GatewaySource(bridge_);
    }

    function _s() private pure returns (MessengerStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            $.slot := _MESSENGER_STORAGE_SLOT
        }
    }

    // --- Remote messenger registry ---

    /// @notice ERC-7930 interoperable address of the matching messenger on `chainId` (empty if unregistered).
    /// @param chainId Destination/source EVM chainId (the bridge maps chainId to its transport id).
    /// @return The registered interoperable address, or empty bytes.
    function remoteMessenger(uint32 chainId) external view returns (bytes memory) {
        return _s().remoteMessenger[chainId];
    }

    /// @dev Registers (or clears, with empty bytes) the matching messenger on `chainId`. Auth is the concrete's
    ///      responsibility (AccessControl lives there).
    function _setRemoteMessenger(uint32 chainId, bytes calldata interop) internal {
        // Inbound auth derives the key from the sender's own bytes, so the interop must embed the same chainId as
        // the key - a mismatch would silently blackhole every message from that chain.
        if (interop.length != 0) {
            (uint256 embedded,) = interop.parseEvmV1Calldata();
            require(embedded == chainId, RemoteMessengerChainMismatch(chainId, embedded));
        }
        _s().remoteMessenger[chainId] = interop;
        emit RemoteMessengerRegistered(chainId, interop);
    }

    /// @dev Registered interoperable address of the matching messenger on `chainId`; reverts if never set.
    function _remoteMessenger(uint32 chainId) internal view returns (bytes memory interop) {
        interop = _s().remoteMessenger[chainId];
        require(interop.length != 0, RemoteMessengerNotSet(chainId));
    }

    // --- Outbound ---

    /// @dev Sends `payload` to the matching messenger on `dstChainId` through the bridge, funding the native fee:
    ///        * relay-funded (`msg.value == 0`): a chain-native module that cannot attach value triggered the send;
    ///          pay the quoted fee from the contract's native float.
    ///        * entry-funded (`msg.value > 0`): require the value covers the fee and refund the excess to the caller,
    ///          so an entry caller's buffer never silently seeds (or drains) the relay float.
    /// @param dstChainId Destination EVM chainId.
    /// @param payload Encoded message body delivered verbatim to the remote messenger.
    /// @param gasLimit Destination execution gas for the message (0 = let the active gateway use its default).
    /// @return sendId The bridge's send identifier.
    function _send(uint32 dstChainId, bytes memory payload, uint256 gasLimit) internal returns (bytes32) {
        bytes memory recipient = _remoteMessenger(dstChainId);
        bytes[] memory attributes = _gasAttributes(gasLimit);
        uint256 fee = IGatewayQuote(address(BRIDGE)).quote(recipient, payload, attributes);

        if (msg.value == 0) {
            if (address(this).balance < fee) revert NotEnoughNative(address(this).balance);
        } else {
            if (msg.value < fee) revert MsgValueBelowFee(msg.value, fee);
            uint256 refund = msg.value - fee;
            if (refund > 0) {
                // slither-disable-next-line arbitrary-send-eth
                (bool ok,) = msg.sender.call{value: refund}("");
                if (!ok) revert RefundFailed();
            }
        }

        return BRIDGE.sendMessage{value: fee}(recipient, payload, attributes);
    }

    /// @dev Native fee to deliver `payload` to the matching messenger on `dstChainId` with `gasLimit` destination gas.
    function _quoteFee(uint32 dstChainId, bytes memory payload, uint256 gasLimit) internal view returns (uint256) {
        return IGatewayQuote(address(BRIDGE)).quote(_remoteMessenger(dstChainId), payload, _gasAttributes(gasLimit));
    }

    /// @dev Wraps `gasLimit` as the single executionGasLimit ERC-7786 attribute (empty array when 0).
    function _gasAttributes(uint256 gasLimit) private pure returns (bytes[] memory attrs) {
        if (gasLimit == 0) return new bytes[](0);
        attrs = new bytes[](1);
        attrs[0] = abi.encodeWithSelector(_GAS_LIMIT_SELECTOR, gasLimit);
    }

    // --- Inbound ---

    /// @inheritdoc IERC7786Recipient
    /// @dev Called by the {BRIDGE} with a message from the matching messenger on the source chain. Authenticates the
    ///      caller (the bridge) and the inner `sender` (the registered peer for its chainId) before dispatching. The
    ///      bridge already deduplicates and rolls back on revert, so a premature message simply reverts here and is
    ///      redelivered by the transport once its prerequisite has landed.
    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        public
        payable
        virtual
        returns (bytes4)
    {
        require(msg.sender == address(BRIDGE), UnauthorizedBridge(msg.sender));

        (uint256 srcChainId,) = sender.parseEvmV1Calldata();
        // Only uint32 chainIds are supported (the registry key); an out-of-range source is rejected outright.
        uint32 chainId = SafeCast.toUint32(srcChainId);

        bytes memory expected = _s().remoteMessenger[chainId];
        require(
            expected.length != 0 && keccak256(sender) == keccak256(expected),
            UnauthorizedSourceMessenger(chainId, sender)
        );

        _dispatch(chainId, receiveId, payload);
        return IERC7786Recipient.receiveMessage.selector;
    }

    /// @dev Handles an authenticated inbound `payload` from the matching messenger on `srcChainId`.
    /// @param srcChainId Source EVM chainId the message was authenticated against.
    /// @param receiveId Bridge-assigned unique message id (binds source bridge + nonce-bearing payload); usable as an
    ///        idempotency/parking key by clients that isolate per-item work (e.g. the NFT bridge clients).
    /// @param payload Encoded message body delivered verbatim from the remote messenger.
    function _dispatch(uint32 srcChainId, bytes32 receiveId, bytes calldata payload) internal virtual;

    /// @notice Accept native to pre-fund the relay float (and receive any bridge fee refunds).
    receive() external payable {}
}
