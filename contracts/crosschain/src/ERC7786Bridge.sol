// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {IERC7786GatewaySource, IERC7786Recipient, IGatewayQuote} from "./interfaces/IERC7786.sol";

/**
 *
 * NOTE: switching a gateway (the default or a per-chain override) drops messages already in flight from the affected
 * chain through the previous one: they are rejected on arrival ({ERC7786BridgeUnauthorizedGateway}) and never execute.
 * Recovery is by re-sending from the source through the new gateway, which is safe against double-execution because
 * the in-flight message never executes.
 */
contract ERC7786Bridge is IERC7786GatewaySource, IERC7786Recipient, IGatewayQuote, Ownable, Pausable {
    using InteroperableAddress for bytes;

    event MessageExecuted(bytes32 indexed receiveId, address indexed recipient);
    event GatewayUpdated(address indexed gateway);
    event ChainGatewayUpdated(uint256 indexed chainId, address indexed gateway);
    event RemoteRegistered(bytes remote);

    error ERC7786BridgeUnauthorizedGateway(address caller);
    error ERC7786BridgeInvalidCrosschainSender();
    error ERC7786BridgeAlreadyExecuted();
    error ERC7786BridgeRemoteNotRegistered(bytes2 chainType, bytes chainReference);
    error ERC7786BridgeGatewayNotSet();
    error ERC7786BridgeInvalidExecutionReturnValue();

    // =================================================== Storage ===================================================

    /// @dev Address of the matching router on a given chain (keyed by ERC-7930 chain type and reference).
    mapping(bytes2 chainType => mapping(bytes chainReference => bytes addr)) private _remotes;

    /// @dev Messages already delivered to their recipient, keyed by keccak256(sender, wrapped payload).
    mapping(bytes32 id => bool executed) private _executed;

    /// @dev The default gateway: used for any chain without a per-chain override.
    address private _activeGateway;

    /// @dev Per-chain gateway override, for outbound sends to and inbound trust from that chain. Zero means "use the
    /// default gateway".
    mapping(uint256 chainId => address gateway) private _gateways;

    /// @dev Nonce for message deduplication (internal)
    uint256 private _nonce;

    constructor(address owner_, address gateway_) Ownable(owner_) {
        if (gateway_ != address(0)) _setGateway(gateway_);
    }

    // ============================================ IERC7786GatewaySource ============================================

    /// @inheritdoc IERC7786GatewaySource
    /// @dev Delegates to the default gateway, which owns the set of supported attributes.
    function supportsAttribute(bytes4 selector) public view virtual returns (bool) {
        address gateway = getGateway();
        return gateway != address(0) && IERC7786GatewaySource(gateway).supportsAttribute(selector);
    }

    /// @inheritdoc IERC7786GatewaySource
    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        public
        payable
        virtual
        whenNotPaused
        returns (bytes32 sendId)
    {
        (uint256 dstChainId,) = recipient.parseEvmV1Calldata();
        address gateway = getGateway(dstChainId);
        require(gateway != address(0), ERC7786BridgeGatewayNotSet());

        // address of the remote bridge, revert if not registered
        bytes memory bridge = getRemoteBridge(recipient);
        bytes memory sender = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);

        // wrapping the payload
        bytes memory wrappedPayload = abi.encode(++_nonce, sender, recipient, payload);

        // Post on the active gateway, forwarding any native fee (fee-bearing transports charge per message).
        bytes32 id = IERC7786GatewaySource(gateway).sendMessage{value: msg.value}(bridge, wrappedPayload, attributes);
        sendId = id == bytes32(0) ? bytes32(0) : keccak256(abi.encode(gateway, id));

        emit MessageSent(sendId, sender, recipient, payload, msg.value, attributes);
    }

    // ============================================== IGatewayQuote ==============================================

    /// @inheritdoc IGatewayQuote
    /// @dev Quotes the native fee {sendMessage} would require for the same `recipient`/`payload`, by delegating to the
    /// recipient chain's gateway. The payload is wrapped exactly as in {sendMessage} so the quoted message size matches.
    function quote(bytes calldata recipient, bytes calldata payload) public view virtual returns (uint256 nativeFee) {
        (uint256 dstChainId,) = recipient.parseEvmV1Calldata();
        address gateway = getGateway(dstChainId);
        require(gateway != address(0), ERC7786BridgeGatewayNotSet());
        bytes memory bridge = getRemoteBridge(recipient);
        bytes memory sender = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        bytes memory wrappedPayload = abi.encode(_nonce + 1, sender, recipient, payload);
        return IGatewayQuote(gateway).quote(bridge, wrappedPayload);
    }

    /// @dev As {quote}, forwarding `attributes` so the estimate honors per-message options (e.g. gas).
    function quote(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        public
        view
        virtual
        returns (uint256 nativeFee)
    {
        (uint256 dstChainId,) = recipient.parseEvmV1Calldata();
        address gateway = getGateway(dstChainId);
        require(gateway != address(0), ERC7786BridgeGatewayNotSet());
        bytes memory bridge = getRemoteBridge(recipient);
        bytes memory sender = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        bytes memory wrappedPayload = abi.encode(_nonce + 1, sender, recipient, payload);
        return IGatewayQuote(gateway).quote(bridge, wrappedPayload, attributes);
    }

    // ============================================== IERC7786Recipient ==============================================

    /**
     * @inheritdoc IERC7786Recipient
     *
     * @dev Delivers a message to its final recipient. Only the source chain's gateway may call this; the cross-chain
     * `sender` must be the registered bridge on the source chain.
     *
     * Reverts if the caller is not the source chain's gateway, if the message does not originate from the registered
     * bridge, if it was already executed, or if the recipient reverts / returns an invalid value. On a recipient revert the
     * whole call reverts (so the deduplication flag is rolled back) and the message stays retryable via the
     * transport's own redelivery.
     */
    function receiveMessage(
        bytes32,
        /*receiveId*/
        bytes calldata sender,
        bytes calldata payload
    )
        public
        payable
        virtual
        whenNotPaused
        returns (bytes4)
    {
        // Only the source chain's gateway may deliver, and only from the registered bridge on the source chain.
        (uint256 srcChainId,) = sender.parseEvmV1Calldata();
        require(msg.sender == getGateway(srcChainId), ERC7786BridgeUnauthorizedGateway(msg.sender));
        require(keccak256(getRemoteBridge(sender)) == keccak256(sender), ERC7786BridgeInvalidCrosschainSender());

        // Deduplicate. The id binds the source bridge (sender) and the wrapped payload (which carries the nonce).
        bytes32 id = keccak256(abi.encode(sender, payload));
        require(!_executed[id], ERC7786BridgeAlreadyExecuted());
        // Effects before interaction (CEI); rolled back with the tx if the recipient reverts, leaving it retryable.
        _executed[id] = true;

        (, bytes memory originalSender, bytes memory recipient, bytes memory unwrappedPayload) =
            abi.decode(payload, (uint256, bytes, bytes, bytes));

        (, address target) = recipient.parseEvmV1();
        bytes4 magic = IERC7786Recipient(target).receiveMessage(id, originalSender, unwrappedPayload);
        require(magic == IERC7786Recipient.receiveMessage.selector, ERC7786BridgeInvalidExecutionReturnValue());

        emit MessageExecuted(id, target);
        return IERC7786Recipient.receiveMessage.selector;
    }

    // =================================================== Getters ===================================================

    function getGateway() public view virtual returns (address) {
        return _activeGateway;
    }

    /// @dev Gateway for `chainId`: the per-chain override when set, the default gateway otherwise.
    function getGateway(uint256 chainId) public view virtual returns (address) {
        address gateway = _gateways[chainId];
        return gateway == address(0) ? _activeGateway : gateway;
    }

    function getRemoteBridge(bytes memory chain) public view virtual returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference,) = chain.parseV1();
        return getRemoteBridge(chainType, chainReference);
    }

    function getRemoteBridge(bytes2 chainType, bytes memory chainReference) public view virtual returns (bytes memory) {
        bytes memory addr = _remotes[chainType][chainReference];
        require(bytes(addr).length != 0, ERC7786BridgeRemoteNotRegistered(chainType, chainReference));
        return InteroperableAddress.formatV1(chainType, chainReference, addr);
    }

    // =================================================== Setters ===================================================

    function setGateway(address gateway) public virtual onlyOwner {
        _setGateway(gateway);
    }

    /// @dev Sets the gateway override for `chainId`. The zero address clears it back to the default gateway.
    function setGateway(uint256 chainId, address gateway) public virtual onlyOwner {
        _gateways[chainId] = gateway;
        emit ChainGatewayUpdated(chainId, gateway);
    }

    function registerRemoteBridge(bytes calldata bridge) public virtual onlyOwner {
        _registerRemoteBridge(bridge);
    }

    function pause() public virtual onlyOwner {
        _pause();
    }

    function unpause() public virtual onlyOwner {
        _unpause();
    }

    // ================================================== Internal ===================================================

    function _setGateway(address gateway) internal virtual {
        _activeGateway = gateway;
        emit GatewayUpdated(gateway);
    }

    function _registerRemoteBridge(bytes calldata bridge) internal virtual {
        (bytes2 chainType, bytes calldata chainReference, bytes calldata addr) = bridge.parseV1Calldata();
        _remotes[chainType][chainReference] = addr;
        emit RemoteRegistered(bridge);
    }
}
