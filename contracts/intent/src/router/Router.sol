// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {BaseRouter} from "./BaseRouter.sol";
import {RouterMessage} from "../libs/RouterMessage.sol";
import {TypeCasts} from "../libs/TypeCasts.sol";
import {IGatewayQuote} from "../interfaces/IGatewayQuote.sol";

/**
 * @title Router
 * @notice Auction-based ERC-7683 router that speaks to a protocol-agnostic ERC-7786 bridge (the `crosschain`
 *         hub's `ERC7786Bridge`) instead of embedding a specific transport.
 * @dev Composition over inheritance: the messaging protocol (LayerZero, Hyperlane, ...) is selected on the bridge
 *      ({setGateway} there); this router never changes. All settlement logic is inherited from {BaseRouter}; only the
 *      cross-chain wiring lives here:
 *        - outbound: {_dispatchSettleCrossChain}/{_dispatchRefundCrossChain} via `bridge.sendMessage`;
 *        - inbound: {receiveMessage} (called by the bridge) -> {_handleSettleOrder}/{_handleRefundOrder};
 *        - `domain == chainId`, so no protocol id translation lives here (the hub's adapters map chainId<->eid/domain).
 *
 *      The matching Router on each destination must be registered via {setRemoteRouter} (explicit per-chain wiring,
 *      like LayerZero peers / Hyperlane enrolled routers); sending to an unregistered domain reverts.
 */
contract Router is BaseRouter, IERC7786Recipient {
    using InteroperableAddress for bytes;

    /// @notice The ERC-7786 bridge this router sends through and accepts deliveries from. Fixed at deploy; the
    ///         cross-chain protocol is swapped on the bridge itself (its `setGateway`), not by repointing here.
    IERC7786GatewaySource public immutable bridge;

    /// @notice ERC-7930 interoperable address of the matching Router on a given domain (domain == chainId).
    mapping(uint32 domain => bytes recipient) public remoteRouters;

    /// @notice Maximum orders processed per inbound message; bounds the loop's gas so an oversized
    ///         batch cannot make delivery un-executable.
    uint256 public constant MAX_BATCH = 100;

    event RemoteRouterRegistered(uint32 indexed domain, bytes recipient);

    error InvalidBridge();
    error UnauthorizedBridge(address caller);
    error RemoteRouterNotSet(uint32 domain);
    error BatchTooLarge(uint256 length);

    constructor(address _bridge, address _owner, address _compact, bytes12 _lockTag, address _escrow, address _auction)
        Ownable(_owner)
        BaseRouter(_compact, _lockTag, _escrow, _auction)
    {
        if (_bridge == address(0)) revert InvalidBridge();
        bridge = IERC7786GatewaySource(_bridge);
    }

    // ============ Configuration ============

    /// @notice Points the order-opening gate at a Whitelist registry; zero address opens it.
    function setWhitelist(address registry) external onlyOwner {
        _setWhitelist(registry);
    }

    /// @notice TEMPORARY: recovers open orders' inputs to the owner when a remote chain is down and
    ///         no delivery can release them.
    /// @dev TODO: remove before production - it also pays out orders a solver already filled.
    function emergencyWithdraw(bytes32[] calldata orderIds) external onlyOwner {
        for (uint256 i = 0; i < orderIds.length; i++) {
            _emergencyWithdraw(orderIds[i], owner());
        }
    }

    /// @notice Registers the matching Router on `domain`. Pass empty bytes to remove it.
    /// @param interop ERC-7930 interoperable address of the remote Router (encodes chainId + address).
    function setRemoteRouter(uint32 domain, bytes calldata interop) external onlyOwner {
        remoteRouters[domain] = interop;
        emit RemoteRouterRegistered(domain, interop);
    }

    // ============ Messaging - outbound ============

    function _dispatchSettleCrossChain(
        uint32 _originDomain,
        bytes32[] memory _orderIds,
        bytes[] memory _ordersFillerData
    ) internal override {
        _send(_originDomain, RouterMessage.encodeSettle(_orderIds, _ordersFillerData));
    }

    function _dispatchRefundCrossChain(uint32 _originDomain, bytes32[] memory _orderIds) internal override {
        _send(_originDomain, RouterMessage.encodeRefund(_orderIds));
    }

    /// @dev Quotes the native fee the bridge needs to deliver `payload` to `_destinationDomain`.
    function quote(uint32 _destinationDomain, bytes calldata payload) external view returns (uint256) {
        return IGatewayQuote(address(bridge)).quote(_remoteRouter(_destinationDomain), payload);
    }

    // ============ Messaging - inbound ============

    /// @inheritdoc IERC7786Recipient
    /// @dev Called by {bridge} with a message from the matching Router on the source chain. `sender` is the ERC-7930
    /// interoperable address of that Router; the source chainId is used directly as the origin domain.
    function receiveMessage(
        bytes32,
        /*receiveId*/
        bytes calldata sender,
        bytes calldata payload
    )
        external
        payable
        returns (bytes4)
    {
        require(msg.sender == address(bridge), UnauthorizedBridge(msg.sender));

        (uint256 srcChainId, address srcRouter) = sender.parseEvmV1Calldata();
        uint32 originDomain = uint32(srcChainId);
        bytes32 messageSender = TypeCasts.addressToBytes32(srcRouter);

        (bool isSettle, bytes32[] memory orderIds, bytes[] memory ordersFillerData) = RouterMessage.decode(payload);
        if (orderIds.length > MAX_BATCH) revert BatchTooLarge(orderIds.length);
        for (uint256 i = 0; i < orderIds.length; i++) {
            if (isSettle) {
                _handleSettleOrder(originDomain, messageSender, orderIds[i], abi.decode(ordersFillerData[i], (bytes32)));
            } else {
                _handleRefundOrder(originDomain, messageSender, orderIds[i]);
            }
        }
        return IERC7786Recipient.receiveMessage.selector;
    }

    // ============ Local domain ============

    function _localDomain() internal view virtual override returns (uint32) {
        return uint32(block.chainid);
    }

    // ============ Internal ============

    function _send(uint32 _domain, bytes memory _payload) internal {
        bridge.sendMessage{value: msg.value}(_remoteRouter(_domain), _payload, new bytes[](0));
    }

    /// @dev ERC-7930 address of the matching Router on `_domain`; reverts if it was never registered.
    function _remoteRouter(uint32 _domain) internal view returns (bytes memory recipient) {
        recipient = remoteRouters[_domain];
        require(recipient.length != 0, RemoteRouterNotSet(_domain));
    }
}
