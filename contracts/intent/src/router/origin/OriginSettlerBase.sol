// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {TypeCasts} from "../../libs/TypeCasts.sol";
import {OrderStatusStorage} from "../common/OrderStatusStorage.sol";
import {RouterAccessors} from "../common/RouterAccessors.sol";

import {OnchainCrossChainOrder, ResolvedCrossChainOrder} from "../../interfaces/OrderTypes.sol";
import {IOriginSettler} from "../../interfaces/IOriginSettler.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IWhitelist, WhitelistUpdated, requireWhitelisted} from "@shared/Whitelist.sol";

/**
 * @title OriginSettlerBase
 * @notice Base implementation for origin chain settlement contracts
 * @dev Handles order creation (open) and resolution on the origin chain
 */
abstract contract OriginSettlerBase is OrderStatusStorage, RouterAccessors, IOriginSettler {
    using SafeERC20 for IERC20;

    // ============ Constants ============

    /// @notice Minimum lead time an order's deadline must have over its creation block.
    ///         Covers the auction (commit + reveal) plus the winning solver's claim + fill;
    ///         a deadline shorter than this leaves no time to settle and is rejected at open().
    uint256 public constant MIN_ORDER_DURATION = 30 seconds;

    // ============ Public Storage ============

    /// @notice Tracks the used nonces for each address
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    /// @notice Stores the resolved orders by their ID
    mapping(bytes32 orderId => bytes orderData) public openOrders;

    /// @notice Registry gating who may open orders. Zero address leaves the gate open.
    IWhitelist public whitelist;

    // ============ Events ============

    /// @notice Emitted when a nonce is invalidated for an address
    event NonceInvalidation(address indexed owner, uint256 nonce);

    // ============ Internal Configuration ============

    /// @dev Points the order-opening gate at `registry`, or opens it when `registry` is zero.
    ///      Expose behind the inheriting contract's own access control.
    function _setWhitelist(address registry) internal {
        emit WhitelistUpdated(address(whitelist), registry);
        whitelist = IWhitelist(registry);
    }

    // ============ External Functions ============

    /**
     * @notice Opens a cross-chain order
     * @dev To be called by the user. Emits the Open event
     * @param _order The OnchainCrossChainOrder definition
     */
    function open(OnchainCrossChainOrder calldata _order) external payable {
        requireWhitelisted(whitelist, msg.sender);

        // The deadline must leave room to run the auction and let the winner claim + fill before it
        // expires. MIN_ORDER_DURATION is strictly positive, so this also rejects past deadlines.
        if (_order.fillDeadline < block.timestamp + MIN_ORDER_DURATION) revert InvalidFillDeadline();

        (ResolvedCrossChainOrder memory resolvedOrder, bytes32 orderId, uint256 nonce) = _resolveOrder(_order);

        openOrders[orderId] = abi.encode(_order.orderDataType, resolvedOrder.fillInstructions[0].originData);
        orderStatus[orderId] = OPENED;
        _useNonce(msg.sender, nonce);

        ITheCompact compact = _compact();
        bytes12 lockTag = _lockTag();
        uint256 totalValue;

        for (uint256 i = 0; i < resolvedOrder.minReceived.length; i++) {
            address token = TypeCasts.bytes32ToAddress(resolvedOrder.minReceived[i].token);
            uint256 amount = resolvedOrder.minReceived[i].amount;

            if (token == address(0)) {
                totalValue += amount;
            } else {
                // Pull tokens from user then deposit into The Compact
                // Settler receives ERC6909 receipt representing the resource lock
                IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
                IERC20(token).forceApprove(address(compact), amount);
                compact.depositERC20(token, lockTag, amount, address(this));
            }
        }

        if (msg.value != totalValue) revert InvalidNativeAmount();

        // Deposit native ETH into The Compact
        if (totalValue > 0) {
            compact.depositNative{value: totalValue}(lockTag, address(this));
        }

        emit Open(orderId, resolvedOrder);
    }

    /**
     * @notice Resolves a specific OnchainCrossChainOrder into a generic ResolvedCrossChainOrder
     * @param _order The OnchainCrossChainOrder definition
     * @return _resolvedOrder ResolvedCrossChainOrder hydrated order data
     */
    function resolve(OnchainCrossChainOrder calldata _order)
        public
        view
        returns (ResolvedCrossChainOrder memory _resolvedOrder)
    {
        (_resolvedOrder,,) = _resolveOrder(_order);
    }

    /**
     * @notice Invalidates a nonce for the user calling the function
     * @param _nonce The nonce to invalidate
     */
    function invalidateNonces(uint256 _nonce) external {
        _useNonce(msg.sender, _nonce);
        emit NonceInvalidation(msg.sender, _nonce);
    }

    /**
     * @notice Checks whether a given nonce is valid
     * @param _from The address whose nonce validity is being checked
     * @param _nonce The nonce to check
     * @return isValid True if the nonce is valid, false otherwise
     */
    function isValidNonce(address _from, uint256 _nonce) external view returns (bool) {
        return !usedNonces[_from][_nonce];
    }

    // ============ Internal Functions ============

    /**
     * @notice Marks a nonce as used
     * @param _from The address for which the nonce is being used
     * @param _nonce The nonce to mark as used
     */
    function _useNonce(address _from, uint256 _nonce) internal {
        if (usedNonces[_from][_nonce]) revert InvalidNonce();
        usedNonces[_from][_nonce] = true;
    }

    /**
     * @notice Resolves an OnchainCrossChainOrder into a ResolvedCrossChainOrder
     * @dev To be implemented by the inheriting contract
     * @param _order The OnchainCrossChainOrder to resolve
     * @return _resolvedOrder A ResolvedCrossChainOrder with hydrated data
     * @return _orderId The unique identifier for the order
     * @return _nonce The nonce associated with the order
     */
    function _resolveOrder(OnchainCrossChainOrder memory _order)
        internal
        view
        virtual
        returns (ResolvedCrossChainOrder memory _resolvedOrder, bytes32 _orderId, uint256 _nonce);
}
