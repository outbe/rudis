// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {OnchainCrossChainOrder} from "../../interfaces/OrderTypes.sol";
import {IAuction} from "../../interfaces/IAuction.sol";
import {ISolverEscrow} from "../../interfaces/ISolverEscrow.sol";
import {OrderData, OrderEncoder} from "../../libs/OrderEncoder.sol";
import {OrderValidator} from "../../libs/OrderValidator.sol";
import {TypeCasts} from "../../libs/TypeCasts.sol";
import {DestinationSettlerBase} from "./DestinationSettlerBase.sol";

/// @title DestinationSettler
/// @notice Destination chain settlement contract for cross-chain swaps with auction
/// @dev Uses external Auction contract via composition (not inheritance)
abstract contract DestinationSettler is DestinationSettlerBase {
    using SafeERC20 for IERC20;

    /// @notice Emitted when slashing collateral on refund fails (e.g. solver revoked the ERC-6909 operator grant).
    ///         The refund itself still completes - slash is best-effort to preserve user-side liveness.
    event SlashSkipped(bytes32 indexed orderId);

    /// @notice Thrown when a settle/refund batch mixes orders from different origin domains.
    ///         The batch is dispatched to a single domain (order [0]'s), so a mixed batch would
    ///         silently mis-route every order whose origin differs and strand its input tokens.
    error MixedOriginDomain(uint32 expected, uint32 got);

    // ========== CLAIM ==========

    /// @notice Claim an order after quoting ends - locks collateral of the winning solver.
    ///         If the winner lacks sufficient collateral, the auction is restarted automatically.
    /// @param _orderId The unique identifier of the order
    /// @param _originData The order data encoded as bytes (OrderData)
    function claimOrder(bytes32 _orderId, bytes calldata _originData) external {
        if (!_isNotProcessed(destinationOrderStatus[_orderId])) revert InvalidOrderStatus();
        if (!_auction().isAuctionEnded(_orderId)) revert IAuction.RevealNotEnded();

        (address winner, uint256 outputAmount) = _auction().getWinner(_orderId);
        OrderData memory orderData = OrderValidator.decodeAndCheck(_originData, _orderId, outputAmount);

        // Check if winner can cover collateral - if not, restart auction
        ISolverEscrow escrow = _solverEscrow();
        if (address(escrow) != address(0)) {
            address outputToken = TypeCasts.bytes32ToAddress(orderData.outputToken);
            if (!escrow.hasMinCollateral(winner, outputToken, outputAmount)) {
                _auction().resetAuction(_orderId, winner);
                return;
            }
        }

        // Collateral is locked before the order is marked CLAIMED: a winner whose collateral cannot
        // be taken into custody forfeits the auction instead of blocking the order.
        if (!_onClaimed(_orderId, winner, _originData)) {
            _auction().resetAuction(_orderId, winner);
            return;
        }

        destinationOrderStatus[_orderId] = CLAIMED;

        emit OrderClaimed(_orderId, winner, outputAmount);
    }

    // ========== FILL ==========

    /// @notice Fills an auction order (called via fill() from DestinationSettlerBase)
    /// @param _orderId The unique identifier of the order
    /// @param _originData The order data encoded as bytes (OrderData)
    function _fillOrder(
        bytes32 _orderId,
        bytes calldata _originData,
        bytes calldata /* _fillerData */
    )
        internal
        virtual
        override
    {
        OrderData memory orderData = OrderEncoder.decode(_originData);

        if (_orderId != OrderEncoder.id(orderData)) revert InvalidOrderId();
        if (block.timestamp > orderData.fillDeadline) revert OrderFillExpired();
        if (orderData.destinationDomain != _localDomain()) revert InvalidOrderDomain();

        (address winner, uint256 outputAmount) = _auction().getWinner(_orderId);
        if (msg.sender != winner) revert NotAWinner();

        address outputToken = TypeCasts.bytes32ToAddress(orderData.outputToken);
        address recipient = TypeCasts.bytes32ToAddress(orderData.recipient);

        if (outputToken == address(0)) {
            if (outputAmount != msg.value) revert InvalidNativeAmount();
            Address.sendValue(payable(recipient), outputAmount);
        } else {
            IERC20(outputToken).safeTransferFrom(msg.sender, recipient, outputAmount);
        }
    }

    // ========== SETTLE ==========

    /// @dev Settles multiple orders by dispatching the settlement instructions.
    function _settleOrders(
        bytes32[] calldata _orderIds,
        bytes[] memory _ordersOriginData,
        bytes[] memory _ordersFillerData
    ) internal override {
        _dispatchSettle(_requireSameOriginDomain(_ordersOriginData), _orderIds, _ordersFillerData);
    }

    // ========== REFUND ==========

    /// @dev Refunds multiple OnchainCrossChain orders by dispatching refund instructions.
    function _refundOrders(OnchainCrossChainOrder[] calldata _orders, bytes32[] memory _orderIds) internal override {
        bytes[] memory ordersData = new bytes[](_orders.length);
        for (uint256 i = 0; i < _orders.length; i++) {
            ordersData[i] = _orders[i].orderData;
        }
        _dispatchRefund(_requireSameOriginDomain(ordersData), _orderIds);
    }

    /// @dev Returns the shared origin domain of a batch, reverting if any order's differs from the
    ///      first. The whole batch dispatches to this one domain, so a mixed batch would silently
    ///      mis-route the divergent orders and strand their input tokens.
    function _requireSameOriginDomain(bytes[] memory _ordersData) private pure returns (uint32 originDomain) {
        originDomain = OrderEncoder.decode(_ordersData[0]).originDomain;
        for (uint256 i = 1; i < _ordersData.length; i++) {
            uint32 got = OrderEncoder.decode(_ordersData[i]).originDomain;
            if (got != originDomain) revert MixedOriginDomain(originDomain, got);
        }
    }

    /// @notice Get order ID for onchain order
    function _getOrderId(OnchainCrossChainOrder calldata _order) internal pure override returns (bytes32) {
        return OrderEncoder.id(OrderEncoder.decode(_order.orderData));
    }

    // ========== COLLATERAL HOOKS ==========

    /// @dev Locks collateral when an order is claimed. The lock takes custody of the winner's
    ///      ERC-6909, which requires a live operator grant; a winner without one cannot be claimed.
    function _onClaimed(bytes32 _orderId, address _solver, bytes calldata _originData)
        internal
        override
        returns (bool)
    {
        ISolverEscrow escrow = _solverEscrow();
        if (address(escrow) == address(0)) return true;

        OrderData memory orderData = OrderEncoder.decode(_originData);
        address outputToken = TypeCasts.bytes32ToAddress(orderData.outputToken);
        (, uint256 outputAmount) = _auction().getWinner(_orderId);
        uint256 collateralAmount = escrow.getCollateralAmount(outputAmount);

        try escrow.lockCollateral(_orderId, _solver, outputToken, collateralAmount) {
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Unlocks collateral when an order is successfully filled
    function _onFilled(bytes32 _orderId) internal override {
        ISolverEscrow escrow = _solverEscrow();
        if (address(escrow) == address(0)) return;
        escrow.unlockCollateral(_orderId);
    }

    /// @dev Slashes collateral when a claimed order expires without being filled.
    ///      Best-effort: a revert is swallowed so the user's refund still proceeds, and the missed
    ///      slash is surfaced via SlashSkipped.
    function _onSlashed(bytes32 _orderId) internal override {
        ISolverEscrow escrow = _solverEscrow();
        if (address(escrow) == address(0)) return;
        try escrow.slashCollateral(_orderId) {}
        catch {
            emit SlashSkipped(_orderId);
        }
    }

    // ========== ABSTRACT - MESSAGING LAYER ==========

    /**
     * @dev Should be implemented by the messaging layer for dispatching a settlement instruction.
     * @param _originDomain The origin domain of the orders.
     * @param _orderIds The IDs of the orders to settle.
     * @param _ordersFillerData The filler data for the orders.
     */
    function _dispatchSettle(uint32 _originDomain, bytes32[] memory _orderIds, bytes[] memory _ordersFillerData)
        internal
        virtual;

    /**
     * @dev Should be implemented by the messaging layer for dispatching a refunding instruction.
     * @param _originDomain The origin domain of the orders.
     * @param _orderIds The IDs of the orders to refund.
     */
    function _dispatchRefund(uint32 _originDomain, bytes32[] memory _orderIds) internal virtual;
}
