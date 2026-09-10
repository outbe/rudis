// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {OriginSettler} from "./origin/OriginSettler.sol";
import {DestinationSettler} from "./destination/DestinationSettler.sol";
import {IAuction} from "../interfaces/IAuction.sol";
import {ISolverEscrow} from "../interfaces/ISolverEscrow.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";

/**
 * @title BaseRouter
 * @notice Shared base for all messaging-layer routers (LayerZero, Hyperlane, etc.)
 * @dev Contains Compact, Auction and SolverEscrow config.
 *      Messaging-specific logic (_dispatchSettleCrossChain, _dispatchRefundCrossChain, _localDomain)
 *      is left abstract for concrete implementations.
 */
abstract contract BaseRouter is OriginSettler, DestinationSettler, Ownable2Step {
    // ============ Immutables ============

    /// @notice The Compact contract - canonical token custody (same address on all chains)
    ITheCompact public immutable COMPACT;

    /// @notice Resource lock tag for origin chain deposits.
    bytes12 public immutable LOCK_TAG;

    /// @notice The SolverEscrow contract - solver collateral management (address(0) if disabled)
    ISolverEscrow public immutable SOLVER_ESCROW;

    /// @notice The Auction contract - competitive solver selection. Immutable: replacing it would
    ///         strand in-flight orders' quotes in the old contract, so it is fixed at deploy and
    ///         swapped only by redeploying the router.
    IAuction public immutable AUCTION;

    // ============ Errors ============

    /// @notice Thrown when The Compact address is zero
    error InvalidCompact();

    /// @notice Thrown when The Auction address is zero
    error InvalidAuction();

    /// @notice Thrown when the resource lock tag is zero
    error InvalidLockTag();

    /// @notice Thrown when native value is attached to a same-chain settle/refund, which forwards no
    ///         bridge fee and would otherwise trap the ETH in the router.
    error UnexpectedNativeValue();

    // ============ Constructor ============

    /**
     * @param compact_ The Compact contract address.
     * @param lockTag_ Resource lock tag from RouterAllocator.buildLockTag().
     * @param escrow_  SolverEscrow address (address(0) to disable collateral checks).
     * @param auction_ Auction contract address (fixed for the router's lifetime).
     */
    constructor(address compact_, bytes12 lockTag_, address escrow_, address auction_) {
        if (compact_ == address(0)) revert InvalidCompact();
        if (lockTag_ == bytes12(0)) revert InvalidLockTag();
        if (auction_ == address(0)) revert InvalidAuction();
        COMPACT = ITheCompact(compact_);
        LOCK_TAG = lockTag_;
        SOLVER_ESCROW = ISolverEscrow(escrow_);
        AUCTION = IAuction(auction_);
    }

    // ============ RouterAccessors Overrides ============

    function _compact() internal view override returns (ITheCompact) {
        return COMPACT;
    }

    function _lockTag() internal view override returns (bytes12) {
        return LOCK_TAG;
    }

    function _auction() internal view override returns (IAuction) {
        return AUCTION;
    }

    function _solverEscrow() internal view override returns (ISolverEscrow) {
        return SOLVER_ESCROW;
    }

    // ============ Same-Chain Dispatch ============

    /// @dev Routes settlement: same-chain calls _handleSettleOrder directly, cross-chain delegates.
    function _dispatchSettle(uint32 _originDomain, bytes32[] memory _orderIds, bytes[] memory _ordersFillerData)
        internal
        override
    {
        if (_originDomain == _localDomain()) {
            if (msg.value != 0) revert UnexpectedNativeValue();
            bytes32 self = bytes32(uint256(uint160(address(this))));
            for (uint256 i = 0; i < _orderIds.length; i++) {
                bytes32 receiver = abi.decode(_ordersFillerData[i], (bytes32));
                _handleSettleOrder(_originDomain, self, _orderIds[i], receiver);
            }
            return;
        }
        _dispatchSettleCrossChain(_originDomain, _orderIds, _ordersFillerData);
    }

    /// @dev Routes refund: same-chain calls _handleRefundOrder directly, cross-chain delegates.
    function _dispatchRefund(uint32 _originDomain, bytes32[] memory _orderIds) internal override {
        if (_originDomain == _localDomain()) {
            bytes32 self = bytes32(uint256(uint160(address(this))));
            for (uint256 i = 0; i < _orderIds.length; i++) {
                _handleRefundOrder(_originDomain, self, _orderIds[i]);
            }
            return;
        }
        _dispatchRefundCrossChain(_originDomain, _orderIds);
    }

    // ============ Abstract - cross-chain messaging (implemented by concrete router) ============

    function _dispatchSettleCrossChain(
        uint32 _originDomain,
        bytes32[] memory _orderIds,
        bytes[] memory _ordersFillerData
    ) internal virtual;

    function _dispatchRefundCrossChain(uint32 _originDomain, bytes32[] memory _orderIds) internal virtual;
}
