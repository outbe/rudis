// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/**
 * @title OrderStatusStorage
 * @notice Shared order status constants, storage and errors for Origin and Destination settlers
 * @dev Prevents diamond inheritance conflicts
 */
abstract contract OrderStatusStorage {
    // ============ Constants ============

    bytes32 public constant UNKNOWN = "";

    // - Origin statuses -
    bytes32 public constant OPENED = "OPENED";
    bytes32 public constant SETTLED = "SETTLED";
    bytes32 public constant REFUNDED = "REFUNDED";

    // - Destination statuses -
    bytes32 public constant CLAIMED = "CLAIMED";
    bytes32 public constant FILLED = "FILLED";

    // ============ Internal Helpers ============

    /// @notice Returns true if the order has not been processed yet (UNKNOWN or OPENED)
    function _isNotProcessed(bytes32 _status) internal pure returns (bool) {
        return _status == UNKNOWN || _status == OPENED;
    }

    // ============ Public Storage ============

    /// @notice Tracks the origin-side lifecycle of each order (UNKNOWN -> OPENED -> SETTLED/REFUNDED)
    mapping(bytes32 orderId => bytes32 status) public orderStatus;

    /// @notice Tracks the destination-side lifecycle of each order (UNKNOWN -> CLAIMED -> FILLED).
    ///         Split from `orderStatus` so a same-chain order (originDomain == destinationDomain)
    ///         on a single router instance does not collapse both lifecycles into one slot.
    mapping(bytes32 orderId => bytes32 status) public destinationOrderStatus;

    // ============ Errors ============

    /// @notice Thrown when the native amount sent doesn't match the required amount
    error InvalidNativeAmount();
}
