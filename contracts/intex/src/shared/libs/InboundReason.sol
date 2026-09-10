// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title InboundReason
/// @author Outbe
/// @notice Reason codes carried by `InboundMessageIgnored`: why an authenticated inbound message, or one item
///         of it, was acknowledged without effect.
library InboundReason {
    /// @notice The effect is already applied; nothing changed.
    uint8 internal constant DUPLICATE = 1;
    /// @notice The state has moved past the point where the message could apply.
    uint8 internal constant OBSOLETE = 2;
    /// @notice Same identity as an applied message, different content; the first one stands.
    uint8 internal constant CONFLICT = 3;
    /// @notice The message names something that does not exist on this chain and never will (day, source).
    uint8 internal constant NOT_FOUND = 4;
    /// @notice The message arrived after the window it needed had closed.
    uint8 internal constant LATE = 5;
    /// @notice The message failed a permanent validation check.
    uint8 internal constant INVALID = 6;
    /// @notice The effect could not be applied yet and waits in a slot for a later trigger.
    uint8 internal constant DEFERRED = 7;
}
