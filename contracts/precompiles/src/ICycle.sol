// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title ICycle
/// @notice Cycle dispatcher storage/events at 0x0000000000000000000000000000000000001010.
/// @dev Cycle is invoked by the begin-zone CycleTick system transaction, not by user calls.
interface ICycle {
    /// Emitted exactly once per slot when a trigger handler completes
    /// successfully. Indexed by the trigger's stable u32 id.
    event CycleTriggerExecuted(uint32 indexed id, uint64 scheduledAt, uint64 blockTimestamp, uint64 blockNumber);
}
