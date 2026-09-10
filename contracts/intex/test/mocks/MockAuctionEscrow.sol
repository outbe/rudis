// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IntexAuction} from "@contracts/target/IntexAuction.sol";

/// @title MockAuctionEscrow
/// @notice Minimal escrow stub for IntexAuction unit tests. Selector-matches `IEscrowAdapter.lockFunds`
///         without implementing the full interface. Supports a `lockShouldRevert` toggle and an
///         `armReentry` hook for reentrancy probes.
/// @dev The canonical full-interface mock lives in `MockEscrowAdapter.sol`; use that when a test
///      needs the entire IEscrowAdapter surface (finalization, etc.).
contract MockAuctionEscrow {
    error MockLockReverted();

    mapping(uint32 => mapping(address => uint128)) public lockedFunds;
    bool public lockShouldRevert;
    uint256 public outstandingCount;

    IntexAuction public reentryTarget;
    bytes public reentryCalldata;
    bool public reentryArmed;

    event FundsLocked(uint32 indexed seriesId, address indexed bidder, uint128 amount);

    function setLockShouldRevert(bool v) external {
        lockShouldRevert = v;
    }

    function armReentry(IntexAuction target, bytes calldata data) external {
        reentryTarget = target;
        reentryCalldata = data;
        reentryArmed = true;
    }

    function lockFunds(uint32 seriesId, address bidder, uint128 amount) external {
        if (lockShouldRevert) revert MockLockReverted();
        if (reentryArmed) {
            reentryArmed = false;
            (bool ok, bytes memory ret) = address(reentryTarget).call(reentryCalldata);
            if (!ok) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
        lockedFunds[seriesId][bidder] = amount;
        ++outstandingCount;
        emit FundsLocked(seriesId, bidder, amount);
    }

    /// @notice Selector-matches `IEscrowAdapter.hasOutstandingLocks`: true while any lock is live.
    function hasOutstandingLocks() external view returns (bool) {
        return outstandingCount != 0;
    }

    /// @dev Test helper: simulate finalization/refund clearing every live lock.
    function releaseAllLocks() external {
        outstandingCount = 0;
    }
}
