// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title RejectingReceiver
/// @notice Receiver that reverts on any incoming ETH; used to exercise sweepNative failure paths.
contract RejectingReceiver {
    receive() external payable {
        revert("rejected");
    }
}
