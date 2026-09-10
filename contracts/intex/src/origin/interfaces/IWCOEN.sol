// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @notice Minimal interface for unwrapping WCOEN to native COEN.
interface IWCOEN {
    function withdraw(uint256 wad) external;
}
