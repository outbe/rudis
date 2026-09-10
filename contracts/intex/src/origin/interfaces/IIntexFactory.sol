// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @notice Minimal interface for the IntexFactory precompile call used by OriginRouter.
interface IIntexFactory {
    /// @notice Credit native auction proceeds from `srcChainId` to the day's pot; the factory pays creators once the
    ///         revenue from every winning chain has arrived (or the fan-in deadline passes).
    /// @param worldwideDay Worldwide day (yyyymmdd) whose creators receive the proceeds.
    /// @param srcChainId Target chain the proceeds arrived from (for fan-in completeness tracking).
    function distribute(uint32 worldwideDay, uint32 srcChainId) external payable;
}
