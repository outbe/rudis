// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title Scope - Resource Lock Scope
 * @notice Scope enum for The Compact resource locks.
 * @dev Compatible with Uniswap The Compact. Full source:
 *      https://github.com/Uniswap/the-compact/blob/main/src/types/Scope.sol
 * @custom:source https://github.com/Uniswap/the-compact
 */
enum Scope {
    Multichain,
    ChainSpecific
}
