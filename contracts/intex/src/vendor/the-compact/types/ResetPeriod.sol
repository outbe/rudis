// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title ResetPeriod - Forced Withdrawal Reset Period
 * @notice Reset period enum for The Compact resource locks.
 * @dev Compatible with Uniswap The Compact. Full source:
 *      https://github.com/Uniswap/the-compact/blob/main/src/types/ResetPeriod.sol
 * @custom:source https://github.com/Uniswap/the-compact
 */
enum ResetPeriod {
    OneSecond,
    FifteenSeconds,
    OneMinute,
    TenMinutes,
    OneHourAndFiveMinutes,
    OneDay,
    SevenDaysAndOneHour,
    ThirtyDays
}
