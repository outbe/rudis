// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MockERC20} from "./MockERC20.sol";

/**
 * @title MockWCOEN
 * @notice The auction's payment token: WCOEN, 18 decimals.
 */
contract MockWCOEN is MockERC20 {
    constructor() MockERC20("Wrapped Rudis", "wrudis", 18) {}
}
