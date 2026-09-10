// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MockERC20} from "./MockERC20.sol";

/// @notice Six-decimal, ISO-denominated settlement asset used only by live E2E.
contract MockReferenceStablecoin is MockERC20 {
    uint16 public immutable ISO_CODE;

    constructor(uint16 isoCode_) MockERC20("E2E USD", "eUSD", 6) {
        ISO_CODE = isoCode_;
    }

    function isoCode() external view returns (uint16) {
        return ISO_CODE;
    }
}
