// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BridgeableERC20} from "./BridgeableERC20.sol";
import {IReferenceCurrency} from "../interfaces/IReferenceCurrency.sol";

/// @title BridgeableERC20Stable
/// @notice ERC-7802 bridgeable ERC20 that denominates a reference currency. The
///         ISO 4217 numeric code is fixed at construction and exposed via
///         IReferenceCurrency (e.g. 840 = USD).
contract BridgeableERC20Stable is BridgeableERC20, IReferenceCurrency {
    uint16 private immutable _ISO_CODE;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint16 isoCode_, address owner_)
        BridgeableERC20(name_, symbol_, decimals_, owner_)
    {
        _ISO_CODE = isoCode_;
    }

    /// @inheritdoc IReferenceCurrency
    function isoCode() external view returns (uint16) {
        return _ISO_CODE;
    }
}
