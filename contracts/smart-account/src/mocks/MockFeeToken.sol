// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockFeeToken
/// @notice ERC20 that burns a fixed basis-point fee on every transfer, so the recipient receives
///         less than the sent amount. Used to prove smart accounting credits the measured delta
///         (T-02) rather than the nominal transfer amount.
contract MockFeeToken is ERC20 {
    uint256 public immutable FEE_BPS;

    constructor(uint256 feeBps) ERC20("Mock Fee Token", "FEE") {
        FEE_BPS = feeBps;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @dev Overrides the internal transfer hook: `fee` is burned, `amount - fee` reaches `to`.
    function _update(address from, address to, uint256 value) internal override {
        if (from == address(0) || to == address(0)) {
            super._update(from, to, value); // mint / burn: no fee
            return;
        }
        uint256 fee = (value * FEE_BPS) / 10_000;
        super._update(from, to, value - fee);
        if (fee > 0) super._update(from, address(0), fee); // burn the fee
    }
}
