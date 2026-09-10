// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title USDT
/// @notice Mintable ERC20 used as source-side test stablecoin for bridge integration tests.
contract USDT is ERC20 {
    uint8 private constant DECIMALS = 6;

    constructor() ERC20("Mock USD", "USDT") {}

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    /// @notice Public mint for testnet/dev bootstrap.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
