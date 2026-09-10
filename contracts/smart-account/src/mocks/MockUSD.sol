// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockUSDC
/// @notice Mock USDC token for testing purposes
/// @dev Standard ERC20 with 6 decimals like real USDC
contract MockUSD is ERC20, Ownable {
    /// @notice Creates a new MockUSDC token
    constructor() ERC20("Mock USD Coin", "USDT0") Ownable(msg.sender) {}

    /// @notice Returns the number of decimals (6 for USD)
    /// @return The number of decimals
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice Mints tokens to a specified address
    /// @param to The address to receive the tokens
    /// @param amount The amount of tokens to mint
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice Burns tokens from the caller's address
    /// @param amount The amount of tokens to burn
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice ISO 4217 numeric currency code for this asset (USD = 840).
    /// @dev Implements `IReferenceCurrency` (contracts/tokens/src/interfaces/IReferenceCurrency.sol);
    ///      the Credis Factory calls this to derive the position's issuance currency.
    /// @return The ISO 4217 numeric code (840 = USD).
    function isoCode() external pure returns (uint16) {
        return 840;
    }
}
