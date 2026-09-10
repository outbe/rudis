// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IVaultV2
/// @notice A copy of the Morpho VaultV2 interface
interface IVaultV2 {
    /// @notice Underlying ERC-20 asset held by the vault.
    function asset() external view returns (address);

    /// @notice Account authorised to administer the vault.
    function owner() external view returns (address);

    function deposit(uint256 assets, address onBehalf) external returns (uint256 shares);

    function previewWithdraw(uint256 assets) external view returns (uint256 shares);

    function withdraw(uint256 assets, address receiver, address onBehalf) external returns (uint256 shares);
}
