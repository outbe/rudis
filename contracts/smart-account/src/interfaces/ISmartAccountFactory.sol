// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title ISmartAccountFactory
/// @notice Interface for deploying Credis-configured Kernel v4 smart accounts.
/// @dev The owner is modelled as a permission (SudoPolicy + ECDSASigner) rather than a plain root
///      validator, because Kernel v4 cannot attach the BundleSpendProtectorHook to a root validator
///      at init. See SmartAccountFactory for the install-package layout.
interface ISmartAccountFactory {
    /// @notice Deploy (or return existing) Kernel smart account with Credis modules installed
    /// @param owner EOA owner of the smart account (controls via ECDSA)
    /// @param cca CCA EOA address
    /// @param bundleTokens ERC-20 tokens governed by bundle permissions
    /// @param bundleSenders Allowed top-up senders (CallerHook whitelist)
    /// @param salt Deployment salt for deterministic address
    /// @return account Deployed (or existing) Kernel account address
    function createAccount(
        address owner,
        address cca,
        address[] calldata bundleTokens,
        address[] calldata bundleSenders,
        uint256 salt
    ) external returns (address account);

    /// @notice Predict Kernel account address without deploying
    /// @param owner EOA owner of the smart account
    /// @param cca CCA EOA address
    /// @param bundleTokens ERC-20 tokens governed by bundle permissions
    /// @param bundleSenders Allowed top-up senders (CallerHook whitelist)
    /// @param salt Deployment salt for deterministic address
    /// @return account Predicted Kernel account address
    function getAccountAddress(
        address owner,
        address cca,
        address[] calldata bundleTokens,
        address[] calldata bundleSenders,
        uint256 salt
    ) external view returns (address account);

    // -- Getters ----------------------------------------------------------

    /// @notice ZeroDev KernelFactory address
    function kernelFactory() external view returns (address);

    /// @notice SudoPolicy singleton address (always-pass policy backing the owner permission)
    function sudoPolicy() external view returns (address);

    /// @notice BundleModulePlugin singleton address
    function bundleModulePlugin() external view returns (address);

    /// @notice CallerHook singleton address
    function callerHook() external view returns (address);

    /// @notice BundleSpendProtectorHook singleton address
    function bundleSpendProtectorHook() external view returns (address);

    /// @notice WithdrawalLimitPolicy singleton address
    function withdrawalLimitPolicy() external view returns (address);

    /// @notice ECDSASigner singleton address
    function ecdsaSigner() external view returns (address);

    /// @notice BundleWithdrawHook singleton address
    function bundleWithdrawHook() external view returns (address);

    // -- Constants --------------------------------------------------------

    /// @notice Daily withdrawal limit enforced by WithdrawalLimitPolicy (6-decimal USDC units)
    function DAILY_LIMIT() external view returns (uint256);

    /// @notice Interval for daily limit reset
    function LIMIT_INTERVAL() external view returns (uint48);
}
