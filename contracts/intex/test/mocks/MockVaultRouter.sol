// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IVaultRouter} from "@precompiles/IVaultRouter.sol";
import {MockSettlementVault} from "./MockSettlementVault.sol";

/// @notice Minimal test double mirroring `outbe-vault/VaultRouter` for the methods
///         `EscrowAdapter` actually calls (`deposit`).
/// @dev Wraps `MockSettlementVault` per asset. `addVault` / `addLiquiditySource` are open
///      (no role checks) - test-helper only. Production `VaultRouter` is `onlyOwner` for both.
contract MockVaultRouter {
    using SafeERC20 for IERC20;

    /// @dev Maps stablecoin address to the registered ERC4626-style vault for that asset.
    mapping(address => MockSettlementVault) public assetVault;

    /// @dev Maps caller address to the registered StablesSource slot
    ///      (`Unknown` = 0 means not registered -> `deposit` reverts).
    mapping(address => IVaultRouter.StablesSource) public liquiditySourceTypes;

    /// @dev When true, `deposit` reverts - used to simulate a vault-side failure during
    ///      finalization (the instruction's split is valid but the payout deposit fails).
    bool public revertOnDeposit;

    error InvalidLiquiditySource();
    error ReserveVaultNotConfigured();
    error DepositReverted();

    /// @notice Toggle a forced revert on `deposit` for failure-path tests.
    function setRevertOnDeposit(bool on) external {
        revertOnDeposit = on;
    }

    /// @notice Register a vault for its underlying asset. Pre-approves the vault to pull tokens
    ///         from this contract (mirrors `VaultRouter.addVault`).
    function addVault(MockSettlementVault vault) external {
        address asset = vault.asset();
        assetVault[asset] = vault;
        IERC20(asset).forceApprove(address(vault), type(uint256).max);
    }

    /// @notice Register `source` as a permitted depositor with the given enum slot.
    /// @dev In production this is `onlyOwner` on `VaultRouter`. The mock leaves it open for
    ///      test setup convenience.
    function addLiquiditySource(address source, IVaultRouter.StablesSource sourceType) external {
        liquiditySourceTypes[source] = sourceType;
    }

    /// @notice Mirrors `IVaultRouter.deposit` semantics:
    ///         pulls `assets` from `msg.sender`, deposits them into the registered vault,
    ///         shares accrue on this contract.
    function deposit(address asset, uint256 assets) external returns (uint256 shares) {
        if (revertOnDeposit) revert DepositReverted();
        if (liquiditySourceTypes[msg.sender] == IVaultRouter.StablesSource.Unknown) {
            revert InvalidLiquiditySource();
        }
        MockSettlementVault vault = assetVault[asset];
        if (address(vault) == address(0)) revert ReserveVaultNotConfigured();

        IERC20(asset).safeTransferFrom(msg.sender, address(this), assets);
        shares = vault.deposit(assets, address(this));
    }

    /// @notice Read-only proxy to the underlying vault's `previewDeposit`. Convenience for tests
    ///         that want to inspect expected shares for a given asset amount.
    function previewDeposit(address asset, uint256 assets) external view returns (uint256) {
        MockSettlementVault vault = assetVault[asset];
        if (address(vault) == address(0)) revert ReserveVaultNotConfigured();
        return vault.previewDeposit(assets);
    }
}
