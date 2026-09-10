// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

/// @notice Local stablecoin vault routing and authorization surface.
interface IVaultRouter {
    enum StablesSource {
        Unknown,
        IntexCostAmount, // todo remove once implement PayNoteDeposit
        CredisCostAmount,
        GemCostAmount, // todo remove once implement PayNoteDeposit
        PayNoteDeposit
    }

    enum StablesTarget {
        Unknown,
        Credis
    }

    error InvalidLiquiditySource();
    error InvalidLiquidityTarget();
    error InvalidReferenceCurrency();
    error ReserveVaultNotConfigured();
    error ReserveVaultAssetMismatch();
    error ReserveVaultAlreadyAdded();
    error ReserveVaultNotFound();
    error ReserveVaultOwnerNotRenounced(address currentOwner);
    error LiquiditySourceNotFound();
    error LiquidityTargetNotFound();
    error InsufficientSharesForWithdraw(uint256 availableShares, uint256 requiredShares);
    error SameVaultRebalance();
    error InvalidRebalanceAmount();
    error RebalanceVaultNotRegistered(address vault);
    error RebalanceInputExceedsMax(uint256 required, uint256 maxAmountTo);
    error UnsupportedAssetDecimals(uint8 decimals);
    error CcaNotActive(address cca);

    event VaultAdded(uint16 indexed isoCode, address indexed asset, address indexed vault);
    event VaultRemoved(uint16 indexed isoCode, address indexed asset, address indexed vault);
    event LiquiditySourceAdded(address indexed sourceAddress, StablesSource sourceType);
    event LiquiditySourceRemoved(address indexed sourceAddress, StablesSource sourceType);
    event LiquidityTargetAdded(address indexed targetAddress, StablesTarget targetType);
    event LiquidityTargetRemoved(address indexed targetAddress, StablesTarget targetType);

    event LiquidityDeposited(
        address indexed source,
        address indexed vault,
        uint256 assetsAmount,
        uint256 sharesAmount,
        StablesSource sourceType
    );

    event LiquidityWithdrawn(
        address indexed target,
        address indexed receiver,
        address indexed vault,
        uint256 assetsAmount,
        uint256 burnedShares,
        StablesTarget targetType
    );

    event LiquidityRebalanced(
        address indexed cca,
        address indexed vaultFrom,
        address indexed vaultTo,
        uint256 assetsWithdrawn,
        uint256 burnedShares,
        uint256 assetsDeposited,
        uint256 mintedShares
    );

    /// @notice Returns the number of assets.
    function assetsCount() external view returns (uint256);

    /// @notice Returns the asset at `index`. Reverts if out of bounds.
    function assetAt(uint256 index) external view returns (address asset);

    /// @notice Returns the number of vaults registered for `asset`.
    function assetVaultsCount(address asset) external view returns (uint256);

    /// @notice Returns the reserve vault at `index` for `asset`. Reverts if out of bounds.
    function assetVaultAt(address asset, uint256 index) external view returns (address vault);

    /// @notice Returns the number of vaults registered for an ISO 4217 currency code.
    function referenceCurrencyVaultsCount(uint16 isoCode) external view returns (uint256);

    /// @notice Returns the vault at `index` for an ISO 4217 currency code. Reverts if out of bounds.
    function referenceCurrencyVaultAt(uint16 isoCode, uint256 index) external view returns (address vault);

    /// @notice Returns the ISO 4217 currency code recorded when `vault` was registered.
    function vaultReferenceCurrency(address vault) external view returns (uint16 isoCode);

    /// @notice Returns every asset registered under `isoCode`. Order is not
    ///         stable across removals and carries no meaning.
    function referenceCurrencyAssets(uint16 isoCode) external view returns (address[] memory assets);

    /// @notice Returns the number of liquidity sources.
    function liquiditySourcesCount() external view returns (uint256);

    /// @notice Returns the liquidity source at `index`. Reverts if out of bounds.
    function liquiditySourceAt(uint256 index) external view returns (address sourceAddress, StablesSource sourceType);

    /// @notice Returns the number of liquidity targets.
    function liquidityTargetsCount() external view returns (uint256);

    /// @notice Returns the liquidity target at `index`. Reverts if out of bounds.
    function liquidityTargetAt(uint256 index) external view returns (address targetAddress, StablesTarget targetType);

    // TODO remove after implementation governance
    /// @notice Registers a vault. Reverts if already registered.
    function addVault(address vault) external;

    // TODO remove after implementation governance
    /// @notice Removes a previously registered vault for `asset`. Reverts if not found.
    function removeVault(address vault) external;

    // TODO remove after implementation governance
    /// @notice Registers `sourceAddress` as an authorized liquidity source of `sourceType`.
    function addLiquiditySource(address sourceAddress, StablesSource sourceType) external;

    // TODO remove after implementation governance
    /// @notice Deregisters a previously registered liquidity source. Reverts if not found.
    function removeLiquiditySource(address sourceAddress) external;

    // TODO remove after implementation governance
    /// @notice Registers `targetAddress` as an authorized liquidity target of `targetType`.
    function addLiquidityTarget(address targetAddress, StablesTarget targetType) external;

    // TODO remove after implementation governance
    /// @notice Deregisters a previously registered liquidity target. Reverts if not found.
    function removeLiquidityTarget(address targetAddress) external;

    /// @notice Deposits `assetsAmount` of `asset` into the asset's vault on behalf of the
    ///         caller. The caller (`msg.sender`) must be a registered liquidity source.
    function deposit(address asset, uint256 assetsAmount) external returns (uint256 sharesAmount);

    /// @notice Redeems `amount` of `asset` from the vault and tops it up into `receiver`.
    ///         The caller (`msg.sender`) must be a registered liquidity target.
    function withdraw(address asset, uint256 amount, address receiver) external returns (uint256 burnedShares);

    // TODO remove after implementation governance
    /// @notice Returns the current owner (admin) of the vault router.
    function owner() external view returns (address);

    /// @notice Returns vault shares currently held by this provider.
    function sharesBalance(address vault) external view returns (uint256);

    /// @notice Moves `assetsAmount` of liquidity from `vaultFrom` to `vaultTo`. The caller
    ///         supplies the destination asset at the oracle cross rate and receives the source
    ///         asset in exchange; it must have approved this router for at least the required
    ///         amount. `maxAmountTo` bounds what the router may pull if the rate moved since
    ///         the caller quoted it. Caller must be an active CCA.
    function rebalance(address vaultFrom, address vaultTo, uint256 assetsAmount, uint256 maxAmountTo)
        external
        returns (uint256 amountTo);

    /// @notice What a {rebalance} of `assetsAmount` would require the caller to supply, so it
    ///         can approve exactly that before calling.
    function previewRebalance(address vaultFrom, address vaultTo, uint256 assetsAmount)
        external
        view
        returns (address assetFrom, address assetTo, uint256 amountTo);
}
