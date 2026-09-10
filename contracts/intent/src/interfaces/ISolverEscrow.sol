// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Interface for solver collateral: check, lock, unlock, slash, view
interface ISolverEscrow {
    struct BalanceInfo {
        address token;
        uint256 total;
        uint256 locked;
        uint256 available;
    }

    // ============ Errors ============

    /// @notice Thrown when a solver lacks sufficient collateral
    error InsufficientCollateral();
    /// @notice Thrown when available balance is insufficient
    error InsufficientAvailableBalance();
    /// @notice Thrown when a collateral lock already exists for the order
    error LockAlreadyExists();
    /// @notice Thrown when no collateral lock exists for the order
    error LockNotFound();

    // ============ Functions ============

    /// @notice Distribute reward from slashed pool to receiver (REWARD_BPS of orderAmountIn)
    /// @param token The underlying token
    /// @param orderAmountIn The order's input amount (reward calculated as percentage)
    /// @param receiver The address to receive underlying tokens
    /// @return reward The amount distributed (0 if insufficient slashed balance)
    function distributeReward(address token, uint256 orderAmountIn, address receiver) external returns (uint256 reward);

    /// @notice Returns true if solver has sufficient available (unlocked) collateral
    function hasMinCollateral(address solver, address token, uint256 outputAmount) external view returns (bool);

    /// @notice Lock solver collateral for a claimed order, moving it into escrow custody
    function lockCollateral(bytes32 orderId, address solver, address token, uint256 amount) external;

    /// @notice Unlock solver collateral after successful fill, returning custody to the solver
    function unlockCollateral(bytes32 orderId) external;

    /// @notice Slash locked collateral into the escrow's slashed pool
    function slashCollateral(bytes32 orderId) external;

    /// @notice Collateral basis points (e.g. 1000 = 10%)
    function collateralBps() external view returns (uint256);

    /// @notice Calculate collateral amount for a given output amount
    function getCollateralAmount(uint256 outputAmount) external view returns (uint256);

    /// @notice Get ERC6909 balance for an owner and token (total, locked, available)
    function getBalance(address owner, address token)
        external
        view
        returns (uint256 total, uint256 locked, uint256 available);

    /// @notice Get ERC6909 balances for an owner across multiple tokens
    function getBalances(address owner, address[] calldata tokens) external view returns (BalanceInfo[] memory);
}
