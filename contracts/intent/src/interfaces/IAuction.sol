// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IAuction
/// @notice Interface for commit-reveal auction-based solver selection
interface IAuction {
    struct Quote {
        address solver;
        uint128 outputAmount;
    }

    // ============ Events ============

    event Committed(bytes32 indexed orderId, address indexed solver);
    event QuoteSubmitted(bytes32 indexed orderId, address indexed solver, uint256 amount);
    event AuctionRestarted(bytes32 indexed orderId, address indexed disqualifiedSolver);
    event CommitPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event RevealPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event MaxQuotesUpdated(uint256 oldMax, uint256 newMax);
    event RouterUpdated(address oldRouter, address newRouter);
    // ============ Errors ============

    /// @notice Thrown when max quotes per order has been reached (checked at reveal)
    error MaxQuotesReached();
    /// @notice Thrown when the commit phase has ended
    error CommitPhaseEnded();
    /// @notice Thrown when the reveal phase is not active
    error RevealPhaseNotActive();
    /// @notice Thrown when a solver has already committed for this order
    error AlreadyCommitted();
    /// @notice Thrown when a solver tries to reveal without committing
    error NotCommitted();
    /// @notice Thrown when the revealed values don't match the commit hash
    error InvalidReveal();
    /// @notice Thrown when the revealed outputAmount exceeds the uint128 range of the stored quote
    error OutputAmountTooLarge();
    /// @notice Thrown when no quotes have been revealed
    error NoQuotes();
    /// @notice Thrown when the reveal period has not ended yet
    error RevealNotEnded();
    /// @notice Thrown when the router is set to the zero address
    error ZeroRouter();
    // ============ Solver Functions ============

    /// @notice Submit a commitment hash for an order (called directly by solver)
    /// @param orderId The unique identifier of the order
    /// @param commitHash keccak256(abi.encode(orderId, outputAmount, salt))
    function commit(bytes32 orderId, bytes32 commitHash) external;

    /// @notice Reveal a previously committed quote (called directly by solver)
    /// @param orderId The unique identifier of the order
    /// @param outputAmount The amount the solver is willing to provide
    /// @param salt Random bytes32 used in commitment hash
    /// @param originData ABI-encoded OrderData; validated against orderId, fillDeadline and amountOut floor
    function reveal(bytes32 orderId, uint256 outputAmount, bytes32 salt, bytes calldata originData) external;

    // ============ Router Functions ============

    /// @notice Reset auction when winner lacks collateral (router only)
    /// @param orderId The order to reset
    /// @param winner The disqualified winner address
    function resetAuction(bytes32 orderId, address winner) external;

    // ============ Admin Functions ============

    /// @notice Update commit period (owner only)
    /// @param newPeriod New commit period in seconds
    function setCommitPeriod(uint256 newPeriod) external;

    /// @notice Update reveal period (owner only)
    /// @param newPeriod New reveal period in seconds
    function setRevealPeriod(uint256 newPeriod) external;

    /// @notice Update max quotes per order (owner only)
    /// @param newMax New maximum number of quotes
    function setMaxQuotesPerOrder(uint256 newMax) external;

    /// @notice Set the router address (owner only)
    /// @param newRouter Address of the router contract
    function setRouter(address newRouter) external;

    // ============ View Functions ============

    /// @notice Get the winning solver and amount after reveal ends
    function getWinner(bytes32 orderId) external view returns (address solver, uint256 amount);

    /// @notice Check if the auction has fully ended (commit + reveal periods elapsed)
    function isAuctionEnded(bytes32 orderId) external view returns (bool);

    /// @notice Get all revealed quotes for an order
    function getQuotes(bytes32 orderId) external view returns (Quote[] memory);

    /// @notice Get the number of revealed quotes for an order
    function getQuoteCount(bytes32 orderId) external view returns (uint256);

    /// @notice Get the commit deadline timestamp (0 if no commits yet)
    function getCommitDeadline(bytes32 orderId) external view returns (uint256);

    /// @notice Get the reveal deadline timestamp (0 if no commits yet)
    function getRevealDeadline(bytes32 orderId) external view returns (uint256);

    /// @notice Check if a solver has committed for an order
    function hasSolverCommitted(bytes32 orderId, address solver) external view returns (bool);

    /// @notice Get the auction start timestamp for an order
    function auctionStartedAt(bytes32 orderId) external view returns (uint256);

    /// @notice Get the commit period in seconds
    function commitPeriod() external view returns (uint256);

    /// @notice Get the reveal period in seconds
    function revealPeriod() external view returns (uint256);

    /// @notice Get the maximum number of quotes per order
    function maxQuotesPerOrder() external view returns (uint256);
}
