// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IStablecoinFactory
/// @notice Read-only discovery surface for protocol-admitted Rust-native stablecoins.
/// @dev Registration and token initialization are available only to the compile-time Vote adapter.
///      Registration is protocol admission, not proof of backing, redeemability, price stability,
///      issuer solvency, creditworthiness, fee eligibility, or payment-lane eligibility.
interface IStablecoinFactory {
    /// @notice Emitted once after token initialization and every Factory index commit atomically.
    /// @dev Solidity permits at most three indexed fields on a non-anonymous event. proposalId is
    ///      therefore canonical event data while tokenId, token, and issuer are indexed.
    event StablecoinCreated(
        bytes32 indexed tokenId,
        address indexed token,
        address indexed issuer,
        uint256 proposalId,
        string name,
        string ticker,
        uint16 iso4217,
        uint8 decimals,
        uint256 supplyCap,
        uint256 policyId
    );

    error UnexpectedValue(uint256 value);
    error InvalidIssuer(address issuer);
    error InvalidTicker(string ticker);
    error NonCanonicalPayload();
    error UnknownPolicy(uint256 policyId);
    error TokenIdReserved(bytes32 tokenId, uint256 proposalId);
    error TickerReserved(string ticker, uint256 proposalId);
    error TokenIdAlreadyRegistered(bytes32 tokenId, address token);
    error TickerAlreadyRegistered(string ticker, address token);
    error TokenAddressCollision(address token, bytes32 existingTokenId, bytes32 requestedTokenId);
    error InvalidListLimit(uint256 limit, uint256 maximum);
    error UnknownStablecoin(address token);

    function tokenCount() external view returns (uint256);

    /// @notice Returns up to `limit` registered token addresses starting at `offset`.
    /// @dev `limit` must be between 1 and 100. `offset >= tokenCount()` returns an
    ///      empty array; the final page is clamped to the current count. No ordering
    ///      guarantee is provided.
    function listTokens(uint256 offset, uint256 limit) external view returns (address[] memory);

    function tokenById(bytes32 tokenId) external view returns (address);

    function tokenByTicker(string calldata ticker) external view returns (address);

    function tokenIdOf(address token) external view returns (bytes32);

    function isStablecoin(address token) external view returns (bool);

    function predictTokenAddress(address issuer, string calldata ticker)
        external
        view
        returns (bytes32 tokenId, address token);
}
