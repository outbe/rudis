// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IERC20
/// @notice Canonical ERC-20 surface for this repository, including the optional
///         metadata extension (`name`, `symbol`, `decimals`).
/// @dev Declared standalone rather than imported from OpenZeppelin because the
///      Rust precompiles bind this file directly through `sol!("<path>")`, and
///      that macro discards `import` directives - an inherited interface would
///      expand with its members missing.
interface IERC20 {
    /// @notice Emitted when `value` tokens move from `from` to `to`.
    event Transfer(address indexed from, address indexed to, uint256 value);

    /// @notice Emitted when the allowance of `spender` over `owner`'s tokens is set.
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
