// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Stand-in for the Rust-native stablecoin precompile: `mint` is issuer-gated, `burnFrom`
///         spends an allowance, and both revert rather than returning false.
contract MockStablecoin is ERC20 {
    mapping(address account => bool) public isIssuer;

    error NotIssuer(address caller);

    constructor(string memory name_, string memory symbol_, address issuer_) ERC20(name_, symbol_) {
        isIssuer[issuer_] = true;
    }

    function grantIssuer(address account) external {
        isIssuer[account] = true;
    }

    function revokeIssuer(address account) external {
        isIssuer[account] = false;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external returns (bool) {
        if (!isIssuer[msg.sender]) revert NotIssuer(msg.sender);
        _mint(to, amount);
        return true;
    }

    function burnFrom(address from, uint256 amount) external returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
        return true;
    }
}
