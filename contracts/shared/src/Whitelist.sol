// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IWhitelist {
    function isWhitelisted(address account) external view returns (bool);
}

/// @notice Thrown when a caller is not on the registry.
error NotWhitelisted(address caller);

/// @notice Emitted by a consumer when it points its gate at a different registry.
event WhitelistUpdated(address indexed previous, address indexed current);

/// @notice Reverts unless `caller` is on `registry`. A zero registry leaves the gate open, so a
///         consumer that has not been wired yet - or was deliberately ungated - keeps working.
function requireWhitelisted(IWhitelist registry, address caller) view {
    if (address(registry) != address(0) && !registry.isWhitelisted(caller)) {
        revert NotWhitelisted(caller);
    }
}

/// @title Whitelist
/// @notice Single registry of addresses allowed to call gated functions. Deployed once,
///         shared by every contract that inherits {Whitelisted}.
contract Whitelist is IWhitelist, Ownable {
    /// @inheritdoc IWhitelist
    mapping(address => bool) public isWhitelisted;

    event Added(address indexed account);
    event Removed(address indexed account);

    error ZeroAccount();

    /// @param owner Registry admin, the only address allowed to add or remove entries.
    /// @param initial Initial whitelist.
    constructor(address owner, address[] memory initial) Ownable(owner) {
        for (uint256 i = 0; i < initial.length; i++) {
            _add(initial[i]);
        }
    }

    function add(address[] calldata accounts) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            _add(accounts[i]);
        }
    }

    function remove(address[] calldata accounts) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            isWhitelisted[accounts[i]] = false;
            emit Removed(accounts[i]);
        }
    }

    function _add(address account) private {
        if (account == address(0)) revert ZeroAccount();
        isWhitelisted[account] = true;
        emit Added(account);
    }
}
