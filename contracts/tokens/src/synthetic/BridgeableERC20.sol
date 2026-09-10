// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Bridgeable} from "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Bridgeable.sol";

/// @title BridgeableERC20
/// @notice ERC-7802 bridgeable ERC20 with constructor-configured metadata and decimals.
contract BridgeableERC20 is ERC20Bridgeable, Ownable {
    uint8 private immutable _LOCAL_DECIMALS;

    address public tokenBridge;

    event TokenBridgeUpdated(address indexed previousBridge, address indexed newBridge);

    error InvalidTokenBridge();
    error UnauthorizedTokenBridge(address caller);

    constructor(string memory name_, string memory symbol_, uint8 decimals_, address owner_)
        ERC20(name_, symbol_)
        Ownable(owner_)
    {
        _LOCAL_DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _LOCAL_DECIMALS;
    }

    function setTokenBridge(address bridge_) external onlyOwner {
        if (bridge_ == address(0) || bridge_.code.length == 0) revert InvalidTokenBridge();
        address previousBridge = tokenBridge;
        tokenBridge = bridge_;
        emit TokenBridgeUpdated(previousBridge, bridge_);
    }

    function _checkTokenBridge(address caller) internal view override {
        if (caller != tokenBridge) revert UnauthorizedTokenBridge(caller);
    }
}
