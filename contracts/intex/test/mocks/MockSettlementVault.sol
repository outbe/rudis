// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Ownerless one-to-one reserve vault used only by live E2E.
contract MockSettlementVault {
    IERC20 public immutable ASSET;
    mapping(address => uint256) public balanceOf;

    constructor(address asset_) {
        ASSET = IERC20(asset_);
    }

    function asset() external view returns (address) {
        return address(ASSET);
    }

    function owner() external pure returns (address) {
        return address(0);
    }

    function deposit(uint256 assets, address onBehalf) external returns (uint256 shares) {
        shares = assets;
        require(ASSET.transferFrom(msg.sender, address(this), assets), "TRANSFER_FROM_FAILED");
        balanceOf[onBehalf] += shares;
    }

    function previewWithdraw(uint256 assets) external pure returns (uint256 shares) {
        return assets;
    }

    function withdraw(uint256 assets, address receiver, address onBehalf) external returns (uint256 shares) {
        shares = assets;
        balanceOf[onBehalf] -= shares;
        require(ASSET.transfer(receiver, assets), "TRANSFER_FAILED");
    }
}
