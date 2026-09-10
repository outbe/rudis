// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {console2} from "forge-std/console2.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {RouteSpec} from "./routes/BaseRoute.sol";
import {ERC7786TokenBridge} from "../src/ERC7786TokenBridge.sol";
import {Routes} from "./routes/Routes.sol";

/// @dev Sends tokens across one route, in either direction. The bridge address is derived from CREATE3 and the token
///      is read off the bridge, so no address can drift out of sync with the deployment. Whether an approval is
///      needed follows from the bridge's own mode: lock/unlock pulls the token, burn/mint does not.
///
/// Required env: `DEPLOYER_PK`, `CONTRACT_SALT`, `CREATE3_FACTORY_ADDRESS`, `ROUTE` ("usdt" | "wcoen"),
///   `DEST_CHAIN_ID`, `RECIPIENT`, `SEND_AMOUNT_LD` (in the token's own decimals).
contract Send is Routes {
    error InsufficientTokenBalance(address signer, uint256 balance, uint256 required);
    error InsufficientNativeBalance(address signer, uint256 balance, uint256 required);

    function run() external returns (bytes32 sendId, uint256 nativeFee) {
        address signer = _deployer();
        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        string memory salt = vm.envString("CONTRACT_SALT");

        uint32 destinationDomain = _toDomain(vm.envUint("DEST_CHAIN_ID"));
        address recipient = vm.envAddress("RECIPIENT");
        uint256 amount = vm.envUint("SEND_AMOUNT_LD");

        ERC7786TokenBridge bridge =
            ERC7786TokenBridge(_bridgeAddress(factory, salt, routeByLabel(vm.envString("ROUTE")).spec));
        _requireCode(address(bridge));
        IERC20 token = bridge.token();

        nativeFee = bridge.quoteSend(destinationDomain, recipient, amount, "", 0);

        uint256 tokenBalance = token.balanceOf(signer);
        if (tokenBalance < amount) revert InsufficientTokenBalance(signer, tokenBalance, amount);
        if (signer.balance < nativeFee) revert InsufficientNativeBalance(signer, signer.balance, nativeFee);

        vm.startBroadcast(_pk());
        // Lock/unlock pulls the token into bridge custody; burn/mint calls ERC-7802 and needs no allowance.
        if (bridge.mode() == ERC7786TokenBridge.TokenBridgeMode.LockUnlock) token.approve(address(bridge), amount);
        sendId = bridge.send{value: nativeFee}(destinationDomain, recipient, amount);
        vm.stopBroadcast();

        console2.log("Sent to chainId:", vm.envUint("DEST_CHAIN_ID"));
        console2.logBytes32(sendId);
        console2.log("  token:", address(token));
        console2.log("  amount:", amount);
        console2.log("  native fee:", nativeFee);
    }
}
