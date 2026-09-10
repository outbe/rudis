// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TargetChainVaultRouter} from "src/TargetChainVaultRouter.sol";

/// @notice Deploys the fixed external-chain WCOEN vault adapter.
/// @dev The WCOEN addresses come from the `tokens` package, which names the two ends of a route by network role:
///      `OUTBE_*` is always Outbe, `EXTERNAL_*` is whichever external chain this deployment targets.
///
///      Required env: DEPLOYER_PK, BRIDGE_ADDRESS, EXTERNAL_CHAIN_ID, OUTBE_CHAIN_ID,
///      EXTERNAL_WCOEN_TOKEN, EXTERNAL_WCOEN_BRIDGE, EXTERNAL_WCOEN_VAULT.
///      Optional env: OUTBE_ROUTER (default 0x1017), ROUTER_OWNER (default: the deployer).
contract DeployTargetChainVaultRouter is Script {
    address internal constant OUTBE_VAULT_ROUTER_PRECOMPILE = 0x0000000000000000000000000000000000001017;

    function run() external returns (TargetChainVaultRouter router) {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        address deployer = vm.addr(deployerPk);
        uint256 externalChainId = vm.envUint("EXTERNAL_CHAIN_ID");
        uint256 outbeChainId = vm.envUint("OUTBE_CHAIN_ID");
        require(outbeChainId <= type(uint32).max, "OUTBE_CHAIN_ID exceeds uint32");

        address asset = vm.envAddress("EXTERNAL_WCOEN_TOKEN");
        address vault = vm.envAddress("EXTERNAL_WCOEN_VAULT");
        address tokenBridge = vm.envAddress("EXTERNAL_WCOEN_BRIDGE");
        address messageBridge = vm.envAddress("BRIDGE_ADDRESS");
        address outbeRouter = vm.envOr("OUTBE_ROUTER", OUTBE_VAULT_ROUTER_PRECOMPILE);
        address owner = vm.envOr("ROUTER_OWNER", deployer);

        require(block.chainid == externalChainId, "wrong destination chain");

        vm.startBroadcast(deployerPk);
        router = new TargetChainVaultRouter(
            asset, vault, tokenBridge, messageBridge, uint32(outbeChainId), outbeRouter, owner
        );
        vm.stopBroadcast();

        console2.log("TargetChainVaultRouter:", address(router));
        console2.log("WCOEN:", asset);
        console2.log("1:1 vault:", vault);
        console2.log("WCOEN token bridge:", tokenBridge);
        console2.log("ERC-7786 message bridge:", messageBridge);
        console2.log("trusted Outbe chain:", outbeChainId);
        console2.log("trusted Outbe router:", outbeRouter);
        console2.log("owner:", owner);
    }
}
