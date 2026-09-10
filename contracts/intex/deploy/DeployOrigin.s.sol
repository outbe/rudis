// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {console} from "forge-std/console.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {BaseScript} from "./BaseScript.s.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";

/// @title DeployOrigin
/// @author Outbe
/// @notice Deploy the origin-side intex engine (OriginRouter) and register every auction target
///         from `TARGET_CHAIN_IDS`. The NFT collection + bridge and the auction stack are a target
///         concern (see DeployTarget); the origin engine needs neither.
/// @dev Env: DEPLOYER_PRIVATE_KEY, BRIDGE_ADDRESS (the ERC-7786 bridge all clients speak to),
///      TARGET_CHAIN_IDS (comma-separated auction target chainIds), optional OUTBE_WCOEN_BRIDGE +
///      OUTBE_WCOEN_TOKEN (creator-reward proceeds unwrap). The deployer is admin + delegate. Target
///      peers are CREATE3-deterministic, so they are predictable before those chains are deployed.
contract DeployOrigin is BaseScript {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address delegate = deployer;
        address bridge = vm.envAddress("BRIDGE_ADDRESS");
        uint256[] memory targetChainIds = vm.envUint("TARGET_CHAIN_IDS", ",");

        vm.startBroadcast(pk);

        Create3Factory factory = create3Factory();

        address router = deployProxy(
            factory,
            deployer,
            "OriginRouter",
            address(new OriginRouter(bridge)),
            abi.encodeCall(OriginRouter.initialize, (delegate))
        );

        // Register every auction target. The TargetRouter sits at the same CREATE3 address on every
        // chain, so its peer is predictable before that chain exists. addTarget requires the peer set
        // first and reverts on a duplicate, so guard on isTarget to keep re-runs / added chains safe.
        address targetRouterPeer = predictProxy(factory, deployer, "TargetRouter");
        for (uint256 i = 0; i < targetChainIds.length; i++) {
            uint32 cid = uint32(targetChainIds[i]);
            if (OriginRouter(payable(router)).isTarget(cid)) continue;
            OriginRouter(payable(router))
                .setRemoteMessenger(cid, InteroperableAddress.formatEvmV1(cid, targetRouterPeer));
            OriginRouter(payable(router)).addTarget(cid);
        }

        // Proceeds route (creator-reward): unwrap inbound WCOEN and hand the native to the factory
        // precompile. Skipped when the WCOEN env is unset.
        address wcoenBridge = vm.envOr("OUTBE_WCOEN_BRIDGE", address(0));
        address wcoenToken = vm.envOr("OUTBE_WCOEN_TOKEN", address(0));
        if (wcoenBridge != address(0) && wcoenToken != address(0)) {
            OriginRouter(payable(router)).setProceedsRoute(wcoenBridge, wcoenToken);
        }

        vm.stopBroadcast();

        console.log("Create3Factory:", address(factory));
        console.log("OriginRouter:", router);
    }
}
