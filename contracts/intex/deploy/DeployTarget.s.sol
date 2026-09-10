// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {console} from "forge-std/console.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {BaseScript} from "./BaseScript.s.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";

/// @title DeployTarget
/// @author Outbe
/// @notice Deploy the auction target stack on one chain: the NFT collection + bridge, EscrowAdapter,
///         IntexAuction and TargetRouter. Uniform for every target - including the origin chain as a
///         loopback target (origin==target): the shared NFT/bridge fall out of idempotent CREATE3
///         deploy, and the bridge meshes only with OTHER targets, so it never self-peers.
/// @dev Env: DEPLOYER_PRIVATE_KEY, BRIDGE_ADDRESS, ORIGIN_CHAIN_ID (where OriginRouter lives),
///      TARGET_CHAIN_IDS (comma-separated, for the NFT-bridge mesh), optional WCOEN_BRIDGE (proceeds
///      route). The deployer is admin + delegate; app wiring (escrow/compact, roles) is a
///      separate step. Peers are CREATE3-deterministic across chains.
contract DeployTarget is BaseScript {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address admin = deployer;
        address delegate = deployer;
        address bridge = vm.envAddress("BRIDGE_ADDRESS");
        uint32 originChainId = uint32(vm.envUint("ORIGIN_CHAIN_ID"));
        uint256[] memory targetChainIds = vm.envUint("TARGET_CHAIN_IDS", ",");
        uint32 local = uint32(block.chainid);

        vm.startBroadcast(pk);

        Create3Factory factory = create3Factory();

        // Shared NFT collection + bridge: on a remote target these deploy here; on the origin loopback
        // target they already exist on this chain, so idempotent deployProxy returns the existing ones.
        address nft = deployProxy(
            factory,
            deployer,
            "IntexNFT1155",
            address(new IntexNFT1155()),
            abi.encodeCall(IntexNFT1155.initialize, (admin))
        );
        address escrow = deployProxy(
            factory,
            deployer,
            "EscrowAdapter",
            address(new EscrowAdapter()),
            abi.encodeCall(EscrowAdapter.initialize, (admin))
        );
        address auction = deployProxy(
            factory,
            deployer,
            "IntexAuction",
            address(new IntexAuction()),
            abi.encodeCall(IntexAuction.initialize, (admin))
        );
        address nftBridge = deployProxy(
            factory,
            deployer,
            "IntexNFT1155Bridge",
            address(new IntexNFT1155Bridge(nft, bridge)),
            abi.encodeCall(IntexNFT1155Bridge.initialize, (delegate))
        );
        address router = deployProxy(
            factory,
            deployer,
            "TargetRouter",
            address(new TargetRouter(bridge, originChainId)),
            abi.encodeCall(TargetRouter.initialize, (delegate))
        );

        // Peer the router with the OriginRouter (same address on every chain via CREATE3).
        TargetRouter(payable(router))
            .setRemoteMessenger(
                originChainId,
                InteroperableAddress.formatEvmV1(originChainId, predictProxy(factory, deployer, "OriginRouter"))
            );

        // Mesh the NFT bridge with every OTHER target's bridge (all at the same CREATE3 address).
        // Skipping `local` means the origin loopback target never self-peers the bridge.
        address bridgePeer = predictProxy(factory, deployer, "IntexNFT1155Bridge");
        for (uint256 i = 0; i < targetChainIds.length; i++) {
            uint32 cid = uint32(targetChainIds[i]);
            if (cid == local) continue;
            IntexNFT1155Bridge(payable(nftBridge))
                .setRemoteMessenger(cid, InteroperableAddress.formatEvmV1(cid, bridgePeer));
        }

        // Proceeds route (creator-reward): the escrow hands finalized proceeds to the router, which
        // bridges them to the OriginRouter for creator payout. Skipped when WCOEN_BRIDGE is unset.
        address wcoenBridge = vm.envOr("WCOEN_BRIDGE", address(0));
        if (wcoenBridge != address(0)) {
            EscrowAdapter(payable(escrow)).setProceedsRecipient(router);
            TargetRouter(payable(router)).setProceedsRoute(wcoenBridge, predictProxy(factory, deployer, "OriginRouter"));
        }

        // Gate bid commits on a Whitelist registry (left open when unset).
        address whitelist = vm.envOr("WHITELIST_ADDRESS", address(0));
        if (whitelist != address(0)) {
            IntexAuction(auction).setWhitelist(whitelist);
            console.log("IntexAuction whitelist:", whitelist);
        }

        vm.stopBroadcast();

        console.log("Create3Factory:", address(factory));
        console.log("IntexNFT1155:", nft);
        console.log("EscrowAdapter:", escrow);
        console.log("IntexAuction:", auction);
        console.log("IntexNFT1155Bridge:", nftBridge);
        console.log("TargetRouter:", router);
    }
}
