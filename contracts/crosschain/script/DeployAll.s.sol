// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {console2} from "forge-std/console2.sol";

import {DeployAdapters} from "./1_DeployAdapters.s.sol";
import {DeployBridge} from "./2_DeployBridge.s.sol";
import {ConfigureBridge} from "./3_ConfigureBridge.s.sol";

/// @dev Full hub deploy + wiring on one chain, in one shot:
///   1. Adapters - each deployed only when its endpoint env is set (`LZ_ENDPOINT` / `HYPERLANE_MAILBOX`)
///   2. Bridge (with the active gateway)
///   3. Wire remotes for each `REMOTE_CHAIN_IDS` (remote addresses == local CREATE3 addresses)
/// The CREATE3 factory is not deployed here: it is built and deployed once from contracts/shared.
/// Remote addresses are deterministic, so step 3 is safe even before other chains are deployed.
///
/// Required env: `DEPLOYER_PK` (= bridge owner), `CONTRACT_SALT`, `BRIDGE_OWNER`, `CREATE3_FACTORY_ADDRESS`,
///   at least one of `LZ_ENDPOINT` / `HYPERLANE_MAILBOX`.
/// Optional: `ACTIVE_GATEWAY` ("lz" | "hyperlane"),
///   `REMOTE_CHAIN_IDS` (csv; step 4 is a no-op if unset), `REMOTE_EIDS` (csv, parallel) for LayerZero,
///   `WIRE_LOOPBACK` (route the local chain through the loopback adapter).
contract DeployAll is DeployAdapters, DeployBridge, ConfigureBridge {
    function run() public override(DeployAdapters, DeployBridge, ConfigureBridge) {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        string memory salt = vm.envString("CONTRACT_SALT");
        address owner = vm.envAddress("BRIDGE_OWNER");
        address deployer = vm.addr(deployerPk);

        address lzEndpoint = vm.envOr("LZ_ENDPOINT", address(0));
        address mailbox = vm.envOr("HYPERLANE_MAILBOX", address(0));
        require(lzEndpoint != address(0) || mailbox != address(0), "set LZ_ENDPOINT and/or HYPERLANE_MAILBOX");
        string memory active = vm.envOr("ACTIVE_GATEWAY", string(""));

        console2.log("Salt:", salt);

        vm.startBroadcast(deployerPk);

        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        console2.log("Create3Factory:", factory);

        // 1. Deploy adapters (each only if its endpoint env is present)
        console2.log("[1/3] Deploy adapters...");
        address lz;
        address hl;
        address lb;
        if (lzEndpoint != address(0)) {
            lz = deployLayerZeroAdapter(factory, salt, owner, lzEndpoint);
            console2.log("  LayerZeroGatewayAdapter:", lz);
        }
        if (mailbox != address(0)) {
            hl = deployHyperlaneAdapter(factory, salt, owner, mailbox);
            console2.log("  HyperlaneGatewayAdapter:", hl);
        }
        if (vm.envOr("WIRE_LOOPBACK", false)) {
            lb = deployLoopbackAdapter(factory, salt, deployer, owner);
            console2.log("  LoopbackGatewayAdapter:", lb);
        }

        // 2. Deploy bridge with the active gateway
        console2.log("[2/3] Deploy bridge...");
        address gateway = _pickGateway(active, lz, hl);
        address bridge = deployBridge(factory, salt, owner, gateway);
        console2.log("  active gateway:", gateway);
        console2.log("  ERC7786Bridge:", bridge);

        // 3. Wire remotes (no-op when REMOTE_CHAIN_IDS is unset)
        console2.log("[3/3] Configure remotes...");
        configureBridge(bridge, lz, hl);
        if (lb != address(0)) configureLoopback(bridge, lb);

        vm.stopBroadcast();

        console2.log("=== DeployAll complete ===");
    }

    function _pickGateway(string memory active, address lz, address hl) internal pure returns (address) {
        bytes32 a = keccak256(bytes(active));
        if (a == keccak256("hyperlane")) {
            require(hl != address(0), "hyperlane adapter not deployed");
            return hl;
        }
        if (a == keccak256("lz")) {
            require(lz != address(0), "lz adapter not deployed");
            return lz;
        }
        return lz != address(0) ? lz : hl; // default: prefer LayerZero, else Hyperlane
    }
}
