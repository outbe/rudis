// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {Create3Factory} from "@shared/Create3Factory.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";
import {LayerZeroGatewayAdapter} from "src/adapters/LayerZeroGatewayAdapter.sol";
import {HyperlaneGatewayAdapter} from "src/adapters/HyperlaneGatewayAdapter.sol";

/// @dev Wires the local hub to its counterparts on other chains. Bridge and adapters share one CREATE3 address across
///      chains, so remote addresses equal the local ones (computed here) - env only lists `(chainId, eid)`.
///      Each adapter is wired only if its endpoint env is present (LZ_ENDPOINT / HYPERLANE_MAILBOX). For Hyperlane the
///      remote domain is assumed equal to the chain id. When `WIRE_LOOPBACK` is true, the local chain itself is wired
///      as a destination through the loopback adapter.
///
/// Required env (DEPLOYER_PK must be BRIDGE_OWNER): `DEPLOYER_PK`, `CONTRACT_SALT`, `CREATE3_FACTORY_ADDRESS`,
/// `REMOTE_CHAIN_IDS` (csv); `REMOTE_EIDS` (csv, parallel) when wiring LayerZero.
contract ConfigureBridge is Script {
    function run() public virtual {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        string memory salt = vm.envString("CONTRACT_SALT");
        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        address deployer = vm.addr(deployerPk);

        bool hasLz = vm.envOr("LZ_ENDPOINT", address(0)) != address(0);
        bool hasHl = vm.envOr("HYPERLANE_MAILBOX", address(0)) != address(0);
        bool wireLoopback = vm.envOr("WIRE_LOOPBACK", false);

        address bridgeAddr = _compute(factory, salt, deployer, "ERC7786Bridge");
        address lzAdapter = hasLz ? _compute(factory, salt, deployer, "LayerZeroGatewayAdapter") : address(0);
        address hlAdapter = hasHl ? _compute(factory, salt, deployer, "HyperlaneGatewayAdapter") : address(0);

        vm.startBroadcast(deployerPk);
        configureBridge(bridgeAddr, lzAdapter, hlAdapter);
        if (wireLoopback) configureLoopback(bridgeAddr, _compute(factory, salt, deployer, "LoopbackGatewayAdapter"));
        vm.stopBroadcast();

        console2.log("=== Configure bridge complete ===");
    }

    /// @dev Routes the local chain through the loopback adapter: the hub becomes its own remote and the adapter the
    ///      local chain's gateway. Requires an active broadcast whose sender owns the bridge.
    function configureLoopback(address bridgeAddr, address loopbackAdapter) public {
        ERC7786Bridge(bridgeAddr).registerRemoteBridge(InteroperableAddress.formatEvmV1(block.chainid, bridgeAddr));
        ERC7786Bridge(bridgeAddr).setGateway(block.chainid, loopbackAdapter);
        console2.log("wired loopback for local chainId:", block.chainid);
    }

    /// @dev Wires the local hub to its counterparts on each `REMOTE_CHAIN_IDS`. Requires an active broadcast whose
    ///      sender owns the bridge/adapters. An adapter is wired only when its address is non-zero. Remote
    ///      bridge/adapter addresses equal the local ones (shared CREATE3 address across chains).
    function configureBridge(address bridgeAddr, address lzAdapter, address hlAdapter) public {
        uint256[] memory remoteChainIds = vm.envOr("REMOTE_CHAIN_IDS", ",", new uint256[](0));
        bool hasLz = lzAdapter != address(0);
        bool hasHl = hlAdapter != address(0);

        uint256[] memory remoteEids = hasLz ? vm.envOr("REMOTE_EIDS", ",", new uint256[](0)) : new uint256[](0);
        if (hasLz) require(remoteEids.length == remoteChainIds.length, "REMOTE_EIDS/REMOTE_CHAIN_IDS length mismatch");

        for (uint256 i = 0; i < remoteChainIds.length; i++) {
            uint256 chainId = remoteChainIds[i];

            // Remote bridge shares the local (CREATE3) address.
            ERC7786Bridge(bridgeAddr).registerRemoteBridge(InteroperableAddress.formatEvmV1(chainId, bridgeAddr));

            if (hasLz) {
                LayerZeroGatewayAdapter(lzAdapter)
                    .setPeerWithChain(uint32(remoteEids[i]), bytes32(uint256(uint160(lzAdapter))), chainId);
            }
            if (hasHl) {
                HyperlaneGatewayAdapter(hlAdapter)
                    .setRouterWithChain(uint32(chainId), bytes32(uint256(uint160(hlAdapter))), chainId);
            }

            console2.log("wired remote chainId:", chainId);
        }
    }

    function _compute(address factory, string memory salt, address deployer, string memory label)
        internal
        view
        returns (address)
    {
        return Create3Factory(factory).predict(deployer, keccak256(abi.encodePacked(label, salt)));
    }
}
