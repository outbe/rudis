// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {console2} from "forge-std/console2.sol";

import {Create3Factory} from "@shared/Create3Factory.sol";
import {DeploySolverEscrow} from "./1_DeploySolverEscrow.s.sol";
import {DeployAuction} from "./2_DeployAuction.s.sol";
import {DeployRouter} from "./3_DeployRouter.s.sol";
import {ConfigureAll} from "./4_ConfigureAll.s.sol";

/// @dev Full deployment + configuration in a single script.
///
/// Deploy order:
///   1. SolverEscrow
///   2. Auction
///   3. RouterAllocator + composition Router (via Create3Factory) - talks to the ERC7786Bridge hub
///   4. Wire all contracts together (same-chain)
///
/// The CREATE3 factory is not deployed here: it is built and deployed once from contracts/shared
/// (`mise run deploy-createx` there), so every project shares one factory address.
///
/// Required env vars:
///   DEPLOYER_PK      - deployer private key
///   CONTRACT_SALT    - salt string for deterministic deployment
///   CREATE3_FACTORY_ADDRESS - CREATE3 factory deployed from contracts/shared
///   BRIDGE_ADDRESS   - deployed ERC7786Bridge (the cross-chain hub facade)
///   ROUTER_OWNER     - contract owner (admin)
///   COMPACT_ADDRESS  - The Compact address
///   COLLATERAL_BPS   - collateral requirement in basis points (e.g. 1000 = 10%)
///
/// Cross-chain wiring (remote routers) is a separate step: ConfigureRouter.s.sol.
contract DeployAll is DeployRouter, DeploySolverEscrow, DeployAuction, ConfigureAll {
    function run() public override(DeployRouter, DeploySolverEscrow, DeployAuction, ConfigureAll) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        string memory salt = vm.envString("CONTRACT_SALT");
        address compact = vm.envAddress("COMPACT_ADDRESS");
        address bridge = vm.envAddress("BRIDGE_ADDRESS");
        uint256 collateralBps = vm.envOr("COLLATERAL_BPS", uint256(1000));

        console2.log("Salt:", salt);

        vm.startBroadcast(deployerPrivateKey);

        address factoryAddr = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        console2.log("Create3Factory:", factoryAddr);

        // Everything below is deterministic from (factory, deployer, salt). If the router already exists, the whole
        // stack is already deployed - skip it: re-deploying escrow/auction/allocator would waste gas and the router's
        // CREATE3 would revert on collision anyway.
        address routerAddr = Create3Factory(factoryAddr).predict(vm.addr(deployerPrivateKey), getRouterSalt(salt));
        if (routerAddr.code.length != 0) {
            console2.log("Already deployed - skipping. Router:", routerAddr);
            vm.stopBroadcast();
            return;
        }

        // 1. Deploy SolverEscrow
        console2.log("[1/4] Deploy SolverEscrow...");
        address escrowAddress = deployEscrow(compact, collateralBps);
        console2.log("  SolverEscrow:", escrowAddress);

        // 2. Deploy Auction
        console2.log("[2/4] Deploy Auction...");
        address auctionAddress = deployAuction(vm.addr(deployerPrivateKey));
        console2.log("  Auction:", auctionAddress);

        // 3. Deploy RouterAllocator + Router via Create3Factory
        console2.log("[3/4] Deploy RouterAllocator + Router...");
        (address routerAddress, address allocatorAddress) =
            deployRouter(factoryAddr, salt, bridge, compact, escrowAddress, auctionAddress);
        console2.log("  Router:", routerAddress);

        // 4. Wire all contracts together
        console2.log("[4/4] Configure all...");
        configureAll(routerAddress, auctionAddress, escrowAddress, allocatorAddress);

        vm.stopBroadcast();

        console2.log("=== DeployAll complete ===");
    }
}
