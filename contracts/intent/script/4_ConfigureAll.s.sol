// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {Auction} from "../src/Auction.sol";
import {SolverEscrow} from "../src/SolverEscrow.sol";
import {RouterAllocator} from "../src/allocators/RouterAllocator.sol";
import {Router} from "../src/router/Router.sol";

/// @dev Post-deployment wiring:
///   1. escrow.setAuthorizedCaller(router)
///   2. auction.setRouter(router)
///   3. allocator.addOperator(router)
///   4. router.setWhitelist(WHITELIST_ADDRESS) when set (gates who may open orders)
///   5. router.setRemoteRouter(chainId, ...) for each REMOTE_CHAIN_IDS (same CREATE3 address across chains)
/// (router->auction is immutable, bound at router construction.)
/// ConfigureRouter.s.sol remains as a standalone helper to add/update a single remote later.
///
/// Required env vars:
///   DEPLOYER_PK       - deployer private key
///   ROUTER_ADDRESS    - deployed Router address
///   AUCTION_ADDRESS   - deployed Auction address
///   ESCROW_ADDRESS    - deployed SolverEscrow address
///   ALLOCATOR_ADDRESS - deployed RouterAllocator address
/// Optional:
///   REMOTE_CHAIN_IDS      - csv of remote EVM chain ids to register (skipped if unset)
///   AUCTION_COMMIT_PERIOD - commit window in seconds (skipped if unset; set per target chain)
///   AUCTION_REVEAL_PERIOD - reveal window in seconds (skipped if unset; set per target chain)
///   AUCTION_MAX_QUOTES    - max revealed quotes per order (skipped if unset)
///   WHITELIST_ADDRESS     - Whitelist registry gating open() (skipped if unset, leaving it open)
contract ConfigureAll is Script {
    function run() public virtual {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address routerAddress = vm.envAddress("ROUTER_ADDRESS");
        address auctionAddress = vm.envAddress("AUCTION_ADDRESS");
        address escrowAddress = vm.envAddress("ESCROW_ADDRESS");
        address allocatorAddress = vm.envAddress("ALLOCATOR_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);
        configureAll(routerAddress, auctionAddress, escrowAddress, allocatorAddress);
        vm.stopBroadcast();

        console2.log("=== Config complete ===");
    }

    function configureAll(
        address routerAddress,
        address auctionAddress,
        address escrowAddress,
        address allocatorAddress
    ) public {
        // 1. Escrow -> Router
        SolverEscrow(escrowAddress).setAuthorizedCaller(routerAddress);
        console2.log("  escrow.setAuthorizedCaller done");

        // 2. Auction -> Router
        Auction(auctionAddress).setRouter(routerAddress);
        console2.log("  auction.setRouter done");

        uint256 commitPeriod = vm.envOr("AUCTION_COMMIT_PERIOD", uint256(0));
        if (commitPeriod != 0) {
            Auction(auctionAddress).setCommitPeriod(commitPeriod);
            console2.log("  auction.setCommitPeriod:", commitPeriod);
        }

        uint256 revealPeriod = vm.envOr("AUCTION_REVEAL_PERIOD", uint256(0));
        if (revealPeriod != 0) {
            Auction(auctionAddress).setRevealPeriod(revealPeriod);
            console2.log("  auction.setRevealPeriod:", revealPeriod);
        }

        uint256 maxQuotes = vm.envOr("AUCTION_MAX_QUOTES", uint256(0));
        if (maxQuotes != 0) {
            Auction(auctionAddress).setMaxQuotesPerOrder(maxQuotes);
            console2.log("  auction.setMaxQuotesPerOrder:", maxQuotes);
        }

        // 3. Allocator -> Router (skipped when the router was reused: its allocator is already wired)
        if (allocatorAddress != address(0)) {
            RouterAllocator(allocatorAddress).addOperator(routerAddress);
            console2.log("  allocator.addOperator done");
        } else {
            console2.log("  allocator.addOperator skipped (router reused)");
        }

        // Router -> Auction binding is immutable (set at router construction); no setAuction step.

        // 4. Gate order opening on the shared Whitelist registry (left open when unset).
        address whitelist = vm.envOr("WHITELIST_ADDRESS", address(0));
        if (whitelist != address(0)) {
            Router(routerAddress).setWhitelist(whitelist);
            console2.log("  router.setWhitelist done");
        }

        // 5. Cross-chain: register the matching Router on each remote chain. The remote Router shares this Router's
        //    CREATE3 address, so its interop address is (chainId, routerAddress).
        uint256[] memory remoteChainIds = vm.envOr("REMOTE_CHAIN_IDS", ",", new uint256[](0));
        for (uint256 i = 0; i < remoteChainIds.length; i++) {
            uint256 chainId = remoteChainIds[i];
            Router(routerAddress)
                .setRemoteRouter(uint32(chainId), InteroperableAddress.formatEvmV1(chainId, routerAddress));
            console2.log("  remote Router set for chainId:", chainId);
        }
    }
}
