// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Auction} from "../src/Auction.sol";

/// @dev Deployment script for standalone Auction contract.
///
/// Required env vars:
///   DEPLOYER_PK      - deployer private key
///   AUCTION_OWNER    - auction contract owner (admin)
contract DeployAuction is Script {
    function run() public virtual {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address auctionOwner = vm.envAddress("AUCTION_OWNER");

        vm.startBroadcast(deployerPrivateKey);
        address auction = deployAuction(auctionOwner);
        vm.stopBroadcast();

        console2.log("Auction deployed at:", auction);
    }

    function deployAuction(address auctionOwner) public returns (address) {
        Auction auction = new Auction(auctionOwner);
        console2.log("  Auction owner:", auctionOwner);
        return address(auction);
    }
}
