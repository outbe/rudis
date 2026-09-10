// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BaseScript} from "./BaseScript.s.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";
import {console} from "forge-std/console.sol";

/// @dev Prints the CREATE3 address every intex proxy lands on for the current salt. The node pins two
///      of them as constants, so they have to be known before the deploy rather than read after it.
contract PredictAddresses is BaseScript {
    string[6] internal PREFIXES =
        ["IntexAuction", "EscrowAdapter", "TargetRouter", "OriginRouter", "IntexNFT1155", "IntexNFT1155Bridge"];

    /// @dev Env: DEPLOYER_PRIVATE_KEY, same as the deploy scripts, since the deployer namespaces the salt.
    function run() external {
        address deployer = vm.addr(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        Create3Factory factory = create3Factory();

        console.log("salt version:", saltVersion());
        console.log("deployer:    ", deployer);
        console.log("factory:     ", address(factory));
        for (uint256 i = 0; i < PREFIXES.length; i++) {
            console.log(PREFIXES[i], predictProxy(factory, deployer, PREFIXES[i]));
        }
    }
}
