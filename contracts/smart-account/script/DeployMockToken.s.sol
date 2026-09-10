// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BaseScript} from "./BaseScript.s.sol";
import {console} from "forge-std/Script.sol";
import {MockUSD} from "src/mocks/MockUSD.sol";

/// @title Deploy Mock ERC20 Tokens for Testing
/// @notice Deploys mock tokens for use in Credis protocol testing using CREATE2
contract DeployMockToken is BaseScript {
    function run() public {
        // Define salt for CREATE2 deployment (can be customized via env var)
        bytes32 salt = generateSalt("MockUSD");

        // Compute deterministic CREATE2 address before deploying
        bytes32 initCodeHash = keccak256(type(MockUSD).creationCode);
        address expectedAddress = vm.computeCreate2Address(salt, initCodeHash);

        console.log("\n=== MockUSD Tokens Deploy with CREATE2 ===");
        console.log("Salt:", vm.toString(salt));

        if (expectedAddress.code.length > 0) {
            console.log("Already deployed, skipping deployment.");
        } else {
            vm.startBroadcast();
            MockUSD erc20Token = new MockUSD{salt: salt}();
            vm.stopBroadcast();
            expectedAddress = address(erc20Token);
            console.log("Deployed success.");
        }

        console.log("");
        console.log("Address:", expectedAddress);
        console.log("Total Supply:", MockUSD(expectedAddress).totalSupply() / 10 ** 6, "USDT0");

        console.log("");
        console.log("ENV:");
        printAndWrite(exportLine("ERC20_ADDRESS", vm.toString(expectedAddress)));
        console.log("");
        console.log("Note: The contract will deploy to the same address on any chain");
        console.log("when using the same deployer address and salt.");
    }
}
