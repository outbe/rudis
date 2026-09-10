// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

/* solhint-disable max-states-count */
contract BaseScript is Script {
    // Salt configuration - change this to deploy to different addresses
    // Using the same salt across different chains will result in the same addresses
    // To deploy to different addresses, use: SALT_VERSION = "v1.0.1", "v2.0.0", etc.
    string public constant SALT_VERSION = "v4.0.0";

    // Note: CREATE2_FACTORY (0x4e59b44847b379578588920cA78FbF26c0B4956C) is inherited from Script
    // and used when always_use_create_2_factory = true in foundry.toml

    address internal ownerAddress;

    constructor() {}

    function setUp() public {
        ownerAddress = vm.envOr("OWNER_ADDRESS", msg.sender);
    }

    /// @notice Generate export string for deployment output
    /// @param name Variable name (e.g., "CCA_REGISTRY_ADDRESS")
    /// @param value Variable value (e.g., "0x123...")
    /// @return Complete export statement (e.g., "export CCA_REGISTRY_ADDRESS=0x123...")
    function exportLine(string memory name, string memory value) public pure returns (string memory) {
        return string.concat("export ", name, "=", value);
    }

    /// @notice Get environment name based on chain ID
    /// @dev Used for naming deployment output files (e.g., ".anvil.deployment.env")
    /// @return Environment name string
    function getEnvName() public view returns (string memory) {
        uint256 chainId = vm.getChainId();

        if (chainId == 31337) return "anvil";
        if (chainId == 424242) return "outbe-dev";
        if (chainId == 424243) return "local-dev";
        if (chainId == 97) return "bsc-testnet";
        if (chainId == 1) return "mainnet";
        if (chainId == 11155111) return "sepolia";
        if (chainId == 137) return "polygon";
        if (chainId == 42161) return "arbitrum";
        if (chainId == 10) return "optimism";
        if (chainId == 8453) return "base";
        if (chainId == 512512) return "outbe-privnet";
        if (chainId == 512215) return "local-reth";
        if (chainId == 70860602) return "outbe-peira";

        return string.concat("chain-", vm.toString(chainId));
    }

    /// @notice Get deployment output file path based on current chain
    /// @return File name (e.g., ".anvil.deployment.env")
    function deploymentFile() public view returns (string memory) {
        return string.concat(".", getEnvName(), ".deployment.env");
    }

    /// @notice Resolve the absolute path for deployment output.
    /// @dev If `DEPLOYMENT_ENV_FILE` env var is set (typically by deploy.sh),
    ///      it overrides the chain-id-derived default. This lets the shell
    ///      caller pin the file name so both writer and sourcer agree.
    function deploymentFilePath() public view returns (string memory) {
        string memory envFile = vm.envOr("DEPLOYMENT_ENV_FILE", string(""));
        if (bytes(envFile).length > 0) {
            return envFile;
        }
        return string.concat(vm.projectRoot(), "/", deploymentFile());
    }

    function writeToDeploymentFile(string memory data) public {
        vm.writeLine(deploymentFilePath(), data);
    }

    function printAndWrite(string memory data) public {
        console.log(data);
        writeToDeploymentFile(data);
    }

    function generateSalt(string memory prefix) public pure returns (bytes32) {
        string memory saltString = string.concat(prefix, SALT_VERSION);
        bytes32 salt = keccak256(abi.encodePacked(saltString));
        return salt;
    }

    function getRpcUrl() public view returns (string memory) {
        return vm.envString("RPC_URL");
    }
}
