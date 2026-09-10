// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Create3Factory} from "../src/Create3Factory.sol";

/// @dev Deploys the protocol-wide CREATE3 factory through the canonical Arachnid CREATE2 deployer
///      with a pinned salt. The factory is ownerless and has no constructor, so its init code -
///      and therefore its address - is identical on every chain. This is the only project that
///      builds it; every other project takes the address as CREATE3_FACTORY_ADDRESS.
///
/// Required env vars:
///   DEPLOYER_PK - deployer private key
contract DeployCreate3Factory is Script {
    /// @notice Pinned salt for the factory itself. Bumping it moves every CREATE3 address.
    bytes32 internal constant FACTORY_SALT = keccak256("outbe:Create3Factory:v1.0.0");

    function run() public virtual {
        vm.startBroadcast(vm.envUint("DEPLOYER_PK"));
        address factory = deployCreate3Factory();
        vm.stopBroadcast();

        console2.log("CREATE3_FACTORY_ADDRESS=", factory);
    }

    /// @notice Deploys the factory if absent, else returns the existing one.
    function deployCreate3Factory() public returns (address) {
        // CREATE2_FACTORY is Arachnid's deterministic deployment proxy, inherited from Script.
        require(CREATE2_FACTORY.code.length != 0, "Arachnid CREATE2 deployer not present on this chain");

        bytes memory initCode = type(Create3Factory).creationCode;
        address predicted = vm.computeCreate2Address(FACTORY_SALT, keccak256(initCode), CREATE2_FACTORY);
        if (predicted.code.length != 0) {
            console2.log("Create3Factory already deployed, reusing:", predicted);
            return predicted;
        }

        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(FACTORY_SALT, initCode));
        require(ok, "Create3Factory deploy failed");
        require(predicted.code.length != 0, "Create3Factory missing after deploy");
        return predicted;
    }
}
