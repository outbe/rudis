// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Whitelist} from "../src/Whitelist.sol";

/// @dev Deploys a {Whitelist} through the canonical CREATE2 deployer at a pinned salt, so it lands on
///      the same address on every chain and one WHITELIST_ADDRESS wires every consumer. The owner is
///      the only constructor argument reaching the address, and it is the same admin everywhere.
///
/// Required env vars:
///   DEPLOYER_PK       - deployer private key; any key works
///   WHITELIST_OWNER   - registry admin. Part of the address: keep it identical on every chain.
/// Optional:
///   WHITELIST_INITIAL - csv of addresses to seed with; needs DEPLOYER_PK to be WHITELIST_OWNER
contract DeployWhitelist is Script {
    /// @notice Pinned salt for the registry. Bumping it moves the registry to a fresh address.
    bytes32 internal constant WHITELIST_SALT = keccak256("outbe:Whitelist:v1.0.0");

    function run() public virtual {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address owner = vm.envAddress("WHITELIST_OWNER");
        address[] memory initial = vm.envOr("WHITELIST_INITIAL", ",", new address[](0));

        // add() is owner-only: fail before broadcasting, not after the registry is deployed.
        require(
            initial.length == 0 || owner == vm.addr(deployerPrivateKey),
            "WHITELIST_INITIAL needs DEPLOYER_PK to be WHITELIST_OWNER; otherwise seed with add() from the owner"
        );

        vm.startBroadcast(deployerPrivateKey);

        address whitelist = deployWhitelist(owner);
        if (initial.length != 0) {
            Whitelist(whitelist).add(initial);
            console2.log("  seeded entries:", initial.length);
        }

        vm.stopBroadcast();

        console2.log("  owner:", owner);
        console2.log("WHITELIST_ADDRESS=", whitelist);
    }

    /// @dev Empty initial list on purpose: entries would otherwise enter the init code and move the address.
    function initCode(address owner) public pure returns (bytes memory) {
        return abi.encodePacked(type(Whitelist).creationCode, abi.encode(owner, new address[](0)));
    }

    /// @notice Predicts the registry address for `owner` without deploying.
    function predictWhitelist(address owner) public pure returns (address) {
        return vm.computeCreate2Address(WHITELIST_SALT, keccak256(initCode(owner)), CREATE2_FACTORY);
    }

    /// @notice Deploys the registry if absent, else returns the existing one.
    function deployWhitelist(address owner) public returns (address) {
        // CREATE2_FACTORY is Arachnid's deployment proxy, inherited from Script.
        require(CREATE2_FACTORY.code.length != 0, "Arachnid CREATE2 deployer not present on this chain");

        address predicted = predictWhitelist(owner);
        if (predicted.code.length != 0) {
            console2.log("Whitelist already deployed, reusing:", predicted);
            return predicted;
        }

        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(WHITELIST_SALT, initCode(owner)));
        require(ok, "Whitelist deploy failed");
        require(predicted.code.length != 0, "Whitelist missing after deploy");
        return predicted;
    }
}
