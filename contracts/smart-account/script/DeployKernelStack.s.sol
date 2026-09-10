// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BaseScript} from "./BaseScript.s.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {console} from "forge-std/Script.sol";

import {KernelUUPS} from "@zerodev/kernel/KernelUUPS.sol";
import {KernelImmutableECDSA} from "@zerodev/kernel/KernelImmutableECDSA.sol";
import {KernelFactory} from "@zerodev/kernel/KernelFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib, ENTRYPOINT_0_9} from "../test/utils/EntryPointLib.sol";
import {CallerHook} from "src/kernel/CallerHook.sol";
import {ECDSASigner} from "src/kernel/ECDSASigner.sol";

/// @title DeployKernelStack
/// @notice Deploys ERC-4337 (EntryPoint v0.9) + ZeroDev Kernel v4 infrastructure.
/// @dev For each contract:
///      1) Predict the CREATE2 address
///      2) Deploy it, or warn if it's already deployed
///      3) Export the address as `export NAME=0x...` and append to the deployment file
contract DeployKernelStack is BaseScript {
    // Deployed contracts
    IEntryPoint public entrypoint;
    KernelUUPS public kernelUUPS;
    KernelImmutableECDSA public kernelImmutableECDSA;
    KernelFactory public kernelFactory;
    CallerHook public callerHook;
    ECDSASigner public ecdsaSigner;

    function run() public {
        console.log("=== Deploying Kernel Stack (v4) ===");
        console.log("Network:", getEnvName());
        console.log("Deployer:", msg.sender);
        console.log("Salt Version:", SALT_VERSION);
        console.log("Deployment file:", deploymentFilePath());
        console.log("");

        _writeDeploymentHeader();

        vm.startBroadcast();

        _deployEntryPoint();
        console.log("");

        _deployKernelImpls();
        console.log("");

        _deployKernelFactory();
        console.log("");

        _deployCallerHook();
        console.log("");

        _deployECDSASigner();
        console.log("");

        vm.stopBroadcast();
    }

    function _writeDeploymentHeader() internal {
        console.log("ENV:");
        printAndWrite(
            string.concat(
                "# Kernel stack deployment at block ",
                vm.toString(vm.getBlockNumber()),
                " timestamp ",
                vm.toString(vm.getBlockTimestamp())
            )
        );
    }

    function _deployEntryPoint() internal {
        console.log("=== Deploying EntryPoint v0.9 ===");

        // Canonical singleton address (deployed via the deterministic CREATE2 deployer).
        address predicted = ENTRYPOINT_0_9;

        if (predicted.code.length > 0) {
            console.log("WARNING: EntryPoint already deployed at:", predicted);
            entrypoint = IEntryPoint(payable(predicted));
        } else {
            entrypoint = EntryPointLib.deploy();
            require(address(entrypoint) == predicted, "EntryPoint address mismatch");
            console.log("EntryPoint deployed:", address(entrypoint));
        }

        printAndWrite(exportLine("ENTRYPOINT_ADDRESS", vm.toString(address(entrypoint))));
    }

    function _deployKernelImpls() internal {
        console.log("=== Deploying Kernel Implementations (UUPS + ImmutableECDSA) ===");

        // KernelUUPS
        bytes32 uupsSalt = generateSalt("KernelUUPS");
        bytes memory uupsCode = abi.encodePacked(type(KernelUUPS).creationCode, abi.encode(address(entrypoint)));
        address uupsPredicted = Create2.computeAddress(uupsSalt, keccak256(uupsCode), CREATE2_FACTORY);
        if (uupsPredicted.code.length > 0) {
            console.log("WARNING: KernelUUPS already deployed at:", uupsPredicted);
        } else {
            address deployed = Create2.deploy(0, uupsSalt, uupsCode);
            require(deployed == uupsPredicted, "KernelUUPS address mismatch");
            console.log("KernelUUPS deployed:", deployed);
        }
        kernelUUPS = KernelUUPS(payable(uupsPredicted));
        printAndWrite(exportLine("KERNEL_UUPS_ADDRESS", vm.toString(uupsPredicted)));

        // KernelImmutableECDSA
        bytes32 immSalt = generateSalt("KernelImmutableECDSA");
        bytes memory immCode =
            abi.encodePacked(type(KernelImmutableECDSA).creationCode, abi.encode(address(entrypoint)));
        address immPredicted = Create2.computeAddress(immSalt, keccak256(immCode), CREATE2_FACTORY);
        if (immPredicted.code.length > 0) {
            console.log("WARNING: KernelImmutableECDSA already deployed at:", immPredicted);
        } else {
            address deployed = Create2.deploy(0, immSalt, immCode);
            require(deployed == immPredicted, "KernelImmutableECDSA address mismatch");
            console.log("KernelImmutableECDSA deployed:", deployed);
        }
        kernelImmutableECDSA = KernelImmutableECDSA(payable(immPredicted));
        printAndWrite(exportLine("KERNEL_IMMUTABLE_ECDSA_ADDRESS", vm.toString(immPredicted)));
    }

    function _deployKernelFactory() internal {
        console.log("=== Deploying KernelFactory ===");

        bytes32 salt = generateSalt("KernelFactory");
        bytes memory creationCode = abi.encodePacked(
            type(KernelFactory).creationCode, abi.encode(address(kernelUUPS), address(kernelImmutableECDSA))
        );
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        if (predicted.code.length > 0) {
            console.log("WARNING: KernelFactory already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "KernelFactory address mismatch");
            console.log("KernelFactory deployed:", deployed);
        }

        kernelFactory = KernelFactory(predicted);
        printAndWrite(exportLine("KERNEL_FACTORY_ADDRESS", vm.toString(predicted)));
    }

    function _deployCallerHook() internal {
        console.log("=== Deploying CallerHook ===");

        bytes32 salt = generateSalt("CallerHook");
        bytes memory creationCode = type(CallerHook).creationCode;
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        if (predicted.code.length > 0) {
            console.log("WARNING: CallerHook already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "CallerHook address mismatch");
            console.log("CallerHook deployed:", deployed);
        }

        callerHook = CallerHook(predicted);
        printAndWrite(exportLine("CALLER_HOOK_ADDRESS", vm.toString(predicted)));
    }

    function _deployECDSASigner() internal {
        console.log("=== Deploying ECDSASigner ===");

        bytes32 salt = generateSalt("ECDSASigner");
        bytes memory creationCode = type(ECDSASigner).creationCode;
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        if (predicted.code.length > 0) {
            console.log("WARNING: ECDSASigner already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "ECDSASigner address mismatch");
            console.log("ECDSASigner deployed:", deployed);
        }

        ecdsaSigner = ECDSASigner(predicted);
        printAndWrite(exportLine("ECDSA_SIGNER_ADDRESS", vm.toString(predicted)));
    }
}
