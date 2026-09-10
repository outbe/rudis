// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BaseScript} from "./BaseScript.s.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {console} from "forge-std/Script.sol";

import {BundleModulePlugin} from "src/BundleModulePlugin.sol";
import {BundleSpendProtectorHook} from "src/BundleSpendProtectorHook.sol";
import {BundleWithdrawHook} from "src/BundleWithdrawHook.sol";
import {SmartAccountFactory} from "src/SmartAccountFactory.sol";
import {WithdrawalLimitPolicy} from "src/WithdrawalLimitPolicy.sol";
import {SudoPolicy} from "src/kernel/SudoPolicy.sol";

/// @title DeploySmartAccountStack
/// @notice Deploys Credis AA modules and SmartAccountFactory
/// @dev For each contract:
///      1) Predict the CREATE2 address
///      2) Deploy it, or warn if it's already deployed
///      3) Export the address as `export NAME=0x...` and append to the deployment file
/// @dev Reads from env:
///      KERNEL_FACTORY_ADDRESS
///      CALLER_HOOK_ADDRESS
///      ECDSA_SIGNER_ADDRESS
contract DeploySmartAccountStack is BaseScript {
    // Deployed contracts
    BundleModulePlugin public bundleModulePlugin;
    WithdrawalLimitPolicy public withdrawalLimitPolicy;
    BundleSpendProtectorHook public bundleSpendProtectorHook;
    BundleWithdrawHook public bundleWithdrawHook;
    SudoPolicy public sudoPolicy;
    SmartAccountFactory public smartAccountFactory;

    function run() public {
        console.log("=== Deploying Smart Account Stack ===");
        console.log("Network:", getEnvName());
        console.log("Deployer:", msg.sender);
        console.log("Salt Version:", SALT_VERSION);
        console.log("Deployment file:", deploymentFilePath());
        console.log("");

        address kernelFactory = vm.envAddress("KERNEL_FACTORY_ADDRESS");
        address callerHook = vm.envAddress("CALLER_HOOK_ADDRESS");
        address ecdsaSigner = vm.envAddress("ECDSA_SIGNER_ADDRESS");

        _writeDeploymentHeader();

        vm.startBroadcast();

        _deployBundleModulePlugin();
        console.log("");

        _deployWithdrawalLimitPolicy();
        console.log("");

        _deployBundleSpendProtectorHook();
        console.log("");

        _deployBundleWithdrawHook();
        console.log("");

        // Authorize BundleWithdrawHook as the sole dispatchDecreaseBalance caller (OIP-00074).
        // Idempotent on re-run; the broadcast tx must originate from OWNER_ADDRESS (the plugin owner).
        if (bundleModulePlugin.withdrawHook() != address(bundleWithdrawHook)) {
            bundleModulePlugin.setWithdrawHook(address(bundleWithdrawHook));
            console.log("BundleModulePlugin.withdrawHook wired:", address(bundleWithdrawHook));
            console.log("");
        }

        _deploySudoPolicy();
        console.log("");

        _deploySmartAccountFactory(kernelFactory, callerHook, ecdsaSigner);
        console.log("");

        vm.stopBroadcast();
    }

    function _deploySudoPolicy() internal {
        console.log("=== Deploying SudoPolicy ===");

        bytes32 salt = generateSalt("SudoPolicy");
        bytes memory creationCode = type(SudoPolicy).creationCode;
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        if (predicted.code.length > 0) {
            console.log("WARNING: SudoPolicy already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "SudoPolicy address mismatch");
            console.log("SudoPolicy deployed:", deployed);
        }

        sudoPolicy = SudoPolicy(predicted);
        printAndWrite(exportLine("SUDO_POLICY_ADDRESS", vm.toString(predicted)));
    }

    function _writeDeploymentHeader() internal {
        console.log("ENV:");
        printAndWrite(
            string.concat(
                "# Smart account stack deployment at block ",
                vm.toString(vm.getBlockNumber()),
                " timestamp ",
                vm.toString(vm.getBlockTimestamp())
            )
        );
    }

    function _deployBundleModulePlugin() internal {
        console.log("=== Deploying BundleModulePlugin ===");

        // 1) Predict
        bytes32 salt = generateSalt("BundleModulePlugin");
        // owner gates setWithdrawHook; can't use msg.sender (= CREATE2 proxy under always_use_create_2_factory).
        bytes memory creationCode = abi.encodePacked(type(BundleModulePlugin).creationCode, abi.encode(ownerAddress));
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        // 2) Deploy or warn
        if (predicted.code.length > 0) {
            console.log("WARNING: BundleModulePlugin already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "BundleModulePlugin address mismatch");
            console.log("BundleModulePlugin deployed:", deployed);
        }

        bundleModulePlugin = BundleModulePlugin(predicted);

        // 3) Export + write
        printAndWrite(exportLine("BUNDLE_MODULE_PLUGIN_ADDRESS", vm.toString(predicted)));
    }

    function _deployWithdrawalLimitPolicy() internal {
        console.log("=== Deploying WithdrawalLimitPolicy ===");

        // 1) Predict
        bytes32 salt = generateSalt("WithdrawalLimitPolicy");
        bytes memory creationCode = type(WithdrawalLimitPolicy).creationCode;
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        // 2) Deploy or warn
        if (predicted.code.length > 0) {
            console.log("WARNING: WithdrawalLimitPolicy already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "WithdrawalLimitPolicy address mismatch");
            console.log("WithdrawalLimitPolicy deployed:", deployed);
        }

        withdrawalLimitPolicy = WithdrawalLimitPolicy(predicted);

        // 3) Export + write
        printAndWrite(exportLine("WITHDRAWAL_LIMIT_POLICY_ADDRESS", vm.toString(predicted)));
    }

    function _deployBundleSpendProtectorHook() internal {
        console.log("=== Deploying BundleSpendProtectorHook ===");

        // 1) Predict
        bytes32 salt = generateSalt("BundleSpendProtectorHook");
        bytes memory creationCode =
            abi.encodePacked(type(BundleSpendProtectorHook).creationCode, abi.encode(address(bundleModulePlugin)));
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        // 2) Deploy or warn
        if (predicted.code.length > 0) {
            console.log("WARNING: BundleSpendProtectorHook already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "BundleSpendProtectorHook address mismatch");
            console.log("BundleSpendProtectorHook deployed:", deployed);
        }

        bundleSpendProtectorHook = BundleSpendProtectorHook(predicted);

        // 3) Export + write
        printAndWrite(exportLine("BUNDLE_SPEND_PROTECTOR_HOOK_ADDRESS", vm.toString(predicted)));
    }

    function _deployBundleWithdrawHook() internal {
        console.log("=== Deploying BundleWithdrawHook ===");

        // 1) Predict
        bytes32 salt = generateSalt("BundleWithdrawHook");
        bytes memory creationCode =
            abi.encodePacked(type(BundleWithdrawHook).creationCode, abi.encode(address(bundleModulePlugin)));
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        // 2) Deploy or warn
        if (predicted.code.length > 0) {
            console.log("WARNING: BundleWithdrawHook already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "BundleWithdrawHook address mismatch");
            console.log("BundleWithdrawHook deployed:", deployed);
        }

        bundleWithdrawHook = BundleWithdrawHook(predicted);

        // 3) Export + write
        printAndWrite(exportLine("BUNDLE_WITHDRAW_HOOK_ADDRESS", vm.toString(predicted)));
    }

    function _deploySmartAccountFactory(address kernelFactory, address callerHook, address ecdsaSigner) internal {
        console.log("=== Deploying SmartAccountFactory ===");

        // 1) Predict
        bytes32 salt = generateSalt("SmartAccountFactory");
        bytes memory creationCode = abi.encodePacked(
            type(SmartAccountFactory).creationCode,
            abi.encode(
                kernelFactory,
                address(sudoPolicy),
                address(bundleModulePlugin),
                callerHook,
                address(bundleSpendProtectorHook),
                address(withdrawalLimitPolicy),
                ecdsaSigner,
                address(bundleWithdrawHook)
            )
        );
        address predicted = Create2.computeAddress(salt, keccak256(creationCode), CREATE2_FACTORY);

        // 2) Deploy or warn
        if (predicted.code.length > 0) {
            console.log("WARNING: SmartAccountFactory already deployed at:", predicted);
        } else {
            address deployed = Create2.deploy(0, salt, creationCode);
            require(deployed == predicted, "SmartAccountFactory address mismatch");
            console.log("SmartAccountFactory deployed:", deployed);
        }

        smartAccountFactory = SmartAccountFactory(predicted);

        // 3) Export + write
        printAndWrite(exportLine("SMART_ACCOUNT_FACTORY_ADDRESS", vm.toString(predicted)));
    }
}
