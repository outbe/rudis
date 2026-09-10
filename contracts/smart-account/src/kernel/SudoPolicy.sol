// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyBase} from "kernel-7579-plugins/base/PolicyBase.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "@zerodev/kernel/types/Constants.sol";

/// @title SudoPolicy
/// @notice Always-pass ERC-7579 policy (module type 5) that imposes no restriction.
/// @dev Used to give the account owner a permission-based root validation. Kernel v4 cannot attach
///      an execution hook to a plain root validator at initialization (the hook must be installed
///      before the root package, but the root is always `packages[0]`, installed first). Modelling
///      the owner as a permission `[SudoPolicy + ECDSASigner + BundleSpendProtectorHook]` lets the
///      hook install before the signer initializes the validation. This policy grants full,
///      root-equivalent authority to the owner, matching the Kernel v3.3 root-validator behavior;
///      no spending/admin restriction is added here.
contract SudoPolicy is PolicyBase {
    /// @notice Number of active policy installs per wallet (permission installs referencing this policy).
    mapping(address wallet => uint256) public usedIds;

    /// @inheritdoc PolicyBase
    /// @dev Always passes: returns success with no time bounds.
    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable override returns (uint256) {
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    /// @inheritdoc PolicyBase
    /// @dev Always passes for ERC-1271 requests routed through the owner permission.
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    // Not part of the kernel-7579-plugins `IModule`; plain declaration (no `override`).
    function isInitialized(address wallet) external view returns (bool) {
        return usedIds[wallet] > 0;
    }

    function _policyOninstall(bytes32, bytes calldata) internal override {
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32, bytes calldata) internal override {
        if (usedIds[msg.sender] > 0) usedIds[msg.sender]--;
    }
}
