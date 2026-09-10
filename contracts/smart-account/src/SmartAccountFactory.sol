// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {ICca} from "@precompiles/ICca.sol";
import {ISmartAccountFactory} from "./interfaces/ISmartAccountFactory.sol";
import {IKernelFactory} from "./interfaces/kernel/IKernelFactory.sol";
import {BundleModulePlugin} from "./BundleModulePlugin.sol";
import {IERC7579Account} from "@zerodev/kernel/interfaces/IERC7579Account.sol";
import {Install} from "@zerodev/kernel/types/Structs.sol";
import {CallType, PermissionId} from "@zerodev/kernel/types/Types.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    CALLTYPE_SINGLE
} from "@zerodev/kernel/types/Constants.sol";

/// @title SmartAccountFactory
/// @notice Deploys Credis-configured Kernel v4 smart accounts.
/// @dev Kernel v4 initializes an account from an ordered `Install[]` package list where `packages[0]`
///      becomes the root validation and every package installs strictly in order. A validation's
///      hook must be enabled *before* the package that references it - impossible for a plain root
///      validator (nothing precedes `packages[0]`). We therefore model the OWNER as a permission
///      `[SudoPolicy(always-pass) + ECDSASigner(owner)]` carrying `BundleSpendProtectorHook` when
///      bundle tokens are configured, installed as `[policy, hook, signer]` so the hook is enabled
///      before the signer initializes the validation. Each CCA is a per-token permission
///      `[WithdrawalLimitPolicy + ECDSASigner(cca)]` guarded by `BundleWithdrawHook`. This preserves
///      the Kernel v3.3 behavior (owner has full authority; the hook enforces the bundle reserve).
contract SmartAccountFactory is ISmartAccountFactory {
    IKernelFactory private immutable _KERNEL_FACTORY;
    address private immutable _SUDO_POLICY;
    address private immutable _BUNDLE_MODULE_PLUGIN;
    address private immutable _CALLER_HOOK;
    address private immutable _BUNDLE_SPEND_PROTECTOR_HOOK;
    address private immutable _WITHDRAWAL_LIMIT_POLICY;
    address private immutable _ECDSA_SIGNER;
    address private immutable _BUNDLE_WITHDRAW_HOOK;

    /// @notice Daily withdrawal limit enforced by WithdrawalLimitPolicy (6-decimal USDC units)
    uint256 public constant DAILY_LIMIT = 1000e6;
    uint48 public constant LIMIT_INTERVAL = 1 days;

    /// @notice Credis Card Agent precompile.
    /// @dev A protocol address, not a deployment parameter: an injectable registry could be
    ///      pointed at a look-alike that reports every agent active, which would silently defeat
    ///      the standing check below. This also confines the factory to Outbe chains - elsewhere
    ///      0x1011 has no code and `createAccount` reverts on the empty return data.
    address public constant CCA_REGISTRY = 0x0000000000000000000000000000000000001011;

    /// @notice Thrown when the CCA is not in good standing at the registry.
    /// @param state The state actually recorded; `Unknown` means it never registered.
    error CcaNotActive(address cca, ICca.State state);

    constructor(
        address kernelFactory_,
        address sudoPolicy_,
        address bundleModulePlugin_,
        address callerHook_,
        address bundleSpendProtectorHook_,
        address withdrawalLimitPolicy_,
        address ecdsaSigner_,
        address bundleWithdrawHook_
    ) {
        _KERNEL_FACTORY = IKernelFactory(kernelFactory_);
        _SUDO_POLICY = sudoPolicy_;
        _BUNDLE_MODULE_PLUGIN = bundleModulePlugin_;
        _CALLER_HOOK = callerHook_;
        _BUNDLE_SPEND_PROTECTOR_HOOK = bundleSpendProtectorHook_;
        _WITHDRAWAL_LIMIT_POLICY = withdrawalLimitPolicy_;
        _ECDSA_SIGNER = ecdsaSigner_;
        _BUNDLE_WITHDRAW_HOOK = bundleWithdrawHook_;
    }

    // -- ISmartAccountFactory getters -------------------------------------

    /// @inheritdoc ISmartAccountFactory
    function kernelFactory() external view override returns (address) {
        return address(_KERNEL_FACTORY);
    }

    /// @inheritdoc ISmartAccountFactory
    function sudoPolicy() external view override returns (address) {
        return _SUDO_POLICY;
    }

    /// @inheritdoc ISmartAccountFactory
    function bundleModulePlugin() external view override returns (address) {
        return _BUNDLE_MODULE_PLUGIN;
    }

    /// @inheritdoc ISmartAccountFactory
    function callerHook() external view override returns (address) {
        return _CALLER_HOOK;
    }

    /// @inheritdoc ISmartAccountFactory
    function bundleSpendProtectorHook() external view override returns (address) {
        return _BUNDLE_SPEND_PROTECTOR_HOOK;
    }

    /// @inheritdoc ISmartAccountFactory
    function withdrawalLimitPolicy() external view override returns (address) {
        return _WITHDRAWAL_LIMIT_POLICY;
    }

    /// @inheritdoc ISmartAccountFactory
    function ecdsaSigner() external view override returns (address) {
        return _ECDSA_SIGNER;
    }

    /// @inheritdoc ISmartAccountFactory
    function bundleWithdrawHook() external view override returns (address) {
        return _BUNDLE_WITHDRAW_HOOK;
    }

    // -- Account creation -------------------------------------------------

    function createAccount(
        address owner,
        address cca,
        address[] calldata bundleTokens,
        address[] calldata bundleSenders,
        uint256 salt //todo investigate if it's ok to expose salt here
    ) external returns (address account) {
        require(owner != address(0), "owner required");
        require(cca != address(0), "cca required");
        // Standing is checked only on the deploying path; `getAccountAddress` stays a pure CREATE2
        // prediction so a client can always compute the address it is about to ask for.
        ICca.State ccaState = ICca(CCA_REGISTRY).getCcaState(cca);
        require(ccaState == ICca.State.Active, CcaNotActive(cca, ccaState));
        Install[] memory packages = _packages(owner, cca, bundleTokens, bundleSenders);
        account = _KERNEL_FACTORY.deploy(packages, salt);
    }

    function getAccountAddress(
        address owner,
        address cca,
        address[] calldata bundleTokens,
        address[] calldata bundleSenders,
        uint256 salt
    ) external view returns (address account) {
        Install[] memory packages = _packages(owner, cca, bundleTokens, bundleSenders);
        account = _KERNEL_FACTORY.getAddress(packages, salt);
    }

    /// @dev Stable owner permission id (single per account).
    function _ownerPermId() internal pure returns (PermissionId) {
        return PermissionId.wrap(bytes4(keccak256("credis.owner")));
    }

    /// @dev Per-token CCA permission id: stable key for per-token daily-limit permission.
    function _ccaPermId(address token) internal pure returns (PermissionId) {
        return PermissionId.wrap(bytes4(keccak256(abi.encode("credis.cca", token))));
    }

    /// @dev Build the ordered Kernel v4 install packages for the account.
    ///
    ///      internalData byte layouts consumed by Kernel v4 (see types/Structs.sol):
    ///        policy  (5): [bytes4 permissionId]
    ///        signer  (6): [bytes4 permissionId | bytes20 hook | bytes4[] allowedSelectors]
    ///        fallback(3): [bytes4 selector | bytes1 callType | bytes20 hook]
    ///      moduleData is forwarded to each module's onInstall (PolicyBase/SignerBase parse the
    ///      32-byte permission id from the front; the module reads the remainder).
    function _packages(address owner, address cca, address[] memory bundleTokens, address[] memory bundleSenders)
        internal
        view
        returns (Install[] memory packages)
    {
        uint256 n = bundleTokens.length;
        bytes4 execSel = IERC7579Account.execute.selector;
        bytes1 callTypeSingle = CallType.unwrap(CALLTYPE_SINGLE);

        PermissionId ownerPerm = _ownerPermId();
        bytes4 ownerPerm4 = PermissionId.unwrap(ownerPerm);
        bytes32 ownerPerm32 = bytes32(ownerPerm4);

        if (n == 0) {
            // Owner permission only (no bundle, no hook): [SudoPolicy(root), ECDSASigner].
            packages = new Install[](2);
            packages[0] = Install({
                moduleType: MODULE_TYPE_POLICY,
                module: _SUDO_POLICY,
                moduleData: abi.encodePacked(ownerPerm32),
                internalData: abi.encodePacked(ownerPerm4)
            });
            packages[1] = Install({
                moduleType: MODULE_TYPE_SIGNER,
                module: _ECDSA_SIGNER,
                moduleData: abi.encodePacked(ownerPerm32, bytes20(owner)),
                internalData: abi.encodePacked(ownerPerm4, bytes20(address(0)), execSel)
            });
            return packages;
        }

        // With bundle tokens: owner permission (hooked) + module wiring + one CCA permission per token.
        // Layout: [0] SudoPolicy(root) [1] BundleSpendProtectorHook [2] owner ECDSASigner
        //         [3] CallerHook [4] BundleWithdrawHook [5] executor [6] fallback
        //         then, per token: [.. policy, signer ..] (each pair contiguous).
        packages = new Install[](7 + 2 * n);

        packages[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: _SUDO_POLICY,
            moduleData: abi.encodePacked(ownerPerm32),
            internalData: abi.encodePacked(ownerPerm4)
        });
        // Enable the root execution hook BEFORE the owner signer initializes the owner validation.
        packages[1] = Install({
            moduleType: MODULE_TYPE_HOOK, module: _BUNDLE_SPEND_PROTECTOR_HOOK, moduleData: hex"", internalData: hex""
        });
        packages[2] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: _ECDSA_SIGNER,
            moduleData: abi.encodePacked(ownerPerm32, bytes20(owner)),
            internalData: abi.encodePacked(ownerPerm4, bytes20(_BUNDLE_SPEND_PROTECTOR_HOOK), execSel)
        });
        // CallerHook guards the topUp fallback; its allowed senders arrive via its own onInstall.
        packages[3] = Install({
            moduleType: MODULE_TYPE_HOOK,
            module: _CALLER_HOOK,
            moduleData: abi.encode(bundleSenders),
            internalData: hex""
        });
        // Shared per-CCA-permission hook.
        packages[4] = Install({
            moduleType: MODULE_TYPE_HOOK, module: _BUNDLE_WITHDRAW_HOOK, moduleData: hex"", internalData: hex""
        });
        // BundleModulePlugin as executor (empty onInstall = no-op) and as the topUp fallback.
        packages[5] = Install({
            moduleType: MODULE_TYPE_EXECUTOR, module: _BUNDLE_MODULE_PLUGIN, moduleData: hex"", internalData: hex""
        });
        packages[6] = Install({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _BUNDLE_MODULE_PLUGIN,
            moduleData: abi.encode(bundleTokens),
            internalData: abi.encodePacked(BundleModulePlugin.topUp.selector, callTypeSingle, bytes20(_CALLER_HOOK))
        });

        for (uint256 i = 0; i < n; i++) {
            PermissionId perm = _ccaPermId(bundleTokens[i]);
            bytes4 perm4 = PermissionId.unwrap(perm);
            bytes32 perm32 = bytes32(perm4);

            packages[7 + 2 * i] = Install({
                moduleType: MODULE_TYPE_POLICY,
                module: _WITHDRAWAL_LIMIT_POLICY,
                moduleData: abi.encodePacked(perm32, abi.encode(DAILY_LIMIT, LIMIT_INTERVAL, bundleTokens[i])),
                internalData: abi.encodePacked(perm4)
            });
            packages[8 + 2 * i] = Install({
                moduleType: MODULE_TYPE_SIGNER,
                module: _ECDSA_SIGNER,
                moduleData: abi.encodePacked(perm32, bytes20(cca)),
                internalData: abi.encodePacked(perm4, bytes20(_BUNDLE_WITHDRAW_HOOK), execSel)
            });
        }
    }
}
