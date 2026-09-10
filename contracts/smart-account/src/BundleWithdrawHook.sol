// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {IHook} from "@zerodev/kernel/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK, CALLTYPE_SINGLE} from "@zerodev/kernel/types/Constants.sol";
import {CallType} from "@zerodev/kernel/types/Types.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {BundleModulePlugin} from "./BundleModulePlugin.sol";

/// @notice Hook for CCA permissions: validates execute(transfer) calls target bundle tokens
///         and decrements bundle balance in postCheck.
/// @dev Installed on each per-token CCA permission. preCheck receives userOp.callData[4:]
///      (Kernel strips executeUserOp.selector before passing to the hook).
///
///      callData layout received by preCheck:
///        [0:4]    execute.selector
///        [4:36]   ExecMode (first byte = CallType)
///        [36:68]  ABI offset to executionCalldata (= 64)
///        [68:100] length of executionCalldata
///        [100:]   executionCalldata = target(20) || value(32) || innerCallData
contract BundleWithdrawHook is IHook {
    BundleModulePlugin public immutable BUNDLE_PLUGIN;

    mapping(address account => bool) public installed;

    error InvalidCallType();
    error InvalidSelector();
    error TokenNotInBundle(address token);
    error NonCanonicalOffset(uint256 offset);

    constructor(address bundlePlugin) {
        BUNDLE_PLUGIN = BundleModulePlugin(bundlePlugin);
    }

    // --- IModule ---

    function onInstall(bytes calldata) external payable override {
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external payable override {
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 id) external pure override returns (bool) {
        return id == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installed[smartAccount];
    }

    // --- IHook ---

    /// @dev msg.sender = smart account
    ///      callData = userOp.callData[4:] (executeUserOp.selector stripped by Kernel)
    function preCheck(address, uint256, bytes calldata callData)
        external
        payable
        override
        returns (bytes memory hookData)
    {
        // callData[4] = first byte of ExecMode = CallType
        if (callData.length < 100) revert InvalidCallType();
        if (CallType.wrap(callData[4]) != CALLTYPE_SINGLE) revert InvalidCallType();

        // Kernel.execute follows this offset when decoding, so reject a non-canonical value to keep
        // this validation in sync with execution.
        uint256 offset = uint256(bytes32(callData[36:68]));
        if (offset != 64) revert NonCanonicalOffset(offset);

        uint256 execLen = uint256(bytes32(callData[68:100]));
        if (callData.length < 100 + execLen) revert InvalidCallType();

        // executionCalldata: target(20) || value(32) || innerCallData
        bytes calldata exec = callData[100:100 + execLen];
        if (exec.length < 56) revert InvalidCallType(); // 20 + 32 + 4 minimum

        address token = address(bytes20(exec[0:20]));

        // innerCallData starts at exec[52:] (after target+value)
        bytes calldata innerCallData = exec[52:];
        if (bytes4(innerCallData[0:4]) != IERC20.transfer.selector) revert InvalidSelector();
        if (innerCallData.length < 68) revert InvalidSelector();
        uint256 amount = uint256(bytes32(innerCallData[36:68]));

        if (!BUNDLE_PLUGIN.isBundleToken(msg.sender, token)) revert TokenNotInBundle(token);

        return abi.encode(token, amount);
    }

    /// @dev Called after execution. msg.sender = smart account.
    ///      Uses this hook's executor registration to call executeFromExecutor, so that
    ///      decreaseBundleBalance is invoked with msg.sender = smart account.
    function postCheck(bytes calldata hookData) external payable override {
        (address token, uint256 amount) = abi.decode(hookData, (address, uint256));
        BUNDLE_PLUGIN.dispatchDecreaseBalance(msg.sender, token, amount);
    }
}
