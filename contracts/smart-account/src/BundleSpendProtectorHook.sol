// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {IHook} from "@zerodev/kernel/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_HOOK, CALLTYPE_SINGLE, CALLTYPE_BATCH} from "@zerodev/kernel/types/Constants.sol";
import {CallType} from "@zerodev/kernel/types/Types.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {ITokenBundle} from "./interfaces/ITokenBundle.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

/// @notice Root-validator execution hook that bounds what the account OWNER can do with the
///         bundled (reserved) portion of a smart account. The owner may freely spend their own
///         (free) balance, but must not touch the reserve. Enforced as a post-execution invariant:
///         after an owner UserOp, for every bundled token the account must
///           (1) retain its reserve - it may remove at most its pre-op free balance, and
///           (2) leave no standing allowance on the token (an approve is fine only if it is
///               consumed within the same UserOp, e.g. by a factory precompile's transferFrom).
///         This is spender/mechanism-agnostic: it covers plain transfers, transferFrom, batches,
///         and the "caller approves, precompile pulls" repayment flows (credis/gem/nod/intex) with
///         no knowledge of specific addresses. The CCA spend-within-limits path runs a different
///         hook (BundleWithdrawHook) and is unaffected.
/// @dev Wired as the root validator execution hook when bundleTokens.length > 0. preCheck snapshots
///      pre-op state; postCheck verifies the invariant and reverts (failing the UserOp) on breach.
///      Using pre-op balance+reserve (captured in preCheck) is deliberate - it neither false-reverts
///      unrelated ops on an over-reserved account (topUp doubles the reserve) nor lets the owner
///      lower their own reserve mid-op to slip funds past the check.
///      msgData layout (from Kernel.executeUserOp -> preCheck):
///        [0:4]     execute.selector
///        [4:36]    ExecMode (bytes32; byte [4] = callType: 0x00 = SINGLE, 0x01 = BATCH)
///        [36:68]   ABI offset to bytes param (= 64)
///        [68:100]  length of executionCalldata
///        [100:]    executionCalldata (SINGLE: packed address||uint256||callData; BATCH: abi.encode(Execution[]))
///
///      Known limitation (unchanged from prior versions): only root-validated ops run this hook;
///      executeFromExecutor / fallback paths use different or no hooks, so a future executor module
///      that moves ERC20s would not be covered here.
contract BundleSpendProtectorHook is IHook {
    error InsufficientFreeBalance();
    error NonCanonicalOffset(uint256 offset);

    /// @dev Pre-op snapshot of a bundled token, used to bound the owner's outflow to freeBalance.
    struct TokenSnapshot {
        address token;
        uint256 preBalance;
        uint256 preReserve;
    }

    /// @dev An approve(spender, amount) on a bundled token seen in the calldata, with the allowance
    ///      that existed before execution. postCheck rejects any net increase (a lingering grant).
    struct ApproveGrant {
        address token;
        address spender;
        uint256 preAllowance;
    }

    ITokenBundle public immutable BUNDLE_PLUGIN;
    mapping(address account => bool) public installed;

    constructor(address bundlePlugin) {
        BUNDLE_PLUGIN = ITokenBundle(bundlePlugin);
    }

    // IModule
    function onInstall(bytes calldata) external payable override {
        installed[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external payable override {
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 id) external pure override returns (bool) {
        return id == MODULE_TYPE_HOOK;
    }

    function isInitialized(address a) external view override returns (bool) {
        return installed[a];
    }

    // IHook

    /// @dev msg.sender = the Kernel account executing the UserOp. Side-effect free: snapshots the
    ///      account's bundled tokens and any approve grants for postCheck to verify.
    function preCheck(address, uint256, bytes calldata msgData) external payable override returns (bytes memory) {
        address account = msg.sender;

        // Snapshot every bundled token's balance and reserve before execution.
        address[] memory tokens = BUNDLE_PLUGIN.bundleTokensOf(account);
        TokenSnapshot[] memory snapshots = new TokenSnapshot[](tokens.length);
        for (uint256 i; i < tokens.length; ++i) {
            snapshots[i] = TokenSnapshot({
                token: tokens[i],
                preBalance: IERC20(tokens[i]).balanceOf(account),
                preReserve: BUNDLE_PLUGIN.balanceOf(account, tokens[i])
            });
        }

        ApproveGrant[] memory grants = _collectApproveGrants(account, msgData);
        return abi.encode(snapshots, grants);
    }

    /// @dev Verifies the reserve invariant and the no-standing-allowance rule; reverts on breach,
    ///      which fails the UserOp (and rolls back the execution that just ran).
    function postCheck(bytes calldata hookData) external payable override {
        if (hookData.length == 0) return;
        address account = msg.sender;
        (TokenSnapshot[] memory snapshots, ApproveGrant[] memory grants) =
            abi.decode(hookData, (TokenSnapshot[], ApproveGrant[]));

        // (1) Reserve retained: the owner may remove at most the pre-op free balance of each token.
        for (uint256 i; i < snapshots.length; ++i) {
            TokenSnapshot memory s = snapshots[i];
            uint256 preFree = s.preBalance > s.preReserve ? s.preBalance - s.preReserve : 0;
            if (IERC20(s.token).balanceOf(account) < s.preBalance - preFree) {
                revert InsufficientFreeBalance();
            }
        }

        // (2) No standing allowance: an approve is permitted only if consumed within this UserOp,
        //     so the residual allowance must not exceed what existed before.
        for (uint256 i; i < grants.length; ++i) {
            ApproveGrant memory g = grants[i];
            if (IERC20(g.token).allowance(account, g.spender) > g.preAllowance) {
                revert InsufficientFreeBalance();
            }
        }
    }

    /// @dev Parse the execution calldata and record each `approve(spender, amount)` targeting a
    ///      bundled token, capturing the pre-execution allowance. Mirrors the kernel's own decoding
    ///      (ExecLib.decodeSingle / LibERC7579.decodeBatch) so the hook and executor agree.
    function _collectApproveGrants(address account, bytes calldata msgData)
        internal
        view
        returns (ApproveGrant[] memory)
    {
        // Need: selector(4) + ExecMode(32) + offset(32) + length(32) = 100 bytes minimum.
        if (msgData.length < 100) return new ApproveGrant[](0);
        // Kernel.execute follows this offset when decoding, so reject a non-canonical value to keep the
        // approve-grant scan in sync with execution (returning an empty set here would be the bypass).
        uint256 offset = uint256(bytes32(msgData[36:68]));
        if (offset != 64) revert NonCanonicalOffset(offset);
        uint256 execLen = uint256(bytes32(msgData[68:100]));
        if (msgData.length < 100 + execLen) return new ApproveGrant[](0);
        bytes calldata execCalldata = msgData[100:100 + execLen];

        // Call type is the first byte of ExecMode, at msgData[4].
        CallType callType = CallType.wrap(msgData[4]);

        if (callType == CALLTYPE_SINGLE) {
            // Minimum: target(20) + value(32) + selector(4) = 56 bytes.
            if (execCalldata.length < 56) return new ApproveGrant[](0);
            (address target,, bytes calldata innerCallData) = LibERC7579.decodeSingle(execCalldata);
            ApproveGrant[] memory grants = new ApproveGrant[](1);
            uint256 n = _appendApproveGrant(account, target, innerCallData, grants, 0);
            return _trim(grants, n);
        }

        if (callType == CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(execCalldata);
            ApproveGrant[] memory grants = new ApproveGrant[](pointers.length);
            uint256 n;
            for (uint256 i; i < pointers.length; ++i) {
                (address target,, bytes calldata innerCallData) = LibERC7579.getExecution(pointers, i);
                n = _appendApproveGrant(account, target, innerCallData, grants, n);
            }
            return _trim(grants, n);
        }

        return new ApproveGrant[](0); // other call types (e.g. delegatecall) grant no allowance here
    }

    /// @dev If `innerCallData` is an `approve(spender, amount)` on a bundled `target`, append a
    ///      grant recording the current allowance and return the new count; otherwise return `n`.
    function _appendApproveGrant(
        address account,
        address target,
        bytes calldata innerCallData,
        ApproveGrant[] memory grants,
        uint256 n
    ) internal view returns (uint256) {
        // approve(address spender, uint256 amount): selector(4) + spender(32) + amount(32)
        if (innerCallData.length < 68) return n;
        if (bytes4(innerCallData[0:4]) != IERC20.approve.selector) return n;
        if (BUNDLE_PLUGIN.balanceOf(account, target) == 0) return n; // not a bundled token
        address spender = address(uint160(uint256(bytes32(innerCallData[4:36]))));
        grants[n] =
            ApproveGrant({token: target, spender: spender, preAllowance: IERC20(target).allowance(account, spender)});
        return n + 1;
    }

    /// @dev Shrink `grants` to its first `n` entries.
    function _trim(ApproveGrant[] memory grants, uint256 n) internal pure returns (ApproveGrant[] memory) {
        if (n == grants.length) return grants;
        ApproveGrant[] memory trimmed = new ApproveGrant[](n);
        for (uint256 i; i < n; ++i) {
            trimmed[i] = grants[i];
        }
        return trimmed;
    }
}
