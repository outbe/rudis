// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyBase} from "kernel-7579-plugins/base/PolicyBase.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {CallType} from "@zerodev/kernel/types/Types.sol";
import {CALLTYPE_SINGLE, CALLTYPE_BATCH} from "@zerodev/kernel/types/Constants.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {_packValidationData} from "account-abstraction/core/Helpers.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";

/// @title WithdrawalLimitPolicy
/// @notice ERC-7579 Policy (module type 5) that enforces per-interval cumulative
///         ERC20 transfer limits on smart accounts.
/// @dev Tracks the total amount of a specific ERC20 token transferred within rolling
///      time windows. Only CALLTYPE_SINGLE calls to `IERC20.transfer` on the configured
///      token are counted; all other call types and selectors are passed through.
/// @author Outbe Team
/// @custom:version 1.0.0
contract WithdrawalLimitPolicy is PolicyBase {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @notice Configuration stored per (id, wallet) pair on install.
    struct WithdrawalLimitConfig {
        uint256 amountLimit; // token-minor units (e.g. 6-dec); max cumulative transfer per interval
        uint48 interval; // Time window length in seconds
        address token; // ERC20 token address this policy governs
    }

    /// @notice Rolling-window state tracked per (id, wallet) pair.
    struct WithdrawalLimitState {
        uint256 usedAmount; // token-minor units (e.g. 6-dec); cumulative spent in current window
        uint48 windowEnd; // Timestamp when current window expires
    }

    enum Status {
        NA,
        Live,
        Deprecated
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error WithdrawalLimitExceeded(uint256 used, uint256 limit);
    error WithdrawalLimitAlreadyInitialized();
    error NonCanonicalOffset(uint256 offset);
    error BatchTargetsConfiguredToken(address token);

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a metered transfer consumes daily-limit headroom, so off-chain monitoring
    ///         can observe the limit nearing exhaustion on a (possibly compromised) CCA.
    event LimitConsumed(bytes32 indexed id, address indexed wallet, uint256 amount, uint256 used, uint48 windowEnd);
    /// @notice Emitted when an expired window is reset before metering a new transfer.
    event WindowReset(bytes32 indexed id, address indexed wallet, uint48 windowEnd);

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// @notice Number of active policy IDs installed per wallet.
    mapping(address => uint256) public usedIds;

    /// @notice Lifecycle status per (id, wallet).
    mapping(bytes32 id => mapping(address wallet => Status)) public status;

    /// @notice Config stored per (id, wallet).
    mapping(bytes32 id => mapping(address wallet => WithdrawalLimitConfig)) public configs;

    /// @notice Rolling-window state per (id, wallet).
    mapping(bytes32 id => mapping(address wallet => WithdrawalLimitState)) public states;

    // -------------------------------------------------------------------------
    // PolicyBase hooks
    // -------------------------------------------------------------------------

    /// @inheritdoc PolicyBase
    /// @dev `data` = abi.encode(uint256 amountLimit, uint48 interval, address token)
    function _policyOninstall(bytes32 id, bytes calldata data) internal override {
        if (status[id][msg.sender] == Status.Live) revert WithdrawalLimitAlreadyInitialized();
        (uint256 amountLimit, uint48 interval, address token) = abi.decode(data, (uint256, uint48, address));
        configs[id][msg.sender] = WithdrawalLimitConfig({amountLimit: amountLimit, interval: interval, token: token});
        uint48 blockTs = uint48(block.timestamp);
        uint48 windowEnd = interval > type(uint48).max - blockTs ? type(uint48).max : blockTs + interval;
        states[id][msg.sender] = WithdrawalLimitState({usedAmount: 0, windowEnd: windowEnd});
        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    /// @inheritdoc PolicyBase
    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }

    /// @notice Returns true once at least one policy id is installed for `wallet`.
    /// @dev Not part of the kernel-7579-plugins `IModule`, so this is a plain declaration (no
    ///      `override`); Kernel still invokes it by selector at install/uninstall time.
    function isInitialized(address wallet) external view returns (bool) {
        return usedIds[wallet] > 0;
    }

    // -------------------------------------------------------------------------
    // IPolicy
    // -------------------------------------------------------------------------

    /// @inheritdoc PolicyBase
    /// @dev Enforces the cumulative transfer limit for CALLTYPE_SINGLE ERC20 transfers.
    ///      Returns 0 (pass-through) for non-matching call types and selectors.
    ///      Reverts with WithdrawalLimitExceeded when the limit is breached.
    ///
    ///      userOp.callData layout (Kernel execute):
    ///        [0:4]   = function selector
    ///        [4:36]  = ExecMode (bytes32)
    ///        [36:68] = ABI offset to executionCalldata bytes (= 64)
    ///        [68:100] = length of executionCalldata
    ///        [100:]  = executionCalldata = abi.encodePacked(target(20), value(32), callData)
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        bytes calldata uopCallData = userOp.callData;

        // When a permission has a hook, Kernel requires callData to start with executeUserOp.selector
        // and checks the inner selector at [4:8]. Strip the outer prefix so ExecMode is at [4:36].
        if (uopCallData.length >= 4 && bytes4(uopCallData[0:4]) == IAccountExecute.executeUserOp.selector) {
            uopCallData = uopCallData[4:];
        }

        // Minimum: selector(4) + ExecMode(32) = 36 bytes
        if (uopCallData.length < 36) return 0;

        // Call type is the first byte of the ExecMode word (at [4]).
        CallType callType = CallType.wrap(bytes1(uopCallData[4]));
        // SINGLE is metered below; BATCH is checked fail-closed against the configured token; any other
        // call type carries no ERC20 transfer target here and is genuinely unrelated (pass-through).
        if (callType != CALLTYPE_SINGLE && callType != CALLTYPE_BATCH) return 0;

        // ABI-encoded params: [4:36]=ExecMode(static), [36:68]=offset=64, [68:100]=execLen, [100:]=execCalldata
        if (uopCallData.length < 100) return 0;
        // Kernel.execute decodes its `bytes calldata` param by following this offset, so a non-canonical
        // value would let execution move a different amount than this policy validates. Reject it rather
        // than pass-through (returning 0 here would be the bypass). Applies to SINGLE and BATCH alike.
        uint256 offset = uint256(bytes32(uopCallData[36:68]));
        if (offset != 64) revert NonCanonicalOffset(offset);
        uint256 execLen = uint256(bytes32(uopCallData[68:100]));
        if (uopCallData.length < 100 + execLen) return 0;
        bytes calldata execCalldata = uopCallData[100:100 + execLen];

        WithdrawalLimitConfig storage cfg = configs[id][msg.sender];

        // Fail-closed for BATCH. This policy meters cumulative amounts only on the SINGLE transfer
        // path (below) and cannot meter a batch atomically, so a batch that moves the configured token
        // must not slip past unmetered - revert if any sub-call targets cfg.token. A batch that touches
        // no configured token is genuinely unrelated and passes through. (In this deployment
        // BundleWithdrawHook already blocks non-SINGLE on every CCA permission, but the policy must be
        // self-contained if reused without that hook.) A batch too short to be a valid Execution[]
        // encoding cannot target the token and would revert at execution anyway, so it passes through.
        if (callType == CALLTYPE_BATCH) {
            if (execCalldata.length < 64) return 0; // not a valid abi.encode(Execution[])
            bytes32[] calldata pointers = LibERC7579.decodeBatch(execCalldata);
            for (uint256 i; i < pointers.length; ++i) {
                (address batchTarget,,) = LibERC7579.getExecution(pointers, i);
                if (batchTarget == cfg.token) revert BatchTargetsConfiguredToken(cfg.token);
            }
            return 0; // batch touches no configured token -> unrelated
        }

        // SINGLE path: decodeSingle requires at least 52 bytes (target + value)
        if (execCalldata.length < 52) return 0;
        (address target,, bytes calldata innerCallData) = LibERC7579.decodeSingle(execCalldata);

        if (target != cfg.token) return 0;

        // innerCallData: [0:4]=selector, [4:36]=recipient, [36:68]=amount
        if (innerCallData.length < 68) return 0;
        if (bytes4(innerCallData[0:4]) != IERC20.transfer.selector) return 0;

        uint256 amount = uint256(bytes32(innerCallData[36:68]));

        WithdrawalLimitState storage state = states[id][msg.sender];

        // Reset window if expired
        if (block.timestamp >= state.windowEnd) {
            state.usedAmount = 0;
            uint48 nowTs = uint48(block.timestamp);
            state.windowEnd = cfg.interval > type(uint48).max - nowTs ? type(uint48).max : nowTs + cfg.interval;
            emit WindowReset(id, msg.sender, state.windowEnd);
        }

        uint256 newUsed = state.usedAmount + amount;
        if (newUsed > cfg.amountLimit) revert WithdrawalLimitExceeded(newUsed, cfg.amountLimit);

        // TODO: NB The debit is committed here in the ERC-4337 validation phase, on purpose. The
        // EntryPoint validates every op in a bundle before executing any, so committing at validation
        // is what prevents two bundled ops from each passing a stale-headroom check and together
        // over-spending the daily limit - the exact protection this limit exists to give the owner
        // against a compromised CCA. The accepted trade-off is over-restriction: if the execution
        // later reverts, the debit still stands until the window resets (a misbehaving CCA can waste
        // its own daily headroom). Moving this to a post-execution commit would reopen the
        // intra-bundle over-spend, so it is deliberately kept in validation. See
        // test_W04_RevertingExec_StillDebits.
        state.usedAmount = newUsed;
        emit LimitConsumed(id, msg.sender, amount, newUsed, state.windowEnd);

        // validAfter = 0, validUntil = windowEnd, sigFailed = false (account-abstraction v0.9 packing).
        return _packValidationData(false, state.windowEnd, 0);
    }

    /// @inheritdoc PolicyBase
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 0;
    }
}
