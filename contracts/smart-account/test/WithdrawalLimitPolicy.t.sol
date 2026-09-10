// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {WithdrawalLimitPolicy} from "src/WithdrawalLimitPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ValidationData, _parseValidationData} from "account-abstraction/core/Helpers.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockUSD} from "src/mocks/MockUSD.sol";

/// @title WithdrawalLimitPolicyTest
/// @notice Unit tests for WithdrawalLimitPolicy
contract WithdrawalLimitPolicyTest is Test {
    WithdrawalLimitPolicy policy;
    MockUSD token;

    address kernelAccount;
    address recipient;

    bytes32 constant DEFAULT_ID = keccak256("default");
    uint256 constant DEFAULT_LIMIT = 1000e6;
    uint48 constant DEFAULT_INTERVAL = 1 days;

    function setUp() public {
        policy = new WithdrawalLimitPolicy();
        token = new MockUSD();

        kernelAccount = makeAddr("kernelAccount");
        recipient = makeAddr("recipient");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Installs the policy for kernelAccount using the given parameters.
    ///      PolicyBase.onInstall layout: [0:32]=id, [32:]=abi.encode(amountLimit, interval, token)
    function _install(bytes32 id, uint256 amountLimit, uint48 interval, address tkn) internal {
        bytes memory data = abi.encodePacked(id, abi.encode(amountLimit, interval, tkn));
        vm.prank(kernelAccount);
        policy.onInstall(data);
    }

    /// @dev Builds a PackedUserOperation whose callData encodes a CALLTYPE_SINGLE transfer.
    ///      callData layout:
    ///        [0:4]    = dummy selector (bytes4(0))
    ///        [4:36]   = ExecMode = bytes32(0) -> CALLTYPE_SINGLE, EXECTYPE_DEFAULT
    ///        [36:68]  = ABI offset = 64
    ///        [68:100] = execCalldata.length
    ///        [100:]   = execCalldata = abi.encodePacked(target, value=0, transferCalldata)
    function _buildUserOp(address target, address to, uint256 amount)
        internal
        view
        returns (PackedUserOperation memory)
    {
        bytes memory transferCalldata = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
        bytes memory execCalldata = abi.encodePacked(target, uint256(0), transferCalldata);
        bytes memory callData = abi.encodeWithSelector(bytes4(0), bytes32(0), execCalldata);

        return PackedUserOperation({
            sender: kernelAccount,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @dev Builds a UserOp with a non-transfer selector targeting the configured token.
    function _buildNonTransferUserOp(address target, bytes4 selector)
        internal
        view
        returns (PackedUserOperation memory)
    {
        bytes memory innerCalldata = abi.encodeWithSelector(selector, uint256(0));
        bytes memory execCalldata = abi.encodePacked(target, uint256(0), innerCalldata);
        bytes memory callData = abi.encodeWithSelector(bytes4(0), bytes32(0), execCalldata);

        return PackedUserOperation({
            sender: kernelAccount,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @dev Builds a UserOp with CALLTYPE_BATCH (first byte of ExecMode = 0x01).
    function _buildBatchUserOp() internal view returns (PackedUserOperation memory) {
        bytes32 batchMode = bytes32(bytes1(0x01)); // CALLTYPE_BATCH
        bytes memory callData = abi.encodeWithSelector(bytes4(0), batchMode, new bytes(0));

        return PackedUserOperation({
            sender: kernelAccount,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @dev ERC-7579 batch execution element (matches solady LibERC7579 / Kernel batch decoding).
    struct Execution {
        address target;
        uint256 value;
        bytes callData;
    }

    /// @dev Builds a CALLTYPE_BATCH UserOp whose single sub-call is a transfer targeting `target`.
    function _buildBatchUserOpTargeting(address target) internal view returns (PackedUserOperation memory) {
        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({
            target: target, value: 0, callData: abi.encodeWithSelector(IERC20.transfer.selector, recipient, uint256(1))
        });
        bytes32 batchMode = bytes32(bytes1(0x01)); // CALLTYPE_BATCH
        bytes memory callData = abi.encodeWithSelector(bytes4(0), batchMode, abi.encode(execs));

        return PackedUserOperation({
            sender: kernelAccount,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    // -------------------------------------------------------------------------
    // Install / Uninstall
    // -------------------------------------------------------------------------

    function test_Install_StoresConfig() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        (uint256 amountLimit, uint48 interval, address tkn) = policy.configs(DEFAULT_ID, kernelAccount);

        assertEq(amountLimit, DEFAULT_LIMIT, "amountLimit mismatch");
        assertEq(interval, DEFAULT_INTERVAL, "interval mismatch");
        assertEq(tkn, address(token), "token mismatch");
        assertEq(
            uint8(policy.status(DEFAULT_ID, kernelAccount)), uint8(WithdrawalLimitPolicy.Status.Live), "status not Live"
        );
        assertEq(policy.usedIds(kernelAccount), 1, "usedIds should be 1");
        assertTrue(policy.isInitialized(kernelAccount), "should be initialized");
    }

    function test_Install_InitializesWindowEnd() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        (, uint48 windowEnd) = policy.states(DEFAULT_ID, kernelAccount);
        assertEq(windowEnd, uint48(block.timestamp) + DEFAULT_INTERVAL, "windowEnd mismatch");
    }

    function test_Install_IdempotentReverts() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        bytes memory data = abi.encodePacked(DEFAULT_ID, abi.encode(DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token)));
        vm.prank(kernelAccount);
        vm.expectRevert(WithdrawalLimitPolicy.WithdrawalLimitAlreadyInitialized.selector);
        policy.onInstall(data);
    }

    function test_Uninstall_SetsDeprecated() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        bytes memory data = abi.encodePacked(DEFAULT_ID, new bytes(0));
        vm.prank(kernelAccount);
        policy.onUninstall(data);

        assertEq(
            uint8(policy.status(DEFAULT_ID, kernelAccount)),
            uint8(WithdrawalLimitPolicy.Status.Deprecated),
            "status not Deprecated"
        );
        assertEq(policy.usedIds(kernelAccount), 0, "usedIds should be 0");
        assertFalse(policy.isInitialized(kernelAccount), "should not be initialized");
    }

    // -------------------------------------------------------------------------
    // checkUserOpPolicy - pass cases
    // -------------------------------------------------------------------------

    function test_CheckUserOpPolicy_PassesUnderLimit() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, DEFAULT_LIMIT - 1);
        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);

        ValidationData memory vd = _parseValidationData(result);
        assertEq(vd.validAfter, 0, "validAfter should be 0");
        assertGt(vd.validUntil, 0, "validUntil should be non-zero");
    }

    function test_CheckUserOpPolicy_PassesAtLimit() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, DEFAULT_LIMIT);
        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);

        ValidationData memory vd = _parseValidationData(result);
        assertGt(vd.validUntil, 0, "validUntil should be non-zero");
        (uint256 usedAfter,) = policy.states(DEFAULT_ID, kernelAccount);
        assertEq(usedAfter, DEFAULT_LIMIT, "usedAmount should equal limit");
    }

    // -------------------------------------------------------------------------
    // checkUserOpPolicy - revert cases
    // -------------------------------------------------------------------------

    function test_RevertWhen_ExceedsLimit() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, DEFAULT_LIMIT + 1);

        vm.prank(kernelAccount);
        vm.expectRevert(
            abi.encodeWithSelector(
                WithdrawalLimitPolicy.WithdrawalLimitExceeded.selector, DEFAULT_LIMIT + 1, DEFAULT_LIMIT
            )
        );
        policy.checkUserOpPolicy(DEFAULT_ID, userOp);
    }

    /// @dev T-01: a UserOp whose ABI offset word is non-canonical must be rejected, not passed through.
    ///      The fixed [68:100]/[100:] window shows a benign amount (1) while the real offset-followed
    ///      data would move DEFAULT_LIMIT+1; Kernel.execute follows the offset, so passing through here
    ///      would desync validation from execution. The policy must revert instead.
    function test_W01_NonCanonicalOffset_Reverts() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        bytes memory transferCalldata = abi.encodeWithSelector(IERC20.transfer.selector, recipient, uint256(1));
        bytes memory execCalldata = abi.encodePacked(address(token), uint256(0), transferCalldata);
        // Hand-build callData with offset word = 96 (0x60) instead of the canonical 64 (0x40).
        bytes memory callData = abi.encodePacked(
            bytes4(0), // [0:4]   selector
            bytes32(0), // [4:36]  ExecMode -> CALLTYPE_SINGLE
            uint256(96), // [36:68] non-canonical offset
            uint256(execCalldata.length), // [68:100] length
            execCalldata // [100:]  data
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: kernelAccount,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });

        vm.prank(kernelAccount);
        vm.expectRevert(abi.encodeWithSelector(WithdrawalLimitPolicy.NonCanonicalOffset.selector, uint256(96)));
        policy.checkUserOpPolicy(DEFAULT_ID, userOp);
    }

    /// @dev T-04: a standalone policy must fail-closed on a batch that targets the configured token,
    ///      not pass it through - otherwise a batch bypasses the daily limit entirely when the policy
    ///      is reused without a call-type-restricting sibling hook.
    function test_W05_BatchTargetingConfiguredToken_Reverts() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildBatchUserOpTargeting(address(token));
        vm.prank(kernelAccount);
        vm.expectRevert(
            abi.encodeWithSelector(WithdrawalLimitPolicy.BatchTargetsConfiguredToken.selector, address(token))
        );
        policy.checkUserOpPolicy(DEFAULT_ID, userOp);
    }

    /// @dev T-04: a batch that touches no configured token is genuinely unrelated and still passes.
    function test_W05_UnrelatedBatch_StillPasses() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildBatchUserOpTargeting(makeAddr("otherToken"));
        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);
        assertEq(result, 0, "unrelated batch must pass through");
    }

    /// @dev T-06: metering a transfer emits LimitConsumed so monitoring can watch limit exhaustion.
    function test_W07_LimitConsumedEmits() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));
        (, uint48 windowEnd) = policy.states(DEFAULT_ID, kernelAccount); // unchanged (no reset this block)

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, 300e6);
        vm.expectEmit(true, true, false, true, address(policy));
        emit WithdrawalLimitPolicy.LimitConsumed(DEFAULT_ID, kernelAccount, 300e6, 300e6, windowEnd);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, userOp);
    }

    /// @dev T-06: the first transfer after the window expires emits WindowReset with the new window.
    function test_W07_WindowResetEmits() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));
        vm.warp(block.timestamp + DEFAULT_INTERVAL + 1);
        uint48 expectedWindowEnd = uint48(block.timestamp) + DEFAULT_INTERVAL;

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, 100e6);
        vm.expectEmit(true, true, false, true, address(policy));
        emit WithdrawalLimitPolicy.WindowReset(DEFAULT_ID, kernelAccount, expectedWindowEnd);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, userOp);
    }

    function test_CheckUserOpPolicy_CumulativeExceedsLimit() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        uint256 half = DEFAULT_LIMIT / 2;

        // First transfer: half the limit
        PackedUserOperation memory op1 = _buildUserOp(address(token), recipient, half);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, op1);

        // Second transfer: the other half (OK, exactly at limit)
        PackedUserOperation memory op2 = _buildUserOp(address(token), recipient, DEFAULT_LIMIT - half);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, op2);

        // Third transfer: 1 more -> exceeds limit
        PackedUserOperation memory op3 = _buildUserOp(address(token), recipient, 1);
        vm.prank(kernelAccount);
        vm.expectRevert(
            abi.encodeWithSelector(
                WithdrawalLimitPolicy.WithdrawalLimitExceeded.selector, DEFAULT_LIMIT + 1, DEFAULT_LIMIT
            )
        );
        policy.checkUserOpPolicy(DEFAULT_ID, op3);
    }

    // -------------------------------------------------------------------------
    // checkUserOpPolicy - window reset
    // -------------------------------------------------------------------------

    function test_CheckUserOpPolicy_ResetsAfterInterval() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        // Fill the limit in the current window
        PackedUserOperation memory op1 = _buildUserOp(address(token), recipient, DEFAULT_LIMIT);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, op1);

        // Warp past the interval
        vm.warp(block.timestamp + DEFAULT_INTERVAL + 1);

        // New window: same amount should pass again
        PackedUserOperation memory op2 = _buildUserOp(address(token), recipient, DEFAULT_LIMIT);
        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, op2);

        assertGt(result, 0, "should pass after window reset");
        (uint256 usedAfterReset,) = policy.states(DEFAULT_ID, kernelAccount);
        assertEq(usedAfterReset, DEFAULT_LIMIT, "usedAmount should reset then accumulate");
    }

    function test_CheckUserOpPolicy_WindowEndUpdatedAfterReset() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        (, uint48 firstWindowEnd) = policy.states(DEFAULT_ID, kernelAccount);

        // Warp past interval
        uint256 warpTo = block.timestamp + DEFAULT_INTERVAL + 100;
        vm.warp(warpTo);

        PackedUserOperation memory op = _buildUserOp(address(token), recipient, 1);
        vm.prank(kernelAccount);
        policy.checkUserOpPolicy(DEFAULT_ID, op);

        (, uint48 newWindowEnd) = policy.states(DEFAULT_ID, kernelAccount);
        assertGt(newWindowEnd, firstWindowEnd, "windowEnd should advance");
        // casting to 'uint48' is safe because warpTo == block.timestamp + 1 days + 100,
        // which is far below uint48 max (~8.9M years from epoch).
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(newWindowEnd, uint48(warpTo) + DEFAULT_INTERVAL, "new windowEnd should be now + interval");
    }

    // -------------------------------------------------------------------------
    // checkUserOpPolicy - skip / pass-through cases
    // -------------------------------------------------------------------------

    function test_CheckUserOpPolicy_NonTargetToken() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        address otherToken = makeAddr("otherToken");
        PackedUserOperation memory userOp = _buildUserOp(otherToken, recipient, DEFAULT_LIMIT * 100);

        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);

        assertEq(result, 0, "should pass-through for non-target token");
    }

    function test_CheckUserOpPolicy_NonTransferSelector() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildNonTransferUserOp(address(token), IERC20.approve.selector);

        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);

        assertEq(result, 0, "should pass-through for non-transfer selector");
    }

    function test_CheckUserOpPolicy_BatchCallSkipped() public {
        _install(DEFAULT_ID, DEFAULT_LIMIT, DEFAULT_INTERVAL, address(token));

        PackedUserOperation memory userOp = _buildBatchUserOp();

        vm.prank(kernelAccount);
        uint256 result = policy.checkUserOpPolicy(DEFAULT_ID, userOp);

        assertEq(result, 0, "should pass-through for batch calltype");
    }

    // -------------------------------------------------------------------------
    // checkSignaturePolicy
    // -------------------------------------------------------------------------

    function test_CheckSignaturePolicy_ReturnsZero() public view {
        uint256 result = policy.checkSignaturePolicy(DEFAULT_ID, address(0), bytes32(0), "");
        assertEq(result, 0, "checkSignaturePolicy should return 0");
    }

    // -------------------------------------------------------------------------
    // isModuleType
    // -------------------------------------------------------------------------

    function test_IsModuleType_ReturnsTrue_ForPolicy() public view {
        assertTrue(policy.isModuleType(5), "should support module type 5 (policy)");
    }

    function test_IsModuleType_ReturnsFalse_ForOthers() public view {
        assertFalse(policy.isModuleType(1), "should not support type 1");
        assertFalse(policy.isModuleType(2), "should not support type 2");
        assertFalse(policy.isModuleType(4), "should not support type 4");
    }

    // -------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------

    /// @dev Fuzz: cumulative transfers must never exceed the limit within a window.
    function testFuzz_WithdrawalLimitPolicy(uint96 amount, uint96 limit, uint48 interval) public {
        vm.assume(limit > 0);
        vm.assume(interval > 0);
        vm.assume(amount > 0);

        _install(DEFAULT_ID, uint256(limit), interval, address(token));

        PackedUserOperation memory userOp = _buildUserOp(address(token), recipient, uint256(amount));

        vm.prank(kernelAccount);
        if (uint256(amount) > uint256(limit)) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    WithdrawalLimitPolicy.WithdrawalLimitExceeded.selector, uint256(amount), uint256(limit)
                )
            );
            policy.checkUserOpPolicy(DEFAULT_ID, userOp);
        } else {
            policy.checkUserOpPolicy(DEFAULT_ID, userOp);
            (uint256 usedFuzz,) = policy.states(DEFAULT_ID, kernelAccount);
            assertEq(usedFuzz, uint256(amount), "usedAmount should match");
        }
    }
}
