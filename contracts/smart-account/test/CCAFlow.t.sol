// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;
import {BaseAATest} from "./BaseAATest.sol";
import {BundleModulePlugin} from "src/BundleModulePlugin.sol";
import {BundleWithdrawHook} from "src/BundleWithdrawHook.sol";
import {BundleSpendProtectorHook} from "src/BundleSpendProtectorHook.sol";
import {ICca} from "@precompiles/ICca.sol";
import {SmartAccountFactory} from "src/SmartAccountFactory.sol";
import {ITokenBundle} from "src/interfaces/ITokenBundle.sol";
import {MockUSD} from "src/mocks/MockUSD.sol";
import {MockFeeToken} from "src/mocks/MockFeeToken.sol";
import {WithdrawalLimitPolicy} from "src/WithdrawalLimitPolicy.sol";
import {Kernel} from "@zerodev/kernel/Kernel.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {PermissionId} from "@zerodev/kernel/types/Types.sol";

contract CCAFlow is BaseAATest {
    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    /// @dev Validates the full E2E flow: predict -> deploy -> fund -> topUp -> UserOp -> verify.
    function test_CCA_CanWithdraw_FullFlow() external {
        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(token);
        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = vault;

        // Step 1: Predict account address
        address predicted = factory.getAccountAddress(user.addr, cca.addr, bundleTokens, bundleSenders, 0);

        // Step 2: Deploy account
        address deployed = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);

        // Predicted address must match deployed address
        assertEq(predicted, deployed, "predicted address must match deployed address");

        // Step 3: Fund account with ETH for gas
        vm.deal(deployed, 0.1 ether);

        // Step 4: Vault topUp - mint 500e6 into bundle (pre-funds SA + vault match)
        uint256 topUpAmount = 500e6;
        _topUp(deployed, topUpAmount);
        // bundle = topUp * 2, SA token balance = topUp * 2 (pre-fund + vault)
        assertEq(
            bundlePlugin.balanceOf(deployed, address(token)), topUpAmount * 2, "bundle balance should equal 2x topUp"
        );
        assertEq(token.balanceOf(deployed), topUpAmount * 2, "account token balance should equal 2x topUp");

        // Step 5: CCA submits UserOp to transfer 200e6 to recipient
        uint256 withdrawAmount = 200e6;
        _ccaWithdraw(deployed, recipient.addr, withdrawAmount);

        // Step 6: Verify recipient received tokens
        assertEq(token.balanceOf(recipient.addr), withdrawAmount, "recipient should receive tokens");
        // Bundle balance decreases by 2x withdrawn amount
        assertEq(
            bundlePlugin.balanceOf(deployed, address(token)),
            topUpAmount * 2 - withdrawAmount * 2,
            "bundle balance should decrease by 2x withdrawn amount"
        );
        // Account token balance decreases by withdrawn amount
        assertEq(
            token.balanceOf(deployed),
            topUpAmount * 2 - withdrawAmount,
            "account token balance should decrease by withdrawn amount"
        );
    }

    function test_CCA_CanWithdrawBundle_WithinLimit() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);

        // topUp 1500e6 bundle tokens (bundle = 3000e6, SA = 3000e6)
        _topUp(smartAccount, 1500e6);
        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 3000e6, "bundle balance should be 3000");

        uint256 withdrawAmount = 800e6;
        _ccaWithdraw(smartAccount, recipient.addr, withdrawAmount);

        assertEq(token.balanceOf(recipient.addr), withdrawAmount, "recipient should receive 800");
        assertEq(token.balanceOf(smartAccount), 2200e6, "sender should have 2200");
        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 1400e6, "bundle balance should be 1400");
    }

    function test_CCA_WithdrawExceedsBundleBalance_UsesAccountBalance() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);

        // topUp 500e6 bundle (bundle=1000e6, SA=1000e6), and transfer 300e6 free tokens
        _topUp(smartAccount, 500e6);
        token.mint(smartAccount, 300e6); // extra free balance (SA=1300e6)

        // Withdraw 800e6 (decrease=1600e6 exceeds bundle balance of 1000e6 -> clamped to 0)
        _ccaWithdraw(smartAccount, recipient.addr, 800e6);

        assertEq(token.balanceOf(recipient.addr), 800e6, "recipient should receive 800");
        // bundle balance clamped to 0 (1000 < 1600)
        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 0, "bundle balance should be 0");
    }

    function test_CCA_BlockedByDailyLimit() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 2000e6);

        // 1001e6 exceeds 1000e6 daily limit -> policy reverts with custom error
        PackedUserOperation memory op = _buildCcaUserOp(smartAccount, recipient.addr, 1001e6);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(WithdrawalLimitPolicy.WithdrawalLimitExceeded.selector, 1001e6, 1000e6)
            )
        );
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));
    }

    function test_CCA_CumulativeLimit() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 2000e6);

        // First withdrawal: 600e6 -> succeeds
        _ccaWithdraw(smartAccount, recipient.addr, 600e6);
        assertEq(token.balanceOf(recipient.addr), 600e6);

        // Second withdrawal: 500e6 -> cumulative 1100e6 exceeds 1000e6 -> fails
        PackedUserOperation memory op = _buildCcaUserOp(smartAccount, recipient.addr, 500e6);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(WithdrawalLimitPolicy.WithdrawalLimitExceeded.selector, 1100e6, 1000e6)
            )
        );
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        // Balance unchanged after failed op
        assertEq(token.balanceOf(recipient.addr), 600e6, "recipient balance should still be 600");
    }

    function test_CCA_WindowResets() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 3000e6);

        // Use 1000e6 in first window
        _ccaWithdraw(smartAccount, recipient.addr, 1000e6);
        assertEq(token.balanceOf(recipient.addr), 1000e6);

        // Warp past the window
        vm.warp(block.timestamp + 1 days + 1);

        // New window: withdraw another 800e6 -> succeeds
        _ccaWithdraw(smartAccount, recipient.addr, 800e6);
        assertEq(token.balanceOf(recipient.addr), 1800e6, "recipient should have 1800 total");
    }

    function test_CCA_CannotTransferNonBundleToken() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);

        MockUSD otherToken = new MockUSD();
        otherToken.mint(smartAccount, 500e6);

        // Build UserOp targeting otherToken - not a bundle token -> hook reverts
        bytes32 execMode = _execMode();
        bytes memory transferCall = abi.encodeWithSelector(otherToken.transfer.selector, recipient.addr, uint256(100e6));
        bytes memory innerExecute =
            abi.encodeWithSelector(Kernel.execute.selector, execMode, _single(address(otherToken), 0, transferCall));
        bytes memory callData = abi.encodePacked(Kernel.executeUserOp.selector, innerExecute);

        PackedUserOperation memory op = _buildCcaUserOpRaw(smartAccount, callData, address(token));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        // Hook reverts with TokenNotInBundle -> EntryPoint wraps as execution revert
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));
        // The UserOp fails (success=false from EntryPointEvent) - recipient gets nothing
        assertEq(otherToken.balanceOf(recipient.addr), 0, "recipient should have no other token");
    }

    function test_NonCCA_SignatureRejected() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 500e6);

        // Build a UserOp but sign with user key instead of cca key (permission signature format)
        PackedUserOperation memory op = _buildCcaUserOp(smartAccount, recipient.addr, 100e6);
        // Overwrite the signer slice with the wrong key -> ECDSASigner recovers != cca -> AA24.
        op.signature = _permSignature(entrypoint.getUserOpHash(op), user.privKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));
    }

    function test_CCA_SeparatePermissionsPerToken() external {
        MockUSD token2 = new MockUSD();

        address[] memory bundleTokens = new address[](2);
        bundleTokens[0] = address(token);
        bundleTokens[1] = address(token2);

        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = vault;

        address smartAccount = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);
        vm.deal(smartAccount, 0.1 ether);

        // Pre-fund SA with user's own funds for each token
        token.mint(smartAccount, 2000e6);
        token2.mint(smartAccount, 2000e6);
        // topUp both tokens from vault
        token.mint(vault, 2000e6);
        token2.mint(vault, 2000e6);
        vm.startPrank(vault);
        token.approve(smartAccount, 2000e6);
        token2.approve(smartAccount, 2000e6);
        ITokenBundle(smartAccount).topUp(vault, address(token), 2000e6);
        ITokenBundle(smartAccount).topUp(vault, address(token2), 2000e6);
        vm.stopPrank();

        // Withdraw 800e6 of token via CCA permission for token
        _ccaWithdrawToken(smartAccount, recipient.addr, 800e6, address(token));
        assertEq(token.balanceOf(recipient.addr), 800e6);

        // Withdraw 900e6 of token2 via CCA permission for token2 - separate limit
        _ccaWithdrawToken(smartAccount, recipient.addr, 900e6, address(token2));
        assertEq(token2.balanceOf(recipient.addr), 900e6);
    }

    /// @dev T-02: a fee-on-transfer bundle token must credit the measured delta (2x(amount-fee)),
    ///      not the nominal 2xamount the pre-transfer credit produced (which over-stated the reserve).
    function test_W02_FeeOnTransfer_CreditsActualReceived() external {
        MockFeeToken feeToken = new MockFeeToken(100); // 1% fee

        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(feeToken);
        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = vault;

        address smartAccount = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);

        uint256 amount = 1000e6;
        uint256 fee = amount / 100; // 1%
        // Pre-fund SA (user's own funds) and vault; mint carries no fee.
        feeToken.mint(smartAccount, amount);
        feeToken.mint(vault, amount);
        vm.startPrank(vault);
        feeToken.approve(smartAccount, amount);
        ITokenBundle(smartAccount).topUp(vault, address(feeToken), amount);
        vm.stopPrank();

        assertEq(
            bundlePlugin.balanceOf(smartAccount, address(feeToken)),
            2 * (amount - fee),
            "bundle must credit 2x the received amount, not 2x the nominal amount"
        );
    }

    /// @dev T-03: the daily-limit debit is committed in the ERC-4337 validation phase, on purpose.
    ///      It is the safe failure mode - it can over-restrict (a reverted execution still consumes the
    ///      limit until the window resets) but two bundled ops can never over-spend, because the
    ///      EntryPoint validates every op before executing any. This test pins that intent: a withdraw
    ///      that passes validation (amount <= DAILY_LIMIT) but reverts in execution (account holds no
    ///      tokens to transfer) still leaves usedAmount debited.
    function test_W04_RevertingExec_StillDebits() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        // No topUp: the account holds 0 bundle tokens, so the transfer reverts on insufficient balance.
        uint256 amount = 500e6; // <= DAILY_LIMIT (1000e6): validation passes; > 0 balance: execution reverts.

        _ccaWithdraw(smartAccount, recipient.addr, amount);

        // Execution reverted (recipient received nothing) but the validation-phase debit persists.
        assertEq(token.balanceOf(recipient.addr), 0, "transfer must have reverted");
        bytes32 permId = bytes32(PermissionId.unwrap(_ccaPermId(address(token))));
        (uint256 used,) = withdrawalLimitPolicy.states(permId, smartAccount);
        assertEq(used, amount, "usedAmount is debited in validation and survives the reverted execution");
    }

    /// @dev T-01/T-08: the offset guard must reject a non-canonical offset in the withdraw-hook parser,
    ///      not only in the policy. callData[4]=0x00 (SINGLE) clears the call-type check; offset word 96
    ///      then trips NonCanonicalOffset before any fixed-window parse. 100 bytes = selector + ExecMode +
    ///      offset + length.
    function test_W01_WithdrawHook_NonCanonicalOffset_Reverts() external {
        bytes memory callData = abi.encodePacked(bytes4(0), bytes32(0), uint256(96), uint256(0));
        vm.expectRevert(abi.encodeWithSelector(BundleWithdrawHook.NonCanonicalOffset.selector, uint256(96)));
        bundleWithdrawHook.preCheck(address(0), 0, callData);
    }

    /// @dev T-01/T-08: the offset guard must reject a non-canonical offset in the spend-protector parser
    ///      too, so a crafted execution can't evade the approve-grant scan.
    function test_W01_SpendProtector_NonCanonicalOffset_Reverts() external {
        bytes memory msgData = abi.encodePacked(bytes4(0), bytes32(0), uint256(96), uint256(0));
        vm.expectRevert(abi.encodeWithSelector(BundleSpendProtectorHook.NonCanonicalOffset.selector, uint256(96)));
        bundleSpendProtectorHook.preCheck(address(0), 0, msgData);
    }

    /// @dev T-06: a Credis spend (CCA withdraw) emits BundleBalanceDecreased so the reserve movement
    ///      on the fund-holding account is observable off-chain (previously a silent mutation).
    function test_W07_DecreaseEmits() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6); // bundle = 2000e6
        uint256 withdrawAmount = 200e6;

        vm.expectEmit(true, true, false, true, address(bundlePlugin));
        emit BundleModulePlugin.BundleBalanceDecreased(
            smartAccount, address(token), withdrawAmount * 2, 2000e6 - withdrawAmount * 2
        );
        _ccaWithdraw(smartAccount, recipient.addr, withdrawAmount);
    }

    // -------------------------------------------------------------------------
    // Security tests
    // -------------------------------------------------------------------------

    function test_Security_DirectPluginCall_CannotDecreaseSmartAccountBalance() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6);

        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        // attacker is not an installed smart account -> BundleNotInstalled revert
        vm.expectRevert(abi.encodeWithSelector(BundleModulePlugin.BundleNotInstalled.selector));
        bundlePlugin.decreaseBundleBalance(address(token), 500e6);

        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 2000e6, "SA bundle balance must be unchanged");
    }

    function test_Security_DirectHookPostCheck_CannotDecreaseSmartAccountBalance() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6);

        address attacker = makeAddr("attacker");
        bytes memory hookData = abi.encode(address(token), uint256(500e6));

        // msg.sender in postCheck = attacker (not a Kernel account), so executeFromExecutor on
        // attacker reverts
        vm.prank(attacker);
        vm.expectRevert();
        bundleWithdrawHook.postCheck(hookData);

        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 2000e6, "SA bundle balance must be unchanged");
    }

    // OIP-00074: dispatchDecreaseBalance is the cross-account write; without a caller gate any address
    // routes it through the plugin's executor registration to zero any account's reserve. Guard binds
    // it to BundleWithdrawHook, so a direct call (attacker or the account owner) must revert.
    function test_R01_DirectDispatchDecrease_Reverts() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6); // reserve = 2000e6

        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(BundleModulePlugin.UnauthorizedHook.selector));
        bundlePlugin.dispatchDecreaseBalance(smartAccount, address(token), 2000e6);

        // Owner self-unlock uses the same entry point and must also revert.
        vm.prank(smartAccount);
        vm.expectRevert(abi.encodeWithSelector(BundleModulePlugin.UnauthorizedHook.selector));
        bundlePlugin.dispatchDecreaseBalance(smartAccount, address(token), 2000e6);

        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 2000e6, "reserve must be unchanged");
    }

    function test_Security_UnregisteredExecutor_CannotCallDispatchDecreaseBalance() external {
        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6);

        // Deploy a second account (attackerSA) - a valid Kernel account but NOT a registered
        // executor on smartAccount
        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(token);
        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = vault;
        (address attackerAddr,) = makeAddrAndKey("attacker2");
        address attackerSA = factory.createAccount(attackerAddr, attackerAddr, bundleTokens, bundleSenders, 99);

        bytes32 execMode = _execMode();
        bytes memory decreaseCall = abi.encodeCall(BundleModulePlugin.decreaseBundleBalance, (address(token), 500e6));
        bytes memory execCalldata = _single(address(bundlePlugin), 0, decreaseCall);

        // attackerSA is not a registered executor on smartAccount -> Kernel reverts
        vm.prank(attackerSA);
        vm.expectRevert();
        Kernel(payable(smartAccount)).executeFromExecutor(execMode, execCalldata);

        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 2000e6, "SA bundle balance must be unchanged");
    }

    function testFuzz_CCA_WithinLimit(uint96 amount) external {
        amount = uint96(bound(amount, 1, 1000e6));

        address smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);
        _topUp(smartAccount, 1000e6);

        _ccaWithdraw(smartAccount, recipient.addr, amount);
        assertEq(token.balanceOf(recipient.addr), amount, "recipient should receive exact amount");
        assertEq(
            bundlePlugin.balanceOf(smartAccount, address(token)), 2000e6 - amount * 2, "bundle balance should decrease"
        );
    }

    // -------------------------------------------------------------------------
    // CCA standing gate on account creation
    // -------------------------------------------------------------------------

    /// @dev Baseline for the three revert cases below: with the registry reporting `Active`,
    ///      creation succeeds. Without this, a gate that rejected *everything* would still make
    ///      the negative tests pass.
    function test_CreateAccount_SucceedsWhenCcaActive() external {
        (address[] memory bundleTokens, address[] memory bundleSenders) = _bundleArgs();
        ccaRegistry.setState(cca.addr, ICca.State.Active);

        address account = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 7);
        assertTrue(account.code.length > 0, "account should be deployed");
    }

    function test_RevertWhen_CcaSuspended() external {
        (address[] memory bundleTokens, address[] memory bundleSenders) = _bundleArgs();
        ccaRegistry.setState(cca.addr, ICca.State.Suspended);

        vm.expectRevert(
            abi.encodeWithSelector(SmartAccountFactory.CcaNotActive.selector, cca.addr, ICca.State.Suspended)
        );
        factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 8);
    }

    function test_RevertWhen_CcaDeregistered() external {
        (address[] memory bundleTokens, address[] memory bundleSenders) = _bundleArgs();
        ccaRegistry.setState(cca.addr, ICca.State.Deregistered);

        vm.expectRevert(
            abi.encodeWithSelector(SmartAccountFactory.CcaNotActive.selector, cca.addr, ICca.State.Deregistered)
        );
        factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 9);
    }

    /// @dev `Unknown` is the state of an address that never registered. It is the case the gate
    ///      exists for, and it must not be conflated with `Active`.
    function test_RevertWhen_CcaNeverRegistered() external {
        (address[] memory bundleTokens, address[] memory bundleSenders) = _bundleArgs();
        (address stranger,) = makeAddrAndKey("unregistered-cca");
        ccaRegistry.setState(stranger, ICca.State.Unknown);

        vm.expectRevert(abi.encodeWithSelector(SmartAccountFactory.CcaNotActive.selector, stranger, ICca.State.Unknown));
        factory.createAccount(user.addr, stranger, bundleTokens, bundleSenders, 10);
    }

    /// @dev Address prediction is deliberately left unguarded, so a client can compute the
    ///      counterfactual address before the agent is in good standing.
    function test_GetAccountAddress_IgnoresCcaState() external {
        (address[] memory bundleTokens, address[] memory bundleSenders) = _bundleArgs();

        ccaRegistry.setState(cca.addr, ICca.State.Active);
        address whenActive = factory.getAccountAddress(user.addr, cca.addr, bundleTokens, bundleSenders, 11);

        ccaRegistry.setState(cca.addr, ICca.State.Deregistered);
        address whenDeregistered = factory.getAccountAddress(user.addr, cca.addr, bundleTokens, bundleSenders, 11);

        assertEq(whenActive, whenDeregistered, "prediction must not depend on registry state");
    }

    function _bundleArgs() private view returns (address[] memory bundleTokens, address[] memory bundleSenders) {
        bundleTokens = new address[](1);
        bundleTokens[0] = address(token);
        bundleSenders = new address[](1);
        bundleSenders[0] = vault;
    }
}
