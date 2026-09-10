// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {BaseAATest} from "./BaseAATest.sol";
import {CallerHook} from "src/kernel/CallerHook.sol";
import {ITokenBundle} from "src/interfaces/ITokenBundle.sol";
import {MockUSD} from "src/mocks/MockUSD.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {Kernel} from "@zerodev/kernel/Kernel.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Execution} from "@zerodev/kernel/interfaces/IERC7579Account.sol";

contract SmartAccountApproach is BaseAATest {
    function test_UserCanSendEth_CcaCantWithdraw() external {
        // Deploy smart account
        address smartAccount = factory.createAccount(user.addr, cca.addr, new address[](0), new address[](0), 0);

        // Prefill user with 7 ETH
        vm.deal(user.addr, 7 ether);

        // User sends 1.3 ETH to smart account
        vm.prank(user.addr);
        (bool ok,) = payable(smartAccount).call{value: 1.3 ether}("");
        require(ok, "ETH transfer to smart account failed");

        assertEq(user.addr.balance, 5.7 ether, "user should have 5.7 ETH after sending to SA");
        assertEq(address(smartAccount).balance, 1.3 ether, "smart account should have 1.3 ETH");

        // Perform UserOp: send 1 ETH from smart account to recipient, signed by user
        bytes memory callData =
            abi.encodeWithSelector(Kernel.execute.selector, _execMode(), _single(recipient.addr, 1 ether, hex""));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, callData, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        // Check final balances
        assertEq(user.addr.balance, 5.7 ether, "user EOA should still have 5.7 ETH");
        assertApproxEqAbs(address(smartAccount).balance, 0.3 ether, 0.01 ether, "smart account should have ~0.3 ETH");
        assertEq(recipient.addr.balance, 1 ether, "recipient should have 1 ETH");

        // Malicious check: CCA cannot withdraw from smart account
        bytes memory maliciousCallData = abi.encodeWithSelector(
            Kernel.execute.selector, _execMode(), _single(cca.addr, address(smartAccount).balance, hex"")
        );

        PackedUserOperation[] memory maliciousOps = new PackedUserOperation[](1);
        maliciousOps[0] = _buildUserOp(smartAccount, maliciousCallData, cca.privKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        _bundle(maliciousOps, payable(ENTRYPOINT_BENEFICIARY));
    }

    function test_UserCanTopUpErc20_AndWithdrawToRecipient() external {
        // Deploy smart account and fund it with ETH for gas
        address smartAccount = factory.createAccount(user.addr, cca.addr, new address[](0), new address[](0), 0);
        vm.deal(smartAccount, 0.1 ether);

        // Mint 1000 tokens to user
        token.mint(user.addr, 1000e18);

        // User transfers 500 tokens to smart account
        vm.prank(user.addr);
        require(token.transfer(smartAccount, 500e18), "user->SA transfer failed");

        assertEq(token.balanceOf(user.addr), 500e18, "user should have 500 tokens");
        assertEq(token.balanceOf(smartAccount), 500e18, "smart account should have 500 tokens");

        // Perform UserOp: transfer 300 tokens from smart account to recipient, signed by user
        bytes memory callData = abi.encodeWithSelector(
            Kernel.execute.selector,
            _execMode(),
            _single(address(token), 0, abi.encodeWithSelector(token.transfer.selector, recipient.addr, 300e18))
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, callData, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        // Check final token balances
        assertEq(token.balanceOf(user.addr), 500e18, "user should still have 500 tokens");
        assertEq(token.balanceOf(smartAccount), 200e18, "smart account should have 200 tokens");
        assertEq(token.balanceOf(recipient.addr), 300e18, "recipient should have 300 tokens");
    }

    function test_topUp_AllowedSenderCanCall() external {
        // Set up bundle config: token as bundle token, mockVault as allowed sender
        address mockVault = makeAddr("vault");
        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(token);

        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = mockVault;

        address smartAccount = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);

        // Pre-fund smart account with user's own funds (required by topUp check)
        token.mint(smartAccount, 500e18);

        // Mint tokens to mockVault and approve the smart account to pull them.
        // topUp calls executeFromExecutor, so the smart account is msg.sender in transferFrom.
        token.mint(mockVault, 1000e18);
        vm.prank(mockVault);
        token.approve(smartAccount, 1000e18);

        // Allowed sender (mockVault) can call topUp through the smart account
        vm.prank(mockVault);
        ITokenBundle(smartAccount).topUp(mockVault, address(token), 500e18);

        assertEq(token.balanceOf(smartAccount), 1000e18, "smart account should have 1000 tokens");
        assertEq(
            bundlePlugin.balanceOf(smartAccount, address(token)),
            1000e18,
            "smart account should have 1000 tokens in bundle"
        );

        // Disallowed sender (cca) must revert with InvalidCaller from CallerHook
        address hacker = makeAddr("hacker");
        vm.prank(hacker);
        vm.expectRevert(CallerHook.InvalidCaller.selector);
        ITokenBundle(smartAccount).topUp(mockVault, address(token), 1e18);
    }

    function test_BundleSpendProtector_BlocksTransferExceedingFreeBalance() external {
        address mockVault = makeAddr("vault");
        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(token);
        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = mockVault;

        address smartAccount = factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);
        vm.deal(smartAccount, 0.1 ether);

        // Pre-fund SA with user's own funds for topUp + extra free balance
        token.mint(user.addr, 800e18);
        vm.prank(user.addr);
        require(token.transfer(smartAccount, 800e18), "user->SA transfer failed");

        // Bundle deposit: 600 tokens (locked) - SA already has 800 >= 600 [OK]
        token.mint(mockVault, 600e18);
        vm.prank(mockVault);
        token.approve(smartAccount, 600e18);
        vm.prank(mockVault);
        ITokenBundle(smartAccount).topUp(mockVault, address(token), 600e18);

        // total=1400, bundle=1200, free=200
        assertEq(token.balanceOf(smartAccount), 1400e18);
        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 1200e18);

        // Attempt 1: transfer 300 (exceeds free=200) -> hook reverts, UserOp marked failed (success=false)
        // Note: ERC-4337 handleOps does NOT revert on execution failures; it emits UserOperationEvent(success=false)
        bytes memory callData300 = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                _execMode(),
                _single(address(token), 0, abi.encodeWithSelector(token.transfer.selector, recipient.addr, 300e18))
            )
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, callData300, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        // Transfer was blocked: recipient has no tokens, smart account still has 1400
        assertEq(token.balanceOf(recipient.addr), 0, "recipient should have 0 tokens after blocked transfer");
        assertEq(token.balanceOf(smartAccount), 1400e18, "SA should still have 1400 tokens after blocked transfer");

        // Attempt 2: transfer 150 (within free=200) -> success
        bytes memory callData150 = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                _execMode(),
                _single(address(token), 0, abi.encodeWithSelector(token.transfer.selector, recipient.addr, 150e18))
            )
        );
        ops[0] = _buildUserOp(smartAccount, callData150, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(recipient.addr), 150e18, "recipient should have 150 tokens");
        assertEq(token.balanceOf(smartAccount), 1250e18, "SA should have 1250 tokens");
    }

    // OIP-00075: the hook enforces the reserve as a post-execution invariant (owner may remove at
    // most freeBalance of a bundled token, and may leave no standing allowance on it), covering
    // SINGLE, BATCH, and the "approve + atomic pull" repayment shape uniformly and address-agnostically.

    /// @dev A batch move within freeBalance is allowed - postCheck checks the NET balance after the
    ///      whole batch, so splitting a move across sub-calls cannot bypass the reserve, and there
    ///      is no need to reject batches wholesale (the prior over-conservative behavior).
    function test_BundleSpendProtector_AllowsBatchTransferWithinFree() external {
        address smartAccount = _setupSmartAccountWithFree(); // total=1400, bundle=1200, free=200

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({
            target: address(token),
            value: 0,
            callData: abi.encodeWithSelector(token.transfer.selector, recipient.addr, 100e18) // 100 <= free 200
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(recipient.addr), 100e18, "batch transfer within free should pass");
        assertEq(token.balanceOf(smartAccount), 1300e18, "SA balance should drop by the free amount");
    }

    /// @dev A batch move exceeding freeBalance breaks the reserve invariant and is rejected.
    function test_BundleSpendProtector_BlocksBatchTransferOverFree() external {
        address smartAccount = _setupSmartAccountWithFree(); // free = 200

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({
            target: address(token),
            value: 0,
            callData: abi.encodeWithSelector(token.transfer.selector, recipient.addr, 300e18) // 300 > free 200
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(recipient.addr), 0, "batch transfer over free must be blocked");
        assertEq(token.balanceOf(smartAccount), 1400e18, "SA balance unchanged after blocked batch");
    }

    /// @dev The sanctioned repayment shape: `[approve(puller, amt), puller.pull(...)]` where the
    ///      pull consumes the allowance via transferFrom within the same op. MockPuller is a generic
    ///      stand-in for the factory precompiles (credis/gem/nod/intex) so the hook needs no address
    ///      knowledge. Within free, it passes and leaves no residual allowance.
    function test_BundleSpendProtector_AllowsApproveConsumedWithinFree() external {
        address smartAccount = _setupSmartAccountWithFree(); // free = 200
        MockPuller puller = new MockPuller();

        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({
            target: address(token),
            value: 0,
            callData: abi.encodeWithSelector(token.approve.selector, address(puller), 150e18)
        });
        execs[1] = Execution({
            target: address(puller),
            value: 0,
            callData: abi.encodeWithSelector(MockPuller.pull.selector, address(token), smartAccount, 150e18)
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(address(puller)), 150e18, "puller should have pulled 150 within free");
        assertEq(token.balanceOf(smartAccount), 1250e18, "SA balance should drop by the pulled amount");
        assertEq(token.allowance(smartAccount, address(puller)), 0, "no residual allowance should remain");
    }

    /// @dev Same shape but the pulled amount exceeds freeBalance -> reserve invariant broken -> rejected.
    function test_BundleSpendProtector_BlocksApproveConsumedOverFree() external {
        address smartAccount = _setupSmartAccountWithFree(); // free = 200
        MockPuller puller = new MockPuller();

        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({
            target: address(token),
            value: 0,
            callData: abi.encodeWithSelector(token.approve.selector, address(puller), 250e18)
        });
        execs[1] = Execution({
            target: address(puller),
            value: 0,
            callData: abi.encodeWithSelector(MockPuller.pull.selector, address(token), smartAccount, 250e18)
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(address(puller)), 0, "pull over free must be blocked");
        assertEq(token.balanceOf(smartAccount), 1400e18, "SA balance unchanged after blocked pull");
        assertEq(token.allowance(smartAccount, address(puller)), 0, "allowance rolled back after revert");
    }

    /// @dev A standalone (unconsumed) approve in a batch leaves a standing allowance a grantee could
    ///      later drain via an unhooked transferFrom -> rejected by the no-standing-allowance rule.
    function test_BundleSpendProtector_BlocksUnconsumedBatchApprove() external {
        address smartAccount = _setupSmartAccountWithFree();
        address spender = makeAddr("spender");

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({
            target: address(token), value: 0, callData: abi.encodeWithSelector(token.approve.selector, spender, 50e18)
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.allowance(smartAccount, spender), 0, "unconsumed batch approve must be blocked");
    }

    /// @dev A batch that touches only non-bundled (free) tokens still executes. Paired with the
    ///      test above, this isolates the block to the bundled-token check (same batch encoding).
    function test_BundleSpendProtector_AllowsBatchOfNonBundledToken() external {
        address smartAccount = _setupSmartAccountWithFree();

        MockUSD freeToken = new MockUSD(); // not part of the bundle
        freeToken.mint(smartAccount, 500e18);

        Execution[] memory execs = new Execution[](1);
        execs[0] = Execution({
            target: address(freeToken),
            value: 0,
            callData: abi.encodeWithSelector(freeToken.transfer.selector, recipient.addr, 500e18)
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, _batchCallData(execs), user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(freeToken.balanceOf(recipient.addr), 500e18, "batch over a non-bundled token should pass");
        assertEq(freeToken.balanceOf(smartAccount), 0, "SA free-token balance should have moved out");
    }

    /// @dev approve of a bundled token is rejected: a static check at grant time cannot bound the
    ///      grantee's later, unhooked transferFrom. Absent the hook the approve would set a 50e18
    ///      allowance, so the allowance staying 0 attributes the block to the hook.
    function test_BundleSpendProtector_BlocksApproveOfBundledToken() external {
        address smartAccount = _setupSmartAccountWithFree();
        address spender = makeAddr("spender");

        bytes memory callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                _execMode(),
                _single(address(token), 0, abi.encodeWithSelector(token.approve.selector, spender, 50e18))
            )
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, callData, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.allowance(smartAccount, spender), 0, "approve of bundled token must be blocked");
    }

    /// @dev transferFrom of a bundled token exceeding freeBalance is blocked. A self-allowance is
    ///      set directly (not via the hooked root path) so that, absent the hook, the transferFrom
    ///      WOULD move funds - the balance staying put attributes the block to the hook, not to a
    ///      missing allowance.
    function test_BundleSpendProtector_BlocksTransferFromOfBundledTokenOverFree() external {
        address smartAccount = _setupSmartAccountWithFree(); // free = 200

        vm.prank(smartAccount);
        token.approve(smartAccount, type(uint256).max);

        // transferFrom(SA, recipient, 250): 250 > free 200, but allowance + balance are sufficient.
        bytes memory callData = abi.encodePacked(
            Kernel.executeUserOp.selector,
            abi.encodeWithSelector(
                Kernel.execute.selector,
                _execMode(),
                _single(
                    address(token),
                    0,
                    abi.encodeWithSelector(token.transferFrom.selector, smartAccount, recipient.addr, 250e18)
                )
            )
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _buildUserOp(smartAccount, callData, user.privKey);
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));

        assertEq(token.balanceOf(recipient.addr), 0, "transferFrom over free must be blocked by the hook");
        assertEq(token.balanceOf(smartAccount), 1400e18, "SA balance unchanged after blocked transferFrom");
    }

    // --- helpers ---

    /// @dev Deploys a smart account (bundle token = `token`, sender = `vault`) and funds it so
    ///      that total = 1400e18, bundleBalance = 1200e18, freeBalance = 200e18.
    function _setupSmartAccountWithFree() private returns (address smartAccount) {
        smartAccount = _deployAccount();
        vm.deal(smartAccount, 0.1 ether);

        // SA's own (free) funds, pre-funded so the topUp solvency check passes
        token.mint(user.addr, 800e18);
        vm.prank(user.addr);
        require(token.transfer(smartAccount, 800e18), "user->SA transfer failed");

        // Bundle deposit: 600 from vault -> bundleBalance doubles to 1200, total balance 1400
        token.mint(vault, 600e18);
        vm.prank(vault);
        token.approve(smartAccount, 600e18);
        vm.prank(vault);
        ITokenBundle(smartAccount).topUp(vault, address(token), 600e18);

        assertEq(token.balanceOf(smartAccount), 1400e18, "setup: SA total balance");
        assertEq(bundlePlugin.balanceOf(smartAccount, address(token)), 1200e18, "setup: bundle balance");
    }

    /// @dev Wraps executions as a CALLTYPE_BATCH executeUserOp callData, using the kernel's own
    ///      ExecLib.encodeBatch (abi.encode(Execution[])) so it decodes via LibERC7579 exactly as
    ///      the hook reads it.
    function _batchCallData(Execution[] memory execs) private pure returns (bytes memory) {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        // ERC-7579 batch execution calldata = abi.encode(Execution[]); decodes via LibERC7579 as the hook reads it.
        bytes memory inner = abi.encodeWithSelector(Kernel.execute.selector, mode, abi.encode(execs));
        return abi.encodePacked(Kernel.executeUserOp.selector, inner);
    }
}

/// @dev Generic stand-in for the "caller approves, precompile pulls" factory flows
///      (credis/gem/nod/intex). `pull` consumes the caller-granted allowance via transferFrom,
///      exactly as those precompiles do - letting the tests exercise the consumed-approve path
///      without deploying the real precompiles.
contract MockPuller {
    function pull(address token, address from, uint256 amount) external {
        require(IERC20(token).transferFrom(from, address(this), amount), "pull failed");
    }
}
