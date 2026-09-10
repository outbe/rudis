// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {SmartAccountFactory} from "src/SmartAccountFactory.sol";
import {BundleModulePlugin} from "src/BundleModulePlugin.sol";
import {CallerHook} from "src/kernel/CallerHook.sol";
import {SudoPolicy} from "src/kernel/SudoPolicy.sol";
import {BundleSpendProtectorHook} from "src/BundleSpendProtectorHook.sol";
import {BundleWithdrawHook} from "src/BundleWithdrawHook.sol";
import {ECDSASigner} from "src/kernel/ECDSASigner.sol";
import {WithdrawalLimitPolicy} from "src/WithdrawalLimitPolicy.sol";
import {ITokenBundle} from "src/interfaces/ITokenBundle.sol";
import {MockCcaRegistry} from "src/mocks/MockCcaRegistry.sol";
import {MockUSD} from "src/mocks/MockUSD.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {Kernel} from "@zerodev/kernel/Kernel.sol";
import {KernelUUPS} from "@zerodev/kernel/KernelUUPS.sol";
import {KernelImmutableECDSA} from "@zerodev/kernel/KernelImmutableECDSA.sol";
import {KernelFactory} from "@zerodev/kernel/KernelFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {PermissionId} from "@zerodev/kernel/types/Types.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @dev Shared harness for the Kernel v4 Credis smart-account stack.
///      Every validation is a permission (owner + per-token CCA), so all UserOps use the
///      permission nonce type (0x02) and the Kernel v4 `PermissionSignature` = abi.encode(bytes[]),
///      one slice per policy (unused here) plus the signer's ECDSA signature last.
abstract contract BaseAATest is Test {
    struct EOA {
        address addr;
        uint256 privKey;
    }

    // actors
    EOA user;
    EOA cca;
    EOA recipient;
    address vault;

    // contracts from Kernel stack
    IEntryPoint entrypoint;
    SmartAccountFactory factory;

    // plugin contracts
    BundleModulePlugin bundlePlugin;
    CallerHook bundleCallerHook;
    SudoPolicy sudoPolicy;
    BundleSpendProtectorHook bundleSpendProtectorHook;
    WithdrawalLimitPolicy withdrawalLimitPolicy;
    ECDSASigner ecdsaSigner;
    BundleWithdrawHook bundleWithdrawHook;

    // token
    MockUSD token;

    // CCA registry precompile stand-in, etched at SmartAccountFactory.CCA_REGISTRY()
    MockCcaRegistry ccaRegistry;

    address ENTRYPOINT_BENEFICIARY = address(0xdeadbeef);

    function setUp() public virtual {
        _setupEoa();

        entrypoint = EntryPointLib.deploy();

        // Kernel v4 ships an abstract Kernel; the factory deploys UUPS ERC-1967 proxies and needs
        // both the UUPS and immutable-ECDSA implementations at construction.
        KernelUUPS uups = new KernelUUPS(entrypoint);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(entrypoint);
        KernelFactory kf = new KernelFactory(uups, immutableEcdsa);

        sudoPolicy = new SudoPolicy();
        bundlePlugin = new BundleModulePlugin(address(this));
        bundleCallerHook = new CallerHook();
        bundleSpendProtectorHook = new BundleSpendProtectorHook(address(bundlePlugin));
        withdrawalLimitPolicy = new WithdrawalLimitPolicy();
        ecdsaSigner = new ECDSASigner();
        bundleWithdrawHook = new BundleWithdrawHook(address(bundlePlugin));
        bundlePlugin.setWithdrawHook(address(bundleWithdrawHook));

        factory = new SmartAccountFactory(
            address(kf),
            address(sudoPolicy),
            address(bundlePlugin),
            address(bundleCallerHook),
            address(bundleSpendProtectorHook),
            address(withdrawalLimitPolicy),
            address(ecdsaSigner),
            address(bundleWithdrawHook)
        );

        token = new MockUSD();

        // The factory reads CCA standing from a fixed protocol address, so put the mock registry
        // there. `vm.etch` copies runtime code only; MockCcaRegistry treats its resulting empty
        // storage as "every agent Active", which is what the current precompile stub answers.
        vm.etch(factory.CCA_REGISTRY(), address(new MockCcaRegistry()).code);
        ccaRegistry = MockCcaRegistry(factory.CCA_REGISTRY());
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    function _setupEoa() private {
        (address addr, uint256 key) = makeAddrAndKey("user");
        user.addr = addr;
        user.privKey = key;

        (addr, key) = makeAddrAndKey("cca");
        cca.addr = addr;
        cca.privKey = key;

        (addr, key) = makeAddrAndKey("recipient");
        recipient.addr = addr;
        recipient.privKey = key;

        vault = makeAddr("vault");
    }

    function _topUp(address smartAccount, uint256 amount) internal {
        // Pre-fund smart account with user's own funds (required by topUp check)
        token.mint(smartAccount, amount);
        // Vault tops up matching amount
        token.mint(vault, amount);
        vm.startPrank(vault);
        token.approve(smartAccount, amount);
        ITokenBundle(smartAccount).topUp(vault, address(token), amount);
        vm.stopPrank();
    }

    function _deployAccount() internal returns (address) {
        address[] memory bundleTokens = new address[](1);
        bundleTokens[0] = address(token);

        address[] memory bundleSenders = new address[](1);
        bundleSenders[0] = vault;

        return factory.createAccount(user.addr, cca.addr, bundleTokens, bundleSenders, 0);
    }

    function _ownerPermId() internal pure returns (PermissionId) {
        return PermissionId.wrap(bytes4(keccak256("credis.owner")));
    }

    function _ccaPermId(address tok) internal pure returns (PermissionId) {
        return PermissionId.wrap(bytes4(keccak256(abi.encode("credis.cca", tok))));
    }

    /// @dev Kernel v4 nonce key (top 24 bytes of userOp.nonce):
    ///      [vMode(1)=0x00 | vType(1)=0x02 permission | vId(20) | parallel(2)=0].
    ///      The permission id occupies the high 4 bytes of the 20-byte vId.
    function _permNonceKey(PermissionId permId) internal pure returns (uint192) {
        return (uint192(0x02) << 176) | (uint192(uint32(PermissionId.unwrap(permId))) << 144);
    }

    /// @dev Kernel v4 permission signature: abi.encode(bytes[] signatures), one slice per policy
    ///      (empty - our policies read from calldata, not the signature) then the signer's ECDSA sig.
    function _permSignature(bytes32 userOpHash, uint256 signerKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ECDSA.toEthSignedMessageHash(userOpHash));
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = ""; // single policy slice (SudoPolicy / WithdrawalLimitPolicy ignore it)
        sigs[1] = abi.encodePacked(r, s, v);
        return abi.encode(sigs);
    }

    function _buildCcaUserOp(address smartAccount, address to, uint256 amount)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        bytes32 execMode = _execMode();
        bytes memory transferCall = abi.encodeWithSelector(token.transfer.selector, to, amount);
        bytes memory innerExecute = abi.encodeWithSelector(
            Kernel.execute.selector, execMode, abi.encodePacked(address(token), uint256(0), transferCall)
        );
        bytes memory callData = abi.encodePacked(Kernel.executeUserOp.selector, innerExecute);
        return _buildCcaUserOpRaw(smartAccount, callData, address(token));
    }

    function _buildCcaUserOpRaw(address smartAccount, bytes memory callData, address tok)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        PermissionId permId = _ccaPermId(tok);

        op = PackedUserOperation({
            sender: smartAccount,
            nonce: entrypoint.getNonce(smartAccount, _permNonceKey(permId)),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
            preVerificationGas: 1_000_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        op.signature = _permSignature(userOpHash, cca.privKey);
    }

    function _ccaWithdraw(address smartAccount, address to, uint256 amount) internal {
        _ccaWithdrawToken(smartAccount, to, amount, address(token));
    }

    function _ccaWithdrawToken(address smartAccount, address to, uint256 amount, address tok) internal {
        bytes32 execMode = _execMode();
        bytes memory transferCall = abi.encodeWithSelector(MockUSD(tok).transfer.selector, to, amount);
        bytes memory innerExecute =
            abi.encodeWithSelector(Kernel.execute.selector, execMode, abi.encodePacked(tok, uint256(0), transferCall));
        bytes memory callData = abi.encodePacked(Kernel.executeUserOp.selector, innerExecute);

        PackedUserOperation memory op = _buildCcaUserOpRaw(smartAccount, callData, tok);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        _bundle(ops, payable(ENTRYPOINT_BENEFICIARY));
    }

    /// @dev Owner-signed UserOp. The owner is a permission (SudoPolicy + ECDSASigner), so it uses
    ///      the permission nonce/signature encoding. When bundle tokens are configured the owner
    ///      permission carries BundleSpendProtectorHook and `callData` must be executeUserOp-wrapped;
    ///      the caller builds the appropriate `callData` shape.
    function _buildUserOp(address sender, bytes memory callData, uint256 signerKey)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        PermissionId permId = _ownerPermId();

        op = PackedUserOperation({
            sender: sender,
            nonce: entrypoint.getNonce(sender, _permNonceKey(permId)),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
            preVerificationGas: 1_000_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        op.signature = _permSignature(userOpHash, signerKey);
    }

    /// @dev Single-call default ERC-7579 execution mode as a raw bytes32 (Kernel v4 execute()).
    function _execMode() internal pure returns (bytes32) {
        return LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
    }

    /// @dev ERC-7579 single execution calldata: target(20) || value(32) || callData (replaces v3.3 ExecLib.encodeSingle).
    function _single(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(target, value, data);
    }

    /// @dev Submit ops through the EntryPoint. EntryPoint v0.9's `nonReentrant` guard requires the
    ///      caller (bundler) to be an EOA with `tx.origin == msg.sender`, so prank as the beneficiary.
    function _bundle(PackedUserOperation[] memory ops, address payable beneficiary) internal {
        vm.prank(ENTRYPOINT_BENEFICIARY, ENTRYPOINT_BENEFICIARY);
        entrypoint.handleOps(ops, beneficiary);
    }
}
