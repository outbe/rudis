// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {ERC7786TokenBridge} from "../../src/ERC7786TokenBridge.sol";
import {IERC7786TokenReceiver} from "../../src/interfaces/IERC7786TokenReceiver.sol";
import {USDT} from "../../src/canonical/USDT.sol";
import {BridgeableERC20Stable} from "../../src/synthetic/BridgeableERC20Stable.sol";
import {MockERC7786Bridge} from "../mocks/MockERC7786Bridge.sol";

/// @dev Records the hook invocation; configurable to misbehave.
contract MockTokenReceiver is IERC7786TokenReceiver {
    IERC20 public immutable token;

    uint256 public calls;
    uint32 public lastSourceDomain;
    bytes public lastFrom;
    uint256 public lastAmount;
    bytes public lastExtraData;
    uint256 public balanceAtHook;

    bool public returnWrongMagic;
    bool public revertOnHook;

    constructor(IERC20 token_) {
        token = token_;
    }

    function setReturnWrongMagic(bool v) external {
        returnWrongMagic = v;
    }

    function setRevertOnHook(bool v) external {
        revertOnHook = v;
    }

    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external returns (bytes4) {
        if (revertOnHook) revert("hook revert");

        calls++;
        lastSourceDomain = sourceDomain;
        lastFrom = from;
        lastAmount = amount;
        lastExtraData = extraData;
        balanceAtHook = token.balanceOf(address(this));

        if (returnWrongMagic) return 0xdeadbeef;
        return IERC7786TokenReceiver.onCrosschainTokensReceived.selector;
    }
}

contract ERC7786TokenBridgeComposedTest is Test {
    uint32 internal constant BNB = 56;
    uint32 internal constant OUTBE = 12_121;

    address internal alice = makeAddr("alice");

    MockERC7786Bridge internal bnbGateway;
    MockERC7786Bridge internal outbeGateway;

    USDT internal usdt;
    BridgeableERC20Stable internal usdt0;
    ERC7786TokenBridge internal bnbUsdtBridge;
    ERC7786TokenBridge internal outbeUsdt0Bridge;

    MockTokenReceiver internal receiver;

    function setUp() public {
        bnbGateway = new MockERC7786Bridge(BNB);
        outbeGateway = new MockERC7786Bridge(OUTBE);
        bnbGateway.setRemoteBridge(OUTBE, outbeGateway);
        outbeGateway.setRemoteBridge(BNB, bnbGateway);

        usdt = new USDT();
        usdt0 = new BridgeableERC20Stable("USDT0", "USDT0", 6, 840, address(this));

        bnbUsdtBridge = new ERC7786TokenBridge(
            address(usdt), address(bnbGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.LockUnlock
        );
        outbeUsdt0Bridge = new ERC7786TokenBridge(
            address(usdt0), address(outbeGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.BurnMint
        );

        usdt0.setTokenBridge(address(outbeUsdt0Bridge));
        bnbUsdtBridge.setRemoteBridge(OUTBE, _interop(OUTBE, address(outbeUsdt0Bridge)));
        outbeUsdt0Bridge.setRemoteBridge(BNB, _interop(BNB, address(bnbUsdtBridge)));

        receiver = new MockTokenReceiver(IERC20(address(usdt0)));
    }

    function test_SendAndCall_DeliversTokensThenHook() public {
        uint256 amount = 100e6;
        bytes memory extraData = abi.encode(uint32(20_260_706));
        usdt.mint(alice, amount);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), amount);
        bnbUsdtBridge.sendAndCall(OUTBE, address(receiver), amount, extraData, 500_000);
        vm.stopPrank();

        assertEq(usdt0.balanceOf(address(receiver)), amount);
        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastSourceDomain(), BNB);
        assertEq(receiver.lastFrom(), _interop(block.chainid, alice));
        assertEq(receiver.lastAmount(), amount);
        assertEq(receiver.lastExtraData(), extraData);
        // Tokens were credited before the hook ran.
        assertEq(receiver.balanceAtHook(), amount);
    }

    function test_Send_PlainDoesNotInvokeHook() public {
        uint256 amount = 100e6;
        usdt.mint(alice, amount);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), amount);
        bnbUsdtBridge.send(OUTBE, address(receiver), amount);
        vm.stopPrank();

        assertEq(usdt0.balanceOf(address(receiver)), amount);
        assertEq(receiver.calls(), 0);
    }

    function test_RevertWhen_SendAndCallWithEmptyExtraData() public {
        usdt.mint(alice, 1);
        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), 1);
        vm.expectRevert(ERC7786TokenBridge.EmptyExtraData.selector);
        bnbUsdtBridge.sendAndCall(OUTBE, address(receiver), 1, "", 0);
        vm.stopPrank();
    }

    function test_RevertWhen_SendAndCallToZeroRecipient() public {
        usdt.mint(alice, 1);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), 1);
        vm.expectRevert(abi.encodeWithSelector(ERC7786TokenBridge.InvalidRecipient.selector, address(0)));
        bnbUsdtBridge.sendAndCall(OUTBE, address(0), 1, abi.encode(uint32(1)), 0);
        vm.stopPrank();

        assertEq(usdt.balanceOf(alice), 1);
        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 0);
    }

    function test_RevertWhen_HookReturnsWrongMagic() public {
        receiver.setReturnWrongMagic(true);
        uint256 amount = 100e6;
        usdt.mint(alice, amount);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), amount);
        vm.expectRevert();
        bnbUsdtBridge.sendAndCall(OUTBE, address(receiver), amount, abi.encode(uint32(1)), 0);
        vm.stopPrank();

        // The whole transfer rolled back: nothing locked, nothing minted.
        assertEq(usdt.balanceOf(alice), amount);
        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 0);
        assertEq(usdt0.balanceOf(address(receiver)), 0);
    }

    function test_RevertWhen_HookReverts() public {
        receiver.setRevertOnHook(true);
        uint256 amount = 100e6;
        usdt.mint(alice, amount);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), amount);
        vm.expectRevert();
        bnbUsdtBridge.sendAndCall(OUTBE, address(receiver), amount, abi.encode(uint32(1)), 0);
        vm.stopPrank();

        assertEq(usdt.balanceOf(alice), amount);
        assertEq(usdt0.balanceOf(address(receiver)), 0);
    }

    function test_RevertWhen_SendAndCallToEOA() public {
        uint256 amount = 100e6;
        usdt.mint(alice, amount);

        vm.startPrank(alice);
        usdt.approve(address(bnbUsdtBridge), amount);
        vm.expectRevert();
        bnbUsdtBridge.sendAndCall(OUTBE, alice, amount, abi.encode(uint32(1)), 0);
        vm.stopPrank();
    }

    function test_QuoteSend_WithExtraDataDelegatesToBridge() public {
        bnbGateway.setFeeQuote(456);
        assertEq(bnbUsdtBridge.quoteSend(OUTBE, address(receiver), 1, abi.encode(uint32(1)), 500_000), 456);
    }

    function _interop(uint256 chainId, address addr) internal pure returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(chainId, addr);
    }
}
