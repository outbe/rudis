// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {ERC7786TokenBridge} from "../../src/ERC7786TokenBridge.sol";
import {USDT} from "../../src/canonical/USDT.sol";
import {BridgeableERC20Stable} from "../../src/synthetic/BridgeableERC20Stable.sol";
import {WCOEN as NativeWCOEN} from "../../src/canonical/WCOEN.sol";
import {BridgeableERC20 as SyntheticWCOEN} from "../../src/synthetic/BridgeableERC20.sol";
import {MockERC7786Bridge} from "../mocks/MockERC7786Bridge.sol";
import {MockStablecoin} from "../mocks/MockStablecoin.sol";

contract ERC7786TokenBridgeTest is Test {
    uint32 internal constant BNB = 97;
    uint32 internal constant OUTBE = 70860602;

    address internal sourceAddr = makeAddr("sourceAddr");
    address internal targetAddr = makeAddr("targetAddr");
    address internal intruder = makeAddr("intruder");

    MockERC7786Bridge internal bnbGateway;
    MockERC7786Bridge internal outbeGateway;

    USDT internal usdt;
    BridgeableERC20Stable internal usdt0;
    ERC7786TokenBridge internal bnbUsdtBridge;
    ERC7786TokenBridge internal outbeUsdt0Bridge;

    NativeWCOEN internal outbeWcoen;
    SyntheticWCOEN internal bnbWcoen;
    ERC7786TokenBridge internal outbeWcoenBridge;
    ERC7786TokenBridge internal bnbWcoenBridge;

    MockStablecoin internal stable;
    ERC7786TokenBridge internal bnbStableBridge;
    ERC7786TokenBridge internal outbeStableBridge;

    function setUp() public {
        bnbGateway = new MockERC7786Bridge(BNB);
        outbeGateway = new MockERC7786Bridge(OUTBE);
        bnbGateway.setRemoteBridge(OUTBE, outbeGateway);
        outbeGateway.setRemoteBridge(BNB, bnbGateway);

        _setUpUsdtRoute();
        _setUpWcoenRoute();
        _setUpStablecoinRoute();
    }

    function test_USDT_BNBToOutbe_LockAndMint() public {
        uint256 amount = 100e6;
        usdt.mint(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bnbUsdtBridge), amount);
        bnbUsdtBridge.send(OUTBE, targetAddr, amount);
        vm.stopPrank();

        assertEq(usdt.balanceOf(sourceAddr), 0);
        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), amount);
        assertEq(usdt0.balanceOf(targetAddr), amount);
    }

    function test_USDT_OutbeToBNB_BurnAndUnlock() public {
        uint256 amount = 100e6;
        usdt.mint(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bnbUsdtBridge), amount);
        bnbUsdtBridge.send(OUTBE, targetAddr, amount);
        vm.stopPrank();

        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 100e6);

        vm.prank(targetAddr);
        outbeUsdt0Bridge.send(BNB, sourceAddr, 40e6);

        assertEq(usdt0.balanceOf(targetAddr), 60e6);
        assertEq(usdt.balanceOf(sourceAddr), 40e6);
        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 60e6);
    }

    function test_WCOEN_OutbeToBNB_LockAndMint() public {
        uint256 amount = 2e6;
        vm.deal(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        outbeWcoen.deposit{value: amount}();
        outbeWcoen.approve(address(outbeWcoenBridge), amount);
        outbeWcoenBridge.send(BNB, targetAddr, amount);
        vm.stopPrank();

        assertEq(outbeWcoen.balanceOf(sourceAddr), 0);
        assertEq(outbeWcoen.balanceOf(address(outbeWcoenBridge)), amount);
        assertEq(bnbWcoen.balanceOf(targetAddr), amount);
    }

    function test_WCOEN_BNBToOutbe_BurnAndUnlock() public {
        uint256 amount = 2e6;
        vm.deal(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        outbeWcoen.deposit{value: amount}();
        outbeWcoen.approve(address(outbeWcoenBridge), amount);
        outbeWcoenBridge.send(BNB, targetAddr, amount);
        vm.stopPrank();

        vm.prank(targetAddr);
        bnbWcoenBridge.send(OUTBE, sourceAddr, 1e6);

        assertEq(bnbWcoen.balanceOf(targetAddr), 1e6);
        assertEq(outbeWcoen.balanceOf(sourceAddr), 1e6);
        assertEq(outbeWcoen.balanceOf(address(outbeWcoenBridge)), 1e6);
    }

    function test_Quote_DelegatesToBridge() public {
        outbeGateway.setFeeQuote(123);
        vm.prank(targetAddr);
        assertEq(outbeUsdt0Bridge.quoteSend(BNB, sourceAddr, 1, "", 0), 123);
    }

    function test_RevertWhen_RemoteBridgeNotSet() public {
        ERC7786TokenBridge bridge = new ERC7786TokenBridge(
            address(usdt), address(bnbGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.LockUnlock
        );
        usdt.mint(sourceAddr, 1);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bridge), 1);
        vm.expectRevert(abi.encodeWithSelector(ERC7786TokenBridge.RemoteBridgeNotSet.selector, OUTBE));
        bridge.send(OUTBE, targetAddr, 1);
        vm.stopPrank();
    }

    function test_RevertWhen_SendToZeroRecipient() public {
        usdt.mint(sourceAddr, 1);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bnbUsdtBridge), 1);
        vm.expectRevert(abi.encodeWithSelector(ERC7786TokenBridge.InvalidRecipient.selector, address(0)));
        bnbUsdtBridge.send(OUTBE, address(0), 1);
        vm.stopPrank();

        assertEq(usdt.balanceOf(sourceAddr), 1);
        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 0);
    }

    function test_RevertWhen_ReceiveFromNonBridge() public {
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(ERC7786TokenBridge.UnauthorizedBridge.selector, intruder));
        outbeUsdt0Bridge.receiveMessage(bytes32(0), _interop(BNB, address(bnbUsdtBridge)), "");
    }

    function test_RevertWhen_ReceiveFromWrongRemoteBridge() public {
        bytes memory wrongSender = _interop(BNB, intruder);

        vm.prank(address(outbeGateway));
        vm.expectRevert(abi.encodeWithSelector(ERC7786TokenBridge.UnauthorizedRemoteBridge.selector, wrongSender));
        outbeUsdt0Bridge.receiveMessage(bytes32(0), wrongSender, "");
    }

    function test_RevertWhen_LockSideHasNoAllowance() public {
        usdt.mint(sourceAddr, 1);

        vm.prank(sourceAddr);
        vm.expectRevert();
        bnbUsdtBridge.send(OUTBE, targetAddr, 1);
    }

    function test_Stablecoin_BNBToOutbe_LockAndMint() public {
        uint256 amount = 100e6;
        usdt.mint(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bnbStableBridge), amount);
        bnbStableBridge.send(OUTBE, targetAddr, amount);
        vm.stopPrank();

        assertEq(usdt.balanceOf(address(bnbStableBridge)), amount, "locked on the canonical side");
        assertEq(stable.balanceOf(targetAddr), amount, "minted on the issuer side");
    }

    function test_Stablecoin_OutbeToBNB_BurnAndUnlock() public {
        uint256 amount = 100e6;
        usdt.mint(address(bnbStableBridge), amount);
        stable.grantIssuer(address(this));
        stable.mint(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        stable.approve(address(outbeStableBridge), amount);
        outbeStableBridge.send(BNB, targetAddr, amount);
        vm.stopPrank();

        assertEq(stable.balanceOf(sourceAddr), 0, "burned on the issuer side");
        assertEq(stable.totalSupply(), 0, "supply follows the burn");
        assertEq(usdt.balanceOf(targetAddr), amount, "unlocked on the canonical side");
    }

    /// @dev `burnFrom` spends an allowance, so an unapproved sender must not get as far as the
    ///      message: the tokens would be minted on the far side against nothing burned here.
    function test_RevertWhen_IssuerBurnHasNoAllowance() public {
        stable.grantIssuer(address(this));
        stable.mint(sourceAddr, 1);

        vm.prank(sourceAddr);
        vm.expectRevert();
        outbeStableBridge.send(BNB, targetAddr, 1);

        assertEq(stable.balanceOf(sourceAddr), 1, "nothing burned");
    }

    function test_RevertWhen_BridgeLacksIssuerRole() public {
        stable.revokeIssuer(address(outbeStableBridge));

        vm.prank(address(outbeGateway));
        vm.expectRevert(abi.encodeWithSelector(MockStablecoin.NotIssuer.selector, address(outbeStableBridge)));
        outbeStableBridge.receiveMessage(
            bytes32(0),
            _interop(BNB, address(bnbStableBridge)),
            abi.encode(abi.encodePacked(sourceAddr), targetAddr, uint256(1), bytes(""))
        );
    }

    function _setUpStablecoinRoute() internal {
        stable = new MockStablecoin("USD Tether", "USDT", address(this));

        bnbStableBridge = new ERC7786TokenBridge(
            address(usdt), address(bnbGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.LockUnlock
        );
        outbeStableBridge = new ERC7786TokenBridge(
            address(stable), address(outbeGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.IssuerBurnMint
        );

        // No setTokenBridge: the issuer side is authorized by role, not by a token->bridge link.
        stable.grantIssuer(address(outbeStableBridge));
        bnbStableBridge.setRemoteBridge(OUTBE, _interop(OUTBE, address(outbeStableBridge)));
        outbeStableBridge.setRemoteBridge(BNB, _interop(BNB, address(bnbStableBridge)));
    }

    function test_EmergencyWithdraw_OwnerRecoversLockedTokens() public {
        uint256 amount = 100e6;
        usdt.mint(sourceAddr, amount);

        vm.startPrank(sourceAddr);
        usdt.approve(address(bnbUsdtBridge), amount);
        bnbUsdtBridge.send(OUTBE, targetAddr, amount);
        vm.stopPrank();

        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), amount, "not locked");

        vm.expectEmit(true, false, false, true);
        emit ERC7786TokenBridge.EmergencyWithdrawn(address(this), amount);
        bnbUsdtBridge.emergencyWithdraw();

        assertEq(usdt.balanceOf(address(bnbUsdtBridge)), 0, "bridge still holds tokens");
        assertEq(usdt.balanceOf(address(this)), amount, "owner did not receive them");
    }

    function test_RevertWhen_EmergencyWithdrawFromNonOwner() public {
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, intruder));
        bnbUsdtBridge.emergencyWithdraw();
    }

    function _setUpUsdtRoute() internal {
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
    }

    function _setUpWcoenRoute() internal {
        outbeWcoen = new NativeWCOEN();
        bnbWcoen = new SyntheticWCOEN("Wrapped Rudis", "wrudis", 18, address(this));

        outbeWcoenBridge = new ERC7786TokenBridge(
            address(outbeWcoen), address(outbeGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.LockUnlock
        );
        bnbWcoenBridge = new ERC7786TokenBridge(
            address(bnbWcoen), address(bnbGateway), address(this), ERC7786TokenBridge.TokenBridgeMode.BurnMint
        );

        bnbWcoen.setTokenBridge(address(bnbWcoenBridge));
        outbeWcoenBridge.setRemoteBridge(BNB, _interop(BNB, address(bnbWcoenBridge)));
        bnbWcoenBridge.setRemoteBridge(OUTBE, _interop(OUTBE, address(outbeWcoenBridge)));
    }

    function _interop(uint256 chainId, address addr) internal pure returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(chainId, addr);
    }
}
