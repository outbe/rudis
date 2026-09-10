// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";
import {ERC7786GatewayMock} from "@openzeppelin/contracts/mocks/crosschain/ERC7786GatewayMock.sol";
import {ERC7786RecipientMock} from "@openzeppelin/contracts/mocks/crosschain/ERC7786RecipientMock.sol";
import {IERC7786GatewaySource, IERC7786Recipient, IGatewayQuote} from "src/interfaces/IERC7786.sol";
import {GasLimitAttribute} from "src/libs/GasLimitAttribute.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @dev Concrete instance of the abstract OZ loopback gateway, plus a fixed quote for the passthrough test.
contract GatewayMock is ERC7786GatewayMock, IGatewayQuote {
    function quote(bytes calldata, bytes calldata) external pure returns (uint256) {
        return 4242;
    }

    function quote(bytes calldata, bytes calldata, bytes[] calldata) external pure returns (uint256) {
        return 4242;
    }
}

/// @dev Gateway that interprets the executionGasLimit attribute (and rejects others), mirroring a real adapter,
/// so the bridge's attribute forwarding / delegation can be checked in isolation.
contract AttrAwareGatewayMock is IERC7786GatewaySource, IGatewayQuote {
    bool public sawGasAttribute;

    function supportsAttribute(bytes4 selector) external pure returns (bool) {
        return selector == GasLimitAttribute.SELECTOR;
    }

    function sendMessage(bytes calldata, bytes calldata, bytes[] calldata attributes)
        external
        payable
        returns (bytes32)
    {
        (bool found,) = GasLimitAttribute.find(attributes); // reverts UnsupportedAttribute for any other attribute
        if (found) sawGasAttribute = true;
        return bytes32(0);
    }

    function quote(bytes calldata, bytes calldata) external pure returns (uint256) {
        return 100;
    }

    function quote(bytes calldata, bytes calldata, bytes[] calldata attributes) external pure returns (uint256) {
        (bool found,) = GasLimitAttribute.find(attributes);
        return found ? 777 : 100;
    }
}

/// @dev Minimal gateway that counts sends and quotes a fixed fee, for per-chain routing assertions.
contract RecordingGatewayMock is IERC7786GatewaySource, IGatewayQuote {
    uint256 public sends;

    function supportsAttribute(bytes4) external pure returns (bool) {
        return false;
    }

    function sendMessage(bytes calldata, bytes calldata, bytes[] calldata) external payable returns (bytes32) {
        sends++;
        return bytes32(0);
    }

    function quote(bytes calldata, bytes calldata) external pure returns (uint256) {
        return 7;
    }

    function quote(bytes calldata, bytes calldata, bytes[] calldata) external pure returns (uint256) {
        return 7;
    }
}

contract ERC7786BridgeTest is Test {
    ERC7786Bridge internal bridge;

    address internal owner = makeAddr("owner");
    address internal app = makeAddr("app");
    address internal gw = makeAddr("gateway");
    address internal sourceBridge = makeAddr("sourceBridge");

    function setUp() public {
        bridge = new ERC7786Bridge(owner, gw);
        vm.prank(owner);
        bridge.registerRemoteBridge(_interop(sourceBridge));
    }

    // --------------------------------------------------- helpers ---------------------------------------------------

    function _interop(address a) internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, a);
    }

    function _noAttrs() internal pure returns (bytes[] memory) {
        return new bytes[](0);
    }

    function _wrap(uint256 nonce, address originalSender, address finalRecipient, bytes memory innerPayload)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(nonce, _interop(originalSender), _interop(finalRecipient), innerPayload);
    }

    /// @dev True if `recipient` emitted ERC7786RecipientMock.MessageReceived in the recorded logs.
    function _recipientExecuted(Vm.Log[] memory logs, address recipient) internal pure returns (bool) {
        bytes32 topic = keccak256("MessageReceived(address,bytes32,bytes,bytes,uint256)");
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == recipient && logs[i].topics[0] == topic) return true;
        }
        return false;
    }

    // ============================================ sendMessage (outbound) ============================================

    function test_SendMessage_ForwardsThroughGatewayAndRoundTrips() public {
        GatewayMock gateway = new GatewayMock();
        ERC7786Bridge bridgeA = new ERC7786Bridge(owner, address(gateway));
        ERC7786Bridge bridgeB = new ERC7786Bridge(owner, address(gateway));
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridgeB));

        vm.startPrank(owner);
        bridgeA.registerRemoteBridge(_interop(address(bridgeB)));
        bridgeB.registerRemoteBridge(_interop(address(bridgeA)));
        vm.stopPrank();

        bytes memory payload = abi.encode("hello", uint256(42));

        vm.recordLogs();
        vm.prank(app);
        bridgeA.sendMessage(_interop(address(recipient)), payload, _noAttrs());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("MessageReceived(address,bytes32,bytes,bytes,uint256)");
        bool seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(recipient) || logs[i].topics[0] != topic) continue;
            (,, bytes memory gotSender, bytes memory gotPayload,) =
                abi.decode(logs[i].data, (address, bytes32, bytes, bytes, uint256));
            assertEq(gotSender, _interop(app), "original sender preserved");
            assertEq(gotPayload, payload, "payload delivered unwrapped");
            seen = true;
        }
        assertTrue(seen, "recipient should have received the message");
    }

    function test_SendMessage_ForwardsNativeValue() public {
        GatewayMock gateway = new GatewayMock();
        ERC7786Bridge bridgeA = new ERC7786Bridge(owner, address(gateway));
        ERC7786Bridge bridgeB = new ERC7786Bridge(owner, address(gateway));
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridgeB));

        vm.startPrank(owner);
        bridgeA.registerRemoteBridge(_interop(address(bridgeB)));
        bridgeB.registerRemoteBridge(_interop(address(bridgeA)));
        vm.stopPrank();

        uint256 fee = 0.1 ether;
        vm.deal(app, fee);
        vm.prank(app);
        bridgeA.sendMessage{value: fee}(_interop(address(recipient)), abi.encode("hello"), _noAttrs());

        assertEq(address(bridgeB).balance, fee, "native fee forwarded through the bridge");
    }

    function test_RevertWhen_SendWithoutGateway() public {
        ERC7786Bridge noGateway = new ERC7786Bridge(owner, address(0));
        vm.prank(app);
        vm.expectRevert(ERC7786Bridge.ERC7786BridgeGatewayNotSet.selector);
        noGateway.sendMessage(_interop(address(0xBEEF)), "x", _noAttrs());
    }

    function test_RevertWhen_SendToUnregisteredRemote() public {
        ERC7786Bridge fresh = new ERC7786Bridge(owner, gw);
        vm.prank(app);
        vm.expectRevert();
        fresh.sendMessage(_interop(address(0xBEEF)), "x", _noAttrs());
    }

    function test_RevertWhen_SendWithUnsupportedAttribute() public {
        AttrAwareGatewayMock gateway = new AttrAwareGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gateway));
        vm.prank(owner);
        b.registerRemoteBridge(_interop(sourceBridge));

        bytes[] memory attrs = new bytes[](1);
        attrs[0] = hex"12345678";
        // The bridge forwards the attribute; the gateway rejects the unknown one.
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(IERC7786GatewaySource.UnsupportedAttribute.selector, bytes4(0x12345678)));
        b.sendMessage(_interop(sourceBridge), "x", attrs);
    }

    function test_SendMessage_ForwardsGasAttributeToGateway() public {
        AttrAwareGatewayMock gateway = new AttrAwareGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gateway));
        vm.prank(owner);
        b.registerRemoteBridge(_interop(sourceBridge));

        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(500_000);
        vm.prank(app);
        b.sendMessage(_interop(sourceBridge), "x", attrs);
        assertTrue(gateway.sawGasAttribute(), "bridge forwards executionGasLimit to the gateway");
    }

    // ============================================== quote (IGatewayQuote) ==========================================

    function test_Quote_DelegatesToGateway() public {
        GatewayMock gateway = new GatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gateway));
        vm.prank(owner);
        b.registerRemoteBridge(_interop(sourceBridge));

        assertEq(b.quote(_interop(sourceBridge), "payload"), 4242, "bridge delegates quote to the active gateway");
    }

    function test_Quote_WithAttributes_DelegatesToGateway() public {
        AttrAwareGatewayMock gateway = new AttrAwareGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gateway));
        vm.prank(owner);
        b.registerRemoteBridge(_interop(sourceBridge));

        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(500_000);
        assertEq(b.quote(_interop(sourceBridge), "x", attrs), 777, "3-arg quote forwards attributes to the gateway");
        assertEq(b.quote(_interop(sourceBridge), "x", _noAttrs()), 100, "3-arg quote without attributes uses default");
    }

    function test_SupportsAttribute_DelegatesToGateway() public {
        AttrAwareGatewayMock gateway = new AttrAwareGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gateway));
        assertTrue(b.supportsAttribute(GasLimitAttribute.SELECTOR), "delegates true for the gas attribute");
        assertFalse(b.supportsAttribute(bytes4(0x12345678)), "delegates false for other attributes");
    }

    function test_RevertWhen_QuoteWithoutGateway() public {
        ERC7786Bridge noGateway = new ERC7786Bridge(owner, address(0));
        vm.expectRevert(ERC7786Bridge.ERC7786BridgeGatewayNotSet.selector);
        noGateway.quote(_interop(sourceBridge), "payload");
    }

    // =========================================== receiveMessage (inbound) ===========================================

    function test_ReceiveMessage_ExecutesOnRecipient() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));

        vm.prank(gw);
        bytes4 magic = bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);
        assertEq(magic, IERC7786Recipient.receiveMessage.selector, "bridge returns 7786 magic value");
    }

    function test_RevertWhen_ReceiveFromNonGateway() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));
        address intruder = makeAddr("intruder");

        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(ERC7786Bridge.ERC7786BridgeUnauthorizedGateway.selector, intruder));
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);
    }

    function test_RevertWhen_ReceiveFromUnregisteredRemote() public {
        address wrongRemote = makeAddr("wrongRemote");
        bytes memory payload = _wrap(1, app, address(0xCAFE), abi.encode("inner"));
        vm.prank(gw);
        vm.expectRevert(ERC7786Bridge.ERC7786BridgeInvalidCrosschainSender.selector);
        bridge.receiveMessage(bytes32(0), _interop(wrongRemote), payload);
    }

    function test_RevertWhen_ReceiveWithMalformedSender() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));
        vm.prank(gw);
        vm.expectRevert();
        bridge.receiveMessage(bytes32(0), hex"deadbeef", payload);
    }

    function test_RevertWhen_ReceiveAlreadyExecuted() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));

        vm.prank(gw);
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);

        // Re-delivering an already executed message reverts (deduplication).
        vm.prank(gw);
        vm.expectRevert(ERC7786Bridge.ERC7786BridgeAlreadyExecuted.selector);
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);
    }

    // ============================================== gateway switch =================================================

    function test_SetGateway_SwitchesGateway() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        address gw2 = makeAddr("gateway2");

        // Old gateway delivers and executes.
        bytes memory p1 = _wrap(1, app, address(recipient), abi.encode("a"));
        vm.prank(gw);
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), p1);

        vm.prank(owner);
        bridge.setGateway(gw2);
        assertEq(bridge.getGateway(), gw2, "active gateway updated");

        // Old gateway is no longer trusted: its delivery reverts.
        bytes memory p2 = _wrap(2, app, address(recipient), abi.encode("b"));
        vm.prank(gw);
        vm.expectRevert(abi.encodeWithSelector(ERC7786Bridge.ERC7786BridgeUnauthorizedGateway.selector, gw));
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), p2);

        // New gateway delivers and executes.
        vm.recordLogs();
        vm.prank(gw2);
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), p2);
        assertTrue(_recipientExecuted(vm.getRecordedLogs(), address(recipient)), "new gateway executes");
    }

    // ============================================= per-chain gateways ==============================================

    function test_SetGateway_PerChainOverrideAndClear() public {
        address gwA = makeAddr("gatewayA");
        vm.prank(owner);
        bridge.setGateway(uint256(1111), gwA);
        assertEq(bridge.getGateway(1111), gwA, "override returned for its chain");
        assertEq(bridge.getGateway(2222), gw, "other chains fall back to the default");
        assertEq(bridge.getGateway(), gw, "default gateway unchanged");

        vm.prank(owner);
        bridge.setGateway(uint256(1111), address(0));
        assertEq(bridge.getGateway(1111), gw, "cleared override falls back to the default");
    }

    function test_RevertWhen_NonOwnerSetsChainGateway() public {
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, app));
        bridge.setGateway(uint256(1111), gw);
    }

    function test_SendMessage_RoutesPerDestinationGateway() public {
        RecordingGatewayMock gwA = new RecordingGatewayMock();
        RecordingGatewayMock gwDefault = new RecordingGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gwDefault));

        vm.startPrank(owner);
        b.registerRemoteBridge(InteroperableAddress.formatEvmV1(1111, address(b)));
        b.registerRemoteBridge(InteroperableAddress.formatEvmV1(2222, address(b)));
        b.setGateway(uint256(1111), address(gwA));
        vm.stopPrank();

        vm.startPrank(app);
        b.sendMessage(InteroperableAddress.formatEvmV1(1111, address(0xAAAA)), "x", _noAttrs());
        b.sendMessage(InteroperableAddress.formatEvmV1(2222, address(0xBBBB)), "x", _noAttrs());
        vm.stopPrank();

        assertEq(gwA.sends(), 1, "send to the overridden chain uses its gateway");
        assertEq(gwDefault.sends(), 1, "send to other chains uses the default gateway");
    }

    function test_Quote_UsesPerChainGateway() public {
        GatewayMock gwDefault = new GatewayMock();
        RecordingGatewayMock gwA = new RecordingGatewayMock();
        ERC7786Bridge b = new ERC7786Bridge(owner, address(gwDefault));

        vm.startPrank(owner);
        b.registerRemoteBridge(InteroperableAddress.formatEvmV1(1111, address(b)));
        b.registerRemoteBridge(InteroperableAddress.formatEvmV1(2222, address(b)));
        b.setGateway(uint256(1111), address(gwA));
        vm.stopPrank();

        assertEq(b.quote(InteroperableAddress.formatEvmV1(1111, address(0xAAAA)), "x"), 7, "override chain quote");
        assertEq(b.quote(InteroperableAddress.formatEvmV1(2222, address(0xBBBB)), "x"), 4242, "default chain quote");
    }

    function test_ReceiveMessage_TrustsPerSourceChainGateway() public {
        address gwA = makeAddr("gatewayA");
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));

        vm.startPrank(owner);
        bridge.registerRemoteBridge(InteroperableAddress.formatEvmV1(1111, sourceBridge));
        bridge.setGateway(uint256(1111), gwA);
        vm.stopPrank();

        bytes memory remoteSender = InteroperableAddress.formatEvmV1(1111, sourceBridge);
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));

        // The default gateway is no longer trusted for the overridden source chain.
        vm.prank(gw);
        vm.expectRevert(abi.encodeWithSelector(ERC7786Bridge.ERC7786BridgeUnauthorizedGateway.selector, gw));
        bridge.receiveMessage(bytes32(0), remoteSender, payload);

        vm.prank(gwA);
        bytes4 magic = bridge.receiveMessage(bytes32(0), remoteSender, payload);
        assertEq(magic, IERC7786Recipient.receiveMessage.selector, "source chain's gateway delivers");
    }

    function test_RevertWhen_ChainGatewayDeliversForOtherChain() public {
        address gwA = makeAddr("gatewayA");
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));

        vm.startPrank(owner);
        bridge.registerRemoteBridge(InteroperableAddress.formatEvmV1(1111, sourceBridge));
        bridge.setGateway(uint256(1111), gwA);
        vm.stopPrank();

        // The local-chain remote registered in setUp is served by the default gateway; the chain-1111 gateway
        // must not be able to deliver on its behalf.
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));
        vm.prank(gwA);
        vm.expectRevert(abi.encodeWithSelector(ERC7786Bridge.ERC7786BridgeUnauthorizedGateway.selector, gwA));
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);
    }

    // ================================================ access / pause ================================================

    function test_RevertWhen_NonOwnerSetsGateway() public {
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, app));
        bridge.setGateway(gw);
    }

    function test_RevertWhen_SendWhilePaused() public {
        vm.prank(owner);
        bridge.pause();
        vm.prank(app);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.sendMessage(_interop(sourceBridge), "x", _noAttrs());
    }

    function test_RevertWhen_ReceiveWhilePaused() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = _wrap(1, app, address(recipient), abi.encode("inner"));
        vm.prank(owner);
        bridge.pause();
        vm.prank(gw);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.receiveMessage(bytes32(0), _interop(sourceBridge), payload);
    }
}
