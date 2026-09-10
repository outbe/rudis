// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";
import {LayerZeroGatewayAdapter} from "src/adapters/LayerZeroGatewayAdapter.sol";
import {EndpointV2Mock} from "./mocks/MockLayerZeroEndpoint.sol";
import {ERC7786RecipientMock} from "@openzeppelin/contracts/mocks/crosschain/ERC7786RecipientMock.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "src/interfaces/IERC7786.sol";
import {GasLimitAttribute} from "src/libs/GasLimitAttribute.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @dev Accepts any inbound delivery so adapter-direct sends complete and we can inspect the recorded options.
contract PermissiveRecipient is IERC7786Recipient {
    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        return IERC7786Recipient.receiveMessage.selector;
    }
}

/// @dev Full-stack test: facade (ERC7786Bridge) -> LayerZeroGatewayAdapter -> mock endpoint, both sides on
/// `block.chainid` but distinguished by LayerZero eid (the intent E2E simulation pattern).
contract LayerZeroGatewayAdapterTest is Test {
    address internal owner = makeAddr("owner");
    address internal app = makeAddr("app");

    uint32 internal aEid = 1;
    uint32 internal bEid = 2;

    EndpointV2Mock internal endpointA;
    EndpointV2Mock internal endpointB;
    LayerZeroGatewayAdapter internal adapterA;
    LayerZeroGatewayAdapter internal adapterB;
    ERC7786Bridge internal facadeA;
    ERC7786Bridge internal facadeB;
    ERC7786RecipientMock internal recipient;

    function setUp() public {
        endpointA = new EndpointV2Mock(aEid);
        endpointB = new EndpointV2Mock(bEid);

        adapterA = new LayerZeroGatewayAdapter(address(endpointA), owner);
        adapterB = new LayerZeroGatewayAdapter(address(endpointB), owner);

        facadeA = new ERC7786Bridge(owner, address(adapterA));
        facadeB = new ERC7786Bridge(owner, address(adapterB));

        recipient = new ERC7786RecipientMock(address(facadeB));

        endpointA.setOApp(address(adapterA));
        endpointB.setOApp(address(adapterB));
        endpointA.setRemoteEndpoint(bEid, endpointB);
        endpointB.setRemoteEndpoint(aEid, endpointA);

        vm.startPrank(owner);
        // Both logical chains share block.chainid here; each adapter binds it to the peer's eid.
        adapterA.setPeerWithChain(bEid, _b32(address(adapterB)), block.chainid);
        adapterB.setPeerWithChain(aEid, _b32(address(adapterA)), block.chainid);
        facadeA.registerRemoteBridge(_interop(address(facadeB)));
        facadeB.registerRemoteBridge(_interop(address(facadeA)));
        vm.stopPrank();
    }

    // --------------------------------------------------- helpers ---------------------------------------------------

    function _interop(address a) internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, a);
    }

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _noAttrs() internal pure returns (bytes[] memory) {
        return new bytes[](0);
    }

    // ----------------------------------------------------- tests ---------------------------------------------------

    function test_E2E_SendThroughLZAdapter() public {
        bytes memory payload = abi.encode("settle", uint256(7));

        vm.recordLogs();
        uint256 fee = 100;
        vm.deal(app, fee);
        vm.prank(app);
        facadeA.sendMessage{value: fee}(_interop(address(recipient)), payload, _noAttrs());

        // The recipient on side B must have received the original sender (app) and the unwrapped payload.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("MessageReceived(address,bytes32,bytes,bytes,uint256)");
        bool seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(recipient) || logs[i].topics[0] != topic) continue;
            (,, bytes memory gotSender, bytes memory gotPayload,) =
                abi.decode(logs[i].data, (address, bytes32, bytes, bytes, uint256));
            assertEq(gotSender, _interop(app), "original sender carried across LayerZero");
            assertEq(gotPayload, payload, "payload delivered unwrapped");
            seen = true;
        }
        assertTrue(seen, "recipient should have received the message");
    }

    function test_RevertWhen_SendUnknownChain() public {
        // chainId 999 has no eid equivalence registered on adapterA.
        bytes memory recipientUnknown = InteroperableAddress.formatEvmV1(999, address(0xBEEF));
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(LayerZeroGatewayAdapter.UnknownDestinationChain.selector, uint256(999)));
        adapterA.sendMessage(recipientUnknown, "x", _noAttrs());
    }

    function test_RevertWhen_UnsupportedAttribute() public {
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = hex"12345678";
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(IERC7786GatewaySource.UnsupportedAttribute.selector, bytes4(0x12345678)));
        adapterA.sendMessage(_interop(address(facadeB)), "x", attrs);
    }

    function test_Quote_DelegatesToEndpoint() public view {
        uint256 fee = adapterA.quote(_interop(address(facadeB)), abi.encode("x"));
        assertEq(fee, 100, "adapter quote delegates to the LayerZero endpoint");
    }

    function test_Quote_ThroughFacade() public view {
        // App asks the facade; facade wraps and delegates to the active gateway (the LZ adapter) -> endpoint.
        uint256 fee = facadeA.quote(_interop(address(recipient)), abi.encode("settle"));
        assertEq(fee, 100, "facade quote routes through the active LZ adapter");
    }

    // ------------------------------------------------ gas attribute ------------------------------------------------

    function _gasAttrs(uint256 gasLimit) internal pure returns (bytes[] memory attrs) {
        attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(gasLimit);
    }

    function test_SupportsExecutionGasLimitAttribute() public view {
        assertTrue(adapterA.supportsAttribute(GasLimitAttribute.SELECTOR), "executionGasLimit supported");
        assertFalse(adapterA.supportsAttribute(bytes4(0x12345678)), "other attribute unsupported");
    }

    function test_ExecutionGasLimit_FlowsIntoOptions() public {
        PermissiveRecipient r = new PermissiveRecipient();
        bytes memory recipientAddr = _interop(address(r));
        vm.deal(app, 1000);

        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _noAttrs());
        bytes32 defaultOpts = keccak256(endpointA.lastOptions());

        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _gasAttrs(999_999));
        assertTrue(keccak256(endpointA.lastOptions()) != defaultOpts, "executionGasLimit must change the LZ options");

        // A gas value equal to the adapter default produces the same options as the no-attribute path.
        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _gasAttrs(adapterA.defaultGasLimit()));
        assertEq(keccak256(endpointA.lastOptions()), defaultOpts, "gas equal to default yields default options");
    }

    function test_Quote_WithGasAttribute() public view {
        uint256 fee = adapterA.quote(_interop(address(facadeB)), abi.encode("x"), _gasAttrs(500_000));
        assertEq(fee, 100, "quote-with-attributes delegates to the endpoint");
    }

    function test_RevertWhen_QuoteUnsupportedAttribute() public {
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = hex"12345678";
        vm.expectRevert(abi.encodeWithSelector(IERC7786GatewaySource.UnsupportedAttribute.selector, bytes4(0x12345678)));
        adapterA.quote(_interop(address(facadeB)), "x", attrs);
    }

    function test_RevertWhen_GasLimitExceedsUint128() public {
        uint256 tooBig = uint256(type(uint128).max) + 1;
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(SafeCast.SafeCastOverflowedUintDowncast.selector, uint8(128), tooBig));
        adapterA.sendMessage(_interop(address(facadeB)), "x", _gasAttrs(tooBig));
    }
}
