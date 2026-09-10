// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";
import {HyperlaneGatewayAdapter} from "src/adapters/HyperlaneGatewayAdapter.sol";
import {MockHyperlaneMailbox} from "./mocks/MockHyperlaneMailbox.sol";
import {ERC7786RecipientMock} from "@openzeppelin/contracts/mocks/crosschain/ERC7786RecipientMock.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "src/interfaces/IERC7786.sol";
import {GasLimitAttribute} from "src/libs/GasLimitAttribute.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @dev Accepts any inbound delivery so adapter-direct sends complete and we can inspect the recorded metadata.
contract PermissiveRecipient is IERC7786Recipient {
    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        return IERC7786Recipient.receiveMessage.selector;
    }
}

/// @dev Full-stack test: facade (ERC7786Bridge) -> HyperlaneGatewayAdapter -> mock mailbox, both sides on
/// `block.chainid` but distinguished by Hyperlane domain.
contract HyperlaneGatewayAdapterTest is Test {
    address internal owner = makeAddr("owner");
    address internal app = makeAddr("app");

    uint32 internal domainA = 1;
    uint32 internal domainB = 2;

    MockHyperlaneMailbox internal mailboxA;
    MockHyperlaneMailbox internal mailboxB;
    HyperlaneGatewayAdapter internal adapterA;
    HyperlaneGatewayAdapter internal adapterB;
    ERC7786Bridge internal facadeA;
    ERC7786Bridge internal facadeB;
    ERC7786RecipientMock internal recipient;

    function setUp() public {
        mailboxA = new MockHyperlaneMailbox(domainA);
        mailboxB = new MockHyperlaneMailbox(domainB);

        adapterA = new HyperlaneGatewayAdapter(address(mailboxA), owner);
        adapterB = new HyperlaneGatewayAdapter(address(mailboxB), owner);

        facadeA = new ERC7786Bridge(owner, address(adapterA));
        facadeB = new ERC7786Bridge(owner, address(adapterB));

        recipient = new ERC7786RecipientMock(address(facadeB));

        mailboxA.setRemoteMailbox(domainB, mailboxB);
        mailboxB.setRemoteMailbox(domainA, mailboxA);

        vm.startPrank(owner);
        // Both logical chains share block.chainid here; each adapter binds it to the peer's Hyperlane domain.
        adapterA.setRouterWithChain(domainB, _b32(address(adapterB)), block.chainid);
        adapterB.setRouterWithChain(domainA, _b32(address(adapterA)), block.chainid);
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

    function test_E2E_SendThroughHyperlaneAdapter() public {
        bytes memory payload = abi.encode("refund", uint256(3));

        vm.recordLogs();
        uint256 fee = 100;
        vm.deal(app, fee);
        vm.prank(app);
        facadeA.sendMessage{value: fee}(_interop(address(recipient)), payload, _noAttrs());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("MessageReceived(address,bytes32,bytes,bytes,uint256)");
        bool seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(recipient) || logs[i].topics[0] != topic) continue;
            (,, bytes memory gotSender, bytes memory gotPayload,) =
                abi.decode(logs[i].data, (address, bytes32, bytes, bytes, uint256));
            assertEq(gotSender, _interop(app), "original sender carried across Hyperlane");
            assertEq(gotPayload, payload, "payload delivered unwrapped");
            seen = true;
        }
        assertTrue(seen, "recipient should have received the message");
    }

    function test_RevertWhen_SendUnknownChain() public {
        bytes memory recipientUnknown = InteroperableAddress.formatEvmV1(999, address(0xBEEF));
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(HyperlaneGatewayAdapter.UnknownDestinationChain.selector, uint256(999)));
        adapterA.sendMessage(recipientUnknown, "x", _noAttrs());
    }

    function test_RevertWhen_UnsupportedAttribute() public {
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = hex"12345678";
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(IERC7786GatewaySource.UnsupportedAttribute.selector, bytes4(0x12345678)));
        adapterA.sendMessage(_interop(address(facadeB)), "x", attrs);
    }

    function test_RevertWhen_HandleFromNonMailbox() public {
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(HyperlaneGatewayAdapter.UnauthorizedCaller.selector, app));
        adapterB.handle(domainA, _b32(address(adapterA)), "");
    }

    function test_RevertWhen_HandleFromUnauthorizedSender() public {
        address wrong = makeAddr("wrong");
        vm.prank(address(mailboxB));
        vm.expectRevert(
            abi.encodeWithSelector(HyperlaneGatewayAdapter.UnauthorizedSender.selector, domainA, _b32(wrong))
        );
        adapterB.handle(domainA, _b32(wrong), "");
    }

    function test_Quote_DelegatesToMailbox() public view {
        uint256 fee = adapterA.quote(_interop(address(facadeB)), abi.encode("x"));
        assertEq(fee, 100, "adapter quote delegates to the Hyperlane mailbox");
    }

    function test_Quote_ThroughFacade() public view {
        uint256 fee = facadeA.quote(_interop(address(recipient)), abi.encode("refund"));
        assertEq(fee, 100, "facade quote routes through the active Hyperlane adapter");
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

    function test_ExecutionGasLimit_FlowsIntoMetadata() public {
        PermissiveRecipient r = new PermissiveRecipient();
        bytes memory recipientAddr = _interop(address(r));
        vm.deal(app, 1000);

        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _noAttrs());
        bytes32 defaultMeta = keccak256(mailboxA.lastMetadata());

        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _gasAttrs(999_999));
        assertTrue(keccak256(mailboxA.lastMetadata()) != defaultMeta, "executionGasLimit must change the hook metadata");

        // A gas value equal to the adapter default produces the same metadata as the no-attribute path.
        // Read the default before the prank so the external getter doesn't consume it (metadata carries msg.sender).
        uint128 dflt = adapterA.defaultGasLimit();
        vm.prank(app);
        adapterA.sendMessage{value: 100}(recipientAddr, "p", _gasAttrs(dflt));
        assertEq(keccak256(mailboxA.lastMetadata()), defaultMeta, "gas equal to default yields default metadata");
    }

    function test_Quote_WithGasAttribute() public view {
        uint256 fee = adapterA.quote(_interop(address(facadeB)), abi.encode("x"), _gasAttrs(500_000));
        assertEq(fee, 100, "quote-with-attributes delegates to the mailbox");
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
