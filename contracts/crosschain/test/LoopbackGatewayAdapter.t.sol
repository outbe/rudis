// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";
import {LoopbackGatewayAdapter} from "src/adapters/LoopbackGatewayAdapter.sol";
import {ERC7786RecipientMock} from "@openzeppelin/contracts/mocks/crosschain/ERC7786RecipientMock.sol";
import {IERC7786Recipient} from "src/interfaces/IERC7786.sol";
import {GasLimitAttribute} from "src/libs/GasLimitAttribute.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/// @dev Recipient that reverts until unlocked, to exercise the park/retry path.
contract FlakyRecipientMock is IERC7786Recipient {
    address public immutable BRIDGE;
    bool public unlocked;
    uint256 public received;

    constructor(address bridge_) {
        BRIDGE = bridge_;
    }

    function unlock() external {
        unlocked = true;
    }

    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        require(msg.sender == BRIDGE, "not bridge");
        require(unlocked, "locked");
        received++;
        return IERC7786Recipient.receiveMessage.selector;
    }
}

/// @dev Recipient that burns all forwarded gas, to check the executionGasLimit bound.
contract GasBurnerRecipientMock is IERC7786Recipient {
    function receiveMessage(bytes32, bytes calldata, bytes calldata) external payable returns (bytes4) {
        uint256 waste;
        while (true) {
            unchecked {
                waste++;
            }
        }
    }
}

contract LoopbackGatewayAdapterTest is Test {
    ERC7786Bridge internal bridge;
    LoopbackGatewayAdapter internal loopback;

    address internal owner = makeAddr("owner");
    address internal app = makeAddr("app");
    address internal defaultGw = makeAddr("defaultGateway");

    function setUp() public {
        bridge = new ERC7786Bridge(owner, defaultGw);
        loopback = new LoopbackGatewayAdapter(address(bridge), owner);

        vm.startPrank(owner);
        bridge.registerRemoteBridge(_interop(address(bridge)));
        bridge.setGateway(block.chainid, address(loopback));
        vm.stopPrank();
    }

    // --------------------------------------------------- helpers ---------------------------------------------------

    function _interop(address a) internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, a);
    }

    function _noAttrs() internal pure returns (bytes[] memory) {
        return new bytes[](0);
    }

    // ============================================== same-tx delivery ===============================================

    function test_SendMessage_DeliversInSameTx() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes memory payload = abi.encode("hello", uint256(42));

        vm.recordLogs();
        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), payload, _noAttrs());

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
        assertTrue(seen, "recipient executed in the same transaction");
        assertEq(loopback.nextParkedIdx(), 0, "nothing parked on the happy path");
    }

    function test_Quote_IsZero() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(500_000);

        assertEq(bridge.quote(_interop(address(recipient)), "x"), 0, "local delivery is free");
        assertEq(bridge.quote(_interop(address(recipient)), "x", attrs), 0, "local delivery is free with attributes");
    }

    // ================================================ send guards ==================================================

    function test_RevertWhen_NotHubSends() public {
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(LoopbackGatewayAdapter.OnlyHub.selector, app));
        loopback.sendMessage(_interop(app), "x", _noAttrs());
    }

    function test_RevertWhen_ValueSent() public {
        vm.deal(address(bridge), 1);
        vm.prank(address(bridge));
        vm.expectRevert(LoopbackGatewayAdapter.NonZeroValue.selector);
        loopback.sendMessage{value: 1}(_interop(app), "x", _noAttrs());
    }

    function test_RevertWhen_NotLocalChain() public {
        vm.prank(address(bridge));
        vm.expectRevert(abi.encodeWithSelector(LoopbackGatewayAdapter.NotLocalChain.selector, 999));
        loopback.sendMessage(InteroperableAddress.formatEvmV1(999, app), "x", _noAttrs());
    }

    function test_RevertWhen_UnderGassedDeliveryFails() public {
        GasBurnerRecipientMock recipient = new GasBurnerRecipientMock();
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(100_000_000);

        // The delivery fails without having received the full limit: revert, never a false park.
        vm.prank(app);
        vm.expectRevert(abi.encodeWithSelector(LoopbackGatewayAdapter.InsufficientForwardGas.selector, 100_000_000));
        bridge.sendMessage{gas: 5_000_000}(_interop(address(recipient)), abi.encode("inner"), attrs);
    }

    function test_SendMessage_SucceedsWhenRecipientNeedsLessThanLimit() public {
        ERC7786RecipientMock recipient = new ERC7786RecipientMock(address(bridge));
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(100_000_000);

        vm.prank(app);
        bridge.sendMessage{gas: 5_000_000}(_interop(address(recipient)), abi.encode("inner"), attrs);

        assertEq(loopback.nextParkedIdx(), 0, "delivery that fits the available gas succeeds");
    }

    // ================================================ park / retry =================================================

    function test_SendMessage_ParksOnRecipientRevert() public {
        FlakyRecipientMock recipient = new FlakyRecipientMock(address(bridge));

        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), _noAttrs());

        assertEq(loopback.nextParkedIdx(), 1, "failed delivery parked, send succeeded");
        (address target, bool done,,) = loopback.parked(0);
        assertEq(target, address(bridge), "delivery targets the hub");
        assertFalse(done, "parked delivery pending");
        assertEq(recipient.received(), 0, "recipient not executed");
    }

    function test_RetryDelivery_SucceedsAfterUnlock() public {
        FlakyRecipientMock recipient = new FlakyRecipientMock(address(bridge));
        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), _noAttrs());

        recipient.unlock();
        loopback.retryDelivery(0);

        assertEq(recipient.received(), 1, "recipient executed exactly once");
        (, bool done,,) = loopback.parked(0);
        assertTrue(done, "parked delivery marked done");
    }

    function test_RetryDelivery_RevertsWhileStillFailing() public {
        FlakyRecipientMock recipient = new FlakyRecipientMock(address(bridge));
        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), _noAttrs());

        vm.expectRevert("locked");
        loopback.retryDelivery(0);

        (, bool done,,) = loopback.parked(0);
        assertFalse(done, "delivery stays parked and retryable");
    }

    function test_RetryDelivery_RevertsAfterGatewayRotation() public {
        FlakyRecipientMock recipient = new FlakyRecipientMock(address(bridge));
        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), _noAttrs());

        vm.prank(owner);
        bridge.setGateway(block.chainid, makeAddr("newLoopback"));

        recipient.unlock();
        vm.expectRevert(
            abi.encodeWithSelector(ERC7786Bridge.ERC7786BridgeUnauthorizedGateway.selector, address(loopback))
        );
        loopback.retryDelivery(0);
        (, bool done,,) = loopback.parked(0);
        assertFalse(done, "entry stays parked after rotation");
    }

    function test_RevertWhen_RetryUnknownOrDone() public {
        vm.expectRevert(abi.encodeWithSelector(LoopbackGatewayAdapter.NoParkedDelivery.selector, 5));
        loopback.retryDelivery(5);

        FlakyRecipientMock recipient = new FlakyRecipientMock(address(bridge));
        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), _noAttrs());
        recipient.unlock();
        loopback.retryDelivery(0);

        vm.expectRevert(abi.encodeWithSelector(LoopbackGatewayAdapter.AlreadyDelivered.selector, 0));
        loopback.retryDelivery(0);
        assertEq(recipient.received(), 1, "no double execution through retry");
    }

    function test_GasAttribute_BoundsDelivery() public {
        GasBurnerRecipientMock recipient = new GasBurnerRecipientMock();
        bytes[] memory attrs = new bytes[](1);
        attrs[0] = GasLimitAttribute.encode(150_000);

        vm.prank(app);
        bridge.sendMessage(_interop(address(recipient)), abi.encode("inner"), attrs);

        assertEq(loopback.nextParkedIdx(), 1, "gas-bounded delivery ran out and parked; send succeeded");
    }
}
