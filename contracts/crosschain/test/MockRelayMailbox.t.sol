// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IMessageRecipient} from "src/interfaces/IHyperlane.sol";
import {MockRelayMailbox} from "./mocks/MockRelayMailbox.sol";

contract RecordingRecipient is IMessageRecipient {
    uint32 public lastOrigin;
    bytes32 public lastSender;
    bytes public lastMessage;
    uint256 public handled;

    function handle(uint32 _origin, bytes32 _sender, bytes calldata _message) external payable {
        lastOrigin = _origin;
        lastSender = _sender;
        lastMessage = _message;
        ++handled;
    }
}

/// The mock exists so a relay can carry a message between two real chains: dispatch
/// must record rather than deliver, and delivery must be a separate, callable step.
contract MockRelayMailboxTest is Test {
    uint32 constant ORIGIN_DOMAIN = 424_242;
    uint32 constant TARGET_DOMAIN = 31_337;

    MockRelayMailbox origin;
    MockRelayMailbox target;
    RecordingRecipient recipient;

    function setUp() public {
        origin = new MockRelayMailbox(ORIGIN_DOMAIN);
        target = new MockRelayMailbox(TARGET_DOMAIN);
        recipient = new RecordingRecipient();
    }

    function test_DispatchRecordsWithoutDelivering() public {
        origin.dispatch(TARGET_DOMAIN, _asBytes32(address(recipient)), hex"c0ffee");

        assertEq(origin.dispatchedCount(), 1, "dispatch is counted");
        assertEq(recipient.handled(), 0, "dispatch must not deliver: the relay carries it");
    }

    function test_DispatchIdsAreUniquePerMessage() public {
        bytes32 first = origin.dispatch(TARGET_DOMAIN, _asBytes32(address(recipient)), hex"c0ffee");
        bytes32 second = origin.dispatch(TARGET_DOMAIN, _asBytes32(address(recipient)), hex"c0ffee");

        assertTrue(first != second, "identical bodies still get their own id");
    }

    function test_DeliverHandsTheMessageToTheRecipient() public {
        bytes memory body = hex"decafbad";
        origin.dispatch(TARGET_DOMAIN, _asBytes32(address(recipient)), body);

        target.deliver(ORIGIN_DOMAIN, _asBytes32(address(this)), _asBytes32(address(recipient)), body);

        assertEq(recipient.handled(), 1, "delivery reaches the recipient");
        assertEq(recipient.lastOrigin(), ORIGIN_DOMAIN, "origin domain travels with it");
        assertEq(recipient.lastMessage(), body, "body arrives unchanged");
    }

    function test_MetadataDispatchKeepsTheLastHookMetadata() public {
        origin.dispatch(TARGET_DOMAIN, _asBytes32(address(recipient)), hex"01", hex"beef");
        assertEq(origin.lastMetadata(), hex"beef", "metadata is inspectable for gas assertions");
    }

    function _asBytes32(address value) private pure returns (bytes32) {
        return bytes32(uint256(uint160(value)));
    }
}
