// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IMessageRecipient} from "src/interfaces/IHyperlane.sol";

/// @dev A Hyperlane Mailbox mock that spans two real chains. NOT for production.
///
/// `MockHyperlaneMailbox` holds its peer as a live contract reference and delivers
/// inside `dispatch`, which only works when both ends share one EVM. Across two
/// chains that reference cannot exist, so this one records the message and emits
/// it; an off-chain relay watches the event and calls `deliver` on the other side.
contract MockRelayMailbox {
    uint32 public immutable localDomain;

    /// @notice Dispatched messages so far, so a relay that reconnects can resume.
    uint256 public dispatchedCount;

    /// @dev What the relay carries. `messageId` is what `dispatch` returned.
    event Dispatched(
        bytes32 indexed messageId, uint32 indexed destinationDomain, bytes32 sender, bytes32 recipient, bytes message
    );

    /// @dev Emitted on delivery so a scenario can assert arrival rather than guess.
    event Delivered(uint32 indexed origin, bytes32 indexed recipient, bytes32 sender);

    /// @notice Hook metadata of the most recent metadata-carrying dispatch.
    bytes public lastMetadata;

    constructor(uint32 _localDomain) {
        localDomain = _localDomain;
    }

    function quoteDispatch(uint32, bytes32, bytes calldata) external pure returns (uint256) {
        return 100;
    }

    function quoteDispatch(uint32, bytes32, bytes calldata, bytes calldata) external pure returns (uint256) {
        return 100;
    }

    function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        external
        payable
        returns (bytes32 messageId)
    {
        return _record(destinationDomain, recipientAddress, messageBody);
    }

    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata
    ) external payable returns (bytes32 messageId) {
        lastMetadata = metadata;
        return _record(destinationDomain, recipientAddress, messageBody);
    }

    /// @notice Delivery hook the relay calls on the destination chain; invokes the
    ///         recipient's `handle` as the local mailbox, as a real one would.
    function deliver(uint32 _origin, bytes32 _sender, bytes32 _recipient, bytes calldata _message) external {
        address target = address(uint160(uint256(_recipient)));
        IMessageRecipient(target).handle(_origin, _sender, _message);
        emit Delivered(_origin, _recipient, _sender);
    }

    function _record(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        private
        returns (bytes32 messageId)
    {
        bytes32 sender = bytes32(uint256(uint160(msg.sender)));
        messageId =
            keccak256(abi.encode(localDomain, destinationDomain, recipientAddress, messageBody, dispatchedCount));
        unchecked {
            ++dispatchedCount;
        }
        emit Dispatched(messageId, destinationDomain, sender, recipientAddress, messageBody);
    }
}
