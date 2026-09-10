// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IMessageRecipient} from "src/interfaces/IHyperlane.sol";

/// @dev Minimal self-contained Hyperlane Mailbox mock for local two-chain simulation. NOT for production.
/// On `dispatch` it routes the message to the remote mailbox, which delivers it to the recipient's `handle`.
contract MockHyperlaneMailbox {
    uint32 public immutable localDomain;

    mapping(uint32 => MockHyperlaneMailbox) public remoteMailboxes;

    /// @dev Records the hook metadata of the most recent metadata-carrying dispatch, for inspecting per-message gas.
    bytes public lastMetadata;

    error RemoteMailboxNotSet(uint32 domain);

    constructor(uint32 _localDomain) {
        localDomain = _localDomain;
    }

    function setRemoteMailbox(uint32 _domain, MockHyperlaneMailbox _mailbox) external {
        remoteMailboxes[_domain] = _mailbox;
    }

    function quoteDispatch(
        uint32,
        /*destinationDomain*/
        bytes32,
        /*recipient*/
        bytes calldata /*body*/
    )
        external
        pure
        returns (uint256)
    {
        // Fixed fee of 100 wei for testing.
        return 100;
    }

    function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody)
        external
        payable
        returns (bytes32 messageId)
    {
        MockHyperlaneMailbox dst = remoteMailboxes[destinationDomain];
        if (address(dst) == address(0)) revert RemoteMailboxNotSet(destinationDomain);

        bytes32 sender = bytes32(uint256(uint160(msg.sender)));
        dst.deliver(localDomain, sender, recipientAddress, messageBody);

        return keccak256(abi.encode(localDomain, destinationDomain, recipientAddress, messageBody));
    }

    function quoteDispatch(
        uint32,
        /*destinationDomain*/
        bytes32,
        /*recipient*/
        bytes calldata,
        /*body*/
        bytes calldata /*metadata*/
    )
        external
        pure
        returns (uint256)
    {
        // Fixed fee of 100 wei for testing.
        return 100;
    }

    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata
    ) external payable returns (bytes32 messageId) {
        lastMetadata = metadata;

        MockHyperlaneMailbox dst = remoteMailboxes[destinationDomain];
        if (address(dst) == address(0)) revert RemoteMailboxNotSet(destinationDomain);

        bytes32 sender = bytes32(uint256(uint160(msg.sender)));
        dst.deliver(localDomain, sender, recipientAddress, messageBody);

        return keccak256(abi.encode(localDomain, destinationDomain, recipientAddress, messageBody));
    }

    /// @notice Delivery hook invoked by the source mailbox; calls the recipient's `handle` as the local mailbox.
    function deliver(uint32 _origin, bytes32 _sender, bytes32 _recipient, bytes calldata _message) external {
        address target = address(uint160(uint256(_recipient)));
        IMessageRecipient(target).handle(_origin, _sender, _message);
    }
}
