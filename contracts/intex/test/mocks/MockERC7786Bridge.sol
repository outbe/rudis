// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {IGatewayQuote} from "@contracts/shared/interfaces/IGatewayQuote.sol";

/// @title MockERC7786Bridge
/// @notice In-process loopback stand-in for the `crosschain` hub's ERC7786Bridge, for intex protocol tests.
/// @dev {sendMessage} records the message and (by default) delivers it to the recipient's {receiveMessage} in the
///      same call, standing in for the transport. Delivery can be turned off ({setAutoDeliver}) to drive inbound
///      timing/redelivery manually, replayed ({deliverLast}), or spoofed from an arbitrary source ({deliverAs}) to
///      exercise the recipient's peer authentication. {quote} returns a settable fee.
contract MockERC7786Bridge is IERC7786GatewaySource, IGatewayQuote {
    using InteroperableAddress for bytes;

    /// @dev ERC-7786 attribute selector for the per-message destination gas limit.
    bytes4 private constant _GAS_LIMIT_SELECTOR = bytes4(keccak256("executionGasLimit(uint256)"));

    /// @dev Fee returned by {quote} (and thus required as msg.value on {sendMessage} when relay-funding is off).
    uint256 public fee;
    /// @dev When true, {sendMessage} delivers immediately; when false, delivery is manual via {deliverLast}.
    bool public autoDeliver = true;
    /// @dev When true, auto-delivery forwards exactly the executionGasLimit attribute as the call gas, so a
    ///      handler that needs more than its IntexGas budget out-of-gases instead of borrowing test gas.
    bool public enforceGasAttribute;

    // --- last-send capture (for assertions) ---
    bytes public lastSender;
    bytes public lastRecipient;
    bytes public lastPayload;
    bytes[] private _lastAttributes;
    uint256 public lastValue;
    bytes32 public lastSendId;

    uint256 private _nonce;

    error DeliveryReturnedInvalidValue(bytes4 got);

    function setFee(uint256 fee_) external {
        fee = fee_;
    }

    function setAutoDeliver(bool on) external {
        autoDeliver = on;
    }

    function setEnforceGasAttribute(bool on) external {
        enforceGasAttribute = on;
    }

    function getLastAttributes() external view returns (bytes[] memory) {
        return _lastAttributes;
    }

    /// @inheritdoc IERC7786GatewaySource
    function supportsAttribute(bytes4) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IGatewayQuote
    function quote(bytes calldata, bytes calldata) external view returns (uint256) {
        return fee;
    }

    /// @inheritdoc IGatewayQuote
    function quote(bytes calldata, bytes calldata, bytes[] calldata) external view returns (uint256) {
        return fee;
    }

    /// @inheritdoc IERC7786GatewaySource
    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        external
        payable
        returns (bytes32 sendId)
    {
        bytes memory sender = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        lastSender = sender;
        lastRecipient = recipient;
        lastPayload = payload;
        _lastAttributes = attributes;
        lastValue = msg.value;
        sendId = keccak256(abi.encode(address(this), ++_nonce));
        lastSendId = sendId;

        if (autoDeliver) {
            (, address target) = recipient.parseEvmV1Calldata();
            bytes32 receiveId = keccak256(abi.encode(sender, payload));
            uint256 gasLimit = enforceGasAttribute ? _gasAttribute(attributes) : 0;
            bytes4 result = gasLimit == 0
                ? IERC7786Recipient(target).receiveMessage(receiveId, sender, payload)
                : IERC7786Recipient(target).receiveMessage{gas: gasLimit}(receiveId, sender, payload);
            if (result != IERC7786Recipient.receiveMessage.selector) revert DeliveryReturnedInvalidValue(result);
        }
    }

    /// @dev The executionGasLimit attribute value, or 0 when absent.
    function _gasAttribute(bytes[] calldata attributes) private pure returns (uint256) {
        for (uint256 i = 0; i < attributes.length; i++) {
            if (bytes4(attributes[i]) == _GAS_LIMIT_SELECTOR) {
                return abi.decode(attributes[i][4:], (uint256));
            }
        }
        return 0;
    }

    /// @dev Re-delivers the most recent message (as the same source), simulating a transport redelivery.
    function deliverLast() external {
        _deliver(lastSender, lastRecipient, lastPayload);
    }

    /// @dev Delivers `payload` to `recipient` as if it came from `sender` - for peer-auth negative tests.
    function deliverAs(bytes calldata sender, bytes calldata recipient, bytes calldata payload) external {
        _deliver(sender, recipient, payload);
    }

    function _deliver(bytes memory sender, bytes memory recipient, bytes memory payload) internal {
        (, address target) = recipient.parseEvmV1();
        // Mirror the hub's receiveId (binds source + payload) so recipients that key per-message work off it (e.g. the
        // NFT bridge clients' failed-mint parking) see a stable, unique id; a `deliverLast` replay reuses the same id.
        bytes32 receiveId = keccak256(abi.encode(sender, payload));
        bytes4 result = IERC7786Recipient(target).receiveMessage(receiveId, sender, payload);
        if (result != IERC7786Recipient.receiveMessage.selector) revert DeliveryReturnedInvalidValue(result);
    }
}
