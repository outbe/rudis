// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/// @dev Loopback ERC-7786 bridge mock. Each instance represents one chain and delivers through its remote peer.
contract MockERC7786Bridge is IERC7786GatewaySource {
    using InteroperableAddress for bytes;

    uint256 public immutable localChainId;
    uint256 public feeQuote;
    mapping(uint256 chainId => MockERC7786Bridge) public remoteBridges;

    error NoRemoteBridge(uint256 chainId);
    error BadMagicValue();

    constructor(uint256 localChainId_) {
        localChainId = localChainId_;
    }

    function setRemoteBridge(uint256 chainId, MockERC7786Bridge bridge) external {
        remoteBridges[chainId] = bridge;
    }

    function setFeeQuote(uint256 fee) external {
        feeQuote = fee;
    }

    function supportsAttribute(bytes4) external pure returns (bool) {
        return false;
    }

    function quote(bytes calldata, bytes calldata) external view returns (uint256) {
        return feeQuote;
    }

    function quote(bytes calldata, bytes calldata, bytes[] calldata) external view returns (uint256) {
        return feeQuote;
    }

    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata)
        external
        payable
        returns (bytes32)
    {
        (uint256 dstChainId, address target) = recipient.parseEvmV1Calldata();
        MockERC7786Bridge dst = remoteBridges[dstChainId];
        require(address(dst) != address(0), NoRemoteBridge(dstChainId));

        dst.deliver(localChainId, msg.sender, target, payload);

        emit MessageSent(
            bytes32(0),
            InteroperableAddress.formatEvmV1(localChainId, msg.sender),
            recipient,
            payload,
            msg.value,
            new bytes[](0)
        );
        return bytes32(0);
    }

    function deliver(uint256 srcChainId, address srcBridge, address target, bytes calldata payload) external {
        bytes memory sender = InteroperableAddress.formatEvmV1(srcChainId, srcBridge);
        bytes4 magic = IERC7786Recipient(target).receiveMessage(bytes32(0), sender, payload);
        require(magic == IERC7786Recipient.receiveMessage.selector, BadMagicValue());
    }
}
