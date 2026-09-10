// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/// @dev Loopback ERC-7786 bridge mock standing in for the `crosschain` hub's `ERC7786Bridge`. Each instance
/// represents one chain (`localChainId`); `sendMessage` routes by destination chainId to that chain's bridge, which
/// delivers to the recipient encoded in the message as that bridge (so the Router's `msg.sender == bridge` check passes).
contract MockERC7786Bridge is IERC7786GatewaySource {
    using InteroperableAddress for bytes;

    uint256 public immutable localChainId;
    uint256 public feeQuote;
    mapping(uint256 chainId => MockERC7786Bridge) public remoteBridges;

    error NoRemoteBridge(uint256 chainId);
    error BadMagicValue();

    constructor(uint256 _localChainId) {
        localChainId = _localChainId;
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

    function quote(
        bytes calldata,
        /*recipient*/
        bytes calldata /*payload*/
    )
        external
        view
        returns (uint256)
    {
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

    /// @notice Delivery hook invoked by the source bridge; calls the recipient as this (destination) bridge.
    function deliver(uint256 srcChainId, address srcRouter, address target, bytes calldata payload) external {
        bytes memory sender = InteroperableAddress.formatEvmV1(srcChainId, srcRouter);
        bytes4 magic = IERC7786Recipient(target).receiveMessage(bytes32(0), sender, payload);
        require(magic == IERC7786Recipient.receiveMessage.selector, BadMagicValue());
    }
}
