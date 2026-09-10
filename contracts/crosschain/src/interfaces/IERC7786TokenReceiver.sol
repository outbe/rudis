// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Receiver hook invoked after an ERC-7786 token bridge credits destination tokens.
interface IERC7786TokenReceiver {
    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external returns (bytes4);
}
