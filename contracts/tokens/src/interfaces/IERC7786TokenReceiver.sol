// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IERC7786TokenReceiver
/// @notice Receiver hook for composed cross-chain token transfers (ERC-1363-style, at the bridge level).
interface IERC7786TokenReceiver {
    /// @notice Called by the token bridge after tokens are credited to the receiver.
    /// @param sourceDomain Source EVM chainId the transfer originated from.
    /// @param from ERC-7930 interoperable address of the sender on the source chain.
    /// @param amount Amount credited to the receiver.
    /// @param extraData Sender-supplied payload, opaque to the bridge.
    /// @return `IERC7786TokenReceiver.onCrosschainTokensReceived.selector` to accept the transfer.
    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external returns (bytes4);
}
