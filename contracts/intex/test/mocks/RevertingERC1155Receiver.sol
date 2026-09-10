// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// @title RevertingERC1155Receiver
/// @notice ERC-1155 receiver whose acceptance hook reverts while `reject` is set; used to exercise
///         per-recipient issuance-mint isolation and the parked-mint flush path.
contract RevertingERC1155Receiver is IERC1155Receiver {
    bool public reject = true;

    function setReject(bool v) external {
        reject = v;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external view returns (bytes4) {
        if (reject) revert("reject-1155");
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        view
        returns (bytes4)
    {
        if (reject) revert("reject-1155");
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}
