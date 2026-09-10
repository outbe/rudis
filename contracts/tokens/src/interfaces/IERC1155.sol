// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IERC1155
/// @notice Canonical ERC-1155 multi-token surface for this repository.
/// @dev Declared standalone rather than imported from OpenZeppelin because the
///      Rust precompiles bind this file directly through `sol!("<path>")`, and
///      that macro discards `import` directives. `IIntexNFT1155` inherits its
///      ERC-1155 members instead of redeclaring them, so callers that need
///      `balanceOf`/`safeTransferFrom` on an Intex series bind this interface.
interface IERC1155 {
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );

    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    event URI(string value, uint256 indexed id);

    function balanceOf(address account, uint256 id) external view returns (uint256);

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory);

    function setApprovalForAll(address operator, bool approved) external;

    function isApprovedForAll(address account, address operator) external view returns (bool);

    function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external;

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external;
}
