// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/**
 * @title IERC1155Bridgeable
 * @author Outbe
 * @notice Interface for ERC1155 tokens with bridge-controlled mint/burn.
 * @dev Implement this interface on any ERC1155 to make it compatible with IntexNFT1155Bridge.
 */
interface IERC1155Bridgeable {
    /**
     * @notice Burns tokens from an address. Called by adapter on source chain.
     * @dev `to` is the address the paired adapter will mint to; it travels so the token can hold
     *      lifecycle rules that constrain who may end up holding the balance.
     * @param from Address to burn from
     * @param to Address the destination chain will mint to
     * @param tokenId Token ID to burn
     * @param amount Amount to burn
     */
    function crosschainBurn(address from, address to, uint256 tokenId, uint256 amount) external;

    /**
     * @notice Mints tokens to an address. Called by adapter on destination chain.
     * @param to Address to mint to
     * @param tokenId Token ID to mint
     * @param amount Amount to mint
     */
    function crosschainMint(address to, uint256 tokenId, uint256 amount) external;
}

