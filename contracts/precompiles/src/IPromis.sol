// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IPromis {
    event PromisMinted(address indexed account, uint256 amount, uint256 newTotalSupply);
    event PromisBurned(address indexed account, uint256 amount, uint256 remainingSupply);

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    // Confidential balance: returns the account's ciphertext blob, a fixed
    // 56 bytes = version(8, big-endian) || ChaCha20Poly1305 ct (32-byte U256
    // amount + 16-byte tag). The length is constant regardless of the balance,
    // so it never leaks magnitude; a never-written account returns empty bytes.
    // Decrypt off-chain with the account's Promis view key (rudis_deriveKeys).
    function balanceOf(address account) external view returns (bytes memory);

    // Current modify-auth replay counter for `account` - the value a write's
    // authorization (`mac`) must bind and that must be passed as `opNonce`.
    // Public: it is a per-account write counter, not a balance.
    function opNonceOf(address account) external view returns (uint64);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
