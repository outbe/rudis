// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IGratis {
    // ERC-20 events (declared for ABI completeness; never emitted because
    // gratis is non-transferable).
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // Gratis runtime events.
    event GratisMinted(address indexed account, uint256 amount, uint256 newTotalSupply);
    event GratisBurned(address indexed account, uint256 amount, uint256 remainingSupply);
    event GratisPledged(address indexed account, uint256 amount, uint256 totalPledged);
    event GratisUnpledged(address indexed account, uint256 amount, uint256 remainingPledged);

    // ERC-20 metadata
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function pledgedTotalSupply() external view returns (uint256);
    // Confidential balance: returns the account's ciphertext blob, a fixed
    // 56 bytes = version(8, big-endian) || ChaCha20Poly1305 ct (32-byte U256
    // amount + 16-byte tag). The length is constant regardless of the balance,
    // so it never leaks magnitude; a never-written account returns empty bytes.
    // Decrypt off-chain with the account's view key.
    function balanceOf(address account) external view returns (bytes memory);

    // ERC-20 transfer surface - gratis is non-transferable.
    // `allowance` returns 0; the others revert.
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    // gratis-specific - confidential pledged amount, returned as the same fixed
    // 56-byte `version || AEAD-ct` blob as balanceOf (empty for a never-pledged
    // account). Decrypt off-chain with the account's view key.
    function pledgedOf(address account) external view returns (bytes memory);

    // Current modify-auth replay counter for `account` - the value a write's
    // authorization (`mac`) must bind and that must be passed as `opNonce`.
    // Public: it is a per-account write counter, not a balance.
    function opNonceOf(address account) external view returns (uint64);

    // ERC-165
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
