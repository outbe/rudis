// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IL2Registry {
    event L2NetworkRegistered(uint64 indexed chainId, address indexed l1Address, bytes publicKey);
    event L2NetworkZkSet(uint64 indexed chainId, bool enabled);
    event L2NetworkRemoved(uint64 indexed chainId);

    /// Removes the caller's registered L2 network. The caller must equal the
    /// `l1Address` stored for `chainId`.
    function removeNetwork(uint64 chainId) external;

    /// Returns the registration for `chainId`. Reverts when not registered.
    function getNetwork(uint64 chainId)
        external
        view
        returns (address l1Address, bytes memory publicKey, bool zkEnabled);

    /// Returns the chain id registered for `l1Address`, or 0 when none.
    function chainIdByL1Address(address l1Address) external view returns (uint64);
}
