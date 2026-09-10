// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title RadicleRegistry V1
/// @notice Permissionless, append-only registry of public Heartwood repositories.
/// @dev maxRepositories() == type(uint32).max denotes an unlimited configured capacity.
interface IRadicleRegistry {
    event RepositoryRegistered(bytes20 indexed repoId, address indexed registrant, uint32 index, uint64 generation);

    function registerRepository(bytes20 repoId) external;
    function repositoryCount() external view returns (uint32);
    function repositoryAt(uint32 index) external view returns (bytes20);
    function repositoryRegistrant(bytes20 repoId) external view returns (address);
    function registryGeneration() external view returns (uint64);
    function maxRepositories() external view returns (uint32);
}
