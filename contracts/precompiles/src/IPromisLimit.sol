// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IPromisLimit {
    event CertifiedCarryOverCredited(
        bytes32 indexed activationCallId,
        uint32 indexed sourceWorldwideDay,
        uint256 beforeValue,
        uint256 creditedUnusedLysis,
        uint256 afterValue,
        bytes32 stateEventDigest
    );

    function totalUnallocated() external view returns (uint256);
}
