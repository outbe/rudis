// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title ICca - Credis Card Agent interface.
interface ICca {
    enum State {
        Unknown,
        Active,
        Suspended,
        Deregistered
    }

    function getCcaState(address cca) external view returns (State);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
