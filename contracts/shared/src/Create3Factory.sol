// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CREATE3} from "./vendor/solady/CREATE3.sol";

/**
 * @title Create3Factory
 * @author Outbe
 * @notice Ownerless CREATE3 factory. A deployed contract's address depends only on
 *         `(this factory, msg.sender, salt)` and not on its init code, so a contract keeps the
 *         same address across init-code iterations, library swaps, and full network wipes.
 * @dev Deploy this factory once per chain through the canonical CREATE2 deployer
 *      (`0x4e59...956C`) with a pinned salt so the factory itself lands at the same address on
 *      every chain. It has no constructor and no owner, so its init code is identical everywhere.
 *      Front-running is prevented by namespacing the CREATE3 salt with `msg.sender`: a caller can
 *      only deploy into addresses derived from its own address.
 */
contract Create3Factory {
    /// @notice A deployment was attempted to an address that already holds code.
    error AlreadyDeployed(address target);

    /// @notice Emitted on every successful deployment.
    /// @param deployer Caller whose address namespaces the salt.
    /// @param salt Caller-supplied salt (pre-namespacing).
    /// @param deployed Address the contract was deployed to.
    event Deployed(address indexed deployer, bytes32 indexed salt, address deployed);

    /// @notice Deploy `initCode` deterministically. The address depends only on `(factory,
    ///         msg.sender, salt)`.
    /// @param salt Caller-chosen salt; namespaced by `msg.sender` internally.
    /// @param initCode Full creation code (e.g. proxy creation code + encoded constructor args).
    /// @return deployed Address of the deployed contract.
    function deploy(bytes32 salt, bytes calldata initCode) external payable returns (address deployed) {
        bytes32 guarded = _guard(msg.sender, salt);
        address predicted = CREATE3.predictDeterministicAddress(guarded);
        if (predicted.code.length != 0) revert AlreadyDeployed(predicted);

        deployed = CREATE3.deployDeterministic(msg.value, initCode, guarded);
        emit Deployed(msg.sender, salt, deployed);
    }

    /// @notice Predict the address `deploy` would produce for `(deployer, salt)`.
    /// @param deployer Address that will call `deploy`.
    /// @param salt Caller-chosen salt (pre-namespacing).
    /// @return The deterministic deployment address.
    function predict(address deployer, bytes32 salt) external view returns (address) {
        return CREATE3.predictDeterministicAddress(_guard(deployer, salt));
    }

    /// @dev Namespace the salt with the deployer so callers cannot occupy each other's addresses.
    function _guard(address deployer, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(deployer, salt));
    }
}
