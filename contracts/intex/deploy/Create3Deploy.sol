// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";

/// @title Create3Deploy
/// @author Outbe
/// @notice Deploy UUPS proxies through a CREATE3 factory with deterministic, init-code-independent
///         addresses and idempotent skip-if-deployed. Shared by the deploy scripts and their tests.
library Create3Deploy {
    /// @notice Derive a per-contract CREATE3 salt from a stable prefix and a version tag.
    /// @param prefix Contract identifier, e.g. "IntexAuction".
    /// @param version Salt version; bump to move every deployment to fresh addresses.
    function salt(string memory prefix, string memory version) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("outbe-intex:", prefix, ":", version));
    }

    /// @notice Predict the proxy address for `(factory, deployer, prefix, version)`.
    function predictProxy(Create3Factory factory, address deployer, string memory prefix, string memory version)
        internal
        view
        returns (address)
    {
        return factory.predict(deployer, salt(prefix, version));
    }

    /// @notice Deploy `impl` behind a UUPS ERC1967 proxy through the factory, idempotently.
    /// @dev `deployer` must be the account that sends the `factory.deploy` call (it namespaces the
    ///      CREATE3 salt). Returns the existing proxy unchanged if already deployed.
    function deployProxy(
        Create3Factory factory,
        address deployer,
        string memory prefix,
        string memory version,
        address impl,
        bytes memory initData
    ) internal returns (address proxy) {
        bytes32 s = salt(prefix, version);
        address predicted = factory.predict(deployer, s);
        if (predicted.code.length != 0) {
            return predicted;
        }
        bytes memory proxyInitCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = factory.deploy(s, proxyInitCode);
        require(proxy == predicted, "Create3Deploy: address mismatch");
    }
}
