// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";
import {Create3Deploy} from "./Create3Deploy.sol";

/// @title BaseScript
/// @author Outbe
/// @notice Shared deployment plumbing: a deterministic CREATE3 factory plus salt-versioned,
///         idempotent UUPS proxy deployment through it.
/// @dev The factory is deployed once per chain from contracts/shared (`mise run
///      deploy-create3-factory` there) and passed in as `CREATE3_FACTORY_ADDRESS`; only that
///      project may build it, since its address depends on the bytecode its compiler emits.
///      Proxy addresses then depend only on `(factory, deployer, salt)`.
abstract contract BaseScript is Script {
    /// @notice CREATE3 salt version. Env-overridable via `SALT_VERSION` so a test run can target a
    ///         throwaway address set without disturbing the pinned production set; blank/unset = production.
    function saltVersion() internal view returns (string memory version) {
        version = vm.envOr("SALT_VERSION", string(""));
        if (bytes(version).length == 0) version = "v4.0.0";
    }

    /// @notice The protocol-wide CREATE3 factory, deployed from contracts/shared.
    /// @return factory The factory at `CREATE3_FACTORY_ADDRESS`; reverts if nothing is deployed there.
    function create3Factory() public view returns (Create3Factory factory) {
        address f = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        require(f.code.length != 0, "Create3Factory not deployed - deploy it from contracts/shared first");
        return Create3Factory(f);
    }

    /// @notice Predict a proxy address without deploying.
    function predictProxy(Create3Factory factory, address deployer, string memory prefix)
        public
        view
        returns (address)
    {
        return Create3Deploy.predictProxy(factory, deployer, prefix, saltVersion());
    }

    /// @notice Deploy `impl` behind a UUPS proxy through `factory`, idempotently.
    function deployProxy(
        Create3Factory factory,
        address deployer,
        string memory prefix,
        address impl,
        bytes memory initData
    ) public returns (address) {
        return Create3Deploy.deployProxy(factory, deployer, prefix, saltVersion(), impl, initData);
    }
}
