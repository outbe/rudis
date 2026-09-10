// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Routes} from "./routes/Routes.sol";

/// @dev Deploys every route in `script/routes/Routes.sol` on the connected chain. Which side of each route is
///      canonical is derived from `OUTBE_CHAIN_ID`, so the same command runs on every chain.
contract DeployRoutes is Routes {
    function run() public virtual {
        string memory salt = vm.envString("CONTRACT_SALT");
        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");

        vm.startBroadcast(_pk());
        deployRoutes(factory, salt);
        vm.stopBroadcast();
    }
}
