// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {console2} from "forge-std/console2.sol";

import {DeployRoutes} from "./1_DeployRoutes.s.sol";
import {ConfigureRemotes} from "./2_ConfigureRemotes.s.sol";

/// @dev Full token-route deploy on one chain, in one command:
/// The CREATE3 factory is not deployed here: it is built and deployed once from contracts/shared,
/// and passed in as `CREATE3_FACTORY_ADDRESS`.
///   2. Every route in `script/routes/Routes.sol`
///   3. Remote wiring for each `REMOTE_CHAIN_IDS`
///
/// Every step self-checks against on-chain state, so a re-run on a finished chain sends no transactions. That is
/// deliberately per-step rather than one top-level short-circuit: a partial state (token deployed, Safe has not yet
/// executed `setTokenBridge`) must still be completed on the next run.
///
/// Addresses come from CREATE3 and depend only on (factory, salt, deployer) - so the same command on every chain
/// produces the same addresses, and step 3 is safe before the other chains exist.
///
/// Required env: `DEPLOYER_PK`, `CONTRACT_SALT`, `BRIDGE_ADDRESS`, `OUTBE_CHAIN_ID`, `EXTERNAL_CHAIN_ID`.
/// Optional env: `OWNER_ADDRESS`, `ALLOW_EOA_OWNER`, `REMOTE_CHAIN_IDS`,
///   `INITIAL_MINT_AMOUNT`, `INITIAL_MINT_RECIPIENT`.
contract DeployAll is DeployRoutes, ConfigureRemotes {
    function run() public override(DeployRoutes, ConfigureRemotes) {
        string memory salt = vm.envString("CONTRACT_SALT");

        console2.log("Salt:", salt);
        console2.log(_isOutbe() ? "Role: Outbe" : "Role: external chain");

        vm.startBroadcast(_pk());

        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        console2.log("Create3Factory:", factory);

        console2.log("[1/2] Routes...");
        deployRoutes(factory, salt);

        console2.log("[2/2] Configure remotes...");
        configureRemotes(factory, salt);

        vm.stopBroadcast();

        console2.log("=== DeployAll complete (identical on every chain) ===");
        console2.log("CREATE3_FACTORY_ADDRESS=", factory);
    }
}
