// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Create3Factory} from "@shared/Create3Factory.sol";
import {ERC7786Bridge} from "src/ERC7786Bridge.sol";

/// @dev Switches the bridge's active gateway, i.e. the cross-chain protocol (LayerZero <-> Hyperlane), via
///      `bridge.setGateway`. The target adapter must already be deployed (1_DeployAdapters) and its CREATE3 address is
///      derived from the salt. Applications are unaffected - they keep talking to the same bridge.
///
/// Run on EVERY chain consistently. Messages already in flight through the previous adapter are dropped on arrival
/// (rejected by the bridge) and must be re-sent from the source through the new gateway.
///
/// Required env (DEPLOYER_PK must be the bridge owner):
///   DEPLOYER_PK, CONTRACT_SALT, CREATE3_FACTORY_ADDRESS, ACTIVE_GATEWAY ("lz" | "hyperlane").
contract SwitchGateway is Script {
    function run() public {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        string memory salt = vm.envString("CONTRACT_SALT");
        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");
        string memory active = vm.envString("ACTIVE_GATEWAY");
        address deployer = vm.addr(deployerPk);

        address bridgeAddr = _compute(factory, salt, deployer, "ERC7786Bridge");
        string memory label =
            keccak256(bytes(active)) == keccak256("hyperlane") ? "HyperlaneGatewayAdapter" : "LayerZeroGatewayAdapter";
        address adapter = _compute(factory, salt, deployer, label);

        vm.startBroadcast(deployerPk);
        ERC7786Bridge(bridgeAddr).setGateway(adapter);
        vm.stopBroadcast();

        console2.log("active gateway switched to:", label, adapter);
    }

    function _compute(address factory, string memory salt, address deployer, string memory label)
        internal
        view
        returns (address)
    {
        return Create3Factory(factory).predict(deployer, keccak256(abi.encodePacked(label, salt)));
    }
}
