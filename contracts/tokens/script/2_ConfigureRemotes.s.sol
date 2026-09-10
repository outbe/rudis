// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {console2} from "forge-std/console2.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {RouteSpec} from "./routes/BaseRoute.sol";
import {ERC7786TokenBridge} from "../src/ERC7786TokenBridge.sol";
import {Route, Routes} from "./routes/Routes.sol";

/// @dev Registers the matching bridge on every remote chain, for every route. Bridges share one CREATE3 address
///      across chains, so the remote address equals the local one - `REMOTE_CHAIN_IDS` lists chain ids only, and the
///      same list can be used unchanged on every chain (the local id is skipped).
///
/// Required env: `DEPLOYER_PK`, `CONTRACT_SALT`, `CREATE3_FACTORY_ADDRESS`, `OUTBE_CHAIN_ID`.
/// Optional env: `REMOTE_CHAIN_IDS` (csv; no-op when unset).
contract ConfigureRemotes is Routes {
    function run() public virtual {
        string memory salt = vm.envString("CONTRACT_SALT");
        address factory = vm.envAddress("CREATE3_FACTORY_ADDRESS");

        vm.startBroadcast(_pk());
        configureRemotes(factory, salt);
        vm.stopBroadcast();
    }

    function configureRemotes(address factory, string memory salt) public {
        uint256[] memory remotes = vm.envOr("REMOTE_CHAIN_IDS", ",", new uint256[](0));
        Route[] memory list = routes();
        for (uint256 i = 0; i < list.length; i++) {
            _wire(factory, salt, list[i].spec, remotes);
        }
    }

    function _wire(address factory, string memory salt, RouteSpec memory spec, uint256[] memory remotes) internal {
        address local = _bridgeAddress(factory, salt, spec);
        _requireCode(local);

        address owner = Ownable(local).owner();
        _requireContractOwnerOnGuardedChain(owner);

        for (uint256 i = 0; i < remotes.length; i++) {
            // One shared REMOTE_CHAIN_IDS is reused on every chain, so the local id shows up here: skip, not fail.
            if (remotes[i] == block.chainid) continue;

            uint32 domain = _toDomain(remotes[i]);
            bytes memory remoteInterop = InteroperableAddress.formatEvmV1(remotes[i], local);
            // Re-running must be free: it is how the Safe flow is verified after the owner signs.
            if (keccak256(ERC7786TokenBridge(local).remoteBridges(domain)) == keccak256(remoteInterop)) continue;

            bytes memory data = abi.encodeCall(ERC7786TokenBridge.setRemoteBridge, (domain, remoteInterop));
            if (!_shouldBroadcastOwnerCall(_deployer(), owner, local, data, "Configure remote bridge")) continue;

            ERC7786TokenBridge(local).setRemoteBridge(domain, remoteInterop);
            console2.log(string.concat("  ", spec.tokenLabel, " wired to chainId:"), remotes[i]);
        }
    }
}
