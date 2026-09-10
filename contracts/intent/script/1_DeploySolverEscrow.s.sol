// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";
import {Scope} from "the-compact/src/types/Scope.sol";

import {SolverAllocator} from "../src/allocators/SolverAllocator.sol";
import {SolverEscrow} from "../src/SolverEscrow.sol";

/// @dev Deployment script for solver collateral system.
///
/// Required env vars:
///   DEPLOYER_PK           - deployer private key
///   COMPACT_ADDRESS       - The Compact address
///   COLLATERAL_BPS        - collateral requirement in basis points (e.g. 1000 = 10%)
contract DeploySolverEscrow is Script {
    function run() public virtual {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address compact = vm.envAddress("COMPACT_ADDRESS");
        uint256 collateralBps = vm.envOr("COLLATERAL_BPS", uint256(1000));

        vm.startBroadcast(deployerPrivateKey);
        address escrow = deployEscrow(compact, collateralBps);
        vm.stopBroadcast();

        console2.log("SolverEscrow deployed at:", escrow);
        console2.log("NOTE: Call escrow.setAuthorizedCaller(router) after deploying the router.");
    }

    function deployEscrow(address compact, uint256 collateralBps) public returns (address) {
        SolverAllocator allocator = new SolverAllocator(compact);
        bytes12 lockTag = allocator.buildLockTag(Scope.ChainSpecific, ResetPeriod.ThirtyDays);
        SolverEscrow escrow = new SolverEscrow(compact, lockTag, collateralBps);
        allocator.setArbiter(address(escrow));
        return address(escrow);
    }
}
