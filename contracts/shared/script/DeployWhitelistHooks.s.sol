// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {IWhitelist} from "../src/Whitelist.sol";
import {V4SwapWhitelistHook, InfinitySwapWhitelistHook} from "../src/SwapWhitelistHook.sol";

/// @dev Deploys a swap gate on top of an existing {Whitelist}. One entry point per protocol:
///      `mise run deploy-whitelist-hook-infinity` / `-v4`.
///
/// The registry has its own deploy task (`deploy-whitelist`); run that first and point both gates at
/// the same WHITELIST_ADDRESS, so one add()/remove() governs every gated pool.
///
/// Required env vars:
///   DEPLOYER_PK              - deployer private key
///   WHITELIST_ADDRESS        - the registry both gates read
///   V4_POOL_MANAGER          - Uniswap v4 PoolManager                  (deployV4 only)
///   INFINITY_CL_POOL_MANAGER - PancakeSwap Infinity CLPoolManager      (deployInfinity only)
contract DeployWhitelistHooks is Script {
    /// @dev Low 14 bits of a v4 hook address encode its callbacks; the manager calls exactly those.
    uint160 internal constant V4_ALL_HOOK_MASK = uint160((1 << 14) - 1);
    uint160 internal constant V4_BEFORE_SWAP_FLAG = uint160(1 << 7);

    /// @dev Salts scanned while mining a v4 address; ~1 in 16384 qualifies.
    uint256 internal constant V4_SALT_SCAN = 1_000_000;

    /// @notice Set by the entry points; lets tests and follow-up scripts read what was deployed.
    V4SwapWhitelistHook public v4Hook;
    InfinitySwapWhitelistHook public infinityHook;

    /// @notice Deploys the Uniswap v4 gate.
    function deployV4() public {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address poolManager = vm.envAddress("V4_POOL_MANAGER");

        vm.startBroadcast(deployerPrivateKey);
        v4Hook = deployV4Hook(poolManager, registry());
        vm.stopBroadcast();

        console2.log("V4_SWAP_WHITELIST_HOOK=", address(v4Hook));
    }

    /// @notice Deploys the PancakeSwap Infinity CL gate.
    function deployInfinity() public {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PK");
        address poolManager = vm.envAddress("INFINITY_CL_POOL_MANAGER");

        vm.startBroadcast(deployerPrivateKey);
        infinityHook = deployInfinityHook(poolManager, registry());
        vm.stopBroadcast();

        console2.log("INFINITY_SWAP_WHITELIST_HOOK=", address(infinityHook));
        console2.log("  poolKey.parameters bitmap:", infinityHook.getHooksRegistrationBitmap());
    }

    /// @notice The registry both gates read; deployed separately by `deploy-whitelist`.
    function registry() public view returns (IWhitelist) {
        address whitelist = vm.envAddress("WHITELIST_ADDRESS");
        require(whitelist.code.length != 0, "WHITELIST_ADDRESS has no code on this chain");
        return IWhitelist(whitelist);
    }

    /// @dev v4 reads a hook's callbacks off its address, so this one has to be mined onto an address
    ///      carrying beforeSwap and nothing else. Deployed through the canonical CREATE2 proxy so the
    ///      mined address holds both under `forge script` and in tests.
    function deployV4Hook(address poolManager, IWhitelist whitelist) public returns (V4SwapWhitelistHook hook) {
        require(CREATE2_FACTORY.code.length != 0, "Arachnid CREATE2 deployer not present on this chain");

        bytes memory initCode = v4InitCode(poolManager, address(whitelist));
        (bytes32 salt, address predicted) = mineV4Salt(keccak256(initCode));

        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(salt, initCode));
        require(ok && predicted.code.length != 0, "V4SwapWhitelistHook deploy failed");
        hook = V4SwapWhitelistHook(predicted);
    }

    function deployInfinityHook(address poolManager, IWhitelist whitelist) public returns (InfinitySwapWhitelistHook) {
        return new InfinitySwapWhitelistHook(poolManager, whitelist);
    }

    function v4InitCode(address poolManager, address whitelist) public pure returns (bytes memory) {
        return abi.encodePacked(type(V4SwapWhitelistHook).creationCode, abi.encode(poolManager, IWhitelist(whitelist)));
    }

    /// @notice First salt whose CREATE2 address carries the beforeSwap flag and nothing else - v4
    ///         calls every callback the address advertises, and this hook implements exactly one.
    function mineV4Salt(bytes32 initCodeHash) public view returns (bytes32 salt, address hook) {
        for (uint256 i = 0; i < V4_SALT_SCAN; i++) {
            salt = bytes32(i);
            hook = vm.computeCreate2Address(salt, initCodeHash, CREATE2_FACTORY);
            if (uint160(hook) & V4_ALL_HOOK_MASK == V4_BEFORE_SWAP_FLAG) return (salt, hook);
        }
        revert("no v4 hook salt found");
    }
}
