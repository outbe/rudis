// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IWhitelist, Whitelist} from "../src/Whitelist.sol";
import {V4SwapWhitelistHook, InfinitySwapWhitelistHook} from "../src/SwapWhitelistHook.sol";
import {DeployWhitelistHooks} from "../script/DeployWhitelistHooks.s.sol";

contract DeployWhitelistHooksTest is Test {
    uint160 internal constant ALL_HOOK_MASK = uint160((1 << 14) - 1);
    uint160 internal constant BEFORE_SWAP_FLAG = uint160(1 << 7);

    DeployWhitelistHooks internal deployScript;

    address internal owner = makeAddr("owner");
    address internal router = makeAddr("router");
    address internal v4PoolManager = makeAddr("v4PoolManager");
    address internal infinityPoolManager = makeAddr("infinityPoolManager");

    function setUp() public {
        deployScript = new DeployWhitelistHooks();
    }

    /// @dev The registry is deployed by its own script; the gates only take its address.
    function _registry() internal returns (IWhitelist) {
        address[] memory initial = new address[](1);
        initial[0] = router;
        return new Whitelist(owner, initial);
    }

    /// @dev Deploying the gates separately must still leave them on one registry - that shared
    ///      registry is the whole point of splitting the deploy into two tasks.
    function test_BothHooks_ShareOneRegistry() public {
        IWhitelist whitelist = _registry();

        V4SwapWhitelistHook v4Hook = deployScript.deployV4Hook(v4PoolManager, whitelist);
        InfinitySwapWhitelistHook infinityHook = deployScript.deployInfinityHook(infinityPoolManager, whitelist);

        assertEq(address(v4Hook.registry()), address(whitelist), "v4 hook wired elsewhere");
        assertEq(v4Hook.poolManager(), v4PoolManager, "v4 pool manager");
        assertEq(address(infinityHook.registry()), address(whitelist), "infinity hook wired elsewhere");
        assertEq(infinityHook.poolManager(), infinityPoolManager, "infinity pool manager");
    }

    /// @dev v4 calls exactly the callbacks the address advertises, so the mined address must carry
    ///      beforeSwap and no other flag - anything else means a callback this hook cannot answer.
    function test_DeployV4Hook_AddressAdvertisesBeforeSwapOnly() public {
        V4SwapWhitelistHook hook = deployScript.deployV4Hook(v4PoolManager, _registry());
        assertEq(uint160(address(hook)) & ALL_HOOK_MASK, BEFORE_SWAP_FLAG, "wrong hook flags");
    }
}
