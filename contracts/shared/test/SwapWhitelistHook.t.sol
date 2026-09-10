// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IWhitelist, Whitelist, NotWhitelisted} from "../src/Whitelist.sol";
import {
    V4SwapWhitelistHook,
    InfinitySwapWhitelistHook,
    V4PoolKey,
    InfinityPoolKey,
    SwapParams,
    NotPoolManager,
    ZeroRegistry
} from "../src/SwapWhitelistHook.sol";

contract SwapWhitelistHookTest is Test {
    /// @dev Signatures copied from upstream (Uniswap v4-core IHooks, PancakeSwap infinity-core
    ///      ICLHooks). If a local struct mirror ever drifts, these stop matching.
    bytes4 internal constant V4_BEFORE_SWAP =
        bytes4(keccak256("beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"));
    bytes4 internal constant INFINITY_BEFORE_SWAP = bytes4(
        keccak256("beforeSwap(address,(address,address,address,address,uint24,bytes32),(bool,int256,uint160),bytes)")
    );

    Whitelist internal registry;
    V4SwapWhitelistHook internal v4Hook;
    InfinitySwapWhitelistHook internal infinityHook;

    address internal poolManager = makeAddr("poolManager");
    address internal router = makeAddr("router");
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        address[] memory initial = new address[](1);
        initial[0] = router;
        registry = new Whitelist(address(this), initial);
        v4Hook = new V4SwapWhitelistHook(poolManager, registry);
        infinityHook = new InfinitySwapWhitelistHook(poolManager, registry);
    }

    function _v4Key() internal view returns (V4PoolKey memory) {
        return V4PoolKey(address(1), address(2), 3000, 60, address(v4Hook));
    }

    function _infinityKey() internal view returns (InfinityPoolKey memory) {
        return InfinityPoolKey(address(1), address(2), address(infinityHook), poolManager, 3000, bytes32(uint256(64)));
    }

    function _params() internal pure returns (SwapParams memory) {
        return SwapParams(true, -1e18, 0);
    }

    /// @dev The pool manager only accepts its own selector back, so the local struct mirrors must
    ///      hash to the upstream signatures.
    function test_SelectorsMatchUpstream() public pure {
        assertEq(V4SwapWhitelistHook.beforeSwap.selector, V4_BEFORE_SWAP, "v4 selector drift");
        assertEq(InfinitySwapWhitelistHook.beforeSwap.selector, INFINITY_BEFORE_SWAP, "infinity selector drift");
    }

    function test_RegistrationBitmap_BeforeSwapOnly() public view {
        assertEq(infinityHook.getHooksRegistrationBitmap(), uint16(1) << 6, "bitmap != beforeSwap");
    }

    function test_WhitelistedRouter_Passes() public {
        vm.startPrank(poolManager);
        (bytes4 v4Sel,,) = v4Hook.beforeSwap(router, _v4Key(), _params(), "");
        (bytes4 infSel,,) = infinityHook.beforeSwap(router, _infinityKey(), _params(), "");
        vm.stopPrank();
        assertEq(v4Sel, V4_BEFORE_SWAP, "v4 wrong selector returned");
        assertEq(infSel, INFINITY_BEFORE_SWAP, "infinity wrong selector returned");
    }

    function test_Stranger_Reverts() public {
        vm.startPrank(poolManager);
        vm.expectRevert(abi.encodeWithSelector(NotWhitelisted.selector, stranger));
        v4Hook.beforeSwap(stranger, _v4Key(), _params(), "");
        vm.expectRevert(abi.encodeWithSelector(NotWhitelisted.selector, stranger));
        infinityHook.beforeSwap(stranger, _infinityKey(), _params(), "");
        vm.stopPrank();
    }

    function test_RemovedRouter_Reverts() public {
        address[] memory drop = new address[](1);
        drop[0] = router;
        registry.remove(drop);
        vm.prank(poolManager);
        vm.expectRevert(abi.encodeWithSelector(NotWhitelisted.selector, router));
        v4Hook.beforeSwap(router, _v4Key(), _params(), "");
    }

    function test_OnlyPoolManager() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(NotPoolManager.selector, stranger));
        v4Hook.beforeSwap(router, _v4Key(), _params(), "");
    }

    function test_ZeroRegistry_Reverts() public {
        vm.expectRevert(ZeroRegistry.selector);
        new V4SwapWhitelistHook(poolManager, IWhitelist(address(0)));
    }
}
