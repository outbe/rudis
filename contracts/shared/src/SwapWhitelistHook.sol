// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IWhitelist, requireWhitelisted} from "./Whitelist.sol";

/// @notice Thrown when anyone other than the pool manager calls a hook callback.
error NotPoolManager(address caller);

/// @notice Thrown when a hook is wired to the zero registry, which would leave the gate open.
error ZeroRegistry();

// ---------------------------------------------------------------------------
// Minimal mirrors of the upstream calldata layouts.
//
// A hook is only ever reached through the pool manager's `call`, so the ABI shape is all that
// matters: identical field types produce identical selectors, and the hooks below return the very
// selector the manager compares against. Declaring the structs here keeps this package free of the
// v4-core / infinity-core dependency trees.
//
// ponytail: layouts copied from upstream (Uniswap v4-core types/PoolKey.sol + PoolOperation.sol,
// PancakeSwap infinity-core types/PoolKey.sol + ICLPoolManager.sol). If either protocol ever
// reshapes PoolKey or SwapParams, the selector changes and pool initialization reverts loudly -
// swap these for real imports if that ever happens.
// ---------------------------------------------------------------------------

/// @dev Uniswap v4 `PoolKey`.
struct V4PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

/// @dev PancakeSwap Infinity `PoolKey`.
struct InfinityPoolKey {
    address currency0;
    address currency1;
    address hooks;
    address poolManager;
    uint24 fee;
    bytes32 parameters;
}

/// @dev Swap parameters; identical in both protocols.
struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

/// @notice Shared plumbing: remembers the pool manager allowed to call back and the registry that
///         decides who may swap.
/// @dev The address the hook sees is whoever called the pool manager inside the lock - the router,
///      not the end user. Whitelist the router you control and let it check its own callers, or
///      restrict routing to a router that forwards a verified swapper.
abstract contract BaseSwapWhitelistHook {
    /// @notice The only address allowed to invoke the hook callbacks.
    address public immutable poolManager;

    /// @notice Registry consulted on every swap.
    IWhitelist public immutable registry;

    constructor(address _poolManager, IWhitelist _registry) {
        if (address(_registry) == address(0)) revert ZeroRegistry();
        poolManager = _poolManager;
        registry = _registry;
    }

    modifier onlyPoolManager() {
        if (msg.sender != poolManager) revert NotPoolManager(msg.sender);
        _;
    }
}

/// @title V4SwapWhitelistHook
/// @notice Uniswap v4 hook that rejects swaps from callers outside the shared {Whitelist}.
/// @dev The pool manager derives permissions from the hook address, so this must be deployed to an
///      address with `BEFORE_SWAP_FLAG` (1 << 7) set - mine the CREATE2 salt (forge's `HookMiner`).
contract V4SwapWhitelistHook is BaseSwapWhitelistHook {
    constructor(address _poolManager, IWhitelist _registry) BaseSwapWhitelistHook(_poolManager, _registry) {}

    function beforeSwap(address sender, V4PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        view
        onlyPoolManager
        returns (bytes4, int256, uint24)
    {
        requireWhitelisted(registry, sender);
        // (selector, zero BeforeSwapDelta, no lp fee override)
        return (this.beforeSwap.selector, int256(0), uint24(0));
    }
}

/// @title InfinitySwapWhitelistHook
/// @notice PancakeSwap Infinity CL hook that rejects swaps from callers outside the shared {Whitelist}.
/// @dev Permissions come from the registration bitmap rather than the address, so any deployment
///      address works. `poolKey.parameters` must carry the same bitmap in its low 16 bits.
contract InfinitySwapWhitelistHook is BaseSwapWhitelistHook {
    /// @dev Bit 6 is `HOOKS_BEFORE_SWAP_OFFSET`; every other callback stays off.
    uint16 private constant _BEFORE_SWAP_BITMAP = uint16(1) << 6;

    constructor(address _poolManager, IWhitelist _registry) BaseSwapWhitelistHook(_poolManager, _registry) {}

    /// @notice Callbacks this hook subscribes to, checked against `poolKey.parameters` on initialize.
    function getHooksRegistrationBitmap() external pure returns (uint16) {
        return _BEFORE_SWAP_BITMAP;
    }

    function beforeSwap(address sender, InfinityPoolKey calldata, SwapParams calldata, bytes calldata)
        external
        view
        onlyPoolManager
        returns (bytes4, int256, uint24)
    {
        requireWhitelisted(registry, sender);
        return (this.beforeSwap.selector, int256(0), uint24(0));
    }
}
