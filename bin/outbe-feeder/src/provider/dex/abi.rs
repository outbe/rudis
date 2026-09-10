//! Upstream pool ABI subsets. See the feeder README for authoritative sources.
use alloy_sol_types::sol;

sol! {
    interface Token {
        function decimals() external view returns (uint8);
    }
    interface Pair {
        function token0() external view returns (address);
        function token1() external view returns (address);
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 timestamp);
        event Swap(address indexed sender, uint256 amount0In, uint256 amount1In,
            uint256 amount0Out, uint256 amount1Out, address indexed to);
    }
    interface UniV3 {
        function slot0() external view returns (uint160 sqrtPriceX96, int24 tick,
            uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext,
            uint8 feeProtocol, bool unlocked);
        event Swap(address indexed sender, address indexed recipient, int256 amount0,
            int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick);
    }
    interface PancakeV3 {
        function slot0() external view returns (uint160 sqrtPriceX96, int24 tick,
            uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext,
            uint32 feeProtocol, bool unlocked);
        event Swap(address indexed sender, address indexed recipient, int256 amount0,
            int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick,
            uint128 protocolFeesToken0, uint128 protocolFeesToken1);
    }
    struct UniPoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    struct InfinityPoolKey {
        address currency0;
        address currency1;
        address hooks;
        address poolManager;
        uint24 fee;
        bytes32 parameters;
    }
    interface StateView {
        function poolManager() external view returns (address);
        function getSlot0(bytes32 poolId) external view returns
            (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee);
    }
    interface UniV4 {
        event Swap(bytes32 indexed id, address indexed sender, int128 amount0, int128 amount1,
            uint160 sqrtPriceX96, uint128 liquidity, int24 tick, uint24 fee);
    }
    interface InfinityCl {
        function getSlot0(bytes32 poolId) external view returns
            (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee);
        event Swap(bytes32 indexed id, address indexed sender, int128 amount0, int128 amount1,
            uint160 sqrtPriceX96, uint128 liquidity, int24 tick, uint24 fee, uint16 protocolFee);
    }
    interface InfinityBin {
        function getSlot0(bytes32 poolId) external view returns
            (uint24 activeId, uint24 protocolFee, uint24 lpFee);
        event Swap(bytes32 indexed id, address indexed sender, int128 amount0, int128 amount1,
            uint24 activeId, uint24 fee, uint16 protocolFee);
    }
}
