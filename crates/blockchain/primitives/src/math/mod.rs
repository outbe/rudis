//! Shared deterministic arithmetic and the PancakeSwap Liquidity Book math port.
//!
//! The Outbe-owned [`scaled_math`] and [`reference_price`] modules are kept
//! separate from the verbatim vendor port. The remaining file layout mirrors
//! `pancakeswap/infinity-core@main` so that port stays auditable line-for-line:
//! - [`constants`] - `src/pool-bin/libraries/Constants.sol` + `PriceHelper.sol`.
//! - [`bit_math`] - `src/pool-bin/libraries/math/BitMath.sol`.
//! - [`uint256x256_math`] - `src/pool-bin/libraries/math/Uint256x256Math.sol`.
//! - [`uint128x128_math`] - `src/pool-bin/libraries/math/Uint128x128Math.sol`.
//! - [`price_helper`] - `src/pool-bin/libraries/PriceHelper.sol`.
//! - [`tree_math`] - `src/pool-bin/libraries/math/TreeMath.sol` (decoupled
//!   from any specific contract via the [`tree_math::BinTreeStorage`] trait).

pub mod bit_math;
pub mod constants;
pub mod price_helper;
pub mod reference_price;
pub mod scaled_math;
pub mod tree_math;
pub mod uint128x128_math;
pub mod uint256x256_math;
