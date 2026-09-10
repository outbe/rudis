//! Pair and asset identity types.
//!
//! These live in `outbe-primitives` because `outbe-cli` and `outbe-feeder` need
//! the same asset encoding to build oracle calldata, and neither depends on this
//! crate. Re-exported here so oracle code can keep saying `crate::types`.

pub use outbe_primitives::address_pair::AddressPair;
pub use outbe_primitives::asset_type::{currency_address, AssetType, COEN_ASSET};
