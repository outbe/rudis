//! Shared bounded policy registry for Rust-native stablecoins.
//!
//! The registry owns immutable policy descriptors, policy administration and
//! bounded membership sets. Stablecoin ledgers use the narrow read-only
//! functions in [`api`] instead of issuing nested ABI calls.

pub mod api;
pub mod errors;
pub mod precompile;
pub mod schema;

mod abi;
mod state;

pub use schema::{
    PolicyDescriptor, PolicyLane, PolicyType, StablecoinPolicyRegistryContract,
    ALLOW_ALL_POLICY_ID, DENY_ALL_POLICY_ID,
};

#[cfg(test)]
mod tests;
