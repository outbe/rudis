//! VaultRouter precompile (`VAULT_ROUTER_ADDRESS`) aka Reserve liquidity router.
//!
//! Registers ERC-4626 vaults per asset and moves funds in and out.

pub mod api;
pub mod crosschain;
pub mod errors;
pub mod precompile;
pub mod runtime;
pub mod schema;
mod sol_ext;

pub use schema::VaultRouterContract;

#[cfg(test)]
mod tests;
