//! Callee-scoped state and execution core for Rust-native stablecoins.
//!
//! Every token uses the same code marker and runtime, while [`StablecoinContract`]
//! binds all reads and writes to the actual EVM callee address. Creation is not an
//! ABI operation: the only initialization entry point is the typed Factory API in
//! [`api`].

pub mod api;
pub mod errors;
pub mod precompile;
pub mod schema;

mod abi;
mod state;

pub use api::{FactoryTokenInitialization, StablecoinFactoryApi, TokenIdentity};
pub use schema::{
    allowance_key, role_key, StablecoinContract, ADMIN_ROLE, CAP_MANAGER_ROLE, COMPLIANCE_ROLE,
    ENFORCER_ROLE, GUARDIAN_ROLE, ISSUER_ROLE,
};

#[cfg(test)]
mod tests;
