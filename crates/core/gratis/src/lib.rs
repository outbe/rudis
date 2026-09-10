//! Confidential Gratis token precompile (`0x1003`).
//!
//! A non-transferable, mineable/burnable balance ledger whose per-account
//! balances and pledged amounts are **encrypted at rest**: the TEE enclave is the
//! only party that decrypts them (and the account's view-key holder, client-side).
//! Every write routes through the enclave - read the current ciphertext, apply the
//! op inside SGX, store the returned ciphertext verbatim - mirroring the tribute
//! offer path's determinism + attestation model.
//!
//! Module layout:
//! - [`api`] - cross-crate surface (owner-authorized writes + credis-driven ops +
//!   ciphertext reads); other crates call `outbe_gratis::api::*`.
//! - [`precompile`] - inbound ABI (metadata + confidential reads + non-transferable
//!   stubs); no writes go through the ABI.
//! - [`enclave_client`] - host caller for `ApplyGratisOp` (determinism + attestation
//!   checks) plus the in-process test enclave.
//! - `runtime` / `state` - orchestration and ledger CRUD (crate-private).
//! - `schema` - encrypted storage layout for the [`Gratis`] facade.

pub mod api;
pub mod enclave_client;
pub mod precompile;
pub mod schema;

pub(crate) mod runtime;
pub(crate) mod state;

pub use schema::Gratis;

#[cfg(test)]
mod tests;
