//! Fidelity (RCFI) precompile (`0x100C`).
//!
//! The per-owner cohort ledger (the Gratis movement history) is **encrypted at
//! rest**: the TEE enclave is the only party that decrypts it. RCFI/league are
//! never computed on-chain - the enclave produces them via cohort ops
//! ([`api::cohort_in`]/[`api::cohort_out`]), the per-WWD league snapshot
//! ([`api::snapshot_leagues`]/[`api::league`]), and owner-authorized signed
//! queries (the [`precompile`] eth_call path). Every enclave interaction carries
//! the same determinism (canonical-hash recheck) + attestation guarantees as the
//! confidential Gratis path.
//!
//! Module layout:
//! - [`api`] - cross-crate surface (cohort hooks + league lookups).
//! - [`precompile`] - inbound ABI (signed-auth index queries + plaintext
//!   metadata); no cohort mutations go through the ABI.
//! - [`enclave_client`] - host caller for the fidelity enclave requests plus the
//!   in-process test enclave.
//! - `runtime` / `state` - orchestration and cohort-blob CRUD (crate-private).
//! - `schema` - encrypted storage layout for the [`FidelityContract`] facade.
//! - [`math`] - re-export of the shared fixed-point RCFI arithmetic (the enclave
//!   uses the same leaf crate, so the two evaluators cannot drift).

pub mod api;
pub mod enclave_client;
pub mod precompile;
pub mod schema;

pub(crate) mod runtime;
pub(crate) mod state;

/// Shared fixed-point RCFI decay math - re-exported so existing
/// `crate::math::*` paths keep working after the arithmetic moved to the leaf
/// crate `outbe-fidelity-math` (also used by the enclave engine).
pub use outbe_fidelity_math as math;

pub use outbe_fidelity_math::{MAX_LEAGUE, MIN_LEAGUE};
pub use schema::FidelityContract;

#[cfg(test)]
mod tests;
