//! `TeeRegistry` - storage-backed KV precompile (`0x...EE0A`).
//!
//! Records role-neutral V1 NodeHost enclave bindings and the global
//! `tribute_offer_public_key`, written once by the OST3 block-1 system
//! transaction. [`v1_precompile`] is the only public ABI; there is no
//! caller-authorized registration dispatcher or fallback admission path.

pub mod runtime;
pub mod schema;
pub mod v1;
#[cfg(feature = "tee-attestation-v1")]
pub mod v1_precompile;

pub use runtime::TeeBootstrapData;
pub use schema::TeeRegistry;
pub use v1::{NodeEnclaveBindingV1, V1RegistrationOutcome};

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "tee-attestation-v1"))]
mod v1_tests;
