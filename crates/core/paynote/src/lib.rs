//! PayNote — shielded ERC20 note pool (`0x…1019`).
//!
//! A **deposit** pulls an ERC20 from the caller, routes it into the asset's
//! reserve vault through VaultRouter, and appends a note commitment to a
//! depth-32 incremental Merkle tree. The commitment is derived by the runtime
//! from the transfer it actually performed — the circuit binds the asset in the
//! *commitment* rather than the serial precisely so the pool can do this, and
//! so a depositor cannot fund a note in a cheap token and spend it as an
//! expensive one.
//!
//! A **spend** consumes the frozen `outbe.paynote@1.1.0` UltraHonkKeccak proof:
//! it proves membership under an accepted root, publishes a nullifier, and — for
//! a partial spend — the deterministic change commitment. Notes are bearer
//! instruments: spend authority is knowledge of the note spend key, not an
//! address. Spending is exposed only as [`api::consume`], an in-process Rust
//! entry point for other precompile modules; it is not on the Solidity ABI and
//! it moves no tokens, returning the validated claim for the caller to settle.
//!
//! The hash/tree formulas mirror the frozen noir circuit's `paynote.nr`; the
//! runtime is implemented over persistent EVM storage.
//!
//! Layout: [`hash`] (formula mirror), [`schema`] (frozen V1 storage table),
//! [`runtime`] (transition core), [`api`] (cross-module surface),
//! [`precompile`] (ABI dispatch, value policy, selector-sensitive gas),
//! [`errors`].

pub mod api;
pub mod errors;
pub mod hash;
pub mod precompile;
pub mod runtime;
pub mod schema;
mod sol_ext;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_support;

pub use api::PayNoteClaim;
pub use schema::PayNoteContract;

#[cfg(test)]
mod tests;
