//! Promisfactory precompile (`0x2337`). Thin orchestration layer on top of the
//! Promis token (`outbe_promis`, `0x1337`).
//!
//! Owns the promis mint/burn orchestration. `mine` wraps `Promis::mine`.
//! `mine_coen` is the symmetric sale path: it wraps `Promis::burn`, mints native
//! COEN 1:1, and emits `RudisMined`.

pub mod api;
pub mod precompile;
pub mod runtime;

#[cfg(test)]
mod tests;
