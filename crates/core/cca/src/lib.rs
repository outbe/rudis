//! Credis Card Agent (CCA) registry precompile.
//!
//! Stub: the ABI of `ICca.sol` is live and routed, but there is no registry
//! behind it yet - every address reads back `Active`. See [`precompile`].
pub mod api;
pub mod precompile;

#[cfg(test)]
mod tests;
