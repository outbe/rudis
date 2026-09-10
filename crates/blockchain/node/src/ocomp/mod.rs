//! Node-local OCOMP retention and finalized-input authority.
//!
//! Nothing in this module changes block validity. It decides only whether this
//! validator has enough durable, authenticated input to advertise, vote for,
//! export, execute, or sign one PoC job.

pub mod finality;
pub mod fork;
pub mod local_result;
mod openings;
pub mod retention;
pub use openings::{build_lysis_openings, build_public_lysis_openings, verify_lysis_openings};

#[cfg(test)]
mod tests;
