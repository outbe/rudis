//! Governance precompile: on-chain registry of the normative objects
//! (meta-canon, canon) and improvement proposals (OIP, GIP).
//!
//! - **Meta-canon / canon** - a single structured text each, versioned, with a
//!   keccak hash and a `version -> hash` revision map. Two operations: read and
//!   full-overwrite write. No status model.
//! - **OIP / GIP** - separate record types with independent id sequences; each
//!   carries a small header (author, status, blocks, text hash) plus the
//!   proposal text in-record. Status lifecycle:
//!   `Draft -> Approved | Rejected | Rework`, `Rework -> Draft`,
//!   `Approved -> Implemented`.
//! - **diff** - unified diff of a proposal's text against the current canon or
//!   meta-canon (view-only, via `similar`).
//!
//! Writes to the normative texts and to proposal status are gated by the
//! `authorities` set (seeded at genesis with the validator addresses) - PoC
//! scaffolding standing in for the not-yet-built decision pipeline.
//! Approved OIP/GIP records may also be materialized via the vote path
//! ([`GovernanceVoteTarget`]) after validator quorum.

pub mod diff;
pub mod errors;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;
pub mod status;
pub mod vote_target;

pub use schema::{Gip, GovernanceContract, Oip};
pub use vote_target::{GovernanceVotePayload, GovernanceVoteTarget, ProposalKind};

#[cfg(test)]
mod tests;
