//! Application actor - bridges Simplex consensus with Reth's execution layer.
//!
//! Handles propose/verify/finalize requests from the consensus engine
//! by communicating with Reth via `beacon_engine_handle`.

pub mod actor;
pub(crate) mod ancestry;
pub(crate) mod epoch_boundary;
pub mod handler;
pub mod ingress;
pub(crate) mod validation;
pub(crate) mod verify_resolution;

pub use epoch_boundary::ApplicationEpochFence;
pub use handler::{
    ApplicationDeps, ApplicationHandler, OffsetUnixTimeSource, SystemUnixTimeSource, UnixTimeSource,
};
pub use ingress::Mailbox;
