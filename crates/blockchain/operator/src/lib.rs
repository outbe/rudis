//! Host-only operator workflows shared by the CLI and node lifecycle workers.
//!
//! This crate may use RPC, timers, relay accounts and durable host journals. It
//! is intentionally outside the `outbe-tee`/enclave dependency direction so
//! host dependencies can never enter the enclave graph through feature
//! unification.

pub mod rpc;
pub mod tee;
pub mod tx;
