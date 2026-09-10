//! V2 Phase 1 accounting-progress runtime module.
//!
//! Owns the persistent EVM storage slot
//! `[ACCOUNTING_PROGRESS_ADDRESS] slot 0 = last_accounted_block_number: u64`.
//!
//! ## Scope
//!
//! * [`schema::Accounting`] - single-slot storage facade.
//! * [`state`] - local CRUD helpers around the schema.
//! * [`runtime`] - `record_phase1_progress(ctx, block_number)` invoked by
//!   the V2 executor Phase 1 path (the writer is wired),
//!   `read_last_accounted_block_number(ctx)` for Cycle/Rewards readers.
//!
//! ## Not in scope here
//!
//! * Phase 1 commit logic lives in the executor reorder task.
//! * Phase 2 Cycle gating lives.
//!
//! ## System-only
//!
//! `ACCOUNTING_PROGRESS_ADDRESS` is NOT registered in
//! `outbe-evm::precompiles::extend_outbe_precompiles`, so user-issued CALLs
//! to this address do not reach a dispatch routine - they execute as
//! ordinary calls into a no-op account whose only deployed bytecode is the
//! `[0xef]` EIP-161 marker. Only the executor Phase 1 path may write slot 0
//! (enforced by the schema facade visibility + the fact that the writer
//! `record_phase1_progress` is the only crate-public mutating entrypoint).

#![forbid(unsafe_code)]

pub mod errors;
pub mod events;
pub mod runtime;
pub mod schema;
pub mod state;

pub use runtime::{read_last_accounted_block_number, record_phase1_progress};
pub use schema::Accounting;
