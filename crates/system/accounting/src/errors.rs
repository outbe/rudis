//! V2 Phase 1 accounting errors.
//!
//! No module-local error type is needed in the scope: every
//! mutating call returns
//! [`outbe_primitives::error::PrecompileError`] surfaced from the
//! underlying [`outbe_primitives::storage::types::Slot`] read/write.
//! Reserved as a module so future cross-module call surfaces (,
//! ) can add typed errors without re-organizing the crate.
