//! Local OCOMP process identity helpers.
//!
//! OCOMP runtime transport is public node RPC, Axum registration, Worker Salvo
//! observability and ZeroMQ over loopback TCP. This module is intentionally
//! transport-free: it retains only fixed chain identity and the current process
//! owner used by strict local key and journal loaders.

use alloy_primitives::B256;
use thiserror::Error;

use crate::SchemaLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub boot_nonce: B256,
    pub protocol_bundle_hash: B256,
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("local process identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Compile ceilings generated for the PoC. They do not arm a fork or select a
/// bundle; callers must still supply one exact [`EndpointIdentity`].
#[must_use]
pub fn poc_schema_limits() -> SchemaLimits {
    crate::profile::poc_schema_limits()
}

pub fn effective_uid() -> Result<u32, ControlError> {
    Ok(rustix::process::geteuid().as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_uid_reports_the_current_process_identity() {
        assert_eq!(
            effective_uid().unwrap(),
            rustix::process::geteuid().as_raw()
        );
    }
}
