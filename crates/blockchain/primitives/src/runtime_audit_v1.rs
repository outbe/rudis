//! Stable machine-readable runtime audit vocabulary.
//!
//! Human log messages are deliberately outside this contract. Consumers must
//! classify records only by these versioned fields and correlation identities.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{keccak256, B256};

pub const SCHEMA_VERSION: u8 = 1;
pub const SCHEMA_FIELD: &str = "audit_schema";
pub const EVENT_FIELD: &str = "audit_event";
pub const FAILURE_KIND_FIELD: &str = "failure_kind";
pub const PROCESS_INSTANCE_FIELD: &str = "process_instance";

pub const PROPOSAL_VIEW_CANCELLED: &str = "proposal_view_cancelled_v1";
pub const PAYLOAD_EXECUTION_FAILED: &str = "payload_execution_failed_v1";

pub const BODY_READ_REQUEST_DEADLINE: &str = "body_read_request_deadline";
pub const OTHER_PAYLOAD_EXECUTION_FAILURE: &str = "other_payload_execution_failure";

/// Node-process boot identity used only to correlate runtime audit records.
///
/// This is not protocol authority or a security token. Combining the PID with
/// the first-observation wall-clock instant prevents records retained across a
/// process restart from authorizing an exception in the next process.
pub fn process_instance_id() -> B256 {
    static PROCESS_INSTANCE: OnceLock<B256> = OnceLock::new();
    *PROCESS_INSTANCE.get_or_init(|| {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        keccak256(format!("{}:{started_at}", std::process::id()))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_instance_is_stable_within_one_process() {
        assert_eq!(super::process_instance_id(), super::process_instance_id());
    }
}
