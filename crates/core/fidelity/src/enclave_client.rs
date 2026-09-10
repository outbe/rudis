//! Host-side enclave client for the confidential Fidelity cohort path.
//!
//! Every RCFI/league value and every cohort mutation routes through the enclave:
//! [`crate::runtime`] reads the current cohort ciphertext from committed storage,
//! hands it to the enclave, and stores the returned ciphertext verbatim. Mirrors
//! [`outbe_gratis`]'s `enclave_client` - same determinism (canonical-hash
//! recheck), attestation (verify-then-discard), and `tee_sidecar_unavailable`
//! failure mode.

use outbe_primitives::error::{PrecompileError, Result};
use outbe_tee::protocol::{
    fidelity_cohort_canonical_hash, fidelity_query_canonical_hash,
    fidelity_snapshot_canonical_hash, EnclaveRequest, EnclaveResponse, FidelityCohortRequest,
    FidelityCohortResult, FidelityLeagueEntry, FidelityQueryRequest, FidelityQueryResult,
    FidelitySnapshotRequest,
};

fn unavailable(context: &str) -> PrecompileError {
    PrecompileError::Fatal(format!("tee_sidecar_unavailable: {context}"))
}

/// Apply a standalone Fidelity cohort op inside the enclave and validate the
/// response (determinism recheck + attestation verify-then-discard).
pub(crate) fn apply_cohort_op(req: FidelityCohortRequest) -> Result<FidelityCohortResult> {
    #[cfg(any(test, feature = "test-enclave"))]
    if let Some(result) = test_enclave::try_cohort(&req) {
        return result;
    }

    let expected_hash = fidelity_cohort_canonical_hash(&req);
    let (attestation_pub, response) = outbe_tee::try_with_enclave(|client| {
        let attestation_pub = client.attestation_pub();
        let response = client.request(&EnclaveRequest::ApplyFidelityCohortOp {
            request: Box::new(req),
        });
        (attestation_pub, response)
    })
    .ok_or_else(|| unavailable("ApplyFidelityCohortOp"))?;
    let response = response.map_err(|e| unavailable(&format!("ApplyFidelityCohortOp: {e}")))?;

    let result = match response {
        EnclaveResponse::FidelityCohortApplied { result } => *result,
        EnclaveResponse::Error { message } => {
            return Err(PrecompileError::Fatal(format!(
                "enclave ApplyFidelityCohortOp error: {message}"
            )))
        }
        other => {
            return Err(PrecompileError::Fatal(format!(
                "unexpected enclave response: {other:?}"
            )))
        }
    };
    if result.inputs_canonical_hash != expected_hash {
        return Err(PrecompileError::Fatal(
            "tee_enclave_nondeterminism".to_string(),
        ));
    }
    outbe_tee::verify_fidelity_cohort_attestation(
        &attestation_pub,
        result.inputs_canonical_hash,
        &result,
        &result.attestation_tag,
    )
    .map_err(|e| PrecompileError::Fatal(format!("tee_fidelity_attestation_invalid: {e}")))?;
    Ok(result)
}

/// Batch-snapshot per-owner leagues inside the enclave.
pub(crate) fn snapshot_leagues(req: FidelitySnapshotRequest) -> Result<Vec<FidelityLeagueEntry>> {
    #[cfg(any(test, feature = "test-enclave"))]
    if let Some(leagues) = test_enclave::try_snapshot(&req) {
        return leagues;
    }

    let expected_hash = fidelity_snapshot_canonical_hash(&req);
    let (attestation_pub, response) = outbe_tee::try_with_enclave(|client| {
        let attestation_pub = client.attestation_pub();
        let response = client.request(&EnclaveRequest::SnapshotFidelityLeagues {
            request: Box::new(req),
        });
        (attestation_pub, response)
    })
    .ok_or_else(|| unavailable("SnapshotFidelityLeagues"))?;
    let response = response.map_err(|e| unavailable(&format!("SnapshotFidelityLeagues: {e}")))?;

    let (leagues, inputs_canonical_hash, attestation_tag) = match response {
        EnclaveResponse::FidelityLeaguesSnapshotted {
            leagues,
            inputs_canonical_hash,
            attestation_tag,
        } => (leagues, inputs_canonical_hash, attestation_tag),
        EnclaveResponse::Error { message } => {
            return Err(PrecompileError::Fatal(format!(
                "enclave SnapshotFidelityLeagues error: {message}"
            )))
        }
        other => {
            return Err(PrecompileError::Fatal(format!(
                "unexpected enclave response: {other:?}"
            )))
        }
    };
    if inputs_canonical_hash != expected_hash {
        return Err(PrecompileError::Fatal(
            "tee_enclave_nondeterminism".to_string(),
        ));
    }
    outbe_tee::verify_fidelity_snapshot_attestation(
        &attestation_pub,
        inputs_canonical_hash,
        &leagues,
        &attestation_tag,
    )
    .map_err(|e| PrecompileError::Fatal(format!("tee_fidelity_attestation_invalid: {e}")))?;
    Ok(leagues)
}

/// Owner-authorized RCFI/league query inside the enclave (eth_call path).
pub(crate) fn query_index(req: FidelityQueryRequest) -> Result<FidelityQueryResult> {
    #[cfg(any(test, feature = "test-enclave"))]
    if let Some(result) = test_enclave::try_query(&req) {
        return result;
    }

    let expected_hash = fidelity_query_canonical_hash(&req);
    let (attestation_pub, response) = outbe_tee::try_with_enclave(|client| {
        let attestation_pub = client.attestation_pub();
        let response = client.request(&EnclaveRequest::QueryFidelityIndex {
            request: Box::new(req),
        });
        (attestation_pub, response)
    })
    .ok_or_else(|| unavailable("QueryFidelityIndex"))?;
    let response = response.map_err(|e| unavailable(&format!("QueryFidelityIndex: {e}")))?;

    let result = match response {
        EnclaveResponse::FidelityIndexQueried { result } => *result,
        EnclaveResponse::Error { message } => {
            return Err(PrecompileError::Fatal(format!(
                "enclave QueryFidelityIndex error: {message}"
            )))
        }
        other => {
            return Err(PrecompileError::Fatal(format!(
                "unexpected enclave response: {other:?}"
            )))
        }
    };
    if result.inputs_canonical_hash != expected_hash {
        return Err(PrecompileError::Fatal(
            "tee_enclave_nondeterminism".to_string(),
        ));
    }
    outbe_tee::verify_fidelity_query_attestation(
        &attestation_pub,
        result.inputs_canonical_hash,
        &result,
        &result.attestation_tag,
    )
    .map_err(|e| PrecompileError::Fatal(format!("tee_fidelity_attestation_invalid: {e}")))?;
    Ok(result)
}

/// In-process enclave stand-in for tests (this crate's tests and any downstream
/// crate that enables the `test-enclave` feature). Runs the **real**
/// `outbe_tee_enclave::fidelity` engine against a fixed dev state key, so the
/// full confidential path is exercised without an SGX sidecar. Attestation is not
/// checked on this path (verified only in the mock-enclave e2e).
#[cfg(any(test, feature = "test-enclave"))]
pub mod test_enclave {
    use super::*;
    use alloy_primitives::B256;
    use std::cell::RefCell;

    thread_local! {
        static STATE_KEY: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
    }

    const DEV_EPOCH: u64 = 0;

    /// Chain id the in-process enclave binds. Query auth is chain-scoped, so the
    /// resident chain must equal what the runtime derives from
    /// `storage.chain_id()` - tests that exercise the query path build their
    /// storage with this id and sign over [`dev_chain`]. Cohort/snapshot ops do
    /// not verify chain id, so downstream crates may use any storage chain id.
    ///
    /// The group sig + chain are the SHARED dev fidelity identity
    /// ([`outbe_tee_enclave::dev`]): the gratis stand-in derives the same
    /// fidelity key when it applies a folded cohort section, so a folded mint and
    /// a standalone snapshot agree.
    pub const DEV_CHAIN_ID: u64 = outbe_tee_enclave::dev::FIDELITY_CHAIN_ID;

    /// The resident chain id as a `B256`, matching the runtime's
    /// `B256::from(U256::from(storage.chain_id()))` encoding.
    pub fn dev_chain() -> B256 {
        outbe_tee_enclave::dev::fidelity_chain()
    }

    /// Install the in-process enclave for the current thread.
    pub fn install() {
        let key = outbe_tee_enclave::fidelity::derive_fidelity_state_key(
            outbe_tee_enclave::dev::FIDELITY_GROUP_SIG,
            dev_chain(),
            DEV_EPOCH,
        )
        .expect("derive dev fidelity state key");
        STATE_KEY.with(|k| *k.borrow_mut() = Some(key));
    }

    /// Remove the in-process enclave for the current thread.
    pub fn uninstall() {
        STATE_KEY.with(|k| *k.borrow_mut() = None);
    }

    /// The dev state key, so tests can derive view keys to decrypt cohorts.
    pub fn state_key() -> [u8; 32] {
        STATE_KEY
            .with(|k| *k.borrow())
            .expect("test enclave not installed")
    }

    /// Map an in-process engine error to the same `Fatal` shape the real host
    /// path produces from an `EnclaveResponse::Error`.
    fn engine_err(context: &str, e: impl core::fmt::Display) -> PrecompileError {
        PrecompileError::Fatal(format!("enclave {context} error: {e}"))
    }

    pub(super) fn try_cohort(req: &FidelityCohortRequest) -> Option<Result<FidelityCohortResult>> {
        STATE_KEY.with(|k| {
            k.borrow().map(|key| {
                outbe_tee_enclave::fidelity::apply_cohort_op(&key, req)
                    .map_err(|e| engine_err("ApplyFidelityCohortOp", e))
            })
        })
    }

    pub(super) fn try_snapshot(
        req: &FidelitySnapshotRequest,
    ) -> Option<Result<Vec<FidelityLeagueEntry>>> {
        STATE_KEY.with(|k| {
            k.borrow().map(|key| {
                outbe_tee_enclave::fidelity::snapshot_leagues(&key, req)
                    .map_err(|e| engine_err("SnapshotFidelityLeagues", e))
            })
        })
    }

    pub(super) fn try_query(req: &FidelityQueryRequest) -> Option<Result<FidelityQueryResult>> {
        STATE_KEY.with(|k| {
            k.borrow().map(|key| {
                outbe_tee_enclave::fidelity::query_index(&key, dev_chain(), req)
                    .map_err(|e| engine_err("QueryFidelityIndex", e))
            })
        })
    }
}
