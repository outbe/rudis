//! Host-side enclave client for the confidential Gratis write path.
//!
//! Every Gratis state transition routes through the enclave: [`crate::runtime`]
//! reads the current ciphertext from committed storage, hands it + the op to the
//! enclave via [`apply_gratis_op`], and stores the returned ciphertext verbatim.
//! Mirrors `tributefactory::enclave_offer` - same determinism (canonical-hash
//! recheck) and attestation (verify-then-discard) guarantees, and the same
//! `tee_sidecar_unavailable` failure mode when no enclave is configured.

use outbe_primitives::error::{PrecompileError, Result};
use outbe_tee::protocol::{
    gratis_op_canonical_hash, EnclaveRequest, EnclaveResponse, GratisOpRequest, GratisOpResult,
};

/// Run one Gratis op inside the enclave and validate the response.
///
/// Determinism: recompute the canonical inputs hash and reject a mismatch
/// (`tee_enclave_nondeterminism`). Attestation: verify the tag against the
/// enclave key pinned from its quote (`tee_gratis_attestation_invalid`), then
/// discard it - it is never written to state. A missing enclave is
/// `tee_sidecar_unavailable`. All of these are `Fatal` (a node/consensus fault,
/// not a user revert); a *business* rejection is carried in
/// `GratisOpResult::status` and handled by the caller.
pub(crate) fn apply_gratis_op(req: GratisOpRequest) -> Result<GratisOpResult> {
    #[cfg(any(test, feature = "test-enclave"))]
    if let Some(result) = test_enclave::try_apply(&req) {
        return Ok(result);
    }

    let expected_hash = gratis_op_canonical_hash(&req);
    let (attestation_pub, response) = outbe_tee::try_with_enclave(|client| {
        let attestation_pub = client.attestation_pub();
        let response = client.request(&EnclaveRequest::ApplyGratisOp {
            request: Box::new(req),
        });
        (attestation_pub, response)
    })
    .ok_or_else(|| PrecompileError::Fatal("tee_sidecar_unavailable".to_string()))?;
    let response =
        response.map_err(|e| PrecompileError::Fatal(format!("tee_sidecar_unavailable: {e}")))?;

    let result = match response {
        EnclaveResponse::GratisOpApplied { result } => *result,
        EnclaveResponse::Error { message } => {
            return Err(PrecompileError::Fatal(format!(
                "enclave ApplyGratisOp error: {message}"
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
    outbe_tee::verify_gratis_op_attestation(
        &attestation_pub,
        result.inputs_canonical_hash,
        &result,
        &result.attestation_tag,
    )
    .map_err(|e| PrecompileError::Fatal(format!("tee_gratis_attestation_invalid: {e}")))?;
    Ok(result)
}

/// In-process enclave stand-in for tests (this crate's tests and any downstream
/// crate that enables the `test-enclave` feature). It runs the **real**
/// `outbe_tee_enclave::gratis::apply_op` engine against a fixed dev state key, so
/// the full confidential path is exercised without an SGX sidecar. Attestation is
/// not checked on this path (it is verified only in the mock-enclave e2e).
#[cfg(any(test, feature = "test-enclave"))]
pub mod test_enclave {
    use super::*;
    use alloy_primitives::B256;
    use std::cell::RefCell;

    thread_local! {
        static STATE_KEY: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
    }

    /// Fixed dev group signature + chain/epoch, so the derived state key (and thus
    /// every account's view/modify key) is deterministic across a test process.
    const DEV_GROUP_SIG: &[u8] = b"outbe-dev-gratis-group-signature-fixed-seed!!";
    const DEV_CHAIN: B256 = B256::repeat_byte(0xC1);
    const DEV_EPOCH: u64 = 0;

    /// Install the in-process enclave for the current thread.
    pub fn install() {
        let key =
            outbe_tee_enclave::gratis::derive_gratis_state_key(DEV_GROUP_SIG, DEV_CHAIN, DEV_EPOCH)
                .expect("derive dev gratis state key");
        STATE_KEY.with(|k| *k.borrow_mut() = Some(key));
    }

    /// Remove the in-process enclave for the current thread.
    pub fn uninstall() {
        STATE_KEY.with(|k| *k.borrow_mut() = None);
    }

    /// The dev state key, so tests can derive view/modify keys to build auth and
    /// decrypt balances exactly as a client would.
    pub fn state_key() -> [u8; 32] {
        STATE_KEY
            .with(|k| *k.borrow())
            .expect("test enclave not installed")
    }

    pub(crate) fn try_apply(req: &GratisOpRequest) -> Option<GratisOpResult> {
        STATE_KEY.with(|k| {
            k.borrow().map(|key| {
                let mut result = outbe_tee_enclave::gratis::apply_op(&key, req);
                // Mirror the real transport's combined op: on success, apply the
                // co-located fidelity cohort section under the INDEPENDENT
                // fidelity key (the shared dev fidelity identity, so a folded
                // mint writes a blob the fidelity stand-in can later read).
                if let (outbe_tee::protocol::GratisOpStatus::Applied, Some(section)) =
                    (&result.status, &req.fidelity)
                {
                    let fidelity_key = outbe_tee_enclave::fidelity::derive_fidelity_state_key(
                        outbe_tee_enclave::dev::FIDELITY_GROUP_SIG,
                        outbe_tee_enclave::dev::fidelity_chain(),
                        DEV_EPOCH,
                    )
                    .expect("derive dev fidelity state key");
                    // Mirror the real transport: a failing fidelity section
                    // rejects the WHOLE op (rejected_result), so the host reverts
                    // and writes NEITHER ledger - not a panic.
                    match outbe_tee_enclave::fidelity::apply_cohort_section(
                        &fidelity_key,
                        req.account,
                        req.amount,
                        section,
                    ) {
                        Ok(outcome) => result.fidelity = Some(outcome),
                        Err(e) => {
                            result = outbe_tee_enclave::gratis::rejected_result(
                                format!("fidelity section failed: {e}"),
                                result.inputs_canonical_hash,
                            );
                        }
                    }
                }
                result
            })
        })
    }
}
