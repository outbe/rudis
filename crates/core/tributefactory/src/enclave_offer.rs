//! Host-side TEE enclave client for tribute-offer decryption.
//!
//! When the node is started with `--tee-enclave-socket`, [`init_enclave_client`]
//! connects to the enclave sidecar (validating quote/key bindings and pinning its
//! Noise-IK static key) and installs a process-global client. Every offer decryption then
//! routes through the enclave via [`process_tribute_offer_batch_via_enclave`] - the offer
//! key exists only inside the enclave, and there is no in-process key path. The L1<->L2 linkage
//! (`creator`, `tribute_draft_id`) is parsed
//! and validated inside the enclave but withheld from the host (Enclave Return
//! Rule); the public draft fields are returned and used to issue the tribute.
//!
//! Determinism: every node's enclave holds the same shared offer key, so the same
//! ciphertext decrypts identically on all validators (re-execution agrees). The
//! enclave call is a **blocking** UDS round-trip made straight from the precompile
//! path - it never holds a `StorageHandle` across an await and never spawns a
//! thread (the `StorageHandle` `!Send` constraint). A dead sidecar (after the
//! session's one bounded reconnect + retry) surfaces as `PrecompileError::Fatal`
//! (`tee_sidecar_unavailable`) - a node-local fault, never a deterministic
//! revert, matching the gratis/promis/fidelity enclave paths. Only per-offer
//! rejections reported by the enclave inside the results are deterministic and
//! revert.

use std::path::Path;

use alloy_primitives::B256;
use outbe_primitives::error::PrecompileError;
use outbe_tee::protocol::{
    EnclaveRequest, EnclaveResponse, EncryptedTributeOffer, TributeOfferResult,
};
use outbe_tee::{verify_tribute_offer_attestation, EnclaveClient};

/// True once an enclave client is installed. Offers always route through the
/// enclave (single path); when no client is configured, `offerTribute` reverts
/// with a typed `tee_sidecar_unavailable` error. Delegates to the process-global
/// enclave client in `outbe-tee` (shared with the TEE registry seal).
pub fn is_enclave_configured() -> bool {
    outbe_tee::is_enclave_configured()
}

/// Connect to the enclave sidecar at `socket`, validate its structural key
/// bindings, verify it answers an encrypted request, and install the global
/// offer-decryption client. Production enclave identity and DCAP admission are
/// enforced by the authorized manifest and enclave-resident native QVL paths.
pub fn init_enclave_client(socket: &Path) -> eyre::Result<()> {
    // A `host:port` endpoint connects over TCP (enclave under Gramine); a path
    // connects over the Unix domain socket (native sidecar).
    let endpoint = socket
        .to_str()
        .ok_or_else(|| eyre::eyre!("TEE enclave endpoint is not valid UTF-8"))?;
    let mut client = EnclaveClient::connect_endpoint(endpoint)
        .map_err(|e| eyre::eyre!("TEE enclave connect at {} failed: {e}", socket.display()))?;
    // Verify the encrypted channel works before installing the client.
    match client.request(&EnclaveRequest::GetPublicKeys) {
        Ok(EnclaveResponse::PublicKeys { .. }) => {}
        Ok(other) => {
            return Err(eyre::eyre!(
                "unexpected enclave handshake response: {other:?}"
            ))
        }
        Err(e) => return Err(eyre::eyre!("enclave GetPublicKeys failed: {e}")),
    }
    // Report the enclave's declared attestation mode. This connect-time path does
    // not verify DCAP; production admission is enforced by native QVL + TeeRegistry.
    let mode = client.attestation_label();
    if client.is_hardware_attested() {
        let (mrenclave, mrsigner, isv_svn) = client.measurements();
        tracing::info!(
            attestation = %mode, %mrenclave, %mrsigner, isv_svn,
            "TEE enclave reports SGX/DCAP quote metadata; connect-time validation is structural only"
        );
    } else {
        tracing::warn!(
            attestation = %mode,
            "TEE enclave is UNATTESTED: mode is `{mode}`; this development connection \
             provides no SGX confidentiality or DCAP admission"
        );
    }
    outbe_tee::install_enclave_client(client, endpoint.to_owned()).map_err(|e| eyre::eyre!(e))?;
    Ok(())
}

/// Process a batch of offers through the enclave: it decrypts (offer key stays in
/// SGX), applies each offer's node-resolved price, computes economics + Poseidon
/// `token_id`, and returns the public `TributeOfferResult[]`. The host then issues
/// the Tributes from those fields plus its own request inputs (no host recompute
/// of the private economics).
///
/// The host recomputes `inputs_canonical_hash` from the request it sent and
/// compares it to the enclave's - a mismatch is enclave non-determinism
/// (`tee_enclave_nondeterminism`). It then verifies the per-offer `attestation_tag`
/// (an Ed25519 signature over the inputs hash + results) against the attestation
/// key pinned for the enclave session, binding the results to that peer
/// (`tee_offer_attestation_invalid` on failure); the tag is
/// then discarded (never written to chain state). Both checks live in
/// [`validate_tribute_offer_batch_response`] so they are unit-testable without a sidecar.
///
/// Failure classification (aligned with `gratis::enclave_client::apply_gratis_op`):
/// every failure of THIS function is a node-local fault (`PrecompileError::Fatal`) -
/// dead sidecar, transport error after the session's bounded reconnect+retry,
/// enclave authorization denial (keyless enclave), non-determinism, bad
/// attestation. Executing the tx differently from healthy validators would
/// diverge state, so the node fails the block instead. Deterministic per-offer
/// rejections ride inside the returned results and are handled by the caller.
pub fn process_tribute_offer_batch_via_enclave(
    offers: &[EncryptedTributeOffer],
) -> Result<Vec<TributeOfferResult>, PrecompileError> {
    // Route through the process-global enclave session (shared with the TEE registry
    // seal). Pin the attestation key from the installed identity before the
    // call. `None` means no client is configured -> typed `tee_sidecar_unavailable`.
    let (attestation_pub, response) = outbe_tee::try_with_enclave(|session| {
        let attestation_pub = session.attestation_pub();
        let response = session.request(&EnclaveRequest::ProcessTributeOfferBatch {
            offers: offers.to_vec(),
        });
        (attestation_pub, response)
    })
    .ok_or_else(|| PrecompileError::Fatal("tee_sidecar_unavailable".to_string()))?;
    let response =
        response.map_err(|e| PrecompileError::Fatal(format!("tee_sidecar_unavailable: {e}")))?;

    match response {
        EnclaveResponse::TributeOfferBatch {
            results,
            inputs_canonical_hash,
            attestation_tag,
        } => validate_tribute_offer_batch_response(
            offers,
            results,
            inputs_canonical_hash,
            &attestation_pub,
            &attestation_tag,
        ),
        EnclaveResponse::Error { message } => Err(PrecompileError::Fatal(format!(
            "enclave ProcessTributeOfferBatch error: {message}"
        ))),
        other => Err(PrecompileError::Fatal(format!(
            "unexpected enclave response: {other:?}"
        ))),
    }
}

/// Validate the enclave's `TributeOfferBatch` response: (1) the canonical-inputs hash
/// equals the host's recompute over the exact request it sent (non-determinism
/// detector -> `tee_enclave_nondeterminism`); (2) the per-offer attestation tag
/// verifies against the pinned attestation key (-> `tee_offer_attestation_invalid`).
/// Both failures are node-local (`Fatal`), never deterministic reverts.
/// Returns the results on success. Pure (no transport) so it is unit-testable.
fn validate_tribute_offer_batch_response(
    offers: &[EncryptedTributeOffer],
    results: Vec<TributeOfferResult>,
    inputs_canonical_hash: B256,
    attestation_pub: &[u8; 32],
    attestation_tag: &[u8],
) -> Result<Vec<TributeOfferResult>, PrecompileError> {
    let expected = outbe_tee::protocol::inputs_canonical_hash(offers);
    if inputs_canonical_hash != expected {
        return Err(PrecompileError::Fatal(
            "tee_enclave_nondeterminism: inputs_canonical_hash mismatch".to_string(),
        ));
    }
    verify_tribute_offer_attestation(
        attestation_pub,
        inputs_canonical_hash,
        &results,
        attestation_tag,
    )
    .map_err(|e| PrecompileError::Fatal(format!("tee_offer_attestation_invalid: {e}")))?;
    validate_effective_reference_prices(offers, &results)?;
    Ok(results)
}

fn validate_effective_reference_prices(
    offers: &[EncryptedTributeOffer],
    results: &[TributeOfferResult],
) -> Result<(), PrecompileError> {
    if offers.len() != results.len() {
        return Err(PrecompileError::Fatal(format!(
            "tee_enclave_nondeterminism: result count mismatch: expected {}, got {}",
            offers.len(),
            results.len()
        )));
    }
    for (offer, result) in offers.iter().zip(results) {
        if !matches!(
            result.status,
            outbe_tee::protocol::TributeOfferStatus::Created
        ) {
            continue;
        }
        let expected = offer
            .reference_wwd_vwap_minor
            .max(offer.reference_scurve_minor);
        if result.effective_reference_price_minor != expected {
            return Err(PrecompileError::Fatal(
                "tee_enclave_nondeterminism: effective reference price mismatch".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use outbe_tee::protocol::WorldwideDay;

    const NEXT_DAY: WorldwideDay = WorldwideDay::new(20250116);

    fn sample_tribute_offer() -> EncryptedTributeOffer {
        EncryptedTributeOffer {
            owner: Address::repeat_byte(0x11),
            cipher_text: vec![1, 2, 3, 4],
            nonce: vec![0u8; 12],
            ephemeral_pubkey: U256::from(7u64),
            worldwide_day: WorldwideDay::new(20250115),
            tribute_currency: 840,
            reference_currency: 840,
            exclude_from_intex_issuance: false,
            issuance_wwd_vwap_minor: U256::from(1_000u64),
            reference_wwd_vwap_minor: U256::from(2_000u64),
            reference_scurve_minor: U256::from(3_000u64),
            zk_context: None,
        }
    }

    fn sample_result() -> TributeOfferResult {
        TributeOfferResult {
            token_id: B256::repeat_byte(0x22),
            owner: Address::repeat_byte(0x11),
            issuance_amount_minor: U256::from(100u64),
            nominal_amount_minor: U256::from(10u64),
            effective_reference_price_minor: U256::from(3_000u64),
            su_hashes: Vec::new(),
            wallet_addresses: Vec::new(),
            sra_addresses: Vec::new(),
            zk_expected_hashes: None,
            status: outbe_tee::protocol::TributeOfferStatus::Created,
        }
    }

    /// Regression (2026-08-22 testnet incident): a dead/unconfigured sidecar is
    /// a NODE-LOCAL fault. It must surface as `PrecompileError::Fatal`, never as
    /// a deterministic revert - reverting a tx that healthy validators execute
    /// diverges state.
    #[test]
    fn transport_unavailability_is_fatal_not_revert() {
        // No enclave session is installed in this test process.
        let err = process_tribute_offer_batch_via_enclave(&[sample_tribute_offer()])
            .expect_err("no enclave configured");
        match err {
            PrecompileError::Fatal(message) => assert!(
                message.contains("tee_sidecar_unavailable"),
                "unexpected fatal message: {message}"
            ),
            other => panic!("expected Fatal, got: {other:?}"),
        }
    }

    /// A returned `inputs_canonical_hash` that disagrees with the host's
    /// recompute is enclave non-determinism -> `tee_enclave_nondeterminism`. The
    /// hash check runs before attestation, so a bogus tag is irrelevant here.
    #[test]
    fn validate_rejects_inputs_canonical_hash_divergence() {
        let offers = vec![sample_tribute_offer()];
        let wrong_hash = B256::repeat_byte(0xFF);
        // Sanity: the wrong hash really differs from the canonical recompute.
        assert_ne!(
            wrong_hash,
            outbe_tee::protocol::inputs_canonical_hash(&offers)
        );

        let err =
            validate_tribute_offer_batch_response(&offers, Vec::new(), wrong_hash, &[0u8; 32], &[])
                .expect_err("hash divergence must be rejected");
        assert!(
            err.to_string().contains("tee_enclave_nondeterminism"),
            "unexpected error: {err}"
        );
    }

    /// The day, currency and price are request inputs the node resolved, so a
    /// response hashed over different values must not validate - otherwise they
    /// ride to the enclave unattested.
    #[test]
    fn validate_binds_the_priced_request_fields() {
        let offers = vec![sample_tribute_offer()];

        for mutate in [
            (|o: &mut EncryptedTributeOffer| o.worldwide_day = NEXT_DAY) as fn(&mut _),
            |o: &mut EncryptedTributeOffer| o.tribute_currency = 978,
            |o: &mut EncryptedTributeOffer| o.issuance_wwd_vwap_minor = U256::from(2_000u64),
            |o: &mut EncryptedTributeOffer| o.reference_wwd_vwap_minor = U256::from(4_000u64),
            |o: &mut EncryptedTributeOffer| o.reference_scurve_minor = U256::from(5_000u64),
        ] {
            let mut other = offers.clone();
            mutate(&mut other[0]);
            let hash_of_other = outbe_tee::protocol::inputs_canonical_hash(&other);

            let err = validate_tribute_offer_batch_response(
                &offers,
                Vec::new(),
                hash_of_other,
                &[0u8; 32],
                &[],
            )
            .expect_err("a hash over different request fields must be rejected");
            assert!(
                err.to_string().contains("tee_enclave_nondeterminism"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn effective_reference_price_must_match_the_public_request_inputs() {
        let offers = vec![sample_tribute_offer()];
        let results = vec![sample_result()];
        validate_effective_reference_prices(&offers, &results).unwrap();

        let mut wrong = results;
        wrong[0].effective_reference_price_minor -= U256::ONE;
        let error = validate_effective_reference_prices(&offers, &wrong)
            .expect_err("a forged enclave effective reference price must fail closed");
        assert!(error.to_string().contains("tee_enclave_nondeterminism"));
    }
}
