//! Bounded, per-Noise-session upload for enclave-resident DCAP verification.

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{MAX_ATTESTATION_EVIDENCE_BYTES, MAX_TEE_POLICY_BYTES};
use outbe_tee::{
    dcap_protocol::{
        dcap_onboarding_attestation_preimage, dcap_onboarding_request_hash,
        dcap_verification_attestation_preimage, dcap_verification_request_hash,
        DcapOnboardingArtifactV1, DcapOnboardingContextV1, DcapRejectCodeV1,
        DcapVerificationOutcomeV1, MAX_DCAP_VERIFICATION_CHUNK_BYTES,
    },
    protocol::{EnclaveRequest, EnclaveResponse},
};

use crate::{keys::EnclaveKeys, transport::DerivedTributeOfferKey};

#[derive(Debug)]
struct UploadV1 {
    request_hash: B256,
    evidence_len: usize,
    policy_len: usize,
    block_timestamp: u64,
    purpose: VerificationPurposeV1,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerificationPurposeV1 {
    Generic,
    RegisterOnboarding {
        node_signature: [u8; 65],
        enclave_signature: [u8; 64],
        expected_tribute_offer_public: [u8; 32],
        key_epoch: u64,
        tribute_offer_epoch: u64,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CompleteDcapVerificationV1 {
    request_hash: B256,
    evidence: Vec<u8>,
    policy: Vec<u8>,
    block_timestamp: u64,
    pub(crate) purpose: VerificationPurposeV1,
}

pub(crate) enum DcapVerificationProgressV1 {
    Started {
        request_hash: B256,
    },
    ChunkAccepted {
        request_hash: B256,
        next_offset: u32,
    },
    Complete(Box<CompleteDcapVerificationV1>),
}

/// One bounded upload at a time on one authenticated Noise connection.
#[derive(Default)]
pub(crate) struct DcapVerificationSessionV1 {
    upload: Option<UploadV1>,
}

impl DcapVerificationSessionV1 {
    pub(crate) fn handle(
        &mut self,
        request: EnclaveRequest,
    ) -> Result<DcapVerificationProgressV1, &'static str> {
        let result = match request {
            EnclaveRequest::BeginDcapVerificationV1 {
                request_hash,
                evidence_len,
                policy_len,
                block_timestamp,
            } => self.begin(
                request_hash,
                evidence_len,
                policy_len,
                block_timestamp,
                VerificationPurposeV1::Generic,
            ),
            EnclaveRequest::BeginDcapOnboardingVerificationV1 {
                request_hash,
                evidence_len,
                policy_len,
                block_timestamp,
                node_signature,
                enclave_signature,
                expected_tribute_offer_public,
                key_epoch,
                tribute_offer_epoch,
            } => {
                let node_signature = node_signature
                    .try_into()
                    .map_err(|_| "DCAP onboarding node signature length is invalid")?;
                let enclave_signature = enclave_signature
                    .try_into()
                    .map_err(|_| "DCAP onboarding enclave signature length is invalid")?;
                self.begin(
                    request_hash,
                    evidence_len,
                    policy_len,
                    block_timestamp,
                    VerificationPurposeV1::RegisterOnboarding {
                        node_signature,
                        enclave_signature,
                        expected_tribute_offer_public,
                        key_epoch,
                        tribute_offer_epoch,
                    },
                )
            }
            EnclaveRequest::DcapVerificationChunkV1 {
                request_hash,
                offset,
                bytes,
            } => self.push(request_hash, offset, bytes),
            EnclaveRequest::FinishDcapVerificationV1 { request_hash } => self.finish(request_hash),
            _ => Err("request is not part of DCAP verification upload"),
        };
        if result.is_err() {
            self.upload = None;
        }
        result
    }

    fn begin(
        &mut self,
        request_hash: B256,
        evidence_len: u32,
        policy_len: u32,
        block_timestamp: u64,
        purpose: VerificationPurposeV1,
    ) -> Result<DcapVerificationProgressV1, &'static str> {
        if self.upload.is_some() {
            return Err("a DCAP verification upload is already active");
        }
        let evidence_len = usize::try_from(evidence_len)
            .map_err(|_| "DCAP evidence length exceeds this target")?;
        let policy_len =
            usize::try_from(policy_len).map_err(|_| "DCAP policy length exceeds this target")?;
        if evidence_len > MAX_ATTESTATION_EVIDENCE_BYTES {
            return Err("DCAP evidence length exceeds the protocol cap");
        }
        if policy_len > MAX_TEE_POLICY_BYTES {
            return Err("DCAP policy length exceeds the protocol cap");
        }
        let total = evidence_len
            .checked_add(policy_len)
            .ok_or("DCAP verification upload length overflow")?;
        self.upload = Some(UploadV1 {
            request_hash,
            evidence_len,
            policy_len,
            block_timestamp,
            purpose,
            bytes: Vec::with_capacity(total),
        });
        Ok(DcapVerificationProgressV1::Started { request_hash })
    }

    fn push(
        &mut self,
        request_hash: B256,
        offset: u32,
        bytes: Vec<u8>,
    ) -> Result<DcapVerificationProgressV1, &'static str> {
        let upload = self
            .upload
            .as_mut()
            .ok_or("no DCAP verification upload is active")?;
        if upload.request_hash != request_hash {
            return Err("DCAP verification chunk request hash mismatch");
        }
        if bytes.is_empty() || bytes.len() > MAX_DCAP_VERIFICATION_CHUNK_BYTES {
            return Err("DCAP verification chunk length is invalid");
        }
        let offset = usize::try_from(offset).map_err(|_| "DCAP verification offset overflow")?;
        if offset != upload.bytes.len() {
            return Err("DCAP verification chunk offset is not sequential");
        }
        let total = upload
            .evidence_len
            .checked_add(upload.policy_len)
            .ok_or("DCAP verification upload length overflow")?;
        let next = offset
            .checked_add(bytes.len())
            .ok_or("DCAP verification chunk length overflow")?;
        if next > total {
            return Err("DCAP verification chunk exceeds the declared upload length");
        }
        upload.bytes.extend_from_slice(&bytes);
        let next_offset = u32::try_from(next).map_err(|_| "DCAP verification offset overflow")?;
        Ok(DcapVerificationProgressV1::ChunkAccepted {
            request_hash,
            next_offset,
        })
    }

    fn finish(&mut self, request_hash: B256) -> Result<DcapVerificationProgressV1, &'static str> {
        let upload = self
            .upload
            .take()
            .ok_or("no DCAP verification upload is active")?;
        if upload.request_hash != request_hash {
            return Err("DCAP verification finish request hash mismatch");
        }
        let total = upload
            .evidence_len
            .checked_add(upload.policy_len)
            .ok_or("DCAP verification upload length overflow")?;
        if upload.bytes.len() != total {
            return Err("DCAP verification upload is truncated");
        }
        let policy = upload.bytes[upload.evidence_len..].to_vec();
        let evidence = upload.bytes[..upload.evidence_len].to_vec();
        let computed = match &upload.purpose {
            VerificationPurposeV1::Generic => {
                dcap_verification_request_hash(&evidence, &policy, upload.block_timestamp)
            }
            VerificationPurposeV1::RegisterOnboarding {
                node_signature,
                enclave_signature,
                expected_tribute_offer_public,
                key_epoch,
                tribute_offer_epoch,
            } => dcap_onboarding_request_hash(
                &evidence,
                &policy,
                upload.block_timestamp,
                node_signature,
                enclave_signature,
                expected_tribute_offer_public,
                *key_epoch,
                *tribute_offer_epoch,
            ),
        }
        .map_err(|_| "DCAP verification request commitment is invalid")?;
        if computed != request_hash {
            return Err("DCAP verification request commitment mismatch");
        }
        Ok(DcapVerificationProgressV1::Complete(Box::new(
            CompleteDcapVerificationV1 {
                request_hash,
                evidence,
                policy,
                block_timestamp: upload.block_timestamp,
                purpose: upload.purpose,
            },
        )))
    }
}

pub(crate) fn complete_verification_response(
    request: CompleteDcapVerificationV1,
    keys: &EnclaveKeys,
    resident_offer_key: Option<&DerivedTributeOfferKey>,
    source_manifest: Option<&outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1>,
) -> EnclaveResponse {
    #[cfg(feature = "native-dcap")]
    let outcome = verify_complete_request(&request);
    #[cfg(not(feature = "native-dcap"))]
    let outcome: Result<DcapVerificationOutcomeV1, &'static str> =
        Err("enclave was built without the pinned native DCAP verifier");

    let mut outcome = match outcome {
        Ok(outcome) => outcome,
        Err(message) => {
            return EnclaveResponse::Error {
                message: message.to_string(),
            };
        }
    };
    let onboarding_artifact = if matches!(
        request.purpose,
        VerificationPurposeV1::RegisterOnboarding { .. }
    ) {
        match build_onboarding_artifact(
            &request,
            &mut outcome,
            resident_offer_key,
            source_manifest,
            keys.code_identity(),
        ) {
            Ok(artifact) => artifact,
            Err(message) => {
                return EnclaveResponse::Error {
                    message: message.to_string(),
                };
            }
        }
    } else {
        None
    };
    let outcome = match outcome.encode_canonical() {
        Ok(outcome) => outcome,
        Err(_) => {
            return EnclaveResponse::Error {
                message: "enclave produced a non-canonical DCAP outcome".to_string(),
            };
        }
    };
    if matches!(
        request.purpose,
        VerificationPurposeV1::RegisterOnboarding { .. }
    ) {
        let onboarding_artifact = match onboarding_artifact
            .map(|artifact| artifact.encode_canonical())
            .transpose()
        {
            Ok(Some(artifact)) => artifact,
            Ok(None) => Vec::new(),
            Err(_) => {
                return EnclaveResponse::Error {
                    message: "enclave produced a non-canonical onboarding artifact".to_string(),
                };
            }
        };
        let preimage = match dcap_onboarding_attestation_preimage(
            request.request_hash,
            &outcome,
            &onboarding_artifact,
        ) {
            Ok(preimage) => preimage,
            Err(_) => {
                return EnclaveResponse::Error {
                    message: "enclave produced an oversized onboarding result".to_string(),
                };
            }
        };
        return EnclaveResponse::DcapOnboardingVerificationFinishedV1 {
            request_hash: request.request_hash,
            outcome,
            onboarding_artifact,
            attestation_tag: keys.sign_attestation(&preimage).to_vec(),
        };
    }
    let preimage = match dcap_verification_attestation_preimage(request.request_hash, &outcome) {
        Ok(preimage) => preimage,
        Err(_) => {
            return EnclaveResponse::Error {
                message: "enclave produced an oversized DCAP outcome".to_string(),
            };
        }
    };
    EnclaveResponse::DcapVerificationFinishedV1 {
        request_hash: request.request_hash,
        outcome,
        attestation_tag: keys.sign_attestation(&preimage).to_vec(),
    }
}

/// Build a deterministic purpose-bound artifact after TeeRegistry has already
/// validated the DirectDev registration. The request carries only the exact
/// canonical context, never host-selected plaintext key material.
pub(crate) fn complete_gramine_direct_dev_onboarding_response(
    request_hash: B256,
    context: &[u8],
    resident_offer_key: Option<&DerivedTributeOfferKey>,
    source_manifest: Option<&outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1>,
) -> EnclaveResponse {
    let context = match DcapOnboardingContextV1::decode_canonical(context) {
        Ok(context) => context,
        Err(_) => {
            return EnclaveResponse::Error {
                message: "GramineDirectDev onboarding context is not canonical".into(),
            }
        }
    };
    if request_hash != context.context_hash() {
        return EnclaveResponse::Error {
            message: "GramineDirectDev onboarding context hash mismatch".into(),
        };
    }
    let artifact = match build_gramine_direct_dev_onboarding_artifact(
        context,
        resident_offer_key,
        source_manifest,
    ) {
        Ok(artifact) => artifact,
        Err(message) => {
            return EnclaveResponse::Error {
                message: message.to_string(),
            };
        }
    };
    let onboarding_artifact = match artifact.encode_canonical() {
        Ok(artifact) => artifact,
        Err(_) => {
            return EnclaveResponse::Error {
                message: "enclave produced a non-canonical GramineDirectDev onboarding artifact"
                    .to_string(),
            };
        }
    };
    EnclaveResponse::GramineDirectDevOnboardingArtifactPreparedV1 {
        request_hash,
        onboarding_artifact,
    }
}

fn build_gramine_direct_dev_onboarding_artifact(
    context: DcapOnboardingContextV1,
    resident_offer_key: Option<&DerivedTributeOfferKey>,
    source_manifest: Option<&outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1>,
) -> Result<DcapOnboardingArtifactV1, &'static str> {
    use outbe_primitives::tee_attestation_v1::AttestationMode;

    let source_manifest = source_manifest.ok_or("onboarding source is not initialized")?;
    if source_manifest.attestation_mode != AttestationMode::GramineDirectDev
        || source_manifest.chain_id != context.chain_id
        || source_manifest.genesis_hash != context.genesis_hash
    {
        return Err("GramineDirectDev onboarding source network binding mismatch");
    }
    let resident_offer_key =
        resident_offer_key.ok_or("onboarding source offer key is not ready")?;
    if resident_offer_key.public() != context.tribute_offer_public
        || resident_offer_key.key_epoch() != context.key_epoch
        || resident_offer_key.tribute_offer_epoch() != context.tribute_offer_epoch
    {
        return Err("GramineDirectDev onboarding offer-key context mismatch");
    }
    crate::crypto::encrypt_onboarding_artifact_v1(
        resident_offer_key.secret(),
        context,
        resident_offer_key.group_sig(),
    )
    .map_err(|_| "purpose-bound GramineDirectDev onboarding artifact encryption failed")
}

fn build_onboarding_artifact(
    request: &CompleteDcapVerificationV1,
    outcome: &mut DcapVerificationOutcomeV1,
    resident_offer_key: Option<&DerivedTributeOfferKey>,
    source_manifest: Option<&outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1>,
    source_code_identity: (B256, B256, u16, u16),
) -> Result<Option<outbe_tee::dcap_protocol::DcapOnboardingArtifactV1>, &'static str> {
    use outbe_primitives::tee_attestation_v1::{AttestationEvidenceV1, AttestationOperationV1};

    if !matches!(outcome, DcapVerificationOutcomeV1::Accepted(_)) {
        return Ok(None);
    }
    let VerificationPurposeV1::RegisterOnboarding {
        node_signature,
        enclave_signature,
        expected_tribute_offer_public,
        key_epoch,
        tribute_offer_epoch,
    } = &request.purpose
    else {
        return Ok(None);
    };
    let evidence = match AttestationEvidenceV1::decode_canonical(&request.evidence) {
        Ok(AttestationEvidenceV1::Dcap(evidence)) => evidence,
        _ => {
            *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::EvidenceNonCanonical);
            return Ok(None);
        }
    };
    let intent = &evidence.intent;
    if intent.operation != AttestationOperationV1::RegisterEnclave {
        *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::OperationMismatch);
        return Ok(None);
    }
    if !intent.verify_node_signature(node_signature) {
        *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::NodeSignatureInvalid);
        return Ok(None);
    }
    if !intent.verify_enclave_signature(enclave_signature) {
        *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::EnclaveSignatureInvalid);
        return Ok(None);
    }
    let source_manifest = source_manifest.ok_or("onboarding source is not initialized")?;
    let resident_offer_key =
        resident_offer_key.ok_or("onboarding source offer key is not ready")?;
    let DcapVerificationOutcomeV1::Accepted(verdict) = outcome else {
        unreachable!("non-accepted outcomes return before onboarding construction")
    };
    if source_manifest.attestation_mode
        != outbe_primitives::tee_attestation_v1::AttestationMode::DcapRequired
        || (
            verdict.mrenclave,
            verdict.mrsigner,
            verdict.isv_prod_id,
            verdict.isv_svn,
        ) != source_code_identity
    {
        *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::MeasurementRejected);
        return Ok(None);
    }
    if intent.chain_id != source_manifest.chain_id
        || intent.genesis_hash != source_manifest.genesis_hash
        || resident_offer_key.public() != *expected_tribute_offer_public
        || resident_offer_key.key_epoch() != *key_epoch
        || resident_offer_key.tribute_offer_epoch() != *tribute_offer_epoch
    {
        *outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::OnboardingContextMismatch);
        return Ok(None);
    }
    let context = DcapOnboardingContextV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        intent_hash: intent
            .intent_hash()
            .map_err(|_| "accepted onboarding intent hash is unavailable")?,
        node_id_hash: intent
            .node_id
            .node_id_hash()
            .map_err(|_| "accepted onboarding node id hash is unavailable")?,
        enclave_id: intent
            .derived_enclave_id()
            .map_err(|_| "accepted onboarding enclave id is unavailable")?,
        binding_id: intent.binding_id,
        policy_hash: intent.policy_hash,
        recipient_x25519: intent.recipient_x25519,
        tribute_offer_public: *expected_tribute_offer_public,
        key_epoch: *key_epoch,
        tribute_offer_epoch: *tribute_offer_epoch,
    };
    crate::crypto::encrypt_onboarding_artifact_v1(
        resident_offer_key.secret(),
        context,
        resident_offer_key.group_sig(),
    )
    .map(Some)
    .map_err(|_| "purpose-bound onboarding artifact encryption failed")
}

#[cfg(feature = "native-dcap")]
fn verify_complete_request(
    request: &CompleteDcapVerificationV1,
) -> Result<DcapVerificationOutcomeV1, &'static str> {
    use outbe_primitives::tee_attestation_v1::{AttestationEvidenceV1, TeePolicyV1};

    let evidence = match AttestationEvidenceV1::decode_canonical(&request.evidence) {
        Ok(AttestationEvidenceV1::Dcap(evidence)) => evidence,
        Ok(AttestationEvidenceV1::GramineDirectDev(_)) | Err(_) => {
            return Ok(DcapVerificationOutcomeV1::Rejected(
                DcapRejectCodeV1::EvidenceNonCanonical,
            ));
        }
    };
    let policy = match TeePolicyV1::decode_canonical(&request.policy) {
        Ok(policy) => policy,
        Err(_) => {
            return Ok(DcapVerificationOutcomeV1::Rejected(
                DcapRejectCodeV1::PolicyNonCanonical,
            ));
        }
    };
    Ok(
        match outbe_tee::dcap_v1::verify_dcap_evidence(&evidence, &policy, request.block_timestamp)
        {
            Ok(verdict) => DcapVerificationOutcomeV1::Accepted(verdict),
            Err(code) => DcapVerificationOutcomeV1::Rejected(code),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    use outbe_primitives::tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapCollateralComponentV1,
        DcapCollateralKind, DcapEvidenceV1, EnclaveInitializationManifestV1, NodeIdV1,
        RegistrationIntentV1,
    };
    use outbe_tee::dcap_protocol::{
        dcap_onboarding_request_hash, dcap_verification_request_hash, DcapPckCaV1,
        DcapPlatformTcbStatusV1, DcapVerdictV1,
    };

    fn signed_onboarding_fixture() -> (
        CompleteDcapVerificationV1,
        EnclaveInitializationManifestV1,
        crate::transport::DerivedTributeOfferKey,
    ) {
        let keys = crate::keys::EnclaveKeys::new([0x81; 32], Some([0x81; 32])).unwrap();
        let node_key = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x82)).into(),
        )
        .unwrap();
        let node_public: [u8; 33] = node_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let manifest = EnclaveInitializationManifestV1 {
            chain_id: [0x83; 32],
            genesis_hash: B256::repeat_byte(0x84),
            attestation_mode: AttestationMode::DcapRequired,
            node_id: NodeIdV1 {
                reth_p2p_public: node_public,
            },
            initialization_challenge: [0x85; 32],
            node_host_noise_x25519: [0x86; 32],
            recipient_x25519: keys.tribute_offer_public(),
            attestation_ed25519: keys.attestation_pub(),
            noise_responder_x25519: keys.noise_public(),
        };
        let mut intent = RegistrationIntentV1 {
            chain_id: manifest.chain_id,
            genesis_hash: manifest.genesis_hash,
            operation: AttestationOperationV1::RegisterEnclave,
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash: B256::repeat_byte(0x87),
            node_id: manifest.node_id.clone(),
            enclave_id: manifest.enclave_id().unwrap(),
            binding_id: B256::repeat_byte(0x88),
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until: 7_200,
            recipient_x25519: manifest.recipient_x25519,
            attestation_ed25519: manifest.attestation_ed25519,
            noise_responder_x25519: manifest.noise_responder_x25519,
            node_host_authorization_hash: manifest.node_host_authorization_hash().unwrap(),
        };
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        let intent_hash = intent.intent_hash().unwrap();
        let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            node_key.sign_prehash(intent_hash.as_slice()).unwrap();
        let mut node_signature = [0_u8; 65];
        node_signature[..64].copy_from_slice(signature.to_bytes().as_slice());
        node_signature[64] = recovery.to_byte();
        let enclave_signature = keys.sign_attestation(intent_hash.as_slice());
        let evidence = AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
            intent,
            quote: vec![0x89],
            components: (1_u8..=8)
                .map(|kind| DcapCollateralComponentV1 {
                    kind: DcapCollateralKind::try_from(kind).unwrap(),
                    bytes: vec![kind],
                })
                .collect(),
            transition_key_ready_proof: None,
        })
        .encode_canonical()
        .unwrap();
        let resident =
            crate::transport::DerivedTributeOfferKey::for_test([0x8a; 32], vec![0x8b; 96], 2, 3);
        let request = CompleteDcapVerificationV1 {
            request_hash: B256::repeat_byte(0x8c),
            evidence,
            policy: vec![0x8d],
            block_timestamp: 1,
            purpose: VerificationPurposeV1::RegisterOnboarding {
                node_signature,
                enclave_signature,
                expected_tribute_offer_public: resident.public(),
                key_epoch: 2,
                tribute_offer_epoch: 3,
            },
        };
        (request, manifest, resident)
    }

    fn accepted_outcome() -> DcapVerificationOutcomeV1 {
        let (mrenclave, mrsigner, isv_prod_id, isv_svn) = accepted_code_identity();
        DcapVerificationOutcomeV1::Accepted(DcapVerdictV1 {
            mrenclave,
            mrsigner,
            isv_prod_id,
            isv_svn,
            pck_ca: DcapPckCaV1::Processor,
            fmspc: [0x93; 6],
            pce_id: 1,
            platform_tcb_status: DcapPlatformTcbStatusV1::UpToDate,
            advisory_ids: Vec::new(),
            tcb_evaluation_data_number: 1,
            qe_tcb_evaluation_data_number: 1,
            collateral_valid_until: 10_000,
        })
    }

    fn accepted_code_identity() -> (B256, B256, u16, u16) {
        (B256::repeat_byte(0x91), B256::repeat_byte(0x92), 1, 1)
    }

    #[test]
    fn gramine_direct_dev_onboarding_is_bound_to_testnet_genesis_policy() {
        use outbe_primitives::{
            chain::TESTNET_CHAIN_ID,
            tee_genesis_v1::{initial_tee_policy_v1, InitialTeeProfileV1},
        };

        let genesis_hash = B256::repeat_byte(0xA1);
        let policy = initial_tee_policy_v1(
            InitialTeeProfileV1::GramineDirectDev,
            TESTNET_CHAIN_ID,
            genesis_hash,
        )
        .unwrap();
        let policy_hash = policy.policy_hash().unwrap();
        let source_keys = crate::keys::EnclaveKeys::new([0xA2; 32], Some([0xA2; 32])).unwrap();
        let source_node_key = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0xA3)).into(),
        )
        .unwrap();
        let source_node_public: [u8; 33] = source_node_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let source_manifest = EnclaveInitializationManifestV1 {
            chain_id: U256::from(TESTNET_CHAIN_ID).to_be_bytes(),
            genesis_hash,
            attestation_mode: AttestationMode::GramineDirectDev,
            node_id: NodeIdV1 {
                reth_p2p_public: source_node_public,
            },
            initialization_challenge: [0xA4; 32],
            node_host_noise_x25519: [0xA5; 32],
            recipient_x25519: source_keys.tribute_offer_public(),
            attestation_ed25519: source_keys.attestation_pub(),
            noise_responder_x25519: source_keys.noise_public(),
        };

        let target_keys = crate::keys::EnclaveKeys::new([0xA6; 32], Some([0xA6; 32])).unwrap();
        let target_node_key = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0xA7)).into(),
        )
        .unwrap();
        let target_node_public: [u8; 33] = target_node_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let target_manifest = EnclaveInitializationManifestV1 {
            chain_id: U256::from(TESTNET_CHAIN_ID).to_be_bytes(),
            genesis_hash,
            attestation_mode: AttestationMode::GramineDirectDev,
            node_id: NodeIdV1 {
                reth_p2p_public: target_node_public,
            },
            initialization_challenge: [0xA8; 32],
            node_host_noise_x25519: [0xA9; 32],
            recipient_x25519: target_keys.tribute_offer_public(),
            attestation_ed25519: target_keys.attestation_pub(),
            noise_responder_x25519: target_keys.noise_public(),
        };
        let mut intent = RegistrationIntentV1 {
            chain_id: target_manifest.chain_id,
            genesis_hash,
            operation: AttestationOperationV1::RegisterEnclave,
            attestation_mode: AttestationMode::GramineDirectDev,
            policy_hash,
            node_id: target_manifest.node_id.clone(),
            enclave_id: target_manifest.enclave_id().unwrap(),
            binding_id: B256::repeat_byte(0xAA),
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until: 7_200,
            recipient_x25519: target_manifest.recipient_x25519,
            attestation_ed25519: target_manifest.attestation_ed25519,
            noise_responder_x25519: target_manifest.noise_responder_x25519,
            node_host_authorization_hash: target_manifest.node_host_authorization_hash().unwrap(),
        };
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        let intent_hash = intent.intent_hash().unwrap();
        let resident =
            crate::transport::DerivedTributeOfferKey::for_test([0xAB; 32], vec![0xAC; 96], 2, 3);
        let context = DcapOnboardingContextV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            intent_hash,
            node_id_hash: intent.node_id.node_id_hash().unwrap(),
            enclave_id: intent.enclave_id,
            binding_id: intent.binding_id,
            policy_hash: intent.policy_hash,
            recipient_x25519: intent.recipient_x25519,
            tribute_offer_public: resident.public(),
            key_epoch: 2,
            tribute_offer_epoch: 3,
        };
        let request_hash = context.context_hash();
        let canonical_context = context.encode_canonical();

        let response = complete_gramine_direct_dev_onboarding_response(
            request_hash,
            &canonical_context,
            Some(&resident),
            Some(&source_manifest),
        );
        let EnclaveResponse::GramineDirectDevOnboardingArtifactPreparedV1 {
            request_hash: actual_hash,
            onboarding_artifact,
            ..
        } = response
        else {
            panic!("testnet GramineDirectDev onboarding was rejected: {response:?}");
        };
        assert_eq!(actual_hash, request_hash);
        let artifact = DcapOnboardingArtifactV1::decode_canonical(&onboarding_artifact).unwrap();
        assert_eq!(artifact.context.chain_id, intent.chain_id);
        assert_eq!(artifact.context.genesis_hash, intent.genesis_hash);
        assert_eq!(artifact.context.policy_hash, intent.policy_hash);
        assert_eq!(artifact.context.intent_hash, intent_hash);
        assert_eq!(artifact.context.recipient_x25519, intent.recipient_x25519);

        let mut wrong_source_mode = source_manifest.clone();
        wrong_source_mode.attestation_mode = AttestationMode::DcapRequired;
        let rejected = complete_gramine_direct_dev_onboarding_response(
            request_hash,
            &canonical_context,
            Some(&resident),
            Some(&wrong_source_mode),
        );
        assert!(matches!(
            rejected,
            EnclaveResponse::Error { ref message }
                if message.contains("source network binding mismatch")
        ));

        let mut wrong_network_context = context;
        wrong_network_context.genesis_hash = B256::repeat_byte(0xAD);
        let rejected = complete_gramine_direct_dev_onboarding_response(
            wrong_network_context.context_hash(),
            &wrong_network_context.encode_canonical(),
            Some(&resident),
            Some(&source_manifest),
        );
        assert!(matches!(
            rejected,
            EnclaveResponse::Error { ref message }
                if message.contains("source network binding mismatch")
        ));

        let wrong_resident =
            crate::transport::DerivedTributeOfferKey::for_test([0xAE; 32], vec![0xAF; 96], 2, 3);
        let rejected = complete_gramine_direct_dev_onboarding_response(
            request_hash,
            &canonical_context,
            Some(&wrong_resident),
            Some(&source_manifest),
        );
        assert!(matches!(
            rejected,
            EnclaveResponse::Error { ref message }
                if message.contains("offer-key context mismatch")
        ));
    }

    #[test]
    fn bounded_upload_reassembles_the_exact_committed_inputs() {
        let evidence = vec![0x11; 70_000];
        let policy = vec![0x22; 1_000];
        let timestamp = 1_700_000_000;
        let hash = dcap_verification_request_hash(&evidence, &policy, timestamp).unwrap();
        let mut session = DcapVerificationSessionV1::default();
        assert!(matches!(
            session
                .handle(EnclaveRequest::BeginDcapVerificationV1 {
                    request_hash: hash,
                    evidence_len: evidence.len() as u32,
                    policy_len: policy.len() as u32,
                    block_timestamp: timestamp,
                })
                .unwrap(),
            DcapVerificationProgressV1::Started { request_hash } if request_hash == hash
        ));
        let mut combined = evidence.clone();
        combined.extend_from_slice(&policy);
        let first = combined[..MAX_DCAP_VERIFICATION_CHUNK_BYTES].to_vec();
        assert!(matches!(
            session
                .handle(EnclaveRequest::DcapVerificationChunkV1 {
                    request_hash: hash,
                    offset: 0,
                    bytes: first,
                })
                .unwrap(),
            DcapVerificationProgressV1::ChunkAccepted { next_offset, .. }
                if next_offset == MAX_DCAP_VERIFICATION_CHUNK_BYTES as u32
        ));
        session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: MAX_DCAP_VERIFICATION_CHUNK_BYTES as u32,
                bytes: combined[MAX_DCAP_VERIFICATION_CHUNK_BYTES..].to_vec(),
            })
            .unwrap();
        let DcapVerificationProgressV1::Complete(complete) = session
            .handle(EnclaveRequest::FinishDcapVerificationV1 { request_hash: hash })
            .unwrap()
        else {
            panic!("finish did not return the complete verifier request");
        };
        assert_eq!(complete.request_hash, hash);
        assert_eq!(complete.evidence, evidence);
        assert_eq!(complete.policy, policy);
        assert_eq!(complete.block_timestamp, timestamp);
    }

    #[test]
    fn upload_caps_reject_before_accepting_any_chunk() {
        let mut session = DcapVerificationSessionV1::default();
        let hash = B256::repeat_byte(0x41);
        assert!(session
            .handle(EnclaveRequest::BeginDcapVerificationV1 {
                request_hash: hash,
                evidence_len: (MAX_ATTESTATION_EVIDENCE_BYTES + 1) as u32,
                policy_len: 1,
                block_timestamp: 1,
            })
            .is_err());
        assert!(session
            .handle(EnclaveRequest::BeginDcapVerificationV1 {
                request_hash: hash,
                evidence_len: 1,
                policy_len: (MAX_TEE_POLICY_BYTES + 1) as u32,
                block_timestamp: 1,
            })
            .is_err());
        session
            .handle(EnclaveRequest::BeginDcapVerificationV1 {
                request_hash: hash,
                evidence_len: 1,
                policy_len: 1,
                block_timestamp: 1,
            })
            .unwrap();
        assert!(session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: 0,
                bytes: vec![0; MAX_DCAP_VERIFICATION_CHUNK_BYTES + 1],
            })
            .is_err());
        assert!(session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: 0,
                bytes: vec![0],
            })
            .is_err());
    }

    #[test]
    fn upload_order_hash_or_truncation_fault_clears_the_session() {
        let evidence = [0x51, 0x52];
        let policy = [0x61, 0x62];
        let timestamp = 7;
        let hash = dcap_verification_request_hash(&evidence, &policy, timestamp).unwrap();
        let begin = || EnclaveRequest::BeginDcapVerificationV1 {
            request_hash: hash,
            evidence_len: evidence.len() as u32,
            policy_len: policy.len() as u32,
            block_timestamp: timestamp,
        };
        let mut session = DcapVerificationSessionV1::default();

        session.handle(begin()).unwrap();
        assert!(session.handle(begin()).is_err());
        assert!(session
            .handle(EnclaveRequest::FinishDcapVerificationV1 { request_hash: hash })
            .is_err());

        session.handle(begin()).unwrap();
        assert!(session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: 1,
                bytes: vec![0x51],
            })
            .is_err());
        assert!(session
            .handle(EnclaveRequest::FinishDcapVerificationV1 { request_hash: hash })
            .is_err());

        session.handle(begin()).unwrap();
        session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: 0,
                bytes: evidence.to_vec(),
            })
            .unwrap();
        assert!(session
            .handle(EnclaveRequest::FinishDcapVerificationV1 { request_hash: hash })
            .is_err());

        session.handle(begin()).unwrap();
        let mut combined = evidence.to_vec();
        combined.extend_from_slice(&policy);
        session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash: hash,
                offset: 0,
                bytes: combined,
            })
            .unwrap();
        assert!(session
            .handle(EnclaveRequest::FinishDcapVerificationV1 {
                request_hash: B256::repeat_byte(0x99),
            })
            .is_err());
    }

    #[test]
    fn onboarding_upload_commits_exact_authorization_and_epochs() {
        let evidence = [0x71, 0x72];
        let policy = [0x73];
        let node_signature = [0x74; 65];
        let enclave_signature = [0x75; 64];
        let offer_public = [0x76; 32];
        let request_hash = dcap_onboarding_request_hash(
            &evidence,
            &policy,
            77,
            &node_signature,
            &enclave_signature,
            &offer_public,
            2,
            3,
        )
        .unwrap();
        let mut session = DcapVerificationSessionV1::default();
        session
            .handle(EnclaveRequest::BeginDcapOnboardingVerificationV1 {
                request_hash,
                evidence_len: evidence.len() as u32,
                policy_len: policy.len() as u32,
                block_timestamp: 77,
                node_signature: node_signature.to_vec(),
                enclave_signature: enclave_signature.to_vec(),
                expected_tribute_offer_public: offer_public,
                key_epoch: 2,
                tribute_offer_epoch: 3,
            })
            .unwrap();
        let mut combined = evidence.to_vec();
        combined.extend_from_slice(&policy);
        session
            .handle(EnclaveRequest::DcapVerificationChunkV1 {
                request_hash,
                offset: 0,
                bytes: combined,
            })
            .unwrap();
        let DcapVerificationProgressV1::Complete(complete) = session
            .handle(EnclaveRequest::FinishDcapVerificationV1 { request_hash })
            .unwrap()
        else {
            panic!("onboarding upload did not complete");
        };
        assert_eq!(
            complete.purpose,
            VerificationPurposeV1::RegisterOnboarding {
                node_signature,
                enclave_signature,
                expected_tribute_offer_public: offer_public,
                key_epoch: 2,
                tribute_offer_epoch: 3,
            }
        );
    }

    #[test]
    fn accepted_onboarding_requires_both_exact_signatures_before_artifact_creation() {
        let (request, manifest, resident) = signed_onboarding_fixture();
        let mut outcome = accepted_outcome();
        let artifact = build_onboarding_artifact(
            &request,
            &mut outcome,
            Some(&resident),
            Some(&manifest),
            accepted_code_identity(),
        )
        .unwrap();
        assert!(artifact.is_some());

        let mut bad_node = request;
        let VerificationPurposeV1::RegisterOnboarding { node_signature, .. } =
            &mut bad_node.purpose
        else {
            unreachable!()
        };
        node_signature[0] ^= 1;
        let mut outcome = accepted_outcome();
        assert!(build_onboarding_artifact(
            &bad_node,
            &mut outcome,
            Some(&resident),
            Some(&manifest),
            accepted_code_identity(),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            outcome,
            DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::NodeSignatureInvalid)
        );

        let (mut bad_enclave, _, _) = signed_onboarding_fixture();
        let VerificationPurposeV1::RegisterOnboarding {
            enclave_signature, ..
        } = &mut bad_enclave.purpose
        else {
            unreachable!()
        };
        enclave_signature[0] ^= 1;
        let mut outcome = accepted_outcome();
        assert!(build_onboarding_artifact(
            &bad_enclave,
            &mut outcome,
            Some(&resident),
            Some(&manifest),
            accepted_code_identity(),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            outcome,
            DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::EnclaveSignatureInvalid)
        );
    }

    #[test]
    fn rejected_qvl_outcome_never_creates_an_onboarding_artifact() {
        let (request, manifest, resident) = signed_onboarding_fixture();
        let mut outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::QuoteMalformed);
        assert!(build_onboarding_artifact(
            &request,
            &mut outcome,
            Some(&resident),
            Some(&manifest),
            accepted_code_identity(),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            outcome,
            DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::QuoteMalformed)
        );
    }

    #[test]
    fn onboarding_rejects_host_policy_that_admits_another_enclave_binary() {
        let (request, manifest, resident) = signed_onboarding_fixture();
        let mut outcome = accepted_outcome();
        let source_identity = (B256::repeat_byte(0xa1), B256::repeat_byte(0xa2), 1, 2);
        assert!(build_onboarding_artifact(
            &request,
            &mut outcome,
            Some(&resident),
            Some(&manifest),
            source_identity,
        )
        .unwrap()
        .is_none());
        assert_eq!(
            outcome,
            DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::MeasurementRejected)
        );
    }
}
