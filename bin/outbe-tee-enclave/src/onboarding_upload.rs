//! Streaming, genesis-anchored onboarding admission verification.

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::TrustedNetworkDescriptorV1;
use outbe_tee::{
    dcap_protocol::{DcapOnboardingArtifactV1, MAX_DCAP_ONBOARDING_ARTIFACT_BYTES},
    finalized_admission::{
        onboarding_artifact_ingest_request_hash_v1, FinalizedAdmissionRecordKindV1,
        MAX_COMMITTEE_TRANSITION_RECORD_BYTES, MAX_FINALIZED_ADMISSION_RECORD_BYTES,
        MAX_ONBOARDING_INGEST_CHUNK_BYTES,
    },
    protocol::EnclaveRequest,
};

use crate::finalized_admission::{FinalizedAdmissionVerifierV1, VerifiedAdmissionAnchorV1};

struct UploadV1 {
    request_hash: B256,
    artifact: Vec<u8>,
    expected_intent_hash: B256,
    expected_tribute_offer_public: [u8; 32],
    expected_key_epoch: u64,
    expected_tribute_offer_epoch: u64,
    verifier: FinalizedAdmissionVerifierV1,
    record_kind: Option<FinalizedAdmissionRecordKindV1>,
    record: Vec<u8>,
    verified_admission: Option<VerifiedAdmissionAnchorV1>,
}

pub(crate) struct CompleteOnboardingArtifactIngestV1 {
    pub(crate) request_hash: B256,
    pub(crate) artifact: Vec<u8>,
    pub(crate) expected_intent_hash: B256,
    pub(crate) expected_tribute_offer_public: [u8; 32],
    pub(crate) expected_key_epoch: u64,
    pub(crate) expected_tribute_offer_epoch: u64,
    pub(crate) verified_admission: VerifiedAdmissionAnchorV1,
}

pub(crate) enum OnboardingArtifactUploadProgressV1 {
    Started {
        request_hash: B256,
    },
    ChunkAccepted {
        request_hash: B256,
        next_offset: u32,
    },
    RecordAccepted {
        request_hash: B256,
        kind: FinalizedAdmissionRecordKindV1,
    },
    Complete(Box<CompleteOnboardingArtifactIngestV1>),
}

/// Exactly one stream may exist on one authenticated Noise connection. Any
/// malformed transition destroys the cursor so retries restart from genesis.
#[derive(Default)]
pub(crate) struct OnboardingArtifactUploadSessionV1 {
    upload: Option<UploadV1>,
}

impl OnboardingArtifactUploadSessionV1 {
    pub(crate) const fn is_active(&self) -> bool {
        self.upload.is_some()
    }

    pub(crate) fn abort(&mut self) {
        self.upload = None;
    }

    pub(crate) fn handle(
        &mut self,
        request: EnclaveRequest,
        descriptor: Option<&TrustedNetworkDescriptorV1>,
    ) -> Result<OnboardingArtifactUploadProgressV1, String> {
        let result = match request {
            EnclaveRequest::BeginDcapOnboardingArtifactIngestV1 {
                request_hash,
                artifact,
                anchor_outcome,
                expected_intent_hash,
                expected_tribute_offer_public,
                expected_key_epoch,
                expected_tribute_offer_epoch,
            } => self.begin(
                descriptor.ok_or_else(|| {
                    "onboarding ingest requires a release-measured network descriptor".to_owned()
                })?,
                request_hash,
                artifact,
                anchor_outcome,
                expected_intent_hash,
                expected_tribute_offer_public,
                expected_key_epoch,
                expected_tribute_offer_epoch,
            ),
            EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                request_hash,
                kind,
                offset,
                bytes,
            } => self.push(request_hash, kind, offset, bytes),
            EnclaveRequest::CommitDcapOnboardingArtifactRecordV1 { request_hash, kind } => {
                self.commit_record(request_hash, kind)
            }
            EnclaveRequest::FinishDcapOnboardingArtifactIngestV1 { request_hash } => {
                self.finish(request_hash)
            }
            _ => Err("request is not part of onboarding artifact ingest".to_owned()),
        };
        if result.is_err() {
            self.upload = None;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        descriptor: &TrustedNetworkDescriptorV1,
        request_hash: B256,
        artifact: Vec<u8>,
        anchor_outcome: Vec<u8>,
        expected_intent_hash: B256,
        expected_tribute_offer_public: [u8; 32],
        expected_key_epoch: u64,
        expected_tribute_offer_epoch: u64,
    ) -> Result<OnboardingArtifactUploadProgressV1, String> {
        if self.upload.is_some() {
            return Err("an onboarding artifact upload is already active".into());
        }
        if artifact.is_empty() || artifact.len() > MAX_DCAP_ONBOARDING_ARTIFACT_BYTES {
            return Err("onboarding artifact length is invalid".into());
        }
        let decoded = DcapOnboardingArtifactV1::decode_canonical(&artifact)
            .map_err(|_| "onboarding artifact is not canonical")?;
        if decoded.context.intent_hash != expected_intent_hash
            || decoded.context.tribute_offer_public != expected_tribute_offer_public
            || decoded.context.key_epoch != expected_key_epoch
            || decoded.context.tribute_offer_epoch != expected_tribute_offer_epoch
        {
            return Err("onboarding artifact does not match the expected Registry values".into());
        }
        let computed = onboarding_artifact_ingest_request_hash_v1(
            &artifact,
            &anchor_outcome,
            expected_intent_hash,
            expected_tribute_offer_public,
            expected_key_epoch,
            expected_tribute_offer_epoch,
        )
        .map_err(|error| error.to_string())?;
        if computed != request_hash {
            return Err("onboarding artifact request commitment mismatch".into());
        }
        let verifier =
            FinalizedAdmissionVerifierV1::new(descriptor, &decoded.context, &anchor_outcome)?;
        self.upload = Some(UploadV1 {
            request_hash,
            artifact,
            expected_intent_hash,
            expected_tribute_offer_public,
            expected_key_epoch,
            expected_tribute_offer_epoch,
            verifier,
            record_kind: None,
            record: Vec::new(),
            verified_admission: None,
        });
        Ok(OnboardingArtifactUploadProgressV1::Started { request_hash })
    }

    fn push(
        &mut self,
        request_hash: B256,
        kind: FinalizedAdmissionRecordKindV1,
        offset: u32,
        bytes: Vec<u8>,
    ) -> Result<OnboardingArtifactUploadProgressV1, String> {
        let upload = self
            .upload
            .as_mut()
            .ok_or_else(|| "no onboarding artifact upload is active".to_owned())?;
        if upload.request_hash != request_hash || upload.verified_admission.is_some() {
            return Err("onboarding artifact chunk is out of sequence".into());
        }
        if bytes.is_empty() || bytes.len() > MAX_ONBOARDING_INGEST_CHUNK_BYTES {
            return Err("onboarding artifact chunk length is invalid".into());
        }
        match upload.record_kind {
            Some(active) if active != kind => {
                return Err("onboarding artifact record kinds cannot be interleaved".into())
            }
            None => upload.record_kind = Some(kind),
            _ => {}
        }
        let offset = usize::try_from(offset)
            .map_err(|_| "onboarding artifact chunk offset exceeds this target")?;
        if offset != upload.record.len() {
            return Err("onboarding artifact chunks are not strictly sequential".into());
        }
        let next = offset
            .checked_add(bytes.len())
            .ok_or_else(|| "onboarding artifact chunk offset overflow".to_owned())?;
        let max = match kind {
            FinalizedAdmissionRecordKindV1::CommitteeTransition => {
                MAX_COMMITTEE_TRANSITION_RECORD_BYTES
            }
            FinalizedAdmissionRecordKindV1::Admission => MAX_FINALIZED_ADMISSION_RECORD_BYTES,
        };
        if next > max {
            return Err("onboarding artifact record exceeds its byte cap".into());
        }
        upload.record.extend_from_slice(&bytes);
        Ok(OnboardingArtifactUploadProgressV1::ChunkAccepted {
            request_hash,
            next_offset: u32::try_from(next)
                .map_err(|_| "onboarding artifact chunk offset exceeds u32")?,
        })
    }

    fn commit_record(
        &mut self,
        request_hash: B256,
        kind: FinalizedAdmissionRecordKindV1,
    ) -> Result<OnboardingArtifactUploadProgressV1, String> {
        let upload = self
            .upload
            .as_mut()
            .ok_or_else(|| "no onboarding artifact upload is active".to_owned())?;
        if upload.request_hash != request_hash
            || upload.record_kind != Some(kind)
            || upload.record.is_empty()
            || upload.verified_admission.is_some()
        {
            return Err("onboarding artifact record commit is out of sequence".into());
        }
        let record = std::mem::take(&mut upload.record);
        upload.record_kind = None;
        match kind {
            FinalizedAdmissionRecordKindV1::CommitteeTransition => {
                upload.verifier.advance_committee(&record)?;
            }
            FinalizedAdmissionRecordKindV1::Admission => {
                upload.verified_admission = Some(upload.verifier.verify_admission(&record)?);
            }
        }
        Ok(OnboardingArtifactUploadProgressV1::RecordAccepted { request_hash, kind })
    }

    fn finish(&mut self, request_hash: B256) -> Result<OnboardingArtifactUploadProgressV1, String> {
        let upload = self
            .upload
            .take()
            .ok_or_else(|| "no onboarding artifact upload is active".to_owned())?;
        if upload.request_hash != request_hash
            || upload.record_kind.is_some()
            || !upload.record.is_empty()
        {
            return Err("onboarding artifact finish is out of sequence".into());
        }
        let verified_admission = upload
            .verified_admission
            .ok_or_else(|| "onboarding artifact has no verified admission record".to_owned())?;
        Ok(OnboardingArtifactUploadProgressV1::Complete(Box::new(
            CompleteOnboardingArtifactIngestV1 {
                request_hash,
                artifact: upload.artifact,
                expected_intent_hash: upload.expected_intent_hash,
                expected_tribute_offer_public: upload.expected_tribute_offer_public,
                expected_key_epoch: upload.expected_key_epoch,
                expected_tribute_offer_epoch: upload.expected_tribute_offer_epoch,
                verified_admission,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use commonware_consensus::types::Epoch;
    use outbe_consensus::finalized_admission_test_utils::FinalityCommitteeFixture;
    use outbe_primitives::tee_attestation_v1::{AttestationMode, NetworkBindingV1};
    use outbe_tee::dcap_protocol::DcapOnboardingContextV1;

    fn expect_error(result: Result<OnboardingArtifactUploadProgressV1, String>) -> String {
        match result {
            Err(error) => error,
            Ok(_) => panic!("onboarding stream operation unexpectedly succeeded"),
        }
    }

    fn started_session() -> (OnboardingArtifactUploadSessionV1, B256) {
        let committee = FinalityCommitteeFixture::new(110);
        let context = DcapOnboardingContextV1 {
            chain_id: U256::ZERO.to_be_bytes(),
            genesis_hash: B256::repeat_byte(0x11),
            intent_hash: B256::repeat_byte(0x12),
            node_id_hash: B256::repeat_byte(0x13),
            enclave_id: B256::repeat_byte(0x14),
            binding_id: B256::repeat_byte(0x15),
            policy_hash: B256::repeat_byte(0x16),
            recipient_x25519: [0x17; 32],
            tribute_offer_public: [0x18; 32],
            key_epoch: 19,
            tribute_offer_epoch: 20,
        };
        let descriptor = TrustedNetworkDescriptorV1 {
            network_binding: NetworkBindingV1 {
                chain_id: context.chain_id,
                genesis_hash: context.genesis_hash,
                attestation_mode: AttestationMode::DcapRequired,
            },
            genesis_consensus_keys: committee.public_keys_min_pk(),
        };
        let artifact = DcapOnboardingArtifactV1 {
            context,
            nonce: [0x21; 12],
            ciphertext: vec![0x22; 16],
        }
        .encode_canonical()
        .unwrap();
        let anchor = committee.outcome(Epoch::new(0));
        let request_hash = onboarding_artifact_ingest_request_hash_v1(
            &artifact,
            &anchor,
            context.intent_hash,
            context.tribute_offer_public,
            context.key_epoch,
            context.tribute_offer_epoch,
        )
        .unwrap();
        let mut session = OnboardingArtifactUploadSessionV1::default();
        assert!(matches!(
            session.handle(
                EnclaveRequest::BeginDcapOnboardingArtifactIngestV1 {
                    request_hash,
                    artifact,
                    anchor_outcome: anchor,
                    expected_intent_hash: context.intent_hash,
                    expected_tribute_offer_public: context.tribute_offer_public,
                    expected_key_epoch: context.key_epoch,
                    expected_tribute_offer_epoch: context.tribute_offer_epoch,
                },
                Some(&descriptor),
            ),
            Ok(OnboardingArtifactUploadProgressV1::Started {
                request_hash: echoed
            }) if echoed == request_hash
        ));
        (session, request_hash)
    }

    #[test]
    fn record_kinds_cannot_interleave_and_error_aborts_the_stream() {
        let (mut session, request_hash) = started_session();
        session
            .handle(
                EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                    request_hash,
                    kind: FinalizedAdmissionRecordKindV1::CommitteeTransition,
                    offset: 0,
                    bytes: vec![1],
                },
                None,
            )
            .unwrap();

        let error = expect_error(session.handle(
            EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                request_hash,
                kind: FinalizedAdmissionRecordKindV1::Admission,
                offset: 1,
                bytes: vec![2],
            },
            None,
        ));
        assert!(error.contains("cannot be interleaved"));
        assert!(!session.is_active());
    }

    #[test]
    fn transition_record_cap_is_cumulative_across_chunks() {
        let (mut session, request_hash) = started_session();
        let mut offset = 0_u32;
        for chunk_len in [MAX_ONBOARDING_INGEST_CHUNK_BYTES; 2] {
            let progress = session
                .handle(
                    EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                        request_hash,
                        kind: FinalizedAdmissionRecordKindV1::CommitteeTransition,
                        offset,
                        bytes: vec![0x31; chunk_len],
                    },
                    None,
                )
                .unwrap();
            let OnboardingArtifactUploadProgressV1::ChunkAccepted { next_offset, .. } = progress
            else {
                panic!("transition chunk was not acknowledged")
            };
            offset = next_offset;
        }
        let overflow = MAX_COMMITTEE_TRANSITION_RECORD_BYTES + 1 - usize::try_from(offset).unwrap();
        let error = expect_error(session.handle(
            EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                request_hash,
                kind: FinalizedAdmissionRecordKindV1::CommitteeTransition,
                offset,
                bytes: vec![0x32; overflow],
            },
            None,
        ));
        assert!(error.contains("exceeds its byte cap"));
        assert!(!session.is_active());
    }

    #[test]
    fn commit_and_finish_require_a_complete_record_in_order() {
        let (mut session, request_hash) = started_session();
        assert!(expect_error(session.handle(
            EnclaveRequest::CommitDcapOnboardingArtifactRecordV1 {
                request_hash,
                kind: FinalizedAdmissionRecordKindV1::Admission,
            },
            None,
        ))
        .contains("commit is out of sequence"));
        assert!(!session.is_active());

        let (mut session, request_hash) = started_session();
        assert!(expect_error(session.handle(
            EnclaveRequest::FinishDcapOnboardingArtifactIngestV1 { request_hash },
            None,
        ))
        .contains("no verified admission record"));
        assert!(!session.is_active());
    }
}
