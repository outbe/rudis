//! Stable, native-verifier-independent DCAP protocol values.
//!
//! These values cross the Gramine enclave seam. The node can decode and
//! validate the canonical outcome without linking Intel QVL; only the enclave
//! compiles the native verifier implementation.

use alloy_primitives::{keccak256, B256};
use outbe_primitives::tee_attestation_v1::{MAX_ATTESTATION_EVIDENCE_BYTES, MAX_TEE_POLICY_BYTES};

const DCAP_VERIFICATION_REQUEST_DOMAIN_V1: &[u8] = b"outbe/tee/dcap-verification-request/v1";
const DCAP_ONBOARDING_REQUEST_DOMAIN_V1: &[u8] = b"outbe/tee/dcap-onboarding-request/v1";
const DCAP_VERIFICATION_ATTESTATION_DOMAIN_V1: &[u8] =
    b"outbe/tee/dcap-verification-attestation/v1";
const DCAP_ONBOARDING_ATTESTATION_DOMAIN_V1: &[u8] = b"outbe/tee/dcap-onboarding-attestation/v1";
const DCAP_EVIDENCE_DOMAIN_V1: &[u8] = b"outbe/tee/dcap-evidence/v1";
const DCAP_ONBOARDING_CONTEXT_DOMAIN_V1: &[u8] = b"outbe/tee/onboarding-context/v1";

/// Canonical `AttestationOperationV1::RegisterEnclave` discriminant committed
/// by the purpose-bound onboarding request. Keeping the byte here avoids
/// serializing a Rust enum across the enclave wire while still binding the
/// exact operation into the request hash.
pub const DCAP_REGISTER_ENCLAVE_OPERATION_V1: u8 = 0x01;

/// Maximum canonical purpose-bound artifact emitted into the Registry event.
/// The fixed public context plus one encrypted BLS group signature fit well
/// below this cap, which is shared with the existing consensus log bound.
pub const MAX_DCAP_ONBOARDING_ARTIFACT_BYTES: usize = 512;

const DCAP_ONBOARDING_CONTEXT_BYTES: usize = 305;
const DCAP_ONBOARDING_ARTIFACT_FIXED_BYTES: usize = 1 + DCAP_ONBOARDING_CONTEXT_BYTES + 12 + 2;

/// Maximum plaintext payload in one upload chunk. Postcard metadata and Noise
/// authentication remain safely below the shared 64 KiB frame ceiling.
pub const MAX_DCAP_VERIFICATION_CHUNK_BYTES: usize = 60 * 1024;

/// Upper bound for the canonical stable verdict returned by the enclave.
/// Intel QVL 1.26 exposes at most 450 advisory bytes; 1 KiB leaves bounded
/// framing headroom without allowing an unbounded response.
pub const MAX_DCAP_VERDICT_BYTES: usize = 1024;

/// Public values that make a one-time offer-key artifact useful for exactly
/// one accepted `RegisterEnclave` intent and unusable in every other context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcapOnboardingContextV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub intent_hash: B256,
    pub node_id_hash: B256,
    pub enclave_id: B256,
    pub binding_id: B256,
    pub policy_hash: B256,
    pub recipient_x25519: [u8; 32],
    pub tribute_offer_public: [u8; 32],
    pub key_epoch: u64,
    pub tribute_offer_epoch: u64,
}

impl DcapOnboardingContextV1 {
    pub fn encode_canonical(&self) -> Vec<u8> {
        debug_assert!(!self.binding_id.is_zero() && !self.policy_hash.is_zero());
        let mut encoded = Vec::with_capacity(DCAP_ONBOARDING_CONTEXT_BYTES);
        encoded.push(1);
        encoded.extend_from_slice(&self.chain_id);
        encoded.extend_from_slice(self.genesis_hash.as_slice());
        encoded.extend_from_slice(self.intent_hash.as_slice());
        encoded.extend_from_slice(self.node_id_hash.as_slice());
        encoded.extend_from_slice(self.enclave_id.as_slice());
        encoded.extend_from_slice(self.binding_id.as_slice());
        encoded.extend_from_slice(self.policy_hash.as_slice());
        encoded.extend_from_slice(&self.recipient_x25519);
        encoded.extend_from_slice(&self.tribute_offer_public);
        encoded.extend_from_slice(&self.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.tribute_offer_epoch.to_be_bytes());
        debug_assert_eq!(encoded.len(), DCAP_ONBOARDING_CONTEXT_BYTES);
        encoded
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, DcapRejectCodeV1> {
        if input.len() != DCAP_ONBOARDING_CONTEXT_BYTES {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            intent_hash: B256::from(decoder.array::<32>()?),
            node_id_hash: B256::from(decoder.array::<32>()?),
            enclave_id: B256::from(decoder.array::<32>()?),
            binding_id: B256::from(decoder.array::<32>()?),
            policy_hash: B256::from(decoder.array::<32>()?),
            recipient_x25519: decoder.array()?,
            tribute_offer_public: decoder.array()?,
            key_epoch: decoder.u64()?,
            tribute_offer_epoch: decoder.u64()?,
        };
        decoder.finish()?;
        if value.binding_id.is_zero() || value.policy_hash.is_zero() {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        Ok(value)
    }

    pub fn context_hash(&self) -> B256 {
        let canonical = self.encode_canonical();
        let mut preimage =
            Vec::with_capacity(DCAP_ONBOARDING_CONTEXT_DOMAIN_V1.len() + 4 + canonical.len());
        preimage.extend_from_slice(DCAP_ONBOARDING_CONTEXT_DOMAIN_V1);
        preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&canonical);
        keccak256(preimage)
    }
}

/// Deterministic, purpose-bound ciphertext committed by TeeRegistry. The
/// serialized nonce is transport redundancy only: target ingest must derive
/// the expected nonce from [`DcapOnboardingContextV1::context_hash`] and reject
/// a mismatch before opening the AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapOnboardingArtifactV1 {
    pub context: DcapOnboardingContextV1,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl DcapOnboardingArtifactV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DcapRejectCodeV1> {
        if self.ciphertext.len() < 16
            || self.ciphertext.len()
                > MAX_DCAP_ONBOARDING_ARTIFACT_BYTES - DCAP_ONBOARDING_ARTIFACT_FIXED_BYTES
        {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let ciphertext_len = u16::try_from(self.ciphertext.len())
            .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
        let mut encoded =
            Vec::with_capacity(DCAP_ONBOARDING_ARTIFACT_FIXED_BYTES + self.ciphertext.len());
        encoded.push(1);
        encoded.extend_from_slice(&self.context.encode_canonical());
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&ciphertext_len.to_be_bytes());
        encoded.extend_from_slice(&self.ciphertext);
        Ok(encoded)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, DcapRejectCodeV1> {
        if input.len() < DCAP_ONBOARDING_ARTIFACT_FIXED_BYTES + 16
            || input.len() > MAX_DCAP_ONBOARDING_ARTIFACT_BYTES
        {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let context = DcapOnboardingContextV1::decode_canonical(
            decoder.take(DCAP_ONBOARDING_CONTEXT_BYTES)?,
        )?;
        let nonce = decoder.array()?;
        let ciphertext_len = usize::from(decoder.u16()?);
        if ciphertext_len < 16 {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let ciphertext = decoder.take(ciphertext_len)?.to_vec();
        decoder.finish()?;
        Ok(Self {
            context,
            nonce,
            ciphertext,
        })
    }
}

/// Result returned by the dedicated onboarding verifier. Rejections never
/// carry an artifact; accepted results must carry exactly one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapOnboardingVerificationResultV1 {
    pub outcome: DcapVerificationOutcomeV1,
    pub artifact: Option<DcapOnboardingArtifactV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DcapPckCaV1 {
    Processor = 0x01,
    Platform = 0x02,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DcapPlatformTcbStatusV1 {
    UpToDate = 0x01,
    SWHardeningNeeded = 0x02,
    ConfigurationAndSWHardeningNeeded = 0x03,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapVerdictV1 {
    pub mrenclave: B256,
    pub mrsigner: B256,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub pck_ca: DcapPckCaV1,
    pub fmspc: [u8; 6],
    pub pce_id: u16,
    pub platform_tcb_status: DcapPlatformTcbStatusV1,
    pub advisory_ids: Vec<String>,
    pub tcb_evaluation_data_number: u32,
    pub qe_tcb_evaluation_data_number: u32,
    pub collateral_valid_until: u64,
}

impl DcapVerdictV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DcapRejectCodeV1> {
        let advisory_count = u16::try_from(self.advisory_ids.len())
            .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
        let mut encoded = Vec::new();
        encoded.push(1);
        encoded.extend_from_slice(self.mrenclave.as_slice());
        encoded.extend_from_slice(self.mrsigner.as_slice());
        encoded.extend_from_slice(&self.isv_prod_id.to_be_bytes());
        encoded.extend_from_slice(&self.isv_svn.to_be_bytes());
        encoded.push(self.pck_ca as u8);
        encoded.extend_from_slice(&self.fmspc);
        encoded.extend_from_slice(&self.pce_id.to_be_bytes());
        encoded.push(self.platform_tcb_status as u8);
        encoded.extend_from_slice(&self.tcb_evaluation_data_number.to_be_bytes());
        encoded.extend_from_slice(&self.qe_tcb_evaluation_data_number.to_be_bytes());
        encoded.extend_from_slice(&self.collateral_valid_until.to_be_bytes());
        encoded.extend_from_slice(&advisory_count.to_be_bytes());
        for advisory in &self.advisory_ids {
            validate_advisory(advisory)?;
            let len = u16::try_from(advisory.len())
                .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
            encoded.extend_from_slice(&len.to_be_bytes());
            encoded.extend_from_slice(advisory.as_bytes());
        }
        if encoded.len() > MAX_DCAP_VERDICT_BYTES {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        Ok(encoded)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, DcapRejectCodeV1> {
        if input.len() > MAX_DCAP_VERDICT_BYTES {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let mrenclave = B256::from_slice(decoder.take(32)?);
        let mrsigner = B256::from_slice(decoder.take(32)?);
        let isv_prod_id = decoder.u16()?;
        let isv_svn = decoder.u16()?;
        let pck_ca = match decoder.u8()? {
            0x01 => DcapPckCaV1::Processor,
            0x02 => DcapPckCaV1::Platform,
            _ => return Err(DcapRejectCodeV1::NativeOutputMalformed),
        };
        let fmspc = decoder
            .take(6)?
            .try_into()
            .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
        let pce_id = decoder.u16()?;
        let platform_tcb_status = match decoder.u8()? {
            0x01 => DcapPlatformTcbStatusV1::UpToDate,
            0x02 => DcapPlatformTcbStatusV1::SWHardeningNeeded,
            0x03 => DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded,
            _ => return Err(DcapRejectCodeV1::NativeOutputMalformed),
        };
        let tcb_evaluation_data_number = decoder.u32()?;
        let qe_tcb_evaluation_data_number = decoder.u32()?;
        let collateral_valid_until = decoder.u64()?;
        let advisory_count = usize::from(decoder.u16()?);
        let mut advisory_ids = Vec::with_capacity(advisory_count);
        for _ in 0..advisory_count {
            let len = usize::from(decoder.u16()?);
            let advisory = std::str::from_utf8(decoder.take(len)?)
                .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?
                .to_owned();
            validate_advisory(&advisory)?;
            advisory_ids.push(advisory);
        }
        decoder.finish()?;
        Ok(Self {
            mrenclave,
            mrsigner,
            isv_prod_id,
            isv_svn,
            pck_ca,
            fmspc,
            pce_id,
            platform_tcb_status,
            advisory_ids,
            tcb_evaluation_data_number,
            qe_tcb_evaluation_data_number,
            collateral_valid_until,
        })
    }
}

fn validate_advisory(advisory: &str) -> Result<(), DcapRejectCodeV1> {
    if advisory.is_empty()
        || !advisory
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(DcapRejectCodeV1::NativeOutputMalformed);
    }
    Ok(())
}

/// Stable consensus-visible rejection codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DcapRejectCodeV1 {
    EvidenceNonCanonical = 0x0101,
    PolicyNonCanonical = 0x0102,
    PolicyBindingMismatch = 0x0103,
    TimestampInvalid = 0x0104,
    QuoteMalformed = 0x0201,
    QuoteProfileMismatch = 0x0202,
    QuoteCertificationDataMismatch = 0x0203,
    ReportDataMismatch = 0x0204,
    CollateralNonCanonical = 0x0301,
    IntelRootMismatch = 0x0302,
    PlatformIdentityMismatch = 0x0303,
    CollateralNotYetValid = 0x0304,
    CollateralExpired = 0x0305,
    NativeVerifierUnavailable = 0x0401,
    NativeVerificationFailed = 0x0402,
    NativeOutputMalformed = 0x0403,
    PlatformTcbRejected = 0x0501,
    QeTcbRejected = 0x0502,
    TcbEvaluationNumberTooLow = 0x0503,
    MeasurementRejected = 0x0601,
    OperationMismatch = 0x0701,
    NodeSignatureInvalid = 0x0702,
    EnclaveSignatureInvalid = 0x0703,
    OnboardingContextMismatch = 0x0704,
}

impl DcapRejectCodeV1 {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for DcapRejectCodeV1 {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0101 => Self::EvidenceNonCanonical,
            0x0102 => Self::PolicyNonCanonical,
            0x0103 => Self::PolicyBindingMismatch,
            0x0104 => Self::TimestampInvalid,
            0x0201 => Self::QuoteMalformed,
            0x0202 => Self::QuoteProfileMismatch,
            0x0203 => Self::QuoteCertificationDataMismatch,
            0x0204 => Self::ReportDataMismatch,
            0x0301 => Self::CollateralNonCanonical,
            0x0302 => Self::IntelRootMismatch,
            0x0303 => Self::PlatformIdentityMismatch,
            0x0304 => Self::CollateralNotYetValid,
            0x0305 => Self::CollateralExpired,
            0x0401 => Self::NativeVerifierUnavailable,
            0x0402 => Self::NativeVerificationFailed,
            0x0403 => Self::NativeOutputMalformed,
            0x0501 => Self::PlatformTcbRejected,
            0x0502 => Self::QeTcbRejected,
            0x0503 => Self::TcbEvaluationNumberTooLow,
            0x0601 => Self::MeasurementRejected,
            0x0701 => Self::OperationMismatch,
            0x0702 => Self::NodeSignatureInvalid,
            0x0703 => Self::EnclaveSignatureInvalid,
            0x0704 => Self::OnboardingContextMismatch,
            _ => return Err(()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DcapVerificationOutcomeV1 {
    Accepted(DcapVerdictV1),
    Rejected(DcapRejectCodeV1),
}

impl DcapVerificationOutcomeV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DcapRejectCodeV1> {
        match self {
            Self::Accepted(verdict) => {
                let verdict = verdict.encode_canonical()?;
                let len = u32::try_from(verdict.len())
                    .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
                let mut encoded = Vec::with_capacity(6 + verdict.len());
                encoded.extend_from_slice(&[1, 1]);
                encoded.extend_from_slice(&len.to_be_bytes());
                encoded.extend_from_slice(&verdict);
                Ok(encoded)
            }
            Self::Rejected(code) => Ok(vec![1, 2, (code.code() >> 8) as u8, code.code() as u8]),
        }
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, DcapRejectCodeV1> {
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        let outcome = match decoder.u8()? {
            1 => {
                let len = usize::try_from(decoder.u32()?)
                    .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
                Self::Accepted(DcapVerdictV1::decode_canonical(decoder.take(len)?)?)
            }
            2 => Self::Rejected(
                DcapRejectCodeV1::try_from(decoder.u16()?)
                    .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?,
            ),
            _ => return Err(DcapRejectCodeV1::NativeOutputMalformed),
        };
        decoder.finish()?;
        Ok(outcome)
    }
}

/// Commit to the exact verifier inputs supplied over the authenticated local
/// channel. Length prefixes make the three fields unambiguous.
pub fn dcap_verification_request_hash(
    evidence: &[u8],
    policy: &[u8],
    block_timestamp: u64,
) -> Result<B256, DcapRejectCodeV1> {
    if evidence.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
        return Err(DcapRejectCodeV1::EvidenceNonCanonical);
    }
    if policy.len() > MAX_TEE_POLICY_BYTES {
        return Err(DcapRejectCodeV1::PolicyNonCanonical);
    }
    let evidence_len =
        u32::try_from(evidence.len()).map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    let policy_len =
        u32::try_from(policy.len()).map_err(|_| DcapRejectCodeV1::PolicyNonCanonical)?;
    let mut preimage = Vec::with_capacity(
        DCAP_VERIFICATION_REQUEST_DOMAIN_V1.len() + evidence.len() + policy.len() + 16,
    );
    preimage.extend_from_slice(DCAP_VERIFICATION_REQUEST_DOMAIN_V1);
    preimage.extend_from_slice(&evidence_len.to_be_bytes());
    preimage.extend_from_slice(evidence);
    preimage.extend_from_slice(&policy_len.to_be_bytes());
    preimage.extend_from_slice(policy);
    preimage.extend_from_slice(&block_timestamp.to_be_bytes());
    Ok(keccak256(preimage))
}

/// Commit to the exact purpose-bound onboarding verifier inputs. This is a
/// separate domain from generic evidence verification: possession of an
/// authenticated generic verdict can never authorize offer-key delivery.
#[allow(clippy::too_many_arguments)]
pub fn dcap_onboarding_request_hash(
    evidence: &[u8],
    policy: &[u8],
    block_timestamp: u64,
    node_signature: &[u8; 65],
    enclave_signature: &[u8; 64],
    expected_tribute_offer_public: &[u8; 32],
    key_epoch: u64,
    tribute_offer_epoch: u64,
) -> Result<B256, DcapRejectCodeV1> {
    if evidence.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
        return Err(DcapRejectCodeV1::EvidenceNonCanonical);
    }
    if policy.len() > MAX_TEE_POLICY_BYTES {
        return Err(DcapRejectCodeV1::PolicyNonCanonical);
    }
    let evidence_len =
        u32::try_from(evidence.len()).map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    let policy_len =
        u32::try_from(policy.len()).map_err(|_| DcapRejectCodeV1::PolicyNonCanonical)?;
    let mut preimage = Vec::with_capacity(
        DCAP_ONBOARDING_REQUEST_DOMAIN_V1.len()
            + evidence.len()
            + policy.len()
            + node_signature.len()
            + enclave_signature.len()
            + 69,
    );
    preimage.extend_from_slice(DCAP_ONBOARDING_REQUEST_DOMAIN_V1);
    preimage.push(DCAP_REGISTER_ENCLAVE_OPERATION_V1);
    preimage.extend_from_slice(&evidence_len.to_be_bytes());
    preimage.extend_from_slice(evidence);
    preimage.extend_from_slice(&policy_len.to_be_bytes());
    preimage.extend_from_slice(policy);
    preimage.extend_from_slice(&block_timestamp.to_be_bytes());
    preimage.extend_from_slice(node_signature);
    preimage.extend_from_slice(enclave_signature);
    preimage.extend_from_slice(expected_tribute_offer_public);
    preimage.extend_from_slice(&key_epoch.to_be_bytes());
    preimage.extend_from_slice(&tribute_offer_epoch.to_be_bytes());
    Ok(keccak256(preimage))
}

/// Domain-separated hash of the exact canonical evidence bytes used for
/// current-binding idempotency. A new quote or collateral set is not an exact
/// replay even when it carries the same registration intent.
pub fn dcap_evidence_hash_v1(evidence: &[u8]) -> Result<B256, DcapRejectCodeV1> {
    if evidence.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
        return Err(DcapRejectCodeV1::EvidenceNonCanonical);
    }
    let len = u32::try_from(evidence.len()).map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    let mut preimage = Vec::with_capacity(DCAP_EVIDENCE_DOMAIN_V1.len() + evidence.len() + 4);
    preimage.extend_from_slice(DCAP_EVIDENCE_DOMAIN_V1);
    preimage.extend_from_slice(&len.to_be_bytes());
    preimage.extend_from_slice(evidence);
    Ok(keccak256(preimage))
}

/// Local-only Ed25519 signature preimage binding an enclave outcome to the
/// exact request commitment. It is verified by the node and never enters
/// calldata, state or events.
pub fn dcap_verification_attestation_preimage(
    request_hash: B256,
    outcome: &[u8],
) -> Result<Vec<u8>, DcapRejectCodeV1> {
    if outcome.len() > MAX_DCAP_VERDICT_BYTES + 6 {
        return Err(DcapRejectCodeV1::NativeOutputMalformed);
    }
    let len = u32::try_from(outcome.len()).map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
    let mut preimage =
        Vec::with_capacity(DCAP_VERIFICATION_ATTESTATION_DOMAIN_V1.len() + outcome.len() + 36);
    preimage.extend_from_slice(DCAP_VERIFICATION_ATTESTATION_DOMAIN_V1);
    preimage.extend_from_slice(request_hash.as_slice());
    preimage.extend_from_slice(&len.to_be_bytes());
    preimage.extend_from_slice(outcome);
    Ok(preimage)
}

/// Local-only signature preimage for the purpose-bound onboarding result.
/// Both the verifier outcome and exact deterministic artifact are authenticated
/// by the source enclave's quote-bound Ed25519 key.
pub fn dcap_onboarding_attestation_preimage(
    request_hash: B256,
    outcome: &[u8],
    artifact: &[u8],
) -> Result<Vec<u8>, DcapRejectCodeV1> {
    if outcome.len() > MAX_DCAP_VERDICT_BYTES + 6
        || artifact.len() > MAX_DCAP_ONBOARDING_ARTIFACT_BYTES
    {
        return Err(DcapRejectCodeV1::NativeOutputMalformed);
    }
    let outcome_len =
        u32::try_from(outcome.len()).map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
    let artifact_len =
        u32::try_from(artifact.len()).map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
    let mut preimage = Vec::with_capacity(
        DCAP_ONBOARDING_ATTESTATION_DOMAIN_V1.len() + outcome.len() + artifact.len() + 40,
    );
    preimage.extend_from_slice(DCAP_ONBOARDING_ATTESTATION_DOMAIN_V1);
    preimage.extend_from_slice(request_hash.as_slice());
    preimage.extend_from_slice(&outcome_len.to_be_bytes());
    preimage.extend_from_slice(outcome);
    preimage.extend_from_slice(&artifact_len.to_be_bytes());
    preimage.extend_from_slice(artifact);
    Ok(preimage)
}

struct Decoder<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DcapRejectCodeV1> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(DcapRejectCodeV1::NativeOutputMalformed)?;
        let value = self
            .input
            .get(self.cursor..end)
            .ok_or(DcapRejectCodeV1::NativeOutputMalformed)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, DcapRejectCodeV1> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DcapRejectCodeV1> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, DcapRejectCodeV1> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DcapRejectCodeV1> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DcapRejectCodeV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)
    }

    fn finish(self) -> Result<(), DcapRejectCodeV1> {
        if self.cursor != self.input.len() {
            return Err(DcapRejectCodeV1::NativeOutputMalformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict() -> DcapVerdictV1 {
        DcapVerdictV1 {
            mrenclave: B256::repeat_byte(0x11),
            mrsigner: B256::repeat_byte(0x22),
            isv_prod_id: 7,
            isv_svn: 4,
            pck_ca: DcapPckCaV1::Processor,
            fmspc: [0x33; 6],
            pce_id: 2,
            platform_tcb_status: DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded,
            advisory_ids: vec!["INTEL-SA-00001".to_string()],
            tcb_evaluation_data_number: 19,
            qe_tcb_evaluation_data_number: 18,
            collateral_valid_until: 1_800_000_000,
        }
    }

    #[test]
    fn canonical_outcome_round_trips_and_rejects_trailing_or_unknown_codes() {
        for outcome in [
            DcapVerificationOutcomeV1::Accepted(verdict()),
            DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::PlatformTcbRejected),
        ] {
            let encoded = outcome.encode_canonical().unwrap();
            assert_eq!(
                DcapVerificationOutcomeV1::decode_canonical(&encoded),
                Ok(outcome)
            );
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                DcapVerificationOutcomeV1::decode_canonical(&trailing),
                Err(DcapRejectCodeV1::NativeOutputMalformed)
            );
        }
        assert_eq!(
            DcapVerificationOutcomeV1::decode_canonical(&[1, 2, 0xFF, 0xFF]),
            Err(DcapRejectCodeV1::NativeOutputMalformed)
        );
    }

    #[test]
    fn request_and_evidence_commitments_bind_every_exact_input() {
        let evidence = [0x11, 0x12, 0x13];
        let policy = [0x21, 0x22];
        let timestamp = 1_700_000_000;
        let request = dcap_verification_request_hash(&evidence, &policy, timestamp).unwrap();
        assert_ne!(
            request,
            dcap_verification_request_hash(&[0x11, 0x12, 0x14], &policy, timestamp).unwrap()
        );
        assert_ne!(
            request,
            dcap_verification_request_hash(&evidence, &[0x21, 0x23], timestamp).unwrap()
        );
        assert_ne!(
            request,
            dcap_verification_request_hash(&evidence, &policy, timestamp + 1).unwrap()
        );
        assert_ne!(dcap_evidence_hash_v1(&evidence).unwrap(), B256::ZERO);
        assert_ne!(
            dcap_evidence_hash_v1(&evidence).unwrap(),
            dcap_evidence_hash_v1(&[0x11, 0x12, 0x14]).unwrap()
        );
        let outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::PlatformTcbRejected)
            .encode_canonical()
            .unwrap();
        let preimage = dcap_verification_attestation_preimage(request, &outcome).unwrap();
        assert!(preimage.ends_with(&outcome));
        assert!(preimage
            .windows(32)
            .any(|window| window == request.as_slice()));
    }

    fn onboarding_context() -> DcapOnboardingContextV1 {
        DcapOnboardingContextV1 {
            chain_id: [0x31; 32],
            genesis_hash: B256::repeat_byte(0x32),
            intent_hash: B256::repeat_byte(0x33),
            node_id_hash: B256::repeat_byte(0x34),
            enclave_id: B256::repeat_byte(0x35),
            binding_id: B256::repeat_byte(0x38),
            policy_hash: B256::repeat_byte(0x39),
            recipient_x25519: [0x36; 32],
            tribute_offer_public: [0x37; 32],
            key_epoch: 7,
            tribute_offer_epoch: 8,
        }
    }

    #[test]
    fn onboarding_context_and_artifact_are_canonical_and_bounded() {
        let context = onboarding_context();
        let canonical = context.encode_canonical();
        assert_eq!(
            DcapOnboardingContextV1::decode_canonical(&canonical),
            Ok(context)
        );
        assert_ne!(context.context_hash(), B256::ZERO);

        let artifact = DcapOnboardingArtifactV1 {
            context,
            nonce: [0x41; 12],
            ciphertext: vec![0x42; 112],
        };
        let encoded = artifact.encode_canonical().unwrap();
        assert!(encoded.len() <= MAX_DCAP_ONBOARDING_ARTIFACT_BYTES);
        assert_eq!(
            DcapOnboardingArtifactV1::decode_canonical(&encoded),
            Ok(artifact)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            DcapOnboardingArtifactV1::decode_canonical(&trailing),
            Err(DcapRejectCodeV1::NativeOutputMalformed)
        );
    }

    #[test]
    fn onboarding_request_commitment_binds_signatures_offer_and_epochs() {
        let evidence = [0x51, 0x52];
        let policy = [0x61, 0x62];
        let timestamp = 1_700_000_000;
        let node_signature = [0x71; 65];
        let enclave_signature = [0x72; 64];
        let offer_public = [0x73; 32];
        let request = dcap_onboarding_request_hash(
            &evidence,
            &policy,
            timestamp,
            &node_signature,
            &enclave_signature,
            &offer_public,
            9,
            10,
        )
        .unwrap();

        let mut changed_node_signature = node_signature;
        changed_node_signature[0] ^= 1;
        assert_ne!(
            request,
            dcap_onboarding_request_hash(
                &evidence,
                &policy,
                timestamp,
                &changed_node_signature,
                &enclave_signature,
                &offer_public,
                9,
                10,
            )
            .unwrap()
        );
        assert_ne!(
            request,
            dcap_onboarding_request_hash(
                &evidence,
                &policy,
                timestamp,
                &node_signature,
                &enclave_signature,
                &offer_public,
                9,
                11,
            )
            .unwrap()
        );

        let outcome = DcapVerificationOutcomeV1::Rejected(DcapRejectCodeV1::PlatformTcbRejected)
            .encode_canonical()
            .unwrap();
        let artifact = DcapOnboardingArtifactV1 {
            context: onboarding_context(),
            nonce: [0x74; 12],
            ciphertext: vec![0x75; 112],
        }
        .encode_canonical()
        .unwrap();
        let preimage = dcap_onboarding_attestation_preimage(request, &outcome, &artifact).unwrap();
        assert!(preimage.ends_with(&artifact));
    }
}
