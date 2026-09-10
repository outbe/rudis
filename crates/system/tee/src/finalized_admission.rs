//! Bounded wire proof consumed before a keyless production enclave activates
//! an onboarding artifact.

use alloy_primitives::{keccak256, B256, U256};

use crate::dcap_protocol::{DcapOnboardingContextV1, MAX_DCAP_ONBOARDING_ARTIFACT_BYTES};

pub const MAX_COMMITTEE_TRANSITION_RECORD_BYTES: usize = 128 * 1024;
pub const MAX_FINALIZED_ADMISSION_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// The current Hybrid finalization is below 256 bytes at the maximum committee
/// size. Keep a versioned wire margin without permitting a record-sized opaque
/// certificate allocation.
pub const MAX_FINALIZATION_BYTES: usize = 4 * 1024;
/// A canonical Ethereum header is fixed-size except for Outbe's bounded
/// `extra_data`. The extra margin covers all fixed and optional RLP fields.
pub const MAX_COMPACT_HEADER_BYTES: usize =
    outbe_primitives::consensus::OUTBE_MAX_EXTRA_DATA_SIZE + 4 * 1024;
/// An epoch outcome is transported inside the consensus header's `extra_data`,
/// so a genesis anchor can never legitimately exceed the same protocol cap.
pub const MAX_COMMITTEE_OUTCOME_BYTES: usize =
    outbe_primitives::consensus::OUTBE_MAX_EXTRA_DATA_SIZE;
/// Leaves room for postcard metadata and Noise authentication inside the
/// shared 64 KiB transport frame.
pub const MAX_ONBOARDING_INGEST_CHUNK_BYTES: usize = 60 * 1024;
pub const MAX_MPT_PROOF_NODES: usize = 128;
pub const MAX_MPT_NODE_BYTES: usize = 64 * 1024;
pub const EXACT_REGISTRY_STORAGE_PROOFS: usize = 9;

const ONBOARDING_INGEST_REQUEST_DOMAIN_V1: &[u8] =
    b"outbe/tee/onboarding-artifact-ingest-request/v1";

/// Commits the immutable start of one streaming target-enclave ingest. Every
/// later committee transition is independently authenticated by the current
/// committee, so the transcript does not need to be buffered or pre-hashed.
pub fn onboarding_artifact_ingest_request_hash_v1(
    artifact: &[u8],
    anchor_outcome: &[u8],
    expected_intent_hash: B256,
    expected_tribute_offer_public: [u8; 32],
    expected_key_epoch: u64,
    expected_tribute_offer_epoch: u64,
) -> Result<B256, FinalizedAdmissionCodecError> {
    if artifact.len() > MAX_DCAP_ONBOARDING_ARTIFACT_BYTES
        || anchor_outcome.len() > MAX_COMMITTEE_OUTCOME_BYTES
    {
        return Err(FinalizedAdmissionCodecError::TooLarge);
    }
    let artifact_len =
        u64::try_from(artifact.len()).map_err(|_| FinalizedAdmissionCodecError::TooLarge)?;
    let anchor_len =
        u64::try_from(anchor_outcome.len()).map_err(|_| FinalizedAdmissionCodecError::TooLarge)?;
    let mut preimage = Vec::with_capacity(ONBOARDING_INGEST_REQUEST_DOMAIN_V1.len() + 160);
    preimage.extend_from_slice(ONBOARDING_INGEST_REQUEST_DOMAIN_V1);
    preimage.extend_from_slice(&artifact_len.to_be_bytes());
    preimage.extend_from_slice(keccak256(artifact).as_slice());
    preimage.extend_from_slice(&anchor_len.to_be_bytes());
    preimage.extend_from_slice(keccak256(anchor_outcome).as_slice());
    preimage.extend_from_slice(expected_intent_hash.as_slice());
    preimage.extend_from_slice(&expected_tribute_offer_public);
    preimage.extend_from_slice(&expected_key_epoch.to_be_bytes());
    preimage.extend_from_slice(&expected_tribute_offer_epoch.to_be_bytes());
    Ok(keccak256(preimage))
}

// Physical EVM slots, centralized here and checked against the generated
// TeeRegistry accessors by the teeregistry test suite.
pub const TEE_REGISTRY_OFFER_PUBLIC_SLOT_V1: u64 = 1;
pub const TEE_REGISTRY_KEY_EPOCH_SLOT_V1: u64 = 3;
pub const TEE_REGISTRY_OFFER_EPOCH_SLOT_V1: u64 = 4;
pub const TEE_REGISTRY_NODE_ENCLAVE_ID_SLOT_V1: u64 = 14;
pub const TEE_REGISTRY_NODE_BINDING_ID_SLOT_V1: u64 = 16;
pub const TEE_REGISTRY_NODE_INTENT_HASH_SLOT_V1: u64 = 18;
pub const TEE_REGISTRY_NODE_POLICY_HASH_SLOT_V1: u64 = 19;
pub const TEE_REGISTRY_NODE_VALID_UNTIL_SLOT_V1: u64 = 24;
pub const TEE_REGISTRY_NODE_RECIPIENT_X25519_SLOT_V1: u64 = 26;

#[must_use]
pub fn onboarding_registry_slots_v1(context: &DcapOnboardingContextV1) -> [B256; 9] {
    let direct = |slot: u64| B256::from(U256::from(slot).to_be_bytes::<32>());
    let mapped = |slot: u64| {
        let mut preimage = [0_u8; 64];
        preimage[..32].copy_from_slice(context.node_id_hash.as_slice());
        preimage[32..].copy_from_slice(&U256::from(slot).to_be_bytes::<32>());
        keccak256(preimage)
    };
    [
        direct(TEE_REGISTRY_OFFER_PUBLIC_SLOT_V1),
        direct(TEE_REGISTRY_KEY_EPOCH_SLOT_V1),
        direct(TEE_REGISTRY_OFFER_EPOCH_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_ENCLAVE_ID_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_BINDING_ID_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_INTENT_HASH_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_POLICY_HASH_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_VALID_UNTIL_SLOT_V1),
        mapped(TEE_REGISTRY_NODE_RECIPIENT_X25519_SLOT_V1),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedHeaderV1 {
    pub finalization: Vec<u8>,
    pub header: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinalizedAdmissionRecordKindV1 {
    CommitteeTransition,
    Admission,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MptAccountProofV1 {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub storage_root: B256,
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MptStorageProofV1 {
    pub key: B256,
    pub value: U256,
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedAdmissionWitnessV1 {
    /// Finalized block whose state root authenticates the Registry opening.
    pub admission: CertifiedHeaderV1,
    pub registry_account: MptAccountProofV1,
    pub registry_storage: Vec<MptStorageProofV1>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FinalizedAdmissionCodecError {
    #[error("finalized admission proof exceeds its byte cap")]
    TooLarge,
    #[error("finalized admission proof is malformed: {0}")]
    Malformed(&'static str),
}

impl CertifiedHeaderV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FinalizedAdmissionCodecError> {
        let mut out = Vec::new();
        out.push(1);
        put_certified_header(&mut out, self)?;
        if out.len() > MAX_COMMITTEE_TRANSITION_RECORD_BYTES {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, FinalizedAdmissionCodecError> {
        if input.len() > MAX_COMMITTEE_TRANSITION_RECORD_BYTES {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(FinalizedAdmissionCodecError::Malformed("version"));
        }
        let value = decoder.certified_header()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl FinalizedAdmissionWitnessV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FinalizedAdmissionCodecError> {
        if self.registry_storage.len() != EXACT_REGISTRY_STORAGE_PROOFS {
            return Err(FinalizedAdmissionCodecError::Malformed(
                "registry proof count",
            ));
        }
        let mut out = Vec::new();
        out.push(1);
        put_certified_header(&mut out, &self.admission)?;
        put_account(&mut out, &self.registry_account)?;
        put_u16(&mut out, self.registry_storage.len())?;
        for proof in &self.registry_storage {
            out.extend_from_slice(proof.key.as_slice());
            out.extend_from_slice(&proof.value.to_be_bytes::<32>());
            put_nodes(&mut out, &proof.nodes)?;
        }
        if out.len() > MAX_FINALIZED_ADMISSION_RECORD_BYTES {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, FinalizedAdmissionCodecError> {
        if input.len() > MAX_FINALIZED_ADMISSION_RECORD_BYTES {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        let mut decoder = Decoder::new(input);
        if decoder.u8()? != 1 {
            return Err(FinalizedAdmissionCodecError::Malformed("version"));
        }
        let admission = decoder.certified_header()?;
        let registry_account = decoder.account()?;
        let storage_count = decoder.count(EXACT_REGISTRY_STORAGE_PROOFS)?;
        if storage_count != EXACT_REGISTRY_STORAGE_PROOFS {
            return Err(FinalizedAdmissionCodecError::Malformed(
                "registry proof count",
            ));
        }
        let mut registry_storage = Vec::with_capacity(storage_count);
        for _ in 0..storage_count {
            registry_storage.push(MptStorageProofV1 {
                key: B256::from(decoder.array::<32>()?),
                value: U256::from_be_bytes(decoder.array::<32>()?),
                nodes: decoder.nodes()?,
            });
        }
        decoder.finish()?;
        Ok(Self {
            admission,
            registry_account,
            registry_storage,
        })
    }
}

fn put_certified_header(
    out: &mut Vec<u8>,
    proof: &CertifiedHeaderV1,
) -> Result<(), FinalizedAdmissionCodecError> {
    validate_certified_header_fields(&proof.finalization, &proof.header)?;
    put_bytes(out, &proof.finalization)?;
    put_bytes(out, &proof.header)
}

fn validate_certified_header_fields(
    finalization: &[u8],
    header: &[u8],
) -> Result<(), FinalizedAdmissionCodecError> {
    if finalization.is_empty() || header.is_empty() {
        return Err(FinalizedAdmissionCodecError::Malformed(
            "empty certified header field",
        ));
    }
    if finalization.len() > MAX_FINALIZATION_BYTES || header.len() > MAX_COMPACT_HEADER_BYTES {
        return Err(FinalizedAdmissionCodecError::TooLarge);
    }
    Ok(())
}

fn put_account(
    out: &mut Vec<u8>,
    proof: &MptAccountProofV1,
) -> Result<(), FinalizedAdmissionCodecError> {
    out.extend_from_slice(&proof.nonce.to_be_bytes());
    out.extend_from_slice(&proof.balance.to_be_bytes::<32>());
    out.extend_from_slice(proof.code_hash.as_slice());
    out.extend_from_slice(proof.storage_root.as_slice());
    put_nodes(out, &proof.nodes)
}

fn put_nodes(out: &mut Vec<u8>, nodes: &[Vec<u8>]) -> Result<(), FinalizedAdmissionCodecError> {
    if nodes.len() > MAX_MPT_PROOF_NODES {
        return Err(FinalizedAdmissionCodecError::TooLarge);
    }
    put_u16(out, nodes.len())?;
    for node in nodes {
        if node.len() > MAX_MPT_NODE_BYTES {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        put_bytes(out, node)?;
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FinalizedAdmissionCodecError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FinalizedAdmissionCodecError::TooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, value: usize) -> Result<(), FinalizedAdmissionCodecError> {
    out.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| FinalizedAdmissionCodecError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn certified_header(&mut self) -> Result<CertifiedHeaderV1, FinalizedAdmissionCodecError> {
        let finalization = self.bytes()?;
        let header = self.bytes()?;
        validate_certified_header_fields(finalization, header)?;
        Ok(CertifiedHeaderV1 {
            finalization: finalization.to_vec(),
            header: header.to_vec(),
        })
    }

    fn account(&mut self) -> Result<MptAccountProofV1, FinalizedAdmissionCodecError> {
        Ok(MptAccountProofV1 {
            nonce: u64::from_be_bytes(self.array()?),
            balance: U256::from_be_bytes(self.array::<32>()?),
            code_hash: B256::from(self.array::<32>()?),
            storage_root: B256::from(self.array::<32>()?),
            nodes: self.nodes()?,
        })
    }

    fn nodes(&mut self) -> Result<Vec<Vec<u8>>, FinalizedAdmissionCodecError> {
        let count = self.count(MAX_MPT_PROOF_NODES)?;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let node = self.bytes()?;
            if node.len() > MAX_MPT_NODE_BYTES {
                return Err(FinalizedAdmissionCodecError::TooLarge);
            }
            nodes.push(node.to_vec());
        }
        Ok(nodes)
    }

    fn bytes(&mut self) -> Result<&'a [u8], FinalizedAdmissionCodecError> {
        let len = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| FinalizedAdmissionCodecError::TooLarge)?;
        self.take(len)
    }

    fn count(&mut self, max: usize) -> Result<usize, FinalizedAdmissionCodecError> {
        let count = usize::from(u16::from_be_bytes(self.array()?));
        if count > max {
            return Err(FinalizedAdmissionCodecError::TooLarge);
        }
        Ok(count)
    }

    fn u8(&mut self) -> Result<u8, FinalizedAdmissionCodecError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FinalizedAdmissionCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| FinalizedAdmissionCodecError::Malformed("fixed field"))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FinalizedAdmissionCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FinalizedAdmissionCodecError::TooLarge)?;
        if end > self.input.len() {
            return Err(FinalizedAdmissionCodecError::Malformed("truncated field"));
        }
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), FinalizedAdmissionCodecError> {
        if self.offset != self.input.len() {
            return Err(FinalizedAdmissionCodecError::Malformed("trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> FinalizedAdmissionWitnessV1 {
        FinalizedAdmissionWitnessV1 {
            admission: CertifiedHeaderV1 {
                finalization: vec![7],
                header: vec![8],
            },
            registry_account: MptAccountProofV1 {
                nonce: 9,
                balance: U256::from(10),
                code_hash: B256::repeat_byte(11),
                storage_root: B256::repeat_byte(12),
                nodes: vec![vec![13]],
            },
            registry_storage: (0..EXACT_REGISTRY_STORAGE_PROOFS)
                .map(|index| MptStorageProofV1 {
                    key: B256::with_last_byte(index as u8),
                    value: U256::from(15),
                    nodes: vec![vec![16]],
                })
                .collect(),
        }
    }

    #[test]
    fn canonical_round_trip_and_trailing_rejection() {
        let proof = fixture();
        let encoded = proof.encode_canonical().unwrap();
        assert_eq!(
            FinalizedAdmissionWitnessV1::decode_canonical(&encoded).unwrap(),
            proof
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            FinalizedAdmissionWitnessV1::decode_canonical(&trailing).unwrap_err(),
            FinalizedAdmissionCodecError::Malformed("trailing bytes")
        );
    }

    #[test]
    fn compact_certified_header_is_canonical_and_field_bounded() {
        let header = CertifiedHeaderV1 {
            finalization: vec![0x31, 0x32],
            header: vec![0x41, 0x42],
        };
        let encoded = header.encode_canonical().unwrap();
        assert_eq!(CertifiedHeaderV1::decode_canonical(&encoded), Ok(header));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            CertifiedHeaderV1::decode_canonical(&trailing),
            Err(FinalizedAdmissionCodecError::Malformed("trailing bytes"))
        );

        for malformed in [
            CertifiedHeaderV1 {
                finalization: Vec::new(),
                header: vec![1],
            },
            CertifiedHeaderV1 {
                finalization: vec![1],
                header: Vec::new(),
            },
        ] {
            assert_eq!(
                malformed.encode_canonical(),
                Err(FinalizedAdmissionCodecError::Malformed(
                    "empty certified header field"
                ))
            );
        }

        assert_eq!(
            CertifiedHeaderV1 {
                finalization: vec![0; MAX_FINALIZATION_BYTES + 1],
                header: vec![1],
            }
            .encode_canonical(),
            Err(FinalizedAdmissionCodecError::TooLarge)
        );
        assert_eq!(
            CertifiedHeaderV1 {
                finalization: vec![1],
                header: vec![0; MAX_COMPACT_HEADER_BYTES + 1],
            }
            .encode_canonical(),
            Err(FinalizedAdmissionCodecError::TooLarge)
        );
    }

    #[test]
    fn admission_witness_applies_compact_header_field_caps() {
        let mut witness = fixture();
        witness.admission.finalization = vec![0; MAX_FINALIZATION_BYTES + 1];
        assert_eq!(
            witness.encode_canonical(),
            Err(FinalizedAdmissionCodecError::TooLarge)
        );

        let mut witness = fixture();
        witness.admission.header = vec![0; MAX_COMPACT_HEADER_BYTES + 1];
        assert_eq!(
            witness.encode_canonical(),
            Err(FinalizedAdmissionCodecError::TooLarge)
        );
    }

    #[test]
    fn ingest_commitment_binds_every_byte_string_and_expected_value() {
        let artifact = [0x21, 0x22];
        let anchor = [0x31, 0x32, 0x33];
        let intent = B256::repeat_byte(0x41);
        let offer = [0x51; 32];
        let original =
            onboarding_artifact_ingest_request_hash_v1(&artifact, &anchor, intent, offer, 6, 7)
                .unwrap();

        let mut changed_artifact = artifact;
        changed_artifact[0] ^= 1;
        let mut changed_anchor = anchor;
        changed_anchor[0] ^= 1;
        let mutations = [
            onboarding_artifact_ingest_request_hash_v1(
                &changed_artifact,
                &anchor,
                intent,
                offer,
                6,
                7,
            )
            .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(
                &artifact,
                &changed_anchor,
                intent,
                offer,
                6,
                7,
            )
            .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(
                &artifact,
                &anchor,
                B256::repeat_byte(0x42),
                offer,
                6,
                7,
            )
            .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(
                &artifact, &anchor, intent, [0x52; 32], 6, 7,
            )
            .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(&artifact, &anchor, intent, offer, 8, 7)
                .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(&artifact, &anchor, intent, offer, 6, 8)
                .unwrap(),
            onboarding_artifact_ingest_request_hash_v1(
                &[artifact[0]],
                &anchor,
                intent,
                offer,
                6,
                7,
            )
            .unwrap(),
        ];
        assert!(mutations.into_iter().all(|hash| hash != original));
        assert_eq!(
            onboarding_artifact_ingest_request_hash_v1(
                &artifact,
                &vec![0; MAX_COMMITTEE_OUTCOME_BYTES + 1],
                intent,
                offer,
                6,
                7,
            ),
            Err(FinalizedAdmissionCodecError::TooLarge)
        );
    }
}
