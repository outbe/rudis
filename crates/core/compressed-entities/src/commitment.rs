use alloy_primitives::{Address, B256, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::WwdEntityId;

pub const CES1_TAG_BASE: u64 = 0x4345_5331_0000_0000;
pub const TAG_BYTES_INIT: u64 = CES1_TAG_BASE + 1;
pub const TAG_BYTES_ABSORB: u64 = CES1_TAG_BASE + 2;
pub const TAG_BYTES_FINAL: u64 = CES1_TAG_BASE + 3;
pub const TAG_ID: u64 = CES1_TAG_BASE + 4;
pub const TAG_KEY: u64 = CES1_TAG_BASE + 5;
pub const TAG_BODY: u64 = CES1_TAG_BASE + 6;
pub const TAG_LEAF: u64 = CES1_TAG_BASE + 7;
pub const TAG_SMT_BASE: u64 = CES1_TAG_BASE + 8;
pub const TAG_SMT_NORMAL: u64 = CES1_TAG_BASE + 9;
pub const TAG_SMT_ZERO: u64 = CES1_TAG_BASE + 10;
pub const TAG_TOP_NODE: u64 = CES1_TAG_BASE + 11;
pub const TAG_SEALED_ROOT: u64 = CES1_TAG_BASE + 12;
pub const TAG_COLLECTION_KEY: u64 = CES1_TAG_BASE + 13;
pub const TAG_COLLECTION_ROOT: u64 = CES1_TAG_BASE + 14;
pub const ACTIVE_COMMITMENT_SCHEME: u32 = 1;

/// Canonical non-zero BN254 body leaf.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Commitment([u8; 32]);

impl Commitment {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0_u8; 32]
    }

    #[must_use]
    pub fn to_u256(self) -> U256 {
        U256::from_be_bytes(self.0)
    }
}

impl TryFrom<[u8; 32]> for Commitment {
    type Error = CommitmentError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        if bytes == [0_u8; 32] {
            return Err(CommitmentError::ZeroPresentLeaf);
        }
        let field = Fr::from_be_bytes_mod_order(&bytes);
        if field_to_be32(field) != bytes {
            return Err(CommitmentError::NonCanonicalFieldElement);
        }
        Ok(Self(bytes))
    }
}

/// The full Poseidon digest of `(owner, worldwide_day)`.
///
/// [`derive_poseidon_entity_id`] keeps only its last 28 bytes, so a caller that
/// has to check the whole digest - verifying an enclave-returned token id, for
/// one - must take it from here and not from the identity.
pub fn derive_poseidon_digest(
    owner: Address,
    worldwide_day: WorldwideDay,
) -> Result<B256, CommitmentError> {
    let mut hasher = Poseidon::<Fr>::new_circom(2)
        .map_err(|error| CommitmentError::Poseidon(error.to_string()))?;
    let digest = hasher
        .hash(&[
            Fr::from_be_bytes_mod_order(owner.as_slice()),
            Fr::from(worldwide_day.value()),
        ])
        .map_err(|error| CommitmentError::Poseidon(error.to_string()))?;
    Ok(B256::from(field_to_be32(digest)))
}

/// Derives the Poseidon digest from `(owner, worldwide_day)` and prefixes WWD BE4.
pub fn derive_poseidon_entity_id(
    owner: Address,
    worldwide_day: WorldwideDay,
) -> Result<WwdEntityId, CommitmentError> {
    Ok(WwdEntityId::from_day_and_digest(
        worldwide_day,
        derive_poseidon_digest(owner, worldwide_day)?,
    ))
}

/// Derives the canonical field input from the exact 32-byte identity.
pub fn identity_field(identity: WwdEntityId) -> Result<[u8; 32], CommitmentError> {
    pbytes(TAG_ID, identity.as_slice())
}

/// Computes the active CES1 leaf for a canonical typed payload.
pub fn body_commitment(
    commitment_scheme_version: u32,
    schema_version: u32,
    identity: WwdEntityId,
    canonical_payload: &[u8],
) -> Result<Commitment, CommitmentError> {
    if commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME {
        return Err(CommitmentError::UnsupportedCommitmentScheme {
            actual: commitment_scheme_version,
        });
    }
    if schema_version != crate::BODY_SCHEMA_V1 {
        return Err(CommitmentError::UnsupportedSchema {
            actual: schema_version,
        });
    }
    if canonical_payload.is_empty() {
        return Err(CommitmentError::EmptyPayload);
    }
    let payload_len =
        u64::try_from(canonical_payload.len()).map_err(|_| CommitmentError::InputTooLong)?;
    let identity_f = Fr::from_be_bytes_mod_order(&identity_field(identity)?);
    let body_f = Fr::from_be_bytes_mod_order(&pbytes(TAG_BODY, canonical_payload)?);
    let leaf = poseidon(
        TAG_LEAF,
        &[
            Fr::from(commitment_scheme_version),
            Fr::from(schema_version),
            identity_f,
            Fr::from(payload_len),
            body_f,
        ],
    )?;
    Commitment::try_from(field_to_be32(leaf))
}

/// Hashes arbitrary bytes using the only CES1 byte-to-field conversion.
pub fn pbytes(object_tag: u64, bytes: &[u8]) -> Result<[u8; 32], CommitmentError> {
    let byte_len = u64::try_from(bytes.len()).map_err(|_| CommitmentError::InputTooLong)?;
    let chunk_count =
        u64::try_from(bytes.chunks(31).len()).map_err(|_| CommitmentError::InputTooLong)?;
    let mut state = poseidon(
        TAG_BYTES_INIT,
        &[
            Fr::from(object_tag),
            Fr::from(byte_len),
            Fr::from(chunk_count),
        ],
    )?;

    for (index, chunk) in bytes.chunks(31).enumerate() {
        let index = u64::try_from(index).map_err(|_| CommitmentError::InputTooLong)?;
        state = poseidon(
            TAG_BYTES_ABSORB,
            &[
                Fr::from(object_tag),
                state,
                Fr::from(index),
                chunk_to_field(chunk),
            ],
        )?;
    }

    poseidon(
        TAG_BYTES_FINAL,
        &[
            Fr::from(object_tag),
            Fr::from(byte_len),
            Fr::from(chunk_count),
            state,
        ],
    )
    .map(field_to_be32)
}

fn chunk_to_field(chunk: &[u8]) -> Fr {
    debug_assert!(chunk.len() <= 31);
    let mut padded = [0_u8; 32];
    padded[1..1 + chunk.len()].copy_from_slice(chunk);
    Fr::from_be_bytes_mod_order(&padded)
}

pub(crate) fn poseidon(tag: u64, inputs: &[Fr]) -> Result<Fr, CommitmentError> {
    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(tag))
        .map_err(|error| CommitmentError::Poseidon(error.to_string()))?;
    hasher
        .hash(inputs)
        .map_err(|error| CommitmentError::Poseidon(error.to_string()))
}

pub(crate) fn field_to_be32(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}

/// Deterministic CES1 commitment construction failure.
#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("byte input length is not representable as u64")]
    InputTooLong,
    #[error("Poseidon-BN254 failure: {0}")]
    Poseidon(String),
    #[error("unsupported commitment scheme version {actual}")]
    UnsupportedCommitmentScheme { actual: u32 },
    #[error("unsupported body schema version {actual}")]
    UnsupportedSchema { actual: u32 },
    #[error("canonical payload must not be empty")]
    EmptyPayload,
    #[error("present body commitment computed to zero")]
    ZeroPresentLeaf,
    #[error("value is not a canonical BN254 scalar field element")]
    NonCanonicalFieldElement,
}
