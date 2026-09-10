use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    control::{FinalizedJobSpecV1, FinalizedJobSummaryV1, SnapshotExportCommittedV1},
    ProtocolError, SchemaLimits,
};
use thiserror::Error;

const OFFER_MAGIC: [u8; 8] = *b"OUTBDOR1";
const ACK_MAGIC: [u8; 8] = *b"OUTBDAR1";
const OBSERVATION_DOMAIN: &[u8] = b"outbe.ocomp.discovery.observation.v1";

pub const DISCOVERY_CONTROL_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryOfferRefV1 {
    pub version: u16,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub observation_id: B256,
    pub generation: u64,
    pub discovery_record_digest: B256,
}

impl DiscoveryOfferRefV1 {
    pub const FIXED_BYTES: usize = 8 + 2 + 8 + 32 + 32 + 8 + 32;

    pub fn from_spec(
        chain_id: u64,
        genesis_hash: B256,
        generation: u64,
        spec: &FinalizedJobSpecV1,
        limits: &SchemaLimits,
    ) -> Result<Self, DiscoveryControlError> {
        let canonical = spec.encode_body(limits)?;
        let reference = Self {
            version: DISCOVERY_CONTROL_VERSION_V1,
            chain_id,
            genesis_hash,
            observation_id: observation_id(chain_id, genesis_hash, &spec.summary),
            generation,
            discovery_record_digest: keccak256(canonical),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn encode_fixed(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::FIXED_BYTES);
        encoded.extend_from_slice(&OFFER_MAGIC);
        encode_offer_fields(&mut encoded, self);
        encoded
    }

    pub fn decode_fixed(encoded: &[u8]) -> Result<Self, DiscoveryControlError> {
        if encoded.len() != Self::FIXED_BYTES || encoded[..8] != OFFER_MAGIC {
            return Err(DiscoveryControlError::InvalidOfferRef);
        }
        let reference = decode_offer_fields(encoded, 8)?;
        reference.validate()?;
        if reference.encode_fixed() != encoded {
            return Err(DiscoveryControlError::InvalidOfferRef);
        }
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), DiscoveryControlError> {
        if self.version != DISCOVERY_CONTROL_VERSION_V1 {
            return Err(DiscoveryControlError::UnsupportedVersion(self.version));
        }
        if self.chain_id == 0
            || self.genesis_hash.is_zero()
            || self.observation_id.is_zero()
            || self.generation == 0
            || self.discovery_record_digest.is_zero()
        {
            return Err(DiscoveryControlError::InvalidOfferRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryAckRefV1 {
    pub version: u16,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub observation_id: B256,
    pub generation: u64,
    pub discovery_record_digest: B256,
    pub export_receipt_digest: B256,
}

impl DiscoveryAckRefV1 {
    pub const FIXED_BYTES: usize = DiscoveryOfferRefV1::FIXED_BYTES + 32;

    pub fn from_committed(
        offer: &DiscoveryOfferRefV1,
        committed: &SnapshotExportCommittedV1,
        export_receipt_digest: B256,
        limits: &SchemaLimits,
    ) -> Result<Self, DiscoveryControlError> {
        offer.validate()?;
        committed.encode_body(limits)?;
        let reference = Self {
            version: offer.version,
            chain_id: offer.chain_id,
            genesis_hash: offer.genesis_hash,
            observation_id: offer.observation_id,
            generation: offer.generation,
            discovery_record_digest: offer.discovery_record_digest,
            export_receipt_digest,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn offer_ref(&self) -> DiscoveryOfferRefV1 {
        DiscoveryOfferRefV1 {
            version: self.version,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            observation_id: self.observation_id,
            generation: self.generation,
            discovery_record_digest: self.discovery_record_digest,
        }
    }

    pub fn encode_fixed(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::FIXED_BYTES);
        encoded.extend_from_slice(&ACK_MAGIC);
        encode_offer_fields(&mut encoded, &self.offer_ref());
        encoded.extend_from_slice(self.export_receipt_digest.as_slice());
        encoded
    }

    pub fn decode_fixed(encoded: &[u8]) -> Result<Self, DiscoveryControlError> {
        if encoded.len() != Self::FIXED_BYTES || encoded[..8] != ACK_MAGIC {
            return Err(DiscoveryControlError::InvalidAckRef);
        }
        let offer = decode_offer_fields(encoded, 8)?;
        let export_receipt_digest = read_b256(encoded, DiscoveryOfferRefV1::FIXED_BYTES)?;
        let reference = Self {
            version: offer.version,
            chain_id: offer.chain_id,
            genesis_hash: offer.genesis_hash,
            observation_id: offer.observation_id,
            generation: offer.generation,
            discovery_record_digest: offer.discovery_record_digest,
            export_receipt_digest,
        };
        reference.validate()?;
        if reference.encode_fixed() != encoded {
            return Err(DiscoveryControlError::InvalidAckRef);
        }
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), DiscoveryControlError> {
        self.offer_ref().validate()?;
        if self.export_receipt_digest.is_zero() {
            return Err(DiscoveryControlError::InvalidAckRef);
        }
        Ok(())
    }
}

#[must_use]
pub fn observation_id(chain_id: u64, genesis_hash: B256, summary: &FinalizedJobSummaryV1) -> B256 {
    let mut preimage = Vec::with_capacity(OBSERVATION_DOMAIN.len() + 8 + 32 * 2 + 8);
    preimage.extend_from_slice(OBSERVATION_DOMAIN);
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(genesis_hash.as_slice());
    preimage.extend_from_slice(&summary.cursor.to_be_bytes());
    preimage.extend_from_slice(summary.intent_id.as_slice());
    keccak256(preimage)
}

fn encode_offer_fields(encoded: &mut Vec<u8>, reference: &DiscoveryOfferRefV1) {
    encoded.extend_from_slice(&reference.version.to_be_bytes());
    encoded.extend_from_slice(&reference.chain_id.to_be_bytes());
    encoded.extend_from_slice(reference.genesis_hash.as_slice());
    encoded.extend_from_slice(reference.observation_id.as_slice());
    encoded.extend_from_slice(&reference.generation.to_be_bytes());
    encoded.extend_from_slice(reference.discovery_record_digest.as_slice());
}

fn decode_offer_fields(
    encoded: &[u8],
    start: usize,
) -> Result<DiscoveryOfferRefV1, DiscoveryControlError> {
    Ok(DiscoveryOfferRefV1 {
        version: read_u16(encoded, start)?,
        chain_id: read_u64(encoded, start + 2)?,
        genesis_hash: read_b256(encoded, start + 10)?,
        observation_id: read_b256(encoded, start + 42)?,
        generation: read_u64(encoded, start + 74)?,
        discovery_record_digest: read_b256(encoded, start + 82)?,
    })
}

fn read_u16(encoded: &[u8], start: usize) -> Result<u16, DiscoveryControlError> {
    encoded
        .get(start..start + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(DiscoveryControlError::InvalidEncoding)
}

fn read_u64(encoded: &[u8], start: usize) -> Result<u64, DiscoveryControlError> {
    encoded
        .get(start..start + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(DiscoveryControlError::InvalidEncoding)
}

fn read_b256(encoded: &[u8], start: usize) -> Result<B256, DiscoveryControlError> {
    encoded
        .get(start..start + 32)
        .map(B256::from_slice)
        .ok_or(DiscoveryControlError::InvalidEncoding)
}

#[derive(Debug, Error)]
pub enum DiscoveryControlError {
    #[error("unsupported discovery control version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid discovery offer reference")]
    InvalidOfferRef,
    #[error("invalid discovery acknowledgement reference")]
    InvalidAckRef,
    #[error("invalid discovery control encoding")]
    InvalidEncoding,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}
