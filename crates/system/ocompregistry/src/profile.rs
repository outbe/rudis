use alloy_primitives::B256;
use outbe_chain_constants::DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS;
use outbe_ocomp_protocol::{
    generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1, profile::CapacityProfileV1, SchemaLimits,
};
use outbe_primitives::error::Result;

use crate::errors::corruption;

const REQUEST_PROFILE_MAGIC: [u8; 4] = *b"OMRP";
const REQUEST_PROFILE_VERSION: u16 = 1;
const REQUEST_PROFILE_FIXED_LEN: usize = 4 + 2 + 8 + 32 * 5 + 4;

/// Network policy used by OCOMP consumers when constructing a fresh job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompRequestProfile {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub protocol_bundle_hash: B256,
    pub correctness_profile_id: B256,
    pub capacity_profile: CapacityProfileV1,
    pub source_availability_policy_id: B256,
}

impl OcompRequestProfile {
    /// Validates the canonical request authority without encoding it.
    pub fn validate(&self) -> Result<()> {
        validate_request_profile(self)
    }

    pub fn encode_canonical(&self, limits: &SchemaLimits) -> Result<Vec<u8>> {
        encode_request_profile(self, limits)
    }

    pub fn decode_canonical(encoded: &[u8], limits: &SchemaLimits) -> Result<Self> {
        decode_request_profile(encoded, limits)
    }
}

#[must_use]
pub fn poc_schema_limits() -> SchemaLimits {
    outbe_ocomp_protocol::profile::poc_schema_limits()
}

pub(crate) fn validate_request_profile(profile: &OcompRequestProfile) -> Result<()> {
    let capacity = &profile.capacity_profile;
    if profile.chain_id == 0
        || profile.genesis_hash.is_zero()
        || profile.fork_id.is_zero()
        || profile.protocol_bundle_hash.is_zero()
        || profile.correctness_profile_id.is_zero()
        || profile.source_availability_policy_id.is_zero()
        || capacity.profile_id.is_zero()
        || capacity.generated_limits_manifest_hash.is_zero()
    {
        return Err(corruption(
            "OCOMP request profile contains a reserved zero identity",
        ));
    }

    let candidate = OCOMP_POC_CANDIDATE_LIMITS_V1;
    let max_tributes_per_work_shard = u32::try_from(candidate.max_tributes_per_work_shard)
        .map_err(|_| corruption("generated unit size exceeds u32"))?;
    let max_reference_currencies = u16::try_from(candidate.max_oracle_openings)
        .map_err(|_| corruption("generated reference-currency cap exceeds u16"))?;
    let max_oracle_entries = u32::try_from(candidate.max_oracle_wwd_pair_entries)
        .map_err(|_| corruption("generated Oracle entry cap exceeds u32"))?;
    let max_active_scurve_entries = u32::try_from(candidate.max_active_scurve_entries)
        .map_err(|_| corruption("generated S-curve entry cap exceeds u32"))?;

    if capacity.max_tributes_per_work_shard != max_tributes_per_work_shard
        || capacity.max_workers_per_domain != 4
        || capacity.max_intents_per_block != 1
        || capacity.max_activations_per_block != 1
        || capacity.max_ready_inspections_per_block != 1
        || capacity.max_expirations_per_block != 1
        || capacity.ready_backoff_blocks != 1
        || capacity.max_reference_currencies == 0
        || capacity.max_reference_currencies > max_reference_currencies
        || capacity.max_oracle_wwd_pair_entries == 0
        || capacity.max_oracle_wwd_pair_entries > max_oracle_entries
        || capacity.max_active_scurve_entries == 0
        || capacity.max_active_scurve_entries > max_active_scurve_entries
        || capacity.result_deadline_blocks == 0
        || capacity.result_deadline_blocks > DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS
        || capacity.source_retention_after_terminal_blocks
            != candidate.source_retention_after_terminal_blocks
    {
        return Err(corruption(
            "OCOMP request profile violates frozen PoC bounds",
        ));
    }
    Ok(())
}

fn encode_request_profile(profile: &OcompRequestProfile, limits: &SchemaLimits) -> Result<Vec<u8>> {
    validate_request_profile(profile)?;
    let capacity = profile
        .capacity_profile
        .encode_canonical(limits)
        .map_err(|error| corruption(format!("encode OCOMP capacity profile: {error}")))?;
    let capacity_len = u32::try_from(capacity.len())
        .map_err(|_| corruption("capacity profile length exceeds u32"))?;
    let total = REQUEST_PROFILE_FIXED_LEN
        .checked_add(capacity.len())
        .ok_or_else(|| corruption("OCOMP request profile length overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total)
        .map_err(|_| corruption("allocate OCOMP request profile"))?;
    encoded.extend_from_slice(&REQUEST_PROFILE_MAGIC);
    encoded.extend_from_slice(&REQUEST_PROFILE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&profile.chain_id.to_be_bytes());
    encoded.extend_from_slice(profile.genesis_hash.as_slice());
    encoded.extend_from_slice(profile.fork_id.as_slice());
    encoded.extend_from_slice(profile.protocol_bundle_hash.as_slice());
    encoded.extend_from_slice(profile.correctness_profile_id.as_slice());
    encoded.extend_from_slice(profile.source_availability_policy_id.as_slice());
    encoded.extend_from_slice(&capacity_len.to_be_bytes());
    encoded.extend_from_slice(&capacity);
    if encoded.len() != total {
        return Err(corruption("OCOMP request profile encoded length mismatch"));
    }
    Ok(encoded)
}

fn decode_request_profile(encoded: &[u8], limits: &SchemaLimits) -> Result<OcompRequestProfile> {
    if encoded.len() < REQUEST_PROFILE_FIXED_LEN {
        return Err(corruption("truncated OCOMP request profile"));
    }
    let mut reader = ProfileReader::new(encoded);
    if reader.take::<4>()? != REQUEST_PROFILE_MAGIC
        || u16::from_be_bytes(reader.take::<2>()?) != REQUEST_PROFILE_VERSION
    {
        return Err(corruption("OCOMP request profile magic/version mismatch"));
    }
    let chain_id = reader.u64()?;
    let genesis_hash = B256::from(reader.take::<32>()?);
    let fork_id = B256::from(reader.take::<32>()?);
    let protocol_bundle_hash = B256::from(reader.take::<32>()?);
    let correctness_profile_id = B256::from(reader.take::<32>()?);
    let source_availability_policy_id = B256::from(reader.take::<32>()?);
    let capacity_len = usize::try_from(reader.u32()?)
        .map_err(|_| corruption("OCOMP capacity profile length exceeds usize"))?;
    if capacity_len != reader.remaining() {
        return Err(corruption("OCOMP capacity profile length mismatch"));
    }
    let capacity_encoded = reader.take_dynamic(capacity_len)?;
    reader.finish()?;
    let capacity_profile = CapacityProfileV1::decode_canonical(capacity_encoded, limits)
        .map_err(|error| corruption(format!("decode OCOMP capacity profile: {error}")))?;
    let profile = OcompRequestProfile {
        chain_id,
        genesis_hash,
        fork_id,
        protocol_bundle_hash,
        correctness_profile_id,
        capacity_profile,
        source_availability_policy_id,
    };
    validate_request_profile(&profile)?;
    if encode_request_profile(&profile, limits)? != encoded {
        return Err(corruption("non-canonical OCOMP request profile encoding"));
    }
    Ok(profile)
}

struct ProfileReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> ProfileReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| corruption("OCOMP request profile offset overflow"))?;
        let bytes = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| corruption("truncated OCOMP request profile"))?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| corruption("invalid OCOMP request profile field width"))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn remaining(&self) -> usize {
        self.encoded.len().saturating_sub(self.offset)
    }

    fn take_dynamic(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| corruption("OCOMP request profile offset overflow"))?;
        let bytes = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| corruption("truncated OCOMP request profile field"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<()> {
        if self.offset == self.encoded.len() {
            Ok(())
        } else {
            Err(corruption("OCOMP request profile has trailing bytes"))
        }
    }
}
