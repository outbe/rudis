use alloy_primitives::B256;
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::{
    constants::MAX_RECORDS_KEPT, errors::storage_corruption_message, schema::MetadosisContract,
};

use super::{
    codec::FixedReader,
    state::{DayPhase, JobFsmProjection},
};

const READY_INDEX_MAGIC: [u8; 4] = *b"OMRI";
const READY_INDEX_VERSION: u16 = 1;
const READY_INDEX_HEADER_LEN: usize = 4 + 2 + 2;
const READY_INDEX_KEY_LEN: usize = 8 + 4 + 8;
const RESPONSE_INDEX_MAGIC: [u8; 4] = *b"OMDI";
const RESPONSE_INDEX_VERSION: u16 = 1;
const RESPONSE_INDEX_HEADER_LEN: usize = 4 + 2 + 2;
const RESPONSE_INDEX_KEY_LEN: usize = 8 + 32 + 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ReadyIndexKey {
    pub(crate) next_check_height: u64,
    pub(crate) worldwide_day: WorldwideDay,
    pub(crate) pending_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ResponseDeadlineKey {
    pub(crate) deadline_height: u64,
    pub(crate) job_id: B256,
    pub(crate) intent_id: B256,
}

impl ReadyIndexKey {
    pub(super) fn from_projection(projection: JobFsmProjection) -> Result<Self> {
        if projection.phase != DayPhase::Ready
            || projection.live_intent_id.is_some()
            || projection.deadline_height.is_some()
        {
            return Err(storage_corruption_message(
                "OCOMP READY index received a non-READY FSM state",
            ));
        }
        Ok(Self {
            next_check_height: projection
                .next_check_height
                .ok_or_else(|| storage_corruption_message("OCOMP READY state has no due height"))?,
            worldwide_day: projection.worldwide_day,
            pending_nonce: projection.pending_nonce,
        })
    }
}

impl MetadosisContract<'_> {
    pub(crate) fn read_ready_index(&self) -> Result<Vec<ReadyIndexKey>> {
        decode_ready_index(&self.ocomp_ready_index.read()?)
    }

    pub(super) fn write_ready_index(&self, index: &[ReadyIndexKey]) -> Result<()> {
        if index.is_empty() {
            return self.ocomp_ready_index.clear();
        }
        self.ocomp_ready_index.write(&encode_ready_index(index)?)
    }

    pub(crate) fn read_response_deadline_index(&self) -> Result<Vec<ResponseDeadlineKey>> {
        decode_response_deadline_index(&self.ocomp_response_deadline_index.read()?)
    }

    pub(crate) fn write_response_deadline_index(
        &self,
        index: &[ResponseDeadlineKey],
    ) -> Result<()> {
        if index.is_empty() {
            return self.ocomp_response_deadline_index.clear();
        }
        self.ocomp_response_deadline_index
            .write(&encode_response_deadline_index(index)?)
    }

    pub(crate) fn response_window_for_job(
        &self,
        job_id: B256,
    ) -> Result<Option<ResponseDeadlineKey>> {
        Ok(self
            .read_response_deadline_index()?
            .into_iter()
            .find(|key| key.job_id == job_id))
    }
}

pub(super) fn insert_ready_key(index: &mut Vec<ReadyIndexKey>, key: ReadyIndexKey) -> Result<()> {
    if index
        .iter()
        .any(|existing| existing.worldwide_day == key.worldwide_day)
    {
        return Err(storage_corruption_message(
            "OCOMP READY index already contains the WWD",
        ));
    }
    if index.len() >= MAX_RECORDS_KEPT {
        return Err(storage_corruption_message(
            "OCOMP READY index capacity exhausted",
        ));
    }
    let position = index
        .binary_search(&key)
        .unwrap_or_else(|position| position);
    index.insert(position, key);
    validate_ready_index(index)
}

pub(super) fn remove_ready_key(index: &mut Vec<ReadyIndexKey>, key: ReadyIndexKey) -> Result<()> {
    let position = index.binary_search(&key).map_err(|_| {
        storage_corruption_message("OCOMP READY index is missing the exact FSM key")
    })?;
    index.remove(position);
    validate_ready_index(index)
}

fn encode_ready_index(index: &[ReadyIndexKey]) -> Result<Vec<u8>> {
    validate_ready_index(index)?;
    let count = u16::try_from(index.len())
        .map_err(|_| storage_corruption_message("OCOMP READY index count exceeds u16"))?;
    let capacity = READY_INDEX_KEY_LEN
        .checked_mul(index.len())
        .and_then(|bytes| READY_INDEX_HEADER_LEN.checked_add(bytes))
        .ok_or_else(|| storage_corruption_message("OCOMP READY index encoded length overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| storage_corruption_message("allocate bounded OCOMP READY index"))?;
    encoded.extend_from_slice(&READY_INDEX_MAGIC);
    encoded.extend_from_slice(&READY_INDEX_VERSION.to_be_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for key in index {
        encoded.extend_from_slice(&key.next_check_height.to_be_bytes());
        encoded.extend_from_slice(&key.worldwide_day.value().to_be_bytes());
        encoded.extend_from_slice(&key.pending_nonce.to_be_bytes());
    }
    if encoded.len() != capacity {
        return Err(storage_corruption_message(
            "OCOMP READY index encoded length mismatch",
        ));
    }
    Ok(encoded)
}

fn decode_ready_index(encoded: &[u8]) -> Result<Vec<ReadyIndexKey>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    if encoded.len() < READY_INDEX_HEADER_LEN {
        return Err(storage_corruption_message(
            "OCOMP READY index is shorter than its header",
        ));
    }
    let mut reader = FixedReader::new(encoded);
    if reader.take::<4>()? != READY_INDEX_MAGIC
        || u16::from_be_bytes(reader.take::<2>()?) != READY_INDEX_VERSION
    {
        return Err(storage_corruption_message(
            "OCOMP READY index magic/version mismatch",
        ));
    }
    let count = usize::from(u16::from_be_bytes(reader.take::<2>()?));
    if count > MAX_RECORDS_KEPT {
        return Err(storage_corruption_message(
            "OCOMP READY index exceeds its fixed capacity",
        ));
    }
    let expected_len = READY_INDEX_KEY_LEN
        .checked_mul(count)
        .and_then(|bytes| READY_INDEX_HEADER_LEN.checked_add(bytes))
        .ok_or_else(|| storage_corruption_message("OCOMP READY index declared length overflow"))?;
    if encoded.len() != expected_len {
        return Err(storage_corruption_message(
            "OCOMP READY index has non-canonical length",
        ));
    }
    let mut index = Vec::new();
    index
        .try_reserve_exact(count)
        .map_err(|_| storage_corruption_message("allocate bounded OCOMP READY index"))?;
    for _ in 0..count {
        index.push(ReadyIndexKey {
            next_check_height: reader.u64()?,
            worldwide_day: WorldwideDay::new(reader.u32()?),
            pending_nonce: reader.u64()?,
        });
    }
    reader.finish()?;
    validate_ready_index(&index)?;
    Ok(index)
}

fn validate_ready_index(index: &[ReadyIndexKey]) -> Result<()> {
    if index.len() > MAX_RECORDS_KEPT {
        return Err(storage_corruption_message(
            "OCOMP READY index exceeds its fixed capacity",
        ));
    }
    if index.iter().any(|key| !key.worldwide_day.is_valid()) {
        return Err(storage_corruption_message(
            "OCOMP READY index contains an invalid WorldwideDay",
        ));
    }
    if index.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(storage_corruption_message(
            "OCOMP READY index is not in strict canonical order",
        ));
    }
    for (position, key) in index.iter().enumerate() {
        if index[..position]
            .iter()
            .any(|existing| existing.worldwide_day == key.worldwide_day)
        {
            return Err(storage_corruption_message(
                "OCOMP READY index contains a duplicate WWD",
            ));
        }
    }
    Ok(())
}

pub(super) fn insert_response_deadline_key(
    index: &mut Vec<ResponseDeadlineKey>,
    key: ResponseDeadlineKey,
) -> Result<()> {
    if key.job_id.is_zero() || key.intent_id.is_zero() || key.deadline_height == 0 {
        return Err(storage_corruption_message(
            "OCOMP response index contains a reserved zero field",
        ));
    }
    if index
        .iter()
        .any(|existing| existing.job_id == key.job_id || existing.intent_id == key.intent_id)
    {
        return Err(storage_corruption_message(
            "OCOMP response index already contains this job",
        ));
    }
    let position = index
        .binary_search(&key)
        .unwrap_or_else(|position| position);
    index.insert(position, key);
    validate_response_deadline_index(index)
}

pub(crate) fn remove_response_deadline_key(
    index: &mut Vec<ResponseDeadlineKey>,
    key: ResponseDeadlineKey,
) -> Result<()> {
    let position = index
        .binary_search(&key)
        .map_err(|_| storage_corruption_message("OCOMP response index is missing the exact job"))?;
    index.remove(position);
    validate_response_deadline_index(index)
}

fn encode_response_deadline_index(index: &[ResponseDeadlineKey]) -> Result<Vec<u8>> {
    validate_response_deadline_index(index)?;
    let count = u16::try_from(index.len())
        .map_err(|_| storage_corruption_message("OCOMP response index count exceeds u16"))?;
    let capacity = RESPONSE_INDEX_KEY_LEN
        .checked_mul(index.len())
        .and_then(|bytes| RESPONSE_INDEX_HEADER_LEN.checked_add(bytes))
        .ok_or_else(|| {
            storage_corruption_message("OCOMP response index encoded length overflow")
        })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| storage_corruption_message("allocate bounded OCOMP response index"))?;
    encoded.extend_from_slice(&RESPONSE_INDEX_MAGIC);
    encoded.extend_from_slice(&RESPONSE_INDEX_VERSION.to_be_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for key in index {
        encoded.extend_from_slice(&key.deadline_height.to_be_bytes());
        encoded.extend_from_slice(key.job_id.as_slice());
        encoded.extend_from_slice(key.intent_id.as_slice());
    }
    if encoded.len() != capacity {
        return Err(storage_corruption_message(
            "OCOMP response index encoded length mismatch",
        ));
    }
    Ok(encoded)
}

fn decode_response_deadline_index(encoded: &[u8]) -> Result<Vec<ResponseDeadlineKey>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    if encoded.len() < RESPONSE_INDEX_HEADER_LEN {
        return Err(storage_corruption_message(
            "OCOMP response index is shorter than its header",
        ));
    }
    let mut reader = FixedReader::new(encoded);
    if reader.take::<4>()? != RESPONSE_INDEX_MAGIC
        || u16::from_be_bytes(reader.take::<2>()?) != RESPONSE_INDEX_VERSION
    {
        return Err(storage_corruption_message(
            "OCOMP response index magic/version mismatch",
        ));
    }
    let count = usize::from(u16::from_be_bytes(reader.take::<2>()?));
    if count == 0 {
        return Err(storage_corruption_message(
            "OCOMP response index must use empty bytes for zero windows",
        ));
    }
    let expected_len = RESPONSE_INDEX_KEY_LEN
        .checked_mul(count)
        .and_then(|bytes| RESPONSE_INDEX_HEADER_LEN.checked_add(bytes))
        .ok_or_else(|| {
            storage_corruption_message("OCOMP response index declared length overflow")
        })?;
    if encoded.len() != expected_len {
        return Err(storage_corruption_message(
            "OCOMP response index has non-canonical length",
        ));
    }
    let mut index = Vec::new();
    index
        .try_reserve_exact(count)
        .map_err(|_| storage_corruption_message("allocate bounded OCOMP response index"))?;
    for _ in 0..count {
        index.push(ResponseDeadlineKey {
            deadline_height: reader.u64()?,
            job_id: B256::from(reader.take::<32>()?),
            intent_id: B256::from(reader.take::<32>()?),
        });
    }
    reader.finish()?;
    validate_response_deadline_index(&index)?;
    Ok(index)
}

fn validate_response_deadline_index(index: &[ResponseDeadlineKey]) -> Result<()> {
    if index
        .iter()
        .any(|key| key.deadline_height == 0 || key.job_id.is_zero() || key.intent_id.is_zero())
    {
        return Err(storage_corruption_message(
            "OCOMP response index contains a reserved zero field",
        ));
    }
    if index.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(storage_corruption_message(
            "OCOMP response index is not in strict canonical order",
        ));
    }
    for (position, key) in index.iter().enumerate() {
        if index[..position]
            .iter()
            .any(|existing| existing.job_id == key.job_id || existing.intent_id == key.intent_id)
        {
            return Err(storage_corruption_message(
                "OCOMP response index contains a duplicate job",
            ));
        }
    }
    Ok(())
}
