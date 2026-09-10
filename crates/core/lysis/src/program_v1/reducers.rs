//! Streaming, Lysis-specific merge reducers for bounded shuffle chunks.

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::WwdEntityId;

use super::{
    phases::{BucketRecordV1, FinalizedContributorV1},
    planner::PRIMARY_WORK_SHARD_SIZE,
    ProgramErrorV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalRunSpanV1 {
    pub start_run: u32,
    pub end_run: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerMergeSummaryV1 {
    pub span: CanonicalRunSpanV1,
    pub record_count: u32,
    pub chunk_count: u32,
    pub max_buffered_records: u32,
    pub checked_eligible_nominal_total: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketMergeSummaryV1 {
    pub span: CanonicalRunSpanV1,
    pub record_count: u32,
    pub chunk_count: u32,
    pub max_buffered_records: u32,
}

#[derive(Debug)]
pub enum StreamingMergeErrorV1<E> {
    Program(ProgramErrorV1),
    Sink(E),
}

impl<E> From<ProgramErrorV1> for StreamingMergeErrorV1<E> {
    fn from(error: ProgramErrorV1) -> Self {
        Self::Program(error)
    }
}

pub fn merge_owner_runs_streaming<L, R, S, E>(
    left_span: CanonicalRunSpanV1,
    left: L,
    right_span: CanonicalRunSpanV1,
    right: R,
    max_chunk_records: usize,
    mut sink: S,
) -> Result<OwnerMergeSummaryV1, StreamingMergeErrorV1<E>>
where
    L: IntoIterator<Item = FinalizedContributorV1>,
    R: IntoIterator<Item = FinalizedContributorV1>,
    S: FnMut(u32, &[FinalizedContributorV1]) -> Result<(), E>,
{
    validate_merge_inputs(left_span, right_span, max_chunk_records)?;
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut previous_left = None;
    let mut previous_right = None;
    let mut previous_output_owner = None;
    let mut output = Vec::with_capacity(max_chunk_records);
    let mut record_count = 0_u32;
    let mut chunk_count = 0_u32;
    let mut max_buffered_records = 0_u32;
    let mut checked_eligible_nominal_total = U256::ZERO;

    while left.peek().is_some() || right.peek().is_some() {
        let take_left = match (left.peek(), right.peek()) {
            (Some(left), Some(right)) => owner_key(left) <= owner_key(right),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let item = if take_left {
            let item = left.next().ok_or(ProgramErrorV1::OutputCountMismatch)?;
            validate_owner_input(&mut previous_left, &item)?;
            item
        } else {
            let item = right.next().ok_or(ProgramErrorV1::OutputCountMismatch)?;
            validate_owner_input(&mut previous_right, &item)?;
            item
        };
        if previous_output_owner.is_some_and(|owner| owner >= item.owner) {
            return Err(ProgramErrorV1::OutputCountMismatch.into());
        }
        previous_output_owner = Some(item.owner);
        checked_eligible_nominal_total = checked_eligible_nominal_total
            .checked_add(item.nominal_amount_minor)
            .ok_or(ProgramErrorV1::ContributorOverflow {
                ordinal: record_count as usize,
            })?;
        output.push(item);
        record_count = record_count
            .checked_add(1)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        max_buffered_records = max_buffered_records
            .max(u32::try_from(output.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?);
        if output.len() == max_chunk_records {
            sink(chunk_count, &output).map_err(StreamingMergeErrorV1::Sink)?;
            chunk_count = chunk_count
                .checked_add(1)
                .ok_or(ProgramErrorV1::OutputCountMismatch)?;
            output.clear();
        }
    }
    if !output.is_empty() {
        sink(chunk_count, &output).map_err(StreamingMergeErrorV1::Sink)?;
        chunk_count = chunk_count
            .checked_add(1)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
    }
    Ok(OwnerMergeSummaryV1 {
        span: CanonicalRunSpanV1 {
            start_run: left_span.start_run,
            end_run: right_span.end_run,
        },
        record_count,
        chunk_count,
        max_buffered_records,
        checked_eligible_nominal_total,
    })
}

pub fn merge_bucket_runs_streaming<L, R, S, E>(
    left_span: CanonicalRunSpanV1,
    left: L,
    right_span: CanonicalRunSpanV1,
    right: R,
    max_chunk_records: usize,
    mut sink: S,
) -> Result<BucketMergeSummaryV1, StreamingMergeErrorV1<E>>
where
    L: IntoIterator<Item = BucketRecordV1>,
    R: IntoIterator<Item = BucketRecordV1>,
    S: FnMut(u32, &[BucketRecordV1]) -> Result<(), E>,
{
    validate_merge_inputs(left_span, right_span, max_chunk_records)?;
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut previous_left = None;
    let mut previous_right = None;
    let mut previous_output = None;
    let mut output = Vec::with_capacity(max_chunk_records);
    let mut record_count = 0_u32;
    let mut chunk_count = 0_u32;
    let mut max_buffered_records = 0_u32;

    while left.peek().is_some() || right.peek().is_some() {
        let take_left = match (left.peek(), right.peek()) {
            (Some(left), Some(right)) => bucket_key(left) <= bucket_key(right),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let item = if take_left {
            let item = left.next().ok_or(ProgramErrorV1::OutputCountMismatch)?;
            validate_bucket_input(&mut previous_left, &item)?;
            item
        } else {
            let item = right.next().ok_or(ProgramErrorV1::OutputCountMismatch)?;
            validate_bucket_input(&mut previous_right, &item)?;
            item
        };
        let key = bucket_key(&item);
        if previous_output.is_some_and(|previous| previous >= key) {
            return Err(ProgramErrorV1::OutputCountMismatch.into());
        }
        previous_output = Some(key);
        output.push(item);
        record_count = record_count
            .checked_add(1)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        max_buffered_records = max_buffered_records
            .max(u32::try_from(output.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?);
        if output.len() == max_chunk_records {
            sink(chunk_count, &output).map_err(StreamingMergeErrorV1::Sink)?;
            chunk_count = chunk_count
                .checked_add(1)
                .ok_or(ProgramErrorV1::OutputCountMismatch)?;
            output.clear();
        }
    }
    if !output.is_empty() {
        sink(chunk_count, &output).map_err(StreamingMergeErrorV1::Sink)?;
        chunk_count = chunk_count
            .checked_add(1)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
    }
    if record_count == 0 {
        return Err(ProgramErrorV1::OutputCountMismatch.into());
    }
    Ok(BucketMergeSummaryV1 {
        span: CanonicalRunSpanV1 {
            start_run: left_span.start_run,
            end_run: right_span.end_run,
        },
        record_count,
        chunk_count,
        max_buffered_records,
    })
}

fn validate_merge_inputs<E>(
    left: CanonicalRunSpanV1,
    right: CanonicalRunSpanV1,
    max_chunk_records: usize,
) -> Result<(), StreamingMergeErrorV1<E>> {
    if left.start_run >= left.end_run
        || right.start_run >= right.end_run
        || left.end_run != right.start_run
        || max_chunk_records == 0
        || max_chunk_records
            > usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch.into());
    }
    Ok(())
}

fn owner_key(value: &FinalizedContributorV1) -> (Address, WwdEntityId) {
    (value.owner, value.source_tribute_id)
}

fn validate_owner_input(
    previous: &mut Option<(Address, WwdEntityId)>,
    item: &FinalizedContributorV1,
) -> Result<(), ProgramErrorV1> {
    let key = owner_key(item);
    if previous.is_some_and(|previous| previous >= key) {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    *previous = Some(key);
    Ok(())
}

fn bucket_key(value: &BucketRecordV1) -> (B256, u32) {
    (value.bucket_key, value.raw_ordinal)
}

fn validate_bucket_input(
    previous: &mut Option<(B256, u32)>,
    item: &BucketRecordV1,
) -> Result<(), ProgramErrorV1> {
    let key = bucket_key(item);
    if previous.is_some_and(|previous| previous >= key) {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    *previous = Some(key);
    Ok(())
}
