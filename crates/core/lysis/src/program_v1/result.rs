//! Bounded ROOT_REDUCE summary and closed result-finalization inputs.

use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    list::{leaf_hash, node_hash, pad_hash},
    result::OutputManifestEntryV1,
    CanonicalReader, CanonicalWriter, ListKind, SchemaLimits,
};

use super::{artifacts::LysisArtifactErrorV1, planner::PRIMARY_WORK_SHARD_SIZE};

const ROOT_REDUCE_SUMMARY_MAGIC: [u8; 4] = *b"LYQ1";
const ROOT_REDUCE_OUTPUT_MAGIC: [u8; 4] = *b"LYR1";
const ROOT_REDUCE_OUTPUT_LEAF: u8 = 1;
const ROOT_REDUCE_OUTPUT_NODE: u8 = 2;
const MAX_LIST_SUBTREE_HEIGHT: u16 = 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LysisListSubtreeCarrierV1 {
    pub list_kind: ListKind,
    pub start_ordinal: u32,
    pub real_count: u32,
    pub subtree_height: u16,
    pub subtree_index: u32,
    pub tree_root: B256,
}

impl LysisListSubtreeCarrierV1 {
    pub fn from_primary_page<T: AsRef<[u8]>>(
        list_kind: ListKind,
        primary_ordinal: u32,
        canonical_items: &[T],
        max_item_bytes: usize,
    ) -> Result<Self, LysisArtifactErrorV1> {
        let subtree_height = primary_subtree_height(list_kind)?;
        let capacity = 1_u32
            .checked_shl(u32::from(subtree_height))
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        let real_count = u32::try_from(canonical_items.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        if real_count > capacity
            || canonical_items
                .iter()
                .any(|item| item.as_ref().len() > max_item_bytes)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Lysis primary list carrier item bounds",
            ));
        }
        let start_ordinal = primary_ordinal
            .checked_mul(capacity)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        let capacity_usize =
            usize::try_from(capacity).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity_usize)
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        for offset in 0..capacity {
            let global_ordinal = start_ordinal
                .checked_add(offset)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
            if offset < real_count {
                nodes.push(leaf_hash(
                    list_kind,
                    global_ordinal,
                    canonical_items[usize::try_from(offset)
                        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?]
                    .as_ref(),
                )?);
            } else {
                nodes.push(pad_hash(list_kind, global_ordinal)?);
            }
        }

        let mut width = capacity_usize;
        let mut level = 1_u16;
        while width > 1 {
            let parent_count = width / 2;
            let global_parent_start = start_ordinal
                .checked_shr(u32::from(level))
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
            for index in 0..parent_count {
                let global_parent_index = global_parent_start
                    .checked_add(
                        u32::try_from(index).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
                    )
                    .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
                nodes[index] = node_hash(
                    list_kind,
                    level,
                    global_parent_index,
                    nodes[index * 2],
                    nodes[index * 2 + 1],
                )?;
            }
            width = parent_count;
            level = level
                .checked_add(1)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        }

        let carrier = Self {
            list_kind,
            start_ordinal,
            real_count,
            subtree_height,
            subtree_index: primary_ordinal,
            tree_root: nodes[0],
        };
        validate_list_subtree_carrier(&carrier)?;
        Ok(carrier)
    }

    pub fn canonical_empty_primary_page(
        list_kind: ListKind,
        primary_ordinal: u32,
    ) -> Result<Self, LysisArtifactErrorV1> {
        Self::from_primary_page::<&[u8]>(list_kind, primary_ordinal, &[], 0)
    }

    pub fn merge_adjacent(self, right: Self) -> Result<Self, LysisArtifactErrorV1> {
        validate_list_subtree_carrier(&self)?;
        validate_list_subtree_carrier(&right)?;
        if self.list_kind != right.list_kind
            || self.subtree_height != right.subtree_height
            || self.subtree_index & 1 != 0
            || self
                .subtree_index
                .checked_add(1)
                .is_none_or(|expected| right.subtree_index != expected)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Lysis list subtree sibling binding",
            ));
        }
        let capacity = 1_u32
            .checked_shl(u32::from(self.subtree_height))
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        if self
            .start_ordinal
            .checked_add(capacity)
            .is_none_or(|expected| right.start_ordinal != expected)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Lysis list subtree adjacency",
            ));
        }
        let subtree_height = self
            .subtree_height
            .checked_add(1)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        if subtree_height > MAX_LIST_SUBTREE_HEIGHT {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Lysis list subtree parent height",
            ));
        }
        let subtree_index = self.subtree_index >> 1;
        let carrier = Self {
            list_kind: self.list_kind,
            start_ordinal: self.start_ordinal,
            real_count: self
                .real_count
                .checked_add(right.real_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            subtree_height,
            subtree_index,
            tree_root: node_hash(
                self.list_kind,
                subtree_height,
                subtree_index,
                self.tree_root,
                right.tree_root,
            )?,
        };
        validate_list_subtree_carrier(&carrier)?;
        Ok(carrier)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootReduceSummaryV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub plan_hash: B256,
    pub covered_primary_start: u32,
    pub covered_primary_count: u32,
    pub nod_actions: LysisListSubtreeCarrierV1,
    pub bucket_records: LysisListSubtreeCarrierV1,
    pub contributor_actions: LysisListSubtreeCarrierV1,
    pub output_manifest_entries: LysisListSubtreeCarrierV1,
    pub result_chunk_hashes: LysisListSubtreeCarrierV1,
    pub tribute_count: u32,
    pub nod_count: u32,
    pub bucket_count: u32,
    pub contributor_count: u32,
    pub tribute_nominal_total: U256,
    pub eligible_nominal_total: U256,
    pub nod_gratis_consumed: U256,
    pub nod_cost_total: U256,
    pub first_error_ordinal: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootReduceOutputV1 {
    Leaf {
        summary: RootReduceSummaryV1,
        output_manifest_entry: OutputManifestEntryV1,
    },
    Node {
        summary: RootReduceSummaryV1,
    },
}

impl RootReduceSummaryV1 {
    pub fn merge_adjacent(self, right: Self) -> Result<Self, LysisArtifactErrorV1> {
        validate_root_reduce_summary(&self)?;
        validate_root_reduce_summary(&right)?;
        if self.protocol_bundle_hash != right.protocol_bundle_hash
            || self.job_id != right.job_id
            || self.attempt != right.attempt
            || self.plan_hash != right.plan_hash
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "root reducer summary parent binding",
            ));
        }
        let left_primary_capacity = 1_u32
            .checked_shl(u32::from(self.result_chunk_hashes.subtree_height))
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        if right.covered_primary_count != 0 && self.covered_primary_count != left_primary_capacity {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "root reducer summary real coverage prefix",
            ));
        }

        let summary = Self {
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            plan_hash: self.plan_hash,
            covered_primary_start: self.covered_primary_start,
            covered_primary_count: self
                .covered_primary_count
                .checked_add(right.covered_primary_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            nod_actions: self.nod_actions.merge_adjacent(right.nod_actions)?,
            bucket_records: self.bucket_records.merge_adjacent(right.bucket_records)?,
            contributor_actions: self
                .contributor_actions
                .merge_adjacent(right.contributor_actions)?,
            output_manifest_entries: self
                .output_manifest_entries
                .merge_adjacent(right.output_manifest_entries)?,
            result_chunk_hashes: self
                .result_chunk_hashes
                .merge_adjacent(right.result_chunk_hashes)?,
            tribute_count: self
                .tribute_count
                .checked_add(right.tribute_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            nod_count: self
                .nod_count
                .checked_add(right.nod_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            bucket_count: self
                .bucket_count
                .checked_add(right.bucket_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            contributor_count: self
                .contributor_count
                .checked_add(right.contributor_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            tribute_nominal_total: checked_add_summary_total(
                self.tribute_nominal_total,
                right.tribute_nominal_total,
            )?,
            eligible_nominal_total: checked_add_summary_total(
                self.eligible_nominal_total,
                right.eligible_nominal_total,
            )?,
            nod_gratis_consumed: checked_add_summary_total(
                self.nod_gratis_consumed,
                right.nod_gratis_consumed,
            )?,
            nod_cost_total: checked_add_summary_total(self.nod_cost_total, right.nod_cost_total)?,
            first_error_ordinal: match (self.first_error_ordinal, right.first_error_ordinal) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left @ Some(_), None) => left,
                (None, right) => right,
            },
        };
        validate_root_reduce_summary(&summary)?;
        Ok(summary)
    }
}

pub fn encode_root_reduce_output(
    output: &RootReduceOutputV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_root_reduce_output(output, limits)?;
    let mut writer = CanonicalWriter::new(limits.codec);
    writer.write_fixed(&ROOT_REDUCE_OUTPUT_MAGIC)?;
    match output {
        RootReduceOutputV1::Leaf {
            summary,
            output_manifest_entry,
        } => {
            writer.write_u8(ROOT_REDUCE_OUTPUT_LEAF)?;
            let summary = encode_root_reduce_summary(summary, limits)?;
            writer.write_bounded_bytes(&summary, limits.max_bounded_bytes)?;
            let entry = output_manifest_entry.encode_canonical_record(limits)?;
            writer.write_bounded_bytes(&entry, limits.max_bounded_bytes)?;
        }
        RootReduceOutputV1::Node { summary } => {
            writer.write_u8(ROOT_REDUCE_OUTPUT_NODE)?;
            let summary = encode_root_reduce_summary(summary, limits)?;
            writer.write_bounded_bytes(&summary, limits.max_bounded_bytes)?;
        }
    }
    Ok(writer.into_bytes())
}

pub fn decode_root_reduce_output(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<RootReduceOutputV1, LysisArtifactErrorV1> {
    let mut reader = CanonicalReader::new(encoded, limits.codec)?;
    if reader.read_fixed::<4>()? != ROOT_REDUCE_OUTPUT_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer output header",
        ));
    }
    let tag = reader.read_u8()?;
    let summary =
        decode_root_reduce_summary(reader.read_bounded_bytes(limits.max_bounded_bytes)?, limits)?;
    let output = match tag {
        ROOT_REDUCE_OUTPUT_LEAF => RootReduceOutputV1::Leaf {
            summary,
            output_manifest_entry: OutputManifestEntryV1::decode_canonical_record(
                reader.read_bounded_bytes(limits.max_bounded_bytes)?,
                limits,
            )?,
        },
        ROOT_REDUCE_OUTPUT_NODE => RootReduceOutputV1::Node { summary },
        _ => {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "root reducer output tag",
            ));
        }
    };
    reader.finish()?;
    validate_root_reduce_output(&output, limits)?;
    if encode_root_reduce_output(&output, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer output canonical re-encoding",
        ));
    }
    Ok(output)
}

pub fn encode_root_reduce_summary(
    summary: &RootReduceSummaryV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_root_reduce_summary(summary)?;
    let mut output = CanonicalWriter::new(limits.codec);
    output.write_fixed(&ROOT_REDUCE_SUMMARY_MAGIC)?;
    output.write_b256(summary.protocol_bundle_hash)?;
    output.write_b256(summary.job_id)?;
    output.write_u32(summary.attempt)?;
    output.write_b256(summary.plan_hash)?;
    output.write_u32(summary.covered_primary_start)?;
    output.write_u32(summary.covered_primary_count)?;
    for carrier in [
        &summary.nod_actions,
        &summary.bucket_records,
        &summary.contributor_actions,
        &summary.output_manifest_entries,
        &summary.result_chunk_hashes,
    ] {
        encode_list_subtree_carrier(&mut output, carrier)?;
    }
    output.write_u32(summary.tribute_count)?;
    output.write_u32(summary.nod_count)?;
    output.write_u32(summary.bucket_count)?;
    output.write_u32(summary.contributor_count)?;
    output.write_u256(summary.tribute_nominal_total)?;
    output.write_u256(summary.eligible_nominal_total)?;
    output.write_u256(summary.nod_gratis_consumed)?;
    output.write_u256(summary.nod_cost_total)?;
    output.write_option(summary.first_error_ordinal.as_ref(), |writer, ordinal| {
        writer.write_u32(*ordinal)
    })?;
    Ok(output.into_bytes())
}

fn validate_root_reduce_output(
    output: &RootReduceOutputV1,
    limits: &SchemaLimits,
) -> Result<(), LysisArtifactErrorV1> {
    match output {
        RootReduceOutputV1::Leaf {
            summary,
            output_manifest_entry,
        } => {
            validate_root_reduce_summary(summary)?;
            if summary.covered_primary_count != 1
                || output_manifest_entry.chunk_ordinal != summary.covered_primary_start
            {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "root reducer leaf coverage",
                ));
            }
            let encoded_entry = output_manifest_entry.encode_canonical_record(limits)?;
            let expected_manifest = LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::CompleteOutputManifest,
                summary.covered_primary_start,
                &[encoded_entry],
                limits.max_bounded_bytes,
            )?;
            let expected_chunk_hashes = LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::ResultChunkHashes,
                summary.covered_primary_start,
                &[output_manifest_entry.result_chunk_hash.as_slice()],
                B256::len_bytes(),
            )?;
            if summary.output_manifest_entries != expected_manifest
                || summary.result_chunk_hashes != expected_chunk_hashes
            {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "root reducer leaf manifest binding",
                ));
            }
            Ok(())
        }
        RootReduceOutputV1::Node { summary } => {
            validate_root_reduce_summary(summary)?;
            if summary.result_chunk_hashes.subtree_height == 0 && summary.covered_primary_count != 0
            {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "root reducer node topology",
                ));
            }
            Ok(())
        }
    }
}

pub fn decode_root_reduce_summary(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<RootReduceSummaryV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != ROOT_REDUCE_SUMMARY_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary header",
        ));
    }
    let summary = RootReduceSummaryV1 {
        protocol_bundle_hash: input.read_b256()?,
        job_id: input.read_b256()?,
        attempt: input.read_u32()?,
        plan_hash: input.read_b256()?,
        covered_primary_start: input.read_u32()?,
        covered_primary_count: input.read_u32()?,
        nod_actions: decode_list_subtree_carrier(&mut input)?,
        bucket_records: decode_list_subtree_carrier(&mut input)?,
        contributor_actions: decode_list_subtree_carrier(&mut input)?,
        output_manifest_entries: decode_list_subtree_carrier(&mut input)?,
        result_chunk_hashes: decode_list_subtree_carrier(&mut input)?,
        tribute_count: input.read_u32()?,
        nod_count: input.read_u32()?,
        bucket_count: input.read_u32()?,
        contributor_count: input.read_u32()?,
        tribute_nominal_total: input.read_u256()?,
        eligible_nominal_total: input.read_u256()?,
        nod_gratis_consumed: input.read_u256()?,
        nod_cost_total: input.read_u256()?,
        first_error_ordinal: input.read_option(|reader| reader.read_u32())?,
    };
    input.finish()?;
    validate_root_reduce_summary(&summary)?;
    if encode_root_reduce_summary(&summary, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary canonical re-encoding",
        ));
    }
    Ok(summary)
}

fn encode_list_subtree_carrier(
    output: &mut CanonicalWriter,
    carrier: &LysisListSubtreeCarrierV1,
) -> Result<(), LysisArtifactErrorV1> {
    validate_list_subtree_carrier(carrier)?;
    output.write_u16(carrier.list_kind.id())?;
    output.write_u32(carrier.start_ordinal)?;
    output.write_u32(carrier.real_count)?;
    output.write_u16(carrier.subtree_height)?;
    output.write_u32(carrier.subtree_index)?;
    output.write_b256(carrier.tree_root)?;
    Ok(())
}

fn decode_list_subtree_carrier(
    input: &mut CanonicalReader<'_>,
) -> Result<LysisListSubtreeCarrierV1, LysisArtifactErrorV1> {
    let carrier = LysisListSubtreeCarrierV1 {
        list_kind: ListKind::try_from(input.read_u16()?)?,
        start_ordinal: input.read_u32()?,
        real_count: input.read_u32()?,
        subtree_height: input.read_u16()?,
        subtree_index: input.read_u32()?,
        tree_root: input.read_b256()?,
    };
    validate_list_subtree_carrier(&carrier)?;
    Ok(carrier)
}

fn validate_root_reduce_summary(summary: &RootReduceSummaryV1) -> Result<(), LysisArtifactErrorV1> {
    if summary.protocol_bundle_hash.is_zero()
        || summary.job_id.is_zero()
        || summary.plan_hash.is_zero()
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary binding",
        ));
    }
    require_carrier(
        &summary.nod_actions,
        ListKind::NodActions,
        summary.tribute_count,
    )?;
    require_carrier(
        &summary.bucket_records,
        ListKind::BucketRecords,
        summary.bucket_count,
    )?;
    require_carrier(
        &summary.contributor_actions,
        ListKind::ContributorActions,
        summary.contributor_count,
    )?;
    require_carrier(
        &summary.output_manifest_entries,
        ListKind::CompleteOutputManifest,
        summary.covered_primary_count,
    )?;
    require_carrier(
        &summary.result_chunk_hashes,
        ListKind::ResultChunkHashes,
        summary.covered_primary_count,
    )?;
    let action_height = summary
        .result_chunk_hashes
        .subtree_height
        .checked_add(primary_subtree_height(ListKind::NodActions)?)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    if [
        summary.nod_actions.subtree_height,
        summary.bucket_records.subtree_height,
        summary.contributor_actions.subtree_height,
    ]
    .into_iter()
    .any(|height| height != action_height)
        || summary.output_manifest_entries.subtree_height
            != summary.result_chunk_hashes.subtree_height
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary carrier span",
        ));
    }

    let action_start = summary
        .covered_primary_start
        .checked_mul(PRIMARY_WORK_SHARD_SIZE)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    if summary.nod_actions.start_ordinal != action_start
        || summary.bucket_records.start_ordinal != action_start
        || summary.contributor_actions.start_ordinal != action_start
        || summary.output_manifest_entries.start_ordinal != summary.covered_primary_start
        || summary.result_chunk_hashes.start_ordinal != summary.covered_primary_start
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary list start",
        ));
    }

    if summary.covered_primary_count == 0 {
        if summary.tribute_count != 0
            || summary.nod_count != 0
            || summary.bucket_count != 0
            || summary.contributor_count != 0
            || !summary.tribute_nominal_total.is_zero()
            || !summary.eligible_nominal_total.is_zero()
            || !summary.nod_gratis_consumed.is_zero()
            || !summary.nod_cost_total.is_zero()
            || summary.first_error_ordinal.is_some()
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "root reducer empty summary",
            ));
        }
        return Ok(());
    }

    let covered_capacity = summary
        .covered_primary_count
        .checked_mul(PRIMARY_WORK_SHARD_SIZE)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    let minimum_count = covered_capacity
        .checked_sub(PRIMARY_WORK_SHARD_SIZE - 1)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    if summary.tribute_count < minimum_count
        || summary.tribute_count > covered_capacity
        || summary.nod_count != summary.tribute_count
        || summary.bucket_count != summary.nod_count
        || summary.contributor_count > summary.tribute_count
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary counts or totals",
        ));
    }
    if summary.first_error_ordinal.is_some_and(|ordinal| {
        action_start
            .checked_add(summary.tribute_count)
            .is_none_or(|end| ordinal < action_start || ordinal >= end)
    }) {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary first error",
        ));
    }
    Ok(())
}

fn require_carrier(
    carrier: &LysisListSubtreeCarrierV1,
    expected_kind: ListKind,
    expected_count: u32,
) -> Result<(), LysisArtifactErrorV1> {
    validate_list_subtree_carrier(carrier)?;
    if carrier.list_kind != expected_kind || carrier.real_count != expected_count {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary carrier binding",
        ));
    }
    Ok(())
}

fn validate_list_subtree_carrier(
    carrier: &LysisListSubtreeCarrierV1,
) -> Result<(), LysisArtifactErrorV1> {
    let primary_height = primary_subtree_height(carrier.list_kind)?;
    if carrier.subtree_height < primary_height || carrier.subtree_height > MAX_LIST_SUBTREE_HEIGHT {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Lysis list subtree kind or height",
        ));
    }
    let capacity = 1_u32
        .checked_shl(u32::from(carrier.subtree_height))
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    let expected_start = carrier
        .subtree_index
        .checked_mul(capacity)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    if carrier.start_ordinal != expected_start {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Lysis list subtree position",
        ));
    }
    if carrier.real_count > capacity || carrier.tree_root.is_zero() {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Lysis list subtree fixed capacity",
        ));
    }
    Ok(())
}

fn primary_subtree_height(list_kind: ListKind) -> Result<u16, LysisArtifactErrorV1> {
    match list_kind {
        ListKind::NodActions | ListKind::BucketRecords | ListKind::ContributorActions => {
            Ok(PRIMARY_WORK_SHARD_SIZE.trailing_zeros() as u16)
        }
        ListKind::CompleteOutputManifest | ListKind::ResultChunkHashes => Ok(0),
        _ => Err(LysisArtifactErrorV1::InvalidEncoding(
            "Lysis list subtree kind",
        )),
    }
}

fn checked_add_summary_total(left: U256, right: U256) -> Result<U256, LysisArtifactErrorV1> {
    left.checked_add(right)
        .ok_or(LysisArtifactErrorV1::InvalidEncoding(
            "root reducer summary total overflow",
        ))
}
