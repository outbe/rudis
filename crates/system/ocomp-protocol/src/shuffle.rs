//! Bounded, Lysis-specific owner/bucket shuffle run artifacts.
//!
//! This closed schema is deliberately not a generic DAG or spill-file
//! framework. A `UnitArtifactV1` embeds one root object; bounded descendants
//! are addressed by their verified CAS references.

use std::collections::{BTreeSet, VecDeque};

use alloy_primitives::{keccak256, Address, B256};

use crate::{
    codec::{CanonicalReader, CanonicalWriter},
    control::CasObjectRefV1,
    error::ProtocolError,
    hash::hash_framed,
    list::StreamingOrderedListRoot,
    registry::{HashDomain, ListKind, ObjectKind},
    result::ContributorActionV1,
    schema::{
        encode_nested_value, impl_top_level_codec, require, wire_enum_u8, wire_struct, NestedCodec,
        SchemaLimits,
    },
    unit::CanonicalRunSpan,
};

/// One shuffle leaf never owns more records than one primary Lysis work shard.
pub const MAX_SHUFFLE_LEAF_RECORDS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShuffleSourceCoverageV1 {
    pub run_span: CanonicalRunSpan,
    pub root: B256,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShuffleRunBuildContextV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub unit_id: B256,
    pub run_span: CanonicalRunSpan,
    pub source_coverage_root: B256,
    pub source_coverage_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedShuffleRecordV1 {
    Owner(ContributorActionV1),
    Bucket(ShuffleBucketRecordV1),
}

pub struct VerifiedShuffleRunIterV1<'a, R>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    limits: &'a SchemaLimits,
    resolver: R,
    context: ShuffleRunContextV1,
    stack: Vec<ShuffleRunArtifactV1>,
    pending_records: VecDeque<VerifiedShuffleRecordV1>,
    next_page: u32,
    leaf_count: u32,
    previous_leaf_record_count: Option<u32>,
    yielded_record_count: u32,
    previous_owner: Option<(Address, B256)>,
    previous_bucket: Option<(B256, u32)>,
    finished: bool,
}

pub struct MergedVerifiedShuffleRunIterV1<L, R>
where
    L: Iterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
    R: Iterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
{
    kind: ShuffleRunKindV1,
    left: std::iter::Peekable<L>,
    right: std::iter::Peekable<R>,
    previous_key: Option<VerifiedShuffleRecordKeyV1>,
    finished: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum VerifiedShuffleRecordKeyV1 {
    Owner(Address, B256),
    Bucket(B256, u32),
}

#[derive(Clone, Debug)]
struct ShuffleRunContextV1 {
    protocol_bundle_hash: B256,
    job_id: B256,
    attempt: u32,
    unit_id: B256,
    kind: ShuffleRunKindV1,
    run_span: CanonicalRunSpan,
    root_page_end: u32,
    root_record_count: u32,
    source_coverage_root: B256,
    source_coverage_count: u32,
}

pub fn verified_shuffle_run_records<'a, R>(
    root: ShuffleRunArtifactV1,
    limits: &'a SchemaLimits,
    resolver: R,
) -> Result<VerifiedShuffleRunIterV1<'a, R>, ProtocolError>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    root.validate_root_semantics(limits)?;
    let context = ShuffleRunContextV1 {
        protocol_bundle_hash: root.protocol_bundle_hash,
        job_id: root.job_id,
        attempt: root.attempt,
        unit_id: root.unit_id,
        kind: root.kind,
        run_span: root.run_span.clone(),
        root_page_end: root.page_span.end_page,
        root_record_count: root.record_count,
        source_coverage_root: root.source_coverage_root,
        source_coverage_count: root.source_coverage_count,
    };
    Ok(VerifiedShuffleRunIterV1 {
        limits,
        resolver,
        context,
        stack: vec![root],
        pending_records: VecDeque::new(),
        next_page: 0,
        leaf_count: 0,
        previous_leaf_record_count: None,
        yielded_record_count: 0,
        previous_owner: None,
        previous_bucket: None,
        finished: false,
    })
}

/// Opens one canonical 256-record page from an already admitted shuffle root.
///
/// The lookup follows only the unique authenticated child path for
/// `page_ordinal`; it never scans the preceding population. A request beyond
/// the exact record stream returns the canonical empty slice.
pub fn verified_shuffle_run_page<R>(
    root: ShuffleRunArtifactV1,
    page_ordinal: u32,
    limits: &SchemaLimits,
    mut resolver: R,
) -> Result<Vec<VerifiedShuffleRecordV1>, ProtocolError>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    root.validate_root_semantics(limits)?;
    let root_page_end = exact_shuffle_page_count(root.kind, root.record_count)?;
    require(
        root.page_span.end_page == root_page_end,
        "shuffle root exact page count",
    )?;
    if page_ordinal >= root_page_end {
        return Ok(Vec::new());
    }
    let context = ShuffleRunContextV1 {
        protocol_bundle_hash: root.protocol_bundle_hash,
        job_id: root.job_id,
        attempt: root.attempt,
        unit_id: root.unit_id,
        kind: root.kind,
        run_span: root.run_span.clone(),
        root_page_end,
        root_record_count: root.record_count,
        source_coverage_root: root.source_coverage_root,
        source_coverage_count: root.source_coverage_count,
    };
    let mut artifact = root;
    loop {
        require_shuffle_context(&context, &artifact, limits)?;
        match artifact.payload {
            ShuffleRunPayloadV1::Node { left, right } => {
                let expected = if page_ordinal >= left.page_span.start_page
                    && page_ordinal < left.page_span.end_page
                {
                    left
                } else if page_ordinal >= right.page_span.start_page
                    && page_ordinal < right.page_span.end_page
                {
                    right
                } else {
                    return Err(ProtocolError::InvalidInvariant(
                        "shuffle page child coverage",
                    ));
                };
                artifact = resolve_shuffle_child(&context, &expected, limits, &mut resolver)?;
            }
            ShuffleRunPayloadV1::OwnerLeaf(records) => {
                require(
                    context.kind == ShuffleRunKindV1::Owner,
                    "shuffle page owner kind",
                )?;
                require_shuffle_page_leaf(
                    &context,
                    &artifact.page_span,
                    artifact.first_record_ordinal,
                    artifact.record_count,
                    page_ordinal,
                )?;
                return Ok(records
                    .into_iter()
                    .map(VerifiedShuffleRecordV1::Owner)
                    .collect());
            }
            ShuffleRunPayloadV1::BucketLeaf(records) => {
                require(
                    context.kind == ShuffleRunKindV1::Bucket,
                    "shuffle page bucket kind",
                )?;
                require_shuffle_page_leaf(
                    &context,
                    &artifact.page_span,
                    artifact.first_record_ordinal,
                    artifact.record_count,
                    page_ordinal,
                )?;
                return Ok(records
                    .into_iter()
                    .map(VerifiedShuffleRecordV1::Bucket)
                    .collect());
            }
        }
    }
}

fn exact_shuffle_page_count(
    kind: ShuffleRunKindV1,
    record_count: u32,
) -> Result<u32, ProtocolError> {
    if record_count == 0 {
        return if kind == ShuffleRunKindV1::Owner {
            Ok(1)
        } else {
            Err(ProtocolError::InvalidInvariant(
                "non-empty bucket shuffle run",
            ))
        };
    }
    Ok(record_count.div_ceil(MAX_SHUFFLE_LEAF_RECORDS as u32))
}

fn require_shuffle_page_leaf(
    context: &ShuffleRunContextV1,
    page_span: &ShufflePageSpanV1,
    first_record_ordinal: u32,
    record_count: u32,
    page_ordinal: u32,
) -> Result<(), ProtocolError> {
    let page_end = page_ordinal
        .checked_add(1)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle requested page end",
        })?;
    let expected_first = page_ordinal
        .checked_mul(MAX_SHUFFLE_LEAF_RECORDS as u32)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle requested first record",
        })?;
    let expected_end = if page_end == context.root_page_end {
        context.root_record_count
    } else {
        page_end
            .checked_mul(MAX_SHUFFLE_LEAF_RECORDS as u32)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "shuffle requested record end",
            })?
    };
    require(
        page_span.start_page == page_ordinal
            && page_span.end_page == page_end
            && first_record_ordinal == expected_first
            && first_record_ordinal
                .checked_add(record_count)
                .is_some_and(|actual| actual == expected_end),
        "shuffle exact page slice",
    )
}

fn resolve_shuffle_child<R>(
    context: &ShuffleRunContextV1,
    expected: &ShuffleRunChildV1,
    limits: &SchemaLimits,
    resolver: &mut R,
) -> Result<ShuffleRunArtifactV1, ProtocolError>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    let bytes = resolver(&expected.artifact_ref)?;
    let encoded_bytes = u64::try_from(bytes.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "shuffle child encoded bytes",
    })?;
    require(
        encoded_bytes == expected.artifact_ref.encoded_bytes
            && keccak256(&bytes) == expected.artifact_ref.transport_digest,
        "shuffle child transport descriptor",
    )?;
    let child = ShuffleRunArtifactV1::decode_canonical(&bytes, limits)?;
    require_shuffle_context(context, &child, limits)?;
    require(
        child.page_span == expected.page_span
            && child.first_record_ordinal == expected.first_record_ordinal
            && child.record_count == expected.record_count
            && child.ordered_record_root == expected.ordered_record_root,
        "shuffle child summary",
    )?;
    Ok(child)
}

fn require_shuffle_context(
    context: &ShuffleRunContextV1,
    artifact: &ShuffleRunArtifactV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    artifact.validate_semantics(limits)?;
    require(
        artifact.protocol_bundle_hash == context.protocol_bundle_hash
            && artifact.job_id == context.job_id
            && artifact.attempt == context.attempt
            && artifact.unit_id == context.unit_id
            && artifact.kind == context.kind
            && artifact.run_span == context.run_span
            && artifact.source_coverage_root == context.source_coverage_root
            && artifact.source_coverage_count == context.source_coverage_count,
        "shuffle descendant context",
    )
}

pub fn merge_verified_shuffle_runs<L, R>(
    kind: ShuffleRunKindV1,
    left: L,
    right: R,
) -> MergedVerifiedShuffleRunIterV1<L::IntoIter, R::IntoIter>
where
    L: IntoIterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
    R: IntoIterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
{
    MergedVerifiedShuffleRunIterV1 {
        kind,
        left: left.into_iter().peekable(),
        right: right.into_iter().peekable(),
        previous_key: None,
        finished: false,
    }
}

pub fn build_owner_shuffle_run<I, S>(
    context: ShuffleRunBuildContextV1,
    records: I,
    limits: &SchemaLimits,
    stage: S,
) -> Result<ShuffleRunArtifactV1, ProtocolError>
where
    I: IntoIterator<Item = Result<ContributorActionV1, ProtocolError>>,
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    build_shuffle_run(
        context,
        ShuffleRunKindV1::Owner,
        records
            .into_iter()
            .map(|record| record.map(VerifiedShuffleRecordV1::Owner)),
        limits,
        stage,
    )
}

pub fn build_bucket_shuffle_run<I, S>(
    context: ShuffleRunBuildContextV1,
    records: I,
    limits: &SchemaLimits,
    stage: S,
) -> Result<ShuffleRunArtifactV1, ProtocolError>
where
    I: IntoIterator<Item = Result<ShuffleBucketRecordV1, ProtocolError>>,
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    build_shuffle_run(
        context,
        ShuffleRunKindV1::Bucket,
        records
            .into_iter()
            .map(|record| record.map(VerifiedShuffleRecordV1::Bucket)),
        limits,
        stage,
    )
}

struct BuiltShuffleSubtreeV1 {
    artifact: ShuffleRunArtifactV1,
    reference: CasObjectRefV1,
}

fn build_shuffle_run<I, S>(
    context: ShuffleRunBuildContextV1,
    kind: ShuffleRunKindV1,
    records: I,
    limits: &SchemaLimits,
    mut stage: S,
) -> Result<ShuffleRunArtifactV1, ProtocolError>
where
    I: IntoIterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    require_valid_run_span(&context.run_span)?;
    require(
        !context.protocol_bundle_hash.is_zero()
            && !context.job_id.is_zero()
            && !context.unit_id.is_zero()
            && !context.source_coverage_root.is_zero()
            && context.source_coverage_count > 0,
        "shuffle build context",
    )?;

    let mut frontier: Vec<Option<BuiltShuffleSubtreeV1>> = Vec::new();
    let mut page = Vec::with_capacity(MAX_SHUFFLE_LEAF_RECORDS);
    let mut page_ordinal = 0_u32;
    let mut first_record_ordinal = 0_u32;
    let mut previous_owner = None;
    let mut previous_bucket = None;

    for record in records {
        let record = record?;
        validate_build_record(kind, &record, &mut previous_owner, &mut previous_bucket)?;
        page.push(record);
        if page.len() == MAX_SHUFFLE_LEAF_RECORDS {
            let leaf = build_leaf(
                &context,
                kind,
                page_ordinal,
                first_record_ordinal,
                core::mem::take(&mut page),
                limits,
                &mut stage,
            )?;
            push_subtree(&context, kind, leaf, &mut frontier, limits, &mut stage)?;
            page_ordinal = page_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "shuffle output page ordinal",
                })?;
            first_record_ordinal = first_record_ordinal
                .checked_add(MAX_SHUFFLE_LEAF_RECORDS as u32)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "shuffle output record ordinal",
                })?;
            page = Vec::with_capacity(MAX_SHUFFLE_LEAF_RECORDS);
        }
    }

    if !page.is_empty() || (first_record_ordinal == 0 && kind == ShuffleRunKindV1::Owner) {
        let leaf = build_leaf(
            &context,
            kind,
            page_ordinal,
            first_record_ordinal,
            page,
            limits,
            &mut stage,
        )?;
        push_subtree(&context, kind, leaf, &mut frontier, limits, &mut stage)?;
    } else if first_record_ordinal == 0 {
        return Err(ProtocolError::InvalidInvariant(
            "non-empty bucket shuffle run",
        ));
    }

    let mut root = None;
    for subtree in frontier.into_iter().flatten() {
        root = Some(match root {
            None => subtree,
            Some(right) => build_node(&context, kind, subtree, right, limits, &mut stage)?,
        });
    }
    let root = root
        .ok_or(ProtocolError::InvalidInvariant("shuffle output root"))?
        .artifact;
    root.validate_root_semantics(limits)?;
    Ok(root)
}

fn validate_build_record(
    kind: ShuffleRunKindV1,
    record: &VerifiedShuffleRecordV1,
    previous_owner: &mut Option<(Address, B256)>,
    previous_bucket: &mut Option<(B256, u32)>,
) -> Result<(), ProtocolError> {
    match record {
        VerifiedShuffleRecordV1::Owner(record) => {
            require(kind == ShuffleRunKindV1::Owner, "shuffle build record kind")?;
            let key = (record.owner, record.source_tribute_id);
            require(
                previous_owner.is_none_or(|previous| previous.0 < key.0)
                    && previous_bucket.is_none(),
                "global owner shuffle order",
            )?;
            *previous_owner = Some(key);
        }
        VerifiedShuffleRecordV1::Bucket(record) => {
            require(
                kind == ShuffleRunKindV1::Bucket,
                "shuffle build record kind",
            )?;
            let key = (record.bucket_key, record.raw_ordinal);
            require(
                previous_bucket.is_none_or(|previous| previous < key) && previous_owner.is_none(),
                "global bucket shuffle order",
            )?;
            *previous_bucket = Some(key);
        }
    }
    Ok(())
}

fn build_leaf<S>(
    context: &ShuffleRunBuildContextV1,
    kind: ShuffleRunKindV1,
    page_ordinal: u32,
    first_record_ordinal: u32,
    records: Vec<VerifiedShuffleRecordV1>,
    limits: &SchemaLimits,
    stage: &mut S,
) -> Result<BuiltShuffleSubtreeV1, ProtocolError>
where
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    let record_count =
        u32::try_from(records.len()).map_err(|_| ProtocolError::IntegerOverflow {
            what: "shuffle leaf record count",
        })?;
    let payload = match kind {
        ShuffleRunKindV1::Owner => ShuffleRunPayloadV1::OwnerLeaf(
            records
                .into_iter()
                .map(|record| match record {
                    VerifiedShuffleRecordV1::Owner(record) => Ok(record),
                    VerifiedShuffleRecordV1::Bucket(_) => Err(ProtocolError::InvalidInvariant(
                        "shuffle build owner record",
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ShuffleRunKindV1::Bucket => ShuffleRunPayloadV1::BucketLeaf(
            records
                .into_iter()
                .map(|record| match record {
                    VerifiedShuffleRecordV1::Bucket(record) => Ok(record),
                    VerifiedShuffleRecordV1::Owner(_) => Err(ProtocolError::InvalidInvariant(
                        "shuffle build bucket record",
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let artifact = ShuffleRunArtifactV1 {
        protocol_bundle_hash: context.protocol_bundle_hash,
        job_id: context.job_id,
        attempt: context.attempt,
        unit_id: context.unit_id,
        kind,
        run_span: context.run_span.clone(),
        page_span: ShufflePageSpanV1 {
            start_page: page_ordinal,
            end_page: page_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "shuffle leaf page span",
                })?,
        },
        first_record_ordinal,
        record_count,
        source_coverage_root: context.source_coverage_root,
        source_coverage_count: context.source_coverage_count,
        ordered_record_root: B256::ZERO,
        payload,
    }
    .with_recomputed_ordered_record_root(limits)?;
    stage_artifact(artifact, limits, stage)
}

fn push_subtree<S>(
    context: &ShuffleRunBuildContextV1,
    kind: ShuffleRunKindV1,
    mut subtree: BuiltShuffleSubtreeV1,
    frontier: &mut Vec<Option<BuiltShuffleSubtreeV1>>,
    limits: &SchemaLimits,
    stage: &mut S,
) -> Result<(), ProtocolError>
where
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    let mut level = 0_usize;
    loop {
        if level == frontier.len() {
            frontier.push(Some(subtree));
            return Ok(());
        }
        let Some(left) = frontier[level].take() else {
            frontier[level] = Some(subtree);
            return Ok(());
        };
        subtree = build_node(context, kind, left, subtree, limits, stage)?;
        level = level.checked_add(1).ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle builder frontier level",
        })?;
    }
}

fn build_node<S>(
    context: &ShuffleRunBuildContextV1,
    kind: ShuffleRunKindV1,
    left: BuiltShuffleSubtreeV1,
    right: BuiltShuffleSubtreeV1,
    limits: &SchemaLimits,
    stage: &mut S,
) -> Result<BuiltShuffleSubtreeV1, ProtocolError>
where
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    let page_span = ShufflePageSpanV1 {
        start_page: left.artifact.page_span.start_page,
        end_page: right.artifact.page_span.end_page,
    };
    let record_count = left
        .artifact
        .record_count
        .checked_add(right.artifact.record_count)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle node output count",
        })?;
    let first_record_ordinal = left.artifact.first_record_ordinal;
    let artifact = ShuffleRunArtifactV1 {
        protocol_bundle_hash: context.protocol_bundle_hash,
        job_id: context.job_id,
        attempt: context.attempt,
        unit_id: context.unit_id,
        kind,
        run_span: context.run_span.clone(),
        page_span,
        first_record_ordinal,
        record_count,
        source_coverage_root: context.source_coverage_root,
        source_coverage_count: context.source_coverage_count,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::Node {
            left: child_summary(left),
            right: child_summary(right),
        },
    }
    .with_recomputed_ordered_record_root(limits)?;
    stage_artifact(artifact, limits, stage)
}

fn child_summary(subtree: BuiltShuffleSubtreeV1) -> ShuffleRunChildV1 {
    ShuffleRunChildV1 {
        artifact_ref: subtree.reference,
        page_span: subtree.artifact.page_span,
        first_record_ordinal: subtree.artifact.first_record_ordinal,
        record_count: subtree.artifact.record_count,
        ordered_record_root: subtree.artifact.ordered_record_root,
    }
}

fn stage_artifact<S>(
    artifact: ShuffleRunArtifactV1,
    limits: &SchemaLimits,
    stage: &mut S,
) -> Result<BuiltShuffleSubtreeV1, ProtocolError>
where
    S: FnMut(&[u8]) -> Result<CasObjectRefV1, ProtocolError>,
{
    let bytes = artifact.encode_canonical(limits)?;
    let reference = stage(&bytes)?;
    let encoded_bytes = u64::try_from(bytes.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "staged shuffle object bytes",
    })?;
    require(
        reference.transport_digest == keccak256(&bytes)
            && reference.encoded_bytes == encoded_bytes
            && reference.expected_ocb1_kind == Some(ObjectKind::ShuffleRunArtifactV1.tag()),
        "staged shuffle object descriptor",
    )?;
    Ok(BuiltShuffleSubtreeV1 {
        artifact,
        reference,
    })
}

impl<R> Iterator for VerifiedShuffleRunIterV1<'_, R>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    type Item = Result<VerifiedShuffleRecordV1, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(record) = self.pending_records.pop_front() {
                return Some(self.validate_next_record(record));
            }
            let Some(artifact) = self.stack.pop() else {
                if self.finished {
                    return None;
                }
                self.finished = true;
                return self.finish().err().map(Err);
            };
            if let Err(error) = self.open_artifact(artifact) {
                self.finished = true;
                return Some(Err(error));
            }
        }
    }
}

impl<L, R> Iterator for MergedVerifiedShuffleRunIterV1<L, R>
where
    L: Iterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
    R: Iterator<Item = Result<VerifiedShuffleRecordV1, ProtocolError>>,
{
    type Item = Result<VerifiedShuffleRecordV1, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let side = match (self.left.peek(), self.right.peek()) {
            (Some(Err(_)), _) => MergeSideV1::Left,
            (_, Some(Err(_))) => MergeSideV1::Right,
            (Some(Ok(left)), Some(Ok(right))) => {
                let left_key = match shuffle_record_key(self.kind, left) {
                    Ok(key) => key,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                };
                let right_key = match shuffle_record_key(self.kind, right) {
                    Ok(key) => key,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                };
                if left_key <= right_key {
                    MergeSideV1::Left
                } else {
                    MergeSideV1::Right
                }
            }
            (Some(Ok(_)), None) => MergeSideV1::Left,
            (None, Some(Ok(_))) => MergeSideV1::Right,
            (None, None) => return None,
        };
        let item = match side {
            MergeSideV1::Left => self.left.next(),
            MergeSideV1::Right => self.right.next(),
        }?;
        let record = match item {
            Ok(record) => record,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        let key = match shuffle_record_key(self.kind, &record) {
            Ok(key) => key,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        if self
            .previous_key
            .is_some_and(|previous| !strict_shuffle_key_order(previous, key))
        {
            self.finished = true;
            return Some(Err(ProtocolError::InvalidInvariant(
                "strict merged shuffle order",
            )));
        }
        self.previous_key = Some(key);
        Some(Ok(record))
    }
}

#[derive(Clone, Copy)]
enum MergeSideV1 {
    Left,
    Right,
}

fn shuffle_record_key(
    kind: ShuffleRunKindV1,
    record: &VerifiedShuffleRecordV1,
) -> Result<VerifiedShuffleRecordKeyV1, ProtocolError> {
    match (kind, record) {
        (ShuffleRunKindV1::Owner, VerifiedShuffleRecordV1::Owner(record)) => Ok(
            VerifiedShuffleRecordKeyV1::Owner(record.owner, record.source_tribute_id),
        ),
        (ShuffleRunKindV1::Bucket, VerifiedShuffleRecordV1::Bucket(record)) => Ok(
            VerifiedShuffleRecordKeyV1::Bucket(record.bucket_key, record.raw_ordinal),
        ),
        _ => Err(ProtocolError::InvalidInvariant(
            "merged shuffle record kind",
        )),
    }
}

fn strict_shuffle_key_order(
    previous: VerifiedShuffleRecordKeyV1,
    current: VerifiedShuffleRecordKeyV1,
) -> bool {
    match (previous, current) {
        (
            VerifiedShuffleRecordKeyV1::Owner(previous_owner, _),
            VerifiedShuffleRecordKeyV1::Owner(current_owner, _),
        ) => previous_owner < current_owner,
        (
            VerifiedShuffleRecordKeyV1::Bucket(previous_bucket, previous_ordinal),
            VerifiedShuffleRecordKeyV1::Bucket(current_bucket, current_ordinal),
        ) => (previous_bucket, previous_ordinal) < (current_bucket, current_ordinal),
        _ => false,
    }
}

impl<R> VerifiedShuffleRunIterV1<'_, R>
where
    R: FnMut(&CasObjectRefV1) -> Result<Vec<u8>, ProtocolError>,
{
    fn open_artifact(&mut self, artifact: ShuffleRunArtifactV1) -> Result<(), ProtocolError> {
        self.require_context(&artifact)?;
        match artifact.payload {
            ShuffleRunPayloadV1::OwnerLeaf(records) => {
                self.open_leaf(
                    artifact.page_span,
                    artifact.first_record_ordinal,
                    artifact.record_count,
                )?;
                self.pending_records
                    .extend(records.into_iter().map(VerifiedShuffleRecordV1::Owner));
            }
            ShuffleRunPayloadV1::BucketLeaf(records) => {
                self.open_leaf(
                    artifact.page_span,
                    artifact.first_record_ordinal,
                    artifact.record_count,
                )?;
                self.pending_records
                    .extend(records.into_iter().map(VerifiedShuffleRecordV1::Bucket));
            }
            ShuffleRunPayloadV1::Node { left, right } => {
                let right = self.resolve_child(&right)?;
                let left = self.resolve_child(&left)?;
                self.stack.push(right);
                self.stack.push(left);
            }
        }
        Ok(())
    }

    fn resolve_child(
        &mut self,
        expected: &ShuffleRunChildV1,
    ) -> Result<ShuffleRunArtifactV1, ProtocolError> {
        let bytes = (self.resolver)(&expected.artifact_ref)?;
        let encoded_bytes =
            u64::try_from(bytes.len()).map_err(|_| ProtocolError::IntegerOverflow {
                what: "shuffle child encoded bytes",
            })?;
        require(
            encoded_bytes == expected.artifact_ref.encoded_bytes
                && keccak256(&bytes) == expected.artifact_ref.transport_digest,
            "shuffle child transport descriptor",
        )?;
        let child = ShuffleRunArtifactV1::decode_canonical(&bytes, self.limits)?;
        self.require_context(&child)?;
        require(
            child.page_span == expected.page_span
                && child.first_record_ordinal == expected.first_record_ordinal
                && child.record_count == expected.record_count
                && child.ordered_record_root == expected.ordered_record_root,
            "shuffle child summary",
        )?;
        Ok(child)
    }

    fn require_context(&self, artifact: &ShuffleRunArtifactV1) -> Result<(), ProtocolError> {
        artifact.validate_semantics(self.limits)?;
        require(
            artifact.protocol_bundle_hash == self.context.protocol_bundle_hash
                && artifact.job_id == self.context.job_id
                && artifact.attempt == self.context.attempt
                && artifact.unit_id == self.context.unit_id
                && artifact.kind == self.context.kind
                && artifact.run_span == self.context.run_span
                && artifact.source_coverage_root == self.context.source_coverage_root
                && artifact.source_coverage_count == self.context.source_coverage_count,
            "shuffle descendant context",
        )
    }

    fn open_leaf(
        &mut self,
        page_span: ShufflePageSpanV1,
        first_record_ordinal: u32,
        record_count: u32,
    ) -> Result<(), ProtocolError> {
        if let Some(previous) = self.previous_leaf_record_count {
            require(
                usize::try_from(previous).ok() == Some(MAX_SHUFFLE_LEAF_RECORDS),
                "full non-final shuffle leaf",
            )?;
        }
        require(
            page_span.start_page == self.next_page
                && page_span.end_page
                    == self
                        .next_page
                        .checked_add(1)
                        .ok_or(ProtocolError::IntegerOverflow {
                            what: "shuffle traversal page",
                        })?
                && first_record_ordinal == self.yielded_record_count,
            "shuffle traversal leaf adjacency",
        )?;
        self.next_page = page_span.end_page;
        self.leaf_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "shuffle traversal leaf count",
            })?;
        self.previous_leaf_record_count = Some(record_count);
        Ok(())
    }

    fn validate_next_record(
        &mut self,
        record: VerifiedShuffleRecordV1,
    ) -> Result<VerifiedShuffleRecordV1, ProtocolError> {
        match &record {
            VerifiedShuffleRecordV1::Owner(record) => {
                require(
                    self.context.kind == ShuffleRunKindV1::Owner,
                    "shuffle traversal record kind",
                )?;
                let key = (record.owner, record.source_tribute_id);
                require(
                    self.previous_owner
                        .is_none_or(|previous| previous.0 < key.0)
                        && self.previous_bucket.is_none(),
                    "global owner shuffle order",
                )?;
                self.previous_owner = Some(key);
            }
            VerifiedShuffleRecordV1::Bucket(record) => {
                require(
                    self.context.kind == ShuffleRunKindV1::Bucket,
                    "shuffle traversal record kind",
                )?;
                let key = (record.bucket_key, record.raw_ordinal);
                require(
                    self.previous_bucket.is_none_or(|previous| previous < key)
                        && self.previous_owner.is_none(),
                    "global bucket shuffle order",
                )?;
                self.previous_bucket = Some(key);
            }
        }
        self.yielded_record_count =
            self.yielded_record_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "shuffle traversal record count",
                })?;
        Ok(record)
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        require(
            self.leaf_count == self.context.root_page_end
                && self.next_page == self.context.root_page_end
                && self.yielded_record_count == self.context.root_record_count,
            "shuffle traversal exact counts",
        )?;
        if self.context.root_record_count == 0 {
            require(
                self.context.kind == ShuffleRunKindV1::Owner
                    && self.leaf_count == 1
                    && self.previous_leaf_record_count == Some(0),
                "canonical empty owner shuffle run",
            )
        } else {
            require(
                self.previous_leaf_record_count.is_some_and(|count| {
                    count > 0
                        && usize::try_from(count)
                            .is_ok_and(|count| count <= MAX_SHUFFLE_LEAF_RECORDS)
                }),
                "non-empty final shuffle leaf",
            )
        }
    }
}

impl ShuffleSourceCoverageV1 {
    pub fn leaf(
        run_span: CanonicalRunSpan,
        raw_coverage_root: B256,
        raw_coverage_count: u32,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        require_valid_run_span(&run_span)?;
        require(
            !raw_coverage_root.is_zero() && raw_coverage_count > 0,
            "shuffle leaf source coverage",
        )?;
        let mut payload = CanonicalWriter::new(limits.codec);
        payload.write_u8(1)?;
        payload.write_u32(run_span.start_run)?;
        payload.write_u32(run_span.end_run)?;
        payload.write_b256(raw_coverage_root)?;
        payload.write_u32(raw_coverage_count)?;
        Ok(Self {
            run_span,
            root: hash_framed(HashDomain::ShuffleSourceCoverage, payload.as_slice())?,
            count: raw_coverage_count,
        })
    }

    pub fn merge(left: &Self, right: &Self, limits: &SchemaLimits) -> Result<Self, ProtocolError> {
        require_valid_run_span(&left.run_span)?;
        require_valid_run_span(&right.run_span)?;
        require(
            left.run_span.end_run == right.run_span.start_run,
            "adjacent shuffle source coverage",
        )?;
        require(
            !left.root.is_zero() && !right.root.is_zero() && left.count > 0 && right.count > 0,
            "shuffle producer source coverage",
        )?;
        let count = left
            .count
            .checked_add(right.count)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "shuffle source coverage count",
            })?;
        let run_span = CanonicalRunSpan {
            start_run: left.run_span.start_run,
            end_run: right.run_span.end_run,
        };
        let mut payload = CanonicalWriter::new(limits.codec);
        payload.write_u8(2)?;
        payload.write_u32(run_span.start_run)?;
        payload.write_u32(run_span.end_run)?;
        payload.write_b256(left.root)?;
        payload.write_u32(left.count)?;
        payload.write_b256(right.root)?;
        payload.write_u32(right.count)?;
        Ok(Self {
            run_span,
            root: hash_framed(HashDomain::ShuffleSourceCoverage, payload.as_slice())?,
            count,
        })
    }
}

wire_enum_u8! {
    pub enum ShuffleRunKindV1 {
        Owner = 1,
        Bucket = 2,
    }
}

wire_struct! {
    pub struct ShufflePageSpanV1 {
        pub start_page: u32,
        pub end_page: u32,
    }
    validate = validate_page_span;
}

wire_struct! {
    pub struct ShuffleBucketRecordV1 {
        pub bucket_key: B256,
        pub raw_ordinal: u32,
        pub tribute_id: B256,
        pub nod_id: B256,
    }
}

impl ShuffleBucketRecordV1 {
    pub fn encode_canonical_record(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut writer, limits)?;
        Ok(writer.into_bytes())
    }
}

wire_struct! {
    /// Authenticated summary of one child object. The referenced child repeats
    /// the root's immutable identity and source-coverage fields.
    pub struct ShuffleRunChildV1 {
        pub artifact_ref: CasObjectRefV1,
        pub page_span: ShufflePageSpanV1,
        pub first_record_ordinal: u32,
        pub record_count: u32,
        pub ordered_record_root: B256,
    }
    validate = validate_child;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShuffleRunPayloadV1 {
    OwnerLeaf(Vec<ContributorActionV1>),
    BucketLeaf(Vec<ShuffleBucketRecordV1>),
    Node {
        left: ShuffleRunChildV1,
        right: ShuffleRunChildV1,
    },
}

impl NestedCodec for ShuffleRunPayloadV1 {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        match self {
            Self::OwnerLeaf(records) => validate_owner_records(records, limits),
            Self::BucketLeaf(records) => validate_bucket_records(records, limits),
            Self::Node { left, right } => {
                left.validate(limits)?;
                right.validate(limits)
            }
        }
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_u8(match self {
            Self::OwnerLeaf(_) => 1,
            Self::BucketLeaf(_) => 2,
            Self::Node { .. } => 3,
        })?;
        match self {
            Self::OwnerLeaf(records) => records.encode_nested(output, limits),
            Self::BucketLeaf(records) => records.encode_nested(output, limits),
            Self::Node { left, right } => {
                left.encode_nested(output, limits)?;
                right.encode_nested(output, limits)
            }
        }
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        match input.read_u8()? {
            1 => Ok(Self::OwnerLeaf(Vec::<ContributorActionV1>::decode_nested(
                input, limits,
            )?)),
            2 => Ok(Self::BucketLeaf(
                Vec::<ShuffleBucketRecordV1>::decode_nested(input, limits)?,
            )),
            3 => Ok(Self::Node {
                left: ShuffleRunChildV1::decode_nested(input, limits)?,
                right: ShuffleRunChildV1::decode_nested(input, limits)?,
            }),
            value => Err(ProtocolError::UnknownEnum {
                width: 8,
                value: u16::from(value),
            }),
        }
    }
}

wire_struct! {
    pub struct ShuffleRunArtifactV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub unit_id: B256,
        pub kind: ShuffleRunKindV1,
        pub run_span: CanonicalRunSpan,
        pub page_span: ShufflePageSpanV1,
        pub first_record_ordinal: u32,
        pub record_count: u32,
        pub source_coverage_root: B256,
        pub source_coverage_count: u32,
        pub ordered_record_root: B256,
        pub payload: ShuffleRunPayloadV1,
    }
    validate = validate_shuffle_run_artifact;
}
impl_top_level_codec!(ShuffleRunArtifactV1, ShuffleRunArtifactV1);

impl ShuffleRunArtifactV1 {
    /// Binds the canonical leaf-list or binary-node commitment after all other
    /// fields and child summaries have been selected.
    pub fn with_recomputed_ordered_record_root(
        mut self,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        self.ordered_record_root = self.recompute_ordered_record_root(limits)?;
        Ok(self)
    }

    pub fn recompute_ordered_record_root(
        &self,
        limits: &SchemaLimits,
    ) -> Result<B256, ProtocolError> {
        match &self.payload {
            ShuffleRunPayloadV1::OwnerLeaf(records) => {
                validate_owner_records(records, limits)?;
                ordered_leaf_root(
                    ListKind::ContributorActions,
                    records
                        .iter()
                        .map(|record| encode_nested_value(record, limits)),
                    records.len(),
                    limits,
                )
            }
            ShuffleRunPayloadV1::BucketLeaf(records) => {
                validate_bucket_records(records, limits)?;
                ordered_leaf_root(
                    ListKind::BucketRecords,
                    records
                        .iter()
                        .map(|record| encode_nested_value(record, limits)),
                    records.len(),
                    limits,
                )
            }
            ShuffleRunPayloadV1::Node { left, right } => {
                left.validate(limits)?;
                right.validate(limits)?;
                let mut payload = CanonicalWriter::new(limits.codec);
                payload.write_u8(self.kind as u8)?;
                payload.write_u32(self.page_span.start_page)?;
                payload.write_u32(self.page_span.end_page)?;
                payload.write_u32(self.first_record_ordinal)?;
                payload.write_u32(self.record_count)?;
                payload.write_b256(left.ordered_record_root)?;
                payload.write_b256(right.ordered_record_root)?;
                hash_framed(HashDomain::ShuffleRunNode, payload.as_slice())
            }
        }
    }

    /// Validates one root embedded by a producing `UnitArtifactV1`.
    pub fn validate_root_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        self.validate_semantics(limits)?;
        require(self.page_span.start_page == 0, "shuffle root first page")?;
        require(
            self.first_record_ordinal == 0,
            "shuffle root first record ordinal",
        )
    }

    /// Validates the fields that are self-contained in this object. A consumer
    /// additionally opens child references and compares their repeated fields.
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)
    }
}

fn validate_page_span(
    span: &ShufflePageSpanV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        span.start_page < span.end_page,
        "non-empty shuffle page span",
    )
}

fn require_valid_run_span(run_span: &CanonicalRunSpan) -> Result<(), ProtocolError> {
    require(
        run_span.start_run < run_span.end_run,
        "non-empty shuffle run span",
    )
}

fn validate_child(child: &ShuffleRunChildV1, _limits: &SchemaLimits) -> Result<(), ProtocolError> {
    require(
        !child.artifact_ref.transport_digest.is_zero()
            && child.artifact_ref.encoded_bytes > 0
            && child.artifact_ref.expected_ocb1_kind
                == Some(ObjectKind::ShuffleRunArtifactV1.tag()),
        "typed shuffle child CAS reference",
    )?;
    require(
        !child.ordered_record_root.is_zero(),
        "shuffle child ordered record root",
    )?;
    checked_record_end(child.first_record_ordinal, child.record_count)?;
    Ok(())
}

fn validate_shuffle_run_artifact(
    artifact: &ShuffleRunArtifactV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !artifact.protocol_bundle_hash.is_zero()
            && !artifact.job_id.is_zero()
            && !artifact.unit_id.is_zero(),
        "shuffle artifact identity",
    )?;
    require_valid_run_span(&artifact.run_span)?;
    require(
        artifact.source_coverage_count > 0 && !artifact.source_coverage_root.is_zero(),
        "shuffle source coverage",
    )?;
    require(
        !artifact.ordered_record_root.is_zero(),
        "shuffle ordered record root",
    )?;
    checked_record_end(artifact.first_record_ordinal, artifact.record_count)?;

    let page_width = artifact
        .page_span
        .end_page
        .checked_sub(artifact.page_span.start_page)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle page width",
        })?;
    match &artifact.payload {
        ShuffleRunPayloadV1::OwnerLeaf(records) => {
            require(
                artifact.kind == ShuffleRunKindV1::Owner,
                "shuffle payload kind binding",
            )?;
            validate_leaf_shape(artifact, page_width, records.len())
        }
        ShuffleRunPayloadV1::BucketLeaf(records) => {
            require(
                artifact.kind == ShuffleRunKindV1::Bucket,
                "shuffle payload kind binding",
            )?;
            require(!records.is_empty(), "non-empty bucket shuffle leaf")?;
            validate_leaf_shape(artifact, page_width, records.len())
        }
        ShuffleRunPayloadV1::Node { left, right } => {
            require(page_width > 1, "shuffle node page width")?;
            require(artifact.record_count > 0, "non-empty shuffle node")?;
            if artifact.kind == ShuffleRunKindV1::Bucket {
                require(
                    artifact.record_count > 0 && left.record_count > 0 && right.record_count > 0,
                    "non-empty bucket shuffle node",
                )?;
            }
            require(
                left.artifact_ref.transport_digest != right.artifact_ref.transport_digest,
                "shuffle node distinct child objects",
            )?;

            let split = canonical_page_split(&artifact.page_span)?;
            require(
                left.page_span.start_page == artifact.page_span.start_page
                    && left.page_span.end_page == split
                    && right.page_span.start_page == split
                    && right.page_span.end_page == artifact.page_span.end_page,
                "shuffle node canonical page split",
            )?;
            let right_first = checked_record_end(left.first_record_ordinal, left.record_count)?;
            require(
                left.first_record_ordinal == artifact.first_record_ordinal
                    && right.first_record_ordinal == right_first,
                "shuffle node record adjacency",
            )?;
            let child_count = left.record_count.checked_add(right.record_count).ok_or(
                ProtocolError::IntegerOverflow {
                    what: "shuffle node record count",
                },
            )?;
            require(
                child_count == artifact.record_count,
                "shuffle node record count",
            )
        }
    }?;
    require(
        artifact.ordered_record_root == artifact.recompute_ordered_record_root(limits)?,
        "shuffle ordered record root",
    )
}

fn validate_leaf_shape(
    artifact: &ShuffleRunArtifactV1,
    page_width: u32,
    actual_records: usize,
) -> Result<(), ProtocolError> {
    require(page_width == 1, "shuffle leaf page width")?;
    require(
        actual_records <= MAX_SHUFFLE_LEAF_RECORDS,
        "shuffle leaf record cap",
    )?;
    require(
        usize::try_from(artifact.record_count).ok() == Some(actual_records),
        "shuffle leaf record count",
    )
}

fn validate_owner_records(
    records: &[ContributorActionV1],
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        records.len() <= limits.max_chunk_items && records.len() <= MAX_SHUFFLE_LEAF_RECORDS,
        "shuffle leaf record cap",
    )?;
    for record in records {
        record.validate(limits)?;
    }
    for pair in records.windows(2) {
        require(
            (pair[0].owner, pair[0].source_tribute_id) < (pair[1].owner, pair[1].source_tribute_id)
                && pair[0].owner != pair[1].owner,
            "owner shuffle records strictly ordered",
        )?;
    }
    Ok(())
}

fn validate_bucket_records(
    records: &[ShuffleBucketRecordV1],
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        records.len() <= limits.max_chunk_items && records.len() <= MAX_SHUFFLE_LEAF_RECORDS,
        "shuffle leaf record cap",
    )?;
    let mut raw_ordinals = BTreeSet::new();
    let mut tribute_ids = BTreeSet::new();
    let mut nod_ids = BTreeSet::new();
    for record in records {
        record.validate(limits)?;
        require(
            raw_ordinals.insert(record.raw_ordinal)
                && tribute_ids.insert(record.tribute_id)
                && nod_ids.insert(record.nod_id),
            "unique bucket shuffle records",
        )?;
    }
    for pair in records.windows(2) {
        require(
            (pair[0].bucket_key, pair[0].raw_ordinal) < (pair[1].bucket_key, pair[1].raw_ordinal),
            "bucket shuffle records strictly ordered",
        )?;
    }
    Ok(())
}

fn canonical_page_split(span: &ShufflePageSpanV1) -> Result<u32, ProtocolError> {
    let width =
        span.end_page
            .checked_sub(span.start_page)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "shuffle page width",
            })?;
    require(width > 1, "shuffle node page width")?;
    let left_width = 1_u32 << (31 - (width - 1).leading_zeros());
    span.start_page
        .checked_add(left_width)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle page split",
        })
}

fn checked_record_end(start: u32, count: u32) -> Result<u32, ProtocolError> {
    start
        .checked_add(count)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "shuffle record interval",
        })
}

fn ordered_leaf_root(
    kind: ListKind,
    records: impl IntoIterator<Item = Result<Vec<u8>, ProtocolError>>,
    record_count: usize,
    limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    let expected_count =
        u32::try_from(record_count).map_err(|_| ProtocolError::IntegerOverflow {
            what: "shuffle leaf record count",
        })?;
    let mut root = StreamingOrderedListRoot::new(kind, expected_count)?;
    for record in records {
        root.push(&record?, limits.max_bounded_bytes)?;
    }
    root.finish()
}
