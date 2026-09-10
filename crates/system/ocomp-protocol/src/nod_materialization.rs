//! Canonical proof-backed batches for materializing certified NOD generations.

use alloy_primitives::B256;

use crate::{
    codec::{CanonicalReader, CanonicalWriter},
    error::ProtocolError,
    list::{leaf_hash, node_hash, pad_hash, root_hash},
    registry::ListKind,
    result::NodActionV1,
    schema::{impl_top_level_codec, require, wire_struct, NestedCodec, SchemaLimits},
};

pub const MAX_NOD_MATERIALIZATION_ACTIONS: usize = 256;
pub const MAX_NOD_MATERIALIZATION_ROOT_PATH: usize = 32;
const NOD_ACTION_CANONICAL_BYTES: usize = 266;

wire_struct! {
    pub struct NodMaterializationHeadV1 {
        pub queue_sequence: u64,
        pub job_id: B256,
        pub program_semantics_hash: B256,
        pub worldwide_day: u32,
        pub generation: u64,
        pub nod_root: B256,
        pub nod_count: u32,
        pub next_nod_ordinal: u32,
        pub last_progress_height: u64,
    }
    validate = validate_head;
}
impl_top_level_codec!(NodMaterializationHeadV1, NodMaterializationHeadV1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodMaterializationBatchV1 {
    pub queue_sequence: u64,
    pub first_nod_ordinal: u32,
    pub actions: Vec<NodActionV1>,
    pub root_path: Vec<B256>,
}

impl NestedCodec for NodMaterializationBatchV1 {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(self.queue_sequence != 0, "materialization queue sequence")?;
        require(
            !self.actions.is_empty() && self.actions.len() <= MAX_NOD_MATERIALIZATION_ACTIONS,
            "materialization action count",
        )?;
        require(
            self.root_path.len() <= MAX_NOD_MATERIALIZATION_ROOT_PATH,
            "materialization root path length",
        )?;
        for action in &self.actions {
            <NodActionV1 as NestedCodec>::validate(action, limits)?;
        }
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_u64(self.queue_sequence)?;
        output.write_u32(self.first_nod_ordinal)?;
        output.write_vec(
            &self.actions,
            MAX_NOD_MATERIALIZATION_ACTIONS,
            |writer, action| action.encode_nested(writer, limits),
        )?;
        output.write_vec(
            &self.root_path,
            MAX_NOD_MATERIALIZATION_ROOT_PATH,
            |writer, sibling| writer.write_b256(*sibling),
        )
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            queue_sequence: input.read_u64()?,
            first_nod_ordinal: input.read_u32()?,
            actions: input.read_vec(
                MAX_NOD_MATERIALIZATION_ACTIONS,
                NOD_ACTION_CANONICAL_BYTES,
                |reader| NodActionV1::decode_nested(reader, limits),
            )?,
            root_path: input.read_vec(MAX_NOD_MATERIALIZATION_ROOT_PATH, 32, |reader| {
                reader.read_b256()
            })?,
        })
    }
}
impl_top_level_codec!(NodMaterializationBatchV1, NodMaterializationBatchV1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNodMaterializationBatchV1 {
    actions: Vec<NodActionV1>,
}

impl VerifiedNodMaterializationBatchV1 {
    #[must_use]
    pub fn actions(&self) -> &[NodActionV1] {
        &self.actions
    }
}

pub fn verify_nod_materialization_batch(
    batch: &NodMaterializationBatchV1,
    head: &NodMaterializationHeadV1,
    configured_subtree_height: u8,
    limits: &SchemaLimits,
) -> Result<VerifiedNodMaterializationBatchV1, ProtocolError> {
    <NodMaterializationBatchV1 as NestedCodec>::validate(batch, limits)?;
    <NodMaterializationHeadV1 as NestedCodec>::validate(head, limits)?;
    require(
        batch.queue_sequence == head.queue_sequence,
        "materialization queue binding",
    )?;
    require(
        batch.first_nod_ordinal == head.next_nod_ordinal,
        "materialization cursor binding",
    )?;

    let padded_count =
        head.nod_count
            .checked_next_power_of_two()
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization padded NOD count",
            })?;
    let tree_height = u16::try_from(padded_count.trailing_zeros()).map_err(|_| {
        ProtocolError::IntegerOverflow {
            what: "materialization tree height",
        }
    })?;
    let effective_subtree_height = configured_subtree_height.min(tree_height as u8);
    let capacity = 1_u32
        .checked_shl(u32::from(effective_subtree_height))
        .ok_or(ProtocolError::IntegerOverflow {
            what: "materialization batch capacity",
        })?;
    require(
        capacity <= MAX_NOD_MATERIALIZATION_ACTIONS as u32,
        "materialization configured capacity",
    )?;
    require(
        batch.first_nod_ordinal.is_multiple_of(capacity),
        "materialization cursor alignment",
    )?;
    let remaining = head.nod_count.checked_sub(head.next_nod_ordinal).ok_or(
        ProtocolError::InvalidInvariant("materialization remaining NOD count"),
    )?;
    let expected_actions = remaining.min(capacity);
    require(
        batch.actions.len() == expected_actions as usize,
        "materialization exact batch action count",
    )?;
    require(
        batch.root_path.len()
            == usize::from(tree_height.saturating_sub(u16::from(effective_subtree_height))),
        "materialization exact root path length",
    )?;

    let mut nodes = Vec::with_capacity(capacity as usize);
    for offset in 0..capacity {
        let ordinal =
            batch
                .first_nod_ordinal
                .checked_add(offset)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "materialization NOD ordinal",
                })?;
        if offset < expected_actions {
            let action = &batch.actions[offset as usize];
            require(
                action.raw_ordinal == ordinal && action.wwd == head.worldwide_day,
                "materialization ordered action binding",
            )?;
            nodes.push(leaf_hash(
                ListKind::NodActions,
                ordinal,
                &action.encode_canonical_record(limits)?,
            )?);
        } else {
            nodes.push(pad_hash(ListKind::NodActions, ordinal)?);
        }
    }

    let mut width = capacity as usize;
    let mut level = 1_u16;
    while width > 1 {
        for index in 0..width / 2 {
            let global_index = (batch.first_nod_ordinal >> level)
                .checked_add(
                    u32::try_from(index).map_err(|_| ProtocolError::IntegerOverflow {
                        what: "materialization subtree index",
                    })?,
                )
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "materialization global subtree index",
                })?;
            nodes[index] = node_hash(
                ListKind::NodActions,
                level,
                global_index,
                nodes[index * 2],
                nodes[index * 2 + 1],
            )?;
        }
        width /= 2;
        level = level.checked_add(1).ok_or(ProtocolError::IntegerOverflow {
            what: "materialization subtree level",
        })?;
    }

    let mut hash = nodes[0];
    let mut position = batch.first_nod_ordinal >> effective_subtree_height;
    for (offset, sibling) in batch.root_path.iter().enumerate() {
        let child_level = u16::from(effective_subtree_height)
            .checked_add(
                u16::try_from(offset).map_err(|_| ProtocolError::IntegerOverflow {
                    what: "materialization root path level",
                })?,
            )
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization root path level",
            })?;
        let parent_level = child_level
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization parent level",
            })?;
        hash = if position & 1 == 0 {
            node_hash(
                ListKind::NodActions,
                parent_level,
                position >> 1,
                hash,
                *sibling,
            )?
        } else {
            node_hash(
                ListKind::NodActions,
                parent_level,
                position >> 1,
                *sibling,
                hash,
            )?
        };
        position >>= 1;
    }
    let committed = root_hash(ListKind::NodActions, head.nod_count, tree_height, hash)?;
    require(committed == head.nod_root, "materialization NOD root")?;

    Ok(VerifiedNodMaterializationBatchV1 {
        actions: batch.actions.clone(),
    })
}

fn validate_head(
    head: &NodMaterializationHeadV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        head.queue_sequence != 0
            && !head.job_id.is_zero()
            && !head.program_semantics_hash.is_zero()
            && head.worldwide_day != 0
            && head.generation != 0
            && !head.nod_root.is_zero()
            && head.nod_count != 0
            && head.next_nod_ordinal < head.nod_count,
        "materialization head authority",
    )
}
