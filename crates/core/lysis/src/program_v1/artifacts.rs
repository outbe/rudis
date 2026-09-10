//! Canonical bounded artifacts for the fixed Lysis V1 work graph.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, WwdEntityId};
use outbe_ocomp_protocol::list::{
    leaf_hash, node_hash, ordered_list_root, pad_hash, root_hash, OrderedListLimits,
};
use outbe_ocomp_protocol::registry::{HashDomain, ListKind};
use outbe_ocomp_protocol::unit::UnitPhase;
use outbe_ocomp_protocol::{hash_framed, CanonicalReader, CanonicalWriter, SchemaLimits};
use outbe_primitives::time::WorldwideDay;

use outbe_nod::NodContract;

use super::execute::validate_canonical_tributes;
use super::phases::{
    AmountRecordV1, AmountRunV1, FidelityAggregateV1, FidelityLeaguePartialV1, FidelityMapOutputV1,
    FidelityObservationV1, FinalizedContributorV1, FinalizedOutputRecordV1, FinalizedOutputRunV1,
    GratisIncomingV1, GratisLeafPrefixV1, GratisSegmentSummaryV1,
};
use super::planner::PRIMARY_WORK_SHARD_SIZE;
use super::{LeagueFractionV1, NodActionV1, ProgramErrorV1, TributeInputV1};

const ENUMERATED_RUN_MAGIC: [u8; 4] = *b"LYE1";
const FIDELITY_MAP_MAGIC: [u8; 4] = *b"LYF1";
const FIXED_REDUCE_MAGIC: [u8; 4] = *b"LYR1";
const AMOUNT_RUN_MAGIC: [u8; 4] = *b"LYA1";
const GRATIS_SUMMARY_MAGIC: [u8; 4] = *b"LYG1";
const GRATIS_PREFIX_DOWN_MAGIC: [u8; 4] = *b"LYD1";
const FINALIZED_OUTPUT_MAGIC: [u8; 4] = *b"LYO1";
const RAW_COVERAGE_CARRIER_MAGIC: [u8; 4] = *b"LYC1";
const COVERAGE_RECORD_BYTES: usize = 36;
const PRIMARY_SUBTREE_HEIGHT: u16 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawCoverageCarrierV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub subtree_height: u16,
    pub subtree_index: u32,
    pub tree_root: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedReduceOutputV1 {
    pub aggregate: Option<FidelityAggregateV1>,
    pub coverage: RawCoverageCarrierV1,
    pub ordered_fractions: Vec<LeagueFractionV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GratisPrefixDownOutputV1 {
    Branch([Option<GratisIncomingV1>; 2]),
    Leaf(GratisLeafPrefixV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GratisSummaryCoverageV1 {
    pub root: B256,
    pub count: u32,
}

impl RawCoverageCarrierV1 {
    pub fn from_records(
        total_count: u32,
        records: &[(u32, WwdEntityId)],
    ) -> Result<Self, LysisArtifactErrorV1> {
        if total_count == 0 || records.is_empty() {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage carrier records",
            ));
        }
        validate_shard_size(records.len())?;

        let start_ordinal = records[0].0;
        let expected_count =
            PRIMARY_WORK_SHARD_SIZE.min(total_count.checked_sub(start_ordinal).ok_or(
                LysisArtifactErrorV1::InvalidEncoding("raw coverage carrier range"),
            )?);
        if !start_ordinal.is_multiple_of(PRIMARY_WORK_SHARD_SIZE)
            || records.len() != expected_count as usize
            || records.iter().enumerate().any(|(offset, (ordinal, _))| {
                u32::try_from(offset)
                    .ok()
                    .and_then(|offset| start_ordinal.checked_add(offset))
                    != Some(*ordinal)
            })
            || records.windows(2).any(|pair| pair[0].1 >= pair[1].1)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage carrier canonical records",
            ));
        }

        let primary_count = total_count.div_ceil(PRIMARY_WORK_SHARD_SIZE);
        let subtree_height = if primary_count == 1 {
            u16::try_from(
                total_count
                    .checked_next_power_of_two()
                    .ok_or(LysisArtifactErrorV1::LengthOverflow)?
                    .trailing_zeros(),
            )
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?
        } else {
            PRIMARY_SUBTREE_HEIGHT
        };
        let subtree_index = start_ordinal >> subtree_height;
        let tree_root =
            raw_coverage_subtree_root(start_ordinal, subtree_height, total_count, records)?;
        Ok(Self {
            start_ordinal,
            end_ordinal: start_ordinal
                .checked_add(expected_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
            subtree_height,
            subtree_index,
            tree_root,
        })
    }

    pub fn canonical_empty(
        total_count: u32,
        primary_ordinal: u32,
    ) -> Result<Self, LysisArtifactErrorV1> {
        let primary_count = total_count.div_ceil(PRIMARY_WORK_SHARD_SIZE);
        let padded_primary_count = primary_count
            .checked_next_power_of_two()
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?
            .max(2);
        if primary_ordinal < primary_count || primary_ordinal >= padded_primary_count {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage empty carrier position",
            ));
        }
        let start = primary_ordinal
            .checked_mul(PRIMARY_WORK_SHARD_SIZE)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        Ok(Self {
            start_ordinal: total_count,
            end_ordinal: total_count,
            subtree_height: PRIMARY_SUBTREE_HEIGHT,
            subtree_index: primary_ordinal,
            tree_root: raw_coverage_subtree_root(start, PRIMARY_SUBTREE_HEIGHT, total_count, &[])?,
        })
    }

    pub fn merge(left: &Self, right: &Self) -> Result<Self, LysisArtifactErrorV1> {
        validate_raw_coverage_carrier(left)?;
        validate_raw_coverage_carrier(right)?;
        let expected_right_index = left
            .subtree_index
            .checked_add(1)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        if left.subtree_height != right.subtree_height
            || left.subtree_index & 1 != 0
            || right.subtree_index != expected_right_index
            || left.end_ordinal != right.start_ordinal
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage carrier adjacency",
            ));
        }
        let subtree_height = left
            .subtree_height
            .checked_add(1)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        let subtree_index = left.subtree_index >> 1;
        Ok(Self {
            start_ordinal: left.start_ordinal,
            end_ordinal: right.end_ordinal,
            subtree_height,
            subtree_index,
            tree_root: node_hash(
                ListKind::RawTributeCoverage,
                subtree_height,
                subtree_index,
                left.tree_root,
                right.tree_root,
            )?,
        })
    }

    pub fn final_root(&self, total_count: u32) -> Result<B256, LysisArtifactErrorV1> {
        validate_raw_coverage_carrier(self)?;
        if total_count == 0
            || self.start_ordinal != 0
            || self.end_ordinal != total_count
            || self.subtree_index != 0
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage final carrier range",
            ));
        }
        let tree_height = u16::try_from(
            total_count
                .checked_next_power_of_two()
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
                .trailing_zeros(),
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        if self.subtree_height != tree_height {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage final carrier height",
            ));
        }
        root_hash(
            ListKind::RawTributeCoverage,
            total_count,
            tree_height,
            self.tree_root,
        )
        .map_err(LysisArtifactErrorV1::Protocol)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumeratedTributeRecordV1 {
    pub raw_ordinal: u32,
    pub tribute: TributeInputV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumeratedRunV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub worldwide_day: WorldwideDay,
    pub ordered_records: Vec<EnumeratedTributeRecordV1>,
}

impl EnumeratedRunV1 {
    pub fn coverage_root(&self) -> Result<B256, LysisArtifactErrorV1> {
        validate_enumerated_run(self)?;
        raw_coverage_root(
            self.ordered_records
                .iter()
                .map(|record| (record.raw_ordinal, record.tribute.tribute_id)),
        )
    }
}

impl FidelityMapOutputV1 {
    pub fn coverage_root(&self) -> Result<B256, LysisArtifactErrorV1> {
        validate_fidelity_map_output(self)?;
        raw_coverage_root(
            self.observations
                .iter()
                .map(|record| (record.raw_ordinal, record.tribute_id)),
        )
    }
}

impl AmountRunV1 {
    pub fn coverage_root(&self) -> Result<B256, LysisArtifactErrorV1> {
        validate_amount_run(self)?;
        raw_coverage_root(
            self.ordered_records
                .iter()
                .map(|record| (record.raw_ordinal, record.tribute_id)),
        )
    }
}

impl FinalizedOutputRunV1 {
    pub fn coverage_root(&self) -> Result<B256, LysisArtifactErrorV1> {
        validate_finalized_output_run(self)?;
        raw_coverage_root(
            self.ordered_records
                .iter()
                .map(|record| (record.raw_ordinal, record.nod_action.source_tribute_id)),
        )
    }
}

#[derive(Debug)]
pub enum LysisArtifactErrorV1 {
    InvalidEncoding(&'static str),
    LengthOverflow,
    Program(ProgramErrorV1),
    Protocol(outbe_ocomp_protocol::ProtocolError),
}

impl fmt::Display for LysisArtifactErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(message) => {
                write!(formatter, "invalid Lysis V1 artifact: {message}")
            }
            Self::LengthOverflow => formatter.write_str("Lysis V1 artifact length overflow"),
            Self::Program(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LysisArtifactErrorV1 {}

impl From<ProgramErrorV1> for LysisArtifactErrorV1 {
    fn from(error: ProgramErrorV1) -> Self {
        Self::Program(error)
    }
}

impl From<outbe_ocomp_protocol::ProtocolError> for LysisArtifactErrorV1 {
    fn from(error: outbe_ocomp_protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

pub fn enumerate_tributes(
    start_ordinal: u32,
    worldwide_day: WorldwideDay,
    tributes: &[TributeInputV1],
) -> Result<EnumeratedRunV1, LysisArtifactErrorV1> {
    validate_shard_size(tributes.len())?;
    validate_canonical_tributes(worldwide_day, tributes)?;
    let count = u32::try_from(tributes.len()).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    let end_ordinal = start_ordinal
        .checked_add(count)
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    let ordered_records = tributes
        .iter()
        .enumerate()
        .map(|(offset, tribute)| {
            let offset = u32::try_from(offset).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
            Ok(EnumeratedTributeRecordV1 {
                raw_ordinal: start_ordinal
                    .checked_add(offset)
                    .ok_or(LysisArtifactErrorV1::LengthOverflow)?,
                tribute: tribute.clone(),
            })
        })
        .collect::<Result<Vec<_>, LysisArtifactErrorV1>>()?;
    Ok(EnumeratedRunV1 {
        start_ordinal,
        end_ordinal,
        worldwide_day,
        ordered_records,
    })
}

pub fn encode_raw_coverage_carrier(
    carrier: &RawCoverageCarrierV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_raw_coverage_carrier(carrier)?;
    let mut output = CanonicalWriter::new(limits.codec);
    output.write_fixed(&RAW_COVERAGE_CARRIER_MAGIC)?;
    output.write_u32(carrier.start_ordinal)?;
    output.write_u32(carrier.end_ordinal)?;
    output.write_u16(carrier.subtree_height)?;
    output.write_u32(carrier.subtree_index)?;
    output.write_b256(carrier.tree_root)?;
    Ok(output.into_bytes())
}

pub fn decode_raw_coverage_carrier(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<RawCoverageCarrierV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != RAW_COVERAGE_CARRIER_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "raw coverage carrier header",
        ));
    }
    let carrier = RawCoverageCarrierV1 {
        start_ordinal: input.read_u32()?,
        end_ordinal: input.read_u32()?,
        subtree_height: input.read_u16()?,
        subtree_index: input.read_u32()?,
        tree_root: input.read_b256()?,
    };
    input.finish()?;
    validate_raw_coverage_carrier(&carrier)?;
    if encode_raw_coverage_carrier(&carrier, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "raw coverage carrier canonical re-encoding",
        ));
    }
    Ok(carrier)
}

pub fn encode_fixed_reduce_output(
    output: &FixedReduceOutputV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_fixed_reduce_output(output)?;
    let encoded_carrier = encode_raw_coverage_carrier(&output.coverage, limits)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&FIXED_REDUCE_MAGIC)?;
    encoded.write_bounded_bytes(&encoded_carrier, limits.max_bounded_bytes)?;
    encoded.write_option(output.aggregate.as_ref(), |writer, aggregate| {
        writer.write_u32(aggregate.start_ordinal)?;
        writer.write_u32(aggregate.end_ordinal)?;
        writer.write_u32(aggregate.tribute_count)?;
        writer.write_u256(aggregate.checked_total_nominal)?;
        writer.write_vec(
            &aggregate.ordered_league_partials,
            limits.max_collection_items,
            |writer, partial| {
                writer.write_u16(partial.league_id)?;
                writer.write_u32(partial.count)?;
                writer.write_u256(partial.nominal_amount_minor)
            },
        )
    })?;
    encoded.write_vec(
        &output.ordered_fractions,
        limits.max_collection_items,
        |writer, fraction| {
            writer.write_u16(fraction.league)?;
            writer.write_u256(fraction.fraction)
        },
    )?;
    Ok(encoded.into_bytes())
}

pub fn decode_fixed_reduce_output(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<FixedReduceOutputV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != FIXED_REDUCE_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "fixed reducer output header",
        ));
    }
    let carrier =
        decode_raw_coverage_carrier(input.read_bounded_bytes(limits.max_bounded_bytes)?, limits)?;
    let aggregate = input.read_option(|reader| {
        let start_ordinal = reader.read_u32()?;
        let end_ordinal = reader.read_u32()?;
        let tribute_count = reader.read_u32()?;
        let checked_total_nominal = reader.read_u256()?;
        let ordered_league_partials =
            reader.read_vec(limits.max_collection_items, 38, |reader| {
                Ok(FidelityLeaguePartialV1 {
                    league_id: reader.read_u16()?,
                    count: reader.read_u32()?,
                    nominal_amount_minor: reader.read_u256()?,
                })
            })?;
        Ok(FidelityAggregateV1 {
            start_ordinal,
            end_ordinal,
            tribute_count,
            checked_total_nominal,
            ordered_league_partials,
        })
    })?;
    let ordered_fractions = input.read_vec(limits.max_collection_items, 34, |reader| {
        Ok(LeagueFractionV1 {
            league: reader.read_u16()?,
            fraction: reader.read_u256()?,
        })
    })?;
    input.finish()?;
    let output = FixedReduceOutputV1 {
        aggregate,
        coverage: carrier,
        ordered_fractions,
    };
    validate_fixed_reduce_output(&output)?;
    if encode_fixed_reduce_output(&output, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "fixed reducer output canonical re-encoding",
        ));
    }
    Ok(output)
}

pub fn encode_amount_run(
    run: &AmountRunV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_amount_run(run)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&AMOUNT_RUN_MAGIC)?;
    encoded.write_u32(run.start_ordinal)?;
    encoded.write_u32(run.end_ordinal)?;
    encoded.write_u256(run.checked_segment_gratis_total)?;
    encoded.write_u32(
        u32::try_from(run.ordered_records.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    for record in &run.ordered_records {
        encoded.write_u32(record.raw_ordinal)?;
        encoded.write_b256(*record.tribute_id)?;
        encoded.write_address20(record.owner)?;
        encoded.write_u32(record.worldwide_day.value())?;
        encoded.write_u16(record.league_id)?;
        encoded.write_u256(record.nominal_amount_minor)?;
        encoded.write_u256(record.gratis_fraction_fp)?;
        encoded.write_u256(record.gratis_load_minor)?;
        encoded.write_u256(record.entry_price_minor)?;
        encoded.write_u256(record.floor_price_minor)?;
        encoded.write_u256(record.cost_amount_minor)?;
        encoded.write_u16(record.issuance_currency)?;
        encoded.write_u16(record.reference_currency)?;
        encoded.write_bool(record.exclude_from_intex_issuance)?;
    }
    Ok(encoded.into_bytes())
}

pub fn decode_amount_run(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<AmountRunV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != AMOUNT_RUN_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding("amount run header"));
    }
    let start_ordinal = input.read_u32()?;
    let end_ordinal = input.read_u32()?;
    let checked_segment_gratis_total = input.read_u256()?;
    let count = input.read_u32()?;
    validate_shard_size(usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?)?;
    let mut ordered_records = Vec::new();
    ordered_records
        .try_reserve_exact(
            usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for _ in 0..count {
        ordered_records.push(AmountRecordV1 {
            raw_ordinal: input.read_u32()?,
            tribute_id: WwdEntityId::from(input.read_b256()?),
            owner: input.read_address20()?,
            worldwide_day: WorldwideDay::new(input.read_u32()?),
            league_id: input.read_u16()?,
            nominal_amount_minor: input.read_u256()?,
            gratis_fraction_fp: input.read_u256()?,
            gratis_load_minor: input.read_u256()?,
            entry_price_minor: input.read_u256()?,
            floor_price_minor: input.read_u256()?,
            cost_amount_minor: input.read_u256()?,
            issuance_currency: input.read_u16()?,
            reference_currency: input.read_u16()?,
            exclude_from_intex_issuance: input.read_bool()?,
        });
    }
    input.finish()?;
    let run = AmountRunV1 {
        start_ordinal,
        end_ordinal,
        ordered_records,
        checked_segment_gratis_total,
    };
    validate_amount_run(&run)?;
    if encode_amount_run(&run, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "amount run canonical re-encoding",
        ));
    }
    Ok(run)
}

pub fn encode_gratis_segment_summary(
    summary: &GratisSegmentSummaryV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_gratis_segment_summary(summary)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&GRATIS_SUMMARY_MAGIC)?;
    encoded.write_u32(summary.start_ordinal)?;
    encoded.write_u32(summary.end_ordinal)?;
    encoded.write_u256(summary.checked_segment_gratis_total)?;
    Ok(encoded.into_bytes())
}

pub fn decode_gratis_segment_summary(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<GratisSegmentSummaryV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != GRATIS_SUMMARY_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis summary header",
        ));
    }
    let summary = GratisSegmentSummaryV1 {
        start_ordinal: input.read_u32()?,
        end_ordinal: input.read_u32()?,
        checked_segment_gratis_total: input.read_u256()?,
    };
    input.finish()?;
    validate_gratis_segment_summary(&summary)?;
    if encode_gratis_segment_summary(&summary, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis summary canonical re-encoding",
        ));
    }
    Ok(summary)
}

pub fn encode_gratis_prefix_down_output(
    output: &GratisPrefixDownOutputV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_gratis_prefix_down_output(output)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&GRATIS_PREFIX_DOWN_MAGIC)?;
    match output {
        GratisPrefixDownOutputV1::Branch(children) => {
            encoded.write_u8(1)?;
            for child in children {
                encoded.write_option(child.as_ref(), |writer, incoming| {
                    writer.write_u32(incoming.start_ordinal)?;
                    writer.write_u32(incoming.end_ordinal)?;
                    writer
                        .write_option(incoming.incoming_remaining.as_ref(), |writer, remaining| {
                            writer.write_u256(*remaining)
                        })
                })?;
            }
        }
        GratisPrefixDownOutputV1::Leaf(prefix) => {
            encoded.write_u8(2)?;
            encoded.write_u32(prefix.segment_ordinal)?;
            encoded.write_u256(prefix.incoming_remaining)?;
            encoded.write_u256(prefix.outgoing_remaining)?;
            encoded.write_option(prefix.first_error_ordinal.as_ref(), |writer, ordinal| {
                writer.write_u32(*ordinal)
            })?;
        }
    }
    Ok(encoded.into_bytes())
}

pub fn decode_gratis_prefix_down_output(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<GratisPrefixDownOutputV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != GRATIS_PREFIX_DOWN_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis prefix-down header",
        ));
    }
    let output = match input.read_u8()? {
        1 => {
            let mut child = || {
                input.read_option(|reader| {
                    Ok(GratisIncomingV1 {
                        start_ordinal: reader.read_u32()?,
                        end_ordinal: reader.read_u32()?,
                        incoming_remaining: reader.read_option(|reader| reader.read_u256())?,
                    })
                })
            };
            GratisPrefixDownOutputV1::Branch([child()?, child()?])
        }
        2 => GratisPrefixDownOutputV1::Leaf(GratisLeafPrefixV1 {
            segment_ordinal: input.read_u32()?,
            incoming_remaining: input.read_u256()?,
            outgoing_remaining: input.read_u256()?,
            first_error_ordinal: input.read_option(|reader| reader.read_u32())?,
        }),
        _ => {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Gratis prefix-down variant",
            ))
        }
    };
    input.finish()?;
    validate_gratis_prefix_down_output(&output)?;
    if encode_gratis_prefix_down_output(&output, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis prefix-down canonical re-encoding",
        ));
    }
    Ok(output)
}

pub fn encode_finalized_output_run(
    run: &FinalizedOutputRunV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_finalized_output_run(run)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&FINALIZED_OUTPUT_MAGIC)?;
    encoded.write_u32(run.start_ordinal)?;
    encoded.write_u32(run.end_ordinal)?;
    encoded.write_u32(
        u32::try_from(run.ordered_records.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    for record in &run.ordered_records {
        let nod = &record.nod_action;
        encoded.write_u32(record.raw_ordinal)?;
        encoded.write_b256(*nod.source_tribute_id)?;
        encoded.write_b256(*nod.nod_id)?;
        encoded.write_address20(nod.owner)?;
        encoded.write_u32(nod.worldwide_day.value())?;
        encoded.write_u16(nod.league_id)?;
        encoded.write_u256(nod.floor_price_minor)?;
        encoded.write_u256(nod.gratis_load_minor)?;
        encoded.write_u256(nod.entry_price_minor)?;
        encoded.write_u256(nod.cost_amount_minor)?;
        encoded.write_u16(nod.issuance_currency)?;
        encoded.write_u16(nod.reference_currency)?;
        encoded.write_b256(nod.bucket_key)?;
        encoded.write_u64(nod.issued_at)?;
        encoded.write_option(record.contributor_action.as_ref(), |writer, contributor| {
            writer.write_address20(contributor.owner)?;
            writer.write_b256(*contributor.source_tribute_id)?;
            writer.write_u256(contributor.nominal_amount_minor)
        })?;
    }
    encoded.write_u256(run.checked_tribute_nominal_total)?;
    Ok(encoded.into_bytes())
}

pub fn decode_finalized_output_run(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<FinalizedOutputRunV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != FINALIZED_OUTPUT_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "finalized output header",
        ));
    }
    let start_ordinal = input.read_u32()?;
    let end_ordinal = input.read_u32()?;
    let count = input.read_u32()?;
    validate_shard_size(usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?)?;
    let mut ordered_records = Vec::new();
    ordered_records
        .try_reserve_exact(
            usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for _ in 0..count {
        let raw_ordinal = input.read_u32()?;
        let source_tribute_id = WwdEntityId::from(input.read_b256()?);
        let nod_id = WwdEntityId::from(input.read_b256()?);
        let owner = input.read_address20()?;
        let worldwide_day = WorldwideDay::new(input.read_u32()?);
        let league_id = input.read_u16()?;
        let floor_price_minor = input.read_u256()?;
        let gratis_load_minor = input.read_u256()?;
        let entry_price_minor = input.read_u256()?;
        let cost_amount_minor = input.read_u256()?;
        let issuance_currency = input.read_u16()?;
        let reference_currency = input.read_u16()?;
        let bucket_key = input.read_b256()?;
        let issued_at = input.read_u64()?;
        let contributor_action = input.read_option(|reader| {
            Ok(FinalizedContributorV1 {
                owner: reader.read_address20()?,
                source_tribute_id: WwdEntityId::from(reader.read_b256()?),
                nominal_amount_minor: reader.read_u256()?,
            })
        })?;
        ordered_records.push(FinalizedOutputRecordV1 {
            raw_ordinal,
            nod_action: NodActionV1 {
                source_tribute_id,
                nod_id,
                owner,
                worldwide_day,
                league_id,
                floor_price_minor,
                gratis_load_minor,
                entry_price_minor,
                cost_amount_minor,
                issuance_currency,
                reference_currency,
                bucket_key,
                issued_at,
            },
            contributor_action,
        });
    }
    let checked_tribute_nominal_total = input.read_u256()?;
    input.finish()?;
    let run = FinalizedOutputRunV1 {
        start_ordinal,
        end_ordinal,
        ordered_records,
        checked_tribute_nominal_total,
    };
    validate_finalized_output_run(&run)?;
    if encode_finalized_output_run(&run, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "finalized output canonical re-encoding",
        ));
    }
    Ok(run)
}

pub fn gratis_summary_coverage(
    prefix_interval_commitment: B256,
    children: [Option<(B256, u32)>; 2],
) -> Result<GratisSummaryCoverageV1, LysisArtifactErrorV1> {
    if prefix_interval_commitment.is_zero()
        || children[0].is_none()
        || children
            .iter()
            .flatten()
            .any(|(root, count)| root.is_zero() || *count == 0)
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis summary coverage inputs",
        ));
    }
    let count = children
        .iter()
        .flatten()
        .try_fold(0_u32, |total, (_, count)| total.checked_add(*count))
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    let mut payload = Vec::with_capacity(1 + 32 + (32 * 2) + (4 * 2));
    payload.push(UnitPhase::GratisPrefix as u8);
    payload.extend_from_slice(prefix_interval_commitment.as_slice());
    for child in children {
        let (root, _) = child.unwrap_or((B256::ZERO, 0));
        payload.extend_from_slice(root.as_slice());
    }
    for child in children {
        let (_, count) = child.unwrap_or((B256::ZERO, 0));
        payload.extend_from_slice(&count.to_be_bytes());
    }
    Ok(GratisSummaryCoverageV1 {
        root: hash_framed(HashDomain::UnitCoverage, &payload)?,
        count,
    })
}

pub fn encode_enumerated_run(
    run: &EnumeratedRunV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_enumerated_run(run)?;
    let mut output = CanonicalWriter::new(limits.codec);
    output.write_fixed(&ENUMERATED_RUN_MAGIC)?;
    output.write_u32(run.start_ordinal)?;
    output.write_u32(run.end_ordinal)?;
    output.write_u32(run.worldwide_day.value())?;
    output.write_u32(
        u32::try_from(run.ordered_records.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    for record in &run.ordered_records {
        output.write_u32(record.raw_ordinal)?;
        output.write_b256(*record.tribute.tribute_id)?;
        output.write_address20(record.tribute.owner)?;
        output.write_u16(record.tribute.issuance_currency)?;
        output.write_u256(record.tribute.nominal_amount_minor)?;
        output.write_u16(record.tribute.reference_currency)?;
        output.write_u256(record.tribute.tribute_price_minor)?;
        output.write_bool(record.tribute.exclude_from_intex_issuance)?;
    }
    Ok(output.into_bytes())
}

pub fn decode_enumerated_run(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<EnumeratedRunV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != ENUMERATED_RUN_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "enumerated run header",
        ));
    }
    let start_ordinal = input.read_u32()?;
    let end_ordinal = input.read_u32()?;
    let worldwide_day = WorldwideDay::new(input.read_u32()?);
    let count = input.read_u32()?;
    validate_shard_size(usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?)?;
    let mut ordered_records = Vec::new();
    ordered_records
        .try_reserve_exact(
            usize::try_from(count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for _ in 0..count {
        let raw_ordinal = input.read_u32()?;
        let tribute_id = WwdEntityId::from(input.read_b256()?);
        ordered_records.push(EnumeratedTributeRecordV1 {
            raw_ordinal,
            tribute: TributeInputV1 {
                tribute_id,
                owner: input.read_address20()?,
                worldwide_day,
                issuance_currency: input.read_u16()?,
                nominal_amount_minor: input.read_u256()?,
                reference_currency: input.read_u16()?,
                tribute_price_minor: input.read_u256()?,
                exclude_from_intex_issuance: input.read_bool()?,
            },
        });
    }
    input.finish()?;
    let run = EnumeratedRunV1 {
        start_ordinal,
        end_ordinal,
        worldwide_day,
        ordered_records,
    };
    validate_enumerated_run(&run)?;
    if encode_enumerated_run(&run, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "enumerated run canonical re-encoding",
        ));
    }
    Ok(run)
}

pub fn encode_fidelity_map_output(
    output: &FidelityMapOutputV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, LysisArtifactErrorV1> {
    validate_fidelity_map_output(output)?;
    let mut encoded = CanonicalWriter::new(limits.codec);
    encoded.write_fixed(&FIDELITY_MAP_MAGIC)?;
    encoded.write_u32(output.aggregate.start_ordinal)?;
    encoded.write_u32(output.aggregate.end_ordinal)?;
    encoded.write_u32(output.aggregate.tribute_count)?;
    encoded.write_u256(output.aggregate.checked_total_nominal)?;
    encoded.write_u32(
        u32::try_from(output.observations.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    for observation in &output.observations {
        encoded.write_u32(observation.raw_ordinal)?;
        encoded.write_b256(*observation.tribute_id)?;
        encoded.write_u16(observation.pre_distribution_league)?;
        encoded.write_u16(observation.issuance_league)?;
        encoded.write_u256(observation.nominal_amount_minor)?;
    }
    encoded.write_u32(
        u32::try_from(output.aggregate.ordered_league_partials.len())
            .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    for partial in &output.aggregate.ordered_league_partials {
        encoded.write_u16(partial.league_id)?;
        encoded.write_u32(partial.count)?;
        encoded.write_u256(partial.nominal_amount_minor)?;
    }
    Ok(encoded.into_bytes())
}

pub fn decode_fidelity_map_output(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<FidelityMapOutputV1, LysisArtifactErrorV1> {
    let mut input = CanonicalReader::new(encoded, limits.codec)?;
    if input.read_fixed::<4>()? != FIDELITY_MAP_MAGIC {
        return Err(LysisArtifactErrorV1::InvalidEncoding("Fidelity map header"));
    }
    let start_ordinal = input.read_u32()?;
    let end_ordinal = input.read_u32()?;
    let tribute_count = input.read_u32()?;
    let checked_total_nominal = input.read_u256()?;
    let observation_count = input.read_u32()?;
    validate_shard_size(
        usize::try_from(observation_count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(
            usize::try_from(observation_count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for _ in 0..observation_count {
        observations.push(FidelityObservationV1 {
            raw_ordinal: input.read_u32()?,
            tribute_id: WwdEntityId::from(input.read_b256()?),
            pre_distribution_league: input.read_u16()?,
            issuance_league: input.read_u16()?,
            nominal_amount_minor: input.read_u256()?,
        });
    }
    let partial_count = input.read_u32()?;
    validate_shard_size(
        usize::try_from(partial_count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
    )?;
    let mut ordered_league_partials = Vec::new();
    ordered_league_partials
        .try_reserve_exact(
            usize::try_from(partial_count).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
        )
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for _ in 0..partial_count {
        ordered_league_partials.push(FidelityLeaguePartialV1 {
            league_id: input.read_u16()?,
            count: input.read_u32()?,
            nominal_amount_minor: input.read_u256()?,
        });
    }
    input.finish()?;
    let output = FidelityMapOutputV1 {
        observations,
        aggregate: FidelityAggregateV1 {
            start_ordinal,
            end_ordinal,
            tribute_count,
            checked_total_nominal,
            ordered_league_partials,
        },
    };
    validate_fidelity_map_output(&output)?;
    if encode_fidelity_map_output(&output, limits)? != encoded {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Fidelity map canonical re-encoding",
        ));
    }
    Ok(output)
}

fn validate_enumerated_run(run: &EnumeratedRunV1) -> Result<(), LysisArtifactErrorV1> {
    validate_shard_size(run.ordered_records.len())?;
    let tributes = run
        .ordered_records
        .iter()
        .map(|record| record.tribute.clone())
        .collect::<Vec<_>>();
    validate_canonical_tributes(run.worldwide_day, &tributes)?;
    let count = u32::try_from(run.ordered_records.len())
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    if run.end_ordinal
        != run
            .start_ordinal
            .checked_add(count)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?
        || run
            .ordered_records
            .iter()
            .enumerate()
            .any(|(offset, record)| {
                u32::try_from(offset)
                    .ok()
                    .and_then(|offset| run.start_ordinal.checked_add(offset))
                    != Some(record.raw_ordinal)
            })
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "enumerated run ordinal coverage",
        ));
    }
    Ok(())
}

fn validate_fidelity_map_output(output: &FidelityMapOutputV1) -> Result<(), LysisArtifactErrorV1> {
    validate_shard_size(output.observations.len())?;
    validate_shard_size(output.aggregate.ordered_league_partials.len())?;
    let observation_count = u32::try_from(output.observations.len())
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    if output.aggregate.tribute_count != observation_count
        || output.aggregate.end_ordinal
            != output
                .aggregate
                .start_ordinal
                .checked_add(observation_count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Fidelity map aggregate range",
        ));
    }

    let mut checked_total_nominal = U256::ZERO;
    let mut previous_id = None;
    let mut expected_partials = BTreeMap::<u16, (u32, U256)>::new();
    for (offset, observation) in output.observations.iter().enumerate() {
        let offset = u32::try_from(offset).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        if observation.raw_ordinal
            != output
                .aggregate
                .start_ordinal
                .checked_add(offset)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
            || observation.pre_distribution_league != observation.issuance_league
            || previous_id.is_some_and(|previous| previous >= observation.tribute_id)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Fidelity map observation order",
            ));
        }
        previous_id = Some(observation.tribute_id);
        checked_total_nominal = checked_total_nominal
            .checked_add(observation.nominal_amount_minor)
            .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                "Fidelity map nominal overflow",
            ))?;
        let expected = expected_partials
            .entry(observation.issuance_league)
            .or_insert((0, U256::ZERO));
        expected.0 = expected
            .0
            .checked_add(1)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        expected.1 = expected
            .1
            .checked_add(observation.nominal_amount_minor)
            .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                "Fidelity map league nominal overflow",
            ))?;
    }
    if checked_total_nominal != output.aggregate.checked_total_nominal {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Fidelity map aggregate nominal",
        ));
    }

    let mut checked_partial_count = 0_u32;
    let mut checked_partial_nominal = U256::ZERO;
    let mut previous_league = None;
    for partial in &output.aggregate.ordered_league_partials {
        if partial.count == 0
            || partial.nominal_amount_minor.is_zero()
            || previous_league.is_some_and(|previous| previous >= partial.league_id)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Fidelity map league partial order",
            ));
        }
        previous_league = Some(partial.league_id);
        checked_partial_count = checked_partial_count
            .checked_add(partial.count)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        checked_partial_nominal = checked_partial_nominal
            .checked_add(partial.nominal_amount_minor)
            .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                "Fidelity map partial nominal overflow",
            ))?;
    }
    if checked_partial_count != observation_count
        || checked_partial_nominal != checked_total_nominal
        || output
            .aggregate
            .ordered_league_partials
            .iter()
            .map(|partial| {
                (
                    partial.league_id,
                    (partial.count, partial.nominal_amount_minor),
                )
            })
            .ne(expected_partials
                .iter()
                .map(|(league, values)| (*league, *values)))
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Fidelity map league partial totals",
        ));
    }
    Ok(())
}

fn validate_amount_run(run: &AmountRunV1) -> Result<(), LysisArtifactErrorV1> {
    validate_shard_size(run.ordered_records.len())?;
    let count = u32::try_from(run.ordered_records.len())
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    if run.end_ordinal
        != run
            .start_ordinal
            .checked_add(count)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?
        || run.checked_segment_gratis_total.is_zero()
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "amount run aggregate range",
        ));
    }
    let mut checked_gratis_total = U256::ZERO;
    let mut previous_id = None;
    for (offset, record) in run.ordered_records.iter().enumerate() {
        let offset = u32::try_from(offset).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        if record.raw_ordinal
            != run
                .start_ordinal
                .checked_add(offset)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
            || previous_id.is_some_and(|previous| previous >= record.tribute_id)
            || record.owner.is_zero()
            || record.worldwide_day.value() == 0
            || record.nominal_amount_minor.is_zero()
            || record.gratis_fraction_fp.is_zero()
            || record.gratis_load_minor.is_zero()
            || record.entry_price_minor.is_zero()
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "amount run record order",
            ));
        }
        previous_id = Some(record.tribute_id);
        checked_gratis_total = checked_gratis_total
            .checked_add(record.gratis_load_minor)
            .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                "amount run Gratis overflow",
            ))?;
    }
    if checked_gratis_total != run.checked_segment_gratis_total {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "amount run Gratis total",
        ));
    }
    Ok(())
}

fn validate_gratis_segment_summary(
    summary: &GratisSegmentSummaryV1,
) -> Result<(), LysisArtifactErrorV1> {
    if summary.start_ordinal >= summary.end_ordinal
        || summary.checked_segment_gratis_total.is_zero()
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "Gratis summary fields",
        ));
    }
    Ok(())
}

fn validate_gratis_prefix_down_output(
    output: &GratisPrefixDownOutputV1,
) -> Result<(), LysisArtifactErrorV1> {
    match output {
        GratisPrefixDownOutputV1::Branch([Some(left), right]) => {
            if left.start_ordinal >= left.end_ordinal
                || right.as_ref().is_some_and(|right| {
                    right.start_ordinal >= right.end_ordinal
                        || left.end_ordinal != right.start_ordinal
                })
            {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "Gratis prefix-down branch",
                ));
            }
        }
        GratisPrefixDownOutputV1::Branch([None, _]) => {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "Gratis prefix-down empty left branch",
            ));
        }
        GratisPrefixDownOutputV1::Leaf(prefix) => {
            if prefix.incoming_remaining.is_zero()
                || prefix.incoming_remaining <= prefix.outgoing_remaining
                || prefix.first_error_ordinal.is_some()
            {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "Gratis prefix-down leaf",
                ));
            }
        }
    }
    Ok(())
}

fn validate_finalized_output_run(run: &FinalizedOutputRunV1) -> Result<(), LysisArtifactErrorV1> {
    validate_shard_size(run.ordered_records.len())?;
    let count = u32::try_from(run.ordered_records.len())
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    if !run.start_ordinal.is_multiple_of(PRIMARY_WORK_SHARD_SIZE)
        || run.checked_tribute_nominal_total.is_zero()
        || run.end_ordinal
            != run
                .start_ordinal
                .checked_add(count)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "finalized output range",
        ));
    }
    let mut previous_tribute = None;
    for (offset, record) in run.ordered_records.iter().enumerate() {
        let offset = u32::try_from(offset).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
        let nod = &record.nod_action;
        if record.raw_ordinal
            != run
                .start_ordinal
                .checked_add(offset)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
            || previous_tribute.is_some_and(|previous| previous >= nod.source_tribute_id)
            || nod.owner.is_zero()
            || nod.worldwide_day.value() == 0
            || nod.gratis_load_minor.is_zero()
            || nod.entry_price_minor.is_zero()
            || nod.reference_currency == 0
            || nod.bucket_key
                != NodContract::bucket_key(
                    nod.worldwide_day,
                    nod.floor_price_minor,
                    nod.reference_currency,
                )
            || nod.issued_at == 0
            || derive_poseidon_entity_id(nod.owner, nod.worldwide_day)
                .map_err(|_| LysisArtifactErrorV1::InvalidEncoding("finalized Nod identity"))?
                != nod.nod_id
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "finalized output record",
            ));
        }
        previous_tribute = Some(nod.source_tribute_id);
        if record
            .contributor_action
            .as_ref()
            .is_some_and(|contributor| {
                contributor.owner != nod.owner
                    || contributor.source_tribute_id != nod.source_tribute_id
                    || contributor.nominal_amount_minor.is_zero()
            })
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "finalized contributor binding",
            ));
        }
    }
    Ok(())
}

fn validate_raw_coverage_carrier(
    carrier: &RawCoverageCarrierV1,
) -> Result<(), LysisArtifactErrorV1> {
    if carrier.start_ordinal > carrier.end_ordinal
        || carrier.subtree_height > 32
        || carrier.tree_root.is_zero()
        || (carrier.subtree_height == 32 && carrier.subtree_index != 0)
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "raw coverage carrier fields",
        ));
    }
    Ok(())
}

fn validate_fixed_reduce_output(output: &FixedReduceOutputV1) -> Result<(), LysisArtifactErrorV1> {
    validate_raw_coverage_carrier(&output.coverage)?;
    let Some(aggregate) = &output.aggregate else {
        if output.coverage.start_ordinal != output.coverage.end_ordinal
            || !output.ordered_fractions.is_empty()
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "empty fixed reducer output",
            ));
        }
        return Ok(());
    };

    if aggregate.start_ordinal != output.coverage.start_ordinal
        || aggregate.end_ordinal != output.coverage.end_ordinal
        || aggregate.start_ordinal >= aggregate.end_ordinal
        || aggregate.tribute_count != aggregate.end_ordinal - aggregate.start_ordinal
        || aggregate.checked_total_nominal.is_zero()
        || aggregate.ordered_league_partials.is_empty()
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "fixed reducer aggregate range",
        ));
    }
    let mut checked_count = 0_u32;
    let mut checked_nominal = U256::ZERO;
    let mut previous_league = None;
    for partial in &aggregate.ordered_league_partials {
        if partial.count == 0
            || partial.nominal_amount_minor.is_zero()
            || previous_league.is_some_and(|previous| previous >= partial.league_id)
        {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "fixed reducer league partial order",
            ));
        }
        previous_league = Some(partial.league_id);
        checked_count = checked_count
            .checked_add(partial.count)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        checked_nominal = checked_nominal
            .checked_add(partial.nominal_amount_minor)
            .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                "fixed reducer nominal overflow",
            ))?;
    }
    if checked_count != aggregate.tribute_count
        || checked_nominal != aggregate.checked_total_nominal
        || (!output.ordered_fractions.is_empty()
            && (output.ordered_fractions.len() != aggregate.ordered_league_partials.len()
                || output
                    .ordered_fractions
                    .iter()
                    .zip(&aggregate.ordered_league_partials)
                    .any(|(fraction, partial)| fraction.league != partial.league_id)))
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "fixed reducer aggregate totals",
        ));
    }
    Ok(())
}

fn raw_coverage_subtree_root(
    subtree_start: u32,
    subtree_height: u16,
    total_count: u32,
    records: &[(u32, WwdEntityId)],
) -> Result<B256, LysisArtifactErrorV1> {
    let width = 1_u32
        .checked_shl(u32::from(subtree_height))
        .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    if width > PRIMARY_WORK_SHARD_SIZE
        || !subtree_start.is_multiple_of(width)
        || records.len() > width as usize
    {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "raw coverage subtree geometry",
        ));
    }

    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(width as usize)
        .map_err(|_| LysisArtifactErrorV1::LengthOverflow)?;
    for offset in 0..width {
        let raw_ordinal = subtree_start
            .checked_add(offset)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
        if raw_ordinal < total_count {
            let record_offset = raw_ordinal
                .checked_sub(subtree_start)
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?
                as usize;
            let (record_ordinal, tribute_id) =
                records
                    .get(record_offset)
                    .ok_or(LysisArtifactErrorV1::InvalidEncoding(
                        "raw coverage subtree record",
                    ))?;
            if *record_ordinal != raw_ordinal {
                return Err(LysisArtifactErrorV1::InvalidEncoding(
                    "raw coverage subtree ordinal",
                ));
            }
            let mut encoded = [0_u8; COVERAGE_RECORD_BYTES];
            encoded[..4].copy_from_slice(&raw_ordinal.to_be_bytes());
            encoded[4..].copy_from_slice(tribute_id.as_slice());
            nodes.push(leaf_hash(
                ListKind::RawTributeCoverage,
                raw_ordinal,
                &encoded,
            )?);
        } else {
            nodes.push(pad_hash(ListKind::RawTributeCoverage, raw_ordinal)?);
        }
    }
    if nodes.is_empty() {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "raw coverage subtree width",
        ));
    }

    let mut current_width = width as usize;
    let mut level = 1_u16;
    while current_width > 1 {
        let parent_count = current_width / 2;
        let first_parent_index = subtree_start >> level;
        for index in 0..parent_count {
            let parent_index = first_parent_index
                .checked_add(
                    u32::try_from(index).map_err(|_| LysisArtifactErrorV1::LengthOverflow)?,
                )
                .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
            nodes[index] = node_hash(
                ListKind::RawTributeCoverage,
                level,
                parent_index,
                nodes[index * 2],
                nodes[index * 2 + 1],
            )?;
        }
        current_width = parent_count;
        level = level
            .checked_add(1)
            .ok_or(LysisArtifactErrorV1::LengthOverflow)?;
    }
    Ok(nodes[0])
}

fn raw_coverage_root(
    records: impl IntoIterator<Item = (u32, WwdEntityId)>,
) -> Result<B256, LysisArtifactErrorV1> {
    let mut encoded_records = Vec::new();
    for (raw_ordinal, tribute_id) in records {
        if encoded_records.len() >= PRIMARY_WORK_SHARD_SIZE as usize {
            return Err(LysisArtifactErrorV1::InvalidEncoding(
                "raw coverage item cap",
            ));
        }
        let mut encoded = [0_u8; COVERAGE_RECORD_BYTES];
        encoded[..4].copy_from_slice(&raw_ordinal.to_be_bytes());
        encoded[4..].copy_from_slice(tribute_id.as_slice());
        encoded_records.push(encoded);
    }
    ordered_list_root(
        ListKind::RawTributeCoverage,
        &encoded_records,
        OrderedListLimits {
            max_items: PRIMARY_WORK_SHARD_SIZE as usize,
            max_item_bytes: COVERAGE_RECORD_BYTES,
            max_tree_allocation_bytes: PRIMARY_WORK_SHARD_SIZE as usize
                * core::mem::size_of::<B256>(),
        },
    )
    .map_err(LysisArtifactErrorV1::Protocol)
}

fn validate_shard_size(count: usize) -> Result<(), LysisArtifactErrorV1> {
    if count == 0 || count > PRIMARY_WORK_SHARD_SIZE as usize {
        return Err(LysisArtifactErrorV1::InvalidEncoding(
            "enumerated run shard size",
        ));
    }
    Ok(())
}
