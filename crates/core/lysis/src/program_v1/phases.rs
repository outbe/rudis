//! Pure bounded phase functions used by the fixed Lysis V1 work graph.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, WwdEntityId};
use outbe_nod::NodContract;
use outbe_primitives::time::WorldwideDay;

use crate::constants::calc_floor_price;

use super::{
    execute::{
        calculate_cost, calculate_gratis_load, compute_fraction_map_from_groups,
        validate_entry_price, validate_required_gratis,
    },
    FidelityPhaseV1, LeagueFractionV1, NodActionV1, ObservedTributeV1, ProgramErrorV1,
};

use super::planner::PRIMARY_WORK_SHARD_SIZE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidelityObservationV1 {
    pub raw_ordinal: u32,
    pub tribute_id: WwdEntityId,
    pub pre_distribution_league: u16,
    pub issuance_league: u16,
    pub nominal_amount_minor: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidelityLeaguePartialV1 {
    pub league_id: u16,
    pub count: u32,
    pub nominal_amount_minor: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidelityAggregateV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub tribute_count: u32,
    pub checked_total_nominal: U256,
    pub ordered_league_partials: Vec<FidelityLeaguePartialV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidelityMapOutputV1 {
    pub observations: Vec<FidelityObservationV1>,
    pub aggregate: FidelityAggregateV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmountRecordV1 {
    pub raw_ordinal: u32,
    pub tribute_id: WwdEntityId,
    pub owner: Address,
    pub worldwide_day: WorldwideDay,
    pub league_id: u16,
    pub nominal_amount_minor: U256,
    pub gratis_fraction_fp: U256,
    pub gratis_load_minor: U256,
    pub entry_price_minor: U256,
    pub floor_price_minor: U256,
    pub cost_amount_minor: U256,
    pub issuance_currency: u16,
    pub reference_currency: u16,
    pub exclude_from_intex_issuance: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmountRunV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub ordered_records: Vec<AmountRecordV1>,
    pub checked_segment_gratis_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedOutputRecordV1 {
    pub raw_ordinal: u32,
    pub nod_action: NodActionV1,
    pub contributor_action: Option<FinalizedContributorV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedContributorV1 {
    pub owner: Address,
    pub source_tribute_id: WwdEntityId,
    pub nominal_amount_minor: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedOutputRunV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub ordered_records: Vec<FinalizedOutputRecordV1>,
    pub checked_tribute_nominal_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerOrderedRunV1 {
    pub run_ordinal: u32,
    pub ordered_contributors: Vec<FinalizedContributorV1>,
    pub checked_eligible_nominal_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketRecordV1 {
    pub bucket_key: B256,
    pub raw_ordinal: u32,
    pub tribute_id: WwdEntityId,
    pub nod_id: WwdEntityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketOrderedRunV1 {
    pub run_ordinal: u32,
    pub ordered_records: Vec<BucketRecordV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FidelityReduceValueV1 {
    Empty,
    Aggregate(FidelityAggregateV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GratisSegmentSummaryV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub checked_segment_gratis_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GratisSummaryValueV1 {
    Empty,
    Summary(GratisSegmentSummaryV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GratisIncomingV1 {
    pub start_ordinal: u32,
    pub end_ordinal: u32,
    pub incoming_remaining: Option<U256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GratisLeafPrefixV1 {
    pub segment_ordinal: u32,
    pub incoming_remaining: U256,
    pub outgoing_remaining: U256,
    pub first_error_ordinal: Option<u32>,
}

pub fn fidelity_map(
    start_ordinal: u32,
    observed: &[ObservedTributeV1],
) -> Result<FidelityMapOutputV1, ProgramErrorV1> {
    if observed.is_empty()
        || observed.len()
            > usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    let count = u32::try_from(observed.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?;
    let end_ordinal = start_ordinal
        .checked_add(count)
        .ok_or(ProgramErrorV1::OutputCountMismatch)?;
    let mut observations = Vec::with_capacity(observed.len());
    let mut groups = BTreeMap::<u16, (u32, U256)>::new();
    let mut checked_total_nominal = U256::ZERO;

    for (local_ordinal, item) in observed.iter().enumerate() {
        let raw_ordinal = start_ordinal
            .checked_add(
                u32::try_from(local_ordinal).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
            )
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        let first = item
            .first_league
            .copied()
            .ok_or(ProgramErrorV1::FidelityUnavailable {
                ordinal: raw_ordinal as usize,
                phase: FidelityPhaseV1::First,
            })?;
        let second = item
            .second_league
            .copied()
            .ok_or(ProgramErrorV1::FidelityUnavailable {
                ordinal: raw_ordinal as usize,
                phase: FidelityPhaseV1::Second,
            })?;
        if first != second {
            return Err(ProgramErrorV1::FidelityMismatch {
                ordinal: raw_ordinal as usize,
                first,
                second,
            });
        }
        checked_total_nominal = checked_total_nominal
            .checked_add(item.tribute.nominal_amount_minor)
            .ok_or(ProgramErrorV1::TotalNominalOverflow {
                ordinal: raw_ordinal as usize,
            })?;
        let group = groups.entry(first).or_insert((0, U256::ZERO));
        group.0 = group
            .0
            .checked_add(1)
            .ok_or_else(|| ProgramErrorV1::Arithmetic {
                message: "Fidelity league population overflow".to_owned(),
            })?;
        group.1 = group
            .1
            .checked_add(item.tribute.nominal_amount_minor)
            .ok_or(ProgramErrorV1::TotalNominalOverflow {
                ordinal: raw_ordinal as usize,
            })?;
        observations.push(FidelityObservationV1 {
            raw_ordinal,
            tribute_id: item.tribute.tribute_id,
            pre_distribution_league: first,
            issuance_league: second,
            nominal_amount_minor: item.tribute.nominal_amount_minor,
        });
    }

    Ok(FidelityMapOutputV1 {
        observations,
        aggregate: FidelityAggregateV1 {
            start_ordinal,
            end_ordinal,
            tribute_count: count,
            checked_total_nominal,
            ordered_league_partials: groups
                .into_iter()
                .map(
                    |(league_id, (count, nominal_amount_minor))| FidelityLeaguePartialV1 {
                        league_id,
                        count,
                        nominal_amount_minor,
                    },
                )
                .collect(),
        },
    })
}

pub fn fidelity_reduce(
    left: &FidelityAggregateV1,
    right: &FidelityAggregateV1,
) -> Result<FidelityAggregateV1, ProgramErrorV1> {
    if left.start_ordinal >= left.end_ordinal
        || right.start_ordinal >= right.end_ordinal
        || left.end_ordinal != right.start_ordinal
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    let tribute_count = left
        .tribute_count
        .checked_add(right.tribute_count)
        .ok_or(ProgramErrorV1::OutputCountMismatch)?;
    let checked_total_nominal = left
        .checked_total_nominal
        .checked_add(right.checked_total_nominal)
        .ok_or(ProgramErrorV1::TotalNominalOverflow {
            ordinal: right.start_ordinal as usize,
        })?;
    let mut groups = BTreeMap::<u16, (u32, U256)>::new();
    for partial in left
        .ordered_league_partials
        .iter()
        .chain(&right.ordered_league_partials)
    {
        let group = groups.entry(partial.league_id).or_insert((0, U256::ZERO));
        group.0 = group
            .0
            .checked_add(partial.count)
            .ok_or_else(|| ProgramErrorV1::Arithmetic {
                message: "Fidelity reducer population overflow".to_owned(),
            })?;
        group.1 = group.1.checked_add(partial.nominal_amount_minor).ok_or(
            ProgramErrorV1::TotalNominalOverflow {
                ordinal: right.start_ordinal as usize,
            },
        )?;
    }
    Ok(FidelityAggregateV1 {
        start_ordinal: left.start_ordinal,
        end_ordinal: right.end_ordinal,
        tribute_count,
        checked_total_nominal,
        ordered_league_partials: groups
            .into_iter()
            .map(
                |(league_id, (count, nominal_amount_minor))| FidelityLeaguePartialV1 {
                    league_id,
                    count,
                    nominal_amount_minor,
                },
            )
            .collect(),
    })
}

pub fn fidelity_reduce_pair(
    left: FidelityReduceValueV1,
    right: FidelityReduceValueV1,
) -> Result<FidelityReduceValueV1, ProgramErrorV1> {
    match (left, right) {
        (FidelityReduceValueV1::Empty, FidelityReduceValueV1::Empty) => {
            Ok(FidelityReduceValueV1::Empty)
        }
        (FidelityReduceValueV1::Aggregate(left), FidelityReduceValueV1::Empty) => {
            Ok(FidelityReduceValueV1::Aggregate(left))
        }
        (FidelityReduceValueV1::Aggregate(left), FidelityReduceValueV1::Aggregate(right)) => {
            fidelity_reduce(&left, &right).map(FidelityReduceValueV1::Aggregate)
        }
        (FidelityReduceValueV1::Empty, FidelityReduceValueV1::Aggregate(_)) => {
            Err(ProgramErrorV1::OutputCountMismatch)
        }
    }
}

pub fn finalize_fi_fraction_table(
    aggregate: &FidelityAggregateV1,
    gratis_allocation: U256,
) -> Result<Vec<LeagueFractionV1>, ProgramErrorV1> {
    if aggregate.tribute_count == 0 || aggregate.checked_total_nominal.is_zero() {
        return Err(ProgramErrorV1::ZeroTotalNominal);
    }
    let groups = aggregate
        .ordered_league_partials
        .iter()
        .map(|partial| {
            (
                partial.league_id,
                (partial.count, partial.nominal_amount_minor),
            )
        })
        .collect::<BTreeMap<_, _>>();
    compute_fraction_map_from_groups(
        &groups,
        aggregate.tribute_count,
        aggregate.checked_total_nominal,
        gratis_allocation,
    )
    .map(|fractions| {
        fractions
            .into_iter()
            .map(|(league, fraction)| LeagueFractionV1 { league, fraction })
            .collect()
    })
}

pub fn amount_map(
    start_ordinal: u32,
    observed: &[ObservedTributeV1],
    fidelity_observations: &[FidelityObservationV1],
    fractions: &[LeagueFractionV1],
    mandatory_entry_price_840: U256,
) -> Result<AmountRunV1, ProgramErrorV1> {
    if observed.is_empty()
        || observed.len() != fidelity_observations.len()
        || observed.len()
            > usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    validate_entry_price(mandatory_entry_price_840, None, 840)?;
    let mut fraction_by_league = BTreeMap::new();
    let mut previous_league = None;
    for fraction in fractions {
        if previous_league.is_some_and(|previous| previous >= fraction.league) {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        previous_league = Some(fraction.league);
        fraction_by_league.insert(fraction.league, fraction.fraction);
    }

    let mut ordered_records = Vec::with_capacity(observed.len());
    let mut checked_segment_gratis_total = U256::ZERO;
    for (local_ordinal, (item, fidelity)) in observed.iter().zip(fidelity_observations).enumerate()
    {
        let raw_ordinal = start_ordinal
            .checked_add(
                u32::try_from(local_ordinal).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
            )
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        if fidelity.raw_ordinal != raw_ordinal
            || fidelity.tribute_id != item.tribute.tribute_id
            || fidelity.nominal_amount_minor != item.tribute.nominal_amount_minor
            || fidelity.pre_distribution_league != fidelity.issuance_league
        {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        let first_league =
            item.first_league
                .copied()
                .ok_or(ProgramErrorV1::FidelityUnavailable {
                    ordinal: raw_ordinal as usize,
                    phase: FidelityPhaseV1::First,
                })?;
        let second_league =
            item.second_league
                .copied()
                .ok_or(ProgramErrorV1::FidelityUnavailable {
                    ordinal: raw_ordinal as usize,
                    phase: FidelityPhaseV1::Second,
                })?;
        if first_league != second_league {
            return Err(ProgramErrorV1::FidelityMismatch {
                ordinal: raw_ordinal as usize,
                first: first_league,
                second: second_league,
            });
        }
        if first_league != fidelity.pre_distribution_league
            || second_league != fidelity.issuance_league
        {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        let fraction = fraction_by_league
            .get(&first_league)
            .copied()
            .unwrap_or(U256::ZERO);
        let gratis_load_minor = calculate_gratis_load(
            item.tribute.nominal_amount_minor,
            fraction,
            raw_ordinal as usize,
        )?;
        let entry_price_minor = if item.tribute.reference_currency == 840 {
            mandatory_entry_price_840
        } else {
            item.conditional_entry_price_minor.copied().ok_or(
                ProgramErrorV1::ConditionalOracleUnavailable {
                    ordinal: raw_ordinal as usize,
                    currency: item.tribute.reference_currency,
                },
            )?
        };
        validate_entry_price(
            entry_price_minor,
            Some(raw_ordinal as usize),
            item.tribute.reference_currency,
        )?;
        if !item.nod_target_available || item.tribute.owner.is_zero() {
            return Err(ProgramErrorV1::InvalidNodTarget {
                ordinal: raw_ordinal as usize,
            });
        }
        let floor_price_minor =
            calc_floor_price(item.tribute.tribute_price_minor.max(entry_price_minor));
        let cost_amount_minor =
            calculate_cost(entry_price_minor, gratis_load_minor, raw_ordinal as usize)?;
        checked_segment_gratis_total = checked_segment_gratis_total
            .checked_add(gratis_load_minor)
            .ok_or_else(|| ProgramErrorV1::Arithmetic {
                message: format!("Gratis total overflow at {raw_ordinal}"),
            })?;
        ordered_records.push(AmountRecordV1 {
            raw_ordinal,
            tribute_id: item.tribute.tribute_id,
            owner: item.tribute.owner,
            worldwide_day: item.tribute.worldwide_day,
            league_id: second_league,
            nominal_amount_minor: item.tribute.nominal_amount_minor,
            gratis_fraction_fp: fraction,
            gratis_load_minor,
            entry_price_minor,
            floor_price_minor,
            cost_amount_minor,
            issuance_currency: item.tribute.issuance_currency,
            reference_currency: item.tribute.reference_currency,
            exclude_from_intex_issuance: item.tribute.exclude_from_intex_issuance,
        });
    }
    let count =
        u32::try_from(ordered_records.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?;
    Ok(AmountRunV1 {
        start_ordinal,
        end_ordinal: start_ordinal
            .checked_add(count)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?,
        ordered_records,
        checked_segment_gratis_total,
    })
}

pub fn gratis_summary(
    start_ordinal: u32,
    gratis_loads: &[U256],
) -> Result<GratisSegmentSummaryV1, ProgramErrorV1> {
    if gratis_loads.is_empty()
        || gratis_loads.len()
            > usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    let count =
        u32::try_from(gratis_loads.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?;
    let end_ordinal = start_ordinal
        .checked_add(count)
        .ok_or(ProgramErrorV1::OutputCountMismatch)?;
    let mut checked_segment_gratis_total = U256::ZERO;
    for (local_ordinal, load) in gratis_loads.iter().copied().enumerate() {
        let raw_ordinal = start_ordinal
            .checked_add(
                u32::try_from(local_ordinal).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
            )
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        if load.is_zero() {
            return Err(ProgramErrorV1::ZeroGratisLoad {
                ordinal: raw_ordinal as usize,
            });
        }
        checked_segment_gratis_total =
            checked_segment_gratis_total
                .checked_add(load)
                .ok_or_else(|| ProgramErrorV1::Arithmetic {
                    message: format!("Gratis total overflow at {raw_ordinal}"),
                })?;
    }
    Ok(GratisSegmentSummaryV1 {
        start_ordinal,
        end_ordinal,
        checked_segment_gratis_total,
    })
}

pub fn gratis_summary_reduce_pair(
    left: GratisSummaryValueV1,
    right: GratisSummaryValueV1,
) -> Result<GratisSummaryValueV1, ProgramErrorV1> {
    match (left, right) {
        (GratisSummaryValueV1::Empty, GratisSummaryValueV1::Empty) => {
            Ok(GratisSummaryValueV1::Empty)
        }
        (GratisSummaryValueV1::Summary(left), GratisSummaryValueV1::Empty) => {
            Ok(GratisSummaryValueV1::Summary(left))
        }
        (GratisSummaryValueV1::Empty, GratisSummaryValueV1::Summary(_)) => {
            Err(ProgramErrorV1::OutputCountMismatch)
        }
        (GratisSummaryValueV1::Summary(left), GratisSummaryValueV1::Summary(right)) => {
            if left.start_ordinal >= left.end_ordinal
                || right.start_ordinal >= right.end_ordinal
                || left.end_ordinal != right.start_ordinal
            {
                return Err(ProgramErrorV1::OutputCountMismatch);
            }
            let total = left
                .checked_segment_gratis_total
                .checked_add(right.checked_segment_gratis_total)
                .ok_or_else(|| ProgramErrorV1::Arithmetic {
                    message: format!("Gratis reducer total overflow at {}", right.start_ordinal),
                })?;
            Ok(GratisSummaryValueV1::Summary(GratisSegmentSummaryV1 {
                start_ordinal: left.start_ordinal,
                end_ordinal: right.end_ordinal,
                checked_segment_gratis_total: total,
            }))
        }
    }
}

pub fn gratis_prefix_down(
    parent_incoming: Option<U256>,
    left: GratisSummaryValueV1,
    right: GratisSummaryValueV1,
) -> Result<[Option<GratisIncomingV1>; 2], ProgramErrorV1> {
    match (left, right) {
        (GratisSummaryValueV1::Empty, GratisSummaryValueV1::Empty) => Ok([None, None]),
        (GratisSummaryValueV1::Empty, GratisSummaryValueV1::Summary(_)) => {
            Err(ProgramErrorV1::OutputCountMismatch)
        }
        (GratisSummaryValueV1::Summary(left), right) => {
            let left_outgoing = parent_incoming
                .and_then(|remaining| remaining.checked_sub(left.checked_segment_gratis_total));
            let left_prefix = Some(GratisIncomingV1 {
                start_ordinal: left.start_ordinal,
                end_ordinal: left.end_ordinal,
                incoming_remaining: parent_incoming,
            });
            let right_prefix = match right {
                GratisSummaryValueV1::Empty => None,
                GratisSummaryValueV1::Summary(right) => {
                    if left.end_ordinal != right.start_ordinal {
                        return Err(ProgramErrorV1::OutputCountMismatch);
                    }
                    Some(GratisIncomingV1 {
                        start_ordinal: right.start_ordinal,
                        end_ordinal: right.end_ordinal,
                        incoming_remaining: left_outgoing,
                    })
                }
            };
            Ok([left_prefix, right_prefix])
        }
    }
}

pub fn finalize_gratis_leaf(
    incoming_remaining: Option<U256>,
    start_ordinal: u32,
    gratis_loads: &[U256],
) -> Result<GratisLeafPrefixV1, ProgramErrorV1> {
    if gratis_loads.is_empty()
        || gratis_loads.len()
            > usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    let incoming_remaining = incoming_remaining.ok_or(ProgramErrorV1::OutputCountMismatch)?;
    let mut remaining = incoming_remaining;
    for (local_ordinal, load) in gratis_loads.iter().copied().enumerate() {
        let raw_ordinal = start_ordinal
            .checked_add(
                u32::try_from(local_ordinal).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
            )
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        remaining = validate_required_gratis(remaining, load, raw_ordinal as usize)?;
    }
    Ok(GratisLeafPrefixV1 {
        segment_ordinal: start_ordinal / PRIMARY_WORK_SHARD_SIZE,
        incoming_remaining,
        outgoing_remaining: remaining,
        first_error_ordinal: None,
    })
}

pub fn output_finalize(
    amounts: &AmountRunV1,
    prefix: &GratisLeafPrefixV1,
    logical_evaluation_time: u64,
) -> Result<FinalizedOutputRunV1, ProgramErrorV1> {
    if amounts.ordered_records.is_empty()
        || amounts.start_ordinal / PRIMARY_WORK_SHARD_SIZE != prefix.segment_ordinal
        || prefix.first_error_ordinal.is_some()
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    let mut remaining = prefix.incoming_remaining;
    let mut ordered_records = Vec::with_capacity(amounts.ordered_records.len());
    let mut checked_tribute_nominal_total = U256::ZERO;
    for amount in &amounts.ordered_records {
        if amount.raw_ordinal
            != amounts
                .start_ordinal
                .checked_add(
                    u32::try_from(ordered_records.len())
                        .map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
                )
                .ok_or(ProgramErrorV1::OutputCountMismatch)?
        {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        remaining = validate_required_gratis(
            remaining,
            amount.gratis_load_minor,
            amount.raw_ordinal as usize,
        )?;
        checked_tribute_nominal_total = checked_tribute_nominal_total
            .checked_add(amount.nominal_amount_minor)
            .ok_or(ProgramErrorV1::TotalNominalOverflow {
                ordinal: amount.raw_ordinal as usize,
            })?;
        let nod_id =
            derive_poseidon_entity_id(amount.owner, amount.worldwide_day).map_err(|error| {
                ProgramErrorV1::Arithmetic {
                    message: error.to_string(),
                }
            })?;
        let bucket_key = NodContract::bucket_key(
            amount.worldwide_day,
            amount.floor_price_minor,
            amount.reference_currency,
        );
        ordered_records.push(FinalizedOutputRecordV1 {
            raw_ordinal: amount.raw_ordinal,
            nod_action: NodActionV1 {
                source_tribute_id: amount.tribute_id,
                nod_id,
                owner: amount.owner,
                worldwide_day: amount.worldwide_day,
                league_id: amount.league_id,
                floor_price_minor: amount.floor_price_minor,
                gratis_load_minor: amount.gratis_load_minor,
                entry_price_minor: amount.entry_price_minor,
                cost_amount_minor: amount.cost_amount_minor,
                issuance_currency: amount.issuance_currency,
                reference_currency: amount.reference_currency,
                bucket_key,
                issued_at: logical_evaluation_time,
            },
            contributor_action: (!amount.exclude_from_intex_issuance).then_some(
                FinalizedContributorV1 {
                    owner: amount.owner,
                    source_tribute_id: amount.tribute_id,
                    nominal_amount_minor: amount.nominal_amount_minor,
                },
            ),
        });
    }
    if prefix.incoming_remaining - remaining != amounts.checked_segment_gratis_total
        || remaining != prefix.outgoing_remaining
        || amounts.end_ordinal
            != amounts
                .start_ordinal
                .checked_add(
                    u32::try_from(ordered_records.len())
                        .map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
                )
                .ok_or(ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    Ok(FinalizedOutputRunV1 {
        start_ordinal: amounts.start_ordinal,
        end_ordinal: amounts.end_ordinal,
        ordered_records,
        checked_tribute_nominal_total,
    })
}

fn validate_finalized_leaf(run: &FinalizedOutputRunV1) -> Result<u32, ProgramErrorV1> {
    let count = u32::try_from(run.ordered_records.len())
        .map_err(|_| ProgramErrorV1::OutputCountMismatch)?;
    if count == 0
        || count > PRIMARY_WORK_SHARD_SIZE
        || !run.start_ordinal.is_multiple_of(PRIMARY_WORK_SHARD_SIZE)
        || run.end_ordinal
            != run
                .start_ordinal
                .checked_add(count)
                .ok_or(ProgramErrorV1::OutputCountMismatch)?
    {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }
    for (local_ordinal, record) in run.ordered_records.iter().enumerate() {
        let expected = run
            .start_ordinal
            .checked_add(
                u32::try_from(local_ordinal).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
            )
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        if record.raw_ordinal != expected {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
    }
    Ok(run.start_ordinal / PRIMARY_WORK_SHARD_SIZE)
}

pub fn shuffle_owners(run: &FinalizedOutputRunV1) -> Result<OwnerOrderedRunV1, ProgramErrorV1> {
    let run_ordinal = validate_finalized_leaf(run)?;
    let mut ordered_contributors = run
        .ordered_records
        .iter()
        .filter_map(|record| record.contributor_action.clone())
        .collect::<Vec<_>>();
    ordered_contributors.sort_by_key(|action| (action.owner, action.source_tribute_id));
    let mut previous_owner = None;
    let mut checked_eligible_nominal_total = U256::ZERO;
    for contributor in &ordered_contributors {
        if previous_owner == Some(contributor.owner) {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        previous_owner = Some(contributor.owner);
        checked_eligible_nominal_total = checked_eligible_nominal_total
            .checked_add(contributor.nominal_amount_minor)
            .ok_or(ProgramErrorV1::ContributorOverflow {
                ordinal: run.start_ordinal as usize,
            })?;
    }
    Ok(OwnerOrderedRunV1 {
        run_ordinal,
        ordered_contributors,
        checked_eligible_nominal_total,
    })
}

pub fn shuffle_buckets(run: &FinalizedOutputRunV1) -> Result<BucketOrderedRunV1, ProgramErrorV1> {
    let run_ordinal = validate_finalized_leaf(run)?;
    let mut ordered_records = run
        .ordered_records
        .iter()
        .map(|record| BucketRecordV1 {
            bucket_key: record.nod_action.bucket_key,
            raw_ordinal: record.raw_ordinal,
            tribute_id: record.nod_action.source_tribute_id,
            nod_id: record.nod_action.nod_id,
        })
        .collect::<Vec<_>>();
    ordered_records.sort_by_key(|record| (record.bucket_key, record.raw_ordinal));
    Ok(BucketOrderedRunV1 {
        run_ordinal,
        ordered_records,
    })
}
