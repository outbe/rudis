//! Pure sequential Lysis V1 semantic program and its staged legacy adapter seam.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use outbe_compressed_entities::derive_poseidon_entity_id;
use outbe_nod::NodContract;
use outbe_primitives::math::scaled_math::checked_mul_div_floor;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::units::SCALE_1E6_U256;

use crate::algorithm::{calc_fraction_distribution_fp, SCALE};
use crate::constants::calc_floor_price;

use super::types::{
    ContributorActionV1, FidelityPhaseV1, LeagueFractionV1, NodActionV1, ProgramErrorV1,
    ProgramInputV1, ProgramResultV1, SemanticObservationV1, TributeInputV1,
};

/// Prepared input after the first Fidelity pass and fraction derivation.
pub(crate) struct PreparedProgramV1 {
    tributes: Vec<TributeInputV1>,
    first_leagues: Vec<u16>,
    fractions: BTreeMap<u16, U256>,
    total_nominal: U256,
    gratis_allocation: U256,
    logical_evaluation_time: u64,
    observations: Vec<SemanticObservationV1>,
}

/// One load checked before the conditional Oracle/Fidelity reads at its ordinal.
pub(crate) struct PendingNodV1 {
    ordinal: usize,
    gratis_load_minor: U256,
    remaining_after: U256,
}

/// Stateful sequential reducer. It owns no storage and emits no chain effects.
pub(crate) struct ProgramExecutionV1 {
    prepared: PreparedProgramV1,
    mandatory_entry_price_840: U256,
    next_ordinal: usize,
    remaining: U256,
    nod_actions: Vec<NodActionV1>,
    contributors: BTreeMap<Address, U256>,
    observations: Vec<SemanticObservationV1>,
}

/// Execute a complete pre-observed logical input.
pub fn execute(mut input: ProgramInputV1) -> Result<ProgramResultV1, ProgramErrorV1> {
    input
        .tributes
        .sort_by_key(|observed| observed.tribute.tribute_id);
    let tributes = input
        .tributes
        .iter()
        .map(|observed| observed.tribute.clone())
        .collect::<Vec<_>>();
    if tributes.is_empty() {
        return Err(ProgramErrorV1::EmptyInput);
    }
    validate_canonical_tributes(input.worldwide_day, &tributes)?;
    let mut first_leagues = Vec::with_capacity(input.tributes.len());
    let mut observed_total = U256::ZERO;
    for (ordinal, observed) in input.tributes.iter().enumerate() {
        let league = observed
            .first_league
            .copied()
            .ok_or(ProgramErrorV1::FidelityUnavailable {
                ordinal,
                phase: FidelityPhaseV1::First,
            })?;
        first_leagues.push(league);
        observed_total = checked_nominal_step(
            observed_total,
            observed.tribute.nominal_amount_minor,
            ordinal,
        )?;
    }
    if observed_total.is_zero() {
        return Err(ProgramErrorV1::ZeroTotalNominal);
    }
    let prepared = prepare(
        input.worldwide_day,
        tributes,
        first_leagues,
        input.gratis_allocation,
        input.logical_evaluation_time,
    )?;
    let mandatory = input
        .mandatory_entry_price_840
        .copied()
        .ok_or(ProgramErrorV1::MandatoryOracleUnavailable)?;
    let mut execution = prepared.start(mandatory)?;

    for observed in &input.tributes {
        let pending = execution.quote_next()?;
        let ordinal = pending.ordinal;
        let entry_price = if observed.tribute.reference_currency == 840 {
            mandatory
        } else {
            observed.conditional_entry_price_minor.copied().ok_or(
                ProgramErrorV1::ConditionalOracleUnavailable {
                    ordinal,
                    currency: observed.tribute.reference_currency,
                },
            )?
        };
        validate_entry_price(
            entry_price,
            Some(ordinal),
            observed.tribute.reference_currency,
        )?;
        let second_league =
            observed
                .second_league
                .copied()
                .ok_or(ProgramErrorV1::FidelityUnavailable {
                    ordinal,
                    phase: FidelityPhaseV1::Second,
                })?;
        execution.commit_next(
            pending,
            entry_price,
            second_league,
            observed.nod_target_available,
        )?;
    }
    execution.finish()
}

/// Validate canonical input and derive the current FI fraction map.
pub(crate) fn prepare(
    worldwide_day: WorldwideDay,
    tributes: Vec<TributeInputV1>,
    first_leagues: Vec<u16>,
    gratis_allocation: U256,
    logical_evaluation_time: u64,
) -> Result<PreparedProgramV1, ProgramErrorV1> {
    if tributes.is_empty() {
        return Err(ProgramErrorV1::EmptyInput);
    }
    if tributes.len() != first_leagues.len() {
        return Err(ProgramErrorV1::OutputCountMismatch);
    }

    validate_canonical_tributes(worldwide_day, &tributes)?;
    let mut total_nominal = U256::ZERO;
    let mut observations = Vec::with_capacity(tributes.len());
    for (ordinal, (tribute, league)) in tributes.iter().zip(&first_leagues).enumerate() {
        total_nominal = checked_nominal_step(total_nominal, tribute.nominal_amount_minor, ordinal)?;
        observations.push(SemanticObservationV1::Fidelity {
            ordinal,
            phase: FidelityPhaseV1::First,
            owner: tribute.owner,
            league: *league,
        });
    }
    if total_nominal.is_zero() {
        return Err(ProgramErrorV1::ZeroTotalNominal);
    }

    let nominal_amounts = tributes
        .iter()
        .map(|tribute| tribute.nominal_amount_minor)
        .collect::<Vec<_>>();
    let fractions = compute_fraction_map(
        &nominal_amounts,
        &first_leagues,
        total_nominal,
        gratis_allocation,
    )?;
    Ok(PreparedProgramV1 {
        tributes,
        first_leagues,
        fractions,
        total_nominal,
        gratis_allocation,
        logical_evaluation_time,
        observations,
    })
}

impl PreparedProgramV1 {
    /// Bind the mandatory ISO 840 observation before any per-Tribute output.
    pub(crate) fn start(
        self,
        mandatory_entry_price_840: U256,
    ) -> Result<ProgramExecutionV1, ProgramErrorV1> {
        validate_entry_price(mandatory_entry_price_840, None, 840)?;
        let gratis_allocation = self.gratis_allocation;
        let mut observations = self.observations.clone();
        observations.push(SemanticObservationV1::Oracle {
            ordinal: None,
            currency: 840,
            entry_price_minor: mandatory_entry_price_840,
        });
        Ok(ProgramExecutionV1 {
            prepared: self,
            mandatory_entry_price_840,
            next_ordinal: 0,
            remaining: gratis_allocation,
            nod_actions: Vec::new(),
            contributors: BTreeMap::new(),
            observations,
        })
    }
}

impl ProgramExecutionV1 {
    /// Compute and budget-check the next Gratis load before external observations.
    pub(crate) fn quote_next(&self) -> Result<PendingNodV1, ProgramErrorV1> {
        let ordinal = self.next_ordinal;
        let tribute = self
            .prepared
            .tributes
            .get(ordinal)
            .ok_or(ProgramErrorV1::OutputCountMismatch)?;
        let fraction = self
            .prepared
            .fractions
            .get(&self.prepared.first_leagues[ordinal])
            .copied()
            .unwrap_or(U256::ZERO);
        let gratis_load_minor =
            calculate_gratis_load(tribute.nominal_amount_minor, fraction, ordinal)?;
        let remaining_after = validate_required_gratis(self.remaining, gratis_load_minor, ordinal)?;
        Ok(PendingNodV1 {
            ordinal,
            gratis_load_minor,
            remaining_after,
        })
    }

    /// Complete the next semantic action after its conditional observations.
    pub(crate) fn commit_next(
        &mut self,
        pending: PendingNodV1,
        entry_price_minor: U256,
        second_league: u16,
        nod_target_available: bool,
    ) -> Result<&NodActionV1, ProgramErrorV1> {
        let ordinal = self.next_ordinal;
        if pending.ordinal != ordinal {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        let tribute = &self.prepared.tributes[ordinal];
        validate_entry_price(entry_price_minor, Some(ordinal), tribute.reference_currency)?;
        if tribute.reference_currency != 840 {
            self.observations.push(SemanticObservationV1::Oracle {
                ordinal: Some(ordinal),
                currency: tribute.reference_currency,
                entry_price_minor,
            });
        } else if entry_price_minor != self.mandatory_entry_price_840 {
            return Err(ProgramErrorV1::Arithmetic {
                message: "ISO 840 entry price was not reused".to_owned(),
            });
        }

        let floor_price_minor =
            calc_floor_price(tribute.tribute_price_minor.max(entry_price_minor));
        let first_league = self.prepared.first_leagues[ordinal];
        self.observations.push(SemanticObservationV1::Fidelity {
            ordinal,
            phase: FidelityPhaseV1::Second,
            owner: tribute.owner,
            league: second_league,
        });
        if first_league != second_league {
            return Err(ProgramErrorV1::FidelityMismatch {
                ordinal,
                first: first_league,
                second: second_league,
            });
        }
        let cost_amount_minor =
            calculate_cost(entry_price_minor, pending.gratis_load_minor, ordinal)?;
        let nod_id =
            derive_poseidon_entity_id(tribute.owner, tribute.worldwide_day).map_err(|error| {
                ProgramErrorV1::Arithmetic {
                    message: error.to_string(),
                }
            })?;
        let bucket_key = NodContract::bucket_key(
            tribute.worldwide_day,
            floor_price_minor,
            tribute.reference_currency,
        );
        if !nod_target_available || tribute.owner.is_zero() {
            return Err(ProgramErrorV1::InvalidNodTarget { ordinal });
        }
        let action = NodActionV1 {
            source_tribute_id: tribute.tribute_id,
            nod_id,
            owner: tribute.owner,
            worldwide_day: tribute.worldwide_day,
            league_id: second_league,
            floor_price_minor,
            gratis_load_minor: pending.gratis_load_minor,
            entry_price_minor,
            cost_amount_minor,
            issuance_currency: tribute.issuance_currency,
            reference_currency: tribute.reference_currency,
            bucket_key,
            issued_at: self.prepared.logical_evaluation_time,
        };

        if !tribute.exclude_from_intex_issuance {
            let contributor = self.contributors.entry(tribute.owner).or_insert(U256::ZERO);
            *contributor = contributor
                .checked_add(tribute.nominal_amount_minor)
                .ok_or(ProgramErrorV1::ContributorOverflow { ordinal })?;
        }
        self.remaining = pending.remaining_after;
        let action_index = self.nod_actions.len();
        self.nod_actions.push(action);
        self.next_ordinal += 1;
        Ok(&self.nod_actions[action_index])
    }

    /// Finish only after exactly one action per canonical Tribute.
    pub(crate) fn finish(self) -> Result<ProgramResultV1, ProgramErrorV1> {
        if self.next_ordinal != self.prepared.tributes.len()
            || self.nod_actions.len() != self.prepared.tributes.len()
        {
            return Err(ProgramErrorV1::OutputCountMismatch);
        }
        Ok(ProgramResultV1 {
            tribute_ids: self
                .prepared
                .tributes
                .iter()
                .map(|tribute| tribute.tribute_id)
                .collect(),
            total_nominal: self.prepared.total_nominal,
            gratis_allocation: self.prepared.gratis_allocation,
            remaining_gratis: self.remaining,
            league_fractions: self
                .prepared
                .fractions
                .iter()
                .map(|(league, fraction)| LeagueFractionV1 {
                    league: *league,
                    fraction: *fraction,
                })
                .collect(),
            nod_actions: self.nod_actions,
            contributors: self
                .contributors
                .into_iter()
                .map(|(owner, nominal_amount_minor)| ContributorActionV1 {
                    owner,
                    nominal_amount_minor,
                })
                .collect(),
            observations: self.observations,
        })
    }
}

pub(crate) fn compute_fraction_map(
    nominal_amounts: &[U256],
    tribute_fis: &[u16],
    total_interest: U256,
    gratis_allocation: U256,
) -> Result<BTreeMap<u16, U256>, ProgramErrorV1> {
    let mut fi_groups = BTreeMap::<u16, (u32, U256)>::new();
    for (ordinal, &league) in tribute_fis.iter().enumerate() {
        let group = fi_groups.entry(league).or_insert((0, U256::ZERO));
        group.0 = group
            .0
            .checked_add(1)
            .ok_or_else(|| ProgramErrorV1::Arithmetic {
                message: "Fidelity league population overflow".to_owned(),
            })?;
        group.1 = group
            .1
            .checked_add(nominal_amounts[ordinal])
            .ok_or(ProgramErrorV1::TotalNominalOverflow { ordinal })?;
    }
    compute_fraction_map_from_groups(
        &fi_groups,
        u32::try_from(nominal_amounts.len()).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
        total_interest,
        gratis_allocation,
    )
}

pub(crate) fn compute_fraction_map_from_groups(
    fi_groups: &BTreeMap<u16, (u32, U256)>,
    tribute_count: u32,
    total_interest: U256,
    gratis_allocation: U256,
) -> Result<BTreeMap<u16, U256>, ProgramErrorV1> {
    let sorted_fis = fi_groups.keys().copied().collect::<Vec<_>>();
    let mut shares = Vec::with_capacity(sorted_fis.len());
    let mut populations = Vec::with_capacity(sorted_fis.len());
    let mut group_nominals = Vec::with_capacity(sorted_fis.len());
    for league in &sorted_fis {
        let (population, group_nominal) = fi_groups[league];
        shares.push(scaled_floor(group_nominal, SCALE, total_interest)?);
        populations.push(u64::from(population));
        group_nominals.push(group_nominal);
    }
    let share_sum = shares.iter().copied().try_fold(U256::ZERO, |sum, share| {
        sum.checked_add(share)
            .ok_or_else(|| ProgramErrorV1::Arithmetic {
                message: "Fidelity share sum overflow".to_owned(),
            })
    })?;
    if let Some(last) = shares.last_mut() {
        if share_sum < SCALE {
            *last =
                last.checked_add(SCALE - share_sum)
                    .ok_or_else(|| ProgramErrorV1::Arithmetic {
                        message: "Fidelity share remainder overflow".to_owned(),
                    })?;
        }
    }
    let f = scaled_floor(gratis_allocation, SCALE, total_interest)?;
    let fmax = f
        .checked_mul(U256::from(2_u8))
        .ok_or_else(|| ProgramErrorV1::Arithmetic {
            message: "maximum Gratis fraction overflow".to_owned(),
        })?;
    let mut fractions = calc_fraction_distribution_fp(
        &shares,
        &populations,
        usize::try_from(tribute_count).map_err(|_| ProgramErrorV1::OutputCountMismatch)?,
        f,
        fmax,
    )
    .map_err(|error| ProgramErrorV1::Arithmetic {
        message: error.to_string(),
    })?;

    // Six-decimal share rounding can make the real group projection exceed the
    // allocation even when the normalized share-space projection does not. Own
    // the one real-amount normalization here so sequential and OCOMP consume
    // exactly the same fraction map.
    let projected = group_nominals.iter().zip(&fractions).try_fold(
        U256::ZERO,
        |sum, (nominal, fraction)| {
            let load = scaled_floor(*nominal, *fraction, SCALE)?;
            sum.checked_add(load)
                .ok_or_else(|| ProgramErrorV1::Arithmetic {
                    message: "projected Gratis allocation overflow".to_owned(),
                })
        },
    )?;
    if projected > gratis_allocation {
        for fraction in &mut fractions {
            *fraction = scaled_floor(*fraction, gratis_allocation, projected)?;
        }
    }
    Ok(sorted_fis.into_iter().zip(fractions).collect())
}

fn scaled_floor(
    numerator: U256,
    multiplier: U256,
    denominator: U256,
) -> Result<U256, ProgramErrorV1> {
    checked_mul_div_floor(numerator, multiplier, denominator).map_err(|error| {
        ProgramErrorV1::Arithmetic {
            message: error.to_string(),
        }
    })
}

pub(crate) fn calculate_gratis_load(
    nominal_amount_minor: U256,
    fraction: U256,
    ordinal: usize,
) -> Result<U256, ProgramErrorV1> {
    let load = scaled_floor(nominal_amount_minor, fraction, SCALE)?;
    if load.is_zero() {
        return Err(ProgramErrorV1::ZeroGratisLoad { ordinal });
    }
    Ok(load)
}

pub(crate) fn calculate_cost(
    entry_price_minor: U256,
    gratis_load_minor: U256,
    ordinal: usize,
) -> Result<U256, ProgramErrorV1> {
    let cost = scaled_floor(entry_price_minor, gratis_load_minor, SCALE_1E6_U256)?;
    if cost.is_zero() {
        return Err(ProgramErrorV1::ZeroCost {
            ordinal,
            entry_price_minor,
            gratis_load_minor,
        });
    }
    Ok(cost)
}

pub(crate) fn validate_canonical_tributes(
    worldwide_day: WorldwideDay,
    tributes: &[TributeInputV1],
) -> Result<(), ProgramErrorV1> {
    let mut previous = None;
    for (ordinal, tribute) in tributes.iter().enumerate() {
        if tribute.worldwide_day != worldwide_day
            || tribute.tribute_id.worldwide_day() != worldwide_day
        {
            return Err(ProgramErrorV1::WorldwideDayMismatch { ordinal });
        }
        if let Some(previous) = previous {
            if tribute.tribute_id == previous {
                return Err(ProgramErrorV1::DuplicateInput { ordinal });
            }
            if tribute.tribute_id < previous {
                return Err(ProgramErrorV1::NonCanonicalInput { ordinal });
            }
        }
        previous = Some(tribute.tribute_id);
        let expected =
            derive_poseidon_entity_id(tribute.owner, tribute.worldwide_day).map_err(|error| {
                ProgramErrorV1::Arithmetic {
                    message: error.to_string(),
                }
            })?;
        if tribute.tribute_id != expected {
            return Err(ProgramErrorV1::InvalidTributeIdentity { ordinal });
        }
    }
    Ok(())
}

pub(crate) fn checked_nominal_step(
    total: U256,
    nominal_amount_minor: U256,
    ordinal: usize,
) -> Result<U256, ProgramErrorV1> {
    total
        .checked_add(nominal_amount_minor)
        .ok_or(ProgramErrorV1::TotalNominalOverflow { ordinal })
}

pub(crate) fn validate_entry_price(
    entry_price_minor: U256,
    ordinal: Option<usize>,
    currency: u16,
) -> Result<(), ProgramErrorV1> {
    if entry_price_minor.is_zero() {
        return Err(ProgramErrorV1::ZeroEntryPrice { ordinal, currency });
    }
    Ok(())
}

pub(crate) fn validate_required_gratis(
    remaining: U256,
    gratis_load_minor: U256,
    ordinal: usize,
) -> Result<U256, ProgramErrorV1> {
    if gratis_load_minor.is_zero() {
        return Err(ProgramErrorV1::ZeroGratisLoad { ordinal });
    }
    if gratis_load_minor > remaining {
        return Err(ProgramErrorV1::GratisLoadExceedsRemaining { ordinal });
    }
    Ok(remaining - gratis_load_minor)
}

/// Compatibility helper for existing unit tests while the implementation
/// authority lives in `program_v1`.
#[cfg(test)]
pub(crate) fn compute_fraction_hash_map(
    nominal_amounts: &[U256],
    tribute_fis: &[u16],
    total_interest: U256,
    gratis_allocation: U256,
) -> Result<HashMap<u16, U256>, ProgramErrorV1> {
    compute_fraction_map(
        nominal_amounts,
        tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .map(|fractions| fractions.into_iter().collect())
}
