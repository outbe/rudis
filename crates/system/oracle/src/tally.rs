//! Oracle tally algorithm: validator median, standard deviation, reward band.
//!
//! Ported from Cosmos SDK `x/oracle/tally.go` and `x/oracle/types/ballot.go`.
//! Rates and volumes remain in each pair's registered scale. Dimensionless
//! reward/validity ratios and the unchanged generic cross-rate use FP18.

use alloy_primitives::{aliases::U1024, Address, U256, U512};
use alloy_sol_types::SolEvent;
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::addresses::ORACLE_ADDRESS;
use outbe_primitives::error::Result;

use crate::constants::reciprocal_scale;
use crate::errors::OracleError;
use crate::precompile::IOracle;
use crate::schema::{OracleContract, PairIndex, SCALE_1E18};

/// Maximum validator records processed by the receipt-visible Oracle slash-window
/// system transaction. The configured genesis maximum is 128; keeping the cap
/// explicit makes the mandatory phase's gas bound protocol-visible.
pub const MAX_ORACLE_SLASH_WINDOW_VALIDATORS: usize = 128;

/// A single vote entry in a ballot for one trading pair.
#[derive(Clone, Debug)]
pub struct VoteForTally {
    /// Exchange rate in the pair's registered scale.
    pub exchange_rate: U256,
    /// Volume in the pair's registered scale.
    pub volume: U256,
    /// Validator address.
    pub voter: Address,
}

/// Per-validator claim tracking across all pairs during a tally round.
#[derive(Clone, Debug, Default)]
pub struct Claim {
    /// Number of pairs where this validator's vote was within reward band.
    pub win_count: u32,
    /// Whether the validator submitted any vote.
    pub did_vote: bool,
}

#[derive(Clone, Debug)]
struct PairTallyOutcome {
    median: U256,
    winning_validators: Vec<Address>,
}

/// Deterministic integer square root via Newton's method on U256.
///
/// Returns floor(sqrt(n)). Fully deterministic across platforms (no floats).
pub fn isqrt(n: U256) -> U256 {
    if n.is_zero() {
        return U256::ZERO;
    }
    if n == U256::from(1u64) {
        return U256::from(1u64);
    }
    let mut x = n;
    let mut y = (x + U256::from(1u64)) >> 1;
    while y < x {
        x = y;
        y = (x + n / x) >> 1;
    }
    x
}

fn isqrt_u1024(n: U1024) -> U1024 {
    if n.is_zero() {
        return U1024::ZERO;
    }
    if n == U1024::ONE {
        return U1024::ONE;
    }
    let mut x = n;
    let mut y = (x + U1024::ONE) >> 1;
    while y < x {
        x = y;
        y = (x + n / x) >> 1;
    }
    x
}

/// Computes the median of one-price-per-validator observations.
///
/// The ballot must be sorted by exchange rate. Every validator has equal
/// weight. An even ballot uses the floored midpoint of the two central rates.
pub fn median(ballot: &[VoteForTally]) -> U256 {
    if ballot.is_empty() {
        return U256::ZERO;
    }

    let upper_index = ballot.len() / 2;
    if ballot.len() % 2 == 1 {
        return ballot[upper_index].exchange_rate;
    }

    let lower = ballot[upper_index - 1].exchange_rate;
    let upper = ballot[upper_index].exchange_rate;
    lower + (upper - lower) / U256::from(2u64)
}

/// Computes the population standard deviation of a ballot around a given median.
///
/// Formula: sqrt(sum((rate_i - median)^2) / count)
/// Uses integer sqrt (Newton's method) for determinism.
/// The result remains in the ballot's rate scale; squared deviations use the
/// square of that scale.
pub fn standard_deviation(ballot: &[VoteForTally], median: U256) -> Result<U256> {
    if ballot.is_empty() {
        return Ok(U256::ZERO);
    }

    let count = U1024::from(ballot.len());
    let mut sum_sq = U1024::ZERO;

    for vote in ballot {
        // deviation = |rate - median| (unsigned arithmetic)
        let deviation = if vote.exchange_rate > median {
            vote.exchange_rate - median
        } else {
            median - vote.exchange_rate
        };
        let wide = U1024::from(deviation);
        let sq = wide * wide;
        sum_sq = sum_sq
            .checked_add(sq)
            .ok_or(OracleError::TallyArithmeticOverflow(
                "standard deviation sum",
            ))?;
    }

    // variance = sum_sq / count (at the square of the rate scale)
    let variance = sum_sq / count;

    // sqrt(variance) -> result in the original rate scale
    let result = isqrt_u1024(variance);
    if result > U1024::from(U256::MAX) {
        return Err(OracleError::TallyArithmeticOverflow("standard deviation result").into());
    }
    Ok(result.wrapping_to::<U256>())
}

/// Runs the tally algorithm for a single pair's ballot.
///
/// Computes validator median, standard deviation, reward spread, and marks
/// winners in the claim map.
///
/// Only positive-rate rows participate in price, deviation and winner
/// calculations. Every submitted row still marks participation, so a zero-rate
/// row is a miss rather than an abstention at the round level.
///
/// Returns the validator median exchange rate.
pub fn tally_pair(
    ballot: &mut [VoteForTally],
    reward_band: U256,
    claims: &mut [(Address, Claim)],
) -> Result<U256> {
    for vote in ballot.iter() {
        mark_participation(claims, vote.voter);
    }

    let outcome = evaluate_pair(ballot, reward_band)?;
    apply_winners(claims, &outcome.winning_validators);
    Ok(outcome.median)
}

fn evaluate_pair(ballot: &[VoteForTally], reward_band: U256) -> Result<PairTallyOutcome> {
    if ballot.is_empty() {
        return Ok(PairTallyOutcome {
            median: U256::ZERO,
            winning_validators: Vec::new(),
        });
    }

    let mut eligible: Vec<VoteForTally> = ballot
        .iter()
        .filter(|vote| vote_has_price(vote))
        .cloned()
        .collect();
    if eligible.is_empty() {
        return Ok(PairTallyOutcome {
            median: U256::ZERO,
            winning_validators: Vec::new(),
        });
    }

    eligible.sort_by_key(|vote| vote.exchange_rate);

    let median = median(&eligible);
    let std_dev = standard_deviation(&eligible, median)?;

    // reward_spread = max(std_dev, median * reward_band / (2 * FP18)).
    // The reward band is dimensionless FP18; the result stays in median scale.
    let wide_base_spread =
        (U512::from(median) * U512::from(reward_band)) / U512::from(U256::from(2u64) * SCALE_1E18);
    if wide_base_spread > U512::from(U256::MAX) {
        return Err(OracleError::TallyArithmeticOverflow("reward spread").into());
    }
    let base_spread = wide_base_spread.wrapping_to::<U256>();
    let reward_spread = if std_dev > base_spread {
        std_dev
    } else {
        base_spread
    };

    // Determine lower and upper bounds for winning votes
    let lower = median.saturating_sub(reward_spread);
    let upper = median.saturating_add(reward_spread);

    let winning_validators = eligible
        .iter()
        .filter(|vote| vote.exchange_rate >= lower && vote.exchange_rate <= upper)
        .map(|vote| vote.voter)
        .collect();

    Ok(PairTallyOutcome {
        median,
        winning_validators,
    })
}

fn apply_winners(claims: &mut [(Address, Claim)], winning_validators: &[Address]) {
    for voter in winning_validators {
        if let Some((_, claim)) = claims.iter_mut().find(|(address, _)| address == voter) {
            claim.win_count += 1;
        }
    }
}

/// Converts a ballot to cross-rates using a reference pair's votes.
///
/// For each voter, the cross-rate is: `reference_rate / vote_rate`.
/// Rows without an eligible reference leg, whose cross-rate is unrepresentable,
/// or whose positive input floors to zero are excluded independently. One bad
/// validator row must not abort the mandatory round tally.
pub fn to_cross_rate(
    ballot: &[VoteForTally],
    reference_votes: &[(Address, U256)],
    reference_pair: AddressPair,
    target_pair: AddressPair,
) -> Result<Vec<VoteForTally>> {
    let reference_scale = reciprocal_scale(reference_pair);
    let target_scale = reciprocal_scale(target_pair);
    let mut cross_ballot = Vec::with_capacity(ballot.len());
    for vote in ballot.iter().filter(|vote| vote_has_price(vote)) {
        let Some(reference_rate) = reference_votes
            .iter()
            .find(|(address, rate)| *address == vote.voter && !rate.is_zero())
            .map(|(_, rate)| *rate)
        else {
            continue;
        };
        let Some(numerator) = U512::from(reference_rate)
            .checked_mul(U512::from(target_scale))
            .and_then(|value| value.checked_mul(U512::from(SCALE_1E18)))
        else {
            continue;
        };
        let Some(denominator) =
            U512::from(reference_scale).checked_mul(U512::from(vote.exchange_rate))
        else {
            continue;
        };
        let Some(cross) = numerator
            .checked_div(denominator)
            .and_then(narrow_cross_rate)
        else {
            continue;
        };
        if cross.is_zero() {
            continue;
        }
        cross_ballot.push(VoteForTally {
            exchange_rate: cross,
            volume: vote.volume,
            voter: vote.voter,
        });
    }
    Ok(cross_ballot)
}

fn from_cross_rate(
    reference_rate: U256,
    cross_rate: U256,
    reference_pair: AddressPair,
    target_pair: AddressPair,
) -> Option<U256> {
    let numerator = U512::from(reference_rate)
        .checked_mul(U512::from(reciprocal_scale(target_pair)))
        .and_then(|value| value.checked_mul(U512::from(SCALE_1E18)))?;
    let denominator =
        U512::from(reciprocal_scale(reference_pair)).checked_mul(U512::from(cross_rate))?;
    let rate = numerator
        .checked_div(denominator)
        .and_then(narrow_cross_rate)?;
    (!rate.is_zero()).then_some(rate)
}

fn narrow_cross_rate(value: U512) -> Option<U256> {
    if value > U512::from(U256::MAX) {
        return None;
    }
    Some(value.wrapping_to::<U256>())
}

fn vote_has_price(vote: &VoteForTally) -> bool {
    !vote.exchange_rate.is_zero()
}

fn observation_count(ballot: &[VoteForTally]) -> usize {
    ballot.iter().filter(|vote| vote_has_price(vote)).count()
}

fn volume_sum(ballot: &[VoteForTally]) -> U512 {
    ballot
        .iter()
        .filter(|vote| vote_has_price(vote))
        .fold(U512::ZERO, |sum, vote| sum + U512::from(vote.volume))
}

fn narrow_volume_sum(ballot: &[VoteForTally]) -> Option<U256> {
    let sum = volume_sum(ballot);
    (sum <= U512::from(U256::MAX)).then(|| sum.wrapping_to::<U256>())
}

/// Removes one whole validator tuple when the aggregate volume cannot be
/// represented together with `rate`. The largest volume is rejected first; an
/// equal-volume tie rejects the validator later in active-registry order.
fn remove_one_volume_over_capacity(
    ballot: &mut Vec<VoteForTally>,
    capacity: U256,
    validator_order: &[Address],
) -> bool {
    if volume_sum(ballot) <= U512::from(capacity) {
        return false;
    }

    let rejected = ballot
        .iter()
        .enumerate()
        .filter(|(_, vote)| vote_has_price(vote) && !vote.volume.is_zero())
        .max_by(|(_, left), (_, right)| {
            left.volume.cmp(&right.volume).then_with(|| {
                let left_order = validator_order
                    .iter()
                    .position(|address| *address == left.voter)
                    .unwrap_or(usize::MAX);
                let right_order = validator_order
                    .iter()
                    .position(|address| *address == right.voter)
                    .unwrap_or(usize::MAX);
                left_order.cmp(&right_order)
            })
        })
        .map(|(index, _)| index);

    if let Some(index) = rejected {
        ballot.remove(index);
        true
    } else {
        false
    }
}

fn remove_one_unrepresentable_volume(
    ballot: &mut Vec<VoteForTally>,
    rate: U256,
    validator_order: &[Address],
) -> bool {
    !rate.is_zero() && remove_one_volume_over_capacity(ballot, U256::MAX / rate, validator_order)
}

fn stabilize_direct_volume(
    ballot: &mut Vec<VoteForTally>,
    reward_band: U256,
    validator_order: &[Address],
) -> Result<()> {
    loop {
        let rate = evaluate_pair(ballot, reward_band)?.median;
        if rate.is_zero() || !remove_one_unrepresentable_volume(ballot, rate, validator_order) {
            return Ok(());
        }
    }
}

/// Number of independent validator observations required for one raw pair.
/// Every active validator contributes at most one vote, regardless of stake.
fn pair_quorum(active_validator_count: usize) -> usize {
    active_validator_count - active_validator_count / 3
}

fn mark_participation(claims: &mut [(Address, Claim)], voter: Address) {
    if let Some((_, claim)) = claims.iter_mut().find(|(address, _)| *address == voter) {
        claim.did_vote = true;
    }
}

/// Orchestrates the full tally for all pairs in a vote period.
///
/// 1. Reads all votes from storage
/// 2. Organizes into per-pair ballots
/// 3. Picks reference pair (most validator observations)
/// 4. Tallies reference pair directly, others via cross-rate
/// 5. Updates exchange rates and snapshots
/// 6. Counts miss/success/abstain per validator
/// 7. Clears votes
pub fn run_tally(oracle: &mut OracleContract, block_number: u64, timestamp: u64) -> Result<()> {
    let storage = oracle.storage.clone();
    storage.with_checkpoint(|| run_tally_inner(oracle, block_number, timestamp))
}

fn run_tally_inner(oracle: &mut OracleContract, block_number: u64, timestamp: u64) -> Result<()> {
    let enabled = oracle.config_enabled.read()?;
    if !enabled {
        return Ok(());
    }

    let reward_band = oracle.config_reward_band.read()?;

    // Collect the active validator set at tally time.
    // Intentional divergence from Cosmos (which locks the set at period start):
    // membership is revalidated at tally time so a validator that exited after
    // submitting cannot contribute to quorum. Snapshotting membership at vote
    // time would require additional storage per period per validator.
    let vs = outbe_validatorset::contract::ValidatorSet::new(oracle.storage.clone());
    let all_validators = vs.get_active_validators()?;
    if all_validators.is_empty() {
        oracle.clear_votes()?;
        return Ok(());
    }

    // Build claims map: (address, claim)
    let mut claims: Vec<(Address, Claim)> = all_validators
        .iter()
        .map(|v| (v.validator_address, Claim::default()))
        .collect();

    // Read all votes and organize into per-pair ballots
    let voter_count = oracle.voter_list.len()?;
    if voter_count == 0 {
        // No votes this period - all validators get abstain
        for v in &all_validators {
            oracle.increment_abstain(&v.validator_address)?;
        }
        oracle.clear_votes()?;
        return Ok(());
    }

    // Collect vote targets (active pairs) with the registry index the rate
    // columns are keyed by, so the write-back never re-derives it from the pair.
    let pair_count = oracle.pair_count.read()?;
    let mut active_pairs: Vec<(PairIndex, AddressPair)> = Vec::new();
    for pid in 1..=pair_count {
        let pair = oracle.pair_at(pid)?;
        if oracle.vote_target.read(&pair)? {
            active_pairs.push((pid, pair));
        }
    }
    let total_targets = active_pairs.len() as u32;

    if total_targets == 0 {
        oracle.clear_votes()?;
        return Ok(());
    }

    // Organize votes into per-pair ballots
    let mut ballot_map: Vec<(PairIndex, AddressPair, Vec<VoteForTally>)> = active_pairs
        .iter()
        .map(|(index, pair)| (*index, *pair, Vec::new()))
        .collect();

    for vi in 0..voter_count {
        let voter = oracle.voter_list.get(vi)?.unwrap_or(Address::ZERO);
        if !all_validators
            .iter()
            .any(|validator| validator.validator_address == voter)
        {
            continue;
        }
        let tuple_count = oracle.vote_tuple_count.read(&voter)?;

        let pair_map = oracle.vote_pair.get_nested(&voter);
        let rate_map = oracle.vote_rate.get_nested(&voter);
        let volume_map = oracle.vote_volume.get_nested(&voter);

        for ti in 0..tuple_count {
            let voted_pair = pair_map.read_pair(&ti)?;
            let rate = rate_map.read(&ti)?;
            let volume = volume_map.read(&ti)?;

            // Find the ballot for this pair
            if let Some((_, _, ballot)) = ballot_map
                .iter_mut()
                .find(|(_, pair, _)| pair.same_market(&voted_pair))
            {
                mark_participation(&mut claims, voter);
                ballot.push(VoteForTally {
                    exchange_rate: rate,
                    volume,
                    voter,
                });
            }
        }
    }

    let validator_order: Vec<Address> = all_validators
        .iter()
        .map(|validator| validator.validator_address)
        .collect();
    // Each pair needs a direct candidate so reference selection considers only
    // tuples that would be representable if that pair became the reference.
    // Keep target ballots untouched: their capacity depends on the eventual
    // cross-derived rate, not on their raw median.
    let mut direct_ballots: Vec<Vec<VoteForTally>> = ballot_map
        .iter()
        .map(|(_, _, ballot)| ballot.clone())
        .collect();
    for ballot in &mut direct_ballots {
        stabilize_direct_volume(ballot, reward_band, &validator_order)?;
    }

    // Raw pair quorum is independent per pair. Direct candidates additionally
    // decide whether a pair is eligible to serve as the reference.
    let quorum = pair_quorum(all_validators.len());
    let mut raw_qualified = vec![false; ballot_map.len()];
    let mut reference_qualified = vec![false; ballot_map.len()];
    for (index, (_, _, ballot)) in ballot_map.iter().enumerate() {
        if observation_count(ballot) >= quorum {
            raw_qualified[index] = true;
            reference_qualified[index] = observation_count(&direct_ballots[index]) >= quorum;
        } else {
            // Cosmos-style participation credit: a valid observation on a pair
            // that lacks quorum is not punished as an outlier. Missing and
            // zero-rate or unrepresentable-volume observations receive no
            // credit for that pair.
            for vote in direct_ballots[index]
                .iter()
                .filter(|vote| vote_has_price(vote))
            {
                if let Some((_, claim)) = claims
                    .iter_mut()
                    .find(|(address, _)| *address == vote.voter)
                {
                    claim.win_count += 1;
                }
            }
        }
    }

    // Pick the qualified reference pair with the most validator observations.
    // Iteration follows registry order, so equal counts keep the first pair.
    let mut ref_pair_idx = reference_qualified
        .iter()
        .position(|is_qualified| *is_qualified);
    if let Some(mut current) = ref_pair_idx {
        for index in (current + 1)..ballot_map.len() {
            if reference_qualified[index]
                && observation_count(&direct_ballots[index])
                    > observation_count(&direct_ballots[current])
            {
                current = index;
            }
        }
        ref_pair_idx = Some(current);
    }

    if ref_pair_idx.is_none() {
        // Every otherwise-quorate pair lost reference eligibility only because
        // invalid volume tuples were removed. Preserve the established
        // below-quorum credit for the remaining valid observations.
        for (index, ballot) in direct_ballots.iter().enumerate() {
            if !raw_qualified[index] {
                continue;
            }
            for vote in ballot.iter().filter(|vote| vote_has_price(vote)) {
                if let Some((_, claim)) = claims
                    .iter_mut()
                    .find(|(address, _)| *address == vote.voter)
                {
                    claim.win_count += 1;
                }
            }
        }
    }

    // Snapshot entries to collect.
    let mut snapshot_entries: Vec<(AddressPair, U256, U256)> = Vec::new();
    let mut pairs_updated = 0u32;
    if let Some(ref_pair_idx) = ref_pair_idx {
        // Tally reference pair directly.
        let (ref_index, ref_pair) = (ballot_map[ref_pair_idx].0, ballot_map[ref_pair_idx].1);
        let reference_ballot = &direct_ballots[ref_pair_idx];
        let ref_median = evaluate_pair(reference_ballot, reward_band)?;

        let reference_votes: Vec<(Address, U256)> = reference_ballot
            .iter()
            .filter(|vote| vote_has_price(vote))
            .map(|v| (v.voter, v.exchange_rate))
            .collect();

        if !ref_median.median.is_zero() {
            apply_winners(&mut claims, &ref_median.winning_validators);
            oracle.update_exchange_rate(ref_index, ref_median.median, block_number, timestamp)?;
            pairs_updated += 1;
            let event = IOracle::ExchangeRateUpdated {
                base: ref_pair.address1(),
                quote: ref_pair.address2(),
                rate: ref_median.median,
                blockNumber: block_number,
            };
            let _ = oracle
                .storage
                .emit_event(ORACLE_ADDRESS, event.encode_log_data());

            let total_volume = narrow_volume_sum(reference_ballot)
                .expect("volume stabilization guarantees a U256 sum");
            if oracle.snapshot_can_accept(timestamp, ref_pair, ref_median.median, total_volume)? {
                snapshot_entries.push((ref_pair, ref_median.median, total_volume));
            }
        }

        // Tally every other quorum-qualified pair via the reference overlap.
        // There is intentionally no second quorum over that intersection.
        for i in 0..ballot_map.len() {
            if i == ref_pair_idx || !raw_qualified[i] {
                continue;
            }

            let (index, pair) = (ballot_map[i].0, ballot_map[i].1);
            let final_tally = loop {
                if observation_count(&ballot_map[i].2) < quorum {
                    for vote in ballot_map[i].2.iter().filter(|vote| vote_has_price(vote)) {
                        if let Some((_, claim)) = claims
                            .iter_mut()
                            .find(|(address, _)| *address == vote.voter)
                        {
                            claim.win_count += 1;
                        }
                    }
                    break None;
                }

                let cross_ballot =
                    to_cross_rate(&ballot_map[i].2, &reference_votes, ref_pair, pair)?;
                let cross_outcome = evaluate_pair(&cross_ballot, reward_band)?;
                if cross_outcome.median.is_zero() {
                    break None;
                }
                let Some(actual_rate) =
                    from_cross_rate(ref_median.median, cross_outcome.median, ref_pair, pair)
                else {
                    break None;
                };
                if remove_one_unrepresentable_volume(
                    &mut ballot_map[i].2,
                    actual_rate,
                    &validator_order,
                ) {
                    continue;
                }
                break Some((actual_rate, cross_outcome));
            };

            if let Some((actual_rate, cross_outcome)) = final_tally {
                apply_winners(&mut claims, &cross_outcome.winning_validators);
                oracle.update_exchange_rate(index, actual_rate, block_number, timestamp)?;
                pairs_updated += 1;
                let event = IOracle::ExchangeRateUpdated {
                    base: pair.address1(),
                    quote: pair.address2(),
                    rate: actual_rate,
                    blockNumber: block_number,
                };
                let _ = oracle
                    .storage
                    .emit_event(ORACLE_ADDRESS, event.encode_log_data());

                // Volume belongs to the target pair's full eligible raw ballot,
                // not merely validators in the cross intersection.
                let total_volume = narrow_volume_sum(&ballot_map[i].2)
                    .expect("volume stabilization guarantees a U256 sum");
                if oracle.snapshot_can_accept(timestamp, pair, actual_rate, total_volume)? {
                    snapshot_entries.push((pair, actual_rate, total_volume));
                }
            }
        }
    }

    // Write price snapshot
    if !snapshot_entries.is_empty() {
        oracle.write_snapshot(timestamp, &snapshot_entries)?;
    }

    // Count miss/success/abstain per validator
    for (addr, claim) in &claims {
        if claim.win_count == total_targets {
            oracle.increment_success(addr)?;
        } else if !claim.did_vote {
            oracle.increment_abstain(addr)?;
        } else {
            oracle.increment_miss(addr)?;
        }
    }

    // Emit TallyCompleted event
    let event = IOracle::TallyCompleted {
        blockNumber: block_number,
        pairsUpdated: pairs_updated,
    };
    let _ = oracle
        .storage
        .emit_event(ORACLE_ADDRESS, event.encode_log_data());

    // Clear all votes
    oracle.clear_votes()?;

    Ok(())
}

/// Processes the slash window: checks vote rates and force-exits underperformers.
pub fn slash_and_reset_counters(oracle: &mut OracleContract, _timestamp: u64) -> Result<()> {
    let min_valid = oracle.config_min_valid_per_window.read()?;
    let allow_protected = oracle.config_allow_protected.read()?;

    let vs = outbe_validatorset::contract::ValidatorSet::new(oracle.storage.clone());
    let validator_addresses = vs.registered_validator_addresses()?;
    if validator_addresses.len() > MAX_ORACLE_SLASH_WINDOW_VALIDATORS {
        return Err(OracleError::SlashWindowValidatorSetExceedsCap {
            actual: validator_addresses.len(),
            cap: MAX_ORACLE_SLASH_WINDOW_VALIDATORS,
        }
        .into());
    }

    for addr in validator_addresses {
        // Skip protected validators
        if allow_protected {
            let is_protected = oracle.protected_validator.read(&addr)?;
            if is_protected {
                oracle.reset_penalty_counter(&addr)?;
                continue;
            }
        }

        let success = oracle.penalty_success_count.read(&addr)?;
        let abstain = oracle.penalty_abstain_count.read(&addr)?;
        let miss = oracle.penalty_miss_count.read(&addr)?;
        let total = success + abstain + miss;

        if total == 0 {
            oracle.reset_penalty_counter(&addr)?;
            continue;
        }

        // valid_rate = success * 1e18 / total
        let valid_rate = U256::from(success) * SCALE_1E18 / U256::from(total);

        if valid_rate < min_valid {
            let storage = oracle.storage.clone();
            storage.with_checkpoint(|| {
                // Force-exit first so validator lifecycle events and status
                // transitions follow the same ordering as slash indicator.
                // Keep the cross-module writes under one checkpoint: any later
                // slash/reset failure must roll back forced-exit state.
                let mut vs_mut =
                    outbe_validatorset::contract::ValidatorSet::new(oracle.storage.clone());
                // Oracle underperformance felony: JAIL (not force-exit) + slash.
                vs_mut.jail_validator(addr)?;
                let event = IOracle::ValidatorForcedExit { validator: addr };
                let _ = oracle
                    .storage
                    .emit_event(ORACLE_ADDRESS, event.encode_log_data());

                let slash_fraction = oracle.config_slash_fraction.read()?;
                if !slash_fraction.is_zero() {
                    // Convert 1e18-scaled fraction to percent: fraction * 100 / 1e18
                    let slash_pct = (slash_fraction * U256::from(100u64) / SCALE_1E18).to::<u64>();
                    if slash_pct > 0 {
                        let mut staking =
                            outbe_staking::contract::Staking::new(oracle.storage.clone());
                        staking.slash_stake(addr, slash_pct)?;
                        let event = IOracle::ValidatorSlashed {
                            validator: addr,
                            slashPercent: slash_pct,
                        };
                        let _ = oracle
                            .storage
                            .emit_event(ORACLE_ADDRESS, event.encode_log_data());
                    }
                }

                oracle.reset_penalty_counter(&addr)?;
                Ok(())
            })?;
            continue;
        }

        oracle.reset_penalty_counter(&addr)?;
    }

    // Remove exchange rates for deactivated pairs (Cosmos: RemoveExcessFeeds)
    oracle.remove_excess_feeds()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed18(whole: u64) -> U256 {
        U256::from(whole) * SCALE_1E18
    }

    #[test]
    fn pair_quorum_is_ceiling_two_thirds_of_active_validators() {
        let expected = [0usize, 1, 2, 2, 3, 4, 4, 5, 6, 6, 7];
        for (active, expected_quorum) in expected.into_iter().enumerate() {
            assert_eq!(pair_quorum(active), expected_quorum, "N={active}");
        }
    }

    #[test]
    fn volume_capacity_accepts_the_exact_boundary_and_rejects_one_unit_over() {
        let voter = Address::new([1u8; 20]);
        let validator_order = [voter];
        let capacity = U256::MAX / U256::from(2u64);
        let mut exact = vec![VoteForTally {
            exchange_rate: U256::from(2u64),
            volume: capacity,
            voter,
        }];
        assert!(!remove_one_unrepresentable_volume(
            &mut exact,
            U256::from(2u64),
            &validator_order,
        ));

        let mut over = vec![VoteForTally {
            exchange_rate: U256::from(2u64),
            volume: capacity + U256::ONE,
            voter,
        }];
        assert!(remove_one_unrepresentable_volume(
            &mut over,
            U256::from(2u64),
            &validator_order,
        ));
        assert!(over.is_empty());
    }

    #[test]
    fn combined_volume_overflow_removes_the_largest_tuple() {
        let voters = [
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
        ];
        let half = U256::MAX / U256::from(2u64);
        let mut ballot = vec![
            VoteForTally {
                exchange_rate: U256::ONE,
                volume: half + U256::from(2u64),
                voter: voters[0],
            },
            VoteForTally {
                exchange_rate: U256::ONE,
                volume: half + U256::ONE,
                voter: voters[1],
            },
            VoteForTally {
                exchange_rate: U256::ONE,
                volume: U256::ONE,
                voter: voters[2],
            },
        ];

        assert!(remove_one_unrepresentable_volume(
            &mut ballot,
            U256::ONE,
            &voters,
        ));
        assert_eq!(ballot.len(), 2);
        assert!(!ballot.iter().any(|vote| vote.voter == voters[0]));
        assert!(narrow_volume_sum(&ballot).is_some());
    }

    #[test]
    fn equal_largest_volumes_keep_the_earlier_registered_validator() {
        let voters = [
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
        ];
        let large = U256::MAX / U256::from(2u64) + U256::ONE;
        for reverse_input in [false, true] {
            let mut ballot = vec![
                VoteForTally {
                    exchange_rate: U256::ONE,
                    volume: large,
                    voter: voters[0],
                },
                VoteForTally {
                    exchange_rate: U256::ONE,
                    volume: large,
                    voter: voters[1],
                },
                VoteForTally {
                    exchange_rate: U256::ONE,
                    volume: U256::ZERO,
                    voter: voters[2],
                },
            ];
            if reverse_input {
                ballot.reverse();
            }

            assert!(remove_one_unrepresentable_volume(
                &mut ballot,
                U256::ONE,
                &voters,
            ));
            assert!(ballot.iter().any(|vote| vote.voter == voters[0]));
            assert!(!ballot.iter().any(|vote| vote.voter == voters[1]));
        }
    }

    #[test]
    fn zero_volume_is_a_valid_tuple_for_volume_stabilization() {
        let voter = Address::new([1u8; 20]);
        let mut ballot = vec![VoteForTally {
            exchange_rate: U256::MAX,
            volume: U256::ZERO,
            voter,
        }];
        assert!(!remove_one_unrepresentable_volume(
            &mut ballot,
            U256::MAX,
            &[voter],
        ));
        assert_eq!(ballot.len(), 1);
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(U256::ZERO), U256::ZERO);
        assert_eq!(isqrt(U256::from(1u64)), U256::from(1u64));
        assert_eq!(isqrt(U256::from(4u64)), U256::from(2u64));
        assert_eq!(isqrt(U256::from(9u64)), U256::from(3u64));
        assert_eq!(isqrt(U256::from(16u64)), U256::from(4u64));
        assert_eq!(isqrt(U256::from(100u64)), U256::from(10u64));
        // floor(sqrt(2)) = 1
        assert_eq!(isqrt(U256::from(2u64)), U256::from(1u64));
        // floor(sqrt(15)) = 3
        assert_eq!(isqrt(U256::from(15u64)), U256::from(3u64));
        // Large value: sqrt(1e36) = 1e18
        let val = SCALE_1E18 * SCALE_1E18;
        assert_eq!(isqrt(val), SCALE_1E18);
    }

    #[test]
    fn median_returns_the_only_observation() {
        let ballot = vec![VoteForTally {
            exchange_rate: fixed18(100u64),
            volume: SCALE_1E18,
            voter: Address::new([1u8; 20]),
        }];
        assert_eq!(median(&ballot), fixed18(100u64));
    }

    #[test]
    fn median_returns_the_central_observation_for_an_odd_ballot() {
        let ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(100u64),
                volume: SCALE_1E18,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: fixed18(200u64),
                volume: SCALE_1E18,
                voter: Address::new([2u8; 20]),
            },
            VoteForTally {
                exchange_rate: fixed18(300u64),
                volume: SCALE_1E18,
                voter: Address::new([3u8; 20]),
            },
        ];
        assert_eq!(median(&ballot), fixed18(200u64));
    }

    #[test]
    fn median_averages_the_two_central_observations_for_an_even_ballot() {
        let ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(100u64),
                volume: SCALE_1E18,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: fixed18(200u64),
                volume: SCALE_1E18,
                voter: Address::new([2u8; 20]),
            },
        ];
        assert_eq!(median(&ballot), fixed18(150));
    }

    #[test]
    fn median_midpoint_floors_in_the_rate_minor_unit() {
        let ballot = vec![
            VoteForTally {
                exchange_rate: U256::from(100u64),
                volume: U256::ONE,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: U256::from(201u64),
                volume: U256::ONE,
                voter: Address::new([2u8; 20]),
            },
        ];

        assert_eq!(median(&ballot), U256::from(150u64));
    }

    #[test]
    fn median_is_invariant_under_input_permutation_after_sorting() {
        let mut ballot = vec![
            VoteForTally {
                exchange_rate: U256::from(300u64),
                volume: U256::ONE,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: U256::from(100u64),
                volume: U256::ONE,
                voter: Address::new([2u8; 20]),
            },
            VoteForTally {
                exchange_rate: U256::from(200u64),
                volume: U256::ONE,
                voter: Address::new([3u8; 20]),
            },
        ];
        ballot.sort_by_key(|vote| vote.exchange_rate);
        assert_eq!(median(&ballot), U256::from(200u64));
    }

    #[test]
    fn median_of_an_empty_ballot_is_zero() {
        let ballot: Vec<VoteForTally> = vec![];
        assert_eq!(median(&ballot), U256::ZERO);
    }

    #[test]
    fn test_standard_deviation_identical() {
        // All same rate -> std dev = 0
        let ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(100u64),
                volume: SCALE_1E18,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: fixed18(100u64),
                volume: SCALE_1E18,
                voter: Address::new([2u8; 20]),
            },
        ];
        let median = fixed18(100u64);
        assert_eq!(standard_deviation(&ballot, median).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_standard_deviation_known() {
        // Rates: 100, 200. Median = 150.
        // Deviations: 50, 50. Squared: 2500, 2500.
        // Variance = 5000/2 = 2500. StdDev = 50.
        // Rates: 8e18, 12e18. Median = 10e18 (assume given).
        // Deviations: 2e18, 2e18. Squared: 4e36, 4e36.
        // Variance = 8e36/2 = 4e36. StdDev = sqrt(4e36) = 2e18.
        let rate_a = fixed18(8u64);
        let rate_b = fixed18(12u64);
        let median = fixed18(10u64);
        let ballot = vec![
            VoteForTally {
                exchange_rate: rate_a,
                volume: SCALE_1E18,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: rate_b,
                volume: SCALE_1E18,
                voter: Address::new([2u8; 20]),
            },
        ];
        let std_dev = standard_deviation(&ballot, median).unwrap();
        assert_eq!(std_dev, fixed18(2u64));
    }

    #[test]
    fn standard_deviation_widens_large_squares_instead_of_returning_zero() {
        let ballot = vec![
            VoteForTally {
                exchange_rate: U256::MAX,
                volume: SCALE_1E18,
                voter: Address::new([1u8; 20]),
            },
            VoteForTally {
                exchange_rate: U256::MAX,
                volume: SCALE_1E18,
                voter: Address::new([2u8; 20]),
            },
        ];
        let std_dev = standard_deviation(&ballot, U256::ZERO).unwrap();
        assert_eq!(std_dev, U256::MAX);
    }

    #[test]
    fn reward_band_includes_both_exact_boundaries() {
        let voters = [
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
        ];
        let mut ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(99),
                volume: U256::ONE,
                voter: voters[0],
            },
            VoteForTally {
                exchange_rate: fixed18(100),
                volume: U256::ONE,
                voter: voters[1],
            },
            VoteForTally {
                exchange_rate: fixed18(101),
                volume: U256::ONE,
                voter: voters[2],
            },
        ];
        let mut claims = voters
            .into_iter()
            .map(|voter| (voter, Claim::default()))
            .collect::<Vec<_>>();

        let median = tally_pair(
            &mut ballot,
            U256::from(20_000_000_000_000_000u64),
            &mut claims,
        )
        .unwrap();

        assert_eq!(median, fixed18(100));
        assert!(claims.iter().all(|(_, claim)| claim.win_count == 1));
    }

    #[test]
    fn reward_band_excludes_one_rate_unit_beyond_the_lower_boundary() {
        let voters = [
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
        ];
        let mut ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(99) - U256::ONE,
                volume: U256::ONE,
                voter: voters[0],
            },
            VoteForTally {
                exchange_rate: fixed18(100),
                volume: U256::ONE,
                voter: voters[1],
            },
            VoteForTally {
                exchange_rate: fixed18(101),
                volume: U256::ONE,
                voter: voters[2],
            },
        ];
        let mut claims = voters
            .into_iter()
            .map(|voter| (voter, Claim::default()))
            .collect::<Vec<_>>();

        let median = tally_pair(
            &mut ballot,
            U256::from(20_000_000_000_000_000u64),
            &mut claims,
        )
        .unwrap();

        assert_eq!(median, fixed18(100));
        assert_eq!(claims[0].1.win_count, 0);
        assert_eq!(claims[1].1.win_count, 1);
        assert_eq!(claims[2].1.win_count, 1);
    }

    #[test]
    fn test_tally_pair_winners() {
        // 3 validators voting on one pair.
        // Rates: 100, 101, 200 (1e18 scaled).
        // With one validator per observation, the central rate is 101.
        // StdDev: deviations from 101 = |100-101|=1, |101-101|=0, |200-101|=99
        // Squared: 1, 0, 9801. Sum=9802. Variance=9802/3=3267.33. StdDev=sqrt(3267.33)~=57.16
        // Reward band = 0.02 * 1e18. base_spread = 101 * 0.02 / 2 = 1.01.
        // Since stddev(57.16) > base_spread(1.01), reward_spread = 57.16.
        // Range: [101-57.16, 101+57.16] = [43.84, 158.16]
        // Vote 100 is in range -> win. Vote 101 is in range -> win. Vote 200 is NOT in range -> miss.

        let addr1 = Address::new([1u8; 20]);
        let addr2 = Address::new([2u8; 20]);
        let addr3 = Address::new([3u8; 20]);

        let mut ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(100u64),
                volume: SCALE_1E18,
                voter: addr1,
            },
            VoteForTally {
                exchange_rate: fixed18(101u64),
                volume: SCALE_1E18,
                voter: addr2,
            },
            VoteForTally {
                exchange_rate: fixed18(200u64),
                volume: SCALE_1E18,
                voter: addr3,
            },
        ];

        let reward_band = U256::from(20_000_000_000_000_000u128); // 0.02 * 1e18
        let mut claims = vec![
            (addr1, Claim::default()),
            (addr2, Claim::default()),
            (addr3, Claim::default()),
        ];

        let median = tally_pair(&mut ballot, reward_band, &mut claims).unwrap();
        assert_eq!(median, fixed18(101u64));

        // Voters 1 and 2 should have won, voter 3 should have missed
        assert_eq!(claims[0].1.win_count, 1); // addr1: rate 100, in range
        assert_eq!(claims[1].1.win_count, 1); // addr2: rate 101, in range
        assert_eq!(claims[2].1.win_count, 0); // addr3: rate 200, out of range
        assert!(claims[0].1.did_vote);
        assert!(claims[1].1.did_vote);
        assert!(claims[2].1.did_vote);
    }

    #[test]
    fn tally_pair_excludes_zero_rate_from_price_and_rewards() {
        let valid = Address::new([1u8; 20]);
        let zero_rate = Address::new([2u8; 20]);
        let mut ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(100),
                volume: SCALE_1E18,
                voter: valid,
            },
            VoteForTally {
                exchange_rate: U256::ZERO,
                volume: SCALE_1E18,
                voter: zero_rate,
            },
        ];
        let mut claims = vec![(valid, Claim::default()), (zero_rate, Claim::default())];

        let median = tally_pair(&mut ballot, U256::ZERO, &mut claims).unwrap();

        assert_eq!(median, fixed18(100));
        assert_eq!(claims[0].1.win_count, 1);
        assert_eq!(claims[1].1.win_count, 0);
        assert!(claims.iter().all(|(_, claim)| claim.did_vote));
    }

    #[test]
    fn test_cross_rate() {
        let addr1 = Address::new([1u8; 20]);
        let addr2 = Address::new([2u8; 20]);
        let reference_pair =
            AddressPair::from_addresses(Address::new([3u8; 20]), Address::new([4u8; 20]));
        let target_pair =
            AddressPair::from_addresses(Address::new([5u8; 20]), Address::new([6u8; 20]));

        // Reference pair votes (e.g., ETH/USD): voter1=2000, voter2=2010
        let reference_votes = vec![(addr1, fixed18(2000u64)), (addr2, fixed18(2010u64))];

        // Current pair votes (e.g., BTC/USD): voter1=40000, voter2=40200
        let ballot = vec![
            VoteForTally {
                exchange_rate: fixed18(40000u64),
                volume: SCALE_1E18,
                voter: addr1,
            },
            VoteForTally {
                exchange_rate: fixed18(40200u64),
                volume: SCALE_1E18,
                voter: addr2,
            },
        ];

        let cross = to_cross_rate(&ballot, &reference_votes, reference_pair, target_pair).unwrap();

        // Cross rate for voter1: 2000 * 1e18 / 40000 = 0.05 * 1e18
        assert_eq!(
            cross[0].exchange_rate,
            U256::from(50_000_000_000_000_000u128)
        ); // 0.05e18

        // Cross rate for voter2: 2010 * 1e18 / 40200 = 0.05 * 1e18 (approximately)
        // 2010e18 * 1e18 / 40200e18 = 2010/40200 * 1e18 = 0.05 * 1e18
        assert_eq!(
            cross[1].exchange_rate,
            U256::from(50_000_000_000_000_000u128)
        ); // 0.05e18 (exact due to integer division)
    }

    #[test]
    fn cross_rate_keeps_a_dimensionless_fp18_ratio_for_p6_coen_iso_inputs() {
        let voter = Address::new([1u8; 20]);
        let reference_votes = vec![(voter, U256::from(2_000_000u64))];
        let ballot = vec![VoteForTally {
            exchange_rate: U256::from(4_000_000u64),
            volume: U256::from(1_000_000u64),
            voter,
        }];

        let cross = to_cross_rate(
            &ballot,
            &reference_votes,
            AddressPair::new_coen_to(840),
            AddressPair::new_coen_to(978),
        )
        .unwrap();

        assert_eq!(
            cross[0].exchange_rate,
            U256::from(500_000_000_000_000_000u64)
        );
    }

    #[test]
    fn cross_rate_excludes_a_vote_without_an_eligible_reference_leg() {
        let included = Address::new([1u8; 20]);
        let missing = Address::new([2u8; 20]);
        let reference_votes = vec![(included, U256::from(2_000_000u64))];
        let ballot = vec![
            VoteForTally {
                exchange_rate: U256::from(4_000_000u64),
                volume: U256::from(1_000_000u64),
                voter: included,
            },
            VoteForTally {
                exchange_rate: U256::from(5_000_000u64),
                volume: U256::from(1_000_000u64),
                voter: missing,
            },
        ];

        let cross = to_cross_rate(
            &ballot,
            &reference_votes,
            AddressPair::new_coen_to(840),
            AddressPair::new_coen_to(978),
        )
        .unwrap();

        assert_eq!(cross.len(), 1);
        assert_eq!(cross[0].voter, included);
    }

    #[test]
    fn mixed_scale_cross_rate_round_trips_from_coen_iso_to_generic() {
        let voter = Address::new([1u8; 20]);
        let reference_pair = AddressPair::new_coen_to(840);
        let target_pair =
            AddressPair::from_addresses(Address::new([2u8; 20]), Address::new([3u8; 20]));
        let reference_rate = U256::from(2_000_000u64);
        let target_rate = fixed18(40_000);
        let ballot = vec![VoteForTally {
            exchange_rate: target_rate,
            volume: U256::ONE,
            voter,
        }];

        let cross = to_cross_rate(
            &ballot,
            &[(voter, reference_rate)],
            reference_pair,
            target_pair,
        )
        .unwrap();

        assert_eq!(cross[0].exchange_rate, U256::from(50_000_000_000_000u64));
        assert_eq!(
            from_cross_rate(
                reference_rate,
                cross[0].exchange_rate,
                reference_pair,
                target_pair,
            )
            .unwrap(),
            target_rate
        );
    }

    #[test]
    fn mixed_scale_cross_rate_round_trip_documents_flooring_loss() {
        let voter = Address::new([1u8; 20]);
        let reference_pair = AddressPair::new_coen_to(840);
        let target_pair =
            AddressPair::from_addresses(Address::new([2u8; 20]), Address::new([3u8; 20]));
        let reference_rate = U256::from(1_000_000u64);
        let target_rate = fixed18(3);
        let ballot = vec![VoteForTally {
            exchange_rate: target_rate,
            volume: U256::ONE,
            voter,
        }];

        let cross = to_cross_rate(
            &ballot,
            &[(voter, reference_rate)],
            reference_pair,
            target_pair,
        )
        .unwrap();

        assert_eq!(
            cross[0].exchange_rate,
            U256::from(333_333_333_333_333_333u64)
        );
        assert_eq!(
            from_cross_rate(
                reference_rate,
                cross[0].exchange_rate,
                reference_pair,
                target_pair,
            )
            .unwrap(),
            target_rate + U256::from(3u64)
        );
    }

    #[test]
    fn mixed_scale_cross_rate_round_trips_from_generic_to_coen_iso() {
        let voter = Address::new([1u8; 20]);
        let reference_pair =
            AddressPair::from_addresses(Address::new([2u8; 20]), Address::new([3u8; 20]));
        let target_pair = AddressPair::new_coen_to(978);
        let reference_rate = fixed18(2_000);
        let target_rate = U256::from(4_000_000u64);
        let ballot = vec![VoteForTally {
            exchange_rate: target_rate,
            volume: U256::ONE,
            voter,
        }];

        let cross = to_cross_rate(
            &ballot,
            &[(voter, reference_rate)],
            reference_pair,
            target_pair,
        )
        .unwrap();

        assert_eq!(cross[0].exchange_rate, fixed18(500));
        assert_eq!(
            from_cross_rate(
                reference_rate,
                cross[0].exchange_rate,
                reference_pair,
                target_pair,
            )
            .unwrap(),
            target_rate
        );
    }
}
