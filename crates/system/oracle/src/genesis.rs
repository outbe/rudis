//! Genesis import/export for the Oracle contract.
//!
//! Owns the `OracleGenesisConfig` shape plus the `init_from_genesis` /
//! `export_genesis` round-trip used for chain bootstrap and state migration.

use crate::constants::{DAY_TYPE_ISO, DEFAULT_USD_CURRENCY_RATE, MAX_SNAPSHOT_RETENTION_SECONDS};
use crate::schema::OracleContract;
use crate::types::AssetType;
use alloy_primitives::{Address, U256};
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::asset_type::COEN_ASSET;
use outbe_primitives::error::Result;

use crate::errors::OracleError;
use std::collections::BTreeSet;

/// A price snapshot entry for genesis import/export.
#[derive(Clone, Debug)]
pub struct GenesisSnapshot {
    /// Unix timestamp of the snapshot.
    pub timestamp: u64,
    /// Entries as `(base, quote, rate, volume)` in each pair's registered scale.
    pub entries: Vec<(Address, Address, U256, U256)>,
}

/// An S-curve entry for genesis import/export.
#[derive(Clone, Debug)]
pub struct GenesisScurveEntry {
    /// The pair this peak belongs to, quoted as registered.
    pub base: Address,
    /// Quote asset of the pair.
    pub quote: Address,
    /// UTC midnight timestamp of the peak day.
    pub peak_day: u64,
    /// Peak price in the COEN/840 S-Curve's six-decimal scale.
    pub peak_price: U256,
}

/// A pending aggregate vote for genesis import/export.
#[derive(Clone, Debug)]
pub struct GenesisAggregateVote {
    /// Validator address that owns this pending vote.
    pub validator: Address,
    /// Entries as `(base, quote, rate, volume)` in each pair's registered scale.
    pub entries: Vec<(Address, Address, U256, U256)>,
}

/// An independently registered annual policy rate for one ISO 4217 currency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRate {
    /// ISO 4217 numeric code (e.g., 840 = USD).
    pub iso_code: u16,
    /// Annualized rate at scale `1e6` (e.g., 0.043 -> 43_000).
    pub annual_rate_1e6: U256,
}

const MAX_REFERENCE_CURRENCIES: usize = 6;

/// Configurable genesis parameters for the Oracle contract.
///
/// Dimensionless policy fields retain FP18. COEN/ISO pair rates, volumes and
/// snapshots use six decimals; the COEN/840 S-Curve uses the same rate scale 1e6.
/// Generic non-ISO pair data retains its existing contract.
pub struct OracleGenesisConfig {
    /// Vote period in blocks (default: 2).
    pub vote_period: u64,
    /// Reward band width (1e18 scaled, default: 0.02 * 1e18 = 2e16).
    pub reward_band: U256,
    /// Slash window in blocks (default: 96).
    pub slash_window: u64,
    /// Minimum valid-vote ratio per window (1e18 scaled, default: 0.05 * 1e18 = 5e16).
    pub min_valid_per_window: U256,
    /// Slash fraction (1e18 scaled, default: 0).
    pub slash_fraction: U256,
    /// Lookback duration in seconds for VWAP (default: 86400).
    pub lookback_duration: u64,
    /// Trading pairs to register at genesis as `(base, quote)` asset addresses.
    /// The direction given here is the direction reads must be quoted in.
    pub pairs: Vec<(Address, Address)>,
    /// Initial exchange rates as `(base, quote, rate)` in each pair's scale.
    pub initial_rates: Vec<(Address, Address, U256)>,
    /// Feeder delegations as `(validator, feeder)`.
    pub feeder_delegations: Vec<(Address, Address)>,
    /// Sorted unique ISO codes valid as pricing reference currencies.
    pub reference_currencies: Vec<u16>,
    /// Sorted unique annual policy rates, independent from references and pairs.
    pub policy_rates: Vec<PolicyRate>,
    /// Penalty counters as `(validator, success, abstain, miss)`.
    pub penalty_counters: Vec<(Address, u64, u64, u64)>,
    /// Pending aggregate votes that have not yet been tallied.
    pub aggregate_votes: Vec<GenesisAggregateVote>,
    /// Price snapshots for the circular buffer.
    pub snapshots: Vec<GenesisSnapshot>,
    /// Active S-curve entries.
    pub scurve_entries: Vec<GenesisScurveEntry>,
    /// Validators protected from slashing.
    pub protected_validators: Vec<Address>,
}

impl OracleGenesisConfig {
    /// Returns the config that matches the current hard-coded genesis values.
    pub fn default_config() -> Self {
        Self {
            vote_period: 2,
            reward_band: U256::from(20_000_000_000_000_000u128), // 0.02
            slash_window: 96,
            min_valid_per_window: U256::from(50_000_000_000_000_000u128), // 0.05
            slash_fraction: U256::ZERO,
            lookback_duration: 86400,
            pairs: vec![(COEN_ASSET, AssetType::IsoCurrency(DAY_TYPE_ISO).into())],
            initial_rates: vec![],
            feeder_delegations: vec![],
            reference_currencies: vec![156, 344, 392, 826, 840, 978],
            policy_rates: vec![PolicyRate {
                iso_code: 840,
                annual_rate_1e6: DEFAULT_USD_CURRENCY_RATE,
            }],
            penalty_counters: vec![],
            aggregate_votes: vec![],
            snapshots: vec![],
            scurve_entries: vec![],
            protected_validators: vec![],
        }
    }
}

/// Initializes all oracle state from a genesis configuration.
///
/// Writes config slots, registers pairs, sets initial exchange rates, and
/// records feeder delegations. The oracle is marked as enabled and
/// initialized on success.
pub fn init_from_genesis(oracle: &mut OracleContract, config: &OracleGenesisConfig) -> Result<()> {
    // Idempotency guard: skip if already initialized (safe for block 0 replay).
    if oracle.config_is_initialized.read()? {
        return Ok(());
    }

    // Validate config parameters
    if config.vote_period == 0 {
        return Err(OracleError::VotePeriodZero.into());
    }
    if config.slash_window == 0 {
        return Err(OracleError::SlashWindowZero.into());
    }
    if config.lookback_duration > MAX_SNAPSHOT_RETENTION_SECONDS {
        return Err(OracleError::LookbackExceedsRetention.into());
    }
    validate_reference_currencies(&config.reference_currencies)?;
    validate_policy_rates(&config.policy_rates)?;

    oracle.config_vote_period.write(config.vote_period)?;
    oracle.config_reward_band.write(config.reward_band)?;
    oracle.config_slash_window.write(config.slash_window)?;
    oracle
        .config_min_valid_per_window
        .write(config.min_valid_per_window)?;
    oracle.config_slash_fraction.write(config.slash_fraction)?;
    oracle
        .config_lookback_duration
        .write(config.lookback_duration)?;

    // Register trading pairs.
    for (base, quote) in &config.pairs {
        oracle.register_pair(AddressPair::from_addresses(*base, *quote))?;
    }

    // Set initial exchange rates (system caller = Address::ZERO).
    for (base, quote, rate) in &config.initial_rates {
        oracle.set_exchange_rate(
            Address::ZERO,
            AddressPair::from_addresses(*base, *quote),
            *rate,
            0,
            0,
        )?;
    }

    // Record role-scoped feeder delegations in ValidatorSet.
    let mut validator_set = outbe_validatorset::contract::ValidatorSet::new(oracle.storage.clone());
    for (validator, feeder) in &config.feeder_delegations {
        validator_set.set_delegate(
            *validator,
            outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
            *feeder,
        )?;
    }

    // Import the independent reference-currency and policy-rate registries.
    for iso_code in &config.reference_currencies {
        oracle.reference_currencies.push(*iso_code)?;
    }
    for policy in &config.policy_rates {
        oracle.policy_rate_currencies.push(policy.iso_code)?;
        oracle
            .policy_rate
            .write(&policy.iso_code, policy.annual_rate_1e6)?;
    }

    // Import penalty counters.
    for (validator, success, abstain, miss) in &config.penalty_counters {
        oracle.penalty_success_count.write(validator, *success)?;
        oracle.penalty_abstain_count.write(validator, *abstain)?;
        oracle.penalty_miss_count.write(validator, *miss)?;
    }

    // Import pending aggregate votes.
    import_aggregate_votes(oracle, &config.aggregate_votes)?;

    // Import price snapshots into the circular buffer. Entries name pairs by
    // ordinal, so every one has to resolve against a pair registered above.
    for snapshot in &config.snapshots {
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for (base, quote, rate, volume) in &snapshot.entries {
            let pair = oracle.require_pair_from(*base, *quote)?;
            entries.push((pair, *rate, *volume));
        }
        oracle.write_snapshot(snapshot.timestamp, &entries)?;
    }

    // Import S-curve entries.
    for entry in &config.scurve_entries {
        let pair = oracle.require_pair_from(entry.base, entry.quote)?;
        crate::scurve::store_scurve_entry(oracle, pair, entry.peak_day, entry.peak_price)?;
    }

    // Import protected validators.
    if !config.protected_validators.is_empty() {
        oracle.config_allow_protected.write(true)?;
        for validator in &config.protected_validators {
            oracle.protected_validator.write(validator, true)?;
        }
    }

    oracle.config_enabled.write(true)?;
    oracle.config_is_initialized.write(true)?;

    Ok(())
}

/// Exports the full oracle state into an `OracleGenesisConfig`.
///
/// This reads all config slots, pair registry, exchange rates, delegations,
/// penalty counters, pending aggregate votes, snapshots, S-curve entries, and
/// protected validators.
///
/// The exported config can be used to re-initialize a fresh oracle via
/// `init_from_genesis`, enabling full state migration.
pub fn export_genesis(
    oracle: &OracleContract,
    validators: &[Address],
) -> Result<OracleGenesisConfig> {
    let vote_period = oracle.config_vote_period.read()?;
    let reward_band = oracle.config_reward_band.read()?;
    let slash_window = oracle.config_slash_window.read()?;
    let min_valid_per_window = oracle.config_min_valid_per_window.read()?;
    let slash_fraction = oracle.config_slash_fraction.read()?;
    let lookback_duration = oracle.config_lookback_duration.read()?;

    // Export pairs and non-zero initial rates.
    let pair_count = oracle.pair_count.read()?;
    let mut pairs = Vec::with_capacity(pair_count as usize);
    let mut initial_rates = Vec::new();

    for pair_id in 1..=pair_count {
        let pair = export_pair_metadata(oracle, pair_id)?;
        let rate = oracle.exchange_rate.read(&pair_id)?;
        if !rate.is_zero() {
            initial_rates.push((pair.address1(), pair.address2(), rate));
        }
        pairs.push((pair.address1(), pair.address2()));
    }

    // Export authoritative role-scoped feeder delegations.
    let validator_set = outbe_validatorset::contract::ValidatorSet::new(oracle.storage.clone());
    let mut feeder_delegations = Vec::new();
    for validator in validators {
        let feeder = validator_set.get_delegate(
            *validator,
            outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
        )?;
        if feeder != Address::ZERO {
            feeder_delegations.push((*validator, feeder));
        }
    }

    // Export penalty counters.
    let mut penalty_counters = Vec::new();
    for validator in validators {
        let success = oracle.penalty_success_count.read(validator)?;
        let abstain = oracle.penalty_abstain_count.read(validator)?;
        let miss = oracle.penalty_miss_count.read(validator)?;
        if success > 0 || abstain > 0 || miss > 0 {
            penalty_counters.push((*validator, success, abstain, miss));
        }
    }

    // Export pending aggregate votes.
    let aggregate_votes = export_aggregate_votes(oracle)?;

    // Export snapshots.
    let write_idx = oracle.snapshot_write_idx.read()?;
    let oldest_idx = oracle.snapshot_oldest_idx.read()?;
    let mut snapshots = Vec::new();
    for idx in oldest_idx..write_idx {
        let timestamp = oracle.snapshot_timestamp.read(&idx)?;
        let pc = oracle.snapshot_pair_count.read(&idx)?;
        let pair_map = oracle.snapshot_pair.get_nested(&idx);
        let rate_map = oracle.snapshot_rate.get_nested(&idx);
        let volume_map = oracle.snapshot_volume.get_nested(&idx);

        let mut entries = Vec::with_capacity(pc as usize);
        for p in 0..pc {
            let pair = pair_map.read_pair(&p)?;
            let rate = rate_map.read(&p)?;
            let volume = volume_map.read(&p)?;
            entries.push((pair.address1(), pair.address2(), rate, volume));
        }
        snapshots.push(GenesisSnapshot { timestamp, entries });
    }

    // Export S-curve entries.
    let scurve_count = oracle.scurve_count.read()?;
    let scurve_oldest = oracle.scurve_oldest_idx.read()?;
    let mut scurve_entries = Vec::new();
    for idx in scurve_oldest..scurve_count {
        let pair = oracle.scurve_pair.read_pair(&idx)?;
        let peak_day = oracle.scurve_peak_day.read(&idx)?;
        let peak_price = oracle.scurve_peak_price.read(&idx)?;
        scurve_entries.push(GenesisScurveEntry {
            base: pair.address1(),
            quote: pair.address2(),
            peak_day,
            peak_price,
        });
    }

    // Export protected validators.
    let allow_protected = oracle.config_allow_protected.read()?;
    let mut protected_validators = Vec::new();
    if allow_protected {
        for validator in validators {
            let is_protected = oracle.protected_validator.read(validator)?;
            if is_protected {
                protected_validators.push(*validator);
            }
        }
    }

    let reference_currencies = oracle.reference_currencies.read_all()?;
    let policy_iso_codes = oracle.policy_rate_currencies.read_all()?;
    let mut policy_rates = Vec::with_capacity(policy_iso_codes.len());
    for iso_code in policy_iso_codes {
        let annual_rate_1e6 = oracle.policy_rate.read(&iso_code)?;
        policy_rates.push(PolicyRate {
            iso_code,
            annual_rate_1e6,
        });
    }

    Ok(OracleGenesisConfig {
        vote_period,
        reward_band,
        slash_window,
        min_valid_per_window,
        slash_fraction,
        lookback_duration,
        pairs,
        initial_rates,
        feeder_delegations,
        reference_currencies,
        policy_rates,
        penalty_counters,
        aggregate_votes,
        snapshots,
        scurve_entries,
        protected_validators,
    })
}

fn validate_reference_currencies(reference_currencies: &[u16]) -> Result<()> {
    if reference_currencies.len() > MAX_REFERENCE_CURRENCIES {
        return Err(OracleError::ReferenceCurrencyCountExceedsMax.into());
    }
    let mut previous = None;
    for iso_code in reference_currencies {
        if *iso_code == 0 {
            return Err(OracleError::ReferenceIsoCodeZero.into());
        }
        if let Some(previous) = previous {
            if *iso_code == previous {
                return Err(OracleError::DuplicateReferenceIsoCode {
                    iso_code: *iso_code,
                }
                .into());
            }
            if *iso_code < previous {
                return Err(OracleError::ReferenceCurrenciesNotSorted.into());
            }
        }
        previous = Some(*iso_code);
    }
    if reference_currencies.binary_search(&DAY_TYPE_ISO).is_err() {
        return Err(OracleError::MissingUsdReferenceCurrency.into());
    }
    Ok(())
}

fn validate_policy_rates(policy_rates: &[PolicyRate]) -> Result<()> {
    let mut previous = None;
    for policy in policy_rates {
        if policy.iso_code == 0 {
            return Err(OracleError::PolicyIsoCodeZero.into());
        }
        if policy.annual_rate_1e6.is_zero() {
            return Err(OracleError::PolicyRateZero {
                iso_code: policy.iso_code,
            }
            .into());
        }
        if let Some(previous) = previous {
            if policy.iso_code == previous {
                return Err(OracleError::DuplicatePolicyIsoCode {
                    iso_code: policy.iso_code,
                }
                .into());
            }
            if policy.iso_code < previous {
                return Err(OracleError::PolicyRatesNotSorted.into());
            }
        }
        previous = Some(policy.iso_code);
    }
    Ok(())
}

fn import_aggregate_votes(
    oracle: &mut OracleContract,
    aggregate_votes: &[GenesisAggregateVote],
) -> Result<()> {
    let pair_count = oracle.pair_count.read()?;
    let mut seen_validators = BTreeSet::new();
    let mut validated_votes = Vec::with_capacity(aggregate_votes.len());

    for vote in aggregate_votes {
        if vote.validator == Address::ZERO {
            return Err(OracleError::AggregateVoteValidatorZero.into());
        }
        if !seen_validators.insert(vote.validator) {
            return Err(OracleError::DuplicateAggregateVoteValidator.into());
        }
        if oracle.vote_exists.read(&vote.validator)? {
            return Err(OracleError::AggregateVoteAlreadyExists.into());
        }
        if vote.entries.len() > u32::MAX as usize || vote.entries.len() as u32 > pair_count {
            return Err(OracleError::AggregateVoteTupleCountExceedsPairCount.into());
        }

        let mut seen_pairs = BTreeSet::new();
        for (base, quote, _, _) in &vote.entries {
            // `require_pair` also rejects a pair quoted against its registered
            // direction, so an imported vote cannot smuggle in an inverted rate.
            let pair = oracle
                .require_pair_from(*base, *quote)
                .map_err(|_| OracleError::AggregateVotePairNotRegistered)?;
            if !seen_pairs.insert(pair) {
                return Err(OracleError::DuplicatePairInAggregateVote.into());
            }
            if !oracle.vote_target.read(&pair)? {
                return Err(OracleError::AggregateVotePairNotVoteTarget.into());
            }
        }

        validated_votes.push((vote.validator, vote.entries.clone()));
    }

    for (validator, entries) in validated_votes {
        oracle.vote_exists.write(&validator, true)?;
        oracle
            .vote_tuple_count
            .write(&validator, entries.len() as u32)?;

        let pair_map = oracle.vote_pair.get_nested(&validator);
        let rate_map = oracle.vote_rate.get_nested(&validator);
        let volume_map = oracle.vote_volume.get_nested(&validator);

        for (idx, (base, quote, rate, volume)) in entries.into_iter().enumerate() {
            let idx = idx as u32;
            pair_map.write_pair(&idx, AddressPair::from_addresses(base, quote))?;
            rate_map.write(&idx, rate)?;
            volume_map.write(&idx, volume)?;
        }

        oracle.voter_list.push(validator)?;
    }

    Ok(())
}

fn export_aggregate_votes(oracle: &OracleContract) -> Result<Vec<GenesisAggregateVote>> {
    let voter_count = oracle.voter_list.len()?;
    let mut seen_validators = BTreeSet::new();
    let mut aggregate_votes = Vec::with_capacity(voter_count as usize);

    for voter_idx in 0..voter_count {
        let validator = oracle.voter_list.get(voter_idx)?.ok_or(
            OracleError::MissingAggregateVoteValidator {
                voter_index: voter_idx,
            },
        )?;

        if validator == Address::ZERO {
            return Err(OracleError::AggregateVoteValidatorZero.into());
        }
        if !seen_validators.insert(validator) {
            return Err(OracleError::DuplicateAggregateVoteValidator.into());
        }
        if !oracle.vote_exists.read(&validator)? {
            return Err(OracleError::VoterListEntryWithoutVote.into());
        }

        let tuple_count = oracle.vote_tuple_count.read(&validator)?;
        let pair_map = oracle.vote_pair.get_nested(&validator);
        let rate_map = oracle.vote_rate.get_nested(&validator);
        let volume_map = oracle.vote_volume.get_nested(&validator);
        let mut seen_pairs = BTreeSet::new();
        let mut entries = Vec::with_capacity(tuple_count as usize);

        for tuple_idx in 0..tuple_count {
            let pair = pair_map.read_pair(&tuple_idx)?;
            if oracle.pair_index_of(pair)? == 0 {
                return Err(OracleError::AggregateVotePairNotRegistered.into());
            }
            // Deduplicate on the market, not the quote direction, so the same
            // pair submitted both ways round is still caught.
            if !seen_pairs.insert(pair.to_canonical()) {
                return Err(OracleError::DuplicatePairInAggregateVote.into());
            }
            entries.push((
                pair.address1(),
                pair.address2(),
                rate_map.read(&tuple_idx)?,
                volume_map.read(&tuple_idx)?,
            ));
        }

        aggregate_votes.push(GenesisAggregateVote { validator, entries });
    }

    Ok(aggregate_votes)
}

/// The registered pair at `index`, checked against the forward map.
///
/// The zero address is a legitimate asset (native COEN), so an unwritten entry
/// cannot be spotted by a zero check. Round-tripping the pair back through
/// `pair_index` proves it is really there and doubles as the corruption check
/// the old pair-hash comparison used to provide.
fn export_pair_metadata(oracle: &OracleContract, pair_id: u32) -> Result<AddressPair> {
    let pair = oracle.pair_at(pair_id)?;
    if oracle.pair_index_of(pair)? != pair_id {
        return Err(OracleError::MissingPairMetadata { pair_id }.into());
    }
    Ok(pair)
}
