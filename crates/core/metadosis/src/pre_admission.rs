use alloy_primitives::B256;
use outbe_ocomp_protocol::{
    generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1,
    intent::{AuctionEntryPriceSource, PreAdmissionEnvelopeV1, ReferenceEntryPriceV1},
    profile::CapacityProfileV1,
    SchemaLimits,
};
use outbe_oracle::api::{OcompAuctionEntryPriceSource, OcompOraclePreAdmissionProjection};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::TributePreAdmissionProjection;

use crate::{
    errors::MetadosisError,
    schema::{MetadosisContract, OcompPreAdmissionState},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreAdmissionContext {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub correctness_profile_id: B256,
    pub capacity_profile: CapacityProfileV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreAdmissionInputs {
    pub tribute: TributePreAdmissionProjection,
    /// Ordered commitment over the day's snapshotted `(owner, league)` pairs,
    /// computed by the caller from the sealed owner set. Sealed into the
    /// envelope so the OCOMP opening's owner/league set is consensus-committed.
    pub fidelity_league_snapshot_root: B256,
    pub oracle: OcompOraclePreAdmissionProjection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PreAdmissionDecision {
    Eligible(Box<PreAdmissionEnvelopeV1>),
    Deferred(PreAdmissionDeferredReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreAdmissionDeferredReason {
    TributeProfileNotReady,
    TributeNotSealed,
    EmptyTributeDay,
    ReferenceCurrencyCountExceeded { actual: u16, limit: u16 },
    OracleProfileNotReady,
    OracleOpeningCountExceeded { actual: u16, limit: u16 },
    OracleWwdPairEntriesExceeded { actual: u32, limit: u32 },
    ActiveScurveEntriesExceeded { actual: u32, limit: u32 },
    ArithmeticOverflow,
}

/// Produces the complete typed pre-admission envelope from bounded owner
/// projections only. It never owns or enumerates Tribute, Fidelity or Oracle
/// records.
pub(crate) fn evaluate_pre_admission(
    context: &PreAdmissionContext,
    inputs: &PreAdmissionInputs,
) -> Result<PreAdmissionDecision> {
    let candidate = OCOMP_POC_CANDIDATE_LIMITS_V1;
    let tribute = inputs.tribute;
    let oracle = &inputs.oracle;

    if !tribute.profile_ready {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::TributeProfileNotReady,
        ));
    }
    if !tribute.is_sealed || tribute.sealed_collection_root.is_zero() {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::TributeNotSealed,
        ));
    }
    if tribute.tribute_count == 0 {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::EmptyTributeDay,
        ));
    }
    let reference_currency_limit = context
        .capacity_profile
        .max_reference_currencies
        .min(u16::try_from(candidate.max_oracle_openings).unwrap_or(u16::MAX));
    if tribute.distinct_reference_currency_count > reference_currency_limit {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::ReferenceCurrencyCountExceeded {
                actual: tribute.distinct_reference_currency_count,
                limit: reference_currency_limit,
            },
        ));
    }
    if !oracle.profile_ready {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::OracleProfileNotReady,
        ));
    }
    let Some(oracle_opening_limit) = u16::try_from(candidate.max_oracle_openings).ok() else {
        return Ok(arithmetic_overflow());
    };
    if tribute.distinct_reference_currency_count > oracle_opening_limit {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::OracleOpeningCountExceeded {
                actual: tribute.distinct_reference_currency_count,
                limit: oracle_opening_limit,
            },
        ));
    }
    let Some(candidate_oracle_pair_limit) =
        u32::try_from(candidate.max_oracle_wwd_pair_entries).ok()
    else {
        return Ok(arithmetic_overflow());
    };
    let oracle_pair_limit = context
        .capacity_profile
        .max_oracle_wwd_pair_entries
        .min(candidate_oracle_pair_limit);
    if oracle.wwd_pair_entries > oracle_pair_limit {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::OracleWwdPairEntriesExceeded {
                actual: oracle.wwd_pair_entries,
                limit: oracle_pair_limit,
            },
        ));
    }
    let Some(candidate_scurve_limit) = u32::try_from(candidate.max_active_scurve_entries).ok()
    else {
        return Ok(arithmetic_overflow());
    };
    let scurve_limit = context
        .capacity_profile
        .max_active_scurve_entries
        .min(candidate_scurve_limit);
    if oracle.active_scurve_entries > scurve_limit {
        return Ok(PreAdmissionDecision::Deferred(
            PreAdmissionDeferredReason::ActiveScurveEntriesExceeded {
                actual: oracle.active_scurve_entries,
                limit: scurve_limit,
            },
        ));
    }

    let Some(input_encoded_bytes_upper_bound) = tribute
        .canonical_body_bytes
        .checked_add(candidate.max_input_manifest_bytes)
    else {
        return Ok(arithmetic_overflow());
    };
    let Some(output_record_upper_bound) = tribute.tribute_count.checked_mul(3) else {
        return Ok(arithmetic_overflow());
    };
    let Some(retained_bytes_upper_bound) = input_encoded_bytes_upper_bound
        .checked_add(candidate.max_result_summary_bytes)
        .and_then(|value| value.checked_add(candidate.max_activation_ocb1_bytes))
        .and_then(|value| value.checked_add(candidate.max_finalized_intent_proof_bytes))
        .and_then(|value| value.checked_add(candidate.max_result_vote_bytes))
    else {
        return Ok(arithmetic_overflow());
    };

    // The oracle already ordered the rows by currency; the envelope commits that order.
    let auction_entry_prices = oracle
        .auction_entry_prices
        .iter()
        .map(|row| ReferenceEntryPriceV1 {
            reference_currency: row.reference_currency,
            entry_price_minor: row.entry_price_minor,
            source: match row.source {
                OcompAuctionEntryPriceSource::LastClosedDayVwap => {
                    AuctionEntryPriceSource::LastClosedDayVwap
                }
                OcompAuctionEntryPriceSource::CurrentVwapFallback => {
                    AuctionEntryPriceSource::CurrentVwapFallback
                }
            },
            source_day: row.source_day,
        })
        .collect();
    Ok(PreAdmissionDecision::Eligible(Box::new(
        PreAdmissionEnvelopeV1 {
            chain_id: context.chain_id,
            genesis_hash: context.genesis_hash,
            fork_id: context.fork_id,
            wwd: tribute.worldwide_day.value(),
            sealed_tribute_collection_root: tribute.sealed_collection_root,
            sealed_tribute_count: tribute.tribute_count,
            sealed_tribute_canonical_body_bytes: tribute.canonical_body_bytes,
            distinct_owner_count: tribute.distinct_owner_count,
            distinct_reference_currency_count: tribute.distinct_reference_currency_count,
            fidelity_league_snapshot_root: inputs.fidelity_league_snapshot_root,
            oracle_wwd_pair_entries_observed: oracle.wwd_pair_entries,
            active_scurve_entries_observed: oracle.active_scurve_entries,
            auction_entry_prices,
            oracle_state_version: oracle.oracle_state_version,
            fidelity_opening_upper_bound: tribute.distinct_owner_count,
            oracle_opening_upper_bound: u32::from(tribute.distinct_reference_currency_count),
            input_encoded_bytes_upper_bound,
            output_record_upper_bound,
            result_chunk_bytes_upper_bound: candidate.max_result_chunk_bytes,
            activation_bytes_upper_bound: candidate.max_activation_ocb1_bytes,
            retained_bytes_upper_bound,
            correctness_profile_id: context.correctness_profile_id,
            capacity_profile_id: context.capacity_profile.profile_id,
        },
    )))
}

const fn arithmetic_overflow() -> PreAdmissionDecision {
    PreAdmissionDecision::Deferred(PreAdmissionDeferredReason::ArithmeticOverflow)
}

/// Immutable public projection of the Metadosis-owned OCOMP seal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadosisPreAdmissionProjection {
    pub initialized: bool,
    pub state_version: u64,
    pub envelope_hash: B256,
}

impl MetadosisContract<'_> {
    /// Initializes the per-day OCOMP state on a fresh-devnet fork.
    ///
    /// The later fork handler owns the production call site. Repeating the
    /// exact initialization is idempotent; any non-canonical partial record is
    /// rejected.
    pub(crate) fn initialize_ocomp_pre_admission(
        &mut self,
        wwd: WorldwideDay,
    ) -> Result<MetadosisPreAdmissionProjection> {
        (|| {
            if let Some(existing) = self.ocomp_pre_admission.get(wwd)? {
                if existing.initialized
                    && existing.state_version > 0
                    && existing.envelope_hash.is_zero()
                {
                    return self.ocomp_pre_admission_projection(wwd);
                }
                return Err(MetadosisError::CorruptOcompPreAdmissionState {
                    wwd,
                    initialized: existing.initialized,
                    state_version: existing.state_version,
                    envelope_hash: existing.envelope_hash,
                }
                .into());
            }

            let state = OcompPreAdmissionState {
                wwd,
                initialized: true,
                state_version: 1,
                envelope_hash: B256::ZERO,
            };
            self.ocomp_pre_admission.create(&state)?;
            self.ocomp_pre_admission_projection(wwd)
        })()
    }

    pub fn ocomp_pre_admission_projection(
        &self,
        wwd: WorldwideDay,
    ) -> Result<MetadosisPreAdmissionProjection> {
        let state = self
            .ocomp_pre_admission
            .get(wwd)?
            .unwrap_or_else(|| OcompPreAdmissionState::with_key(wwd));
        Ok(MetadosisPreAdmissionProjection {
            initialized: state.initialized,
            state_version: state.state_version,
            envelope_hash: state.envelope_hash,
        })
    }

    /// Commits the exact canonical envelope once. No component field can be
    /// replaced later because the non-zero hash is an immutable seal.
    pub(crate) fn seal_pre_admission_envelope(
        &mut self,
        wwd: WorldwideDay,
        envelope: &PreAdmissionEnvelopeV1,
        limits: &SchemaLimits,
    ) -> Result<MetadosisPreAdmissionProjection> {
        (|| {
            if envelope.wwd != wwd.value() {
                return Err(MetadosisError::OcompPreAdmissionWwdMismatch {
                    expected: wwd,
                    actual: envelope.wwd,
                }
                .into());
            }

            let mut state = self
                .ocomp_pre_admission
                .get(wwd)?
                .ok_or(MetadosisError::OcompPreAdmissionNotInitialized { wwd })?;
            if !state.initialized || state.state_version == 0 {
                return Err(MetadosisError::CorruptOcompPreAdmissionState {
                    wwd,
                    initialized: state.initialized,
                    state_version: state.state_version,
                    envelope_hash: state.envelope_hash,
                }
                .into());
            }
            if !state.envelope_hash.is_zero() {
                return Err(MetadosisError::OcompPreAdmissionAlreadySealed { wwd }.into());
            }

            let envelope_hash = envelope.envelope_hash(limits).map_err(|error| {
                MetadosisError::InvalidOcompPreAdmissionEnvelope {
                    reason: error.to_string(),
                }
            })?;
            if envelope_hash.is_zero() {
                return Err(MetadosisError::InvalidOcompPreAdmissionEnvelopeHash.into());
            }
            state.state_version = state
                .state_version
                .checked_add(1)
                .ok_or(MetadosisError::OcompStateVersionOverflow { wwd })?;
            state.envelope_hash = envelope_hash;
            self.ocomp_pre_admission.update(&state)?;
            self.ocomp_pre_admission_projection(wwd)
        })()
    }
}
