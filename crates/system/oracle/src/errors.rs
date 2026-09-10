//! Module-local error types for the Oracle.
//!
//! [`OracleError`] covers ordinary oracle failures: pair registry, votes,
//! VWAP/TWAP computation, genesis import/export. [`OracleOcompError`] covers
//! everything OCOMP: the fixed projection profile, its state-version stream, and
//! the raw-storage opening plans evaluated off-chain by `outbe-ocomp`.
//!
//! Both `From` impls below are exhaustive on purpose. A new variant must pick
//! its severity explicitly instead of defaulting to a revert through a wildcard
//! arm. Errors that are not oracle-specific (out-of-gas, storage faults) keep
//! coming from `outbe_primitives::error::PrecompileError`.

use crate::schema::PairIndex;
use alloy_primitives::{B256, U256};
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OracleError {
    // -- pair registry ------------------------------------------------------
    #[error("pair base and quote must differ")]
    PairBaseQuoteIdentical,
    #[error("pair {pair} does not match the registered orientation")]
    PairNotCanonical { pair: AddressPair },
    #[error("pair {pair} already registered")]
    PairAlreadyRegistered { pair: AddressPair },
    #[error("pair {pair} not registered")]
    PairNotRegistered { pair: AddressPair },
    #[error("pair index {index} out of range")]
    PairIndexOutOfRange { index: PairIndex },

    // -- authorization ------------------------------------------------------
    /// The argument completes the sentence, e.g. `"activate vote target"`.
    #[error("only system can {0}")]
    OnlySystem(&'static str),
    #[error("caller is not an active ORACLE signer")]
    NotActiveOracleSigner,

    // -- vote submission ----------------------------------------------------
    #[error("vote tuple count exceeds registered pair count")]
    VoteTupleCountExceedsPairCount,
    #[error("duplicate pair in vote submission")]
    DuplicatePairInVote,
    #[error("pair is not a vote target")]
    PairNotVoteTarget,
    #[error("validator already voted this period")]
    AlreadyVotedThisPeriod,

    // -- VWAP / TWAP --------------------------------------------------------
    #[error("no VWAP data in the requested time range")]
    NoVwapData,
    #[error("no TWAP data in the requested time range")]
    NoTwapData,
    #[error("missing TWAP data")]
    MissingTwapData,
    /// The argument names the accumulator that overflowed.
    #[error("VWAP overflow: {0}")]
    VwapOverflow(&'static str),
    #[error("TWAP overflow")]
    TwapOverflow,
    #[error("cross-currency conversion overflow")]
    CrossRateOverflow,
    #[error("tally arithmetic overflow: {0}")]
    TallyArithmeticOverflow(&'static str),
    #[error("rudis rate for currency {iso_code} is stale")]
    StaleCoenRate { iso_code: u16 },
    #[error("lookback_seconds must be > 0 and <= lookback_duration")]
    InvalidLookbackSeconds,
    #[error("start_time must be less than end_time")]
    InvalidVwapRange,
    #[error("worldwide day VWAP snapshot not found")]
    WorldwideDayVwapSnapshotNotFound,
    #[error("no finalized VWAP for that UTC day")]
    NoFinalizedUtcDayVwap,

    // -- reference currencies -----------------------------------------------
    #[error("iso_code {iso_code} is not a registered reference currency")]
    NotReferenceCurrency { iso_code: u16 },
    #[error("no policy rate for iso_code {iso_code}")]
    NoPolicyRate { iso_code: u16 },

    // -- slash window -------------------------------------------------------
    #[error("Oracle slash-window validator set size {actual} exceeds cap {cap}")]
    SlashWindowValidatorSetExceedsCap { actual: usize, cap: usize },

    // -- genesis config -----------------------------------------------------
    #[error("vote_period must be > 0")]
    VotePeriodZero,
    #[error("slash_window must be > 0")]
    SlashWindowZero,
    #[error("lookback_duration exceeds snapshot retention window")]
    LookbackExceedsRetention,
    #[error("reference iso_code must be non-zero")]
    ReferenceIsoCodeZero,
    #[error("duplicate reference iso_code: {iso_code}")]
    DuplicateReferenceIsoCode { iso_code: u16 },
    #[error("reference currencies must be sorted in ascending ISO order")]
    ReferenceCurrenciesNotSorted,
    #[error("reference currency count exceeds 6")]
    ReferenceCurrencyCountExceedsMax,
    #[error("reference currencies must include USD 840")]
    MissingUsdReferenceCurrency,
    #[error("policy iso_code must be non-zero")]
    PolicyIsoCodeZero,
    #[error("duplicate policy iso_code: {iso_code}")]
    DuplicatePolicyIsoCode { iso_code: u16 },
    #[error("policy rates must be sorted in ascending ISO order")]
    PolicyRatesNotSorted,
    #[error("policy rate must be non-zero for iso_code {iso_code}")]
    PolicyRateZero { iso_code: u16 },

    // -- genesis aggregate votes --------------------------------------------
    #[error("aggregate vote validator must be non-zero")]
    AggregateVoteValidatorZero,
    #[error("duplicate aggregate vote validator")]
    DuplicateAggregateVoteValidator,
    #[error("aggregate vote already exists for validator")]
    AggregateVoteAlreadyExists,
    #[error("aggregate vote tuple count exceeds registered pair count")]
    AggregateVoteTupleCountExceedsPairCount,
    #[error("aggregate vote pair is not registered")]
    AggregateVotePairNotRegistered,
    #[error("duplicate pair in aggregate vote")]
    DuplicatePairInAggregateVote,
    #[error("aggregate vote pair is not a vote target")]
    AggregateVotePairNotVoteTarget,
    #[error("missing aggregate vote validator at voter index {voter_index}")]
    MissingAggregateVoteValidator { voter_index: u32 },
    #[error("voter list contains validator without aggregate vote")]
    VoterListEntryWithoutVote,
    #[error("missing pair metadata for pair_id {pair_id}")]
    MissingPairMetadata { pair_id: u32 },

    // -- storage invariants -------------------------------------------------
    #[error("Oracle snapshot write index overflow")]
    SnapshotWriteIndexOverflow,
    #[error("Oracle S-curve write index overflow")]
    ScurveWriteIndexOverflow,
    #[error("No rate for pair {pair}")]
    NoRateForPair { pair: AddressPair },
}

impl From<OracleError> for PrecompileError {
    fn from(err: OracleError) -> Self {
        use OracleError::*;
        match err {
            // A monotonic counter that cannot advance means the stored oracle
            // state is no longer self-consistent; a revert would let the caller
            // keep reading it.
            SnapshotWriteIndexOverflow | ScurveWriteIndexOverflow => {
                PrecompileError::BodyReadCorruption(err.to_string())
            }

            PairBaseQuoteIdentical
            | PairNotCanonical { .. }
            | PairAlreadyRegistered { .. }
            | PairNotRegistered { .. }
            | PairIndexOutOfRange { .. }
            | NoRateForPair { .. }
            | OnlySystem(_)
            | NotActiveOracleSigner
            | VoteTupleCountExceedsPairCount
            | DuplicatePairInVote
            | PairNotVoteTarget
            | AlreadyVotedThisPeriod
            | NoVwapData
            | NoTwapData
            | MissingTwapData
            | VwapOverflow(_)
            | TwapOverflow
            | CrossRateOverflow
            | TallyArithmeticOverflow(_)
            | StaleCoenRate { .. }
            | InvalidLookbackSeconds
            | InvalidVwapRange
            | WorldwideDayVwapSnapshotNotFound
            | NoFinalizedUtcDayVwap
            | NotReferenceCurrency { .. }
            | NoPolicyRate { .. }
            | SlashWindowValidatorSetExceedsCap { .. }
            | VotePeriodZero
            | SlashWindowZero
            | LookbackExceedsRetention
            | ReferenceIsoCodeZero
            | DuplicateReferenceIsoCode { .. }
            | ReferenceCurrenciesNotSorted
            | ReferenceCurrencyCountExceedsMax
            | MissingUsdReferenceCurrency
            | PolicyIsoCodeZero
            | DuplicatePolicyIsoCode { .. }
            | PolicyRatesNotSorted
            | PolicyRateZero { .. }
            | AggregateVoteValidatorZero
            | DuplicateAggregateVoteValidator
            | AggregateVoteAlreadyExists
            | AggregateVoteTupleCountExceedsPairCount
            | AggregateVotePairNotRegistered
            | DuplicatePairInAggregateVote
            | AggregateVotePairNotVoteTarget
            | MissingAggregateVoteValidator { .. }
            | VoterListEntryWithoutVote
            | MissingPairMetadata { .. } => PrecompileError::Revert(err.to_string()),
        }
    }
}

/// Every OCOMP-related Oracle failure: the fixed projection profile, its
/// state-version stream, and the raw-storage opening plan/evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum OracleOcompError {
    // -- projection profile -------------------------------------------------
    #[error("Oracle OCOMP day-type pair is not registered")]
    DayTypePairNotRegistered,
    #[error("Oracle OCOMP profile is ready with zero state version")]
    ProfileReadyWithZeroVersion,
    #[error("Oracle OCOMP profile contains partial pre-fork state")]
    PartialPreForkState,
    /// Read-path sighting of the same broken invariant as
    /// [`Self::ProfileReadyWithZeroVersion`]; kept apart because a read is
    /// recoverable state corruption, not a failed fork activation.
    #[error("Oracle OCOMP profile is ready with zero state version")]
    StateVersionZero,
    #[error("Oracle OCOMP state version overflow")]
    StateVersionOverflow,
    #[error("Oracle S-curve oldest index exceeds write count")]
    ScurveOldestExceedsWriteCount,

    // -- opening slot plan --------------------------------------------------
    #[error("reference ISO list does not contain mandatory 840")]
    MissingMandatoryUsdReference,
    #[error("reference ISO list is not strictly ascending")]
    NonCanonicalReferenceIsos,
    #[error("reference ISO count {actual} exceeds cap {cap}")]
    ReferenceIsoCountExceedsCap { actual: usize, cap: usize },
    #[error("on-chain reference currency count {actual} exceeds cap {cap}")]
    ReferenceCurrencyCountExceedsCap { actual: u32, cap: u32 },
    #[error("pair index count {actual} does not match {expected} reference ISOs")]
    PairIndexCountMismatch { actual: usize, expected: usize },
    #[error("S-curve oldest index {oldest} exceeds count {count}")]
    ScurveOldestExceedsCount { oldest: u32, count: u32 },
    #[error("active S-curve count {actual} exceeds cap {cap}")]
    ActiveScurveCountExceedsCap { actual: u32, cap: u32 },

    // -- opening evaluation -------------------------------------------------
    #[error("duplicate Oracle opening slot {0}")]
    DuplicateSlot(B256),
    #[error("missing Oracle opening slot {0}")]
    MissingSlot(B256),
    #[error("Oracle opening slots do not match the canonical plan")]
    NonCanonicalSlotSequence,
    #[error("Oracle opening {0} does not fit its runtime type")]
    IntegerOverflow(&'static str),
    #[error("invalid Oracle WorldwideDay exists flag {0}")]
    InvalidWorldwideDayExists(U256),
    #[error("Oracle ISO {iso} names an unregistered pair")]
    PairNotRegistered { iso: u16 },
    #[error("Oracle ISO {iso} is not an on-chain reference currency")]
    IsoNotAReferenceCurrency { iso: u16 },
}

impl From<OracleOcompError> for PrecompileError {
    fn from(err: OracleOcompError) -> Self {
        use OracleOcompError::*;
        match err {
            // Fork activation reached a state the profile cannot be built from.
            // Continuing would pin a wrong projection for every later block.
            DayTypePairNotRegistered | ProfileReadyWithZeroVersion | PartialPreForkState => {
                PrecompileError::Fatal(err.to_string())
            }

            // Stored OCOMP state or an opening does not match what the protocol
            // requires. The opening variants are produced for the off-chain
            // `outbe-ocomp` worker and do not reach the EVM boundary in
            // practice, but they classify the same way: the body being read is
            // not the body the plan describes.
            StateVersionZero
            | StateVersionOverflow
            | ScurveOldestExceedsWriteCount
            | MissingMandatoryUsdReference
            | NonCanonicalReferenceIsos
            | ReferenceIsoCountExceedsCap { .. }
            | ReferenceCurrencyCountExceedsCap { .. }
            | PairIndexCountMismatch { .. }
            | ScurveOldestExceedsCount { .. }
            | ActiveScurveCountExceedsCap { .. }
            | DuplicateSlot(_)
            | MissingSlot(_)
            | NonCanonicalSlotSequence
            | IntegerOverflow(_)
            | InvalidWorldwideDayExists(_)
            | PairNotRegistered { .. }
            | IsoNotAReferenceCurrency { .. } => {
                PrecompileError::BodyReadCorruption(err.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_errors_revert_except_counter_overflows() {
        for err in [
            OracleError::SnapshotWriteIndexOverflow,
            OracleError::ScurveWriteIndexOverflow,
        ] {
            let message = err.to_string();
            assert!(
                matches!(PrecompileError::from(err), PrecompileError::BodyReadCorruption(m) if m == message)
            );
        }

        for err in [
            OracleError::PairNotRegistered {
                pair: AddressPair::new_coen_to(840),
            },
            OracleError::NoVwapData,
            OracleError::OnlySystem("activate vote target"),
            OracleError::NoPolicyRate { iso_code: 978 },
        ] {
            let message = err.to_string();
            assert!(
                matches!(PrecompileError::from(err), PrecompileError::Revert(m) if m == message)
            );
        }
    }

    #[test]
    fn ocomp_activation_breaches_are_fatal_and_the_rest_is_corruption() {
        for err in [
            OracleOcompError::DayTypePairNotRegistered,
            OracleOcompError::ProfileReadyWithZeroVersion,
            OracleOcompError::PartialPreForkState,
        ] {
            let message = err.to_string();
            assert!(
                matches!(PrecompileError::from(err), PrecompileError::Fatal(m) if m == message)
            );
        }

        for err in [
            OracleOcompError::StateVersionZero,
            OracleOcompError::StateVersionOverflow,
            OracleOcompError::ScurveOldestExceedsWriteCount,
            OracleOcompError::NonCanonicalSlotSequence,
            OracleOcompError::IsoNotAReferenceCurrency { iso: 826 },
        ] {
            let message = err.to_string();
            assert!(
                matches!(PrecompileError::from(err), PrecompileError::BodyReadCorruption(m) if m == message)
            );
        }
    }

    /// The messages are user-visible revert reasons; a reword is an ABI change.
    #[test]
    fn messages_match_the_strings_callers_see() {
        assert_eq!(
            OracleError::PairNotRegistered {
                pair: AddressPair::new_coen_to(840),
            }
            .to_string(),
            format!("pair {} not registered", AddressPair::new_coen_to(840))
        );
        assert_eq!(
            OracleError::VwapOverflow("rate * volume").to_string(),
            "VWAP overflow: rate * volume"
        );
        assert_eq!(
            OracleError::OnlySystem("set exchange rate directly").to_string(),
            "only system can set exchange rate directly"
        );
        assert_eq!(
            OracleError::NotReferenceCurrency { iso_code: 978 }.to_string(),
            "iso_code 978 is not a registered reference currency"
        );
        assert_eq!(
            OracleOcompError::ScurveOldestExceedsCount {
                oldest: 3,
                count: 2
            }
            .to_string(),
            "S-curve oldest index 3 exceeds count 2"
        );
    }
}
