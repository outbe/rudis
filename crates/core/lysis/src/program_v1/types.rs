//! Typed storage-independent inputs, actions, observations and failures.

use std::fmt;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{TributeBodyV1, WwdEntityId};
use outbe_primitives::time::WorldwideDay;

/// One canonical Tribute body required by Lysis V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TributeInputV1 {
    pub tribute_id: WwdEntityId,
    pub owner: Address,
    pub worldwide_day: WorldwideDay,
    pub issuance_currency: u16,
    pub nominal_amount_minor: U256,
    pub reference_currency: u16,
    pub tribute_price_minor: U256,
    pub exclude_from_intex_issuance: bool,
}

impl From<&TributeBodyV1> for TributeInputV1 {
    fn from(body: &TributeBodyV1) -> Self {
        Self {
            tribute_id: body.tribute_id,
            owner: body.owner,
            worldwide_day: body.worldwide_day,
            issuance_currency: body.issuance_currency,
            nominal_amount_minor: body.nominal_amount_minor,
            reference_currency: body.reference_currency,
            tribute_price_minor: body.tribute_price_minor,
            exclude_from_intex_issuance: body.exclude_from_intex_issuance,
        }
    }
}

/// A logical snapshot observation, including a deterministic unavailable value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationValueV1<T> {
    Value(T),
    Unavailable,
}

impl<T: Copy> ObservationValueV1<T> {
    pub(crate) fn copied(&self) -> Option<T> {
        match self {
            Self::Value(value) => Some(*value),
            Self::Unavailable => None,
        }
    }
}

/// One Tribute plus the two Fidelity observations, conditional Oracle result
/// and reserved-target fact consumed at its semantic ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTributeV1 {
    pub tribute: TributeInputV1,
    pub first_league: ObservationValueV1<u16>,
    pub second_league: ObservationValueV1<u16>,
    /// Required only when `reference_currency != 840`.
    pub conditional_entry_price_minor: ObservationValueV1<U256>,
    pub nod_target_available: bool,
}

/// Complete logical input for the pure semantic entrypoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramInputV1 {
    pub worldwide_day: WorldwideDay,
    pub logical_evaluation_time: u64,
    pub gratis_allocation: U256,
    pub mandatory_entry_price_840: ObservationValueV1<U256>,
    pub tributes: Vec<ObservedTributeV1>,
}

/// Which repeated Fidelity observation was made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidelityPhaseV1 {
    First,
    Second,
}

/// Ordered semantic observation transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticObservationV1 {
    Fidelity {
        ordinal: usize,
        phase: FidelityPhaseV1,
        owner: Address,
        league: u16,
    },
    Oracle {
        /// `None` is the mandatory ISO 840 observation before the output loop.
        ordinal: Option<usize>,
        currency: u16,
        entry_price_minor: U256,
    },
}

/// One storage-free Nod creation action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodActionV1 {
    pub source_tribute_id: WwdEntityId,
    pub nod_id: WwdEntityId,
    pub owner: Address,
    pub worldwide_day: WorldwideDay,
    pub league_id: u16,
    pub floor_price_minor: U256,
    pub gratis_load_minor: U256,
    pub entry_price_minor: U256,
    pub cost_amount_minor: U256,
    pub issuance_currency: u16,
    pub reference_currency: u16,
    pub bucket_key: B256,
    pub issued_at: u64,
}

/// Canonically owner-sorted contributor action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributorActionV1 {
    pub owner: Address,
    pub nominal_amount_minor: U256,
}

/// One league's fixed-point Gratis fraction, sorted by ascending league.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeagueFractionV1 {
    pub league: u16,
    pub fraction: U256,
}

/// Successful storage-independent Lysis result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramResultV1 {
    pub tribute_ids: Vec<WwdEntityId>,
    pub total_nominal: U256,
    pub gratis_allocation: U256,
    pub remaining_gratis: U256,
    pub league_fractions: Vec<LeagueFractionV1>,
    pub nod_actions: Vec<NodActionV1>,
    pub contributors: Vec<ContributorActionV1>,
    pub observations: Vec<SemanticObservationV1>,
}

/// Deterministic semantic failures, including the lowest raw-ID ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramErrorV1 {
    EmptyInput,
    NonCanonicalInput {
        ordinal: usize,
    },
    DuplicateInput {
        ordinal: usize,
    },
    WorldwideDayMismatch {
        ordinal: usize,
    },
    InvalidTributeIdentity {
        ordinal: usize,
    },
    TotalNominalOverflow {
        ordinal: usize,
    },
    ZeroTotalNominal,
    FidelityUnavailable {
        ordinal: usize,
        phase: FidelityPhaseV1,
    },
    FidelityMismatch {
        ordinal: usize,
        first: u16,
        second: u16,
    },
    MandatoryOracleUnavailable,
    ConditionalOracleUnavailable {
        ordinal: usize,
        currency: u16,
    },
    ZeroEntryPrice {
        ordinal: Option<usize>,
        currency: u16,
    },
    Arithmetic {
        message: String,
    },
    ZeroGratisLoad {
        ordinal: usize,
    },
    ZeroCost {
        ordinal: usize,
        /// The operands, so a floor-to-zero says which side was too small.
        entry_price_minor: U256,
        gratis_load_minor: U256,
    },
    GratisLoadExceedsRemaining {
        ordinal: usize,
    },
    InvalidNodTarget {
        ordinal: usize,
    },
    ContributorOverflow {
        ordinal: usize,
    },
    OutputCountMismatch,
}

impl fmt::Display for ProgramErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("Lysis V1 input is empty"),
            Self::NonCanonicalInput { ordinal } => {
                write!(
                    formatter,
                    "Lysis V1 input is not raw-ID ordered at {ordinal}"
                )
            }
            Self::DuplicateInput { ordinal } => {
                write!(formatter, "Lysis V1 duplicate input at {ordinal}")
            }
            Self::WorldwideDayMismatch { ordinal } => {
                write!(formatter, "Lysis V1 WorldwideDay mismatch at {ordinal}")
            }
            Self::InvalidTributeIdentity { ordinal } => {
                write!(formatter, "Lysis V1 invalid Tribute identity at {ordinal}")
            }
            Self::TotalNominalOverflow { ordinal } => {
                write!(formatter, "Lysis V1 total nominal overflow at {ordinal}")
            }
            Self::ZeroTotalNominal => formatter.write_str("Lysis V1 total nominal is zero"),
            Self::FidelityUnavailable { ordinal, phase } => {
                write!(
                    formatter,
                    "Lysis V1 Fidelity {phase:?} unavailable at {ordinal}"
                )
            }
            Self::FidelityMismatch {
                ordinal,
                first,
                second,
            } => write!(
                formatter,
                "Lysis V1 Fidelity mismatch at {ordinal}: {first} != {second}"
            ),
            Self::MandatoryOracleUnavailable => {
                formatter.write_str("Lysis V1 mandatory ISO 840 Oracle unavailable")
            }
            Self::ConditionalOracleUnavailable { ordinal, currency } => write!(
                formatter,
                "Lysis V1 Oracle {currency} unavailable at {ordinal}"
            ),
            Self::ZeroEntryPrice { ordinal, currency } => write!(
                formatter,
                "Lysis V1 Oracle {currency} returned zero at {ordinal:?}"
            ),
            Self::Arithmetic { message } => write!(formatter, "Lysis V1 arithmetic: {message}"),
            Self::ZeroGratisLoad { ordinal } => {
                write!(formatter, "Lysis V1 zero Gratis load at {ordinal}")
            }
            Self::ZeroCost {
                ordinal,
                entry_price_minor,
                gratis_load_minor,
            } => write!(
                formatter,
                "Lysis V1 zero monetary cost at {ordinal}: entry price {entry_price_minor}, Gratis load {gratis_load_minor}"
            ),
            Self::GratisLoadExceedsRemaining { ordinal } => write!(
                formatter,
                "Lysis V1 Gratis load exceeds remaining at {ordinal}"
            ),
            Self::InvalidNodTarget { ordinal } => {
                write!(formatter, "Lysis V1 invalid Nod target at {ordinal}")
            }
            Self::ContributorOverflow { ordinal } => {
                write!(formatter, "Lysis V1 contributor overflow at {ordinal}")
            }
            Self::OutputCountMismatch => formatter.write_str("Lysis V1 output count mismatch"),
        }
    }
}

impl std::error::Error for ProgramErrorV1 {}
