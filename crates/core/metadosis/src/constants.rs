use outbe_chain_constants::{
    DEFAULT_METADOSIS_BOOTSTRAP_DURATION_SECONDS, DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS,
    DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS, DEFAULT_METADOSIS_OFFERING_PERIOD_SECONDS,
    DEFAULT_METADOSIS_WAITING_PERIOD_SECONDS,
};

/// Compatibility aliases for capacity proofs and canonical-default tests.
pub const FORMING_PERIOD_HOURS: u64 = DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS / SECONDS_PER_HOUR;

/// lookback delay: 502 hours (~21 days).
pub const LOOKBACK_DELAY_HOURS: u64 = DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS / SECONDS_PER_HOUR;

/// offering period: 50 hours.
pub const OFFERING_PERIOD_HOURS: u64 = DEFAULT_METADOSIS_OFFERING_PERIOD_SECONDS / SECONDS_PER_HOUR;

/// Waiting period before processing: 12 hours.
pub const WAITING_PERIOD_HOURS: u64 = DEFAULT_METADOSIS_WAITING_PERIOD_SECONDS / SECONDS_PER_HOUR;

/// Fresh-devnet production creates at most one WorldwideDay per UTC day.
pub const WWD_CREATION_CADENCE_HOURS: u64 = 24;

/// Production ProtocolCycle advances the outer WWD reducer on every aligned
/// UTC-hour boundary.
pub const WWD_ADVANCE_TICK_CADENCE_HOURS: u64 = 1;

/// Symbolic rate: 32% of tribute nominal -> gratis demand.
pub const SYMBOLIC_RATE: u64 = 32;

/// RED day reduction coefficient: divide by 8.
pub const RED_DAY_REDUCTION_COEF: u64 = 8;

/// Bootstrap duration (hours) for dev/testnet.
pub const BOOTSTRAP_DURATION_HOURS: u64 =
    DEFAULT_METADOSIS_BOOTSTRAP_DURATION_SECONDS / SECONDS_PER_HOUR;

/// Bootstrap lookback delay: 0 hours.
pub const BOOTSTRAP_LOOKBACK_DELAY_HOURS: u64 = 0;

/// Bootstrap offering period: 50 hours.
pub const BOOTSTRAP_OFFERING_PERIOD_HOURS: u64 = 50;

const NORMAL_PIPELINE_HOURS: u64 =
    FORMING_PERIOD_HOURS + LOOKBACK_DELAY_HOURS + OFFERING_PERIOD_HOURS + WAITING_PERIOD_HOURS;
const BOOTSTRAP_PIPELINE_HOURS: u64 = FORMING_PERIOD_HOURS
    + BOOTSTRAP_LOOKBACK_DELAY_HOURS
    + BOOTSTRAP_OFFERING_PERIOD_HOURS
    + WAITING_PERIOD_HOURS;
const NORMAL_PIPELINE_WWDS: usize =
    NORMAL_PIPELINE_HOURS.div_ceil(WWD_CREATION_CADENCE_HOURS) as usize;
const BOOTSTRAP_PIPELINE_WWDS: usize =
    BOOTSTRAP_PIPELINE_HOURS.div_ceil(WWD_CREATION_CADENCE_HOURS) as usize;

/// Maximum pre-admission population implied by the production cadence and
/// phase durations. The extra entry is the current day created on the first
/// post-halt midnight before the reducer drains the bounded pre-halt pipeline.
///
/// Normal windows dominate: ceil((50 + 502 + 50 + 12) / 24) + 1 = 27.
/// Hourly advancement drains a halt backlog faster than the one-per-day
/// creation cadence.
pub const MAX_PIPELINE_WWDS: usize = if NORMAL_PIPELINE_WWDS > BOOTSTRAP_PIPELINE_WWDS {
    NORMAL_PIPELINE_WWDS + 1
} else {
    BOOTSTRAP_PIPELINE_WWDS + 1
};

/// Maximum WWD records kept. This is the canonical historical retention bound,
/// not a concurrent OCOMP job admission limit.
pub const MAX_RECORDS_KEPT: usize = 365;

/// READY/OFFCHAIN_PENDING work can use the same population already bounded by
/// the canonical WWD record-retention policy. OCOMP does not impose a smaller
/// concurrent live-job cap.
pub const MAX_RETAINED_WWDS: usize = MAX_RECORDS_KEPT;

/// Exact bound for every scan of the active WorldwideDay aggregate.
pub const MAX_ACTIVE_WWDS: usize = MAX_PIPELINE_WWDS + MAX_RETAINED_WWDS;

/// Under continuing hourly ticks, an already-active candidate can have
/// at most this many older protocol-order admissions ahead of it.
pub const MAX_ADMISSION_WAIT_TICKS: usize = MAX_PIPELINE_WWDS;
pub const MAX_ADMISSION_WAIT_HOURS: u64 =
    MAX_ADMISSION_WAIT_TICKS as u64 * WWD_ADVANCE_TICK_CADENCE_HOURS;

/// Seconds per hour.
pub const SECONDS_PER_HOUR: u64 = 3600;
