//! Storage schema for the Intex runtime module: the canonical per-series
//! identity + lifecycle ledger. One record per `seriesId`.

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::INTEX_ADDRESS;
use outbe_primitives::stablecoin::iso_4217_alpha;
use outbe_primitives::storage::types::{Storable, StorableType, StorageKey};
use outbe_primitives::time::WorldwideDay;
use std::fmt;

use crate::errors::IntexError;

/// Series lifecycle state. `Issued -> Qualified -> Called -> Expired`, where
/// `Expired` means the call window closed, not that anything burned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntexState {
    Issued = 0,
    Qualified = 1,
    Called = 2,
    Expired = 3,
}

impl IntexState {
    pub fn from_u8(value: u8) -> Result<Self, IntexError> {
        match value {
            0 => Ok(Self::Issued),
            1 => Ok(Self::Qualified),
            2 => Ok(Self::Called),
            3 => Ok(Self::Expired),
            other => Err(IntexError::InvalidStateValue(other)),
        }
    }
}

/// Forced-call trigger parameters for a series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IntexCallTrigger {
    pub call_window: u32,
    pub call_threshold: u32,
    /// Seconds between `called_at` and the settlement deadline.
    pub call_notice_period: u32,
}

/// Series identifier: the 14 ASCII bytes of `20260212-TRY-U`. A currency with no
/// alpha code in ISO 4217 falls back to its zero-padded numeric code (`949`).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeriesId([u8; SERIES_ID_LEN]);

pub const SERIES_ID_LEN: usize = 14;

const DAY_DIGITS: usize = 8;
const ISSUANCE_AT: usize = 9;
const REFERENCE_AT: usize = 13;

impl SeriesId {
    /// Rejects a day outside eight digits and code bytes outside `A-Z` / `0-9`.
    pub fn pack(
        worldwide_day: WorldwideDay,
        issuance: [u8; 3],
        reference: u8,
    ) -> Result<Self, IntexError> {
        let mut day = worldwide_day.value();
        if day == 0 || day > 99_999_999 {
            return Err(IntexError::InvalidSeriesId);
        }
        if !issuance.iter().all(|byte| is_code_byte(*byte)) || !is_code_byte(reference) {
            return Err(IntexError::InvalidSeriesId);
        }
        let mut bytes = [b'-'; SERIES_ID_LEN];
        for slot in bytes[..DAY_DIGITS].iter_mut().rev() {
            *slot = b'0' + (day % 10) as u8;
            day /= 10;
        }
        bytes[ISSUANCE_AT..ISSUANCE_AT + 3].copy_from_slice(&issuance);
        bytes[REFERENCE_AT] = reference;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; SERIES_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SERIES_ID_LEN] {
        &self.0
    }

    pub fn worldwide_day(&self) -> WorldwideDay {
        WorldwideDay::new(self.0[..DAY_DIGITS].iter().fold(0u32, |acc, byte| {
            acc * 10 + u32::from(byte.wrapping_sub(b'0'))
        }))
    }

    /// `949 -> b"949"`, `32 -> b"032"`. ISO 4217 numbers are three digits, and a
    /// wider one has no spelling here: folding it would give two currencies one id.
    pub fn numeric_code(iso: u16) -> Result<[u8; 3], IntexError> {
        if iso > 999 {
            return Err(IntexError::InvalidSeriesId);
        }
        Ok([
            b'0' + (iso / 100) as u8,
            b'0' + ((iso / 10) % 10) as u8,
            b'0' + (iso % 10) as u8,
        ])
    }

    /// How a currency is spelled inside an id: its alpha-3 code, or its numeric
    /// code when ISO assigns none.
    pub fn currency_code(iso: u16) -> Result<[u8; 3], IntexError> {
        // todo validate iso and refactor this code
        match iso_4217_alpha(iso) {
            Some(alpha) => Ok(alpha),
            None => Self::numeric_code(iso),
        }
    }

    /// The id of the series a day issues for one `(issuance, reference)` pair.
    pub fn for_pair(
        worldwide_day: WorldwideDay,
        issuance: u16,
        reference: u16,
    ) -> Result<Self, IntexError> {
        Self::pack(
            worldwide_day,
            Self::currency_code(issuance)?,
            Self::currency_code(reference)?[0],
        )
    }
}

const fn is_code_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

impl fmt::Display for SeriesId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

impl StorableType for SeriesId {
    const SLOTS: usize = 1;
}

/// Left-aligned in the word, matching the Solidity `bytes14` layout.
impl Storable for SeriesId {
    fn from_word(word: U256) -> Self {
        let mut bytes = [0u8; SERIES_ID_LEN];
        bytes.copy_from_slice(&word.to_be_bytes::<32>()[..SERIES_ID_LEN]);
        Self(bytes)
    }

    fn to_word(&self) -> U256 {
        let mut word = [0u8; 32];
        word[..SERIES_ID_LEN].copy_from_slice(&self.0);
        U256::from_be_bytes(word)
    }
}

impl StorageKey for SeriesId {
    fn key_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<SeriesId> for FixedBytes<SERIES_ID_LEN> {
    fn from(id: SeriesId) -> Self {
        Self(id.0)
    }
}

impl From<FixedBytes<SERIES_ID_LEN>> for SeriesId {
    fn from(value: FixedBytes<SERIES_ID_LEN>) -> Self {
        Self(value.0)
    }
}

/// Identity parameters captured once at series creation.
///
/// `promis_load_minor` is `u128` to mirror the Origin `uint128` ABI; storage
/// widens it to `U256` (the storage DSL has no `u128` codec), always lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSeriesParams {
    pub series_id: SeriesId,
    pub worldwide_day: WorldwideDay,
    pub issued_intex_count: u32,
    /// PROMIS-units per Intex unit (1e6); bounded by source `uint128`.
    pub promis_load_minor: u128,
    /// Entry price (per-unit, reference ISO stable-units, 1e6). Primary
    /// anchor; cost/floor/call derive from it.
    pub entry_price_minor: U256,
    /// Price floor in reference ISO stable-units (1e6).
    pub floor_price_minor: U256,
    /// Call price level that arms the forced call, in reference ISO stable-units (1e6).
    pub call_price_minor: U256,
    pub call_trigger: IntexCallTrigger,
    /// Creation timestamp (UNIX seconds); non-zero, doubles as existence sentinel.
    pub issued_at: u32,
    pub issuance_currency: u16,
    pub reference_currency: u16,
}

/// Per-series identity + lifecycle record. Keyed by `series_id`.
/// `issued_at == 0` means "no series".
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = issued_at)]
pub struct SeriesRecord {
    #[key]
    pub series_id: SeriesId,

    #[attribute(order = 0)]
    pub issuance_currency: u16,

    #[attribute(order = 1)]
    pub reference_currency: u16,

    #[attribute(order = 2)]
    pub issued_intex_count: u32,

    #[attribute(order = 3)]
    pub promis_load_minor: U256,

    #[attribute(order = 4)]
    pub entry_price_minor: U256,

    #[attribute(order = 5)]
    pub floor_price_minor: U256,

    #[attribute(order = 6)]
    pub call_price_minor: U256,

    // call_trigger group - stored flat (the storage DSL has no nested-struct codec),
    // exposed nested via `call_trigger()`.
    #[attribute(order = 7)]
    pub call_window: u32,

    #[attribute(order = 8)]
    pub call_threshold: u32,

    #[attribute(order = 9)]
    pub call_notice_period: u32,

    #[attribute(order = 10)]
    pub issued_at: u32,

    #[attribute(order = 11, default = 0)]
    pub called_at: u32,

    /// Lifecycle state as `u8`; decode via [`IntexState::from_u8`].
    #[attribute(order = 12)]
    pub state: u8,

    /// Worldwide day whose tributes fed this series; also the id's leading digits.
    #[attribute(order = 13, default = WorldwideDay::new(0))]
    pub worldwide_day: WorldwideDay,
}

impl SeriesRecord {
    pub fn lifecycle_state(&self) -> Result<IntexState, IntexError> {
        IntexState::from_u8(self.state)
    }

    pub fn call_trigger(&self) -> IntexCallTrigger {
        IntexCallTrigger {
            call_window: self.call_window,
            call_threshold: self.call_threshold,
            call_notice_period: self.call_notice_period,
        }
    }
}

/// Paginated creator-reward distribution progress for a worldwide day. Exists
/// while a distribution is in flight; `active != 0` is the existence sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = active)]
pub struct DistProgress {
    #[key]
    pub worldwide_day: WorldwideDay,

    /// Total native COEN received for that day's distribution.
    #[attribute(order = 0)]
    pub amount: U256,

    /// sum of contributor nominals (the proportionality denominator).
    #[attribute(order = 1)]
    pub total_nominal: U256,

    /// Native COEN already paid out across chunks so far.
    #[attribute(order = 2)]
    pub paid_so_far: U256,

    /// Index of the next contributor to pay.
    #[attribute(order = 3)]
    pub cursor: u32,

    /// Existence sentinel: 1 while in flight.
    #[attribute(order = 4)]
    pub active: u8,
}

/// Open payout round over a certified contributor root.
///
/// `amount` is frozen when the round opens (the proceeds pot at that moment) so
/// every share derives from the same denominator regardless of when a batch
/// lands; `active != 0` is the existence sentinel. The record outlives the
/// payout: once `paid_leaf_count` reaches the certified contributor count the
/// caller burns what floor rounding left and the paid bitmap refuses further
/// batches, but the counters stay readable as the day's final accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = active)]
pub struct CertifiedPayoutRound {
    #[key]
    pub wwd: u32,

    /// Native COEN this round distributes, frozen at open.
    #[attribute(order = 0)]
    pub amount: U256,

    /// sum of the shares paid so far; feeds the round cap and the close remainder.
    #[attribute(order = 1)]
    pub paid_so_far: U256,

    /// Number of leaves paid so far; the completion gate for closing the round.
    #[attribute(order = 2)]
    pub paid_leaf_count: u32,

    /// Existence sentinel: 1 while the round is open.
    #[attribute(order = 3)]
    pub active: u8,
}

/// Constant-size certified contributor authority for one Intex series.
///
/// Contributor bodies remain in authenticated result chunks; activation stores
/// only the proof root and exact aggregate scalars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedContributorGenerationProjection {
    pub worldwide_day: u32,
    pub series_version: u64,
    pub contributor_root: B256,
    pub contributor_count: u32,
    pub eligible_nominal_total: U256,
}

impl CertifiedContributorGenerationProjection {
    pub(crate) fn metadata_word(&self) -> U256 {
        U256::from(self.series_version) | (U256::from(self.contributor_count) << 64)
    }
}

/// EVM storage layout for the Intex module.
#[storage_schema]
#[contract(addr = INTEX_ADDRESS)]
pub struct IntexContract {
    #[attribute(order = 0)]
    pub series: outbe_primitives::storage::dsl::Map<SeriesId, SeriesRecord>,

    #[attribute(order = 1)]
    pub total_series: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 2)]
    pub series_id_at_index: outbe_primitives::storage::dsl::Map<u64, U256>,

    // --- Creator-reward: per-day contributors (owner -> nominal share) ---
    // Orders 3-23 are keyed by worldwide day, not by series id.
    /// worldwide_day -> number of contributors.
    #[attribute(order = 3)]
    pub contributor_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// keccak256(worldwide_day_be32 ++ index_be32) -> contributor owner.
    #[attribute(order = 4)]
    pub contributor_owner_at: outbe_primitives::storage::dsl::Map<B256, Address>,

    /// keccak256(worldwide_day_be32 ++ index_be32) -> contributor nominal share.
    #[attribute(order = 5)]
    pub contributor_nominal_at: outbe_primitives::storage::dsl::Map<B256, U256>,

    /// worldwide_day -> sum nominal across all contributors.
    #[attribute(order = 6)]
    pub contributor_total: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    // --- Creator-reward: paginated distribution progress + active set ---
    /// worldwide_day -> in-flight distribution progress.
    #[attribute(order = 7)]
    pub dist_progress: outbe_primitives::storage::dsl::Map<WorldwideDay, DistProgress>,

    /// Number of in-flight distributions (dense active set for the begin-block drain).
    #[attribute(order = 8)]
    pub active_dist_count: outbe_primitives::storage::dsl::Value<u32>,

    /// dense index -> worldwide_day.
    #[attribute(order = 9)]
    pub active_dist_at: outbe_primitives::storage::dsl::Map<u32, u32>,

    /// worldwide_day -> (active index + 1); 0 = not active.
    #[attribute(order = 10)]
    pub active_dist_slot: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Creator-reward: multi-chain proceeds fan-in aggregation ---
    /// worldwide_day -> proceeds accumulated but not yet handed to a distribution round.
    #[attribute(order = 11)]
    pub proceeds_pot: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// worldwide_day -> deadline after which the pot distributes without the missing chains.
    #[attribute(order = 12)]
    pub proceeds_deadline: outbe_primitives::storage::dsl::Map<WorldwideDay, u64>,

    /// worldwide_day -> number of winning chains expected to route proceeds.
    #[attribute(order = 13)]
    pub proceeds_expected_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// worldwide_day -> number of expected chains whose proceeds have arrived.
    #[attribute(order = 14)]
    pub proceeds_arrived_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// keccak256(worldwide_day_be32 ++ chain_be32) -> 1 if a winning (expected) chain.
    #[attribute(order = 15)]
    pub proceeds_expected: outbe_primitives::storage::dsl::Map<B256, u8>,

    /// keccak256(worldwide_day_be32 ++ chain_be32) -> 1 once that chain's proceeds arrived.
    #[attribute(order = 16)]
    pub proceeds_arrived: outbe_primitives::storage::dsl::Map<B256, u8>,

    /// worldwide_day -> 1 if the in-flight distribution round should finalize (clear the
    /// contributor map + aggregation state) on completion; 0 = retain for a late top-up.
    #[attribute(order = 17)]
    pub proceeds_finalize_on_done: outbe_primitives::storage::dsl::Map<WorldwideDay, u8>,

    // Awaiting-proceeds set (dense) for the begin-block deadline sweep.
    #[attribute(order = 18)]
    pub awaiting_proceeds_count: outbe_primitives::storage::dsl::Value<u32>,
    /// dense index -> worldwide_day.
    #[attribute(order = 19)]
    pub awaiting_proceeds_at: outbe_primitives::storage::dsl::Map<u32, u32>,
    /// worldwide_day -> (awaiting index + 1); 0 = not awaiting.
    #[attribute(order = 20)]
    pub awaiting_proceeds_slot: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// Certified contributor proof root for one worldwide day.
    #[attribute(order = 21)]
    pub ocomp_contributor_root: outbe_primitives::storage::dsl::Map<WorldwideDay, B256>,

    /// Packed active selector: series version (low u64), contributor count
    /// (next u32), with all remaining bits reserved as zero.
    #[attribute(order = 22)]
    pub ocomp_contributor_metadata: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// Exact eligible nominal total committed by the certified root.
    #[attribute(order = 23)]
    pub ocomp_eligible_nominal_total: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// worldwide_day -> number of series created for that day.
    #[attribute(order = 24)]
    pub day_series_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// wwd -> open certified payout round.
    #[attribute(order = 25)]
    pub ocomp_payout_round: outbe_primitives::storage::dsl::Map<u32, CertifiedPayoutRound>,

    /// keccak256(wwd_be32 ++ word_index_be32) -> 256 paid flags, one per leaf.
    #[attribute(order = 26)]
    pub ocomp_paid_leaves: outbe_primitives::storage::dsl::Map<B256, U256>,

    // Cumulative: a series forfeits `issued_intex_count - settled - parked` at its
    // deadline. Not on `SeriesRecord` because a record write rewrites every field.
    /// series_id -> units settled so far.
    #[attribute(order = 27)]
    pub settled_units: outbe_primitives::storage::dsl::Map<SeriesId, u32>,

    /// series_id -> units parked into Gem positions.
    #[attribute(order = 28)]
    pub parked_units: outbe_primitives::storage::dsl::Map<SeriesId, u32>,
}

impl IntexContract<'_> {
    /// Composite key for per-day contributor index lists:
    /// `keccak256(worldwide_day_be32 ++ index_be32)`.
    pub fn contributor_index_key(worldwide_day: WorldwideDay, index: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&worldwide_day.value().to_be_bytes());
        buf[4..8].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    /// Composite key for the paid-leaf bitmap:
    /// `keccak256(wwd_be32 ++ word_index_be32)`, one word per 256 leaves.
    pub fn paid_bitmap_key(wwd: u32, word_index: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&wwd.to_be_bytes());
        buf[4..8].copy_from_slice(&word_index.to_be_bytes());
        keccak256(buf)
    }

    /// Composite key for per-(day, chain) proceeds flags:
    /// `keccak256(worldwide_day_be32 ++ chain_be32)`.
    pub fn proceeds_chain_key(worldwide_day: WorldwideDay, chain_id: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&worldwide_day.value().to_be_bytes());
        buf[4..8].copy_from_slice(&chain_id.to_be_bytes());
        keccak256(buf)
    }

    /// Reads the active constant-size contributor proof authority.
    pub fn ocomp_certified_contributor_generation(
        &self,
        worldwide_day: WorldwideDay,
    ) -> outbe_primitives::error::Result<Option<CertifiedContributorGenerationProjection>> {
        let contributor_root = self.ocomp_contributor_root.read(&worldwide_day)?;
        let metadata = self.ocomp_contributor_metadata.read(&worldwide_day)?;
        let eligible_nominal_total = self.ocomp_eligible_nominal_total.read(&worldwide_day)?;

        if metadata.is_zero() {
            if !contributor_root.is_zero() || !eligible_nominal_total.is_zero() {
                return Err(outbe_primitives::error::PrecompileError::Fatal(
                    "absent Intex certified contributor generation has residual state".into(),
                ));
            }
            return Ok(None);
        }
        if !(metadata >> 96usize).is_zero() || contributor_root.is_zero() {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "installed Intex certified contributor generation is malformed".into(),
            ));
        }

        let series_version = (metadata & U256::from(u64::MAX)).to::<u64>();
        let contributor_count = ((metadata >> 64usize) & U256::from(u32::MAX)).to::<u32>();
        // Version 1 is the valid absent -> certified history and remains valid
        // if the independent auction creates the series later. Version 2 is
        // valid only when the series already existed before certification.
        let valid_series_version =
            series_version == 1 || (series_version == 2 && self.day_has_series(worldwide_day)?);
        if !valid_series_version || (contributor_count == 0) != eligible_nominal_total.is_zero() {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "installed Intex certified contributor metadata is malformed".into(),
            ));
        }

        Ok(Some(CertifiedContributorGenerationProjection {
            worldwide_day: worldwide_day.value(),
            series_version,
            contributor_root,
            contributor_count,
            eligible_nominal_total,
        }))
    }
}
