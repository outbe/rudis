use alloy_primitives::{Address, U256};
use outbe_macros::contract;
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::addresses::ORACLE_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot, StorageVec};
use outbe_primitives::time::WorldwideDay;
pub use outbe_primitives::units::SCALE_1E18;

/// Which pair a parallel-column group is talking about: the registry's 1-based
/// enumeration index in `pair_by_index`, and the 0-based entry index in the
/// per-vote, per-snapshot and per-day columns, where every pair appears once.
///
/// An alias, not a newtype - it labels which of this schema's several `u32`s
/// means "which pair" without pretending to stop a `utc_day` being passed as
/// one. The S-curve columns are deliberately *not* indexed by this: a pair can
/// hold several S-curve entries, so their key identifies an entry, not a pair.
pub type PairIndex = u32;

/// EVM storage layout for the Oracle contract.
///
/// Manages exchange rates, validator voting, price snapshots, and VWAP
/// calculation for whitelisted trading pairs.
///
/// Prices and volumes remain `U256` in each pair's registered scale. COEN/ISO
/// uses six decimals; generic non-ISO pairs retain their existing contract.
///
/// A pair is an [`AddressPair`]: its two asset addresses in the orientation they
/// were quoted. As a *key* it sorts (so both directions of a market share one
/// slot); as a *value* it spans two consecutive words, base then quote.
/// `pair_to_index` maps a pair onto a dense 1-based [`PairIndex`], which exists
/// only so the registry can be enumerated, and `pair_by_index` walks back.
///
/// Slot number == field declaration index; every field below occupies exactly
/// one, including `Mapping<_, AddressPair>` - its second word lives at
/// `keccak256(key || slot) + 1`, inside the key's own hashed namespace rather
/// than in the next declaration slot. `openings.rs` and
/// `scripts/seed_genesis.py` hardcode these numbers - see the slot-parity tests
/// in `tests/state.rs` before reordering anything.
#[contract(addr = ORACLE_ADDRESS)]
pub struct OracleContract {
    // === Config (slots 0-7) ===
    // slot 0: vote period in blocks (default: 2)
    pub config_vote_period: Slot<u64>,
    // slot 1: reward band (1e18 scaled, default: 0.02 * 1e18 = 2e16)
    pub config_reward_band: Slot<U256>,
    // slot 2: slash window in blocks (default: 96)
    pub config_slash_window: Slot<u64>,
    // slot 3: min valid per window (1e18 scaled, default: 0.05 * 1e18 = 5e16)
    pub config_min_valid_per_window: Slot<U256>,
    // slot 4: slash fraction (1e18 scaled, default: 0)
    pub config_slash_fraction: Slot<U256>,
    // slot 5: lookback duration in seconds (default: 86400)
    pub config_lookback_duration: Slot<u64>,
    // slot 6: oracle enabled flag
    pub config_enabled: Slot<bool>,
    // slot 7: genesis guard
    pub config_is_initialized: Slot<bool>,

    // === Pair Registry (slots 8-11) ===
    // slot 8: number of registered pairs. Ordinals are 1-based and never
    // reused: nothing unregisters, so `1..=pair_count` is dense and every
    // enumeration relies on that.
    pub pair_count: Slot<PairIndex>,
    // Slot 9 (`pair_id_to_hash`) is a retired hole. Do not reuse.
    // slot 10: mapping(pair => index) (0 = not registered)
    #[slot(10)]
    pub pair_to_index: Mapping<AddressPair, PairIndex>,
    // slot 11: mapping(pair => is_vote_target)
    pub vote_target: Mapping<AddressPair, bool>,

    // === Exchange Rates (slots 12-14) ===
    // Keyed by the registry's [`PairIndex`], so a price read is two steps:
    // `pair_to_index` first, then this column. Only a registered pair has an
    // index, so an unregistered market has no rate slot to write into at all,
    // and the index carries the orientation the pair was registered in - the
    // stored rate is always the registered direction, never the reciprocal.
    // slot 12: mapping(pair_index => exchange_rate), pair-registered scale
    pub exchange_rate: Mapping<PairIndex, U256>,
    // slot 13: mapping(pair_index => last_update_block)
    pub exchange_rate_block: Mapping<PairIndex, u64>,
    // slot 14: mapping(pair_index => last_update_timestamp)
    pub exchange_rate_timestamp: Mapping<PairIndex, u64>,

    // === Feeder Delegation (slot 15) ===
    // slot 15: mapping(validator_address => feeder_address)
    // Address::ZERO means self-delegation (validator is its own feeder)
    pub feeder_delegation: Mapping<Address, Address>,

    // === Vote Penalty Counters (slots 16-18) ===
    // slot 16: mapping(validator => success_count)
    pub penalty_success_count: Mapping<Address, u64>,
    // slot 17: mapping(validator => abstain_count)
    pub penalty_abstain_count: Mapping<Address, u64>,
    // slot 18: mapping(validator => miss_count)
    pub penalty_miss_count: Mapping<Address, u64>,

    // === Aggregate Votes (slots 19-24) ===
    // slot 19: mapping(validator => has_voted_this_period)
    pub vote_exists: Mapping<Address, bool>,
    // slot 20: mapping(validator => number_of_tuples)
    pub vote_tuple_count: Mapping<Address, PairIndex>,
    // slot 21: mapping(validator => mapping(tuple_idx => pair))
    pub vote_pair: Mapping<Address, Mapping<PairIndex, AddressPair>>,
    // slot 22: mapping(validator => mapping(tuple_idx => rate))
    pub vote_rate: Mapping<Address, Mapping<PairIndex, U256>>,
    // slot 23: mapping(validator => mapping(tuple_idx => volume))
    pub vote_volume: Mapping<Address, Mapping<PairIndex, U256>>,

    // === Voter Tracking (slot 24) ===
    // slot 24: dynamic array of voter addresses (length at slot 24, data at keccak256(24))
    pub voter_list: StorageVec<Address>,

    // === Price Snapshots - circular buffer (slots 25-31) ===
    // slot 25: monotonic write index (tail pointer, u64 to avoid wrapping)
    pub snapshot_write_idx: Slot<u64>,
    // slot 26: oldest valid index (head pointer)
    pub snapshot_oldest_idx: Slot<u64>,
    // slot 27: mapping(snapshot_idx => timestamp)
    pub snapshot_timestamp: Mapping<u64, u64>,
    // slot 28: mapping(snapshot_idx => pair_count in this snapshot)
    pub snapshot_pair_count: Mapping<u64, PairIndex>,
    // slot 29: mapping(snapshot_idx => mapping(pair_index => pair))
    pub snapshot_pair: Mapping<u64, Mapping<PairIndex, AddressPair>>,
    // slot 30: mapping(snapshot_idx => mapping(pair_index => rate))
    pub snapshot_rate: Mapping<u64, Mapping<PairIndex, U256>>,
    // slot 31: mapping(snapshot_idx => mapping(pair_index => volume))
    pub snapshot_volume: Mapping<u64, Mapping<PairIndex, U256>>,

    // === Protected Validators (slots 32-33) ===
    // slot 32: mapping(validator => is_protected)
    pub protected_validator: Mapping<Address, bool>,
    // slot 33: allow protected validators flag
    pub config_allow_protected: Slot<bool>,

    // === S-Curve Active Entries (slots 34-39) ===
    // slot 34: number of active S-curve entries
    pub scurve_count: Slot<u32>,
    // slot 35: mapping(entry_idx => pair) for which pair
    pub scurve_pair: Mapping<u32, AddressPair>,
    // slot 36: mapping(entry_idx => peak_day_timestamp) UTC midnight
    pub scurve_peak_day: Mapping<u32, u64>,
    // slot 37: mapping(entry_idx => peak_price), pair-registered scale
    pub scurve_peak_price: Mapping<u32, U256>,
    // slot 38: oldest non-evicted entry index (head pointer for cleanup)
    pub scurve_oldest_idx: Slot<u32>,
    // slot 39: last UTC day (truncated timestamp) when S-curve processing ran
    pub scurve_last_processed_day: Slot<u64>,

    // === Settlement Currencies - retired (slots 40-42) ===
    // The settlement pair is derived, not stored: `AddressPair::new_coen_to(iso)` packs the
    // zero address with the marked ISO address, and an ISO is usable exactly
    // when that pair is present in `pair_index`. Slots 40
    // (`settlement_count`), 41 (`settlement_iso_to_denom`) and 42
    // (`settlement_iso_to_pair`) are retired holes with no live writer. Do not
    // reuse them.

    // === Index -> Pair Reverse Lookup (slot 43) ===
    // The only way to enumerate the registry: mappings are not iterable, so
    // `1..=pair_count` walks this column. It holds the orientation the pair was
    // registered in, which the sorted storage key cannot recover on its own.
    // slot 43 - pinned: without this anchor the running slot counter would slide
    // it down into the retired 40-42 hole.
    #[slot(43)]
    pub pair_by_index: Mapping<PairIndex, AddressPair>,
    // Slots 44 (`pair_ordinal_quote`), 45 (`settlement_index_to_iso`) and 46
    // (`settlement_iso_to_denom_string`) are retired holes. 44 held the second
    // half of the registry entry back when a pair needed two parallel columns.

    // === WorldwideDay VWAP Snapshots (slots 47-49, 52) ===
    // slot 47: mapping(worldwide_day => exists)
    #[slot(47)]
    pub worldwide_day_vwap_exists: Mapping<WorldwideDay, bool>,
    // slot 48: mapping(worldwide_day => start_time)
    pub worldwide_day_vwap_start: Mapping<WorldwideDay, u64>,
    // slot 49: mapping(worldwide_day => end_time)
    pub worldwide_day_vwap_end: Mapping<WorldwideDay, u64>,
    // Slots 50 (`worldwide_day_vwap_pair_count`) and 51
    // (`worldwide_day_vwap_pair`) are retired holes. Do not reuse. They existed
    // only to name the pair behind a per-day entry ordinal; the column below is
    // keyed by the registry index instead, so the pair is already in
    // `pair_by_index`.
    // slot 52: mapping(worldwide_day => mapping(pair_index => vwap))
    // Inner key is the registry [`PairIndex`] - the same key space as
    // `pair_by_index`, so `1..=pair_count` enumerates the day. An absent entry
    // reads as zero and means "no VWAP for that pair on that day".
    // slot 52 - pinned: without this anchor the running slot counter would slide
    // it up into the retired 50-51 hole.
    #[slot(52)]
    pub worldwide_day_vwap_value: Mapping<WorldwideDay, Mapping<PairIndex, U256>>,

    // === Daily Rolling VWAP Aggregates (slots 53-54) ===
    // Updated on every write_snapshot. Keyed by (pair, utc_day_timestamp).
    // utc_day_timestamp = timestamp - (timestamp % 86400).
    // slot 53: mapping(pair => mapping(utc_day_ts => cumulative price*volume sum))
    pub daily_pv_sum: Mapping<AddressPair, Mapping<u64, U256>>,
    // slot 54: mapping(pair => mapping(utc_day_ts => cumulative volume sum))
    pub daily_vol_sum: Mapping<AddressPair, Mapping<u64, U256>>,

    // === Reference Currencies (slot 55) ===
    // Dynamic list of ISO 4217 numeric codes considered "reference" currencies
    // for off-chain pricing. Length at the base slot, data at keccak256(slot)
    // + index. Pre-filled at genesis with [840] (USD).
    pub reference_currencies: StorageVec<u16>,

    // === Per-UTC-Day VWAP Snapshots (slots 58-59) ===
    // Finalized VWAP for a full UTC calendar day, keyed by a yyyymmdd UTC date
    // key (e.g. 20260625) - NOT a WorldwideDay (which is UTC+14). Written once
    // per closed day by the begin-block lifecycle from the canonical
    // `[date_key_to_utc_timestamp(utc_day), +SECONDS_PER_DAY)` window. Stored
    // forever (no pruning). A day with no oracle data is never written, so an
    // empty day is indistinguishable from an unfinalized one by its entries
    // alone; `utc_day_vwap_last_finalized` is the authority on which is which.
    //
    // Slots 56 (`utc_day_vwap_pair_count`) and 57 (`utc_day_vwap_pair`) are
    // retired holes. Do not reuse.
    // slot 58: mapping(utc_day => mapping(pair_index => vwap)), pair scale.
    // Inner key is the registry [`PairIndex`], as for the WorldwideDay column
    // above. slot 58 - pinned against the retired 56-57 hole.
    #[slot(58)]
    pub utc_day_vwap_value: Mapping<u32, Mapping<PairIndex, U256>>,
    // Monotonic watermark: most recent fully-closed UTC day that has been
    // finalized (yyyymmdd). 0 = nothing finalized yet. Backfill is contiguous,
    // so every day <= this watermark is considered finalized.
    pub utc_day_vwap_last_finalized: Slot<u32>,

    // Slot 60 held annual policy rates while they were incorrectly coupled to
    // reference-currency membership. It is retired; do not reuse.

    // === OCOMP PoC pre-admission projection (slots 61, 63-64) ===
    // These trailing fields are inert until the fresh-devnet fork handler sets
    // `ocomp_profile_ready`. Existing pre-fork Oracle writes therefore keep
    // their exact historical state footprint.
    #[slot(61)]
    pub ocomp_profile_ready: Slot<bool>,
    // Slot 62 (`ocomp_day_type_pair_id`) is a retired hole. The day-type pair is
    // the compile-time `DAY_TYPE_PAIR_KEY`, so pinning its ordinal in storage
    // bought nothing once pairs stopped being identified by ordinal.
    // Do not reuse.
    // slot 63: direct O(1) lookup for the single fork-fixed auction-entry pair.
    // The canonical UTC-day finalizer is its only mutation owner.
    #[slot(63)]
    pub ocomp_day_type_vwap_by_utc_day: Mapping<u32, U256>,
    // Advances for every Oracle mutation visible to OCOMP pre-admission.
    pub ocomp_state_version: Slot<u64>,
    // Slots 65-69 held the `quote` half of the five pair columns above, back
    // when a pair needed two parallel `Address` mappings. They are trailing
    // retired holes. Do not reuse.

    // === Exact WorldwideDay edge aggregates (slots 70-73) ===
    // A WorldwideDay formation window starts at 10:00 UTC on the preceding
    // calendar day and ends at 12:00 UTC on the following calendar day. These
    // permanent partial-day aggregates let the canonical 50-hour VWAP compose
    // that exact half-open interval without retaining or rescanning raw
    // snapshots. Keys are (pair, UTC-midnight timestamp), like daily_pv_sum.
    #[slot(70)]
    pub wwd_suffix_pv_sum: Mapping<AddressPair, Mapping<u64, U256>>,
    pub wwd_suffix_vol_sum: Mapping<AddressPair, Mapping<u64, U256>>,
    pub wwd_prefix_pv_sum: Mapping<AddressPair, Mapping<u64, U256>>,
    pub wwd_prefix_vol_sum: Mapping<AddressPair, Mapping<u64, U256>>,

    // === Independent policy-rate registry (slots 74-75) ===
    // Membership is enumerated independently of reference currencies and
    // registered Oracle pairs. Rates are annualized at scale 1e6.
    pub policy_rate_currencies: StorageVec<u16>,
    pub policy_rate: Mapping<u16, U256>,
}
