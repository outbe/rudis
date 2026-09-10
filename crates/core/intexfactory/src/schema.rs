//! Storage schema for IntexFactory: settlement bookkeeping and the
//! unqualified-series bin index. Canonical series state lives in Intex.

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_intex::{SeriesId, SERIES_ID_LEN};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::INTEX_FACTORY_ADDRESS;
use outbe_primitives::time::WorldwideDay;

/// Issuance inputs captured on Outbe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceParams {
    pub series_id: SeriesId,
    pub worldwide_day: WorldwideDay,
    pub issued_intex_count: u32,
    pub promis_load_minor: u128,
    /// Entry price (per-unit, reference ISO stable-units, 1e6); cost/floor/call derive from it.
    pub entry_price_minor: U256,
    pub issuance_currency: u16,
    pub reference_currency: u16,
    /// Auction winners: per-address issue recipients for ISSUANCE_INSTRUCTIONS.
    pub recipients: Vec<Address>,
    pub quantities: Vec<U256>,
    /// Source chain of each winner (parallel to `recipients`); routes each issue to its chain.
    pub recipient_chains: Vec<u32>,
    /// Every target chain of the day's snapshot; each gets an ISSUANCE (empty recipients = create only).
    pub snapshot_chains: Vec<u32>,
}

/// EVM storage layout: settlement bookkeeping (authorized_settler, mine_seq), the
/// lifecycle bin indexes and the queue of called groups awaiting their deadline.
#[storage_schema]
#[contract(addr = INTEX_FACTORY_ADDRESS)]
pub struct IntexFactoryContract {
    /// `keccak256(holder ++ series_id)` -> authorized settler address.
    #[attribute(order = 0)]
    pub authorized_settler: outbe_primitives::storage::dsl::Map<B256, Address>,

    /// `keccak256(series_id ++ holder)` -> monotonic minePromis sequence.
    #[attribute(order = 1)]
    pub mine_seq: outbe_primitives::storage::dsl::Map<B256, u32>,

    // Unqualified-series bin index (by floor_price_minor) for begin_block qualify.
    // A floor is only comparable to the rate of its own reference currency, so
    // every column is namespaced by ISO code and each currency walks its own trie.
    #[attribute(order = 2)]
    pub bin_tree_root: outbe_primitives::storage::dsl::Map<u16, U256>,
    #[attribute(order = 3)]
    pub bin_tree_mid: outbe_primitives::storage::dsl::Map<u64, U256>,
    #[attribute(order = 4)]
    pub bin_tree_leaf: outbe_primitives::storage::dsl::Map<u64, U256>,
    /// `scoped(iso, bin_id)` -> count of groups in the bin.
    #[attribute(order = 5)]
    pub unqualified_bin_count: outbe_primitives::storage::dsl::Map<u64, u32>,

    // Qualified-series bin index (by call_price_minor) for the daily
    // Called scan. A series moves here from the unqualified index on qualify.
    #[attribute(order = 6)]
    pub qualified_bin_tree_root: outbe_primitives::storage::dsl::Map<u16, U256>,
    #[attribute(order = 7)]
    pub qualified_bin_tree_mid: outbe_primitives::storage::dsl::Map<u64, U256>,
    #[attribute(order = 8)]
    pub qualified_bin_tree_leaf: outbe_primitives::storage::dsl::Map<u64, U256>,
    /// `scoped(iso, bin_id)` -> count of groups in the bin.
    #[attribute(order = 9)]
    pub qualified_bin_count: outbe_primitives::storage::dsl::Map<u64, u32>,

    // Genesis parameter-profile selector (0 = prod, 1 = dev); see crate::config.
    #[attribute(order = 10)]
    pub config_profile: outbe_primitives::storage::dsl::Value<u8>,

    // Bin each currency's sweep resumes from, so per-block work stays capped. 0 = fresh sweep.
    #[attribute(order = 11)]
    pub qualify_scan_cursor: outbe_primitives::storage::dsl::Map<u16, u32>,

    // Registry index each scan resumes at, so a currency that exhausts the shared
    // budget cannot starve the ones behind it.
    #[attribute(order = 12)]
    pub qualify_currency_cursor: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 13)]
    pub call_currency_cursor: outbe_primitives::storage::dsl::Value<u32>,

    // Called-scan twin of the qualify cursor: without it a budgeted run re-walks the
    // lowest bins every day and never reaches the series above them.
    #[attribute(order = 14)]
    pub call_scan_cursor: outbe_primitives::storage::dsl::Map<u16, u32>,

    // Group members, keyed by `scoped(iso, day)`: a decision reads only fields the
    // whole (reference currency, worldwide day) pair shares.
    #[attribute(order = 15)]
    pub unqualified_group_count: outbe_primitives::storage::dsl::Map<u64, u32>,
    /// `keccak256(iso_be16 ++ worldwide_day_be32 ++ index_be32)` -> series_id word.
    #[attribute(order = 16)]
    pub unqualified_group_members: outbe_primitives::storage::dsl::Map<B256, U256>,
    /// `scoped(iso, worldwide_day)` -> the bin holding the group; valid while it has members.
    #[attribute(order = 17)]
    pub unqualified_group_bin: outbe_primitives::storage::dsl::Map<u64, u32>,

    #[attribute(order = 18)]
    pub qualified_group_count: outbe_primitives::storage::dsl::Map<u64, u32>,
    /// `keccak256(iso_be16 ++ worldwide_day_be32 ++ index_be32)` -> series_id word.
    #[attribute(order = 19)]
    pub qualified_group_members: outbe_primitives::storage::dsl::Map<B256, U256>,
    /// `scoped(iso, worldwide_day)` -> the bin holding the group; valid while it has members.
    #[attribute(order = 20)]
    pub qualified_group_bin: outbe_primitives::storage::dsl::Map<u64, u32>,

    // UTC day an unfinished call sweep is pinned to, so its later slices decide
    // against the prices it opened with. 0 = none in flight; a date key is never 0.
    #[attribute(order = 21)]
    pub call_sweep_day: outbe_primitives::storage::dsl::Value<u32>,

    /// `keccak256(iso_be16 ++ bin_id_be32 ++ index_be32)` -> group's worldwide day.
    #[attribute(order = 22)]
    pub unqualified_bin_groups: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// `keccak256(iso_be16 ++ bin_id_be32 ++ index_be32)` -> group's worldwide day.
    #[attribute(order = 23)]
    pub qualified_bin_groups: outbe_primitives::storage::dsl::Map<B256, u32>,

    // Lifecycle notices waiting for the `intex_notify` trigger to send them: the
    // scans run in a block hook, which cannot call contracts. Head and tail reset
    // to 0 whenever the queue drains empty.
    #[attribute(order = 24)]
    pub notify_head: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 25)]
    pub notify_tail: outbe_primitives::storage::dsl::Value<u32>,
    /// Queue index -> `scoped(iso, day)` for a Qualified group, or the series word packed with its
    /// call time for a Called one: a called group has left the index, so its notice carries its own.
    #[attribute(order = 26)]
    pub notify_at: outbe_primitives::storage::dsl::Map<u32, U256>,
    /// Queue index -> which mark the notice carries; see `NOTICE_QUALIFIED`.
    #[attribute(order = 27)]
    pub notify_kind: outbe_primitives::storage::dsl::Map<u32, u8>,

    // Called groups awaiting their settlement window, bucketed by the hour it closes
    // in. A called group has left the bin index, so these members are its only trace.
    #[attribute(order = 28)]
    pub expiry_tree_root: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 29)]
    pub expiry_tree_mid: outbe_primitives::storage::dsl::Map<u32, U256>,
    #[attribute(order = 30)]
    pub expiry_tree_leaf: outbe_primitives::storage::dsl::Map<u32, U256>,
    /// `scoped(iso, day)` -> when the group's settlement window closes. Stored so
    /// the head check costs no record load.
    #[attribute(order = 31)]
    pub called_group_deadline: outbe_primitives::storage::dsl::Map<u64, u64>,
    #[attribute(order = 32)]
    pub called_group_count: outbe_primitives::storage::dsl::Map<u64, u32>,
    /// `keccak256(iso_be16 ++ worldwide_day_be32 ++ index_be32)` -> series_id word.
    #[attribute(order = 33)]
    pub called_group_members: outbe_primitives::storage::dsl::Map<B256, U256>,

    // Widest terms ever issued in a currency; both only move outwards, so the range
    // they define covers series the live profile no longer names.
    #[attribute(order = 34)]
    pub max_call_window: outbe_primitives::storage::dsl::Map<u16, u32>,
    #[attribute(order = 35)]
    pub min_call_threshold: outbe_primitives::storage::dsl::Map<u16, u32>,

    /// Slots ever used in a bucket; retired ones are zeroed in place, not compacted.
    #[attribute(order = 36)]
    pub expiry_bucket_len: outbe_primitives::storage::dsl::Map<u32, u32>,
    #[attribute(order = 37)]
    pub expiry_bucket_live: outbe_primitives::storage::dsl::Map<u32, u32>,
    /// `keccak256(bucket_be32 ++ slot_be32)` -> `scoped(iso, worldwide_day)`.
    #[attribute(order = 38)]
    pub expiry_bucket_at: outbe_primitives::storage::dsl::Map<B256, u64>,
    /// `scoped(iso, day)` -> `(bucket << 32) | slot`; 0 = not queued.
    #[attribute(order = 39)]
    pub called_group_slot: outbe_primitives::storage::dsl::Map<u64, u64>,
    #[attribute(order = 40)]
    pub expiry_sweep_day: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 41)]
    pub expiry_cursor: outbe_primitives::storage::dsl::Value<u32>,
}

impl IntexFactoryContract<'_> {
    /// Composite key for `authorized_settler`: `keccak256(holder ++ series_id)`.
    pub fn authorized_settler_key(holder: Address, series_id: SeriesId) -> B256 {
        let mut buf = [0u8; 20 + SERIES_ID_LEN];
        buf[0..20].copy_from_slice(holder.as_slice());
        buf[20..].copy_from_slice(series_id.as_bytes());
        keccak256(buf)
    }

    /// Namespace a bin-index column by the reference currency its prices are in.
    pub(crate) const fn scoped(reference_currency: u16, key: u32) -> u64 {
        ((reference_currency as u64) << 32) | key as u64
    }

    /// Inverse of [`Self::scoped`] for a key that is a worldwide day.
    pub(crate) const fn unscoped(scoped: u64) -> (u16, WorldwideDay) {
        (
            (scoped >> 32) as u16,
            WorldwideDay::new((scoped & 0xffff_ffff) as u32),
        )
    }

    /// Composite key for `mine_seq`: `keccak256(series_id ++ holder)`.
    pub fn mine_seq_key(series_id: SeriesId, holder: Address) -> B256 {
        let mut buf = [0u8; SERIES_ID_LEN + 20];
        buf[..SERIES_ID_LEN].copy_from_slice(series_id.as_bytes());
        buf[SERIES_ID_LEN..].copy_from_slice(holder.as_slice());
        keccak256(buf)
    }
}
