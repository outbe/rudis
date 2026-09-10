use alloy_primitives::{B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::METADOSIS_ADDRESS;
use outbe_primitives::storage::types::{Mapping, StorageBytes};
use outbe_primitives::time::WorldwideDay as WorldwideDayKey;

/// EVM base slot of `MetadosisContract::ocomp_job_records`.
///
/// Earlier DSL collections occupy more than one slot, so this is deliberately
/// not the field's `order = 8`. OCM finality proof construction and verification
/// use this fixed consensus path; the storage behavior test pins it to the
/// macro-generated contract layout.
pub const OCOMP_JOB_RECORDS_BASE_SLOT: u64 = 21;

/// WorldwideDay status values stored as u8.
pub mod status {
    pub const FORMING: u8 = 0;
    pub const LOOKBACK_DELAY: u8 = 1;
    pub const OFFERING: u8 = 2;
    pub const WAITING: u8 = 3;
    pub const READY: u8 = 4;
    pub const RESERVED_IN_PROGRESS: u8 = 5;
    pub const COMPLETED: u8 = 6;
    pub const FAILED: u8 = 7;
    pub const OFFCHAIN_PENDING: u8 = 8;
}

/// Day type values.
pub mod day_type {
    pub const UNKNOWN: u8 = 0;
    pub const GREEN: u8 = 1;
    pub const RED: u8 = 2;
}

/// Durable outer-WWD terminal receipt discriminants.
pub mod terminal_outcome {
    pub const NONE: u8 = 0;
    pub const MISSED_OFFERING: u8 = 1;
    pub const CAPACITY_FORFEITURE: u8 = 2;
    pub const METADOSIS_FAILURE: u8 = 3;
}

/// Canonical Tribute partition-retirement result recorded by a terminal receipt.
pub mod terminal_retirement {
    pub const NONE: u8 = 0;
    pub const NOT_PRESENT: u8 = 1;
    pub const REQUESTED: u8 = 2;
}

#[storage_record(exists_field = forming_start)]
pub struct WorldwideDay {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0, default = status::FORMING)]
    pub status: u8,

    #[attribute(order = 1, default = day_type::UNKNOWN)]
    pub day_type: u8,

    #[attribute(order = 2)]
    pub forming_start: u64,

    #[attribute(order = 3)]
    pub forming_end: u64,

    #[attribute(order = 4)]
    pub lookback_end: u64,

    #[attribute(order = 5)]
    pub offering_end: u64,

    #[attribute(order = 6)]
    pub scheduled_process_time: u64,

    #[attribute(order = 7, default = U256::ZERO)]
    pub metadosis_limit_amount: U256,

    #[attribute(order = 8, default = U256::ZERO)]
    pub previous_vwap: U256,

    #[attribute(order = 9, default = U256::ZERO)]
    pub current_vwap: U256,
}

/// Minimal PoC state proving which carry-over was consumed into an immutable
/// day limit. This is deliberately a separate append-only mapping so the
/// established `WorldwideDay` width and every later consensus slot remain
/// unchanged.
#[storage_record(exists_field = formed)]
pub struct OcompDayLimitFormationState {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0)]
    pub formed: bool,

    #[attribute(order = 1, default = U256::ZERO)]
    pub carry_over_taken: U256,
}

/// Fresh-devnet semantic replay receipt for the Cycle-owned day-limit slot.
/// It is separate from the legacy two-field formation marker so that the
/// established storage layout and OCOMP proof slots remain unchanged.
#[storage_record(exists_field = formed)]
pub struct DayLimitFormationReceiptState {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0)]
    pub formed: bool,

    #[attribute(order = 1, default = U256::ZERO)]
    pub base_limit: U256,

    #[attribute(order = 2, default = U256::ZERO)]
    pub carry_over_before: U256,

    #[attribute(order = 3, default = U256::ZERO)]
    pub carry_over_taken: U256,

    #[attribute(order = 4, default = U256::ZERO)]
    pub carry_over_after: U256,

    #[attribute(order = 5, default = U256::ZERO)]
    pub formed_day_limit: U256,

    #[attribute(order = 6)]
    pub block_number: u64,
}

/// Fork-initialized OCOMP state owned by Metadosis for one WorldwideDay.
///
/// The detailed pre-admission values remain owned by Tribute, Fidelity and
/// Oracle. Metadosis commits their terminal canonical envelope and advances a
/// version used by later activation preconditions.
#[storage_record(exists_field = initialized)]
pub struct OcompPreAdmissionState {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0)]
    pub initialized: bool,

    #[attribute(order = 1)]
    pub state_version: u64,

    #[attribute(order = 2, default = B256::ZERO)]
    pub envelope_hash: B256,
}

#[storage_record(exists_field = outcome)]
pub struct WorldwideDayTerminalReceiptState {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0, default = terminal_outcome::NONE)]
    pub outcome: u8,

    #[attribute(order = 1, default = U256::ZERO)]
    pub value_routed: U256,

    #[attribute(order = 2, default = U256::ZERO)]
    pub carry_over_before: U256,

    #[attribute(order = 3, default = U256::ZERO)]
    pub carry_over_after: U256,

    #[attribute(order = 4, default = terminal_retirement::NONE)]
    pub retirement: u8,

    #[attribute(order = 5)]
    pub block_number: u64,
}

/// Exact bounded evidence for the deterministic retained-cap admission policy.
#[storage_record(exists_field = outcome)]
pub struct CapacityForfeitureReceiptState {
    #[key]
    pub wwd: WorldwideDayKey,

    #[attribute(order = 0, default = terminal_outcome::NONE)]
    pub outcome: u8,

    #[attribute(order = 1)]
    pub max_retained_wwds: u32,

    #[attribute(order = 2)]
    pub retained_count_before: u32,

    #[attribute(order = 3, default = U256::ZERO)]
    pub value_routed: U256,

    #[attribute(order = 4, default = U256::ZERO)]
    pub carry_over_before: U256,

    #[attribute(order = 5, default = U256::ZERO)]
    pub carry_over_after: U256,

    #[attribute(order = 6, default = B256::ZERO)]
    pub sealed_collection_root: B256,

    #[attribute(order = 7)]
    pub forfeited_count: u32,

    #[attribute(order = 8, default = U256::ZERO)]
    pub forfeited_nominal: U256,

    #[attribute(order = 9)]
    pub source_generation: u64,

    #[attribute(order = 10)]
    pub retired_generation: u64,

    #[attribute(order = 11, default = terminal_retirement::NONE)]
    pub retirement: u8,

    #[attribute(order = 12)]
    pub block_number: u64,
}

/// EVM storage layout for the Metadosis orchestrator contract.
///
/// Manages worldwide day lifecycle and daily emission accumulation.
#[storage_schema]
#[contract(addr = METADOSIS_ADDRESS)]
pub struct MetadosisContract {
    #[attribute(order = 0)]
    pub bootstrap_end_time: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 1)]
    pub worldwide_days: outbe_primitives::storage::dsl::Map<WorldwideDayKey, WorldwideDay>,

    #[attribute(order = 2)]
    pub active_wwd_count: outbe_primitives::storage::dsl::Value<u16>,

    #[attribute(order = 3)]
    pub active_wwd: outbe_primitives::storage::dsl::Set<WorldwideDayKey>,

    /// Bounded FIFO of terminal (COMPLETED/FAILED) WorldwideDays, newest at the
    /// back. Capped at `MAX_RECORDS_KEPT`: when a new terminal day pushes past
    /// the cap, the oldest is popped from the front and its record deleted.
    #[attribute(order = 4)]
    pub closed_wwd: outbe_primitives::storage::dsl::Deque<WorldwideDayKey>,

    /// Inert before the OCOMP fresh-devnet fork initializes an entry.
    #[attribute(order = 5)]
    pub ocomp_pre_admission:
        outbe_primitives::storage::dsl::Map<WorldwideDayKey, OcompPreAdmissionState>,

    /// Fork-profile authority installed by `OcompLifecycleBegin`. Empty before
    /// the genesis-bound OCOMP profile is armed.
    #[attribute(order = 6)]
    pub ocomp_request_profile: outbe_primitives::storage::types::StorageBytes,

    /// Exact bounded live-Job registry. Empty while no OCOMP intent is pending.
    /// READY work is kept in the separately bounded ordered index below; each
    /// live entry retains an independent per-WWD FSM and IntentId.
    #[attribute(order = 7)]
    pub ocomp_scheduler: outbe_primitives::storage::types::StorageBytes,

    /// Canonical OCB1 `OcompJobRecordV1`, keyed by
    /// `IntentStorageKeyV1 = H("OUTBE_OCOMP_INTENT_SLOT_V1", IntentId)`.
    #[attribute(order = 8)]
    pub ocomp_job_records: outbe_primitives::storage::types::Mapping<
        B256,
        outbe_primitives::storage::types::StorageBytes,
    >,

    /// Immutable request-phase budget receipt, keyed by WorldwideDay.
    #[attribute(order = 9)]
    pub ocomp_request_budget_receipts: outbe_primitives::storage::types::Mapping<
        WorldwideDayKey,
        outbe_primitives::storage::types::StorageBytes,
    >,

    /// Exact canonical pre-admission envelope committed by a created intent.
    #[attribute(order = 10)]
    pub ocomp_pre_admission_envelopes: outbe_primitives::storage::types::Mapping<
        WorldwideDayKey,
        outbe_primitives::storage::types::StorageBytes,
    >,

    /// Per-WorldwideDay terminal IntentId, keyed
    /// by `keccak(OUTBE_OCOMP_TERMINAL_INDEX_V1 || wwd_be || index_be)` (see
    /// `ocomp::terminal_index`). The single-attempt FSM permits exactly one
    /// immutable entry, deleted together with the day on retirement. Must stay
    /// a 1-slot field: every later base slot depends on this position.
    #[attribute(order = 11)]
    pub ocomp_terminal_intents: outbe_primitives::storage::types::Mapping<B256, B256>,

    /// Canonical per-WWD FSM snapshots. A WWD has one exact READY or live
    /// state, while the global indexes below select bounded work without
    /// scanning `active_wwd`.
    #[attribute(order = 12)]
    pub ocomp_fsm_states: outbe_primitives::storage::types::Mapping<
        WorldwideDayKey,
        outbe_primitives::storage::types::StorageBytes,
    >,

    /// Canonical ordered READY keys `(next_check_height, WWD, pending_nonce)`.
    /// The encoded vector is bounded by `MAX_RECORDS_KEPT`; terminal request
    /// processing reads only its first key.
    #[attribute(order = 13)]
    pub ocomp_ready_index: outbe_primitives::storage::types::StorageBytes,

    /// PoC day-limit formation state. Appended after all existing fields so
    /// OCM finality proof paths and pre-fork storage offsets remain fixed.
    #[attribute(order = 14)]
    pub ocomp_day_limit_formations:
        outbe_primitives::storage::dsl::Map<WorldwideDayKey, OcompDayLimitFormationState>,

    /// Canonical active Lysis generation selected by completed Metadosis state.
    /// This append-only mapping is the public authority after activation.
    #[attribute(order = 15)]
    pub ocomp_active_lysis_generations: Mapping<WorldwideDayKey, StorageBytes>,

    /// Canonical OCB1 `ProtocolBundleV1` installed by `OcompLifecycleBegin`.
    /// The request profile stores its hash; activation needs the complete
    /// immutable bundle to select the frozen LYSIS_V1 program semantics.
    #[attribute(order = 16)]
    pub ocomp_active_protocol_bundle: StorageBytes,

    /// Reserved zero-valued slot from the removed static OCOMP committee.
    /// The field name, type and ordinal stay unchanged so the storage layout
    /// hash and every following field remain byte-identical.
    #[attribute(order = 17)]
    pub ocomp_result_committee_snapshot: StorageBytes,

    /// Dynamic monolithic result-vote slots and their independently closing
    /// accountability summary, keyed by finalized JobId.
    #[attribute(order = 18)]
    pub ocomp_vote_accountability: Mapping<B256, StorageBytes>,

    /// Canonical bounded response-window index ordered by
    /// `(deadline_height, JobId)`. It deliberately survives activation so the
    /// pinned participants and bounded equivocation evidence remain admissible
    /// until the exclusive deadline.
    #[attribute(order = 19)]
    pub ocomp_response_deadline_index: StorageBytes,

    /// Per-owner Fidelity league snapshot for one WorldwideDay, written once by
    /// the OCOMP prepare phase. Keyed by
    /// `outbe_ocomp_protocol::league_snapshot::league_snapshot_key(wwd, owner)`,
    /// it stores one league word per owner so the OCOMP openings MPT-prove a
    /// single league slot per owner instead of the raw Fidelity cohort ledger.
    /// Appended (base slot 34) so pre-fork storage offsets and OCM finality
    /// proof paths stay fixed; `league_snapshot::METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT`
    /// is pinned to this layout by test.
    #[attribute(order = 20)]
    pub ocomp_fidelity_league_snapshot: Mapping<B256, u16>,

    /// Ordered commitment over one day's snapshotted `(owner, league)` pairs,
    /// written alongside the per-owner snapshot during the active-phase prepare
    /// step. The post-seal terminal request reads it (a plain storage read valid
    /// in any lifecycle phase) to bind into the sealed pre-admission envelope. A
    /// non-zero value also marks the day's snapshot as already built.
    #[attribute(order = 21)]
    pub ocomp_fidelity_league_snapshot_root:
        outbe_primitives::storage::types::Mapping<WorldwideDayKey, B256>,

    /// Durable typed outer-WWD terminal receipt. Appended for the fresh-devnet
    /// layout; existing OCOMP proof slots remain byte-identical.
    #[attribute(order = 22)]
    pub worldwide_day_terminal_receipts:
        outbe_primitives::storage::dsl::Map<WorldwideDayKey, WorldwideDayTerminalReceiptState>,

    /// Capacity-forfeiture detail receipt linked to the generic terminal
    /// receipt above. Fresh-devnet append-only layout.
    #[attribute(order = 23)]
    pub capacity_forfeiture_receipts:
        outbe_primitives::storage::dsl::Map<WorldwideDayKey, CapacityForfeitureReceiptState>,

    /// Complete Metadosis-owned semantic result for day-limit replay. Appended
    /// only for fresh devnet; no backfill or mixed-history interpretation.
    #[attribute(order = 24)]
    pub day_limit_formation_receipts:
        outbe_primitives::storage::dsl::Map<WorldwideDayKey, DayLimitFormationReceiptState>,

    /// Per-WorldwideDay terminal record count: the sole authority for the
    /// length of the sparse `ocomp_terminal_intents` index above. Appended so
    /// pre-existing base slots stay fixed.
    #[attribute(order = 25)]
    pub ocomp_terminal_counts: Mapping<WorldwideDayKey, u16>,
}
