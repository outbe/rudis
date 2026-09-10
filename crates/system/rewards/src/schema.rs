use alloy_primitives::{Address, B256, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::REWARDS_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot};

/// EVM storage layout for the Rewards precompile.
///
/// Tracks the chain's genesis UTC-day anchor and the per-finalized-block +
/// per-day accumulators used by the idempotent fee-distribution path and
/// day-boundary settle formula and the FIFO of exact validator Gem obligations.
///
/// Per-block fees are escrowed (`pending_fees`) and settled at `N+K` over the
/// inclusion-window voter set; daily emission top-ups are prepared by
/// [`crate::api::prepare_daily_validator_gem_batch`] and delivered by
/// [`crate::api::deliver_oldest_reward_gem_batch`] (validator emission is paid
/// in gems, not a claimable native balance).
///
/// Storage slots:
///   0:  genesis_utc_day                    - uint32 (yyyymmdd of block 0; 0 = uninit)
///   1:  participation_counted_for_block    - mapping(B256 => mapping(address => bool))
///   2:  daily_fee_sum_raw                  - mapping(uint32 => uint256)
///   3:  daily_fees_paid                    - mapping(uint32 => uint256)
///   4:  daily_fee_dust                     - mapping(uint32 => uint256)
///   5:  daily_participation                - mapping(uint32 => mapping(address => uint64))
///   6:  daily_total_participation          - mapping(uint32 => uint64)
///   7:  daily_voter_count                  - mapping(uint32 => uint32)
///   8:  daily_voter_at                     - mapping(uint32 => mapping(uint32 => address))
///   9:  daily_settled                      - mapping(uint32 => bool)
///  10:  max_observed_finalized_day         - uint32 (yyyymmdd; 0 = uninit)
///  11:  last_settled_utc_day               - uint32 (yyyymmdd; 0 = uninit)
///  12:  block_metadata_counted             - mapping(B256 => bool)
///  13:  metadata_fingerprint_for_block     - mapping(B256 => B256)
///  14:  fee_dust_counted_for_block         - mapping(B256 => bool)
///  15:  daily_topup_settled                - mapping(uint32 => bool)
///  16:  pending_fees                       - mapping(B256 => uint256)
///  17:  fee_settled                        - mapping(B256 => bool)
///  18:  late_voter_k_plus1                 - mapping(B256 => mapping(address => uint8))
///  19:  late_voter_count                   - mapping(B256 => uint32)
///  20:  late_voter_at                      - mapping(B256 => mapping(uint32 => address))
///  21:  pending_fb_hash_at                 - mapping(uint64 => B256)    (number -> fb_hash)
///  22:  pending_committee_size_at          - mapping(uint64 => uint32)
///  23:  pending_epoch_at                   - mapping(uint64 => uint64)
///  24:  pending_committee_set_hash_at      - mapping(uint64 => B256)
///  25:  pending_view_at                    - mapping(uint64 => uint64)
///  26:  pending_parent_view_at             - mapping(uint64 => uint64)
/// 27: block_guard_ring - mapping(uint64 => B256) (prune ring of fb_hash)
/// 28: block_guard_ring_seq - uint64 (ring write cursor)
/// 29: reward_gem_queue_head - uint64 (inclusive FIFO sequence)
/// 30: reward_gem_queue_tail - uint64 (exclusive FIFO sequence)
/// 31: reward_gem_utc_day_by_sequence - mapping(uint64 => uint32)
/// 32: reward_gem_queue_sequence_plus_one - mapping(uint32 => uint64)
/// 33: daily_topup_prepared - mapping(uint32 => bool)
/// 34: reward_gem_batch_digest - mapping(uint32 => B256)
/// 35: reward_gem_planned_load_amount - mapping(uint32 => uint256)
/// 36: reward_gem_recipient_count - mapping(uint32 => uint32)
/// 37: reward_gem_owner_at - mapping(uint32 => mapping(uint32 => address))
/// 38: reward_promis_load_at - mapping(uint32 => mapping(uint32 => uint256))
/// 39: reward_gem_type - mapping(uint32 => uint8)
/// 40: reward_gem_issuance_currency - mapping(uint32 => uint16)
/// 41: reward_gem_reference_currency - mapping(uint32 => uint16)
/// 42: reward_gem_pending_batch_count - uint64
/// 43: pending_reward_day - mapping(B256 => uint32)
/// 44: daily_last_window_close - mapping(uint32 => uint64)
#[contract(addr = REWARDS_ADDRESS)]
pub struct Rewards {
    /// UTC day of block 0 (yyyymmdd). 0 means uninitialized; written
    /// exactly once at the first invocation of `RewardsLifecycle::begin_block`,
    /// which is block 0 in any chain shipping this refactor. After
    /// initialization the value is immutable and used by
    /// `day_emission_limit(day_number_since_genesis(...))` from
    /// `outbe_emissionlimit::day_emission`.
    ///
    /// Tamper-resistance: a node that boots with a different
    /// `genesis.json` timestamp will lock in a different `genesis_utc_day`
    /// here, causing all subsequent day-settle math to diverge from the
    /// quorum's state root -> fall out of consensus on the first settle.
    /// Reth's startup hash check is a complementary defense, not the only
    /// one.
    pub genesis_utc_day: Slot<u32>,

    /// Per-(finalized_block_hash, voter) guard: voter participation has
    /// already been counted for this finalized block in the day's
    /// emission top-up share. Kept separate from the fee guard for
    /// audit clarity.
    pub participation_counted_for_block: Mapping<B256, Mapping<Address, bool>>,

    /// Per-day raw fee sum from finalized metadata (`fees_raw`). Source
    /// of truth for the cap-vs-fees formula at settle time. The emission cap is
    /// six-decimal protocol value while this sum stays raw native COEN:
    ///   `topup = floor((cap * 1e12).saturating_sub(daily_fee_sum_raw) / 1e12)`
    /// Equals `daily_fees_paid + daily_fee_dust` (invariant).
    pub daily_fee_sum_raw: Mapping<u32, U256>,

    /// Per-day total fees actually transferred to voters today, computed
    /// as `floor(fees_raw / voters_count) * voters_count`.
    pub daily_fees_paid: Mapping<u32, U256>,

    /// Per-day fee dust accumulated on `REWARDS_ADDRESS` (the residue
    /// from per-block split). Burned at settle and credited to Metadosis
    /// terminal limit.
    pub daily_fee_dust: Mapping<u32, U256>,

    /// Per-(utc_day, voter) participation count for the day. Used to
    /// proportionally distribute the day's emission top-up.
    pub daily_participation: Mapping<u32, Mapping<Address, u64>>,

    /// Per-day sum of `daily_participation` values for O(1) access at
    /// settle time. Maintained alongside `daily_participation` to avoid
    /// iterating the inner mapping (Mapping has no native iteration).
    pub daily_total_participation: Mapping<u32, u64>,

    /// Per-day count of distinct voters seen - upper bound for index
    /// iteration over `daily_voter_at`.
    pub daily_voter_count: Mapping<u32, u32>,

    /// Per-(utc_day, index) voter address. The index is first-seen-order
    /// of the voter for that day. Replay safety is maintained by
    /// `participation_counted_for_block`, which ensures append happens
    /// exactly once per `(finalized_block_hash, voter)` regardless of
    /// replay order.
    pub daily_voter_at: Mapping<u32, Mapping<u32, Address>>,

    /// Per-day guard that the day has been settled exactly once.
    /// Settle is gated on `max_observed_finalized_day > D` so late
    /// metadata for an already-settled day is rejected as fatal.
    pub daily_settled: Mapping<u32, bool>,

    /// Highest UTC day observed among processed finalized blocks
    /// (yyyymmdd; 0 = uninit). Used to gate the daily Cycle handler in
    /// `outbe-cycle`: a day D is settle-eligible only when at least one
    /// finalized block
    /// from a strictly later UTC day has been observed, so we are
    /// certain no further metadata for D will arrive.
    pub max_observed_finalized_day: Slot<u32>,

    /// Last UTC day successfully settled by `RewardsLifecycle`
    /// (yyyymmdd; 0 = uninit). Initialized lazily on first observed
    /// finalized day to `previous_date_key(fb_day)` so the first
    /// eligible day is exactly the first observed finalized day.
    pub last_settled_utc_day: Slot<u32>,

    /// Per-finalized-block guard: cap/fees-raw from this block already
    /// accumulated into `daily_fee_sum_raw`. Independent of fee-dust
    /// guard so dust accumulation has its own short-circuit semantics.
    pub block_metadata_counted: Mapping<B256, bool>,

    /// Per-finalized-block fingerprint guard. The fingerprint is
    /// `keccak256("OUTBE_METADATA_FINGERPRINT_V1" || canonical-encoded
    /// metadata economic fields)`. Same fingerprint observed twice for
    /// the same `fb_hash` is a replay no-op; different fingerprint for
    /// the same `fb_hash` is fatal (contradictory metadata for the same
    /// finalized block is a protocol violation).
    pub metadata_fingerprint_for_block: Mapping<B256, B256>,

    /// Per-finalized-block guard: fee dust from this block already
    /// accumulated into `daily_fee_dust`. Separate from
    /// `block_metadata_counted` so per-voter and per-block dust paths
    /// have independent short-circuits.
    pub fee_dust_counted_for_block: Mapping<B256, bool>,

    /// Completion guard for actual Gem delivery. A prepared pending batch keeps
    /// this false even after the day's allocation is sealed; delivery flips it
    /// only when the entire FIFO batch has minted atomically.
    pub daily_topup_settled: Mapping<u32, bool>,

    // -- per-block fee escrow + inclusion-window credits ----------
    /// Escrowed fees of a finalized block (key `fb_hash`), recorded instead of
    /// the eager per-voter transfer. Settled at `N+K` across the credited voter
    /// set with a decay-weighted, fixed-denominator payout; residue burns.
    pub pending_fees: Mapping<B256, U256>,

    /// Per-finalized-block guard: the escrowed fee has been settled exactly once.
    pub fee_settled: Mapping<B256, bool>,

    /// Per-(fb_hash, voter) smallest inclusion distance, stored as `k + 1`
    /// (`0` = not yet credited) so the base 2f+1 seeded at `k=0` records `1` and
    /// a later re-inclusion at `k>=1` is a no-op.
    pub late_voter_k_plus1: Mapping<B256, Mapping<Address, u8>>,

    /// Per-fb_hash count of distinct credited voters - bound for index iteration
    /// over `late_voter_at` at settle time.
    pub late_voter_count: Mapping<B256, u32>,

    /// Per-(fb_hash, index) credited voter address, in first-credit order, so the
    /// settlement can enumerate the voter set deterministically.
    pub late_voter_at: Mapping<B256, Mapping<u32, Address>>,

    /// Settle-trigger lookup: finalized block number -> its `fb_hash`, so the
    /// `LateFinalizeCredits` phase at block `N+K` can settle block `N`'s escrow
    /// by number (the mandatory window-close side effect). `B256::ZERO` = absent.
    pub pending_fb_hash_at: Mapping<u64, B256>,

    /// Finalized block number -> committee size at its epoch - the fixed
    /// denominator basis (`D = committee_size * w_max`) for its settlement.
    pub pending_committee_size_at: Mapping<u64, u32>,

    /// Finalized block number -> its canonical consensus epoch
    /// The `LateFinalizeCredits` phase verifies a credit's
    /// proposer-supplied `epoch`/`committee_set_hash`/`fb_hash` against the
    /// canonical binding escrowed here, so `fb_number` cannot be spoofed to
    /// inflate the decay weight `k` or to reference a wrong committee.
    pub pending_epoch_at: Mapping<u64, u64>,

    /// Finalized block number -> its canonical `committee_set_hash`
    /// authentication; see `pending_epoch_at`).
    pub pending_committee_set_hash_at: Mapping<u64, B256>,

    /// Finalized block number -> its canonical consensus `view`
    /// authentication). Together with `pending_parent_view_at` this pins the FULL
    /// signed binding `{epoch, view, parent_view, fb_hash}` at the body, so a
    /// proposer cannot record a credit whose aggregate is over a non-canonical
    /// view of the same `fb_hash` (cross-view equivocation). The pre-exec BLS
    /// verify only ties the credit's view to its signatures; this ties it to the
    /// finalized certificate.
    pub pending_view_at: Mapping<u64, u64>,

    /// Finalized block number -> its canonical `parent_view`
    /// authentication; see `pending_view_at`).
    pub pending_parent_view_at: Mapping<u64, u64>,

    // -- prune ring for the per-finalized-block guard maps ----------
    /// Bounds the per-`fb_hash` guard maps (`block_metadata_counted`,
    /// `metadata_fingerprint_for_block`, `fee_dust_counted_for_block`,
    /// `fee_settled`) to the last [`BLOCK_GUARD_RETAIN`](crate::finalized_metadata_hook::BLOCK_GUARD_RETAIN)
    /// finalized blocks. `on_finalized_metadata` records each finalized `fb_hash`
    /// here and clears the four guards of the block evicted `BLOCK_GUARD_RETAIN`
    /// records ago. Retention is far larger than the K-block late-finalize
    /// window, so no guard is dropped while its block can still be replayed
    /// (re-counted) or settled. The nested `participation_counted_for_block` map
    /// is freed separately at settlement (`settle_window`), where the credited
    /// voter set is known. `B256::ZERO` = empty ring slot.
    pub block_guard_ring: Mapping<u64, B256>,

    /// Monotonic write cursor for `block_guard_ring`; the live slot index is
    /// `block_guard_ring_seq % BLOCK_GUARD_RETAIN`.
    pub block_guard_ring_seq: Slot<u64>,

    // -- deferred validator reward Gem delivery -------------------
    /// Inclusive sequence of the oldest pending validator reward Gem batch.
    pub reward_gem_queue_head: Slot<u64>,

    /// Exclusive sequence for the next validator reward Gem batch append.
    pub reward_gem_queue_tail: Slot<u64>,

    /// FIFO sequence -> UTC reward day. Zero denotes a cleared queue slot.
    pub reward_gem_utc_day_by_sequence: Mapping<u64, u32>,

    /// UTC reward day -> FIFO sequence plus one. Zero denotes no live queue item.
    pub reward_gem_queue_sequence_plus_one: Mapping<u32, u64>,

    /// The exact validator Gem obligation for this day has been calculated.
    pub daily_topup_prepared: Mapping<u32, bool>,

    /// Permanent digest of the exact prepared batch, retained after delivery.
    pub reward_gem_batch_digest: Mapping<u32, B256>,

    /// Permanent sum of all non-zero Gem loads prepared for the reward day.
    pub reward_gem_planned_load_amount: Mapping<u32, U256>,

    /// Number of live pending recipients. Cleared after successful delivery.
    pub reward_gem_recipient_count: Mapping<u32, u32>,

    /// UTC reward day -> pending recipient index -> owner.
    pub reward_gem_owner_at: Mapping<u32, Mapping<u32, Address>>,

    /// UTC reward day -> pending recipient index -> exact Gem load.
    pub reward_promis_load_at: Mapping<u32, Mapping<u32, U256>>,

    /// Reward-day Gem type, frozen at preparation time.
    pub reward_gem_type: Mapping<u32, u8>,

    /// Reward Gem issuance currency, frozen at preparation time.
    pub reward_gem_issuance_currency: Mapping<u32, u16>,

    /// Reward Gem reference currency, frozen at preparation time.
    pub reward_gem_reference_currency: Mapping<u32, u16>,

    /// Live FIFO batch count; must equal `queue_tail - queue_head`.
    pub reward_gem_pending_batch_count: Slot<u64>,

    /// Canonical UTC day of an open finalized-block window. Cleared with escrow.
    pub pending_reward_day: Mapping<B256, u32>,

    /// Last inclusion-window close height for each day's finalized blocks.
    /// Cycle runs before late credits, so preparation requires a later height.
    pub daily_last_window_close: Mapping<u32, u64>,
}
