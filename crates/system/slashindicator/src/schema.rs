use alloy_primitives::{Address, B256};
use outbe_macros::contract;
use outbe_primitives::addresses::SLASH_INDICATOR_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot};

/// EVM storage layout for the SlashIndicator precompile.
///
/// Storage slots:
///   0: config_proposer_misdemeanor_threshold - u64 (default 50)
///   1: config_proposer_felony_threshold      - u64 (default 150)
///   2: config_voter_misdemeanor_threshold    - u64 (default 500)
///   3: config_slash_amount_percent           - u64 (default 5)
///   4: config_evidence_reward_percent        - u64 (default 10)
///   5: proposer_miss_count                   - mapping(address => u64), per-epoch, resets
///   6: voter_miss_count                      - mapping(address => u64), per-epoch, resets
///   7: felony_count                          - mapping(address => u64), cumulative
/// 8: evidence_processed - mapping(B256 => bool), dedup
/// 9: voter_window_slashed - mapping(B256 => bool), per-finalized-block voter slash-window guard
/// 10: proposer_window_slashed - mapping(B256 => bool), per-finalized-block missed-proposer slash-window guard
///  11: invalid_vrf_evidence_processed        - mapping(B256 => bool) dedup keyed by `invalid_vrf_evidence_hash_v2(child_hash, phase1_tx_hash)`
///  12: config_voter_felony_threshold         - u64 (default 150); appended at the end to preserve the slot 0-11 layout
///  13: seed_partial_equivocation_processed   - mapping(B256 => bool) dedup keyed by `SeedPartialEquivocationEvidence::dedup_hash`
///  14: invalid_seed_partial_processed        - mapping(B256 => bool) dedup keyed by `InvalidSeedPartialEvidence::dedup_hash`
/// 15: slash_guard_ring - mapping(uint64 => B256), prune ring of finalized fb_hashes
/// 16: slash_guard_ring_seq - uint64, ring write cursor
#[contract(addr = SLASH_INDICATOR_ADDRESS)]
pub struct SlashIndicator {
    // Config slots (0-4)
    pub config_proposer_misdemeanor_threshold: Slot<u64>,
    pub config_proposer_felony_threshold: Slot<u64>,
    pub config_voter_misdemeanor_threshold: Slot<u64>,
    pub config_slash_amount_percent: Slot<u64>,
    pub config_evidence_reward_percent: Slot<u64>,

    // Per-validator miss counters (slots 5-6), reset each epoch
    pub proposer_miss_count: Mapping<Address, u64>,
    pub voter_miss_count: Mapping<Address, u64>,

    // Cumulative felony count (slot 7), never reset
    pub felony_count: Mapping<Address, u64>,

    // Evidence dedup - tracks processed evidence hashes (slot 8)
    pub evidence_processed: Mapping<B256, bool>,

    // per-finalized-block voter slash-window guard, keyed by
    // `metadata.finalized_block_hash`. The window-close absentee pass is atomic
    // per finalized block (the begin-zone system tx rolls back on revert), so a
    // single bool per `fb_hash` makes replays idempotent without an unbounded
    // per-voter nested mapping. Pruned by the `slash_guard_ring` (slots 15/16).
    pub voter_window_slashed: Mapping<B256, bool>,

    // per-finalized-block missed-proposer slash-window guard, keyed by
    // `fb_hash`. The Phase 1 missed-proposer pass processes the whole
    // `missed_proposers` list for one finalized parent atomically, so a single
    // bool per `fb_hash` is idempotent under metadata replay (duplicate
    // proposers across skipped views are still each slashed within the one
    // pass). Pruned by the `slash_guard_ring`.
    pub proposer_window_slashed: Mapping<B256, bool>,

    // dedup guard for `submitInvalidVrfProofEvidence`. Key is the
    // canonical evidence hash
    // `outbe_consensus::proof::invalid_vrf_evidence_hash_v2(child_hash, phase1_tx_hash)`.
    // A child block has exactly one Phase 1 system transaction, so this
    // pair encodes "one slash per (child, phase1)" - submitting the same
    // evidence twice reverts with "evidence already processed", matching
    // the precedent set by `evidence_processed` for double-proposal and
    // conflicting-vote evidence (slot 8).
    pub invalid_vrf_evidence_processed: Mapping<B256, bool>,

    // Config (late addition, slot 12): voter felony threshold. Appended at the
    // end so existing slots 0-11 keep their layout. `slash_voter` force-exits
    // and slashes a validator at multiples of this threshold; the accessor
    // returns the default (150) when the slot is unset (0), avoiding `count % 0`.
    pub config_voter_felony_threshold: Slot<u64>,

    // Dedup guard for `submitSeedPartialEquivocationEvidence` (slot 13). Key is
    // `SeedPartialEquivocationEvidence::dedup_hash` (order-independent in the two
    // partials, bound to round + material version). Replaying the same
    // equivocation reverts with "evidence already processed", matching the
    // double-proposal / conflicting-vote / invalid-VRF precedents.
    pub seed_partial_equivocation_processed: Mapping<B256, bool>,

    // Dedup guard for `submitInvalidSeedPartialEvidence` (slot 14). Key is
    // `InvalidSeedPartialEvidence::dedup_hash` (round + version + signer +
    // partial), so each distinct invalid partial slashes at most once.
    pub invalid_seed_partial_processed: Mapping<B256, bool>,

    // prune ring (slots 15/16) bounding `voter_window_slashed` and
    // `proposer_window_slashed` to the last `SLASH_GUARD_RETAIN` finalized
    // blocks. Driven once per finalized block from the Phase 1 path (which sees
    // every `fb_hash` exactly once as a direct parent); the entry evicted
    // `SLASH_GUARD_RETAIN` records ago has both window guards cleared. Retention
    // is far larger than the K-block late-finalize window, so no guard is
    // dropped while its block can still be replayed. `B256::ZERO` = empty slot.
    pub slash_guard_ring: Mapping<u64, B256>,
    pub slash_guard_ring_seq: Slot<u64>,
}
