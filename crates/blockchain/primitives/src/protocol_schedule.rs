//! V2 protocol schedule - the single source of truth for V2 timing, sizing,
//! retention, evidence, and performance constants.
//!
//! Every field below is part of the V2 on-chain / off-chain operational
//! contract. Any change is hard-fork-equivalent and must be coordinated. This
//! struct must remain the only home of these values across the workspace; the
//! protocol_schedule_is_shared_by_node_evm_payload_codec_and_verifier test
//! locks that property.
//!
//! Field-by-field rationale:

/// Bucket boundaries (validator count) used by the Phase 1 preflight latency
/// histograms. Exported as a `pub const` because the metrics crate registers
/// histograms with a `&'static [u64]` at startup and cannot read from a
/// non-const value.
pub const PHASE1_PREFLIGHT_VALIDATOR_COUNT_BUCKETS: [u64; 5] = [10, 33, 64, 100, 200];

/// Single source of truth for V2 protocol constants.
///
/// Construction:
/// * Use [`OutbeProtocolSchedule::default`] to get the canonical pinned values.
/// * Custom values are only valid in tests; production paths must consume the
///   default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutbeProtocolSchedule {
    // ----- V2 activation -----
    /// Block height at which V2 Certified-Parent Accounting becomes active.
    /// `0` = greenfield (V2 from genesis).
    pub certified_parent_accounting_v2_height: u64,
    /// Block number at which the genesis bootstrap BoundaryOutcome is
    /// mandatory in the begin-zone. Block `1` under V2.
    pub genesis_bootstrap_block_number: u64,

    // ----- Certified-parent proof fetch -----
    /// Total budget for any single direct-parent proof fetch attempt.
    pub parent_proof_fetch_timeout_ms: u64,
    /// Max retries for direct-parent proof fetch (per proposer build).
    pub parent_proof_fetch_max_attempts: u32,
    /// Hard cap on bytes accepted from a single proof fetch response.
    pub parent_proof_fetch_max_bytes: usize,
    /// Minimum depth below the finalized tip that the certified-parent proof
    /// store must retain.
    pub proof_store_min_retention_depth_blocks: u64,

    // ----- Invalid-VRF slashing evidence -----
    /// Reject evidence whose child block is older than this many blocks behind
    /// the current tip.
    pub invalid_vrf_evidence_max_age_blocks: u64,
    /// Reject evidence whose serialized form exceeds this many bytes.
    pub invalid_vrf_evidence_max_bytes: usize,
    /// Reject evidence whose epoch is more than this many epochs behind the
    /// current consensus epoch.
    pub invalid_vrf_evidence_max_epoch_lag: u64,
    /// Heavy per-evidence base gas charged by every `SlashIndicator` BLS-evidence
    /// submission selector (double-proposal, conflicting-vote/notarize/finalize,
    /// nullify-finalize, invalid-VRF-proof, seed-partial-equivocation,
    /// invalid-seed-partial). Each verifier runs ~2+ BLS12-381 pairings plus
    /// ecrecover/storage reads; on the ZeroFee chain those would be near-free to
    /// spam, so this charges a heavy base proportional to that work and block gas
    /// then bounds how many evidence txs fit per block (complementing the
    /// ACTIVE-validator ACL added in). This struct is the single source of
    /// truth: `outbe_slashindicator::precompile::base_gas` reads it; do not
    /// duplicate the literal.
    ///
    /// `200_000` is the-chosen heavy base; it may be refined by measuring
    /// the worst-case verifier gas across committee sizes and applying
    /// `ceil_to_next_10_000(measured_worst_case_gas * 125 / 100)`. Any change is
    /// hard-fork-equivalent and is guarded by the
    /// [`vrf_evidence_base_gas_is_calibrated`] test (no `u64::MAX` placeholder may
    /// ship).
    pub slash_indicator_vrf_evidence_base_gas: u64,

    // ----- Performance budgets -----
    /// p99 budget for the Phase 1 preflight under a 100-validator set, in
    /// milliseconds.
    pub phase1_preflight_p99_budget_ms_n100: u64,
}

impl Default for OutbeProtocolSchedule {
    /// Pinned values. Any drift here is a hard-fork-equivalent
    /// change to operator behavior.
    fn default() -> Self {
        Self {
            certified_parent_accounting_v2_height: 0,
            genesis_bootstrap_block_number: 1,

            parent_proof_fetch_timeout_ms: 2_000,
            parent_proof_fetch_max_attempts: 3,
            parent_proof_fetch_max_bytes: 16 * 1024 * 1024,
            proof_store_min_retention_depth_blocks: 256,

            invalid_vrf_evidence_max_age_blocks: 2_048,
            invalid_vrf_evidence_max_bytes: 256 * 1024,
            invalid_vrf_evidence_max_epoch_lag: 1,
            slash_indicator_vrf_evidence_base_gas: 200_000,

            phase1_preflight_p99_budget_ms_n100: 25,
        }
    }
}
