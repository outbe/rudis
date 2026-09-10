//! V2 `OutbeProtocolSchedule` invariants.
//!
//! Each test locks one field or class of fields so that drift is caught at
//! merge time, not at the boundary where the field is consumed.

use outbe_primitives::protocol_schedule::{
    OutbeProtocolSchedule, PHASE1_PREFLIGHT_VALIDATOR_COUNT_BUCKETS,
};

#[test]
fn protocol_schedule_v2_height_is_zero() {
    let s = OutbeProtocolSchedule::default();
    assert_eq!(
        s.certified_parent_accounting_v2_height, 0,
        "V2 must be greenfield-active (height 0); any non-zero value is a hard-fork-equivalent change",
    );
    assert_eq!(
        s.genesis_bootstrap_block_number, 1,
        "Genesis bootstrap BoundaryOutcome must ride in block 1 under V2",
    );
}

#[test]
fn protocol_schedule_parent_proof_fetch_bounds_are_shared() {
    let s = OutbeProtocolSchedule::default();
    assert_eq!(s.parent_proof_fetch_timeout_ms, 2_000);
    assert_eq!(s.parent_proof_fetch_max_attempts, 3);
    assert_eq!(s.parent_proof_fetch_max_bytes, 16 * 1024 * 1024);
    assert_eq!(s.proof_store_min_retention_depth_blocks, 256);

    assert_eq!(s.invalid_vrf_evidence_max_age_blocks, 2_048);
    assert_eq!(s.invalid_vrf_evidence_max_bytes, 256 * 1024);
    assert_eq!(s.invalid_vrf_evidence_max_epoch_lag, 1);

    assert_eq!(s.phase1_preflight_p99_budget_ms_n100, 25);
    assert_eq!(
        PHASE1_PREFLIGHT_VALIDATOR_COUNT_BUCKETS,
        [10, 33, 64, 100, 200]
    );
}

#[test]
fn protocol_schedule_is_shared_by_node_evm_payload_codec_and_verifier() {
    // Compile-time anchor: every consumer-relevant field must be reachable
    // from the crate root and addressable as `u64` / `u32` / `usize`. If any
    // future refactor moves a field out of `OutbeProtocolSchedule`, this test
    // stops compiling.
    let s = OutbeProtocolSchedule::default();
    let _certified_v2_height: u64 = s.certified_parent_accounting_v2_height;
    let _genesis_bootstrap_block_number: u64 = s.genesis_bootstrap_block_number;
    let _parent_proof_fetch_timeout_ms: u64 = s.parent_proof_fetch_timeout_ms;
    let _parent_proof_fetch_max_attempts: u32 = s.parent_proof_fetch_max_attempts;
    let _parent_proof_fetch_max_bytes: usize = s.parent_proof_fetch_max_bytes;
    let _proof_store_min_retention_depth_blocks: u64 = s.proof_store_min_retention_depth_blocks;
    let _invalid_vrf_evidence_max_age_blocks: u64 = s.invalid_vrf_evidence_max_age_blocks;
    let _invalid_vrf_evidence_max_bytes: usize = s.invalid_vrf_evidence_max_bytes;
    let _invalid_vrf_evidence_max_epoch_lag: u64 = s.invalid_vrf_evidence_max_epoch_lag;
    let _slash_indicator_vrf_evidence_base_gas: u64 = s.slash_indicator_vrf_evidence_base_gas;
    let _phase1_preflight_p99_budget_ms_n100: u64 = s.phase1_preflight_p99_budget_ms_n100;
    let _buckets: &'static [u64] = &PHASE1_PREFLIGHT_VALIDATOR_COUNT_BUCKETS;
}

/// Merge-to-main gate: no `u64::MAX` reject-everything placeholder may
/// ship for the evidence base gas. The value was calibrated to the heavy
/// base (`200_000`) and wired into `outbe_slashindicator::precompile::base_gas`,
/// so this is now a live guard rather than an `#[ignore]`-tagged tripwire.
#[test]
fn vrf_evidence_base_gas_is_calibrated() {
    let s = OutbeProtocolSchedule::default();
    assert_ne!(
        s.slash_indicator_vrf_evidence_base_gas,
        u64::MAX,
        "evidence base gas must not be the u64::MAX reject-everything placeholder",
    );
    assert_eq!(
        s.slash_indicator_vrf_evidence_base_gas, 200_000,
        "evidence base gas is the-chosen heavy base; any change is hard-fork-equivalent",
    );
}
