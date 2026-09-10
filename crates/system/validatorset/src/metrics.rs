//! Prometheus metrics for ValidatorSet state transitions.
//!
//! Emitted from the corresponding mutation paths in `runtime.rs` so
//! operators have realtime visibility into validator lifecycle without
//! having to poll on-chain state.
//!
//! Per-validator labels: `addr` is the validator address rendered as
//! `0x{40-char-hex}`. Cardinality is bounded by the configured maximum
//! validator count (`config_max_validators`, default 128).

use alloy_primitives::Address;
use metrics::{counter, gauge};

fn addr_label(addr: Address) -> String {
    format!("{addr:?}")
}

/// Per-validator current status, one of the values from
/// [`crate::runtime::status`]:
/// `0=UNINIT`, `1=REGISTERED`, `2=ACTIVE`, `3=EXITING`, `4=UNBONDING`, `5=INACTIVE`.
pub fn record_validator_status(addr: Address, status: u8) {
    gauge!("outbe_validator_status", "addr" => addr_label(addr)).set(f64::from(status));
}

/// Cumulative force-exit events per validator.
pub fn record_validator_force_exit(addr: Address) {
    counter!("outbe_validator_force_exit_total", "addr" => addr_label(addr)).increment(1);
}

/// Cumulative voluntary deactivations per validator.
pub fn record_validator_deactivate(addr: Address) {
    counter!("outbe_validator_deactivate_total", "addr" => addr_label(addr)).increment(1);
}

/// One registration event (first-time or re-register).
pub fn record_validator_register(addr: Address, reregister: bool) {
    counter!(
        "outbe_validator_register_total",
        "addr" => addr_label(addr),
        "kind" => if reregister { "reregister" } else { "first" },
    )
    .increment(1);
}

/// One DKG reshare activation; `transitioned_to_unbonding` is the
/// number of validators transitioned EXITING->UNBONDING this round.
pub fn record_reshared_set_activated(active_count: u32, transitioned_to_unbonding: usize) {
    counter!("outbe_reshared_set_activated_total").increment(1);
    gauge!("outbe_validator_active_set_size").set(f64::from(active_count));
    gauge!("outbe_last_reshare_unbonding_count").set(transitioned_to_unbonding as f64);
}

/// Aggregate validator-status counts. Sample once per relevant
/// transition; cheap because validator-set size is bounded.
pub fn record_aggregate_status_counts(active: usize, exiting: usize, unbonding: usize) {
    gauge!("outbe_validator_active_count").set(active as f64);
    gauge!("outbe_validator_exiting_count").set(exiting as f64);
    gauge!("outbe_validator_unbonding_count").set(unbonding as f64);
}

/// Pending-set-change flag. 0/1.
pub fn record_pending_set_change(pending: bool) {
    gauge!("outbe_validator_pending_set_change").set(if pending { 1.0 } else { 0.0 });
}

/// One certified freeze-height TEE expiry transition per affected validator.
pub fn record_validator_tee_expiry(addr: Address, action: &'static str) {
    counter!(
        "outbe_validator_tee_expiry_total",
        "addr" => addr_label(addr),
        "action" => action,
    )
    .increment(1);
}

/// Size of the most recently applied narrow TEE-expiry transition.
pub fn record_tee_expiry_exclusions(active_demoted: usize, pending_cleared: usize) {
    gauge!("outbe_last_tee_expired_active_demoted").set(active_demoted as f64);
    gauge!("outbe_last_tee_expired_pending_cleared").set(pending_cleared as f64);
}

/// One missing OCOMP result vote. The first miss opens the fixed recovery
/// window; repeats remain visible without implying another slash.
pub fn record_ocomp_miss(addr: Address, first_in_window: bool, recovery_deadline: u64) {
    counter!(
        "outbe_ocomp_vote_missed_total",
        "addr" => addr_label(addr),
        "kind" => if first_in_window { "first" } else { "repeat" },
    )
    .increment(1);
    record_ocomp_recovery_deadline(addr, recovery_deadline);
}

/// Publish one durable open-window deadline. The per-block sweep re-emits this
/// from chain state so a process restart cannot erase the alert series.
pub fn record_ocomp_recovery_deadline(addr: Address, recovery_deadline: u64) {
    gauge!("outbe_ocomp_recovery_deadline", "addr" => addr_label(addr))
        .set(recovery_deadline as f64);
}

/// One durable recovery-window resolution. The per-validator deadline is
/// cleared together with the outcome counter so dashboards never retain a
/// stale open deadline after restore, jail or lifecycle departure.
pub fn record_ocomp_recovery_resolution(addr: Address, outcome: &'static str) {
    clear_ocomp_recovery_deadline(addr);
    counter!("outbe_ocomp_recovery_resolved_total", "outcome" => outcome).increment(1);
}

/// Clears the deadline gauge when lifecycle cleanup removes an open window
/// outside the deadline-resolution path.
pub fn clear_ocomp_recovery_deadline(addr: Address) {
    gauge!("outbe_ocomp_recovery_deadline", "addr" => addr_label(addr)).set(0.0);
}

/// Aggregate result of the bounded per-block OCOMP recovery sweep. The block
/// number comes from the same execution context that decides restoration or
/// jail, so deadline alerts do not depend on the off-chain reader being alive.
pub fn record_ocomp_recovery_sweep(current_block: u64, remaining_open: u32) {
    gauge!("outbe_ocomp_recovery_block_number").set(current_block as f64);
    gauge!("outbe_ocomp_recovery_open_windows").set(f64::from(remaining_open));
}
