//! Prometheus metrics for SlashIndicator state transitions.
//!
//! These gauges and counters are emitted from the corresponding
//! mutation paths in `runtime.rs` so operators can alert on miss-count
//! growth before the felony threshold is reached, and observe
//! cumulative slash/felony events over time.
//!
//! Per-validator labels: `addr` is the validator address rendered as
//! `0x{40-char-hex}`. Cardinality is bounded by the configured maximum
//! validator count (`config_max_validators`, default 128).

use alloy_primitives::Address;
use metrics::{counter, gauge};

fn addr_label(addr: Address) -> String {
    format!("{addr:?}")
}

/// Per-validator current-epoch proposer miss count. Resets at every
/// epoch boundary via `reset_epoch_counters`. Use [`record_proposer_miss_event`]
/// to increment the cumulative counter on every miss.
pub fn record_proposer_miss_count(addr: Address, count: u64) {
    gauge!("outbe_proposer_miss_count", "addr" => addr_label(addr)).set(count as f64);
}

/// Cumulative counter - one increment per `slash_proposer` call.
pub fn record_proposer_miss_event(addr: Address) {
    counter!("outbe_proposer_missed_views_total", "addr" => addr_label(addr)).increment(1);
}

/// Per-validator current-epoch voter miss count. Same reset semantics.
pub fn record_voter_miss_count(addr: Address, count: u64) {
    gauge!("outbe_voter_miss_count", "addr" => addr_label(addr)).set(count as f64);
}

/// Cumulative counter - one increment per `slash_voter` call.
pub fn record_voter_miss_event(addr: Address) {
    counter!("outbe_voter_missed_votes_total", "addr" => addr_label(addr)).increment(1);
}

/// Per-validator cumulative felony count (never resets).
pub fn record_felony_count(addr: Address, count: u64) {
    gauge!("outbe_felony_count", "addr" => addr_label(addr)).set(count as f64);
}

/// One slash event was applied to `addr`. `reason` is one of:
/// `proposer_felony` | `evidence_felony` | `byzantine` | `oracle_penalty`.
pub fn record_validator_slashed(addr: Address, reason: &'static str) {
    counter!(
        "outbe_validator_slashed_total",
        "addr" => addr_label(addr),
        "reason" => reason,
    )
    .increment(1);
}

/// Reset of per-epoch counters at an epoch boundary.
pub fn record_epoch_counters_reset(validator_count: usize) {
    counter!("outbe_epoch_counter_resets_total").increment(1);
    gauge!("outbe_last_epoch_counters_reset_validator_count").set(validator_count as f64);
}
