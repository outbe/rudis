//! Fail-closed capacity evidence validation for the bounded OCOMP PoC profile.
//!
//! This module deliberately models per-interface work and per-worker shard
//! bounds. It has no field that can cap the complete Tribute population of a
//! [`JobIntentV1`](crate::intent::JobIntentV1).

use std::collections::BTreeSet;

use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};

use crate::{
    generated_shape::{
        OCOMP_POC_CANDIDATE_LIMITS_V1, OCOMP_POC_DEVNET_MACHINE_V1, OCOMP_POC_HEADROOM_POLICY_V1,
    },
    profile::CapacityProfileV1,
};

/// Runtime CAS quota assigned to one OCOMP validator domain in the PoC.
///
/// The process launcher and OCM-26 capacity budget share this authority so a
/// benchmark cannot claim more retained artifact headroom than production
/// actually grants.
pub const OCOMP_POC_CAS_QUOTA_BYTES: u64 = 8_589_934_592;

/// Resource dimensions measured for one maximum-shaped public-path run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityWorkBillV1 {
    pub transaction_bytes: u64,
    pub block_bytes: u64,
    pub gas: u64,
    pub internal_work: u64,
    pub cpu_micros: u64,
    pub network_bytes: u64,
    pub assigned_memory_bytes: u64,
    pub disk_write_bytes: u64,
    pub cas_bytes: u64,
    pub block_processing_micros: u64,
    pub finality_latency_micros: u64,
}

impl CapacityWorkBillV1 {
    fn all_positive(self) -> bool {
        [
            self.transaction_bytes,
            self.block_bytes,
            self.gas,
            self.internal_work,
            self.cpu_micros,
            self.network_bytes,
            self.assigned_memory_bytes,
            self.disk_write_bytes,
            self.cas_bytes,
            self.block_processing_micros,
            self.finality_latency_micros,
        ]
        .into_iter()
        .all(|value| value > 0)
    }

    fn component_max(self, other: Self) -> Self {
        Self {
            transaction_bytes: self.transaction_bytes.max(other.transaction_bytes),
            block_bytes: self.block_bytes.max(other.block_bytes),
            gas: self.gas.max(other.gas),
            internal_work: self.internal_work.max(other.internal_work),
            cpu_micros: self.cpu_micros.max(other.cpu_micros),
            network_bytes: self.network_bytes.max(other.network_bytes),
            assigned_memory_bytes: self.assigned_memory_bytes.max(other.assigned_memory_bytes),
            disk_write_bytes: self.disk_write_bytes.max(other.disk_write_bytes),
            cas_bytes: self.cas_bytes.max(other.cas_bytes),
            block_processing_micros: self
                .block_processing_micros
                .max(other.block_processing_micros),
            finality_latency_micros: self
                .finality_latency_micros
                .max(other.finality_latency_micros),
        }
    }
}

/// Available resource budgets for the same dimensions as [`CapacityWorkBillV1`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityBudgetV1 {
    pub transaction_bytes: u64,
    pub block_bytes: u64,
    pub gas: u64,
    pub internal_work: u64,
    pub cpu_micros: u64,
    pub network_bytes: u64,
    pub assigned_memory_bytes: u64,
    pub disk_write_bytes: u64,
    pub cas_bytes: u64,
    pub block_processing_micros: u64,
    pub finality_latency_micros: u64,
}

impl CapacityBudgetV1 {
    fn all_positive(self) -> bool {
        [
            self.transaction_bytes,
            self.block_bytes,
            self.gas,
            self.internal_work,
            self.cpu_micros,
            self.network_bytes,
            self.assigned_memory_bytes,
            self.disk_write_bytes,
            self.cas_bytes,
            self.block_processing_micros,
            self.finality_latency_micros,
        ]
        .into_iter()
        .all(|value| value > 0)
    }
}

/// Observed facts for the exact runner that produced capacity evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedMachineFactsV1 {
    pub architecture: String,
    pub operating_system: String,
    pub logical_cpu_count: u64,
    pub physical_memory_bytes: u64,
    pub process_memory_limit_bytes: u64,
    pub root_disk_bytes: u64,
    pub free_workspace_bytes: u64,
    pub block_iops: u64,
    pub block_throughput_bytes_per_second: u64,
    pub pid1_is_systemd: bool,
    pub unified_cgroup_v2: bool,
    pub writable_resource_cgroup: bool,
    pub production_enclave_sgx_no_attest: bool,
}

impl ObservedMachineFactsV1 {
    /// Verifies that observed facts meet or exceed every frozen machine literal.
    pub fn validate(&self) -> Result<(), CapacityEvidenceError> {
        let required = OCOMP_POC_DEVNET_MACHINE_V1;
        require_machine(self.architecture == required.architecture, "architecture")?;
        require_machine(
            self.operating_system == required.operating_system,
            "operating system",
        )?;
        require_machine(
            self.logical_cpu_count >= required.logical_cpu_count,
            "logical CPU count",
        )?;
        require_machine(
            self.physical_memory_bytes >= required.nominal_memory_bytes,
            "physical memory",
        )?;
        require_machine(
            self.process_memory_limit_bytes >= required.minimum_process_memory_bytes,
            "process memory limit",
        )?;
        require_machine(
            self.root_disk_bytes >= required.nominal_root_disk_bytes,
            "root disk",
        )?;
        require_machine(
            self.free_workspace_bytes >= required.minimum_free_workspace_bytes,
            "free workspace",
        )?;
        require_machine(self.block_iops >= required.minimum_block_iops, "block IOPS")?;
        require_machine(
            self.block_throughput_bytes_per_second
                >= required.minimum_block_throughput_bytes_per_second,
            "block throughput",
        )?;
        require_machine(self.pid1_is_systemd, "systemd PID 1")?;
        require_machine(self.unified_cgroup_v2, "unified cgroup v2")?;
        require_machine(self.writable_resource_cgroup, "writable resource cgroup")?;
        require_machine(
            self.production_enclave_sgx_no_attest,
            "production enclave under real SGX without attestation",
        )?;
        Ok(())
    }
}

/// One validator's exact canonical q-forming block-processing observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityValidatorBlockProcessingV1 {
    pub validator_index: u16,
    pub block_number: u64,
    pub block_hash: B256,
    pub elapsed_micros: u64,
}

/// Exact production startup-recovery outcome retained by one cold run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityRecoveredGenerationBindingV1 {
    pub worldwide_day: u32,
    pub generation: u64,
    pub job_id: B256,
    pub program_semantics_hash: B256,
    pub nod_root: B256,
    pub bucket_root: B256,
    pub output_manifest_root: B256,
    pub tribute_count: u32,
    pub nod_count: u32,
    pub bucket_count: u32,
    pub nod_amount_total: U256,
    pub nod_gratis_consumed: U256,
    pub issued_at: u64,
    pub result_evidence_hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
}

/// Exact production startup-recovery outcome retained by one cold run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityHistoricalReplayBindingV1 {
    pub validator_index: u16,
    pub first_missing_block_number: u64,
    pub target_block_number: u64,
    pub target_block_hash: B256,
    pub replayed_block_count: u64,
    pub elapsed_micros: u64,
    pub recovered_result_digest: B256,
    pub recovered_generation: CapacityRecoveredGenerationBindingV1,
}

impl CapacityHistoricalReplayBindingV1 {
    fn validate(&self, run: &CapacityRunBindingV1) -> Result<(), CapacityEvidenceError> {
        let expected_count = self
            .target_block_number
            .checked_sub(self.first_missing_block_number)
            .and_then(|span| span.checked_add(1));
        let generation = &self.recovered_generation;
        if usize::from(self.validator_index) >= run.validator_block_processing.len()
            || self.first_missing_block_number == 0
            || self.first_missing_block_number > run.q_forming_block_number
            || self.target_block_number < run.finalized_block_number
            || self.target_block_hash.is_zero()
            || expected_count != Some(self.replayed_block_count)
            || self.elapsed_micros == 0
            || self.recovered_result_digest != run.result_digest
            || generation.worldwide_day == 0
            || generation.generation == 0
            || generation.job_id != run.job_id
            || generation.program_semantics_hash.is_zero()
            || generation.nod_root.is_zero()
            || generation.bucket_root.is_zero()
            || generation.output_manifest_root.is_zero()
            || u64::from(generation.tribute_count) != run.tribute_count
            || u64::from(generation.nod_count) != run.nod_count
            || generation.bucket_count == 0
            || generation.nod_amount_total.is_zero()
            || generation.issued_at == 0
            || generation.result_evidence_hash.is_zero()
            || generation.block_number != run.q_forming_block_number
            || generation.block_hash != run.q_forming_block_hash
        {
            return Err(CapacityEvidenceError::InvalidHistoricalReplayBinding { ordinal: 0 });
        }
        Ok(())
    }
}

/// Exact public and historical-recovery identity for one cold run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityRunBindingV1 {
    pub scenario_evidence_sha256: B256,
    pub job_id: B256,
    pub result_digest: B256,
    pub q_forming_transaction_hash: B256,
    pub q_forming_block_number: u64,
    pub q_forming_block_hash: B256,
    pub finalized_block_number: u64,
    pub finalized_block_hash: B256,
    pub tribute_count: u64,
    pub nod_count: u64,
    pub worker_shard_count: u64,
    pub validator_block_processing: Vec<CapacityValidatorBlockProcessingV1>,
    pub historical_replay: CapacityHistoricalReplayBindingV1,
}

impl CapacityRunBindingV1 {
    fn validate(&self) -> Result<(), CapacityEvidenceError> {
        if [
            self.scenario_evidence_sha256,
            self.job_id,
            self.result_digest,
            self.q_forming_transaction_hash,
            self.q_forming_block_hash,
            self.finalized_block_hash,
        ]
        .into_iter()
        .any(|value| value.is_zero())
        {
            return Err(CapacityEvidenceError::MissingIdentity);
        }
        if self.q_forming_block_number == 0
            || self.finalized_block_number < self.q_forming_block_number
            || self.validator_block_processing.is_empty()
            || self
                .validator_block_processing
                .iter()
                .enumerate()
                .any(|(index, observation)| {
                    usize::from(observation.validator_index) != index
                        || observation.block_number != self.q_forming_block_number
                        || observation.block_hash != self.q_forming_block_hash
                        || observation.elapsed_micros == 0
                })
        {
            return Err(CapacityEvidenceError::InvalidPublicCapacityBinding { ordinal: 0 });
        }
        let shard_capacity =
            u32::try_from(OCOMP_POC_CANDIDATE_LIMITS_V1.max_tributes_per_work_shard)
                .map_err(|_| CapacityEvidenceError::GeneratedLimitOverflow)?;
        let expected_population = u64::from(shard_capacity)
            .checked_add(1)
            .ok_or(CapacityEvidenceError::GeneratedLimitOverflow)?;
        if self.tribute_count != expected_population
            || self.nod_count != expected_population
            || self.worker_shard_count != worker_shard_count(expected_population, shard_capacity)?
        {
            return Err(CapacityEvidenceError::InvalidPublicCapacityBinding { ordinal: 0 });
        }
        self.historical_replay.validate(self)?;
        Ok(())
    }
}

/// One cold public-path observation. A failed run stays failed; it cannot be
/// retried away or replaced by another ordinal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityColdRunV1 {
    pub ordinal: u8,
    pub source_revision: B256,
    pub artifact_set_hash: B256,
    pub cold_namespace_hash: B256,
    pub binding: CapacityRunBindingV1,
    pub succeeded: bool,
    pub retried: bool,
    pub work: CapacityWorkBillV1,
}

/// Complete input accepted by the production capacity-profile generator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityEvidenceV1 {
    pub machine: ObservedMachineFactsV1,
    pub budget: CapacityBudgetV1,
    pub runs: Vec<CapacityColdRunV1>,
}

/// Validated evidence returned only after all frozen checks pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCapacityEvidenceV1 {
    pub source_revision: B256,
    pub artifact_set_hash: B256,
    pub worst_work: CapacityWorkBillV1,
}

impl CapacityEvidenceV1 {
    /// Validates the exact machine, five immutable cold runs and 20% headroom.
    pub fn verify(&self) -> Result<VerifiedCapacityEvidenceV1, CapacityEvidenceError> {
        self.machine.validate()?;
        if !self.budget.all_positive() {
            return Err(CapacityEvidenceError::ZeroBudget);
        }
        let expected_runs = usize::try_from(OCOMP_POC_HEADROOM_POLICY_V1.benchmark_cold_runs)
            .map_err(|_| CapacityEvidenceError::InvalidRunCount)?;
        if self.runs.len() != expected_runs {
            return Err(CapacityEvidenceError::InvalidRunCount);
        }

        let first = self
            .runs
            .first()
            .ok_or(CapacityEvidenceError::InvalidRunCount)?;
        if first.source_revision.is_zero()
            || first.artifact_set_hash.is_zero()
            || first.cold_namespace_hash.is_zero()
        {
            return Err(CapacityEvidenceError::MissingIdentity);
        }

        let mut ordinals = BTreeSet::new();
        let mut namespaces = BTreeSet::new();
        let mut scenario_evidence = BTreeSet::new();
        let mut worst = first.work;
        for run in &self.runs {
            if !ordinals.insert(run.ordinal) {
                return Err(CapacityEvidenceError::DuplicateRunOrdinal);
            }
            if run.ordinal == 0 || usize::from(run.ordinal) > expected_runs {
                return Err(CapacityEvidenceError::InvalidRunOrdinal);
            }
            if run.source_revision != first.source_revision
                || run.artifact_set_hash != first.artifact_set_hash
            {
                return Err(CapacityEvidenceError::MixedArtifactSet);
            }
            if run.cold_namespace_hash.is_zero() || !namespaces.insert(run.cold_namespace_hash) {
                return Err(CapacityEvidenceError::ReusedColdNamespace);
            }
            if !scenario_evidence.insert(run.binding.scenario_evidence_sha256) {
                return Err(CapacityEvidenceError::ReusedScenarioEvidence);
            }
            if let Err(error) = run.binding.validate() {
                return Err(match error {
                    CapacityEvidenceError::InvalidPublicCapacityBinding { .. } => {
                        CapacityEvidenceError::InvalidPublicCapacityBinding {
                            ordinal: run.ordinal,
                        }
                    }
                    CapacityEvidenceError::InvalidHistoricalReplayBinding { .. } => {
                        CapacityEvidenceError::InvalidHistoricalReplayBinding {
                            ordinal: run.ordinal,
                        }
                    }
                    other => other,
                });
            }
            if !run.succeeded {
                return Err(CapacityEvidenceError::FailedRun {
                    ordinal: run.ordinal,
                });
            }
            if run.retried {
                return Err(CapacityEvidenceError::RetriedRun {
                    ordinal: run.ordinal,
                });
            }
            if !run.work.all_positive() {
                return Err(CapacityEvidenceError::ZeroWorkBill {
                    ordinal: run.ordinal,
                });
            }
            if run
                .binding
                .validator_block_processing
                .iter()
                .map(|observation| observation.elapsed_micros)
                .max()
                != Some(run.work.block_processing_micros)
            {
                return Err(CapacityEvidenceError::InvalidPublicCapacityBinding {
                    ordinal: run.ordinal,
                });
            }
            verify_headroom(run.ordinal, run.work, self.budget)?;
            worst = worst.component_max(run.work);
        }
        if ordinals.len() != expected_runs
            || !(1..=expected_runs).all(|ordinal| ordinals.contains(&(ordinal as u8)))
        {
            return Err(CapacityEvidenceError::InvalidRunOrdinal);
        }

        Ok(VerifiedCapacityEvidenceV1 {
            source_revision: first.source_revision,
            artifact_set_hash: first.artifact_set_hash,
            worst_work: worst,
        })
    }
}

impl VerifiedCapacityEvidenceV1 {
    /// Generates the fork-pinned capacity profile from already verified
    /// measurements and a content-addressed final limits manifest.
    pub fn capacity_profile(
        &self,
        profile_id: B256,
        generated_limits_manifest_hash: B256,
        result_deadline_blocks: u64,
    ) -> Result<CapacityProfileV1, CapacityEvidenceError> {
        if profile_id.is_zero()
            || generated_limits_manifest_hash.is_zero()
            || result_deadline_blocks == 0
        {
            return Err(CapacityEvidenceError::MissingIdentity);
        }
        let candidate = OCOMP_POC_CANDIDATE_LIMITS_V1;
        Ok(CapacityProfileV1 {
            profile_id,
            max_tributes_per_work_shard: u32::try_from(candidate.max_tributes_per_work_shard)
                .map_err(|_| CapacityEvidenceError::GeneratedLimitOverflow)?,
            max_workers_per_domain: 4,
            max_intents_per_block: 1,
            max_activations_per_block: 1,
            max_ready_inspections_per_block: 1,
            max_expirations_per_block: 1,
            ready_backoff_blocks: 1,
            max_reference_currencies: 8,
            max_oracle_wwd_pair_entries: u32::try_from(candidate.max_oracle_wwd_pair_entries)
                .map_err(|_| CapacityEvidenceError::GeneratedLimitOverflow)?,
            max_active_scurve_entries: u32::try_from(candidate.max_active_scurve_entries)
                .map_err(|_| CapacityEvidenceError::GeneratedLimitOverflow)?,
            result_deadline_blocks,
            source_retention_after_terminal_blocks: candidate
                .source_retention_after_terminal_blocks,
            generated_limits_manifest_hash,
        })
    }
}

/// Returns the exact number of canonical worker shards without allocating a
/// population-sized plan.
pub fn worker_shard_count(
    tribute_count: u64,
    max_tributes_per_work_shard: u32,
) -> Result<u64, CapacityEvidenceError> {
    if max_tributes_per_work_shard == 0 {
        return Err(CapacityEvidenceError::ZeroShardCapacity);
    }
    if tribute_count == 0 {
        return Ok(0);
    }
    let capacity = u64::from(max_tributes_per_work_shard);
    Ok(1 + (tribute_count - 1) / capacity)
}

/// Deterministic worst-case work reserved by one public result-vote
/// transaction. Every vote is admitted as potentially q-forming, so the
/// formula includes the four atomic root transitions and the current
/// validator's signature verification before any state-dependent branching.
pub fn result_vote_internal_work(
    canonical_vote_bytes: usize,
) -> Result<u64, CapacityEvidenceError> {
    let candidate = OCOMP_POC_CANDIDATE_LIMITS_V1;
    let canonical_vote_bytes = u64::try_from(canonical_vote_bytes)
        .map_err(|_| CapacityEvidenceError::InternalWorkOverflow)?;
    if canonical_vote_bytes == 0 || canonical_vote_bytes > candidate.max_result_vote_bytes {
        return Err(CapacityEvidenceError::ResultVoteBytesExceeded);
    }
    let input_work = candidate
        .activation_per_input_byte_gas
        .checked_mul(canonical_vote_bytes)
        .ok_or(CapacityEvidenceError::InternalWorkOverflow)?;
    let root_work = candidate
        .activation_per_root_transition_gas
        .checked_mul(candidate.max_activation_root_transitions)
        .ok_or(CapacityEvidenceError::InternalWorkOverflow)?;
    let signature_work = candidate
        .activation_per_signature_gas
        .checked_mul(1)
        .ok_or(CapacityEvidenceError::InternalWorkOverflow)?;
    let total = candidate
        .activation_base_gas
        .checked_add(input_work)
        .and_then(|value| value.checked_add(root_work))
        .and_then(|value| value.checked_add(signature_work))
        .ok_or(CapacityEvidenceError::InternalWorkOverflow)?;
    if total > candidate.max_activation_internal_work {
        return Err(CapacityEvidenceError::InternalWorkLimitExceeded {
            used: total,
            limit: candidate.max_activation_internal_work,
        });
    }
    Ok(total)
}

fn verify_headroom(
    ordinal: u8,
    work: CapacityWorkBillV1,
    budget: CapacityBudgetV1,
) -> Result<(), CapacityEvidenceError> {
    for (dimension, used, available) in [
        (
            "transaction bytes",
            work.transaction_bytes,
            budget.transaction_bytes,
        ),
        ("block bytes", work.block_bytes, budget.block_bytes),
        ("gas", work.gas, budget.gas),
        ("internal work", work.internal_work, budget.internal_work),
        ("CPU time", work.cpu_micros, budget.cpu_micros),
        ("network bytes", work.network_bytes, budget.network_bytes),
        (
            "assigned memory",
            work.assigned_memory_bytes,
            budget.assigned_memory_bytes,
        ),
        (
            "disk writes",
            work.disk_write_bytes,
            budget.disk_write_bytes,
        ),
        ("CAS bytes", work.cas_bytes, budget.cas_bytes),
        (
            "block processing time",
            work.block_processing_micros,
            budget.block_processing_micros,
        ),
        (
            "finality latency",
            work.finality_latency_micros,
            budget.finality_latency_micros,
        ),
    ] {
        if !within_required_headroom(used, available) {
            return Err(CapacityEvidenceError::InsufficientHeadroom {
                ordinal,
                dimension,
                used,
                available,
            });
        }
    }
    Ok(())
}

fn within_required_headroom(used: u64, available: u64) -> bool {
    let required = u128::from(OCOMP_POC_HEADROOM_POLICY_V1.required_headroom_basis_points);
    let allowed = 10_000_u128.saturating_sub(required);
    u128::from(used) * 10_000 <= u128::from(available) * allowed
}

fn require_machine(condition: bool, fact: &'static str) -> Result<(), CapacityEvidenceError> {
    if condition {
        Ok(())
    } else {
        Err(CapacityEvidenceError::MachineProfile { fact })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CapacityEvidenceError {
    #[error("machine does not satisfy frozen OCOMP profile: {fact}")]
    MachineProfile { fact: &'static str },
    #[error("capacity budget contains a zero dimension")]
    ZeroBudget,
    #[error("capacity evidence must contain exactly five cold runs")]
    InvalidRunCount,
    #[error("capacity run ordinal is outside the exact 1..=5 set")]
    InvalidRunOrdinal,
    #[error("capacity run ordinal is duplicated")]
    DuplicateRunOrdinal,
    #[error("capacity evidence is missing a content identity")]
    MissingIdentity,
    #[error("capacity evidence mixes source revisions or artifact sets")]
    MixedArtifactSet,
    #[error("capacity evidence reuses a cold namespace")]
    ReusedColdNamespace,
    #[error("capacity evidence reuses a public scenario record")]
    ReusedScenarioEvidence,
    #[error("capacity cold run {ordinal} is not bound to the public S+1 path")]
    InvalidPublicCapacityBinding { ordinal: u8 },
    #[error("capacity cold run {ordinal} lacks an exact historical CE replay span")]
    InvalidHistoricalReplayBinding { ordinal: u8 },
    #[error("capacity cold run {ordinal} failed")]
    FailedRun { ordinal: u8 },
    #[error("capacity cold run {ordinal} was retried")]
    RetriedRun { ordinal: u8 },
    #[error("capacity cold run {ordinal} contains a zero work dimension")]
    ZeroWorkBill { ordinal: u8 },
    #[error(
        "capacity cold run {ordinal} lacks 20% headroom for {dimension}: used {used}, available {available}"
    )]
    InsufficientHeadroom {
        ordinal: u8,
        dimension: &'static str,
        used: u64,
        available: u64,
    },
    #[error("generated capacity limit does not fit its protocol field")]
    GeneratedLimitOverflow,
    #[error("worker-shard capacity must be non-zero")]
    ZeroShardCapacity,
    #[error("canonical result-vote bytes exceed the generated capacity bound")]
    ResultVoteBytesExceeded,
    #[error("result-vote internal-work arithmetic overflowed")]
    InternalWorkOverflow,
    #[error("result-vote internal work {used} exceeds generated limit {limit}")]
    InternalWorkLimitExceeded { used: u64, limit: u64 },
}
