//! Capacity budgets and deterministic profile encoding for OCOMP.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use eyre::{ensure, Context, Result};
use outbe_chain_constants::DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS as OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS;
use outbe_consensus::{
    config::MAX_P2P_MESSAGE_SIZE,
    timing::{DEFAULT_CERTIFICATION_TIMEOUT_MS, DEFAULT_LEADER_TIMEOUT_MS},
};
use outbe_ocomp_protocol::{
    capacity::{CapacityBudgetV1, VerifiedCapacityEvidenceV1, OCOMP_POC_CAS_QUOTA_BYTES},
    generated_shape::{
        OCOMP_CAPACITY_PROFILE_ID_HEX, OCOMP_POC_CANDIDATE_LIMITS_V1, OCOMP_POC_DEVNET_MACHINE_V1,
    },
    profile::{poc_schema_limits, CapacityProfileV1},
};
use outbe_primitives::consensus::OUTBE_MAX_BLOCK_SIZE;
use serde::Serialize;
use sha2::{Digest, Sha256};

const GENERATED_CAPACITY_SCHEMA_VERSION: u16 = 1;
const GENERATED_CAPACITY_KIND: &str = "outbe-ocomp-generated-capacity-v1";
#[cfg(test)]
const CAPACITY_CPU_QUOTA_PERCENT: u16 = 400;
const OCOMP_POC_BLOCK_GAS_LIMIT: u64 = 30_000_000;

#[derive(Debug, Serialize)]
struct GeneratedCapacityManifestV1 {
    schema_version: u16,
    kind: &'static str,
    source_revision: B256,
    artifact_set_hash: B256,
    capacity_evidence_sha256: B256,
    generated_limits_manifest_sha256: B256,
    capacity_profile_id: B256,
    capacity_profile_ocb1_sha256: B256,
    capacity_profile_ocb1_hex: String,
    capacity_profile: CapacityProfileDocumentV1,
    worst_work: outbe_ocomp_protocol::capacity::CapacityWorkBillV1,
}

#[derive(Debug, Serialize)]
struct CapacityProfileDocumentV1 {
    profile_id: B256,
    max_tributes_per_work_shard: u32,
    max_workers_per_domain: u8,
    max_intents_per_block: u8,
    max_activations_per_block: u8,
    max_ready_inspections_per_block: u8,
    max_expirations_per_block: u8,
    ready_backoff_blocks: u64,
    max_reference_currencies: u16,
    max_oracle_wwd_pair_entries: u32,
    max_active_scurve_entries: u32,
    result_deadline_blocks: u64,
    source_retention_after_terminal_blocks: u64,
    generated_limits_manifest_hash: B256,
}

impl From<CapacityProfileV1> for CapacityProfileDocumentV1 {
    fn from(profile: CapacityProfileV1) -> Self {
        Self {
            profile_id: profile.profile_id,
            max_tributes_per_work_shard: profile.max_tributes_per_work_shard,
            max_workers_per_domain: profile.max_workers_per_domain,
            max_intents_per_block: profile.max_intents_per_block,
            max_activations_per_block: profile.max_activations_per_block,
            max_ready_inspections_per_block: profile.max_ready_inspections_per_block,
            max_expirations_per_block: profile.max_expirations_per_block,
            ready_backoff_blocks: profile.ready_backoff_blocks,
            max_reference_currencies: profile.max_reference_currencies,
            max_oracle_wwd_pair_entries: profile.max_oracle_wwd_pair_entries,
            max_active_scurve_entries: profile.max_active_scurve_entries,
            result_deadline_blocks: profile.result_deadline_blocks,
            source_retention_after_terminal_blocks: profile.source_retention_after_terminal_blocks,
            generated_limits_manifest_hash: profile.generated_limits_manifest_hash,
        }
    }
}

pub fn publish_budget(repository_root: &Path, output_path: &Path) -> Result<()> {
    let output_path = resolve(repository_root, output_path);
    let budget = frozen_capacity_budget()?;
    let value = serde_json::to_value(budget)?;
    publish_new_json(&output_path, &value)
}

fn frozen_capacity_budget() -> Result<CapacityBudgetV1> {
    let validation_window_ms = DEFAULT_CERTIFICATION_TIMEOUT_MS
        .checked_sub(DEFAULT_LEADER_TIMEOUT_MS)
        .ok_or_else(|| eyre::eyre!("OCOMP PoC validation window underflows"))?;
    ensure!(
        validation_window_ms > 0,
        "OCOMP PoC validation window must be positive"
    );
    let finality_latency_micros = OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS
        .checked_mul(DEFAULT_CERTIFICATION_TIMEOUT_MS)
        .and_then(|value| value.checked_mul(1_000))
        .ok_or_else(|| eyre::eyre!("OCOMP PoC finality budget overflows"))?;
    let cpu_micros = OCOMP_POC_DEVNET_MACHINE_V1
        .logical_cpu_count
        .checked_mul(finality_latency_micros)
        .ok_or_else(|| eyre::eyre!("OCOMP PoC CPU budget overflows"))?;
    let validator_count = u64::from(outbe_consensus::bls::MAX_VALIDATORS);
    let directed_committee_edges = validator_count
        .checked_mul(validator_count.saturating_sub(1))
        .ok_or_else(|| eyre::eyre!("consensus validator edge count overflows"))?;
    let network_bytes = u64::from(MAX_P2P_MESSAGE_SIZE)
        .checked_mul(directed_committee_edges)
        .and_then(|value| value.checked_mul(OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS))
        .ok_or_else(|| eyre::eyre!("OCOMP PoC network budget overflows"))?;
    Ok(CapacityBudgetV1 {
        transaction_bytes: u64::try_from(OUTBE_MAX_BLOCK_SIZE)
            .wrap_err("OCOMP block size exceeds u64")?,
        block_bytes: u64::try_from(OUTBE_MAX_BLOCK_SIZE)
            .wrap_err("OCOMP block size exceeds u64")?,
        gas: OCOMP_POC_BLOCK_GAS_LIMIT,
        internal_work: OCOMP_POC_CANDIDATE_LIMITS_V1.max_activation_internal_work,
        cpu_micros,
        network_bytes,
        assigned_memory_bytes: OCOMP_POC_DEVNET_MACHINE_V1.minimum_process_memory_bytes,
        disk_write_bytes: OCOMP_POC_DEVNET_MACHINE_V1.minimum_free_workspace_bytes,
        cas_bytes: OCOMP_POC_CAS_QUOTA_BYTES,
        block_processing_micros: validation_window_ms
            .checked_mul(1_000)
            .ok_or_else(|| eyre::eyre!("OCOMP PoC block-processing budget overflows"))?,
        finality_latency_micros,
    })
}

fn publish_new_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = create_new_file(path)?;
    file.write_all(&bytes)
        .wrap_err_with(|| format!("write immutable capacity record {}", path.display()))?;
    file.sync_all()
        .wrap_err_with(|| format!("sync immutable capacity record {}", path.display()))
}

fn create_new_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("create immutable capacity file {}", path.display()))
}

pub fn generate(
    evidence_bytes: &[u8],
    limits_manifest_bytes: &[u8],
    verified: VerifiedCapacityEvidenceV1,
) -> Result<Vec<u8>> {
    let evidence_sha256 = sha256(evidence_bytes);
    let generated_limits_manifest_sha256 = sha256(limits_manifest_bytes);
    let capacity_profile_id = parse_b256(OCOMP_CAPACITY_PROFILE_ID_HEX)
        .wrap_err("parse generated capacity profile id")?;
    let profile = verified.capacity_profile(
        capacity_profile_id,
        generated_limits_manifest_sha256,
        OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
    )?;
    let canonical = profile
        .encode_canonical(&poc_schema_limits())
        .wrap_err("encode canonical capacity profile")?;
    let document = GeneratedCapacityManifestV1 {
        schema_version: GENERATED_CAPACITY_SCHEMA_VERSION,
        kind: GENERATED_CAPACITY_KIND,
        source_revision: verified.source_revision,
        artifact_set_hash: verified.artifact_set_hash,
        capacity_evidence_sha256: evidence_sha256,
        generated_limits_manifest_sha256,
        capacity_profile_id,
        capacity_profile_ocb1_sha256: sha256(&canonical),
        capacity_profile_ocb1_hex: hex::encode(canonical),
        capacity_profile: profile.into(),
        worst_work: verified.worst_work,
    };
    let mut encoded = serde_json::to_vec_pretty(&document)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn resolve(repository_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repository_root.join(path)
    }
}

fn parse_b256(value: &str) -> Result<B256> {
    let bytes = hex::decode(value)?;
    ensure!(bytes.len() == B256::len_bytes(), "expected 32-byte digest");
    Ok(B256::from_slice(&bytes))
}

fn sha256(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_ocomp_protocol::capacity::{
        CapacityBudgetV1, CapacityColdRunV1, CapacityEvidenceV1, CapacityRunBindingV1,
        CapacityValidatorBlockProcessingV1, CapacityWorkBillV1, ObservedMachineFactsV1,
    };
    #[test]
    fn ocm_cap_001_generation_is_deterministic_and_bound_to_exact_inputs() {
        let evidence = evidence();
        let evidence_bytes = serde_json::to_vec_pretty(&evidence).unwrap();
        let verified = evidence.verify().unwrap();
        let first = generate(&evidence_bytes, b"{\"limits\":1}\n", verified.clone()).unwrap();
        let second = generate(&evidence_bytes, b"{\"limits\":1}\n", verified).unwrap();
        assert_eq!(first, second);

        let changed = generate(
            &evidence_bytes,
            b"{\"limits\":2}\n",
            evidence.verify().unwrap(),
        )
        .unwrap();
        assert_ne!(first, changed);

        let document: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(
            document["capacity_profile"]["max_tributes_per_work_shard"],
            256
        );
        assert!(
            document["capacity_profile"]
                .get("max_pending_jobs")
                .is_none(),
            "capacity artifacts must not publish an OCOMP-specific live-job limit"
        );
        assert_eq!(
            document["capacity_profile_ocb1_hex"]
                .as_str()
                .unwrap()
                .len()
                % 2,
            0
        );
    }
    #[test]
    fn ocm_cap_001_budget_is_derived_from_frozen_runtime_authorities() {
        let budget = frozen_capacity_budget().unwrap();
        assert_eq!(
            budget.transaction_bytes,
            u64::try_from(OUTBE_MAX_BLOCK_SIZE).unwrap()
        );
        assert_eq!(budget.block_bytes, budget.transaction_bytes);
        assert_eq!(budget.gas, OCOMP_POC_BLOCK_GAS_LIMIT);
        assert_eq!(
            budget.internal_work,
            OCOMP_POC_CANDIDATE_LIMITS_V1.max_activation_internal_work
        );
        let expected_finality_latency_micros =
            OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS * DEFAULT_CERTIFICATION_TIMEOUT_MS * 1_000;
        assert_eq!(
            budget.cpu_micros,
            OCOMP_POC_DEVNET_MACHINE_V1.logical_cpu_count * expected_finality_latency_micros
        );
        let validator_count = u64::from(outbe_consensus::bls::MAX_VALIDATORS);
        assert_eq!(
            budget.network_bytes,
            u64::from(MAX_P2P_MESSAGE_SIZE)
                * validator_count
                * (validator_count - 1)
                * OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS
        );
        assert_eq!(
            budget.assigned_memory_bytes,
            OCOMP_POC_DEVNET_MACHINE_V1.minimum_process_memory_bytes
        );
        assert_eq!(
            budget.disk_write_bytes,
            OCOMP_POC_DEVNET_MACHINE_V1.minimum_free_workspace_bytes
        );
        assert_eq!(budget.cas_bytes, OCOMP_POC_CAS_QUOTA_BYTES);
        assert_eq!(budget.block_processing_micros, 4_000_000);
        assert_eq!(
            budget.finality_latency_micros,
            expected_finality_latency_micros
        );
        assert_eq!(
            CAPACITY_CPU_QUOTA_PERCENT,
            u16::try_from(OCOMP_POC_DEVNET_MACHINE_V1.logical_cpu_count * 100).unwrap()
        );
    }
    fn evidence() -> CapacityEvidenceV1 {
        let budget = CapacityBudgetV1 {
            transaction_bytes: 1_000,
            block_bytes: 1_000,
            gas: 1_000,
            internal_work: 1_000,
            cpu_micros: 1_000,
            network_bytes: 1_000,
            assigned_memory_bytes: 1_000,
            disk_write_bytes: 1_000,
            cas_bytes: 1_000,
            block_processing_micros: 1_000,
            finality_latency_micros: 1_000,
        };
        let work = CapacityWorkBillV1 {
            transaction_bytes: 800,
            block_bytes: 800,
            gas: 800,
            internal_work: 800,
            cpu_micros: 800,
            network_bytes: 800,
            assigned_memory_bytes: 800,
            disk_write_bytes: 800,
            cas_bytes: 800,
            block_processing_micros: 800,
            finality_latency_micros: 800,
        };
        let runs = (1_u8..=5)
            .map(|ordinal| CapacityColdRunV1 {
                ordinal,
                source_revision: B256::repeat_byte(1),
                artifact_set_hash: B256::repeat_byte(2),
                cold_namespace_hash: B256::repeat_byte(ordinal.saturating_add(10)),
                binding: CapacityRunBindingV1 {
                    scenario_evidence_sha256: B256::repeat_byte(ordinal.saturating_add(20)),
                    job_id: B256::repeat_byte(3),
                    result_digest: B256::repeat_byte(4),
                    q_forming_transaction_hash: B256::repeat_byte(5),
                    q_forming_block_number: 40,
                    q_forming_block_hash: B256::repeat_byte(6),
                    finalized_block_number: 42,
                    finalized_block_hash: B256::repeat_byte(7),
                    tribute_count: 257,
                    nod_count: 257,
                    worker_shard_count: 2,
                    validator_block_processing: (0_u16..5)
                        .map(|validator_index| CapacityValidatorBlockProcessingV1 {
                            validator_index,
                            block_number: 40,
                            block_hash: B256::repeat_byte(6),
                            elapsed_micros: if validator_index == 3 { 800 } else { 100 },
                        })
                        .collect(),
                    historical_replay:
                        outbe_ocomp_protocol::capacity::CapacityHistoricalReplayBindingV1 {
                            validator_index: 0,
                            first_missing_block_number: 1,
                            target_block_number: 44,
                            target_block_hash: B256::repeat_byte(8),
                            replayed_block_count: 44,
                            elapsed_micros: 100,
                            recovered_result_digest: B256::repeat_byte(4),
                            recovered_generation:
                                outbe_ocomp_protocol::capacity::CapacityRecoveredGenerationBindingV1 {
                                    worldwide_day: 20260728,
                                    generation: 1,
                                    job_id: B256::repeat_byte(3),
                                    program_semantics_hash: B256::repeat_byte(9),
                                    nod_root: B256::repeat_byte(10),
                                    bucket_root: B256::repeat_byte(11),
                                    output_manifest_root: B256::repeat_byte(12),
                                    tribute_count: 257,
                                    nod_count: 257,
                                    bucket_count: 1,
                                    nod_amount_total: alloy_primitives::U256::from(100),
                                    nod_gratis_consumed: alloy_primitives::U256::ZERO,
                                    issued_at: 1,
                                    result_evidence_hash: B256::repeat_byte(13),
                                    block_number: 40,
                                    block_hash: B256::repeat_byte(6),
                                },
                        },
                },
                succeeded: true,
                retried: false,
                work,
            })
            .collect();
        CapacityEvidenceV1 {
            machine: ObservedMachineFactsV1 {
                architecture: "x86_64".to_owned(),
                operating_system: "Ubuntu 24.04".to_owned(),
                logical_cpu_count: 4,
                physical_memory_bytes: 17_179_869_184,
                process_memory_limit_bytes: 12_884_901_888,
                root_disk_bytes: 139_586_437_120,
                free_workspace_bytes: 107_374_182_400,
                block_iops: 8_000,
                block_throughput_bytes_per_second: 250_000_000,
                pid1_is_systemd: true,
                unified_cgroup_v2: true,
                writable_resource_cgroup: true,
                production_enclave_sgx_no_attest: true,
            },
            budget,
            runs,
        }
    }
}
