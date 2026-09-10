use alloy_primitives::{B256, U256};
use outbe_ocomp::cas::FilesystemCas;
use outbe_ocomp_protocol::{
    input::{CheckpointIdentityV1, Compression, InputManifestV1},
    registry::ObjectKind,
    unit::{PlanCommitmentV1, UnitSpecV1},
    CasObjectRefV1, SchemaLimits,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

pub struct AdmissionAuthorityFixture {
    pub plan_ref: CasObjectRefV1,
    pub manifest_ref: CasObjectRefV1,
    pub plan_hash: B256,
}

pub fn publish_admission_authority(
    cas: &FilesystemCas,
    spec: &UnitSpecV1,
    tribute_count: u32,
    primary_work_unit_count: u32,
    limits: &SchemaLimits,
) -> AdmissionAuthorityFixture {
    let manifest = InputManifestV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 4,
            finalized_block_hash: hash(30),
            finalized_state_root: hash(31),
            finalized_ce_root: hash(32),
            ce_schema_version: 1,
        },
        wwd: 20_260_725,
        sealed_tribute_collection_key: hash(33),
        sealed_tribute_collection_root: hash(34),
        tribute_count,
        tribute_nominal_total: U256::from(100),
        input_chunk_count: 1,
        input_chunk_list_root: hash(35),
        fidelity_opening_root: hash(36),
        oracle_opening_root: hash(37),
        exact_encoded_bytes: 100,
        exact_record_count: tribute_count,
        body_codec_id: hash(38),
        opening_codec_registry_hash: hash(39),
        compression: Compression::None,
    };
    let manifest_hash = manifest.manifest_hash(limits).unwrap();
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let plan = PlanCommitmentV1 {
        protocol_bundle_hash: spec.protocol_bundle_hash,
        job_id: spec.job_id,
        attempt: spec.attempt,
        input_manifest_hash: manifest_hash,
        wwd: manifest.wwd,
        lysis_budget: U256::from(90),
        logical_evaluation_time: 1_784_765_900,
        tribute_count: manifest.tribute_count,
        max_tributes_per_work_shard: 256,
        primary_work_unit_count,
        primary_work_unit_root: hash(40),
        planner_spec_version: spec.planner_spec_version,
        reducer_spec_version: spec.reducer_spec_version,
    };
    let plan_hash = plan.plan_hash(limits).unwrap();
    let plan_ref = cas
        .publish_bytes(&plan.encode_canonical_record(limits).unwrap())
        .unwrap();
    AdmissionAuthorityFixture {
        plan_ref,
        manifest_ref,
        plan_hash,
    }
}
