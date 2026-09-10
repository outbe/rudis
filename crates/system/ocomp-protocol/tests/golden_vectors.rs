// OCOMP-TEST-ID: OCM-BYT-001

use alloy_primitives::keccak256;
use outbe_ocomp_protocol::{
    decode_envelope,
    generated_shape::{
        OCOMP_POC_CANDIDATE_LIMITS_V1, OCOMP_POC_DEVNET_MACHINE_V1, OCOMP_POC_HEADROOM_POLICY_V1,
        OCOMP_SHAPE_ARMABLE, OCOMP_SHAPE_INPUT_SET_SHA256, OCOMP_SHAPE_MEASUREMENT_ONLY,
    },
    CodecLimits, ObjectKind, ProtocolError,
};
use serde_json::Value;

const LIMITS: CodecLimits = CodecLimits::new(1_024, 4, 1_024);
const _: () = {
    assert!(OCOMP_SHAPE_MEASUREMENT_ONLY);
    assert!(!OCOMP_SHAPE_ARMABLE);
    assert!(OCOMP_POC_CANDIDATE_LIMITS_V1.max_tributes_per_work_shard <= 256);
    assert!(OCOMP_POC_CANDIDATE_LIMITS_V1.max_result_chunk_bytes <= 524_288);
    assert!(OCOMP_POC_HEADROOM_POLICY_V1.failed_or_timeout_run_rejects_candidate);
    assert!(!OCOMP_POC_HEADROOM_POLICY_V1.retry_failed_run);
};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            u8::try_from((high << 4) | low).unwrap()
        })
        .collect()
}

fn independent_envelope(kind: u16) -> Vec<u8> {
    let mut bytes = b"OCB1".to_vec();
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes
}

#[test]
fn measurement_shape_has_positive_and_negative_vector_for_every_object() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/shape-vectors-v1.json")).unwrap();
    assert_eq!(fixture["classification"], "measurement_only");
    assert_eq!(fixture["armable"], false);
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), ObjectKind::ALL.len() * 2);

    for (index, kind) in ObjectKind::ALL.iter().copied().enumerate() {
        let positive = &vectors[index * 2];
        assert_eq!(positive["object_kind"], kind.name());
        assert_eq!(positive["expected_decode_outcome"], "envelope_pass");
        assert_eq!(
            positive["generator_artifact_hash"],
            OCOMP_SHAPE_INPUT_SET_SHA256
        );
        assert_eq!(positive["independent_verifier_result"], "PASS");
        let bytes = decode_hex(positive["canonical_hex"].as_str().unwrap());
        assert_eq!(bytes, independent_envelope(kind.tag()));
        assert_eq!(decode_envelope(&bytes, LIMITS).unwrap().kind, kind);
        assert_eq!(
            positive["expected_digest_or_id"],
            format!("{:x}", keccak256(&bytes))
        );

        let negative = &vectors[index * 2 + 1];
        assert_eq!(negative["object_kind"], kind.name());
        assert_eq!(negative["expected_decode_outcome"], "reject");
        assert_eq!(negative["expected_error_code"], "UNKNOWN_OBJECT_KIND");
        let bytes = decode_hex(negative["canonical_hex"].as_str().unwrap());
        assert_eq!(bytes, independent_envelope(u16::MAX));
        assert_eq!(
            decode_envelope(&bytes, LIMITS),
            Err(ProtocolError::UnknownObjectKind(u16::MAX))
        );
    }
}

#[test]
fn generated_candidate_constants_are_measurement_only_and_within_ceiling() {
    assert_eq!(
        OCOMP_POC_CANDIDATE_LIMITS_V1.max_tributes_per_work_shard,
        256
    );
    assert_eq!(OCOMP_POC_CANDIDATE_LIMITS_V1.max_inputs_per_work_unit, 13);
    assert_eq!(
        OCOMP_POC_CANDIDATE_LIMITS_V1.max_records_per_input_chunk,
        768
    );
    assert_eq!(OCOMP_POC_DEVNET_MACHINE_V1.logical_cpu_count, 4);
    assert_eq!(
        OCOMP_POC_DEVNET_MACHINE_V1.nominal_memory_bytes,
        17_179_869_184
    );
    assert_eq!(OCOMP_POC_HEADROOM_POLICY_V1.benchmark_cold_runs, 5);
    assert_eq!(
        OCOMP_POC_HEADROOM_POLICY_V1.required_headroom_basis_points,
        2_000
    );
}

#[test]
fn generated_manifest_has_no_network_binding() {
    let manifest: Value =
        serde_json::from_str(include_str!("../registry/generated-shape-manifest.json")).unwrap();
    assert_eq!(manifest["classification"], "measurement_only");
    assert_eq!(manifest["armable"], false);
    assert_eq!(
        manifest["registries"]["object_count"].as_u64(),
        Some(ObjectKind::ALL.len() as u64)
    );
    assert_eq!(manifest["independent_verification"]["result"], "PASS");
    for field in [
        "chain_id",
        "genesis_hash",
        "committee_snapshot_hash",
        "protocol_bundle_hash",
        "capacity_profile_hash",
        "network_manifest_hash",
    ] {
        assert!(manifest["network_binding"][field].is_null());
    }
}
