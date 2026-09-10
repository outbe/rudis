#![cfg(all(
    feature = "dcap-fixture-tool",
    target_arch = "x86_64",
    target_os = "linux"
))]

use std::{fs, path::PathBuf, process::Command};

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{RegistrationIntentV1, TeePolicyV1};

#[test]
fn prepare_command_emits_a_canonical_intent_bound_to_the_measured_policy() {
    let output = tempfile::tempdir().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_outbe-dcap-fixture"))
        .args([
            "prepare",
            "--mrenclave",
            &"11".repeat(32),
            "--mrsigner",
            &"22".repeat(32),
            "--isv-prod-id",
            "1",
            "--isv-svn",
            "7",
            "--timestamp",
            "1800000000",
            "--output-dir",
            output.path().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let policy =
        TeePolicyV1::decode_canonical(&fs::read(output.path().join("policy.bin")).unwrap())
            .unwrap();
    let intent = RegistrationIntentV1::decode_canonical(
        &fs::read(output.path().join("intent.bin")).unwrap(),
    )
    .unwrap();
    let report_data = fs::read(output.path().join("report-data.bin")).unwrap();

    assert_eq!(policy.measurement_rules.len(), 1);
    assert_eq!(
        policy.measurement_rules[0].mrenclave,
        B256::repeat_byte(0x11)
    );
    assert_eq!(
        policy.measurement_rules[0].mrsigner,
        B256::repeat_byte(0x22)
    );
    assert_eq!(policy.measurement_rules[0].minimum_isv_svn, 7);
    assert_eq!(intent.policy_hash, policy.policy_hash().unwrap());
    assert_eq!(report_data, intent.report_data().unwrap());
}

#[test]
fn assemble_command_rejects_a_real_quote_not_bound_to_the_prepared_intent() {
    let root = tempfile::tempdir().unwrap();
    let prepared = root.path().join("prepared");
    let prepare_status = Command::new(env!("CARGO_BIN_EXE_outbe-dcap-fixture"))
        .args([
            "prepare",
            "--mrenclave",
            &"11".repeat(32),
            "--mrsigner",
            &"22".repeat(32),
            "--isv-prod-id",
            "1",
            "--isv-svn",
            "7",
            "--timestamp",
            "1800000000",
            "--output-dir",
            prepared.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(prepare_status.success());

    let collateral = root.path().join("collateral");
    fs::create_dir(&collateral).unwrap();
    let quote = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/intel-dcap-1.26/sgx-processor-quote-v3.bin");
    let assembled = root.path().join("assembled");
    let output = Command::new(env!("CARGO_BIN_EXE_outbe-dcap-fixture"))
        .args([
            "assemble",
            "--policy",
            prepared.join("policy.bin").to_str().unwrap(),
            "--intent",
            prepared.join("intent.bin").to_str().unwrap(),
            "--quote",
            quote.to_str().unwrap(),
            "--collateral-dir",
            collateral.to_str().unwrap(),
            "--timestamp",
            "1800000000",
            "--output-dir",
            assembled.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("quote REPORT_DATA does not match the canonical intent"));
    assert!(!assembled.exists());
}
