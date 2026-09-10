#![cfg(feature = "dcap-fixture-capture")]

use std::{fs, process::Command};

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, AttestationOperationV1, NodeIdV1, RegistrationIntentV1,
};
use outbe_tee_enclave::gramine::capture_report_data_from_intent;

fn intent() -> RegistrationIntentV1 {
    // Public NodeHost identity from the captured fixture; no private key is needed.
    let reth_p2p_public: [u8; 33] = [
        0x03, 0x79, 0x62, 0xd4, 0x5b, 0x38, 0xe8, 0xbc, 0xf8, 0x2f, 0xa8, 0xef, 0xa8, 0x43, 0x2a,
        0x01, 0xf2, 0x0c, 0x9a, 0x53, 0xe2, 0x4c, 0x7d, 0x3f, 0x11, 0xdf, 0x19, 0x7c, 0xb8, 0xe7,
        0x09, 0x26, 0xda,
    ];
    RegistrationIntentV1 {
        chain_id: [0x11; 32],
        genesis_hash: B256::repeat_byte(0x22),
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: B256::repeat_byte(0x33),
        node_id: NodeIdV1 { reth_p2p_public },
        enclave_id: B256::repeat_byte(0x99),
        binding_id: B256::repeat_byte(0xaa),
        binding_version: 1,
        registration_version: 1,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: 7_200,
        recipient_x25519: [0xbb; 32],
        attestation_ed25519: [0xcc; 32],
        noise_responder_x25519: [0xdd; 32],
        node_host_authorization_hash: B256::repeat_byte(0xee),
    }
}

#[test]
fn capture_boundary_derives_all_report_data_from_the_canonical_intent() {
    let intent = intent();
    let canonical = intent.encode_canonical().unwrap();

    assert_eq!(
        capture_report_data_from_intent(&canonical).unwrap(),
        intent.report_data().unwrap()
    );
}

#[test]
fn capture_boundary_rejects_noncanonical_intent_bytes_before_quote_generation() {
    let mut noncanonical = intent().encode_canonical().unwrap();
    noncanonical.push(0);

    assert!(capture_report_data_from_intent(&noncanonical).is_err());
}

#[test]
fn production_binary_never_exposes_the_capture_command() {
    let root = tempfile::tempdir().unwrap();
    let intent_path = root.path().join("intent.bin");
    let quote_path = root.path().join("quote.bin");
    fs::write(&intent_path, intent().encode_canonical().unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_outbe-tee-enclave"))
        .args([
            "--capture-dcap-intent",
            intent_path.to_str().unwrap(),
            "--capture-dcap-quote-output",
            quote_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("usage: outbe-tee-enclave --socket <path>"));
    assert!(!stderr.contains("DCAP fixture capture"));
    assert!(!quote_path.exists());
}

#[test]
fn dedicated_capture_binary_rejects_noncanonical_intent_before_quote_generation() {
    let root = tempfile::tempdir().unwrap();
    let intent_path = root.path().join("intent.bin");
    let quote_path = root.path().join("quote.bin");
    let mut noncanonical = intent().encode_canonical().unwrap();
    noncanonical.push(0);
    fs::write(&intent_path, noncanonical).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_outbe-dcap-capture-enclave"))
        .args([
            "--intent",
            intent_path.to_str().unwrap(),
            "--quote-output",
            quote_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("decode canonical RegistrationIntentV1"),
        "unexpected capture error: {stderr}"
    );
    assert!(!quote_path.exists());
}
