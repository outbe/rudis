#![cfg(all(native_qvl_linked, target_arch = "x86_64", target_os = "linux"))]

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{
    AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapCollateralComponentV1,
    DcapCollateralKind, DcapEvidenceV1, NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1,
    RegistrationIntentV1, TeeMeasurementRuleV1, TeePolicyV1, TeeRegistryGasScheduleV1,
};
use outbe_tee::dcap_v1::{verify_dcap_evidence, DcapRejectCodeV1};
use serde::Deserialize;

const QUOTE: &[u8] = include_bytes!("fixtures/intel-dcap-1.26/sgx-processor-quote-v3.bin");
const COLLATERAL_WRAPPER: &str =
    include_str!("fixtures/intel-dcap-1.26/sgx-processor-collateral-wrapper.json");
const INTENT_BOUND_PROCESSOR_CAPTURE_TIME: u64 = 1_787_850_648;
const INTENT_BOUND_PROCESSOR_COLLATERAL_EXPIRES_AT: u64 = 1_790_380_006;
const PEM_CERTIFICATE_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

#[derive(Deserialize)]
struct FixtureCollateral {
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
}

fn signed_document(field: &str, body: &str, signature: &str) -> Vec<u8> {
    format!(r#"{{"{field}":{body},"signature":"{signature}"}}"#).into_bytes()
}

fn embedded_pck_chain() -> Vec<u8> {
    let start = QUOTE
        .windows(PEM_CERTIFICATE_BEGIN.len())
        .position(|window| window == PEM_CERTIFICATE_BEGIN)
        .unwrap();
    QUOTE[start..].to_vec()
}

fn policy() -> TeePolicyV1 {
    let measurements = outbe_tee::quote::parse_quote_measurements(QUOTE).unwrap();
    let intel_root_der_hash = B256::from_slice(
        &hex::decode("44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3").unwrap(),
    );
    TeePolicyV1 {
        policy_version: 1,
        chain_id: [0x11; 32],
        genesis_hash: B256::repeat_byte(0x22),
        activation_height: 1,
        predecessor_policy_hash: B256::ZERO,
        attestation_mode: AttestationMode::DcapRequired,
        intel_root_der_hash,
        quote_version: 3,
        tee_type: 0,
        attestation_key_type: 2,
        qe_vendor_id: [
            0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
            0x06, 0x07,
        ],
        certification_data_type: 5,
        tcb_info_schema_version: 3,
        qe_identity_schema_version: 2,
        minimum_tcb_evaluation_data_number: 1,
        accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
        minimum_lease: 3_600,
        maximum_lease: 604_800,
        collateral_margin: 3_600,
        resource_schedule_hash: B256::repeat_byte(0x44),
        measurement_rules: vec![TeeMeasurementRuleV1 {
            mrenclave: B256::from(measurements.mrenclave),
            mrsigner: B256::from(measurements.mrsigner),
            isv_prod_id: measurements.isv_prod_id,
            minimum_isv_svn: measurements.isv_svn,
            admit_from_height: 1,
            admit_until_height_exclusive: 100,
        }],
    }
}

fn evidence(policy: &TeePolicyV1) -> DcapEvidenceV1 {
    let collateral: FixtureCollateral = serde_json::from_str(COLLATERAL_WRAPPER).unwrap();
    // Public NodeHost identity from the captured fixture; no private key is needed.
    let reth_p2p_public: [u8; 33] = [
        0x03, 0x79, 0x62, 0xd4, 0x5b, 0x38, 0xe8, 0xbc, 0xf8, 0x2f, 0xa8, 0xef, 0xa8, 0x43, 0x2a,
        0x01, 0xf2, 0x0c, 0x9a, 0x53, 0xe2, 0x4c, 0x7d, 0x3f, 0x11, 0xdf, 0x19, 0x7c, 0xb8, 0xe7,
        0x09, 0x26, 0xda,
    ];
    let intent = RegistrationIntentV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: policy.policy_hash().unwrap(),
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
    };
    let components = [
        (
            DcapCollateralKind::PckCertificateChain,
            embedded_pck_chain(),
        ),
        (
            DcapCollateralKind::PckCrl,
            hex::decode(&collateral.pck_crl).unwrap(),
        ),
        (
            DcapCollateralKind::PckCrlIssuerChain,
            collateral.pck_crl_issuer_chain.into_bytes(),
        ),
        (
            DcapCollateralKind::RootCaCrl,
            hex::decode(&collateral.root_ca_crl).unwrap(),
        ),
        (
            DcapCollateralKind::TcbInfo,
            signed_document(
                "tcbInfo",
                &collateral.tcb_info,
                &collateral.tcb_info_signature,
            ),
        ),
        (
            DcapCollateralKind::TcbInfoIssuerChain,
            collateral.tcb_info_issuer_chain.into_bytes(),
        ),
        (
            DcapCollateralKind::QeIdentity,
            signed_document(
                "enclaveIdentity",
                &collateral.qe_identity,
                &collateral.qe_identity_signature,
            ),
        ),
        (
            DcapCollateralKind::QeIdentityIssuerChain,
            collateral.qe_identity_issuer_chain.into_bytes(),
        ),
    ];
    DcapEvidenceV1 {
        intent,
        quote: QUOTE.to_vec(),
        components: components
            .into_iter()
            .map(|(kind, bytes)| DcapCollateralComponentV1 { kind, bytes })
            .collect(),
        transition_key_ready_proof: None,
    }
}

fn evidence_with_synthetic_intent_binding(policy: &TeePolicyV1) -> DcapEvidenceV1 {
    let mut evidence = evidence(policy);
    evidence.quote[368..432].copy_from_slice(&evidence.intent.report_data().unwrap());
    evidence
}

fn intent_bound_processor_capture() -> (TeePolicyV1, DcapEvidenceV1) {
    let policy = TeePolicyV1::decode_canonical(include_bytes!(
        "fixtures/intel-dcap-1.26-intent-bound-processor/policy.bin"
    ))
    .unwrap();
    let intent = RegistrationIntentV1::decode_canonical(include_bytes!(
        "fixtures/intel-dcap-1.26-intent-bound-processor/intent.bin"
    ))
    .unwrap();
    let components = [
        (
            DcapCollateralKind::PckCertificateChain,
            include_bytes!(
                "fixtures/intel-dcap-1.26-intent-bound-processor/pck-certificate-chain.pem0"
            )
            .as_slice(),
        ),
        (
            DcapCollateralKind::PckCrl,
            include_bytes!("fixtures/intel-dcap-1.26-intent-bound-processor/pck.crl.der")
                .as_slice(),
        ),
        (
            DcapCollateralKind::PckCrlIssuerChain,
            include_bytes!(
                "fixtures/intel-dcap-1.26-intent-bound-processor/pck-crl-issuer-chain.pem"
            )
            .as_slice(),
        ),
        (
            DcapCollateralKind::RootCaCrl,
            include_bytes!("fixtures/intel-dcap-1.26-intent-bound-processor/root-ca.crl.der")
                .as_slice(),
        ),
        (
            DcapCollateralKind::TcbInfo,
            include_bytes!("fixtures/intel-dcap-1.26-intent-bound-processor/tcb-info.json")
                .as_slice(),
        ),
        (
            DcapCollateralKind::TcbInfoIssuerChain,
            include_bytes!(
                "fixtures/intel-dcap-1.26-intent-bound-processor/tcb-info-issuer-chain.pem"
            )
            .as_slice(),
        ),
        (
            DcapCollateralKind::QeIdentity,
            include_bytes!("fixtures/intel-dcap-1.26-intent-bound-processor/qe-identity.json")
                .as_slice(),
        ),
        (
            DcapCollateralKind::QeIdentityIssuerChain,
            include_bytes!(
                "fixtures/intel-dcap-1.26-intent-bound-processor/qe-identity-issuer-chain.pem"
            )
            .as_slice(),
        ),
    ];

    (
        policy,
        DcapEvidenceV1 {
            intent,
            quote: include_bytes!("fixtures/intel-dcap-1.26-intent-bound-processor/quote.bin")
                .to_vec(),
            components: components
                .into_iter()
                .map(|(kind, bytes)| DcapCollateralComponentV1 {
                    kind,
                    bytes: bytes.to_vec(),
                })
                .collect(),
            transition_key_ready_proof: None,
        },
    )
}

#[test]
fn intent_bound_real_processor_quote_passes_testnet_platform_status_policy() {
    let (policy, evidence) = intent_bound_processor_capture();

    let verdict = verify_dcap_evidence(&evidence, &policy, INTENT_BOUND_PROCESSOR_CAPTURE_TIME)
        .expect("ConfigurationAndSWHardeningNeeded is accepted by testnet policy");
    assert_eq!(
        verdict.platform_tcb_status,
        outbe_tee::dcap_protocol::DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded
    );
}

#[test]
fn intent_bound_real_processor_verdict_is_byte_stable() {
    let (policy, evidence) = intent_bound_processor_capture();
    let verdict =
        verify_dcap_evidence(&evidence, &policy, INTENT_BOUND_PROCESSOR_CAPTURE_TIME).unwrap();
    let expected = hex::decode(
        include_str!("fixtures/intel-dcap-1.26-intent-bound-processor/accepted-verdict-v1.hex")
            .trim(),
    )
    .unwrap();

    assert_eq!(verdict.encode_canonical().unwrap(), expected);
}

#[test]
fn noncanonical_evidence_rejects_at_the_public_boundary() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    evidence.components.clear();

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::EvidenceNonCanonical)
    );
}

#[test]
fn noncanonical_policy_rejects_at_the_public_boundary() {
    let valid_policy = policy();
    let evidence = evidence(&valid_policy);
    let mut invalid_policy = valid_policy;
    invalid_policy.policy_version = 0;

    assert_eq!(
        verify_dcap_evidence(&evidence, &invalid_policy, 1_751_000_000),
        Err(DcapRejectCodeV1::PolicyNonCanonical)
    );
}

#[test]
fn cross_chain_intent_rejects_before_quote_verification() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    evidence.intent.chain_id[0] ^= 0xff;

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::PolicyBindingMismatch)
    );
}

#[test]
fn timestamp_outside_the_native_qvl_range_rejects_before_quote_verification() {
    let policy = policy();
    let evidence = evidence(&policy);
    let out_of_range = i64::MAX as u64 + 1;

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, out_of_range),
        Err(DcapRejectCodeV1::TimestampInvalid)
    );
}

#[test]
fn intent_bound_real_processor_quote_uses_all_collateral_expiration_boundary() {
    let (policy, evidence) = intent_bound_processor_capture();

    let verdict = verify_dcap_evidence(
        &evidence,
        &policy,
        INTENT_BOUND_PROCESSOR_COLLATERAL_EXPIRES_AT - 1,
    )
    .expect("accepted testnet status remains valid before collateral expiration");
    assert_eq!(
        verdict.collateral_valid_until,
        INTENT_BOUND_PROCESSOR_COLLATERAL_EXPIRES_AT
    );
    assert_eq!(
        verify_dcap_evidence(
            &evidence,
            &policy,
            INTENT_BOUND_PROCESSOR_COLLATERAL_EXPIRES_AT,
        ),
        Err(DcapRejectCodeV1::CollateralExpired)
    );
}

#[test]
fn quote_with_trailing_byte_is_rejected_by_the_consensus_interface() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    evidence.quote.push(0xa5);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::QuoteMalformed)
    );
}

#[test]
fn quote_with_trailing_byte_inside_declared_authentication_data_is_rejected() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    let declared = u32::from_le_bytes(evidence.quote[432..436].try_into().unwrap());
    evidence.quote[432..436].copy_from_slice(&(declared + 1).to_le_bytes());
    evidence.quote.push(0xa5);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::QuoteMalformed)
    );
}

#[test]
fn quote_header_must_match_the_active_sgx_v3_policy() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    evidence.quote[0..2].copy_from_slice(&4_u16.to_le_bytes());

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::QuoteProfileMismatch)
    );
}

#[test]
fn embedded_type_five_pck_chain_must_equal_the_evidence_component() {
    let policy = policy();
    let mut evidence = evidence(&policy);
    evidence.components[0].bytes[0] ^= 1;

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::QuoteCertificationDataMismatch)
    );
}

#[test]
fn quote_report_data_must_equal_the_canonical_registration_intent_binding() {
    let policy = policy();
    let evidence = evidence(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::ReportDataMismatch)
    );
}

#[test]
fn semantically_equivalent_noncanonical_pem_collateral_is_rejected() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    evidence.components[2].bytes = String::from_utf8(evidence.components[2].bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::CollateralNonCanonical)
    );
}

#[test]
fn collateral_certificate_counts_are_exact() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    let duplicate = evidence.components[2].bytes.clone();
    evidence.components[2].bytes.extend_from_slice(&duplicate);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::CollateralNonCanonical)
    );
}

#[test]
fn signed_json_wrapper_with_equivalent_whitespace_is_rejected() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    evidence.components[4].bytes.insert(1, b' ');

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_000_000),
        Err(DcapRejectCodeV1::CollateralNonCanonical)
    );
}

#[test]
fn duplicate_keys_anywhere_in_signed_json_are_rejected() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    let tcb_info = String::from_utf8(evidence.components[4].bytes.clone()).unwrap();
    evidence.components[4].bytes = tcb_info
        .replace("\"tcbLevels\":", "\"tcbLevels\":[],\"tcbLevels\":")
        .into_bytes();

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::CollateralNonCanonical)
    );
}

#[test]
fn intent_rebound_quote_is_rejected_by_native_qvl() {
    let policy = policy();
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::NativeVerificationFailed)
    );
}

#[test]
fn consensus_time_before_either_signed_document_issue_time_is_rejected() {
    let policy = policy();
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_750_330_570),
        Err(DcapRejectCodeV1::CollateralNotYetValid)
    );
}

#[test]
fn earliest_signed_document_expiration_is_exclusive() {
    let policy = policy();
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_752_919_278),
        Err(DcapRejectCodeV1::CollateralExpired)
    );
}

#[test]
fn pck_chain_must_terminate_at_the_policy_pinned_intel_root() {
    let mut policy = policy();
    policy.intel_root_der_hash = B256::repeat_byte(0x33);
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::IntelRootMismatch)
    );
}

#[test]
fn both_signed_document_evaluation_numbers_must_meet_policy() {
    let mut policy = policy();
    policy.minimum_tcb_evaluation_data_number = 18;
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::TcbEvaluationNumberTooLow)
    );
}

#[test]
fn signed_tcb_fmspc_must_match_the_verified_pck_certificate() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    let tcb_info = String::from_utf8(evidence.components[4].bytes.clone()).unwrap();
    evidence.components[4].bytes = tcb_info
        .replace("\"fmspc\":\"00A067110000\"", "\"fmspc\":\"00A067110001\"")
        .into_bytes();

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::PlatformIdentityMismatch)
    );
}

#[test]
fn signed_tcb_pce_id_must_match_the_verified_pck_certificate() {
    let policy = policy();
    let mut evidence = evidence_with_synthetic_intent_binding(&policy);
    let tcb_info = String::from_utf8(evidence.components[4].bytes.clone()).unwrap();
    evidence.components[4].bytes = tcb_info
        .replace("\"pceId\":\"0000\"", "\"pceId\":\"0001\"")
        .into_bytes();

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::PlatformIdentityMismatch)
    );
}

#[test]
fn quote_measurements_must_match_an_active_policy_rule_for_the_profile() {
    let mut policy = policy();
    policy.measurement_rules[0].mrenclave = B256::repeat_byte(0x55);
    let evidence = evidence_with_synthetic_intent_binding(&policy);

    assert_eq!(
        verify_dcap_evidence(&evidence, &policy, 1_751_100_000),
        Err(DcapRejectCodeV1::MeasurementRejected)
    );
}

#[test]
fn consensus_qvl_precharge_matches_the_normative_formula_exactly() {
    let policy = policy();
    let evidence = evidence(&policy);
    let evidence_len = AttestationEvidenceV1::Dcap(evidence)
        .encode_canonical()
        .unwrap()
        .len();
    let expected = 1_500_000
        + 6 * u64::try_from(evidence_len).unwrap()
        + 120_000 * 9
        + 180_000 * 2
        + 160_000 * 2
        + 10_000 * u64::try_from(policy.measurement_rules.len()).unwrap();

    assert_eq!(
        TeeRegistryGasScheduleV1::normative()
            .qvl_dcap(evidence_len, policy.measurement_rules.len())
            .unwrap(),
        expected
    );
}
