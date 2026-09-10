#![cfg(all(native_qvl_linked, target_arch = "x86_64", target_os = "linux"))]

use outbe_tee::native_qvl::{verify_quote_native, NativeDcapCollateral, NativeQvlStatus};
use serde::Deserialize;

const FIXTURE_TIME: i64 = 1_751_000_000;
const QUOTE: &[u8] = include_bytes!("fixtures/intel-dcap-1.26/sgx-processor-quote-v3.bin");
const COLLATERAL_WRAPPER: &str =
    include_str!("fixtures/intel-dcap-1.26/sgx-processor-collateral-wrapper.json");

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

struct Fixture {
    root_ca_crl: Vec<u8>,
    pck_crl: Vec<u8>,
    tcb_info: Vec<u8>,
    qe_identity: Vec<u8>,
    source: FixtureCollateral,
}

impl Fixture {
    fn load() -> Self {
        let source: FixtureCollateral = serde_json::from_str(COLLATERAL_WRAPPER).unwrap();
        Self {
            root_ca_crl: hex::decode(&source.root_ca_crl).unwrap(),
            pck_crl: hex::decode(&source.pck_crl).unwrap(),
            tcb_info: signed_document("tcbInfo", &source.tcb_info, &source.tcb_info_signature),
            qe_identity: signed_document(
                "enclaveIdentity",
                &source.qe_identity,
                &source.qe_identity_signature,
            ),
            source,
        }
    }

    fn collateral(&self) -> NativeDcapCollateral<'_> {
        NativeDcapCollateral {
            pck_crl_issuer_chain: self.source.pck_crl_issuer_chain.as_bytes(),
            root_ca_crl: &self.root_ca_crl,
            pck_crl: &self.pck_crl,
            tcb_info_issuer_chain: self.source.tcb_info_issuer_chain.as_bytes(),
            tcb_info: &self.tcb_info,
            qe_identity_issuer_chain: self.source.qe_identity_issuer_chain.as_bytes(),
            qe_identity: &self.qe_identity,
        }
    }
}

#[test]
fn real_processor_quote_is_verified_by_native_qvl_with_explicit_inputs() {
    let fixture = Fixture::load();
    let verdict = verify_quote_native(QUOTE, &fixture.collateral(), FIXTURE_TIME).unwrap();

    assert_eq!(
        verdict.aggregate_status,
        NativeQvlStatus::ConfigurationAndSWHardeningNeeded
    );
    assert!(!verdict.collateral_expired);
    assert_eq!(verdict.supplemental.qe_status, NativeQvlStatus::UpToDate);
    assert_eq!(verdict.supplemental.tee_type, 0);
    assert_eq!(verdict.supplemental.pce_id, 0);
    assert_eq!(verdict.supplemental.tcb_evaluation_data_number, 17);
    assert_eq!(
        (
            verdict.supplemental.major_version,
            verdict.supplemental.minor_version
        ),
        (3, 0)
    );
    assert!(!verdict.supplemental.advisory_ids.is_empty());
    assert!(verdict
        .supplemental
        .advisory_ids
        .iter()
        .all(|advisory| advisory.starts_with("INTEL-SA-")));
}

#[test]
fn tampered_real_quote_returns_a_stable_verification_failure() {
    let fixture = Fixture::load();
    let mut tampered = QUOTE.to_vec();
    tampered[436] ^= 1;

    assert_eq!(
        verify_quote_native(&tampered, &fixture.collateral(), FIXTURE_TIME).unwrap_err(),
        outbe_tee::native_qvl::NativeQvlError::VerificationFailed
    );
}

#[test]
fn explicit_time_controls_the_native_collateral_expiration_boundary() {
    let fixture = Fixture::load();
    let valid = verify_quote_native(QUOTE, &fixture.collateral(), 1_752_919_277).unwrap();
    let expired = verify_quote_native(QUOTE, &fixture.collateral(), 1_752_919_278).unwrap();

    assert!(!valid.collateral_expired);
    assert!(expired.collateral_expired);
}

#[test]
fn empty_submitted_collateral_fails_before_qvl() {
    let fixture = Fixture::load();
    let mut collateral = fixture.collateral();
    collateral.qe_identity = &[];

    assert_eq!(
        verify_quote_native(QUOTE, &collateral, FIXTURE_TIME).unwrap_err(),
        outbe_tee::native_qvl::NativeQvlError::InvalidInput
    );
}

#[test]
fn negative_consensus_time_fails_before_qvl() {
    let fixture = Fixture::load();

    assert_eq!(
        verify_quote_native(QUOTE, &fixture.collateral(), -1).unwrap_err(),
        outbe_tee::native_qvl::NativeQvlError::InvalidInput
    );
}
