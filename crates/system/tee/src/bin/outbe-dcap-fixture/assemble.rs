use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use outbe_primitives::tee_attestation_v1::{
    AttestationEvidenceV1, DcapCollateralComponentV1, DcapCollateralKind, DcapEvidenceV1,
    RegistrationIntentV1, TeePolicyV1,
};
use outbe_tee::{
    dcap_v1::{verify_dcap_evidence, DcapRejectCodeV1},
    native_qvl::{verify_quote_native, NativeDcapCollateral},
    quote::parse_quote_measurements,
};
use sha2::{Digest, Sha256};

const COMPONENT_FILES: [(DcapCollateralKind, &str); 8] = [
    (
        DcapCollateralKind::PckCertificateChain,
        "pck-certificate-chain.pem0",
    ),
    (DcapCollateralKind::PckCrl, "pck.crl.der"),
    (
        DcapCollateralKind::PckCrlIssuerChain,
        "pck-crl-issuer-chain.pem",
    ),
    (DcapCollateralKind::RootCaCrl, "root-ca.crl.der"),
    (DcapCollateralKind::TcbInfo, "tcb-info.json"),
    (
        DcapCollateralKind::TcbInfoIssuerChain,
        "tcb-info-issuer-chain.pem",
    ),
    (DcapCollateralKind::QeIdentity, "qe-identity.json"),
    (
        DcapCollateralKind::QeIdentityIssuerChain,
        "qe-identity-issuer-chain.pem",
    ),
];

pub fn run(arguments: &[String]) -> Result<(), String> {
    let policy_path = PathBuf::from(argument(arguments, "--policy")?);
    let intent_path = PathBuf::from(argument(arguments, "--intent")?);
    let quote_path = PathBuf::from(argument(arguments, "--quote")?);
    let collateral_dir = PathBuf::from(argument(arguments, "--collateral-dir")?);
    let timestamp = argument(arguments, "--timestamp")?
        .parse::<u64>()
        .map_err(|_| "timestamp is not a canonical u64".to_owned())?;
    let output_dir = PathBuf::from(argument(arguments, "--output-dir")?);

    let policy_bytes = read(&policy_path)?;
    let intent_bytes = read(&intent_path)?;
    let quote = read(&quote_path)?;
    let policy = TeePolicyV1::decode_canonical(&policy_bytes)
        .map_err(|error| format!("decode canonical TeePolicyV1: {error}"))?;
    let intent = RegistrationIntentV1::decode_canonical(&intent_bytes)
        .map_err(|error| format!("decode canonical RegistrationIntentV1: {error}"))?;
    let measurements = parse_quote_measurements(&quote)
        .map_err(|error| format!("parse captured SGX quote: {error}"))?;
    let expected_report_data = intent
        .report_data()
        .map_err(|error| format!("derive RegistrationIntentV1 report_data: {error}"))?;
    if measurements.report_data != expected_report_data {
        return Err("quote REPORT_DATA does not match the canonical intent".to_owned());
    }

    let mut source_components = BTreeMap::new();
    let components = COMPONENT_FILES
        .into_iter()
        .map(|(kind, name)| {
            let bytes = read(&collateral_dir.join(name))?;
            source_components.insert(name, bytes.clone());
            Ok(DcapCollateralComponentV1 { kind, bytes })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let source_provenance = read(&collateral_dir.join("capture-provenance.json"))?;
    serde_json::from_slice::<serde_json::Value>(&source_provenance)
        .map_err(|error| format!("decode capture-provenance.json: {error}"))?;
    let component = |name: &str| {
        source_components
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("missing captured component {name}"))
    };
    let native_collateral = NativeDcapCollateral {
        pck_crl_issuer_chain: component("pck-crl-issuer-chain.pem")?,
        root_ca_crl: component("root-ca.crl.der")?,
        pck_crl: component("pck.crl.der")?,
        tcb_info_issuer_chain: component("tcb-info-issuer-chain.pem")?,
        tcb_info: component("tcb-info.json")?,
        qe_identity_issuer_chain: component("qe-identity-issuer-chain.pem")?,
        qe_identity: component("qe-identity.json")?,
    };
    let native_preflight = verify_quote_native(
        &quote,
        &native_collateral,
        i64::try_from(timestamp).map_err(|_| "timestamp exceeds i64".to_owned())?,
    )
    .map_err(|error| format!("native QVL preflight failed: {error:?}"))?;
    eprintln!("native QVL preflight: {native_preflight:?}");
    eprintln!(
        "native QVL supplemental: issue={}..{} expiration={} combined_eval_ref={} qe_eval_ref={}",
        native_preflight.supplemental.earliest_issue_date,
        native_preflight.supplemental.latest_issue_date,
        native_preflight.supplemental.earliest_expiration_date,
        native_preflight.supplemental.tcb_evaluation_data_number,
        native_preflight.supplemental.qe_tcb_evaluation_data_number,
    );

    let evidence = DcapEvidenceV1 {
        intent: intent.clone(),
        quote: quote.clone(),
        components,
        transition_key_ready_proof: None,
    };
    let evidence_bytes = AttestationEvidenceV1::Dcap(evidence.clone())
        .encode_canonical()
        .map_err(|error| format!("encode valid AttestationEvidenceV1: {error}"))?;
    let verdict = verify_dcap_evidence(&evidence, &policy, timestamp).map_err(|code| {
        format!(
            "valid evidence rejected with stable code 0x{:04x}",
            code.code()
        )
    })?;
    let verdict_bytes = verdict
        .encode_canonical()
        .map_err(|code| format!("encode stable verdict 0x{:04x}", code.code()))?;

    let mut tampered = evidence;
    let signature_byte = tampered
        .quote
        .get_mut(436)
        .ok_or_else(|| "captured quote has no ECDSA signature byte".to_owned())?;
    *signature_byte ^= 1;
    let tampered_evidence_bytes = AttestationEvidenceV1::Dcap(tampered.clone())
        .encode_canonical()
        .map_err(|error| format!("encode tampered AttestationEvidenceV1: {error}"))?;
    let tampered_reject = verify_dcap_evidence(&tampered, &policy, timestamp)
        .expect_err("tampered quote unexpectedly passed public verifier");
    if tampered_reject != DcapRejectCodeV1::NativeVerificationFailed {
        return Err(format!(
            "tampered quote returned 0x{:04x}, expected NativeVerificationFailed",
            tampered_reject.code()
        ));
    }
    let reject_bytes = tampered_reject.code().to_be_bytes();

    ensure_empty_directory(&output_dir)?;
    let mut artifacts = BTreeMap::new();
    write_artifact(&output_dir, "policy-v1.bin", &policy_bytes, &mut artifacts)?;
    write_artifact(&output_dir, "intent-v1.bin", &intent_bytes, &mut artifacts)?;
    write_artifact(&output_dir, "quote-v3.bin", &quote, &mut artifacts)?;
    for (name, bytes) in &source_components {
        write_artifact(&output_dir, name, bytes, &mut artifacts)?;
    }
    write_artifact(
        &output_dir,
        "capture-provenance.json",
        &source_provenance,
        &mut artifacts,
    )?;
    write_artifact(
        &output_dir,
        "evidence-valid-v1.bin",
        &evidence_bytes,
        &mut artifacts,
    )?;
    write_artifact(
        &output_dir,
        "verdict-valid-v1.bin",
        &verdict_bytes,
        &mut artifacts,
    )?;
    write_artifact(
        &output_dir,
        "evidence-tampered-quote-v1.bin",
        &tampered_evidence_bytes,
        &mut artifacts,
    )?;
    write_artifact(
        &output_dir,
        "reject-tampered-quote-v1.bin",
        &reject_bytes,
        &mut artifacts,
    )?;

    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "capture_timestamp": timestamp,
        "intent_report_data": encode_hex(&expected_report_data),
        "platform_tcb_status": verdict.platform_tcb_status as u8,
        "pck_ca": verdict.pck_ca as u8,
        "fmspc": encode_hex(&verdict.fmspc),
        "pce_id": verdict.pce_id,
        "tcb_evaluation_data_number": verdict.tcb_evaluation_data_number,
        "qe_tcb_evaluation_data_number": verdict.qe_tcb_evaluation_data_number,
        "collateral_valid_until": verdict.collateral_valid_until,
        "advisory_ids": verdict.advisory_ids,
        "negative_reject_code": tampered_reject.code(),
        "artifacts": artifacts,
    }))
    .map_err(|error| format!("encode fixture manifest: {error}"))?;
    let mut manifest_with_newline = manifest;
    manifest_with_newline.push(b'\n');
    write_new(
        &output_dir.join("fixture-manifest-v1.json"),
        &manifest_with_newline,
    )
}

fn argument(arguments: &[String], name: &str) -> Result<String, String> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing {name}"))?;
    arguments
        .get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn ensure_empty_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        let mut entries =
            fs::read_dir(path).map_err(|error| format!("read {}: {error}", path.display()))?;
        if entries.next().is_some() {
            return Err(format!("output directory is not empty: {}", path.display()));
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|error| format!("create {}: {error}", path.display()))
}

fn write_artifact(
    output_dir: &Path,
    name: &str,
    value: &[u8],
    artifacts: &mut BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    write_new(&output_dir.join(name), value)?;
    artifacts.insert(
        name.to_owned(),
        serde_json::json!({
            "size": value.len(),
            "sha256": encode_hex(&Sha256::digest(value)),
        }),
    );
    Ok(())
}

fn write_new(path: &Path, value: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    output
        .write_all(value)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn encode_hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
