//! Host-only preparation and assembly of real Intel DCAP consensus fixtures.
//!
//! This binary is available only with `dcap-fixture-tool`; it is never linked
//! into the consensus library or the production enclave process.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, AttestationOperationV1, NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1,
    RegistrationIntentV1, TeeMeasurementRuleV1, TeePolicyV1,
};

#[path = "outbe-dcap-fixture/assemble.rs"]
mod assemble;

const INTEL_ROOT_DER_SHA256: &str =
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";

fn main() {
    if let Err(error) = run(&env::args().collect::<Vec<_>>()) {
        eprintln!("outbe-dcap-fixture: {error}");
        std::process::exit(2);
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("prepare") => prepare(arguments),
        Some("assemble") => assemble::run(arguments),
        _ => Err(
            "usage: outbe-dcap-fixture prepare --mrenclave <hex32> --mrsigner <hex32> \
             --isv-prod-id <u16> --isv-svn <u16> --timestamp <u64> --output-dir <empty-dir>"
                .to_owned(),
        ),
    }
}

fn prepare(arguments: &[String]) -> Result<(), String> {
    let mrenclave = parse_hex32(&argument(arguments, "--mrenclave")?)?;
    let mrsigner = parse_hex32(&argument(arguments, "--mrsigner")?)?;
    let isv_prod_id = parse_u16(&argument(arguments, "--isv-prod-id")?, "isv-prod-id")?;
    let isv_svn = parse_u16(&argument(arguments, "--isv-svn")?, "isv-svn")?;
    let timestamp = parse_u64(&argument(arguments, "--timestamp")?, "timestamp")?;
    let output_dir = PathBuf::from(argument(arguments, "--output-dir")?);
    ensure_empty_directory(&output_dir)?;

    let policy = policy(mrenclave, mrsigner, isv_prod_id, isv_svn)?;
    let intent = intent(&policy, timestamp)?;
    let policy_bytes = policy
        .encode_canonical()
        .map_err(|error| format!("encode TeePolicyV1: {error}"))?;
    let intent_bytes = intent
        .encode_canonical()
        .map_err(|error| format!("encode RegistrationIntentV1: {error}"))?;
    let report_data = intent
        .report_data()
        .map_err(|error| format!("derive RegistrationIntentV1 report_data: {error}"))?;

    write_new(&output_dir.join("policy.bin"), &policy_bytes)?;
    write_new(&output_dir.join("intent.bin"), &intent_bytes)?;
    write_new(&output_dir.join("report-data.bin"), &report_data)?;
    let metadata = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "capture_timestamp": timestamp,
        "mrenclave": encode_hex(&mrenclave),
        "mrsigner": encode_hex(&mrsigner),
        "isv_prod_id": isv_prod_id,
        "isv_svn": isv_svn,
        "report_data": encode_hex(&report_data),
    }))
    .map_err(|error| format!("encode capture metadata: {error}"))?;
    let mut metadata_with_newline = metadata;
    metadata_with_newline.push(b'\n');
    write_new(
        &output_dir.join("capture-input-v1.json"),
        &metadata_with_newline,
    )
}

fn policy(
    mrenclave: [u8; 32],
    mrsigner: [u8; 32],
    isv_prod_id: u16,
    isv_svn: u16,
) -> Result<TeePolicyV1, String> {
    Ok(TeePolicyV1 {
        policy_version: 1,
        chain_id: [0x11; 32],
        genesis_hash: B256::repeat_byte(0x22),
        activation_height: 1,
        predecessor_policy_hash: B256::ZERO,
        attestation_mode: AttestationMode::DcapRequired,
        intel_root_der_hash: B256::from(parse_hex32(INTEL_ROOT_DER_SHA256)?),
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
            mrenclave: B256::from(mrenclave),
            mrsigner: B256::from(mrsigner),
            isv_prod_id,
            minimum_isv_svn: isv_svn,
            admit_from_height: 1,
            admit_until_height_exclusive: u64::MAX,
        }],
    })
}

fn intent(policy: &TeePolicyV1, timestamp: u64) -> Result<RegistrationIntentV1, String> {
    // Public NodeHost identity from the captured fixture; no private key is needed.
    let reth_p2p_public: [u8; 33] = [
        0x03, 0x79, 0x62, 0xd4, 0x5b, 0x38, 0xe8, 0xbc, 0xf8, 0x2f, 0xa8, 0xef, 0xa8, 0x43, 0x2a,
        0x01, 0xf2, 0x0c, 0x9a, 0x53, 0xe2, 0x4c, 0x7d, 0x3f, 0x11, 0xdf, 0x19, 0x7c, 0xb8, 0xe7,
        0x09, 0x26, 0xda,
    ];
    Ok(RegistrationIntentV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: policy
            .policy_hash()
            .map_err(|error| format!("hash TeePolicyV1: {error}"))?,
        node_id: NodeIdV1 { reth_p2p_public },
        enclave_id: B256::repeat_byte(0x99),
        binding_id: B256::repeat_byte(0xaa),
        binding_version: 1,
        registration_version: 1,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: timestamp
            .checked_add(86_400)
            .ok_or_else(|| "requested_valid_until overflows u64".to_owned())?,
        recipient_x25519: [0xbb; 32],
        attestation_ed25519: [0xcc; 32],
        noise_responder_x25519: [0xdd; 32],
        node_host_authorization_hash: B256::repeat_byte(0xee),
    })
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

fn parse_u16(value: &str, label: &str) -> Result<u16, String> {
    value
        .parse()
        .map_err(|_| format!("{label} is not a canonical u16"))
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{label} is not a canonical u64"))
}

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected exactly 32 hexadecimal bytes".to_owned());
    }
    let mut decoded = [0u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2])? << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hexadecimal digit".to_owned()),
    }
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
