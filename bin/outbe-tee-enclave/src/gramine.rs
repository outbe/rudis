//! Real Gramine attestation surface (`/dev/attestation/*`).
//!
//! This is the genuine SGX integration - no mock constants. Under `gramine-sgx`
//! these pseudo-files are backed by hardware: `quote` is a real DCAP quote and
//! the keys under `keys/` come from `EGETKEY`. Under `gramine-direct` there is no
//! SGX hardware, so `attestation_type` reads `none`, `quote` is unavailable, and
//! `keys/` does not exist - this module reports that honestly (no fabricated
//! quote, no fixed sealing key). Outside Gramine entirely (bare process) every
//! pseudo-file is absent and every call returns the "unavailable" path.
//!
//! Note that `attestation_type` reading `none` is ambiguous: it is also what real
//! `gramine-sgx` reports when the manifest does not enable remote attestation. We
//! disambiguate via EGETKEY availability (see [`attestation_type`] /
//! [`AttestationType::SgxNoAttest`]) so a real-SGX run is never mislabeled "no SGX".
//!
//! Hardware MRENCLAVE/MRSIGNER/ISVSVN are parsed out of the real quote's embedded
//! SGX report body - they are never hardcoded.

use std::fs;

// The DCAP quote parser is shared with the host (single source of truth).
pub use outbe_tee::quote::{
    parse_quote_measurements, ReportMeasurements, MIN_QUOTE_LEN, REPORT_BODY_OFFSET,
};

const ATTEST_DIR: &str = "/dev/attestation";

/// What the running environment can attest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// `gramine-direct` (or any non-SGX Gramine): no hardware, no real quote.
    None,
    /// Real `gramine-sgx`, but remote attestation is not configured (the manifest
    /// has no `sgx.remote_attestation = "dcap"`/`"epid"`), so
    /// `/dev/attestation/attestation_type` reads `none`. SGX hardware IS present:
    /// EGETKEY sealing keys (`keys/_sgx_mrsigner`) derive. This is NOT
    /// remote-attested - it cannot produce a DCAP quote - but it is confidential
    /// at rest. Distinguished from [`None`] by EGETKEY availability.
    SgxNoAttest,
    /// `gramine-sgx` with DCAP remote attestation.
    Dcap,
    /// `gramine-sgx` with legacy EPID.
    Epid,
    /// Gramine reported a type we do not specifically handle.
    Other(String),
    /// Not running under Gramine at all (`/dev/attestation` absent).
    Unavailable,
}

impl AttestationType {
    /// True only when a real SGX hardware quote can be produced.
    pub fn is_hardware(&self) -> bool {
        matches!(self, AttestationType::Dcap | AttestationType::Epid)
    }

    /// True when real SGX hardware is present - including [`SgxNoAttest`], which
    /// has EGETKEY sealing but no remote attestation. Distinct from
    /// [`is_hardware`](Self::is_hardware), which is narrower: "remote-attestation
    /// capable" (a real quote can be produced). Use this for "is there SGX at all"
    /// wording; use `is_hardware` to gate quote-dependent claims.
    pub fn sgx_present(&self) -> bool {
        matches!(
            self,
            AttestationType::Dcap | AttestationType::Epid | AttestationType::SgxNoAttest
        )
    }

    pub fn label(&self) -> String {
        match self {
            AttestationType::None => "none (gramine-direct / no SGX)".to_string(),
            AttestationType::SgxNoAttest => {
                "none (gramine-sgx; remote attestation disabled - EGETKEY sealing available)"
                    .to_string()
            }
            AttestationType::Dcap => "dcap (gramine-sgx)".to_string(),
            AttestationType::Epid => "epid (gramine-sgx)".to_string(),
            AttestationType::Other(s) => format!("other:{s}"),
            AttestationType::Unavailable => "unavailable (not under Gramine)".to_string(),
        }
    }
}

/// Disambiguate a Gramine `none` attestation type. `/dev/attestation/attestation_type`
/// reads `none` both under `gramine-direct` (no SGX) and under real `gramine-sgx` whose
/// manifest did not enable remote attestation. EGETKEY availability is the discriminator:
/// real SGX derives `keys/_sgx_mrsigner`, gramine-direct cannot.
fn classify_none(egetkey_available: bool) -> AttestationType {
    if egetkey_available {
        AttestationType::SgxNoAttest
    } else {
        AttestationType::None
    }
}

/// Classify the attestation environment.
///
/// Grounded in observed behaviour: under `gramine-sgx` the
/// `/dev/attestation/attestation_type` pseudo-file reads `dcap`/`epid`; under
/// `gramine-direct` the `/dev/attestation` directory exists but real attestation
/// is unavailable (the type file is absent/`none`, `keys/` is empty, and
/// `user_report_data` is not writable); a bare process has no `/dev/attestation`
/// at all.
///
/// A `none` type file is ambiguous: it appears both under `gramine-direct` and
/// under real `gramine-sgx` whose manifest did not enable remote attestation. We
/// resolve it via EGETKEY availability (`sealing_key_raw` reading
/// `keys/_sgx_mrsigner`) - real SGX -> [`AttestationType::SgxNoAttest`],
/// gramine-direct -> [`AttestationType::None`]. See [`classify_none`].
pub fn attestation_type() -> AttestationType {
    if let Ok(s) = fs::read_to_string(format!("{ATTEST_DIR}/attestation_type")) {
        return match s.trim() {
            "dcap" => AttestationType::Dcap,
            "epid" => AttestationType::Epid,
            "none" | "" => classify_none(sealing_key_raw(true).is_ok()),
            other => AttestationType::Other(other.to_string()),
        };
    }
    // No readable type file. If the Gramine attestation dir exists at all we are
    // under Gramine without a configured remote-attestation type; EGETKEY
    // availability still tells real SGX (gramine-sgx) from gramine-direct.
    // Otherwise we are not under Gramine.
    if fs::metadata(ATTEST_DIR).is_ok() {
        classify_none(sealing_key_raw(true).is_ok())
    } else {
        AttestationType::Unavailable
    }
}

/// Produce a real SGX DCAP quote binding `report_data` (64 bytes): write
/// `user_report_data`, then read back `quote`. Only succeeds under `gramine-sgx`
/// with DCAP remote attestation; under `gramine-direct` the `quote` read fails
/// and this returns `Err` (the caller degrades honestly rather than faking).
pub fn dcap_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let urd = format!("{ATTEST_DIR}/user_report_data");
    fs::write(&urd, &report_data[..]).map_err(|e| format!("write {urd}: {e}"))?;
    let qf = format!("{ATTEST_DIR}/quote");
    let quote = fs::read(&qf).map_err(|e| format!("read {qf}: {e}"))?;
    if quote.len() < MIN_QUOTE_LEN {
        return Err(format!(
            "quote too short: {} < {MIN_QUOTE_LEN}",
            quote.len()
        ));
    }
    Ok(quote)
}

/// Decode one canonical registration intent and derive the exact 64-byte value
/// that Gramine must place in the SGX report body. This boundary exists only in
/// `dcap-fixture-capture` builds; production binaries do not expose arbitrary
/// intent-driven quote generation.
#[cfg(feature = "dcap-fixture-capture")]
pub fn capture_report_data_from_intent(canonical_intent: &[u8]) -> Result<[u8; 64], String> {
    use outbe_primitives::tee_attestation_v1::{AttestationMode, RegistrationIntentV1};

    let intent = RegistrationIntentV1::decode_canonical(canonical_intent)
        .map_err(|error| format!("decode canonical RegistrationIntentV1: {error}"))?;
    if intent.attestation_mode != AttestationMode::DcapRequired {
        return Err("capture intent does not require DCAP".to_owned());
    }
    intent
        .report_data()
        .map_err(|error| format!("derive RegistrationIntentV1 report_data: {error}"))
}

/// Capture a real DCAP quote for one canonical intent into a new output file.
/// Both paths are expected to live in the Gramine capture work directory,
/// which is mounted as an untrusted allowed file tree by the capture launcher.
#[cfg(feature = "dcap-fixture-capture")]
pub fn capture_dcap_quote_to_file(intent_path: &str, quote_path: &str) -> Result<(), String> {
    use std::io::Write;

    let canonical_intent =
        fs::read(intent_path).map_err(|error| format!("read {intent_path}: {error}"))?;
    let report_data = capture_report_data_from_intent(&canonical_intent)?;
    let quote = dcap_quote(&report_data)?;
    let measurements = parse_quote_measurements(&quote)?;
    if measurements.report_data != report_data {
        return Err("captured quote REPORT_DATA does not match the canonical intent".to_owned());
    }

    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(quote_path)
        .map_err(|error| format!("create {quote_path}: {error}"))?;
    output
        .write_all(&quote)
        .map_err(|error| format!("write {quote_path}: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("sync {quote_path}: {error}"))
}

/// Read this enclave's REAL measurements (MRENCLAVE/MRSIGNER/ISVSVN) from a LOCAL
/// SGX report (`/dev/attestation/report`), which Gramine produces via EREPORT with
/// NO DCAP/PCCS provisioning - so it works under `gramine-sgx` even when remote
/// attestation is disabled (manifest `sgx.remote_attestation = "none"`). EREPORT
/// needs a target enclave; for a self-report we target THIS enclave by copying
/// `my_target_info` into `target_info`. `report_data` is written so the local
/// report still commits to the enclave's cleartext keys. Returns `Err` under
/// `gramine-direct`/bare (no `/dev/attestation/report`), where the caller falls
/// back to zero (unmeasured) - never fabricated.
pub fn local_report_measurements(report_data: &[u8; 64]) -> Result<ReportMeasurements, String> {
    let mti = format!("{ATTEST_DIR}/my_target_info");
    let ti = format!("{ATTEST_DIR}/target_info");
    let my_target_info = fs::read(&mti).map_err(|e| format!("read {mti}: {e}"))?;
    fs::write(&ti, &my_target_info).map_err(|e| format!("write {ti}: {e}"))?;
    let urd = format!("{ATTEST_DIR}/user_report_data");
    fs::write(&urd, &report_data[..]).map_err(|e| format!("write {urd}: {e}"))?;
    let rf = format!("{ATTEST_DIR}/report");
    let report = fs::read(&rf).map_err(|e| format!("read {rf}: {e}"))?;
    // A standalone SGX report (`sgx_report_t`) has its report BODY at offset 0,
    // whereas `parse_quote_measurements` expects the body after the 48-byte quote
    // header. Prepend `REPORT_BODY_OFFSET` zero bytes so the single-source-of-truth
    // parser reads MRENCLAVE/MRSIGNER/ISVSVN at the identical field offsets.
    let mut as_quote = vec![0u8; REPORT_BODY_OFFSET];
    as_quote.extend_from_slice(&report);
    parse_quote_measurements(&as_quote)
}

/// EGETKEY-derived sealing key from Gramine's `/dev/attestation/keys/<name>`.
/// `mrsigner` survives an enclave update by the same signer; `mrenclave` is
/// strict per-build. Gramine returns a 128-bit key; we expand it to 256 bits with
/// the caller's HKDF. Only available under `gramine-sgx`.
pub fn sealing_key_raw(mrsigner_policy: bool) -> Result<Vec<u8>, String> {
    let name = if mrsigner_policy {
        "_sgx_mrsigner"
    } else {
        "_sgx_mrenclave"
    };
    let path = format!("{ATTEST_DIR}/keys/{name}");
    let key = fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    if key.is_empty() {
        return Err(format!("{path} returned empty key"));
    }
    Ok(key)
}

/// 256-bit sealing key for the `TSEAL` blob, HKDF-expanded from the real 128-bit
/// EGETKEY key. This is the production sealing-key source: it ties the sealed
/// root seed to MRSIGNER (survives a same-signer enclave update). Returns `Err`
/// when no SGX hardware is present (gramine-direct/bare), where there is no
/// confidential at-rest persistence - the caller must not silently substitute a
/// fixed key.
pub fn sealing_key_256(mrsigner_policy: bool) -> Result<[u8; 32], String> {
    let raw = sealing_key_raw(mrsigner_policy)?;
    crate::crypto::hkdf_sha256(&raw, b"", b"outbe/tee/seal-key/v1").map_err(|e| e.to_string())
}

/// Diagnostic dump of the whole attestation surface - used by the
/// `--probe-attestation` startup mode to observe real Gramine behaviour instead
/// of guessing it. Prints to stderr; performs no secret-revealing reads (the
/// sealing key bytes are summarised by length only).
pub fn probe_to_stderr() {
    eprintln!("=== gramine /dev/attestation probe ===");
    let at = attestation_type();
    eprintln!("attestation_type: {}", at.label());

    match fs::read_dir(ATTEST_DIR) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            names.sort();
            eprintln!("/dev/attestation entries: {names:?}");
        }
        Err(e) => eprintln!("/dev/attestation readdir: {e}"),
    }
    match fs::read_dir(format!("{ATTEST_DIR}/keys")) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            names.sort();
            eprintln!("/dev/attestation/keys entries: {names:?}");
        }
        Err(e) => eprintln!("/dev/attestation/keys readdir: {e}"),
    }

    let rd = [0u8; 64];
    match local_report_measurements(&rd) {
        Ok(m) => eprintln!(
            "local_report: mrenclave={} mrsigner={} isv_prod_id={} isv_svn={}",
            hex::encode(m.mrenclave),
            hex::encode(m.mrsigner),
            m.isv_prod_id,
            m.isv_svn
        ),
        Err(e) => eprintln!("local_report: UNAVAILABLE ({e})"),
    }
    match dcap_quote(&rd) {
        Ok(q) => {
            eprintln!("dcap_quote: {} bytes", q.len());
            match parse_quote_measurements(&q) {
                Ok(m) => eprintln!(
                    "  mrenclave={} mrsigner={} isv_svn={}",
                    hex::encode(m.mrenclave),
                    hex::encode(m.mrsigner),
                    m.isv_svn
                ),
                Err(e) => eprintln!("  parse: {e}"),
            }
        }
        Err(e) => eprintln!("dcap_quote: UNAVAILABLE ({e})"),
    }
    for policy in [true, false] {
        match sealing_key_raw(policy) {
            Ok(k) => eprintln!(
                "sealing_key({}): {} bytes",
                if policy { "mrsigner" } else { "mrenclave" },
                k.len()
            ),
            Err(e) => eprintln!(
                "sealing_key({}): UNAVAILABLE ({e})",
                if policy { "mrsigner" } else { "mrenclave" }
            ),
        }
    }
    eprintln!("=== end probe ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_none_uses_egetkey_as_discriminator() {
        // EGETKEY derives -> real SGX with attestation disabled.
        assert_eq!(classify_none(true), AttestationType::SgxNoAttest);
        // EGETKEY absent -> gramine-direct / no SGX.
        assert_eq!(classify_none(false), AttestationType::None);
    }

    #[test]
    fn sgx_no_attest_label_does_not_claim_no_sgx() {
        let label = AttestationType::SgxNoAttest.label();
        assert!(label.contains("gramine-sgx"), "label was: {label}");
        assert!(
            !label.contains("no SGX"),
            "label must not claim no SGX: {label}"
        );
        // The genuine no-SGX case keeps its label.
        assert!(AttestationType::None.label().contains("no SGX"));
    }

    #[test]
    fn sgx_no_attest_is_present_but_not_remote_attested() {
        // Real SGX present, but not remote-attestation capable (no quote).
        assert!(AttestationType::SgxNoAttest.sgx_present());
        assert!(!AttestationType::SgxNoAttest.is_hardware());
        // gramine-direct: neither.
        assert!(!AttestationType::None.sgx_present());
        assert!(!AttestationType::None.is_hardware());
        // DCAP: both.
        assert!(AttestationType::Dcap.sgx_present());
        assert!(AttestationType::Dcap.is_hardware());
    }
}
