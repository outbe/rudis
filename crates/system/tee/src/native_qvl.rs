//! Exact-pinned Intel native QVL adapter for the V1 consensus verifier.
//!
//! This module is compiled into the Outbe Gramine enclave. Its public boundary
//! accepts only quote/collateral bytes plus an explicit consensus timestamp;
//! there is deliberately no host-verdict input. Intel QvE/TVL are unnecessary
//! because QVL and its output execute within the same attestation enclave.

use std::ffi::c_int;

const QVL_RESULT_OK: u32 = 0;
const QVL_RESULT_CONFIG_NEEDED: u32 = 0xA001;
const QVL_RESULT_OUT_OF_DATE: u32 = 0xA002;
const QVL_RESULT_OUT_OF_DATE_CONFIG_NEEDED: u32 = 0xA003;
const QVL_RESULT_INVALID_SIGNATURE: u32 = 0xA004;
const QVL_RESULT_REVOKED: u32 = 0xA005;
const QVL_RESULT_UNSPECIFIED: u32 = 0xA006;
const QVL_RESULT_SW_HARDENING_NEEDED: u32 = 0xA007;
const QVL_RESULT_CONFIG_AND_SW_HARDENING_NEEDED: u32 = 0xA008;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeQvlStatus {
    UpToDate,
    ConfigurationNeeded,
    OutOfDate,
    OutOfDateAndConfigurationNeeded,
    InvalidSignature,
    Revoked,
    Unspecified,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
}

/// SGX results from Intel `sgx_qve_header.h` SHA-256
/// `f8994fcb1b56ed938adbf923146b5fed8c3e8d5d7d6827f45342db0a23e56677`,
/// installed by exact-pinned `libsgx-headers 2.29.100.1-noble1` and paired by
/// the release contract with `libsgx-dcap-quote-verify 1.26.100.1-noble1`.
///
/// This test-only vector is shared with the Outbe Platform/QE policy matrix so
/// every policy case starts from the exact native ABI value. TDX-only results
/// remain outside the SGX V1 vocabulary and fail closed in `from_raw`.
#[cfg(test)]
pub(crate) const SGX_QVL_STATUS_VECTORS: [(u32, NativeQvlStatus); 9] = [
    (0x0000, NativeQvlStatus::UpToDate),
    (0xA001, NativeQvlStatus::ConfigurationNeeded),
    (0xA002, NativeQvlStatus::OutOfDate),
    (0xA003, NativeQvlStatus::OutOfDateAndConfigurationNeeded),
    (0xA004, NativeQvlStatus::InvalidSignature),
    (0xA005, NativeQvlStatus::Revoked),
    (0xA006, NativeQvlStatus::Unspecified),
    (0xA007, NativeQvlStatus::SWHardeningNeeded),
    (0xA008, NativeQvlStatus::ConfigurationAndSWHardeningNeeded),
];

impl NativeQvlStatus {
    fn from_raw(value: u32) -> Result<Self, NativeQvlError> {
        match value {
            QVL_RESULT_OK => Ok(Self::UpToDate),
            QVL_RESULT_CONFIG_NEEDED => Ok(Self::ConfigurationNeeded),
            QVL_RESULT_OUT_OF_DATE => Ok(Self::OutOfDate),
            QVL_RESULT_OUT_OF_DATE_CONFIG_NEEDED => Ok(Self::OutOfDateAndConfigurationNeeded),
            QVL_RESULT_INVALID_SIGNATURE => Ok(Self::InvalidSignature),
            QVL_RESULT_REVOKED => Ok(Self::Revoked),
            QVL_RESULT_UNSPECIFIED => Ok(Self::Unspecified),
            QVL_RESULT_SW_HARDENING_NEEDED => Ok(Self::SWHardeningNeeded),
            QVL_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
                Ok(Self::ConfigurationAndSWHardeningNeeded)
            }
            _ => Err(NativeQvlError::UnsupportedResult),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeQvlSupplemental {
    pub major_version: u16,
    pub minor_version: u16,
    pub earliest_issue_date: i64,
    pub latest_issue_date: i64,
    pub earliest_expiration_date: i64,
    /// Intel `tcb_eval_ref_num`: the lower Platform/QE evaluation reference.
    pub tcb_evaluation_data_number: u32,
    pub pce_id: u16,
    pub tee_type: u32,
    pub sgx_type: u8,
    pub dynamic_platform: i32,
    pub cached_keys: i32,
    pub smt_enabled: i32,
    pub advisory_ids: Vec<String>,
    pub qe_status: NativeQvlStatus,
    /// Intel `qe_iden_tcb_eval_ref_num`; pinned QVL 1.26 may report zero.
    pub qe_tcb_evaluation_data_number: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeQvlVerdict {
    pub aggregate_status: NativeQvlStatus,
    pub collateral_expired: bool,
    pub supplemental: NativeQvlSupplemental,
}

impl std::fmt::Debug for NativeQvlVerdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeQvlVerdict")
            .field("aggregate_status", &self.aggregate_status)
            .field("collateral_expired", &self.collateral_expired)
            .field(
                "supplemental_version",
                &(
                    self.supplemental.major_version,
                    self.supplemental.minor_version,
                ),
            )
            .field(
                "tcb_evaluation_reference_number",
                &self.supplemental.tcb_evaluation_data_number,
            )
            .field("pce_id", &self.supplemental.pce_id)
            .field("tee_type", &self.supplemental.tee_type)
            .field("sgx_type", &self.supplemental.sgx_type)
            .field("advisory_ids", &self.supplemental.advisory_ids)
            .field("qe_status", &self.supplemental.qe_status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub struct NativeDcapCollateral<'a> {
    pub pck_crl_issuer_chain: &'a [u8],
    pub root_ca_crl: &'a [u8],
    pub pck_crl: &'a [u8],
    pub tcb_info_issuer_chain: &'a [u8],
    pub tcb_info: &'a [u8],
    pub qe_identity_issuer_chain: &'a [u8],
    pub qe_identity: &'a [u8],
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum NativeQvlError {
    #[error("native QVL input is empty, oversized, or contains an embedded NUL")]
    InvalidInput,
    #[error("native QVL ABI does not match the pinned Outbe adapter")]
    UnsupportedAbi,
    #[error("native QVL rejected the quote or collateral")]
    VerificationFailed,
    #[error("native QVL returned an unsupported result")]
    UnsupportedResult,
    #[error("native QVL returned malformed supplemental data")]
    MalformedSupplemental,
}

#[repr(C)]
struct RawCollateral {
    pck_crl_issuer_chain: *const u8,
    pck_crl_issuer_chain_size: u32,
    root_ca_crl: *const u8,
    root_ca_crl_size: u32,
    pck_crl: *const u8,
    pck_crl_size: u32,
    tcb_info_issuer_chain: *const u8,
    tcb_info_issuer_chain_size: u32,
    tcb_info: *const u8,
    tcb_info_size: u32,
    qe_identity_issuer_chain: *const u8,
    qe_identity_issuer_chain_size: u32,
    qe_identity: *const u8,
    qe_identity_size: u32,
}

#[repr(C)]
struct RawResult {
    aggregate_status: u32,
    collateral_expiration_status: u32,
    supplemental_major_version: u16,
    supplemental_minor_version: u16,
    earliest_issue_date: i64,
    latest_issue_date: i64,
    earliest_expiration_date: i64,
    tcb_evaluation_data_number: u32,
    pce_id: u16,
    tee_type: u32,
    sgx_type: u8,
    dynamic_platform: i32,
    cached_keys: i32,
    smt_enabled: i32,
    advisory_ids: [u8; 450],
    qe_status: u32,
    qe_tcb_evaluation_data_number: u32,
}

impl Default for RawResult {
    fn default() -> Self {
        Self {
            aggregate_status: 0,
            collateral_expiration_status: 0,
            supplemental_major_version: 0,
            supplemental_minor_version: 0,
            earliest_issue_date: 0,
            latest_issue_date: 0,
            earliest_expiration_date: 0,
            tcb_evaluation_data_number: 0,
            pce_id: 0,
            tee_type: 0,
            sgx_type: 0,
            dynamic_platform: 0,
            cached_keys: 0,
            smt_enabled: 0,
            advisory_ids: [0; 450],
            qe_status: 0,
            qe_tcb_evaluation_data_number: 0,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<RawCollateral>() == 112);
    assert!(std::mem::align_of::<RawCollateral>() == 8);
    assert!(std::mem::size_of::<RawResult>() == 528);
    assert!(std::mem::align_of::<RawResult>() == 8);
    assert!(std::mem::offset_of!(RawResult, earliest_issue_date) == 16);
    assert!(std::mem::offset_of!(RawResult, advisory_ids) == 68);
    assert!(std::mem::offset_of!(RawResult, qe_status) == 520);
};

#[cfg(native_qvl_linked)]
#[allow(unsafe_code)]
unsafe extern "C" {
    fn outbe_qvl_verify_quote_v1(
        quote: *const u8,
        quote_size: u32,
        collateral: *const RawCollateral,
        expiration_check_date: i64,
        output: *mut RawResult,
    ) -> c_int;
}

/// Verify a real SGX quote using only caller-supplied canonical collateral and
/// an explicit consensus timestamp.
pub fn verify_quote_native(
    quote: &[u8],
    collateral: &NativeDcapCollateral<'_>,
    block_timestamp: i64,
) -> Result<NativeQvlVerdict, NativeQvlError> {
    if block_timestamp < 0 {
        return Err(NativeQvlError::InvalidInput);
    }
    let quote_size = nonempty_len(quote)?;
    let pck_crl_issuer_chain = nul_terminated(collateral.pck_crl_issuer_chain)?;
    let tcb_info_issuer_chain = nul_terminated(collateral.tcb_info_issuer_chain)?;
    let tcb_info = nul_terminated(collateral.tcb_info)?;
    let qe_identity_issuer_chain = nul_terminated(collateral.qe_identity_issuer_chain)?;
    let qe_identity = nul_terminated(collateral.qe_identity)?;
    let raw = RawCollateral {
        pck_crl_issuer_chain: pck_crl_issuer_chain.as_ptr(),
        pck_crl_issuer_chain_size: len_u32(&pck_crl_issuer_chain)?,
        root_ca_crl: collateral.root_ca_crl.as_ptr(),
        root_ca_crl_size: nonempty_len(collateral.root_ca_crl)?,
        pck_crl: collateral.pck_crl.as_ptr(),
        pck_crl_size: nonempty_len(collateral.pck_crl)?,
        tcb_info_issuer_chain: tcb_info_issuer_chain.as_ptr(),
        tcb_info_issuer_chain_size: len_u32(&tcb_info_issuer_chain)?,
        tcb_info: tcb_info.as_ptr(),
        tcb_info_size: len_u32(&tcb_info)?,
        qe_identity_issuer_chain: qe_identity_issuer_chain.as_ptr(),
        qe_identity_issuer_chain_size: len_u32(&qe_identity_issuer_chain)?,
        qe_identity: qe_identity.as_ptr(),
        qe_identity_size: len_u32(&qe_identity)?,
    };
    let mut output = RawResult::default();

    let wrapper_status = call_native(quote, quote_size, &raw, block_timestamp, &mut output);
    match wrapper_status {
        0 => convert_output(output),
        1 => Err(NativeQvlError::InvalidInput),
        2 => Err(NativeQvlError::UnsupportedAbi),
        3 => Err(NativeQvlError::VerificationFailed),
        _ => Err(NativeQvlError::UnsupportedAbi),
    }
}

/// Built without the exact-pinned Intel QVL (see `build.rs`): report the
/// wrapper's unsupported-ABI status so every verification fails closed instead
/// of requiring the SGX toolchain on hosts that never verify a quote.
#[cfg(not(native_qvl_linked))]
fn call_native(
    _quote: &[u8],
    _quote_size: u32,
    _collateral: &RawCollateral,
    _block_timestamp: i64,
    _output: &mut RawResult,
) -> c_int {
    2
}

#[cfg(native_qvl_linked)]
#[allow(unsafe_code)]
fn call_native(
    quote: &[u8],
    quote_size: u32,
    collateral: &RawCollateral,
    block_timestamp: i64,
    output: &mut RawResult,
) -> c_int {
    // SAFETY: every pointer is valid for its checked length throughout this
    // call. The C wrapper is compiled against the pinned Intel headers and
    // writes only the fixed-size `RawResult` structure.
    unsafe {
        outbe_qvl_verify_quote_v1(
            quote.as_ptr(),
            quote_size,
            collateral,
            block_timestamp,
            output,
        )
    }
}

fn convert_output(output: RawResult) -> Result<NativeQvlVerdict, NativeQvlError> {
    if output.supplemental_major_version != 3
        || output.supplemental_minor_version != 0
        || output.earliest_issue_date <= 0
        || output.latest_issue_date < output.earliest_issue_date
        || output.earliest_expiration_date <= output.latest_issue_date
        || output.earliest_expiration_date <= 0
        || output.collateral_expiration_status > 1
    {
        return Err(NativeQvlError::MalformedSupplemental);
    }
    Ok(NativeQvlVerdict {
        aggregate_status: NativeQvlStatus::from_raw(output.aggregate_status)?,
        collateral_expired: output.collateral_expiration_status != 0,
        supplemental: NativeQvlSupplemental {
            major_version: output.supplemental_major_version,
            minor_version: output.supplemental_minor_version,
            earliest_issue_date: output.earliest_issue_date,
            latest_issue_date: output.latest_issue_date,
            earliest_expiration_date: output.earliest_expiration_date,
            tcb_evaluation_data_number: output.tcb_evaluation_data_number,
            pce_id: output.pce_id,
            tee_type: output.tee_type,
            sgx_type: output.sgx_type,
            dynamic_platform: output.dynamic_platform,
            cached_keys: output.cached_keys,
            smt_enabled: output.smt_enabled,
            advisory_ids: parse_advisory_ids(&output.advisory_ids)?,
            qe_status: NativeQvlStatus::from_raw(output.qe_status)?,
            qe_tcb_evaluation_data_number: output.qe_tcb_evaluation_data_number,
        },
    })
}

fn parse_advisory_ids(bytes: &[u8; 450]) -> Result<Vec<String>, NativeQvlError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(NativeQvlError::MalformedSupplemental)?;
    let value =
        std::str::from_utf8(&bytes[..end]).map_err(|_| NativeQvlError::MalformedSupplemental)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|advisory| {
            if advisory.is_empty()
                || !advisory
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(NativeQvlError::MalformedSupplemental);
            }
            Ok(advisory.to_owned())
        })
        .collect()
}

fn nul_terminated(bytes: &[u8]) -> Result<Vec<u8>, NativeQvlError> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(NativeQvlError::InvalidInput);
    }
    let mut value = Vec::with_capacity(bytes.len().saturating_add(1));
    value.extend_from_slice(bytes);
    value.push(0);
    let _ = len_u32(&value)?;
    Ok(value)
}

fn nonempty_len(bytes: &[u8]) -> Result<u32, NativeQvlError> {
    if bytes.is_empty() {
        return Err(NativeQvlError::InvalidInput);
    }
    len_u32(bytes)
}

fn len_u32(bytes: &[u8]) -> Result<u32, NativeQvlError> {
    u32::try_from(bytes.len()).map_err(|_| NativeQvlError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_raw_result() -> RawResult {
        RawResult {
            supplemental_major_version: 3,
            supplemental_minor_version: 0,
            earliest_issue_date: 100,
            latest_issue_date: 200,
            earliest_expiration_date: 300,
            ..RawResult::default()
        }
    }

    #[test]
    fn pinned_intel_qvl_sgx_status_abi_is_converted_for_platform_and_qe() {
        for (raw, expected) in SGX_QVL_STATUS_VECTORS {
            assert_eq!(NativeQvlStatus::from_raw(raw), Ok(expected));

            let mut platform_output = valid_raw_result();
            platform_output.aggregate_status = raw;
            assert_eq!(
                convert_output(platform_output).unwrap().aggregate_status,
                expected
            );

            let mut qe_output = valid_raw_result();
            qe_output.qe_status = raw;
            assert_eq!(
                convert_output(qe_output).unwrap().supplemental.qe_status,
                expected
            );
        }
    }

    #[test]
    fn non_sgx_qvl_status_values_fail_closed() {
        for raw in [0xA009, 0xA00A, 0xA0FF, u32::MAX] {
            assert_eq!(
                NativeQvlStatus::from_raw(raw),
                Err(NativeQvlError::UnsupportedResult)
            );
        }

        let mut platform_output = valid_raw_result();
        platform_output.aggregate_status = 0xA009;
        assert_eq!(
            convert_output(platform_output),
            Err(NativeQvlError::UnsupportedResult)
        );
        let mut qe_output = valid_raw_result();
        qe_output.qe_status = 0xA00A;
        assert_eq!(
            convert_output(qe_output),
            Err(NativeQvlError::UnsupportedResult)
        );
    }
}
