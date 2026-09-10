//! DCAP (ECDSA) SGX quote measurement parsing shared by the enclave and host.
//!
//! Only the layout needed to extract MRENCLAVE/MRSIGNER/ISVSVN/report_data is
//! modelled. This module parses fields; cryptographic quote verification belongs
//! to the enclave-resident native QVL path.

/// SGX report body offset inside a DCAP ECDSA quote (after the 48-byte header).
/// A standalone local SGX report has its body at offset 0, so prepending this many
/// bytes lets it be parsed by [`parse_quote_measurements`] at the same offsets.
pub const REPORT_BODY_OFFSET: usize = 48;
const RB_MRENCLAVE: usize = 64;
const RB_MRSIGNER: usize = 128;
const RB_ISV_PROD_ID: usize = 256;
const RB_ISV_SVN: usize = 258;
const RB_REPORT_DATA: usize = 320;
/// Minimum quote length to contain a full report body + report_data.
pub const MIN_QUOTE_LEN: usize = REPORT_BODY_OFFSET + RB_REPORT_DATA + 64;

/// Measurements parsed out of a DCAP quote's embedded SGX report body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportMeasurements {
    pub mrenclave: [u8; 32],
    pub mrsigner: [u8; 32],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub report_data: [u8; 64],
}

/// Parse MRENCLAVE/MRSIGNER/ISVSVN/report_data from a real DCAP quote.
pub fn parse_quote_measurements(quote: &[u8]) -> Result<ReportMeasurements, String> {
    if quote.len() < MIN_QUOTE_LEN {
        return Err(format!(
            "quote too short: {} < {MIN_QUOTE_LEN}",
            quote.len()
        ));
    }
    let base = REPORT_BODY_OFFSET;
    let mut mrenclave = [0u8; 32];
    mrenclave.copy_from_slice(&quote[base + RB_MRENCLAVE..base + RB_MRENCLAVE + 32]);
    let mut mrsigner = [0u8; 32];
    mrsigner.copy_from_slice(&quote[base + RB_MRSIGNER..base + RB_MRSIGNER + 32]);
    let isv_prod_id = u16::from_le_bytes([
        quote[base + RB_ISV_PROD_ID],
        quote[base + RB_ISV_PROD_ID + 1],
    ]);
    let isv_svn = u16::from_le_bytes([quote[base + RB_ISV_SVN], quote[base + RB_ISV_SVN + 1]]);
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&quote[base + RB_REPORT_DATA..base + RB_REPORT_DATA + 64]);
    Ok(ReportMeasurements {
        mrenclave,
        mrsigner,
        isv_prod_id,
        isv_svn,
        report_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic quote with known measurement bytes parses at the right offsets.
    #[test]
    fn parses_measurements_at_sgx_offsets() {
        let mut q = vec![0u8; MIN_QUOTE_LEN];
        let base = REPORT_BODY_OFFSET;
        q[base + RB_MRENCLAVE..base + RB_MRENCLAVE + 32].copy_from_slice(&[0xAA; 32]);
        q[base + RB_MRSIGNER..base + RB_MRSIGNER + 32].copy_from_slice(&[0xBB; 32]);
        q[base + RB_ISV_PROD_ID] = 3;
        q[base + RB_ISV_SVN] = 7;
        q[base + RB_REPORT_DATA..base + RB_REPORT_DATA + 32].copy_from_slice(&[0xCC; 32]);
        let m = parse_quote_measurements(&q).unwrap();
        assert_eq!(m.mrenclave, [0xAA; 32]);
        assert_eq!(m.mrsigner, [0xBB; 32]);
        assert_eq!(m.isv_prod_id, 3);
        assert_eq!(m.isv_svn, 7);
        assert_eq!(&m.report_data[..32], &[0xCC; 32]);
    }

    #[test]
    fn rejects_short_quote() {
        assert!(parse_quote_measurements(&[0u8; 100]).is_err());
    }
}
