//! Consensus-facing DCAP verification for attestation protocol V1.
//!
//! Callers supply only canonical evidence, the active policy and consensus
//! time. Quote grammar, collateral adaptation, native QVL invocation and
//! policy mapping remain private implementation details.

use std::{collections::BTreeSet, fmt};

use alloy_primitives::B256;
use der::{
    asn1::{AnyRef, ObjectIdentifier, OctetStringRef},
    Decode as _, Encode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _,
};
use outbe_primitives::tee_attestation_v1::{
    AttestationEvidenceV1, DcapEvidenceV1, PlatformTcbStatusSetV1, TeePolicyV1,
};
use pem::{EncodeConfig, LineEnding};
use serde::{
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

pub use crate::dcap_protocol::{
    DcapPckCaV1, DcapPlatformTcbStatusV1, DcapRejectCodeV1, DcapVerdictV1,
};
use crate::native_qvl::{
    verify_quote_native, NativeDcapCollateral, NativeQvlError, NativeQvlStatus,
    NativeQvlSupplemental,
};

const QUOTE_AUTHENTICATION_DATA_LENGTH_OFFSET: usize = 432;
const QUOTE_AUTHENTICATION_DATA_OFFSET: usize = 436;
const QUOTE_SIGNATURE_BYTES: usize = 64;
const ATTESTATION_PUBLIC_KEY_BYTES: usize = 64;
const QE_REPORT_BYTES: usize = 384;
const QE_REPORT_SIGNATURE_BYTES: usize = 64;

/// Verify one canonical DCAP evidence value using only consensus inputs.
pub fn verify_dcap_evidence(
    evidence: &DcapEvidenceV1,
    policy: &TeePolicyV1,
    block_timestamp: u64,
) -> Result<DcapVerdictV1, DcapRejectCodeV1> {
    AttestationEvidenceV1::Dcap(evidence.clone())
        .encode_canonical()
        .map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    policy
        .encode_canonical()
        .map_err(|_| DcapRejectCodeV1::PolicyNonCanonical)?;
    let policy_hash = policy
        .policy_hash()
        .map_err(|_| DcapRejectCodeV1::PolicyNonCanonical)?;
    if evidence.intent.chain_id != policy.chain_id
        || evidence.intent.genesis_hash != policy.genesis_hash
        || evidence.intent.policy_hash != policy_hash
    {
        return Err(DcapRejectCodeV1::PolicyBindingMismatch);
    }
    if block_timestamp > i64::MAX as u64 {
        return Err(DcapRejectCodeV1::TimestampInvalid);
    }

    validate_quote_outer_length(&evidence.quote)?;
    validate_quote_profile(&evidence.quote, policy)?;
    let quote_authentication = parse_quote_authentication_data(&evidence.quote)?;
    let submitted_pck_chain = evidence
        .components
        .first()
        .ok_or(DcapRejectCodeV1::EvidenceNonCanonical)?;
    if quote_authentication.certification_data_type != policy.certification_data_type
        || quote_authentication.certification_data != submitted_pck_chain.bytes
    {
        return Err(DcapRejectCodeV1::QuoteCertificationDataMismatch);
    }
    let measurements = crate::quote::parse_quote_measurements(&evidence.quote)
        .map_err(|_| DcapRejectCodeV1::QuoteMalformed)?;
    let expected_report_data = evidence
        .intent
        .report_data()
        .map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    if measurements.report_data != expected_report_data {
        return Err(DcapRejectCodeV1::ReportDataMismatch);
    }
    validate_canonical_pck_certificate_chain(component(evidence, 0)?)?;
    validate_canonical_der_crl(component(evidence, 1)?)?;
    validate_canonical_certificate_chain(component(evidence, 2)?, 2)?;
    validate_canonical_der_crl(component(evidence, 3)?)?;
    validate_canonical_certificate_chain(component(evidence, 5)?, 2)?;
    validate_canonical_certificate_chain(component(evidence, 7)?, 2)?;
    if pck_root_der_hash(component(evidence, 0)?)? != policy.intel_root_der_hash {
        return Err(DcapRejectCodeV1::IntelRootMismatch);
    }
    let tcb_info = parse_signed_tcb_info(component(evidence, 4)?, policy)?;
    let qe_identity = parse_signed_qe_identity(component(evidence, 6)?, policy)?;
    let issue_floor = tcb_info.issue_date.max(qe_identity.issue_date);
    let expiration_ceiling = tcb_info.next_update.min(qe_identity.next_update);
    if block_timestamp < issue_floor {
        return Err(DcapRejectCodeV1::CollateralNotYetValid);
    }
    if block_timestamp >= expiration_ceiling {
        return Err(DcapRejectCodeV1::CollateralExpired);
    }
    if tcb_info.tcb_evaluation_data_number < policy.minimum_tcb_evaluation_data_number
        || qe_identity.tcb_evaluation_data_number < policy.minimum_tcb_evaluation_data_number
    {
        return Err(DcapRejectCodeV1::TcbEvaluationNumberTooLow);
    }
    let pck_identity = parse_pck_identity(component(evidence, 0)?)?;
    if pck_identity.fmspc != tcb_info.fmspc || pck_identity.pce_id != tcb_info.pce_id {
        return Err(DcapRejectCodeV1::PlatformIdentityMismatch);
    }
    let measurement_accepted = policy.measurement_rules.iter().any(|rule| {
        rule.mrenclave == B256::from(measurements.mrenclave)
            && rule.mrsigner == B256::from(measurements.mrsigner)
            && rule.isv_prod_id == measurements.isv_prod_id
            && measurements.isv_svn >= rule.minimum_isv_svn
    });
    if !measurement_accepted {
        return Err(DcapRejectCodeV1::MeasurementRejected);
    }
    let native_collateral = NativeDcapCollateral {
        pck_crl_issuer_chain: component(evidence, 2)?,
        root_ca_crl: component(evidence, 3)?,
        pck_crl: component(evidence, 1)?,
        tcb_info_issuer_chain: component(evidence, 5)?,
        tcb_info: component(evidence, 4)?,
        qe_identity_issuer_chain: component(evidence, 7)?,
        qe_identity: component(evidence, 6)?,
    };
    let native_verdict = verify_quote_native(
        &evidence.quote,
        &native_collateral,
        i64::try_from(block_timestamp).map_err(|_| DcapRejectCodeV1::TimestampInvalid)?,
    )
    .map_err(map_native_error)?;
    let signed_pce_id = u16::from_be_bytes(tcb_info.pce_id);
    let collateral_window = reconcile_native_supplemental(
        &native_verdict.supplemental,
        SignedCollateralClaims {
            tee_type: policy.tee_type,
            pce_id: signed_pce_id,
            issue_floor,
            expiration_ceiling,
            platform_tcb_evaluation_data_number: tcb_info.tcb_evaluation_data_number,
            qe_tcb_evaluation_data_number: qe_identity.tcb_evaluation_data_number,
        },
    )?;
    if block_timestamp < collateral_window.issue_floor {
        return Err(DcapRejectCodeV1::CollateralNotYetValid);
    }
    if native_verdict.collateral_expired || block_timestamp >= collateral_window.expiration_ceiling
    {
        return Err(DcapRejectCodeV1::CollateralExpired);
    }
    validate_qe_status(native_verdict.supplemental.qe_status)?;
    let platform_tcb_status = map_platform_status(
        native_verdict.aggregate_status,
        policy.accepted_platform_tcb_statuses,
    )?;

    Ok(DcapVerdictV1 {
        mrenclave: B256::from(measurements.mrenclave),
        mrsigner: B256::from(measurements.mrsigner),
        isv_prod_id: measurements.isv_prod_id,
        isv_svn: measurements.isv_svn,
        pck_ca: pck_identity.ca,
        fmspc: tcb_info.fmspc,
        pce_id: signed_pce_id,
        platform_tcb_status,
        advisory_ids: native_verdict.supplemental.advisory_ids,
        tcb_evaluation_data_number: tcb_info.tcb_evaluation_data_number,
        qe_tcb_evaluation_data_number: qe_identity.tcb_evaluation_data_number,
        collateral_valid_until: collateral_window.expiration_ceiling,
    })
}

/// Signed Intel collateral time bounds needed by the host renewal scheduler.
///
/// This is deliberately narrower than [`verify_dcap_evidence`]: it validates
/// the canonical TCB-info and QE-identity envelopes under the active policy and
/// returns only their intersection. Quote acceptance remains consensus work in
/// the enclave QVL path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcapCollateralValidityWindowV1 {
    pub issue_floor: u64,
    pub expiration_ceiling: u64,
}

pub fn dcap_collateral_validity_window_v1(
    evidence: &DcapEvidenceV1,
    policy: &TeePolicyV1,
) -> Result<DcapCollateralValidityWindowV1, DcapRejectCodeV1> {
    AttestationEvidenceV1::Dcap(evidence.clone())
        .encode_canonical()
        .map_err(|_| DcapRejectCodeV1::EvidenceNonCanonical)?;
    policy
        .encode_canonical()
        .map_err(|_| DcapRejectCodeV1::PolicyNonCanonical)?;
    let tcb_info = parse_signed_tcb_info(component(evidence, 4)?, policy)?;
    let qe_identity = parse_signed_qe_identity(component(evidence, 6)?, policy)?;
    Ok(DcapCollateralValidityWindowV1 {
        issue_floor: tcb_info.issue_date.max(qe_identity.issue_date),
        expiration_ceiling: tcb_info.next_update.min(qe_identity.next_update),
    })
}

#[derive(Clone, Copy)]
struct SignedCollateralClaims {
    tee_type: u32,
    pce_id: u16,
    issue_floor: u64,
    expiration_ceiling: u64,
    platform_tcb_evaluation_data_number: u32,
    qe_tcb_evaluation_data_number: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CollateralWindow {
    issue_floor: u64,
    expiration_ceiling: u64,
}

fn reconcile_native_supplemental(
    supplemental: &NativeQvlSupplemental,
    signed: SignedCollateralClaims,
) -> Result<CollateralWindow, DcapRejectCodeV1> {
    let issue_floor = u64::try_from(supplemental.latest_issue_date)
        .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
    let expiration_ceiling = u64::try_from(supplemental.earliest_expiration_date)
        .map_err(|_| DcapRejectCodeV1::NativeOutputMalformed)?;
    let expected_tcb_evaluation_reference = signed
        .platform_tcb_evaluation_data_number
        .min(signed.qe_tcb_evaluation_data_number);
    if supplemental.tee_type != signed.tee_type
        || supplemental.pce_id != signed.pce_id
        || supplemental.tcb_evaluation_data_number != expected_tcb_evaluation_reference
        || (supplemental.qe_tcb_evaluation_data_number != 0
            && supplemental.qe_tcb_evaluation_data_number != signed.qe_tcb_evaluation_data_number)
        || issue_floor < signed.issue_floor
        || expiration_ceiling > signed.expiration_ceiling
    {
        return Err(DcapRejectCodeV1::NativeOutputMalformed);
    }
    Ok(CollateralWindow {
        issue_floor,
        expiration_ceiling,
    })
}

const fn map_native_error(error: NativeQvlError) -> DcapRejectCodeV1 {
    match error {
        NativeQvlError::InvalidInput => DcapRejectCodeV1::CollateralNonCanonical,
        NativeQvlError::UnsupportedAbi => DcapRejectCodeV1::NativeVerifierUnavailable,
        NativeQvlError::VerificationFailed => DcapRejectCodeV1::NativeVerificationFailed,
        NativeQvlError::UnsupportedResult | NativeQvlError::MalformedSupplemental => {
            DcapRejectCodeV1::NativeOutputMalformed
        }
    }
}

const fn map_platform_status(
    status: NativeQvlStatus,
    accepted: PlatformTcbStatusSetV1,
) -> Result<DcapPlatformTcbStatusV1, DcapRejectCodeV1> {
    match (status, accepted) {
        (NativeQvlStatus::UpToDate, _) => Ok(DcapPlatformTcbStatusV1::UpToDate),
        (NativeQvlStatus::SWHardeningNeeded, PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded) => {
            Ok(DcapPlatformTcbStatusV1::SWHardeningNeeded)
        }
        (
            NativeQvlStatus::ConfigurationAndSWHardeningNeeded,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        ) => Ok(DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded),
        _ => Err(DcapRejectCodeV1::PlatformTcbRejected),
    }
}

const fn validate_qe_status(status: NativeQvlStatus) -> Result<(), DcapRejectCodeV1> {
    match status {
        NativeQvlStatus::UpToDate => Ok(()),
        _ => Err(DcapRejectCodeV1::QeTcbRejected),
    }
}

fn component(evidence: &DcapEvidenceV1, index: usize) -> Result<&[u8], DcapRejectCodeV1> {
    evidence
        .components
        .get(index)
        .map(|component| component.bytes.as_slice())
        .ok_or(DcapRejectCodeV1::EvidenceNonCanonical)
}

fn validate_canonical_pck_certificate_chain(bytes: &[u8]) -> Result<(), DcapRejectCodeV1> {
    let canonical_pem = bytes
        .strip_suffix(&[0])
        .ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    if canonical_pem.contains(&0) {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    validate_canonical_certificate_chain(canonical_pem, 3)
}

fn pck_root_der_hash(bytes: &[u8]) -> Result<B256, DcapRejectCodeV1> {
    let canonical_pem = bytes
        .strip_suffix(&[0])
        .ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    let certificates =
        pem::parse_many(canonical_pem).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let root = certificates
        .last()
        .ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    Ok(B256::from_slice(&Sha256::digest(root.contents())))
}

struct PckIdentity {
    ca: DcapPckCaV1,
    fmspc: [u8; 6],
    pce_id: [u8; 2],
}

fn parse_pck_identity(bytes: &[u8]) -> Result<PckIdentity, DcapRejectCodeV1> {
    const SGX_EXTENSION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
    const PCE_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.3");
    const FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

    let canonical_pem = bytes
        .strip_suffix(&[0])
        .ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    let certificates =
        pem::parse_many(canonical_pem).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let leaf = certificates
        .first()
        .ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    let certificate =
        AnyRef::from_der(leaf.contents()).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let (issuer, extensions) = certificate
        .sequence(|reader| {
            let tbs_certificate = reader.decode::<AnyRef<'_>>()?;
            reader.decode::<AnyRef<'_>>()?;
            reader.decode::<AnyRef<'_>>()?;
            tbs_certificate.sequence(|reader| {
                if reader.peek_tag()? == TagNumber::N0.context_specific(true) {
                    reader.decode::<AnyRef<'_>>()?;
                }
                reader.decode::<AnyRef<'_>>()?;
                reader.decode::<AnyRef<'_>>()?;
                let issuer = reader.decode::<AnyRef<'_>>()?;
                reader.decode::<AnyRef<'_>>()?;
                reader.decode::<AnyRef<'_>>()?;
                reader.decode::<AnyRef<'_>>()?;
                let mut extensions = None;
                while !reader.is_finished() {
                    let field = reader.decode::<AnyRef<'_>>()?;
                    if field.tag() == TagNumber::N3.context_specific(true) {
                        extensions = Some(field);
                    }
                }
                Ok((issuer, extensions))
            })
        })
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let extensions = extensions.ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    let ca = pck_ca_from_issuer(issuer)?;
    let sgx_extension = find_certificate_extension(extensions, SGX_EXTENSION_OID)?;
    let mut fmspc = None;
    let mut pce_id = None;
    AnyRef::from_der(sgx_extension.as_bytes())
        .and_then(|entries| {
            entries.sequence(|reader| {
                while !reader.is_finished() {
                    let entry = reader.decode::<AnyRef<'_>>()?;
                    let (oid, value) = entry.sequence(|reader| {
                        let oid = reader.decode::<ObjectIdentifier>()?;
                        let value = reader.decode::<AnyRef<'_>>()?;
                        Ok((oid, value))
                    })?;
                    if oid == FMSPC_OID {
                        let value = value.decode_as::<OctetStringRef<'_>>()?;
                        fmspc = Some(
                            value
                                .as_bytes()
                                .try_into()
                                .map_err(|_| der::Tag::OctetString.unexpected_error(None))?,
                        );
                    } else if oid == PCE_ID_OID {
                        let value = value.decode_as::<OctetStringRef<'_>>()?;
                        pce_id = Some(
                            value
                                .as_bytes()
                                .try_into()
                                .map_err(|_| der::Tag::OctetString.unexpected_error(None))?,
                        );
                    }
                }
                Ok(())
            })
        })
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    Ok(PckIdentity {
        ca,
        fmspc: fmspc.ok_or(DcapRejectCodeV1::CollateralNonCanonical)?,
        pce_id: pce_id.ok_or(DcapRejectCodeV1::CollateralNonCanonical)?,
    })
}

fn pck_ca_from_issuer(issuer: AnyRef<'_>) -> Result<DcapPckCaV1, DcapRejectCodeV1> {
    const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
    let (common_name_count, common_name) = issuer
        .sequence(|reader| {
            let mut common_name_count = 0_u8;
            let mut common_name = None;
            while !reader.is_finished() {
                let relative_name = reader.decode::<AnyRef<'_>>()?;
                relative_name.tag().assert_eq(Tag::Set)?;
                let mut set_reader = SliceReader::new(relative_name.value())?;
                while !set_reader.is_finished() {
                    let attribute = set_reader.decode::<AnyRef<'_>>()?;
                    let (oid, value) = attribute.sequence(|reader| {
                        let oid = reader.decode::<ObjectIdentifier>()?;
                        let value = reader.decode::<AnyRef<'_>>()?;
                        Ok((oid, value))
                    })?;
                    if oid == COMMON_NAME_OID {
                        common_name_count = common_name_count.saturating_add(1);
                        common_name = Some((value.tag(), value.value()));
                    }
                }
                set_reader.finish(())?;
            }
            Ok((common_name_count, common_name))
        })
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let (tag, common_name) = common_name.ok_or(DcapRejectCodeV1::CollateralNonCanonical)?;
    if common_name_count != 1 || !matches!(tag, Tag::Utf8String | Tag::PrintableString) {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    match common_name {
        b"Intel SGX PCK Processor CA" => Ok(DcapPckCaV1::Processor),
        b"Intel SGX PCK Platform CA" => Ok(DcapPckCaV1::Platform),
        _ => Err(DcapRejectCodeV1::PlatformIdentityMismatch),
    }
}

fn find_certificate_extension<'a>(
    explicit_extensions: AnyRef<'a>,
    expected_oid: ObjectIdentifier,
) -> Result<OctetStringRef<'a>, DcapRejectCodeV1> {
    let extensions = AnyRef::from_der(explicit_extensions.value())
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    let mut matched = None;
    extensions
        .sequence(|reader| {
            while !reader.is_finished() {
                let extension = reader.decode::<AnyRef<'_>>()?;
                let (oid, value) = extension.sequence(|reader| {
                    let oid = reader.decode::<ObjectIdentifier>()?;
                    if reader.peek_tag()? == Tag::Boolean {
                        reader.decode::<bool>()?;
                    }
                    let value = reader.decode::<OctetStringRef<'_>>()?;
                    Ok((oid, value))
                })?;
                if oid == expected_oid {
                    if matched.is_some() {
                        return Err(Tag::ObjectIdentifier.unexpected_error(None));
                    }
                    matched = Some(value);
                }
            }
            Ok(())
        })
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    matched.ok_or(DcapRejectCodeV1::CollateralNonCanonical)
}

fn validate_canonical_certificate_chain(
    bytes: &[u8],
    expected_count: usize,
) -> Result<(), DcapRejectCodeV1> {
    let certificates =
        pem::parse_many(bytes).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    if certificates.len() != expected_count {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    let config = EncodeConfig::new().set_line_ending(LineEnding::LF);
    let mut canonical = String::new();
    for certificate in certificates {
        if certificate.tag() != "CERTIFICATE" || certificate.headers().iter().next().is_some() {
            return Err(DcapRejectCodeV1::CollateralNonCanonical);
        }
        let canonical_der = canonical_der_document(certificate.contents())?;
        if canonical_der != certificate.contents() {
            return Err(DcapRejectCodeV1::CollateralNonCanonical);
        }
        canonical.push_str(&pem::encode_config(
            &pem::Pem::new("CERTIFICATE", canonical_der),
            config,
        ));
    }
    if canonical.as_bytes() != bytes {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    Ok(())
}

fn validate_canonical_der_crl(bytes: &[u8]) -> Result<(), DcapRejectCodeV1> {
    let canonical = canonical_der_document(bytes)?;
    if canonical != bytes {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    Ok(())
}

fn canonical_der_document(bytes: &[u8]) -> Result<Vec<u8>, DcapRejectCodeV1> {
    let document = AnyRef::from_der(bytes).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    if document.tag() != Tag::Sequence {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    document
        .to_der()
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedTcbInfo<'a> {
    #[serde(borrow, rename = "tcbInfo")]
    body: &'a RawValue,
    signature: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedQeIdentity<'a> {
    #[serde(borrow, rename = "enclaveIdentity")]
    body: &'a RawValue,
    signature: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoBody<'a> {
    id: &'a str,
    version: u8,
    issue_date: &'a str,
    next_update: &'a str,
    fmspc: &'a str,
    pce_id: &'a str,
    tcb_evaluation_data_number: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityBody<'a> {
    id: &'a str,
    version: u8,
    issue_date: &'a str,
    next_update: &'a str,
    tcb_evaluation_data_number: u32,
}

struct TcbInfoMetadata {
    issue_date: u64,
    next_update: u64,
    fmspc: [u8; 6],
    pce_id: [u8; 2],
    tcb_evaluation_data_number: u32,
}

struct QeIdentityMetadata {
    issue_date: u64,
    next_update: u64,
    tcb_evaluation_data_number: u32,
}

fn parse_signed_tcb_info(
    bytes: &[u8],
    policy: &TeePolicyV1,
) -> Result<TcbInfoMetadata, DcapRejectCodeV1> {
    let signed: SignedTcbInfo<'_> =
        serde_json::from_slice(bytes).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    validate_signed_json_wrapper(bytes, "tcbInfo", signed.body, signed.signature)?;
    let body: TcbInfoBody<'_> = serde_json::from_str(signed.body.get())
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    if body.id != "SGX" || body.version != policy.tcb_info_schema_version {
        return Err(DcapRejectCodeV1::PlatformIdentityMismatch);
    }
    let issue_date = parse_canonical_timestamp(body.issue_date)?;
    let next_update = parse_canonical_timestamp(body.next_update)?;
    if issue_date >= next_update {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    Ok(TcbInfoMetadata {
        issue_date,
        next_update,
        fmspc: decode_upper_hex(body.fmspc)?,
        pce_id: decode_upper_hex(body.pce_id)?,
        tcb_evaluation_data_number: body.tcb_evaluation_data_number,
    })
}

fn parse_signed_qe_identity(
    bytes: &[u8],
    policy: &TeePolicyV1,
) -> Result<QeIdentityMetadata, DcapRejectCodeV1> {
    let signed: SignedQeIdentity<'_> =
        serde_json::from_slice(bytes).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    validate_signed_json_wrapper(bytes, "enclaveIdentity", signed.body, signed.signature)?;
    let body: QeIdentityBody<'_> = serde_json::from_str(signed.body.get())
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?;
    if body.id != "QE" || body.version != policy.qe_identity_schema_version {
        return Err(DcapRejectCodeV1::QeTcbRejected);
    }
    let issue_date = parse_canonical_timestamp(body.issue_date)?;
    let next_update = parse_canonical_timestamp(body.next_update)?;
    if issue_date >= next_update {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    Ok(QeIdentityMetadata {
        issue_date,
        next_update,
        tcb_evaluation_data_number: body.tcb_evaluation_data_number,
    })
}

fn validate_signed_json_wrapper(
    bytes: &[u8],
    field: &str,
    body: &RawValue,
    signature: &str,
) -> Result<(), DcapRejectCodeV1> {
    reject_duplicate_json_keys(bytes)?;
    if !body.get().starts_with('{')
        || !body.get().ends_with('}')
        || signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    let canonical = format!(r#"{{"{field}":{},"signature":"{signature}"}}"#, body.get());
    if canonical.as_bytes() != bytes {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    Ok(())
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), DcapRejectCodeV1> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    RejectDuplicateJsonKeys
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)
}

#[derive(Clone, Copy)]
struct RejectDuplicateJsonKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateJsonKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateJsonKeysVisitor)
    }
}

struct RejectDuplicateJsonKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateJsonKeysVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RejectDuplicateJsonKeys.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(RejectDuplicateJsonKeys)?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(RejectDuplicateJsonKeys)?;
        }
        Ok(())
    }
}

fn parse_canonical_timestamp(value: &str) -> Result<u64, DcapRejectCodeV1> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    let timestamp =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)?
            .unix_timestamp();
    u64::try_from(timestamp).map_err(|_| DcapRejectCodeV1::CollateralNonCanonical)
}

fn decode_upper_hex<const N: usize>(value: &str) -> Result<[u8; N], DcapRejectCodeV1> {
    if value.len() != N * 2 {
        return Err(DcapRejectCodeV1::CollateralNonCanonical);
    }
    let mut decoded = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = upper_hex_nibble(pair[0])?;
        let low = upper_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn upper_hex_nibble(value: u8) -> Result<u8, DcapRejectCodeV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DcapRejectCodeV1::CollateralNonCanonical),
    }
}

fn validate_quote_outer_length(quote: &[u8]) -> Result<(), DcapRejectCodeV1> {
    let declared = quote
        .get(
            QUOTE_AUTHENTICATION_DATA_LENGTH_OFFSET
                ..QUOTE_AUTHENTICATION_DATA_LENGTH_OFFSET + size_of::<u32>(),
        )
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(DcapRejectCodeV1::QuoteMalformed)?;
    let expected = QUOTE_AUTHENTICATION_DATA_OFFSET
        .checked_add(usize::try_from(declared).map_err(|_| DcapRejectCodeV1::QuoteMalformed)?)
        .ok_or(DcapRejectCodeV1::QuoteMalformed)?;
    if quote.len() != expected {
        return Err(DcapRejectCodeV1::QuoteMalformed);
    }
    Ok(())
}

fn validate_quote_profile(quote: &[u8], policy: &TeePolicyV1) -> Result<(), DcapRejectCodeV1> {
    let version = read_u16(quote, 0)?;
    let attestation_key_type = read_u16(quote, 2)?;
    let tee_type = read_u32(quote, 4)?;
    let qe_vendor_id: [u8; 16] = quote
        .get(12..28)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DcapRejectCodeV1::QuoteMalformed)?;
    if version != policy.quote_version
        || attestation_key_type != policy.attestation_key_type
        || tee_type != policy.tee_type
        || qe_vendor_id != policy.qe_vendor_id
    {
        return Err(DcapRejectCodeV1::QuoteProfileMismatch);
    }
    Ok(())
}

fn parse_quote_authentication_data(
    quote: &[u8],
) -> Result<QuoteAuthenticationData<'_>, DcapRejectCodeV1> {
    let mut cursor = QuoteCursor::new(
        quote
            .get(QUOTE_AUTHENTICATION_DATA_OFFSET..)
            .ok_or(DcapRejectCodeV1::QuoteMalformed)?,
    );
    cursor.take(QUOTE_SIGNATURE_BYTES)?;
    cursor.take(ATTESTATION_PUBLIC_KEY_BYTES)?;
    cursor.take(QE_REPORT_BYTES)?;
    cursor.take(QE_REPORT_SIGNATURE_BYTES)?;
    let qe_authentication_data_len = usize::from(cursor.u16()?);
    cursor.take(qe_authentication_data_len)?;
    let certification_data_type = cursor.u16()?;
    let certification_data_len =
        usize::try_from(cursor.u32()?).map_err(|_| DcapRejectCodeV1::QuoteMalformed)?;
    let certification_data = cursor.take(certification_data_len)?;
    cursor.finish()?;
    Ok(QuoteAuthenticationData {
        certification_data_type,
        certification_data,
    })
}

struct QuoteAuthenticationData<'a> {
    certification_data_type: u16,
    certification_data: &'a [u8],
}

struct QuoteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> QuoteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DcapRejectCodeV1> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DcapRejectCodeV1::QuoteMalformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DcapRejectCodeV1::QuoteMalformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, DcapRejectCodeV1> {
        self.take(size_of::<u16>())?
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| DcapRejectCodeV1::QuoteMalformed)
    }

    fn u32(&mut self) -> Result<u32, DcapRejectCodeV1> {
        self.take(size_of::<u32>())?
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| DcapRejectCodeV1::QuoteMalformed)
    }

    fn finish(self) -> Result<(), DcapRejectCodeV1> {
        if self.offset != self.bytes.len() {
            return Err(DcapRejectCodeV1::QuoteMalformed);
        }
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DcapRejectCodeV1> {
    bytes
        .get(offset..offset + size_of::<u16>())
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(DcapRejectCodeV1::QuoteMalformed)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DcapRejectCodeV1> {
    bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(DcapRejectCodeV1::QuoteMalformed)
}

#[cfg(test)]
mod tests {
    use outbe_primitives::tee_attestation_v1::PlatformTcbStatusSetV1;

    use super::*;
    use crate::native_qvl::{NativeQvlStatus, NativeQvlSupplemental, SGX_QVL_STATUS_VECTORS};

    fn supplemental() -> NativeQvlSupplemental {
        NativeQvlSupplemental {
            major_version: 3,
            minor_version: 0,
            earliest_issue_date: 100,
            latest_issue_date: 200,
            earliest_expiration_date: 300,
            tcb_evaluation_data_number: 19,
            pce_id: 7,
            tee_type: 0,
            sgx_type: 0,
            dynamic_platform: 0,
            cached_keys: 0,
            smt_enabled: 0,
            advisory_ids: Vec::new(),
            qe_status: NativeQvlStatus::UpToDate,
            qe_tcb_evaluation_data_number: 0,
        }
    }

    fn signed_collateral_claims() -> SignedCollateralClaims {
        SignedCollateralClaims {
            tee_type: 0,
            pce_id: 7,
            issue_floor: 190,
            expiration_ceiling: 310,
            platform_tcb_evaluation_data_number: 20,
            qe_tcb_evaluation_data_number: 19,
        }
    }

    #[test]
    fn supplemental_reconciliation_uses_lower_evaluation_reference_and_all_collateral_time() {
        assert_eq!(
            reconcile_native_supplemental(&supplemental(), signed_collateral_claims()),
            Ok(CollateralWindow {
                issue_floor: 200,
                expiration_ceiling: 300,
            })
        );
    }

    #[test]
    fn supplemental_reconciliation_rejects_wrong_combined_evaluation_reference() {
        let mut supplemental = supplemental();
        supplemental.tcb_evaluation_data_number = 20;

        assert_eq!(
            reconcile_native_supplemental(&supplemental, signed_collateral_claims()),
            Err(DcapRejectCodeV1::NativeOutputMalformed)
        );
    }

    #[test]
    fn supplemental_reconciliation_rejects_wrong_nonzero_qe_evaluation_reference() {
        let mut supplemental = supplemental();
        supplemental.qe_tcb_evaluation_data_number = 18;

        assert_eq!(
            reconcile_native_supplemental(&supplemental, signed_collateral_claims()),
            Err(DcapRejectCodeV1::NativeOutputMalformed)
        );
    }

    #[test]
    fn supplemental_reconciliation_requires_all_collateral_window_to_be_narrower() {
        let claims = signed_collateral_claims();
        let mut issue_before_signed_documents = supplemental();
        issue_before_signed_documents.latest_issue_date = 189;
        let mut expiry_after_signed_documents = supplemental();
        expiry_after_signed_documents.earliest_expiration_date = 311;

        for supplemental in [issue_before_signed_documents, expiry_after_signed_documents] {
            assert_eq!(
                reconcile_native_supplemental(&supplemental, claims),
                Err(DcapRejectCodeV1::NativeOutputMalformed)
            );
        }
    }

    #[test]
    fn platform_status_matrix_is_exact() {
        let statuses = SGX_QVL_STATUS_VECTORS.map(|(_, status)| status);
        for accepted in [
            PlatformTcbStatusSetV1::UpToDateOnly,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        ] {
            for status in statuses {
                let expected = match (status, accepted) {
                    (NativeQvlStatus::UpToDate, _) => Ok(DcapPlatformTcbStatusV1::UpToDate),
                    (
                        NativeQvlStatus::SWHardeningNeeded,
                        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
                    ) => Ok(DcapPlatformTcbStatusV1::SWHardeningNeeded),
                    (
                        NativeQvlStatus::ConfigurationAndSWHardeningNeeded,
                        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
                    ) => Ok(DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded),
                    _ => Err(DcapRejectCodeV1::PlatformTcbRejected),
                };
                assert_eq!(map_platform_status(status, accepted), expected);
            }
        }
    }

    #[test]
    fn qe_status_matrix_accepts_only_up_to_date() {
        let statuses = SGX_QVL_STATUS_VECTORS.map(|(_, status)| status);
        for status in statuses {
            let expected = if status == NativeQvlStatus::UpToDate {
                Ok(())
            } else {
                Err(DcapRejectCodeV1::QeTcbRejected)
            };
            assert_eq!(validate_qe_status(status), expected);
        }
    }

    #[test]
    fn native_errors_map_to_stable_reject_codes_exhaustively() {
        assert_eq!(
            [
                NativeQvlError::InvalidInput,
                NativeQvlError::UnsupportedAbi,
                NativeQvlError::VerificationFailed,
                NativeQvlError::UnsupportedResult,
                NativeQvlError::MalformedSupplemental,
            ]
            .map(map_native_error),
            [
                DcapRejectCodeV1::CollateralNonCanonical,
                DcapRejectCodeV1::NativeVerifierUnavailable,
                DcapRejectCodeV1::NativeVerificationFailed,
                DcapRejectCodeV1::NativeOutputMalformed,
                DcapRejectCodeV1::NativeOutputMalformed,
            ]
        );
    }

    #[test]
    fn official_intel_platform_ca_vector_has_stable_public_identity() {
        let mut pck_chain =
            include_bytes!("../tests/fixtures/intel-platform-ca-parser/platform-pck-leaf.pem")
                .to_vec();
        pck_chain.push(0);

        let identity = parse_pck_identity(&pck_chain).unwrap();
        assert_eq!(identity.ca, DcapPckCaV1::Platform);
        assert_eq!(identity.fmspc, [0x10, 0x47, 0x5c, 0x0d, 0x00, 0x00]);
        assert_eq!(identity.pce_id, [0x00, 0x00]);
    }

    #[test]
    fn stable_verdict_encoding_is_byte_exact() {
        let verdict = DcapVerdictV1 {
            mrenclave: B256::repeat_byte(0x11),
            mrsigner: B256::repeat_byte(0x22),
            isv_prod_id: 0x3344,
            isv_svn: 0x5566,
            pck_ca: DcapPckCaV1::Platform,
            fmspc: [1, 2, 3, 4, 5, 6],
            pce_id: 0x7788,
            platform_tcb_status: DcapPlatformTcbStatusV1::SWHardeningNeeded,
            advisory_ids: vec!["INTEL-SA-00001".to_owned(), "INTEL-SA-00002".to_owned()],
            tcb_evaluation_data_number: 0x99aa_bbcc,
            qe_tcb_evaluation_data_number: 0xddee_ff00,
            collateral_valid_until: 0x0102_0304_0506_0708,
        };
        let mut expected = vec![1];
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&0x3344_u16.to_be_bytes());
        expected.extend_from_slice(&0x5566_u16.to_be_bytes());
        expected.push(DcapPckCaV1::Platform as u8);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        expected.extend_from_slice(&0x7788_u16.to_be_bytes());
        expected.push(DcapPlatformTcbStatusV1::SWHardeningNeeded as u8);
        expected.extend_from_slice(&0x99aa_bbcc_u32.to_be_bytes());
        expected.extend_from_slice(&0xddee_ff00_u32.to_be_bytes());
        expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        expected.extend_from_slice(&2_u16.to_be_bytes());
        for advisory in ["INTEL-SA-00001", "INTEL-SA-00002"] {
            expected.extend_from_slice(&(advisory.len() as u16).to_be_bytes());
            expected.extend_from_slice(advisory.as_bytes());
        }

        assert_eq!(verdict.encode_canonical().unwrap(), expected);
    }

    #[test]
    fn stable_reject_codes_are_byte_exact() {
        assert_eq!(
            [
                DcapRejectCodeV1::EvidenceNonCanonical.code(),
                DcapRejectCodeV1::PolicyNonCanonical.code(),
                DcapRejectCodeV1::PolicyBindingMismatch.code(),
                DcapRejectCodeV1::TimestampInvalid.code(),
                DcapRejectCodeV1::QuoteMalformed.code(),
                DcapRejectCodeV1::QuoteProfileMismatch.code(),
                DcapRejectCodeV1::QuoteCertificationDataMismatch.code(),
                DcapRejectCodeV1::ReportDataMismatch.code(),
                DcapRejectCodeV1::CollateralNonCanonical.code(),
                DcapRejectCodeV1::IntelRootMismatch.code(),
                DcapRejectCodeV1::PlatformIdentityMismatch.code(),
                DcapRejectCodeV1::CollateralNotYetValid.code(),
                DcapRejectCodeV1::CollateralExpired.code(),
                DcapRejectCodeV1::NativeVerifierUnavailable.code(),
                DcapRejectCodeV1::NativeVerificationFailed.code(),
                DcapRejectCodeV1::NativeOutputMalformed.code(),
                DcapRejectCodeV1::PlatformTcbRejected.code(),
                DcapRejectCodeV1::QeTcbRejected.code(),
                DcapRejectCodeV1::TcbEvaluationNumberTooLow.code(),
                DcapRejectCodeV1::MeasurementRejected.code(),
            ],
            [
                0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202, 0x0203, 0x0204, 0x0301, 0x0302,
                0x0303, 0x0304, 0x0305, 0x0401, 0x0402, 0x0403, 0x0501, 0x0502, 0x0503, 0x0601,
            ]
        );
    }
}
