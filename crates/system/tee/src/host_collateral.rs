//! Host-only Intel collateral acquisition for a freshly generated SGX quote.
//!
//! This module runs before consensus starts. It dynamically opens the
//! exact-digest QVL pinned by the project, lets Intel QPL/PCCS acquire the
//! collateral, copies it into the eight canonical V1 components, and frees the
//! Intel allocation. Consensus never calls this module and never performs a
//! network fetch.

use std::ffi::{c_void, CStr, CString};
use std::path::{Path, PathBuf};

use outbe_primitives::tee_attestation_v1::{
    DcapCollateralComponentV1, DcapCollateralKind, MAX_COLLATERAL_COMPONENT_BYTES,
};
use sha2::{Digest as _, Sha256};

use crate::TransportError;

const NATIVE_QVL_MANIFEST: &str = include_str!("../../../../release/dcap-native-qvl-v1.json");
const FIXED_QUOTE_SIZE: usize = 436;
const FIXED_AUTHENTICATION_SIZE: usize = 64 + 64 + 384 + 64;

type GetCollateral = unsafe extern "C" fn(
    quote: *const u8,
    quote_size: u32,
    collateral: *mut *mut c_void,
    collateral_size: *mut u32,
) -> u32;
type FreeCollateral = unsafe extern "C" fn(collateral: *mut c_void) -> u32;

#[repr(C)]
struct QuoteCollateral {
    version: u32,
    tee_type: u32,
    pck_crl_issuer_chain: *const c_void,
    pck_crl_issuer_chain_size: u32,
    root_ca_crl: *const c_void,
    root_ca_crl_size: u32,
    pck_crl: *const c_void,
    pck_crl_size: u32,
    tcb_info_issuer_chain: *const c_void,
    tcb_info_issuer_chain_size: u32,
    tcb_info: *const c_void,
    tcb_info_size: u32,
    qe_identity_issuer_chain: *const c_void,
    qe_identity_issuer_chain_size: u32,
    qe_identity: *const c_void,
    qe_identity_size: u32,
}

struct DynamicLibrary(*mut c_void);

impl DynamicLibrary {
    #[allow(unsafe_code)]
    fn open(path: &Path) -> Result<Self, TransportError> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            TransportError::Attestation("pinned QVL path contains an interior NUL".into())
        })?;
        // SAFETY: the path is a live CString and flags are valid for dlopen.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(TransportError::Attestation(format!(
                "cannot load pinned Intel QVL: {}",
                dynamic_loader_error()
            )));
        }
        Ok(Self(handle))
    }

    #[allow(unsafe_code)]
    fn symbol(&self, name: &'static [u8]) -> Result<*mut c_void, TransportError> {
        // SAFETY: every caller supplies a static NUL-terminated symbol name.
        let symbol = unsafe { libc::dlsym(self.0, name.as_ptr().cast()) };
        if symbol.is_null() {
            return Err(TransportError::Attestation(format!(
                "pinned Intel QVL is missing a collateral symbol: {}",
                dynamic_loader_error()
            )));
        }
        Ok(symbol)
    }
}

impl Drop for DynamicLibrary {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: self.0 is one successful dlopen handle and is closed once.
        unsafe {
            libc::dlclose(self.0);
        }
    }
}

struct IntelCollateralAllocation {
    pointer: *mut c_void,
    free: FreeCollateral,
}

impl Drop for IntelCollateralAllocation {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Intel returned this pointer from tee_qv_get_collateral and the
        // matching function remains live until the enclosing library is dropped.
        // Drop cannot report a cleanup error to the caller. The allocation has
        // already been consumed and the QVL owns the only cleanup mechanism.
        let _status = unsafe { (self.free)(self.pointer) };
    }
}

/// Acquire and canonicalize all eight self-contained collateral components for
/// one complete SGX quote. A missing QVL/QPL/PCCS service is a startup error.
#[allow(unsafe_code)]
pub fn acquire_dcap_collateral_v1(
    quote: &[u8],
) -> Result<Vec<DcapCollateralComponentV1>, TransportError> {
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        return Err(TransportError::Attestation(
            "production DCAP collateral acquisition requires x86_64 Linux".into(),
        ));
    }
    let (library_path, expected_size, expected_sha256) = pinned_qvl_artifact()?;
    verify_pinned_library(&library_path, expected_size, &expected_sha256)?;
    let library = DynamicLibrary::open(&library_path)?;
    // SAFETY: the manifest-pinned Intel library exports the documented QVL ABI
    // under these exact symbol names. The typed values are used only while the
    // library handle remains alive.
    let get: GetCollateral =
        unsafe { std::mem::transmute(library.symbol(b"tee_qv_get_collateral\0")?) };
    // SAFETY: same ABI argument as above.
    let free: FreeCollateral =
        unsafe { std::mem::transmute(library.symbol(b"tee_qv_free_collateral\0")?) };
    let quote_size = u32::try_from(quote.len()).map_err(|_| {
        TransportError::Attestation("SGX quote length exceeds the Intel QVL ABI".into())
    })?;
    let mut pointer = std::ptr::null_mut();
    let mut allocation_size = 0_u32;
    // SAFETY: quote points to quote_size readable bytes and both out-pointers
    // are valid for the duration of the call.
    let status = unsafe {
        get(
            quote.as_ptr(),
            quote_size,
            &mut pointer,
            &mut allocation_size,
        )
    };
    if status != 0 || pointer.is_null() {
        return Err(TransportError::Attestation(format!(
            "Intel tee_qv_get_collateral failed with quote3_error_t {status:#06x}"
        )));
    }
    let allocation = IntelCollateralAllocation { pointer, free };
    if usize::try_from(allocation_size).unwrap_or(0) < std::mem::size_of::<QuoteCollateral>() {
        return Err(TransportError::Attestation(
            "Intel collateral allocation is smaller than its ABI header".into(),
        ));
    }
    // SAFETY: the allocation size covers QuoteCollateral and remains owned by
    // allocation until every pointed-to component has been copied below.
    let collateral = unsafe { &*allocation.pointer.cast::<QuoteCollateral>() };
    let major_version = (collateral.version & 0xffff) as u16;
    let minor_version = (collateral.version >> 16) as u16;
    if major_version != 3 || !matches!(minor_version, 0 | 1) || collateral.tee_type != 0 {
        return Err(TransportError::Attestation(
            "Intel collateral ABI is not supported SGX PCS v3.0 or v3.1".into(),
        ));
    }

    let pck_chain = extract_type5_pck_chain(quote)?;
    let pck_crl = canonical_crl(
        copy_component(collateral.pck_crl, collateral.pck_crl_size, "PCK CRL")?,
        minor_version,
        "PCK CRL",
    )?;
    let pck_crl_issuer = canonical_text(
        copy_component(
            collateral.pck_crl_issuer_chain,
            collateral.pck_crl_issuer_chain_size,
            "PCK CRL issuer chain",
        )?,
        "PCK CRL issuer chain",
    )?;
    let root_ca_crl = canonical_crl(
        copy_component(
            collateral.root_ca_crl,
            collateral.root_ca_crl_size,
            "root CA CRL",
        )?,
        minor_version,
        "root CA CRL",
    )?;
    let tcb_info = canonical_text(
        copy_component(collateral.tcb_info, collateral.tcb_info_size, "TCB Info")?,
        "TCB Info",
    )?;
    let tcb_info_issuer = canonical_text(
        copy_component(
            collateral.tcb_info_issuer_chain,
            collateral.tcb_info_issuer_chain_size,
            "TCB Info issuer chain",
        )?,
        "TCB Info issuer chain",
    )?;
    let qe_identity = canonical_text(
        copy_component(
            collateral.qe_identity,
            collateral.qe_identity_size,
            "QE Identity",
        )?,
        "QE Identity",
    )?;
    let qe_identity_issuer = canonical_text(
        copy_component(
            collateral.qe_identity_issuer_chain,
            collateral.qe_identity_issuer_chain_size,
            "QE Identity issuer chain",
        )?,
        "QE Identity issuer chain",
    )?;

    Ok(vec![
        component(DcapCollateralKind::PckCertificateChain, pck_chain),
        component(DcapCollateralKind::PckCrl, pck_crl),
        component(DcapCollateralKind::PckCrlIssuerChain, pck_crl_issuer),
        component(DcapCollateralKind::RootCaCrl, root_ca_crl),
        component(DcapCollateralKind::TcbInfo, tcb_info),
        component(DcapCollateralKind::TcbInfoIssuerChain, tcb_info_issuer),
        component(DcapCollateralKind::QeIdentity, qe_identity),
        component(
            DcapCollateralKind::QeIdentityIssuerChain,
            qe_identity_issuer,
        ),
    ])
}

fn component(kind: DcapCollateralKind, bytes: Vec<u8>) -> DcapCollateralComponentV1 {
    DcapCollateralComponentV1 { kind, bytes }
}

fn pinned_qvl_artifact() -> Result<(PathBuf, u64, String), TransportError> {
    let manifest: serde_json::Value = serde_json::from_str(NATIVE_QVL_MANIFEST)
        .map_err(|error| TransportError::Codec(format!("invalid native QVL manifest: {error}")))?;
    let artifact = manifest["artifacts"]
        .as_array()
        .and_then(|artifacts| {
            artifacts
                .iter()
                .find(|artifact| artifact["role"].as_str() == Some("qvl"))
        })
        .ok_or_else(|| TransportError::Codec("native QVL manifest has no QVL artifact".into()))?;
    let path = artifact["path"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| TransportError::Codec("native QVL path is missing".into()))?;
    let size = artifact["size"]
        .as_u64()
        .ok_or_else(|| TransportError::Codec("native QVL size is missing".into()))?;
    let sha256 = artifact["sha256"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| TransportError::Codec("native QVL digest is missing".into()))?;
    Ok((path, size, sha256))
}

fn verify_pinned_library(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), TransportError> {
    if !path.is_absolute() {
        return Err(TransportError::Attestation(
            "pinned Intel QVL path is not absolute".into(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        TransportError::Attestation(format!("cannot read pinned Intel QVL: {error}"))
    })?;
    if u64::try_from(bytes.len()).ok() != Some(expected_size) {
        return Err(TransportError::Attestation(
            "installed Intel QVL size differs from the project pin".into(),
        ));
    }
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected_sha256 {
        return Err(TransportError::Attestation(
            "installed Intel QVL digest differs from the project pin".into(),
        ));
    }
    Ok(())
}

fn extract_type5_pck_chain(quote: &[u8]) -> Result<Vec<u8>, TransportError> {
    let minimum = FIXED_QUOTE_SIZE
        .checked_add(FIXED_AUTHENTICATION_SIZE)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| TransportError::Codec("SGX quote size overflow".into()))?;
    if quote.len() < minimum
        || u16::from_le_bytes(quote[0..2].try_into().unwrap_or_default()) != 3
        || u32::from_le_bytes(quote[4..8].try_into().unwrap_or_default()) != 0
    {
        return Err(TransportError::Attestation(
            "quote is not a complete SGX quote v3".into(),
        ));
    }
    let authentication_size = usize::try_from(u32::from_le_bytes(
        quote[432..436].try_into().unwrap_or_default(),
    ))
    .map_err(|_| TransportError::Codec("SGX authentication size overflow".into()))?;
    if FIXED_QUOTE_SIZE.checked_add(authentication_size) != Some(quote.len()) {
        return Err(TransportError::Attestation(
            "SGX quote has trailing or truncated authentication bytes".into(),
        ));
    }
    let mut cursor = FIXED_QUOTE_SIZE + FIXED_AUTHENTICATION_SIZE;
    let qe_auth_size = usize::from(u16::from_le_bytes(
        quote
            .get(cursor..cursor + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| TransportError::Attestation("QE authentication is truncated".into()))?,
    ));
    cursor = cursor
        .checked_add(2)
        .and_then(|value| value.checked_add(qe_auth_size))
        .ok_or_else(|| TransportError::Codec("QE authentication size overflow".into()))?;
    let header = quote.get(cursor..cursor + 6).ok_or_else(|| {
        TransportError::Attestation("quote certification-data header is truncated".into())
    })?;
    let certification_type = u16::from_le_bytes(header[0..2].try_into().unwrap_or_default());
    let certification_size = usize::try_from(u32::from_le_bytes(
        header[2..6].try_into().unwrap_or_default(),
    ))
    .map_err(|_| TransportError::Codec("certification-data size overflow".into()))?;
    cursor += 6;
    let end = cursor
        .checked_add(certification_size)
        .ok_or_else(|| TransportError::Codec("certification-data size overflow".into()))?;
    if certification_type != 5 || end != quote.len() {
        return Err(TransportError::Attestation(
            "quote does not contain exact type-5 PCK certification data".into(),
        ));
    }
    let pck_chain = quote[cursor..end].to_vec();
    if !pck_chain.starts_with(b"-----BEGIN CERTIFICATE-----\n")
        || !pck_chain.ends_with(&[0])
        || pck_chain[..pck_chain.len() - 1].contains(&0)
    {
        return Err(TransportError::Attestation(
            "type-5 PCK chain is not canonical PEM plus NUL".into(),
        ));
    }
    Ok(pck_chain)
}

#[allow(unsafe_code)]
fn copy_component(
    pointer: *const c_void,
    size: u32,
    label: &'static str,
) -> Result<Vec<u8>, TransportError> {
    let size = usize::try_from(size)
        .map_err(|_| TransportError::Codec(format!("{label} size overflow")))?;
    if pointer.is_null() || size == 0 || size > MAX_COLLATERAL_COMPONENT_BYTES + 1 {
        return Err(TransportError::Attestation(format!(
            "Intel QPL returned invalid {label} length"
        )));
    }
    // SAFETY: Intel owns a live collateral allocation, this field points to
    // size readable bytes inside it, and the caller copies before freeing.
    Ok(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) }.to_vec())
}

fn canonical_text(mut bytes: Vec<u8>, label: &'static str) -> Result<Vec<u8>, TransportError> {
    if bytes.last() != Some(&0) || bytes.len() < 2 || bytes[..bytes.len() - 1].contains(&0) {
        return Err(TransportError::Attestation(format!(
            "{label} is not terminated by exactly one NUL"
        )));
    }
    bytes.pop();
    std::str::from_utf8(&bytes)
        .map_err(|_| TransportError::Attestation(format!("{label} is not UTF-8")))?;
    Ok(bytes)
}

fn canonical_crl(
    bytes: Vec<u8>,
    minor_version: u16,
    label: &'static str,
) -> Result<Vec<u8>, TransportError> {
    match minor_version {
        1 if !bytes.is_empty() => Ok(bytes),
        0 => {
            let encoded = canonical_text(bytes, label)?;
            if encoded.len() % 2 != 0 {
                return Err(TransportError::Attestation(format!(
                    "{label} contains odd-length hexadecimal DER"
                )));
            }
            let mut decoded = Vec::with_capacity(encoded.len() / 2);
            for pair in encoded.chunks_exact(2) {
                let text = std::str::from_utf8(pair).map_err(|_| {
                    TransportError::Attestation(format!("{label} is not hexadecimal DER"))
                })?;
                decoded.push(u8::from_str_radix(text, 16).map_err(|_| {
                    TransportError::Attestation(format!("{label} is not hexadecimal DER"))
                })?);
            }
            if decoded.is_empty() {
                return Err(TransportError::Attestation(format!("{label} is empty")));
            }
            Ok(decoded)
        }
        _ => Err(TransportError::Attestation(format!(
            "{label} uses unsupported collateral ABI"
        ))),
    }
}

#[allow(unsafe_code)]
fn dynamic_loader_error() -> String {
    // SAFETY: dlerror returns either NULL or a process-local NUL-terminated
    // diagnostic string valid until the next dynamic-loader call.
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "unknown dynamic-loader error".into()
    } else {
        // SAFETY: non-NULL dlerror output is a valid C string.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}
