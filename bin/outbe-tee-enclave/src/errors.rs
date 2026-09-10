//! Structured errors for the enclave crypto / sealing core.
//!
//! Per project safety rules: no `unwrap`/`expect`/`panic` in these paths - every
//! fallible operation returns a `TeeError`.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TeeError {
    #[error("invalid nonce size: expected 12 bytes, got {0}")]
    InvalidNonce(usize),

    #[error("invalid key material length")]
    InvalidKeyLen,

    #[error("AEAD encryption failed")]
    EncryptFailed,

    #[error("AEAD decryption failed (bad key, nonce, or tampered ciphertext)")]
    DecryptFailed,

    #[error("HKDF-SHA256 derivation failed")]
    HkdfFailed,

    #[error("sealed blob too short")]
    SealedBlobTooShort,

    #[error("sealed blob bad magic")]
    SealedBlobBadMagic,

    #[error("sealed blob unsupported format version: {0}")]
    SealedBlobBadVersion(u8),

    #[error("sealed blob unknown key policy: {0}")]
    SealedBlobBadKeyPolicy(u8),

    #[error("sealed blob anti-rollback: blob isv_svn {blob} > running {running}")]
    SealedBlobRollback { blob: u16, running: u16 },

    #[error("sealed blob unseal failed (bad sealing key or tampered blob)")]
    SealedBlobUnsealFailed,

    #[error("sealed blob contains an invalid network binding: {0}")]
    SealedBlobBadNetworkBinding(String),

    #[error("sealed blob belongs to another network binding")]
    SealedBlobNetworkBindingMismatch,

    #[error("sealed blob payload had unexpected length: {0}")]
    SealedBlobBadPayload(usize),

    #[error("DKG session error: {0}")]
    Dkg(String),

    #[error("DKG ceremony {0} not found in session store")]
    DkgSessionMissing(String),

    #[error("DKG seam called out of order: {0}")]
    DkgSeamOrder(&'static str),

    #[error("offer rejected: {0}")]
    TributeOfferReject(String),

    #[error("fidelity: {0}")]
    Fidelity(String),
}

pub type Result<T> = core::result::Result<T, TeeError>;
