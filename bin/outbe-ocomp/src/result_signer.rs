//! Supervisor-owned secp256k1 signer dedicated to OCOMP result attestations.
//!
//! The loader accepts exactly one development-PoC secret representation:
//! 64 lowercase hexadecimal characters followed by one LF byte in a regular,
//! owner-matching `0600` file. It deliberately exposes no generic purpose or
//! arbitrary-message signing method.

use std::{
    fs::File,
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use outbe_ocomp_protocol::committee::POC_KEY_EPOCH;
use zeroize::Zeroizing;

const SECRET_FILE_BYTES: u64 = 65;
const SECRET_MODE: u32 = 0o600;

#[derive(Clone)]
pub struct OcompSigner {
    secret: Zeroizing<[u8; 32]>,
    public_key_sec1: [u8; 33],
}

impl std::fmt::Debug for OcompSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcompSigner")
            .field("key_epoch", &POC_KEY_EPOCH)
            .field("public_key_sec1", &self.public_key_sec1)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl OcompSigner {
    pub fn from_file(
        path: impl AsRef<Path>,
        expected_owner_uid: u32,
    ) -> Result<Self, OcompKeyError> {
        let path = path.as_ref();
        let path_metadata =
            std::fs::symlink_metadata(path).map_err(|source| OcompKeyError::Inspect {
                path: path.to_path_buf(),
                source,
            })?;
        validate_key_metadata(path, &path_metadata, expected_owner_uid)?;

        let mut file = File::open(path).map_err(|source| OcompKeyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let opened_metadata = file.metadata().map_err(|source| OcompKeyError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
        validate_key_metadata(path, &opened_metadata, expected_owner_uid)?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(OcompKeyError::UnsafeFile {
                path: path.to_path_buf(),
                reason: "key path changed while opening",
            });
        }

        let mut encoded = Zeroizing::new([0u8; SECRET_FILE_BYTES as usize]);
        file.read_exact(encoded.as_mut())
            .map_err(|source| OcompKeyError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        let secret = decode_secret_file(path, encoded.as_ref())?;
        Self::from_secret(secret)
    }

    pub fn from_secret(secret: [u8; 32]) -> Result<Self, OcompKeyError> {
        let signing_key =
            SigningKey::from_bytes((&secret).into()).map_err(|_| OcompKeyError::InvalidScalar)?;
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        let public_key_sec1: [u8; 33] = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| OcompKeyError::InvalidPublicKeyEncoding)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
            public_key_sec1,
        })
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        POC_KEY_EPOCH
    }

    #[must_use]
    pub const fn public_key_sec1(&self) -> [u8; 33] {
        self.public_key_sec1
    }

    pub fn sign_result_digest(&self, result_digest: B256) -> Result<[u8; 64], OcompKeyError> {
        let signing_key = SigningKey::from_bytes(self.secret.as_ref().into())
            .map_err(|_| OcompKeyError::InvalidScalar)?;
        let signature: Signature = signing_key
            .sign_prehash(result_digest.as_slice())
            .map_err(|_| OcompKeyError::SigningFailed)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().into())
    }
}

fn validate_key_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), OcompKeyError> {
    if !metadata.file_type().is_file() {
        return Err(OcompKeyError::UnsafeFile {
            path: path.to_path_buf(),
            reason: "key is not a regular file",
        });
    }
    if metadata.uid() != expected_owner_uid {
        return Err(OcompKeyError::UnsafeFile {
            path: path.to_path_buf(),
            reason: "key has the wrong owner",
        });
    }
    if metadata.permissions().mode() & 0o777 != SECRET_MODE {
        return Err(OcompKeyError::UnsafeFile {
            path: path.to_path_buf(),
            reason: "key mode is not 0600",
        });
    }
    if metadata.nlink() != 1 {
        return Err(OcompKeyError::UnsafeFile {
            path: path.to_path_buf(),
            reason: "key has an unexpected hard-link count",
        });
    }
    if metadata.len() != SECRET_FILE_BYTES {
        return Err(OcompKeyError::NonCanonicalFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn decode_secret_file(path: &Path, encoded: &[u8]) -> Result<[u8; 32], OcompKeyError> {
    if encoded[64] != b'\n'
        || !encoded[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(OcompKeyError::NonCanonicalFile {
            path: path.to_path_buf(),
        });
    }
    let mut secret = [0u8; 32];
    for (index, pair) in encoded[..64].chunks_exact(2).enumerate() {
        secret[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(secret)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("caller validated lowercase hexadecimal input"),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OcompKeyError {
    #[error("failed to inspect OCOMP key at {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read OCOMP key at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe OCOMP key file at {path}: {reason}")]
    UnsafeFile { path: PathBuf, reason: &'static str },
    #[error("OCOMP key file is not exact 64-byte lowercase hex plus LF: {path}")]
    NonCanonicalFile { path: PathBuf },
    #[error("OCOMP key is not a valid secp256k1 scalar")]
    InvalidScalar,
    #[error("OCOMP public key is not compressed SEC1-33")]
    InvalidPublicKeyEncoding,
    #[error("OCOMP result-digest signing failed")]
    SigningFailed,
}
