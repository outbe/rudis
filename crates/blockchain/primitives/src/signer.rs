//! Validator EVM signer system transaction artifacts.
//!
//! This signer is intentionally separate from the BLS consensus key and from
//! `header.beneficiary`. It signs deterministic unsigned transaction artifacts;
//! system tx EVM execution still runs with `SYSTEM_ADDRESS` as caller.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_consensus::{SignableTransaction as _, TxEip1559, TxLegacy};
use alloy_primitives::{keccak256, Address, Signature};
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use reth_ethereum::TransactionSigned;
use zeroize::Zeroizing;

/// Validator EVM signer backed by a zeroizing secp256k1 secret.
#[derive(Clone)]
pub struct OutbeEvmSigner {
    secret: Zeroizing<[u8; 32]>,
    address: Address,
}

impl std::fmt::Debug for OutbeEvmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutbeEvmSigner")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl OutbeEvmSigner {
    pub fn from_secret_bytes(secret: [u8; 32]) -> Result<Self, SignerError> {
        let signing_key = signing_key_from_bytes(&secret)?;
        let address = address_from_signing_key(&signing_key);
        Ok(Self {
            secret: Zeroizing::new(secret),
            address,
        })
    }

    pub fn from_hex(private_key_hex: &str) -> Result<Self, SignerError> {
        let hex = private_key_hex.trim();
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex).map_err(|error| SignerError::InvalidHex(error.to_string()))?;
        let len = bytes.len();
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignerError::InvalidSecretLength { len })?;
        Self::from_secret_bytes(secret)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref();
        ensure_safe_key_file_permissions(path)?;
        let secret = std::fs::read_to_string(path).map_err(|source| SignerError::ReadKey {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_hex(&secret)
    }

    /// Loads a role-custody key from one canonical owner-bound file.
    ///
    /// Unlike [`Self::from_file`], this rejects symlinks, non-regular files,
    /// unexpected owners, modes other than `0600`, hard links, non-canonical
    /// lowercase 32-byte hex payloads, and path replacement during open.
    /// Surrounding ASCII whitespace is ignored and is not part of the key.
    #[cfg(unix)]
    pub fn from_strict_file(
        path: impl AsRef<Path>,
        expected_owner_uid: u32,
    ) -> Result<Self, SignerError> {
        use std::{fs::File, io::Read as _, os::unix::fs::MetadataExt as _};

        const MIN_ENCODED_KEY_BYTES: u64 = 64;
        const MAX_ENCODED_KEY_BYTES: u64 = 128;
        let path = path.as_ref();
        let path_metadata =
            std::fs::symlink_metadata(path).map_err(|source| SignerError::InspectPermissions {
                path: path.to_path_buf(),
                source,
            })?;
        validate_strict_key_metadata(
            path,
            &path_metadata,
            expected_owner_uid,
            MIN_ENCODED_KEY_BYTES,
            MAX_ENCODED_KEY_BYTES,
        )?;

        let mut file = File::open(path).map_err(|source| SignerError::ReadKey {
            path: path.to_path_buf(),
            source,
        })?;
        let opened_metadata =
            file.metadata()
                .map_err(|source| SignerError::InspectPermissions {
                    path: path.to_path_buf(),
                    source,
                })?;
        validate_strict_key_metadata(
            path,
            &opened_metadata,
            expected_owner_uid,
            MIN_ENCODED_KEY_BYTES,
            MAX_ENCODED_KEY_BYTES,
        )?;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(SignerError::UnsafeKeyFile {
                path: path.to_path_buf(),
                reason: "key path changed while opening",
            });
        }

        let mut encoded = Zeroizing::new(String::new());
        file.read_to_string(&mut encoded)
            .map_err(|source| SignerError::ReadKey {
                path: path.to_path_buf(),
                source,
            })?;
        let hex = encoded.trim_ascii();
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SignerError::NonCanonicalKeyFile {
                path: path.to_path_buf(),
            });
        }
        Self::from_hex(hex)
    }

    #[cfg(not(unix))]
    pub fn from_strict_file(
        path: impl AsRef<Path>,
        _expected_owner_uid: u32,
    ) -> Result<Self, SignerError> {
        Self::from_file(path)
    }

    pub const fn address(&self) -> Address {
        self.address
    }

    pub fn sign_unsigned(&self, tx: TxLegacy) -> Result<TransactionSigned, SignerError> {
        let signing_key = signing_key_from_bytes(&self.secret)?;
        let hash = tx.signature_hash();
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key
                .sign_prehash(hash.as_slice())
                .map_err(|error| SignerError::SigningFailed(error.to_string()))?;

        let signature_bytes = signature.to_bytes();
        let bytes = signature_bytes.as_slice();
        if bytes.len() != 64 {
            return Err(SignerError::SignatureEncoding { len: bytes.len() });
        }
        let signature =
            Signature::from_bytes_and_parity(bytes, recovery_id.to_byte() != 0).normalized_s();
        Ok(tx.into_signed(signature).into())
    }

    /// Signs the restricted EIP-1559 envelope used by validator result votes.
    pub fn sign_eip1559(&self, tx: TxEip1559) -> Result<TransactionSigned, SignerError> {
        let signing_key = signing_key_from_bytes(&self.secret)?;
        let hash = tx.signature_hash();
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key
                .sign_prehash(hash.as_slice())
                .map_err(|error| SignerError::SigningFailed(error.to_string()))?;

        let signature_bytes = signature.to_bytes();
        let bytes = signature_bytes.as_slice();
        if bytes.len() != 64 {
            return Err(SignerError::SignatureEncoding { len: bytes.len() });
        }
        let signature =
            Signature::from_bytes_and_parity(bytes, recovery_id.to_byte() != 0).normalized_s();
        Ok(tx.into_signed(signature).into())
    }

    /// Sign a raw 32-byte prehash, returning a recoverable secp256k1 signature in
    /// `r(32) || s(32) || v(1)` form (`v` = recovery id 0/1) - the exact format
    /// [`crate::tee_signatures::recover_signer`] consumes. Used by the consensus
    /// thread to sign the TEE bootstrap payload's `signing_hash` with this
    /// validator's EVM key.
    pub fn sign_hash(&self, hash: &alloy_primitives::B256) -> Result<[u8; 65], SignerError> {
        let signing_key = signing_key_from_bytes(&self.secret)?;
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key
                .sign_prehash(hash.as_slice())
                .map_err(|error| SignerError::SigningFailed(error.to_string()))?;
        let sig_bytes = signature.to_bytes();
        if sig_bytes.len() != 64 {
            return Err(SignerError::SignatureEncoding {
                len: sig_bytes.len(),
            });
        }
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig_bytes.as_slice());
        out[64] = recovery_id.to_byte();
        Ok(out)
    }
}

pub type SharedOutbeEvmSigner = Arc<OutbeEvmSigner>;

/// Default EVM-key path derived from the BLS signing-key path.
pub fn default_validator_evm_key_path(signing_key_path: &Path) -> PathBuf {
    signing_key_path
        .parent()
        .map(|parent| parent.join("evm-key.hex"))
        .unwrap_or_else(|| PathBuf::from("evm-key.hex"))
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("invalid EVM private key hex: {0}")]
    InvalidHex(String),
    #[error("invalid EVM private key length: {len} bytes (expected 32)")]
    InvalidSecretLength { len: usize },
    #[error("invalid EVM private key: {0}")]
    InvalidSecret(String),
    #[error("failed to read EVM private key from {path}: {source}", path = path.display())]
    ReadKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe EVM private key permissions on {path}: mode {mode:o}; expected no group/other permissions", path = path.display())]
    UnsafeFilePermissions { path: PathBuf, mode: u32 },
    #[error("failed to inspect EVM private key permissions on {path}: {source}", path = path.display())]
    InspectPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe EVM private key file at {path}: {reason}", path = path.display())]
    UnsafeKeyFile { path: PathBuf, reason: &'static str },
    #[error("EVM private key file does not contain a lowercase 32-byte hex key after trimming surrounding ASCII whitespace: {path}", path = path.display())]
    NonCanonicalKeyFile { path: PathBuf },
    #[error("failed to sign system transaction: {0}")]
    SigningFailed(String),
    #[error("unexpected ECDSA signature length: {len} bytes")]
    SignatureEncoding { len: usize },
}

fn signing_key_from_bytes(secret: &[u8; 32]) -> Result<SigningKey, SignerError> {
    SigningKey::from_bytes(secret.into())
        .map_err(|error| SignerError::InvalidSecret(error.to_string()))
}

fn address_from_signing_key(signing_key: &SigningKey) -> Address {
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let hash = keccak256(&public_key.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

#[cfg(unix)]
fn ensure_safe_key_file_permissions(path: &Path) -> Result<(), SignerError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|source| SignerError::InspectPermissions {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SignerError::UnsafeFilePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_strict_key_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected_owner_uid: u32,
    min_len: u64,
    max_len: u64,
) -> Result<(), SignerError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let unsafe_reason = if !metadata.file_type().is_file() {
        Some("key is not a regular file")
    } else if metadata.uid() != expected_owner_uid {
        Some("key has the wrong owner")
    } else if metadata.permissions().mode() & 0o777 != 0o600 {
        Some("key mode is not 0600")
    } else if metadata.nlink() != 1 {
        Some("key has an unexpected hard-link count")
    } else {
        None
    };
    if let Some(reason) = unsafe_reason {
        return Err(SignerError::UnsafeKeyFile {
            path: path.to_path_buf(),
            reason,
        });
    }
    if !(min_len..=max_len).contains(&metadata.len()) {
        return Err(SignerError::NonCanonicalKeyFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_safe_key_file_permissions(_path: &Path) -> Result<(), SignerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_tx::{build_unsigned_system_tx, SystemTxInputV2, SystemTxKind};
    use alloy_consensus::Transaction as _;
    use alloy_primitives::{Bytes, TxKind, U256};
    use reth_primitives_traits::SignedTransaction as _;

    const CHAIN_ID: u64 = 2026;

    #[test]
    fn derives_expected_address_from_generated_secret() {
        let signer = OutbeEvmSigner::from_hex(&crate::test_keys::hex(1)).expect("valid signer");
        assert_eq!(
            signer.address(),
            Address::from_public_key(
                SigningKey::from_slice(&crate::test_keys::secret(1))
                    .unwrap()
                    .verifying_key()
            )
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let signer =
            OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret(1)).expect("valid signer");
        let debug = format!("{signer:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&crate::test_keys::hex(1)));
    }

    #[test]
    fn signs_and_recovers_expected_address() {
        let signer =
            OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret(1)).expect("valid signer");
        let input = SystemTxInputV2::CycleTick.encode().expect("input encodes");
        let tx = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input)
            .expect("system tx builds");

        let signed = signer.sign_unsigned(tx).expect("signs");
        let recovered = signed.try_recover().expect("recovers");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn signatures_are_deterministic_for_same_unsigned_tx() {
        let signer =
            OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret(2)).expect("valid signer");
        let input = SystemTxInputV2::CycleTick.encode().expect("input encodes");
        let tx_a = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input.clone())
            .expect("system tx builds");
        let tx_b = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input)
            .expect("system tx builds");

        let signed_a = signer.sign_unsigned(tx_a).expect("signs");
        let signed_b = signer.sign_unsigned(tx_b).expect("signs");
        assert_eq!(signed_a.signature(), signed_b.signature());
        assert_eq!(signed_a.hash(), signed_b.hash());
    }

    #[test]
    fn rejects_wrong_secret_length() {
        let err = OutbeEvmSigner::from_hex("0x1234").expect_err("length rejected");
        assert!(matches!(err, SignerError::InvalidSecretLength { len: 2 }));
    }

    #[cfg(unix)]
    #[test]
    fn strict_role_key_loader_enforces_canonical_owner_bound_file() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ocomp-evm-key.hex");
        std::fs::write(&path, crate::test_keys::hex(1)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner_uid = std::fs::metadata(&path).unwrap().uid();

        let signer = OutbeEvmSigner::from_strict_file(&path, owner_uid).unwrap();
        assert_eq!(
            signer.address(),
            Address::from_public_key(
                SigningKey::from_slice(&crate::test_keys::secret(1))
                    .unwrap()
                    .verifying_key()
            )
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            OutbeEvmSigner::from_strict_file(&path, owner_uid),
            Err(SignerError::UnsafeKeyFile { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let hard_link = root.path().join("hard-link.hex");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(matches!(
            OutbeEvmSigner::from_strict_file(&path, owner_uid),
            Err(SignerError::UnsafeKeyFile { .. })
        ));
        std::fs::remove_file(hard_link).unwrap();

        let symlink = root.path().join("symlink.hex");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(matches!(
            OutbeEvmSigner::from_strict_file(&symlink, owner_uid),
            Err(SignerError::UnsafeKeyFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn strict_role_key_loader_rejects_noncanonical_hex() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ocomp-evm-key.hex");
        std::fs::write(
            &path,
            format!("{}\n", crate::test_keys::hex(1).to_uppercase()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner_uid = std::fs::metadata(&path).unwrap().uid();

        assert!(matches!(
            OutbeEvmSigner::from_strict_file(&path, owner_uid),
            Err(SignerError::NonCanonicalKeyFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn strict_role_key_loader_ignores_surrounding_ascii_whitespace() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ocomp-evm-key.hex");
        std::fs::write(&path, format!(" \t{}\r\n", crate::test_keys::hex(1))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner_uid = std::fs::metadata(&path).unwrap().uid();

        let signer = OutbeEvmSigner::from_strict_file(&path, owner_uid).unwrap();
        assert_eq!(
            signer.address(),
            Address::from_public_key(
                SigningKey::from_slice(&crate::test_keys::secret(1))
                    .unwrap()
                    .verifying_key()
            )
        );
    }

    #[test]
    fn default_key_path_is_sibling_to_bls_key() {
        let path = default_validator_evm_key_path(Path::new("/tmp/validator-1/signing-key.hex"));
        assert_eq!(path, PathBuf::from("/tmp/validator-1/evm-key.hex"));
    }

    #[test]
    fn signed_system_tx_keeps_reserved_to_and_zero_value() {
        let signer =
            OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret(3)).expect("valid signer");
        let input = SystemTxInputV2::CycleTick.encode().expect("input encodes");
        let tx = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input)
            .expect("system tx builds");
        let signed = signer.sign_unsigned(tx).expect("signs");
        assert_eq!(signed.to(), Some(crate::system_tx::OUTBE_SYSTEM_TX_ADDRESS));
        assert_eq!(signed.value(), U256::ZERO);
        assert_eq!(
            signed.kind(),
            TxKind::Call(crate::system_tx::OUTBE_SYSTEM_TX_ADDRESS)
        );
        assert_eq!(signed.input(), &Bytes::from_static(b"OSC2\x02"));
    }
}
