//! BLS12-381 key management - threshold keys and individual (MinPk) keys.
//!
//! Provides loading/saving of:
//! - BLS threshold shares and public polynomials (MinSig variant)
//! - BLS individual signing keys (MinPk variant, for P2P identity + vote attribution)
//!
//! Supports three key storage backends via [`KeyBackend`]:
//! - `Plaintext` - hex-encoded files (development/testing)
//! - `Encrypted` - AES-256-GCM with Argon2id-derived key
//! - `OsLevel` - OS keychain (macOS Keychain / Linux Secret Service)
//!
//! Also includes a centralized DKG bootstrap utility for genesis setup.

use commonware_codec::{Encode, EncodeSize, Read as CodecRead, ReadExt as _, Write as CodecWrite};
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt as dkg,
    primitives::{
        group::Share,
        sharing::{Mode, ModeVersion, Sharing},
        variant::MinSig,
    },
};
use commonware_utils::{ordered::Set, N3f1};
use eyre::{ensure, Result, WrapErr};
use std::{
    io::Write as _,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::debug;

/// Maximum number of validators supported (used as upper bound for codec deserialization).
pub const MAX_VALIDATORS: u32 = 256;
static SECRET_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// KeyBackend - storage backend for BLS key material
// ---------------------------------------------------------------------------

/// Backend for BLS key storage at rest.
#[derive(Debug, Clone, Default)]
pub enum KeyBackend {
    /// Plaintext hex files (default for development/testing).
    #[default]
    Plaintext,
    /// AES-256-GCM encryption with passphrase-derived key (Argon2id KDF).
    Encrypted(String),
    /// OS keychain (macOS Keychain / Linux Secret Service via `keyring` crate).
    /// Key material is stored in the OS secret store; a marker file on disk
    /// points to the keychain entry.
    OsLevel,
}

// ---------------------------------------------------------------------------
// Encrypted file format
// ---------------------------------------------------------------------------

/// Magic bytes identifying an AES-256-GCM encrypted file.
const ENC_MAGIC: &[u8] = b"OUTBE_ENC\x01";

/// Marker prefix for OS keychain reference files.
const KEYCHAIN_MARKER: &str = "OUTBE_KEYCHAIN\n";

/// Derive a 256-bit AES key from a passphrase using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    // Argon2id into a fixed 32-byte buffer cannot fail in practice; return a
    // structured error instead of `expect` on the key-load/startup path.
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| eyre::eyre!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `data` with AES-256-GCM and write the envelope to `path`.
fn save_encrypted(path: &Path, data: &[u8], passphrase: &str) -> Result<()> {
    use rand::RngCore;
    use ring::aead::{self, BoundKey};

    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| eyre::eyre!("failed to create AES-256-GCM key"))?;
    let mut sealing_key = aead::SealingKey::new(unbound, OneNonce::new(nonce_bytes));

    let mut in_out = data.to_vec();
    sealing_key
        .seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| eyre::eyre!("AES-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(ENC_MAGIC.len() + 32 + 12 + in_out.len());
    out.extend_from_slice(ENC_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    atomic_write_secret(path, &out, "encrypted key")
}

use outbe_primitives::crypto::OneNonce;

/// Save `data` to OS keychain and write a marker file at `path`.
fn save_to_keychain(path: &Path, data: &[u8]) -> Result<()> {
    let service = "outbe-chain";
    let account_prefix = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    // A content-addressed account keeps the old marker + old secret valid until
    // the new marker is atomically installed. Reusing one account would expose
    // a cross-backend crash window where the marker still names a secret whose
    // contents have already changed.
    let account = format!(
        "{account_prefix}-{}",
        hex::encode(ring::digest::digest(&ring::digest::SHA256, data,))
    );

    let entry = keyring::Entry::new(service, &account)
        .map_err(|e| eyre::eyre!("keychain entry creation failed: {e}"))?;
    entry
        .set_password(&hex::encode(data))
        .map_err(|e| eyre::eyre!("keychain store failed: {e}"))?;

    // Write marker file on disk (pointer to keychain entry)
    let marker = format!("{KEYCHAIN_MARKER}{service}\n{account}\n");
    atomic_write_secret(path, marker.as_bytes(), "keychain marker")
}

/// Save raw bytes using the specified backend.
pub(crate) fn save_raw(path: &Path, data: &[u8], backend: &KeyBackend) -> Result<()> {
    match backend {
        KeyBackend::Encrypted(passphrase) => save_encrypted(path, data, passphrase),
        KeyBackend::Plaintext => {
            let hex_str = hex::encode(data);
            save_plaintext(path, hex_str.as_bytes())
        }
        KeyBackend::OsLevel => save_to_keychain(path, data),
    }
}

fn save_plaintext(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write_secret(path, data, "plaintext key")
}

/// Crash-consistently replace one secret file.
///
/// The new bytes reach a fresh owner-only file first, then the file is renamed
/// over the old version and the parent directory is synced so the rename itself
/// survives power loss. Callers never expose a partially-written target.
fn atomic_write_secret(path: &Path, data: &[u8], kind: &str) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| eyre::eyre!("{kind} path has no file name: {}", path.display()))?
        .to_string_lossy();
    let open_temp = || -> Result<(PathBuf, std::fs::File)> {
        loop {
            let sequence = SECRET_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let tmp_path = path.with_file_name(format!(
                ".{file_name}.tmp.{}.{}",
                std::process::id(),
                sequence
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&tmp_path) {
                Ok(file) => return Ok((tmp_path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!("failed to open {kind} file: {}", tmp_path.display())
                    });
                }
            }
        }
    };

    let (tmp_path, mut file) = open_temp()?;

    let write_result = (|| -> Result<()> {
        file.write_all(data)
            .wrap_err_with(|| format!("failed to write {kind} file: {}", tmp_path.display()))?;
        file.sync_all()
            .wrap_err_with(|| format!("failed to sync {kind} file: {}", tmp_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .wrap_err_with(|| {
                    format!("failed to set {kind} permissions: {}", tmp_path.display())
                })?;
            let mode = std::fs::metadata(&tmp_path)
                .wrap_err_with(|| format!("failed to stat {kind} file: {}", tmp_path.display()))?
                .permissions()
                .mode()
                & 0o777;
            ensure!(
                mode == 0o600,
                "{kind} file {} has mode {mode:o}, expected 600",
                tmp_path.display()
            );
        }

        std::fs::rename(&tmp_path, path).wrap_err_with(|| {
            format!(
                "failed to atomically install plaintext key file {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .wrap_err_with(|| {
                    format!("failed to sync {kind} directory: {}", parent.display())
                })?;
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

/// Load raw bytes, auto-detecting format (encrypted / keychain / plaintext hex).
pub(crate) fn load_raw(path: &Path, backend: &KeyBackend) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)
        .wrap_err_with(|| format!("failed to read key file: {}", path.display()))?;

    if raw.starts_with(ENC_MAGIC) {
        // AES-256-GCM encrypted
        let passphrase = match backend {
            KeyBackend::Encrypted(p) => p.as_str(),
            _ => {
                return Err(eyre::eyre!(
                    "file is encrypted but backend is not Encrypted (need passphrase)"
                ))
            }
        };
        let header_len = ENC_MAGIC.len();
        if raw.len() < header_len + 32 + 12 {
            return Err(eyre::eyre!("encrypted file too short"));
        }
        let salt: &[u8; 32] = raw[header_len..header_len + 32]
            .try_into()
            .map_err(|_| eyre::eyre!("encrypted file salt slice"))?;
        let nonce_bytes = &raw[header_len + 32..header_len + 44];
        let ciphertext = &raw[header_len + 44..];

        use ring::aead::{self, BoundKey};

        let key = derive_key(passphrase, salt)?;
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| eyre::eyre!("invalid nonce length"))?;
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| eyre::eyre!("failed to create AES-256-GCM key"))?;
        let mut opening_key = aead::OpeningKey::new(unbound, OneNonce::new(nonce));

        let mut in_out = ciphertext.to_vec();
        let plaintext = opening_key
            .open_in_place(aead::Aad::empty(), &mut in_out)
            .map_err(|_| eyre::eyre!("decryption failed (wrong passphrase?)"))?;
        Ok(plaintext.to_vec())
    } else if raw.starts_with(KEYCHAIN_MARKER.as_bytes()) {
        // OS keychain reference
        let text = String::from_utf8(raw).wrap_err("keychain marker not UTF-8")?;
        let lines: Vec<&str> = text.trim().lines().collect();
        if lines.len() < 3 {
            return Err(eyre::eyre!("invalid keychain marker file"));
        }
        let service = lines[1];
        let account = lines[2];
        let entry = keyring::Entry::new(service, account)
            .map_err(|e| eyre::eyre!("keychain entry creation failed: {e}"))?;
        let hex_str = entry
            .get_password()
            .map_err(|e| eyre::eyre!("keychain read failed (key not found?): {e}"))?;
        hex::decode(&hex_str).wrap_err("invalid hex in keychain entry")
    } else {
        // Legacy/plaintext hex
        let hex_str = String::from_utf8(raw)
            .wrap_err("key file not UTF-8")?
            .trim()
            .to_string();
        hex::decode(&hex_str).wrap_err("invalid hex in key file")
    }
}

/// Remove backend-owned raw secret material after its protocol lifecycle ends.
///
/// For keychain storage the marker is removed and synced first, so a crash can
/// only leave an unreachable orphaned keychain entry, never a marker that points
/// at a secret already deleted. Orphans are safe and may be garbage-collected by
/// operator tooling.
pub(crate) fn remove_raw(path: &Path, backend: &KeyBackend) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let keychain_entry = if matches!(backend, KeyBackend::OsLevel) {
        let raw = std::fs::read(path)
            .wrap_err_with(|| format!("failed to read keychain marker: {}", path.display()))?;
        if raw.starts_with(KEYCHAIN_MARKER.as_bytes()) {
            let text = String::from_utf8(raw).wrap_err("keychain marker not UTF-8")?;
            let lines: Vec<&str> = text.trim().lines().collect();
            ensure!(lines.len() >= 3, "invalid keychain marker file");
            Some((lines[1].to_owned(), lines[2].to_owned()))
        } else {
            None
        }
    } else {
        None
    };

    std::fs::remove_file(path)
        .wrap_err_with(|| format!("failed to remove secret file: {}", path.display()))?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .wrap_err_with(|| format!("failed to sync secret directory: {}", parent.display()))?;
    }

    if let Some((service, account)) = keychain_entry {
        let entry = keyring::Entry::new(&service, &account)
            .map_err(|e| eyre::eyre!("keychain entry creation failed: {e}"))?;
        entry
            .delete_credential()
            .map_err(|e| eyre::eyre!("keychain cleanup failed: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signing share (threshold, MinSig)
// ---------------------------------------------------------------------------

/// Load a BLS12-381 signing share.
pub fn load_signing_share(path: &Path, backend: &KeyBackend) -> Result<Share> {
    let bytes = load_raw(path, backend)?;
    Share::read(&mut bytes.as_slice())
        .map_err(|e| eyre::eyre!("invalid BLS12-381 signing share: {e}"))
}

/// Save a BLS12-381 signing share.
pub fn save_signing_share(path: &Path, share: &Share, backend: &KeyBackend) -> Result<()> {
    save_raw(path, &share.encode(), backend)
}

// ---------------------------------------------------------------------------
// Public polynomial (threshold, MinSig)
// ---------------------------------------------------------------------------

/// Load a BLS12-381 public polynomial (Sharing).
pub fn load_public_polynomial(path: &Path, backend: &KeyBackend) -> Result<Sharing<MinSig>> {
    let bytes = load_raw(path, backend)?;
    let cfg = (NonZeroU32::new(MAX_VALIDATORS).unwrap(), ModeVersion::v0());
    Sharing::read_cfg(&mut bytes.as_slice(), &cfg)
        .map_err(|e| eyre::eyre!("invalid BLS12-381 public polynomial: {e}"))
}

/// Save a BLS12-381 public polynomial (Sharing).
pub fn save_public_polynomial(
    path: &Path,
    sharing: &Sharing<MinSig>,
    backend: &KeyBackend,
) -> Result<()> {
    let mut buf = Vec::with_capacity(sharing.encode_size());
    sharing.write(&mut buf);
    save_raw(path, &buf, backend)
}

// ---------------------------------------------------------------------------
// Full DKG output (required for true resharing continuity)
// ---------------------------------------------------------------------------

/// Load a BLS12-381 DKG output artifact.
pub fn load_dkg_output(
    path: &Path,
    backend: &KeyBackend,
) -> Result<dkg::Output<MinSig, bls12381::PublicKey>> {
    let bytes = load_raw(path, backend)?;
    let cfg = (NonZeroU32::new(MAX_VALIDATORS).unwrap(), ModeVersion::v0());
    dkg::Output::<MinSig, bls12381::PublicKey>::read_cfg(&mut bytes.as_slice(), &cfg)
        .map_err(|e| eyre::eyre!("invalid BLS12-381 DKG output: {e}"))
}

/// Save a BLS12-381 DKG output artifact.
pub fn save_dkg_output(
    path: &Path,
    output: &dkg::Output<MinSig, bls12381::PublicKey>,
    backend: &KeyBackend,
) -> Result<()> {
    let mut buf = Vec::with_capacity(output.encode_size());
    output.write(&mut buf);
    save_raw(path, &buf, backend)
}

// ---------------------------------------------------------------------------
// BLS individual key management (MinPk variant)
// ---------------------------------------------------------------------------

/// Load a BLS12-381 individual signing key (MinPk).
pub fn load_individual_key(path: &Path, backend: &KeyBackend) -> Result<bls12381::PrivateKey> {
    let bytes = load_raw(path, backend)?;
    bls12381::PrivateKey::read(&mut bytes.as_slice())
        .map_err(|e| eyre::eyre!("invalid BLS12-381 individual key: {e}"))
}

/// Save a BLS12-381 individual signing key (MinPk).
pub fn save_individual_key(
    path: &Path,
    key: &bls12381::PrivateKey,
    backend: &KeyBackend,
) -> Result<()> {
    save_raw(path, &key.encode(), backend)
}

// ---------------------------------------------------------------------------
// BLS threshold DKG bootstrap
// ---------------------------------------------------------------------------

/// Result of a centralized DKG bootstrap.
///
/// Contains the public polynomial (shared by all validators) and
/// per-validator private shares (distributed to each validator).
pub struct DkgBootstrapResult {
    /// Public polynomial - distribute to all validators.
    pub polynomial: Sharing<MinSig>,
    /// Per-participant shares - distribute each to its corresponding validator.
    /// Indexed by participant index (0-based).
    pub shares: Vec<Share>,
}

/// Result of a participant-bound centralized DKG bootstrap.
///
/// Unlike [`bootstrap_dkg`], this includes the full DKG output artifact with
/// the actual validator public keys bound as dealers/players. Runtime startup
/// needs this output to build the canonical genesis DKG boundary and to support
/// later reshare continuity.
pub struct ParticipantDkgBootstrapResult {
    /// Full DKG output artifact - distribute to every validator.
    pub output: dkg::Output<MinSig, bls12381::PublicKey>,
    /// Public polynomial - distribute to all validators.
    pub polynomial: Sharing<MinSig>,
    /// Per-participant shares in ordered participant-set order.
    pub shares: Vec<Share>,
}

/// Perform a centralized DKG bootstrap for `n` validators.
///
/// Generates a random polynomial and `n` shares with `N3f1` fault tolerance
/// (requires 2f+1 of 3f+1 participants for threshold recovery).
///
/// This is used for genesis setup - each validator receives its share via
/// a secure offline channel. For production use, a distributed DKG protocol
/// should be used instead.
pub fn bootstrap_dkg(n: u32) -> Result<DkgBootstrapResult> {
    let n = NonZeroU32::new(n).ok_or_else(|| eyre::eyre!("validator count must be > 0"))?;
    let mut rng = rand_core::OsRng;

    let (polynomial, shares) =
        dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::NonZeroCounter, n);

    debug!(
        validators = n.get(),
        threshold = polynomial.required::<N3f1>(),
        "bootstrapped DKG with centralized dealing"
    );

    Ok(DkgBootstrapResult { polynomial, shares })
}

/// Perform a centralized DKG bootstrap bound to a concrete ordered validator set.
///
/// The returned shares are ordered identically to `participants`. The full
/// output artifact binds the same public keys as dealers/players, allowing fresh
/// runtime bootstrap to skip the interactive round-0 DKG ceremony while still
/// producing a canonical genesis DKG boundary.
pub fn bootstrap_dkg_for_participants(
    participants: Set<bls12381::PublicKey>,
) -> Result<ParticipantDkgBootstrapResult> {
    ensure!(!participants.is_empty(), "validator count must be > 0");
    let mut rng = rand_core::OsRng;
    let validators = participants.len();

    let (output, shares) =
        dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::NonZeroCounter, participants)
            .map_err(|e| eyre::eyre!("BLS DKG failed: {e}"))?;
    let polynomial = output.public().clone();
    let shares = shares.values().to_vec();

    debug!(
        validators,
        threshold = polynomial.required::<N3f1>(),
        "bootstrapped participant-bound DKG with centralized dealing"
    );

    Ok(ParticipantDkgBootstrapResult {
        output,
        polynomial,
        shares,
    })
}

/// Validate that a share matches the expected public polynomial for a given participant index.
pub fn validate_share(share: &Share, polynomial: &Sharing<MinSig>) -> Result<bool> {
    let expected_public = polynomial
        .partial_public(share.index)
        .map_err(|e| eyre::eyre!("failed to compute partial public key: {e}"))?;
    Ok(share.public::<MinSig>() == expected_public)
}

/// Validate that persisted DKG material is internally consistent.
pub fn validate_dkg_triplet(
    share: &Share,
    polynomial: &Sharing<MinSig>,
    output: &dkg::Output<MinSig, bls12381::PublicKey>,
) -> Result<()> {
    ensure!(
        validate_share(share, polynomial)?,
        "signing share does not match public polynomial"
    );
    ensure!(
        output.public() == polynomial,
        "DKG output public polynomial does not match saved public polynomial"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_bootstrap_dkg_3_validators() {
        let result = bootstrap_dkg(3).unwrap();
        assert_eq!(result.shares.len(), 3);

        // Each share should validate against the polynomial
        for share in &result.shares {
            assert!(validate_share(share, &result.polynomial).unwrap());
        }
    }

    #[test]
    fn test_bootstrap_dkg_128_validators() {
        let result = bootstrap_dkg(128).unwrap();
        assert_eq!(result.shares.len(), 128);

        // Spot-check first and last share
        assert!(validate_share(&result.shares[0], &result.polynomial).unwrap());
        assert!(validate_share(&result.shares[127], &result.polynomial).unwrap());
    }

    #[test]
    fn test_share_roundtrip_file() {
        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let backend = KeyBackend::Plaintext;

        let file = NamedTempFile::new().unwrap();
        save_signing_share(file.path(), share, &backend).unwrap();
        let loaded = load_signing_share(file.path(), &backend).unwrap();

        assert_eq!(share.index, loaded.index);
        assert!(validate_share(&loaded, &result.polynomial).unwrap());
    }

    #[test]
    fn test_individual_key_roundtrip_file() {
        use commonware_math::algebra::Random;
        let key = bls12381::PrivateKey::random(rand_core::OsRng);
        let backend = KeyBackend::Plaintext;

        let file = NamedTempFile::new().unwrap();
        save_individual_key(file.path(), &key, &backend).unwrap();
        let loaded = load_individual_key(file.path(), &backend).unwrap();

        assert_eq!(key, loaded);
    }

    #[test]
    fn test_individual_key_sign_verify() {
        use commonware_cryptography::{Signer as _, Verifier as _};
        use commonware_math::algebra::Random;

        let key = bls12381::PrivateKey::random(rand_core::OsRng);
        let pk = key.public_key();

        let sig = key.sign(b"test-ns", b"hello");
        assert!(pk.verify(b"test-ns", b"hello", &sig));
        assert!(!pk.verify(b"test-ns", b"wrong", &sig));
    }

    #[test]
    fn test_polynomial_roundtrip_file() {
        let result = bootstrap_dkg(3).unwrap();
        let backend = KeyBackend::Plaintext;

        let file = NamedTempFile::new().unwrap();
        save_public_polynomial(file.path(), &result.polynomial, &backend).unwrap();
        let loaded = load_public_polynomial(file.path(), &backend).unwrap();

        // Loaded polynomial should produce the same partial public keys
        for share in &result.shares {
            assert!(validate_share(share, &loaded).unwrap());
        }
    }

    // P2-7: Encrypted backend tests

    #[test]
    fn test_encrypted_share_roundtrip() {
        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let backend = KeyBackend::Encrypted("test-passphrase-123".into());

        let file = NamedTempFile::new().unwrap();
        save_signing_share(file.path(), share, &backend).unwrap();

        // File should start with magic bytes (not hex)
        let raw = std::fs::read(file.path()).unwrap();
        assert!(
            raw.starts_with(ENC_MAGIC),
            "encrypted file must have magic header"
        );

        let loaded = load_signing_share(file.path(), &backend).unwrap();
        assert_eq!(share.index, loaded.index);
        assert!(validate_share(&loaded, &result.polynomial).unwrap());
    }

    #[test]
    fn test_encrypted_wrong_passphrase() {
        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let backend = KeyBackend::Encrypted("correct-password".into());

        let file = NamedTempFile::new().unwrap();
        save_signing_share(file.path(), share, &backend).unwrap();

        // Load with wrong passphrase -> should fail
        let wrong_backend = KeyBackend::Encrypted("wrong-password".into());
        let err = load_signing_share(file.path(), &wrong_backend);
        assert!(err.is_err(), "wrong passphrase should fail");
    }

    #[test]
    fn encrypted_backend_atomically_replaces_existing_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retry.hex");
        let backend = KeyBackend::Encrypted("replacement-password".into());

        save_raw(&path, b"first", &backend).unwrap();
        save_raw(&path, b"second", &backend).unwrap();

        assert_eq!(load_raw(&path, &backend).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_plaintext_backend_roundtrip() {
        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let backend = KeyBackend::Plaintext;

        let file = NamedTempFile::new().unwrap();
        save_signing_share(file.path(), share, &backend).unwrap();

        // File should be hex text
        let content = std::fs::read_to_string(file.path()).unwrap();
        assert!(
            hex::decode(content.trim()).is_ok(),
            "plaintext file should be valid hex"
        );

        let loaded = load_signing_share(file.path(), &backend).unwrap();
        assert_eq!(share.index, loaded.index);
    }

    #[cfg(unix)]
    #[test]
    fn test_plaintext_backend_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let backend = KeyBackend::Plaintext;

        let file = NamedTempFile::new().unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        save_signing_share(file.path(), share, &backend).unwrap();

        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_legacy_plaintext_load() {
        // Simulate a legacy file: just hex-encoded bytes
        let result = bootstrap_dkg(3).unwrap();
        let share = &result.shares[0];
        let hex_str = hex::encode(share.encode());

        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &hex_str).unwrap();

        // Load with Plaintext backend -> should work
        let loaded = load_signing_share(file.path(), &KeyBackend::Plaintext).unwrap();
        assert_eq!(share.index, loaded.index);
    }

    #[test]
    fn test_encrypted_polynomial_roundtrip() {
        let result = bootstrap_dkg(3).unwrap();
        let backend = KeyBackend::Encrypted("poly-secret".into());

        let file = NamedTempFile::new().unwrap();
        save_public_polynomial(file.path(), &result.polynomial, &backend).unwrap();
        let loaded = load_public_polynomial(file.path(), &backend).unwrap();

        for share in &result.shares {
            assert!(validate_share(share, &loaded).unwrap());
        }
    }

    #[test]
    fn test_encrypted_individual_key_roundtrip() {
        use commonware_math::algebra::Random;
        let key = bls12381::PrivateKey::random(rand_core::OsRng);
        let backend = KeyBackend::Encrypted("key-secret".into());

        let file = NamedTempFile::new().unwrap();
        save_individual_key(file.path(), &key, &backend).unwrap();
        let loaded = load_individual_key(file.path(), &backend).unwrap();

        assert_eq!(key, loaded);
    }

    /// Runtime-level test: save and load full threshold material (share + polynomial)
    /// through encrypted backend - the same flow as save_dkg_state() / obtain_threshold_material().
    #[test]
    fn test_encrypted_threshold_material_full_flow() {
        let result = bootstrap_dkg(3).unwrap();
        let backend = KeyBackend::Encrypted("threshold-secret-123".into());

        let dir = tempfile::tempdir().unwrap();
        let share_path = dir.path().join("dkg_share.hex");
        let poly_path = dir.path().join("dkg_polynomial.hex");

        // Save (same calls as save_dkg_state in stack.rs).
        save_signing_share(&share_path, &result.shares[0], &backend).unwrap();
        save_public_polynomial(&poly_path, &result.polynomial, &backend).unwrap();

        // Files must be encrypted (not plaintext hex).
        let share_raw = std::fs::read(&share_path).unwrap();
        let poly_raw = std::fs::read(&poly_path).unwrap();
        assert!(share_raw.starts_with(ENC_MAGIC), "share must be encrypted");
        assert!(
            poly_raw.starts_with(ENC_MAGIC),
            "polynomial must be encrypted"
        );

        // Load (same calls as obtain_threshold_material Path 2 in stack.rs).
        let loaded_share = load_signing_share(&share_path, &backend).unwrap();
        let loaded_poly = load_public_polynomial(&poly_path, &backend).unwrap();

        // Validate roundtrip.
        assert_eq!(result.shares[0].index, loaded_share.index);
        assert!(validate_share(&loaded_share, &loaded_poly).unwrap());

        // Cannot load with wrong passphrase.
        let wrong_backend = KeyBackend::Encrypted("wrong-password".into());
        assert!(load_signing_share(&share_path, &wrong_backend).is_err());
        assert!(load_public_polynomial(&poly_path, &wrong_backend).is_err());

        // Cannot load with plaintext backend (encrypted file).
        assert!(load_signing_share(&share_path, &KeyBackend::Plaintext).is_err());
    }
}
