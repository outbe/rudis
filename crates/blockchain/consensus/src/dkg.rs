//! DKG bootstrap - generate BLS threshold keys and BLS individual identity keys for genesis.
//!
//! Generates all cryptographic material needed to launch a validator set:
//! - One shared public polynomial (distributed to all validators)
//! - One full DKG output artifact (distributed to all validators)
//! - Per-validator BLS threshold signing shares
//! - Per-validator BLS individual identity keys (MinPk)
//!
//! This is centralized dealing - suitable for testnets and genesis ceremonies.
//! For production, a distributed DKG protocol should be used.

use commonware_codec::Encode;
use commonware_cryptography::{bls12381, Signer as _};
use commonware_math::algebra::Random;
use commonware_utils::TryCollect as _;
use eyre::{Result, WrapErr};
use std::path::Path;
use tracing::info;

use crate::bls::{self, KeyBackend};

/// Result of a full DKG bootstrap including BLS individual identity keys.
pub struct BootstrapResult {
    /// Per-validator directories created.
    pub validator_dirs: Vec<std::path::PathBuf>,
    /// Number of validators bootstrapped.
    pub count: u32,
}

/// Bootstrap DKG material and BLS individual keys for `n` validators.
///
/// Creates the following directory structure under `output_dir`:
/// ```text
/// output_dir/
///   polynomial.hex          - shared BLS public polynomial
///   dkg-output.hex          - full DKG output artifact bound to validator public keys
///   validator-0/
///     signing-key.hex       - BLS individual private key (MinPk)
///     signing-share.hex     - BLS threshold signing share
///   validator-1/
///     ...
/// ```
///
/// Returns the paths to each validator directory for further use
/// (e.g., generating a validators.json config file).
pub fn bootstrap_and_save(
    output_dir: &Path,
    n: u32,
    backend: &KeyBackend,
) -> Result<BootstrapResult> {
    std::fs::create_dir_all(output_dir)
        .wrap_err_with(|| format!("failed to create output dir: {}", output_dir.display()))?;

    // 1. Generate BLS individual keys, sort by public key, then bind the
    // participant-bound DKG output to that same ordered validator set.
    //
    // The consensus layer uses an ordered `Set<PublicKey>` sorted by public key bytes.
    // The share index (Participant(i)) must match the position in this sorted set.
    let mut keys: Vec<bls12381::PrivateKey> = (0..n as usize)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();

    // Sort keys by their public key bytes (same ordering as Set<PublicKey>).
    keys.sort_by_key(|a| a.public_key().encode());
    let participants = keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .wrap_err("failed to build ordered DKG participant set")?;

    // 2. Generate BLS threshold keys and a full output artifact for the actual
    // validator public keys. Runtime startup requires the output to construct
    // the canonical genesis DKG boundary without an interactive DKG round.
    let dkg = bls::bootstrap_dkg_for_participants(participants).wrap_err("BLS DKG failed")?;

    // 3. Save shared polynomial and full DKG output artifact.
    let poly_path = output_dir.join("polynomial.hex");
    bls::save_public_polynomial(&poly_path, &dkg.polynomial, backend)
        .wrap_err("failed to save polynomial")?;
    info!(path = %poly_path.display(), "saved public polynomial");

    let output_path = output_dir.join("dkg-output.hex");
    bls::save_dkg_output(&output_path, &dkg.output, backend)
        .wrap_err("failed to save DKG output")?;
    info!(path = %output_path.display(), "saved DKG output");

    let mut validator_dirs = Vec::with_capacity(n as usize);

    for (i, (bls_key, share)) in keys.iter().zip(dkg.shares.iter()).enumerate() {
        let dir = output_dir.join(format!("validator-{i}"));
        std::fs::create_dir_all(&dir)
            .wrap_err_with(|| format!("failed to create validator dir: {}", dir.display()))?;

        // BLS individual identity key (MinPk).
        let key_path = dir.join("signing-key.hex");
        bls::save_individual_key(&key_path, bls_key, backend)
            .wrap_err("failed to save signing key")?;

        // BLS signing share - share[i] goes to the key at sorted position i.
        let share_path = dir.join("signing-share.hex");
        bls::save_signing_share(&share_path, share, backend)
            .wrap_err("failed to save signing share")?;

        info!(
            validator = i,
            key_path = %key_path.display(),
            share_path = %share_path.display(),
            "saved validator material"
        );

        validator_dirs.push(dir);
    }

    Ok(BootstrapResult {
        validator_dirs,
        count: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Verifier as _;
    use tempfile::TempDir;

    #[test]
    fn test_bootstrap_and_save_3_validators() {
        let tmp = TempDir::new().unwrap();
        let backend = KeyBackend::Plaintext;
        let result = bootstrap_and_save(tmp.path(), 3, &backend).unwrap();

        assert_eq!(result.count, 3);
        assert_eq!(result.validator_dirs.len(), 3);

        // Verify polynomial and DKG output files exist and are loadable.
        let poly =
            bls::load_public_polynomial(&tmp.path().join("polynomial.hex"), &backend).unwrap();
        let output = bls::load_dkg_output(&tmp.path().join("dkg-output.hex"), &backend).unwrap();
        assert_eq!(output.public(), &poly);

        // Verify each validator's files.
        for (i, dir) in result.validator_dirs.iter().enumerate() {
            // Load and validate BLS individual signing key.
            let key = bls::load_individual_key(&dir.join("signing-key.hex"), &backend).unwrap();
            let pk = key.public_key();
            // Verify the key works
            let sig = key.sign(b"test", b"msg");
            assert!(pk.verify(b"test", b"msg", &sig));

            // Load and validate signing share.
            let share = bls::load_signing_share(&dir.join("signing-share.hex"), &backend).unwrap();
            assert!(
                bls::validate_share(&share, &poly).unwrap(),
                "share {i} should validate against polynomial"
            );
            bls::validate_dkg_triplet(&share, &poly, &output).unwrap();
        }
    }

    #[test]
    fn test_bootstrap_keys_sorted_match_set_ordering() {
        use commonware_cryptography::bls12381;
        use commonware_utils::{ordered::Quorum as _, TryCollect as _};

        let tmp = TempDir::new().unwrap();
        let backend = KeyBackend::Plaintext;
        let result = bootstrap_and_save(tmp.path(), 4, &backend).unwrap();

        // Load all keys and build a sorted Set (same as consensus does)
        let mut keys = Vec::new();
        for dir in &result.validator_dirs {
            let key = bls::load_individual_key(&dir.join("signing-key.hex"), &backend).unwrap();
            keys.push(key);
        }

        let participants: commonware_utils::ordered::Set<bls12381::PublicKey> =
            keys.iter().map(|k| k.public_key()).try_collect().unwrap();
        let output = bls::load_dkg_output(&tmp.path().join("dkg-output.hex"), &backend).unwrap();
        assert_eq!(output.players(), &participants);
        assert_eq!(output.dealers(), &participants);

        // Verify that validator-i's key is at position i in the sorted Set
        for (i, key) in keys.iter().enumerate() {
            let pk = key.public_key();
            let set_index = participants.index(&pk).unwrap();
            assert_eq!(
                set_index.get() as usize,
                i,
                "validator-{i} key should be at sorted position {i}, but found at {}",
                set_index.get()
            );
        }

        // Verify shares also match: share[i].index should work with participant at position i
        let poly =
            bls::load_public_polynomial(&tmp.path().join("polynomial.hex"), &backend).unwrap();
        for (i, dir) in result.validator_dirs.iter().enumerate() {
            let share = bls::load_signing_share(&dir.join("signing-share.hex"), &backend).unwrap();
            assert!(
                bls::validate_share(&share, &poly).unwrap(),
                "share {i} should validate against polynomial"
            );
        }
    }

    #[test]
    fn test_bootstrap_keys_are_unique() {
        let tmp = TempDir::new().unwrap();
        let result = bootstrap_and_save(tmp.path(), 4, &KeyBackend::Plaintext).unwrap();

        let mut keys = std::collections::HashSet::new();
        for dir in &result.validator_dirs {
            let key_hex = std::fs::read_to_string(dir.join("signing-key.hex")).unwrap();
            assert!(keys.insert(key_hex), "BLS individual keys must be unique");
        }
    }
}
