//! CLI subcommands for the Outbe consensus layer.
//!
//! Provides the `dkg` subcommand for bootstrapping BLS threshold key material,
//! and emergency DKG management commands (status, export-share, import-share).

use alloy_primitives::{keccak256, Address};
use commonware_codec::Encode;
use commonware_cryptography::Signer as _;
use commonware_math::algebra::Random as _;
use eyre::{Result, WrapErr};
use k256::ecdsa::{SigningKey, VerifyingKey};
use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::{
    bls::{self, KeyBackend},
    dkg,
};

const LOCALNET_RETH_BOOTNODES_FILE: &str = "reth-bootnodes.txt";
const LOCALNET_RETH_P2P_SECRET_FILE: &str = "reth-p2p-secret.hex";
const LOCALNET_RETH_BOOTNODE_HOST: &str = "127.0.0.1";
const LOCALNET_RETH_P2P_BASE_PORT: u16 = 30303;

fn write_secret_hex_file(path: &Path, contents: &str) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| eyre::eyre!("secret key path has no file name: {}", path.display()))?
        .to_string_lossy();
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));

    let write_result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp_path)
            .wrap_err_with(|| format!("failed to create secret file: {}", tmp_path.display()))?;
        file.write_all(contents.as_bytes())
            .wrap_err_with(|| format!("failed to write secret file: {}", tmp_path.display()))?;
        file.flush()
            .wrap_err_with(|| format!("failed to flush secret file: {}", tmp_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .wrap_err_with(|| {
                    format!(
                        "failed to set secret file permissions: {}",
                        tmp_path.display()
                    )
                })?;
        }
        std::fs::rename(&tmp_path, path).wrap_err_with(|| {
            format!(
                "failed to atomically install secret file {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct ValidatorEntry {
    public_key: String,
    address: String,
    p2p_address: Option<String>,
}

fn reth_node_id_hex(verifying_key: &VerifyingKey) -> Result<String> {
    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    eyre::ensure!(
        bytes.len() == 65 && bytes[0] == 0x04,
        "unexpected secp256k1 public key encoding for Reth enode"
    );
    Ok(hex::encode(&bytes[1..]))
}

/// Execute the DKG bootstrap command.
///
/// Generates BLS threshold key material for `num_validators` validators:
/// - Shared public polynomial
/// - Per-validator signing keys and threshold shares
/// - A `validators.json` tooling file for genesis seeding and localnet scripts
pub fn execute_dkg_bootstrap(
    output_dir: PathBuf,
    num_validators: u32,
    backend: &KeyBackend,
) -> Result<()> {
    println!("bootstrapping DKG for {num_validators} validators...");

    let result = dkg::bootstrap_and_save(&output_dir, num_validators, backend)
        .wrap_err("DKG bootstrap failed")?;

    // Generate validators.json and secp256k1 EVM/Reth keys.
    let entries = write_validator_identity_bundle(&output_dir, &result.validator_dirs, backend)?;

    println!("DKG bootstrap complete:");
    println!("  output dir:     {}", output_dir.display());
    println!(
        "  polynomial:     {}",
        output_dir.join("polynomial.hex").display()
    );
    println!(
        "  dkg output:     {}",
        output_dir.join("dkg-output.hex").display()
    );
    print_validator_identity_outputs(&output_dir, &result.validator_dirs, &entries);

    Ok(())
}

/// Generate the long-lived validator identities needed by the interactive
/// round-0 genesis DKG without creating a second, incompatible centralized
/// threshold polynomial.
pub fn execute_validator_identities(
    output_dir: PathBuf,
    num_validators: u32,
    backend: &KeyBackend,
) -> Result<()> {
    eyre::ensure!(num_validators > 0, "validator count must be > 0");
    std::fs::create_dir_all(&output_dir)
        .wrap_err_with(|| format!("failed to create output dir: {}", output_dir.display()))?;

    let mut keys: Vec<commonware_cryptography::bls12381::PrivateKey> = (0..num_validators)
        .map(|_| commonware_cryptography::bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|key| key.public_key().encode());

    let mut validator_dirs = Vec::with_capacity(num_validators as usize);
    for (index, key) in keys.iter().enumerate() {
        let directory = output_dir.join(format!("validator-{index}"));
        std::fs::create_dir_all(&directory).wrap_err_with(|| {
            format!(
                "failed to create validator directory: {}",
                directory.display()
            )
        })?;
        bls::save_individual_key(&directory.join("signing-key.hex"), key, backend)
            .wrap_err_with(|| format!("failed to save validator-{index} signing key"))?;
        validator_dirs.push(directory);
    }

    let entries = write_validator_identity_bundle(&output_dir, &validator_dirs, backend)?;
    println!("validator identities generated for fresh interactive genesis DKG:");
    println!("  output dir:     {}", output_dir.display());
    print_validator_identity_outputs(&output_dir, &validator_dirs, &entries);
    Ok(())
}

/// Verify that imported founder private keys reproduce the public identities
/// committed by validators.json before network preparation consumes them.
pub fn execute_validator_identity_verification(
    validators_path: &Path,
    material_dir: &Path,
    backend: &KeyBackend,
) -> Result<()> {
    let validators: Vec<ValidatorEntry> = serde_json::from_slice(
        &std::fs::read(validators_path)
            .wrap_err_with(|| format!("failed to read: {}", validators_path.display()))?,
    )
    .wrap_err_with(|| format!("failed to parse: {}", validators_path.display()))?;
    eyre::ensure!(!validators.is_empty(), "validators.json must not be empty");

    for (index, validator) in validators.iter().enumerate() {
        let expected_public_key = hex::decode(
            validator
                .public_key
                .strip_prefix("0x")
                .unwrap_or(&validator.public_key),
        )
        .wrap_err_with(|| format!("validator-{index} public_key is not valid hex"))?;
        eyre::ensure!(
            expected_public_key.len() == 48,
            "validator-{index} public_key must be 48 bytes"
        );

        let signing_key_path = material_dir
            .join(format!("validator-{index}"))
            .join("signing-key.hex");
        let signing_key = bls::load_individual_key(&signing_key_path, backend)
            .wrap_err_with(|| format!("failed to load validator-{index} BLS signing key"))?;
        eyre::ensure!(
            signing_key.public_key().encode() == expected_public_key,
            "validator-{index} BLS signing key does not match validators.json"
        );

        let expected_address: Address = validator
            .address
            .parse()
            .wrap_err_with(|| format!("validator-{index} address is invalid"))?;
        let evm_key_path = material_dir
            .join(format!("validator-{index}"))
            .join("evm-key.hex");
        let evm_key_text = std::fs::read_to_string(&evm_key_path)
            .wrap_err_with(|| format!("failed to read: {}", evm_key_path.display()))?;
        let evm_key_bytes = hex::decode(
            evm_key_text
                .trim()
                .strip_prefix("0x")
                .unwrap_or(evm_key_text.trim()),
        )
        .wrap_err_with(|| format!("validator-{index} EVM signing key is not valid hex"))?;
        let evm_key = SigningKey::from_slice(&evm_key_bytes)
            .wrap_err_with(|| format!("validator-{index} EVM signing key is invalid"))?;
        let evm_public_key = evm_key.verifying_key().to_encoded_point(false);
        let evm_address_hash = keccak256(&evm_public_key.as_bytes()[1..]);
        let actual_address = Address::from_slice(&evm_address_hash[12..]);
        eyre::ensure!(
            actual_address == expected_address,
            "validator-{index} EVM signing key does not match validators.json"
        );
    }

    println!(
        "verified {} imported founder identities against {}",
        validators.len(),
        validators_path.display()
    );
    Ok(())
}

fn write_validator_identity_bundle(
    output_dir: &Path,
    validator_dirs: &[PathBuf],
    backend: &KeyBackend,
) -> Result<Vec<ValidatorEntry>> {
    let mut entries = Vec::with_capacity(validator_dirs.len());
    let mut reth_bootnodes = Vec::with_capacity(validator_dirs.len());
    for (i, dir) in validator_dirs.iter().enumerate() {
        let key = bls::load_individual_key(&dir.join("signing-key.hex"), backend)
            .wrap_err_with(|| format!("failed to load key for validator {i}"))?;
        let pk = key.public_key();
        let pk_hex = hex::encode(pk.encode());

        // Generate secp256k1 EVM key and derive Ethereum address.
        let evm_key = SigningKey::random(&mut rand_core::OsRng);
        let evm_pubkey = evm_key.verifying_key().to_encoded_point(false);
        let addr_hash = keccak256(&evm_pubkey.as_bytes()[1..]);
        let address = Address::from_slice(&addr_hash[12..]);

        // Save EVM private key as hex.
        let evm_key_hex = hex::encode(evm_key.to_bytes());
        let evm_key_path = dir.join("evm-key.hex");
        write_secret_hex_file(&evm_key_path, &evm_key_hex)
            .wrap_err_with(|| format!("failed to write EVM key: {}", evm_key_path.display()))?;

        // Generate a stable Reth RLPx identity for localnet bootnode wiring.
        // This key is not consensus-critical; it only lets scripts know each
        // node's enode before the first Reth startup.
        let reth_p2p_key = SigningKey::random(&mut rand_core::OsRng);
        let reth_p2p_key_hex = hex::encode(reth_p2p_key.to_bytes());
        let reth_p2p_key_path = dir.join(LOCALNET_RETH_P2P_SECRET_FILE);
        write_secret_hex_file(&reth_p2p_key_path, &reth_p2p_key_hex).wrap_err_with(|| {
            format!(
                "failed to write Reth p2p secret: {}",
                reth_p2p_key_path.display()
            )
        })?;
        let reth_node_id = reth_node_id_hex(reth_p2p_key.verifying_key())?;
        let reth_p2p_port = LOCALNET_RETH_P2P_BASE_PORT
            .checked_add(i as u16)
            .ok_or_else(|| eyre::eyre!("too many validators for localnet Reth p2p port range"))?;
        reth_bootnodes.push(format!(
            "enode://{reth_node_id}@{LOCALNET_RETH_BOOTNODE_HOST}:{reth_p2p_port}"
        ));

        let p2p_port = 30400 + i as u16;
        entries.push(ValidatorEntry {
            public_key: pk_hex,
            address: format!("{address}"),
            p2p_address: Some(format!("127.0.0.1:{p2p_port}")),
        });
    }

    let validators_path = output_dir.join("validators.json");
    let json =
        serde_json::to_string_pretty(&entries).wrap_err("failed to serialize validators.json")?;
    std::fs::write(&validators_path, json)
        .wrap_err_with(|| format!("failed to write: {}", validators_path.display()))?;

    let reth_bootnodes_path = output_dir.join(LOCALNET_RETH_BOOTNODES_FILE);
    std::fs::write(
        &reth_bootnodes_path,
        format!("{}\n", reth_bootnodes.join("\n")),
    )
    .wrap_err_with(|| format!("failed to write: {}", reth_bootnodes_path.display()))?;

    Ok(entries)
}

fn print_validator_identity_outputs(
    output_dir: &Path,
    validator_dirs: &[PathBuf],
    entries: &[ValidatorEntry],
) {
    let validators_path = output_dir.join("validators.json");
    let reth_bootnodes_path = output_dir.join(LOCALNET_RETH_BOOTNODES_FILE);
    println!("  validators:     {}", validators_path.display());
    println!("  reth bootnodes: {}", reth_bootnodes_path.display());
    for (i, dir) in validator_dirs.iter().enumerate() {
        let evm_address = entries
            .get(i)
            .map(|entry| entry.address.as_str())
            .unwrap_or("<unknown>");
        println!(
            "  validator-{i}:    {}  (evm-address: {evm_address}, evm-key: {} <redacted>)",
            dir.display(),
            dir.join("evm-key.hex").display()
        );
    }
}

/// DKG state file names (must match stack.rs constants).
const DKG_SHARE_FILE: &str = "dkg_share.hex";
const DKG_POLYNOMIAL_FILE: &str = "dkg_polynomial.hex";
const DKG_OUTPUT_FILE: &str = "dkg_output.hex";

/// Show the status of DKG key material in a storage directory.
///
/// Checks for the existence and validity of the signing share and public
/// polynomial files. Exits with a human-readable summary.
pub fn execute_dkg_status(storage_dir: &Path, backend: &KeyBackend) -> Result<()> {
    println!("DKG status for: {}", storage_dir.display());
    println!();

    let share_path = storage_dir.join(DKG_SHARE_FILE);
    let poly_path = storage_dir.join(DKG_POLYNOMIAL_FILE);
    let output_path = storage_dir.join(DKG_OUTPUT_FILE);

    let share_ok = if share_path.exists() {
        match bls::load_signing_share(&share_path, backend) {
            Ok(_) => {
                println!("  signing share:  OK  ({})", share_path.display());
                true
            }
            Err(e) => {
                println!("  signing share:  INVALID  ({e})");
                false
            }
        }
    } else {
        println!("  signing share:  MISSING");
        false
    };

    let poly_ok = if poly_path.exists() {
        match bls::load_public_polynomial(&poly_path, backend) {
            Ok(_) => {
                println!("  polynomial:     OK  ({})", poly_path.display());
                true
            }
            Err(e) => {
                println!("  polynomial:     INVALID  ({e})");
                false
            }
        }
    } else {
        println!("  polynomial:     MISSING");
        false
    };

    println!();
    let output_ok = if output_path.exists() {
        match bls::load_dkg_output(&output_path, backend) {
            Ok(_) => {
                println!("  DKG output:     OK  ({})", output_path.display());
                true
            }
            Err(e) => {
                println!("  DKG output:     INVALID  ({e})");
                false
            }
        }
    } else {
        println!("  DKG output:     MISSING");
        false
    };

    let triplet_ok = if share_ok && poly_ok && output_ok {
        let share = bls::load_signing_share(&share_path, backend)
            .wrap_err("failed to reload signing share for triplet validation")?;
        let polynomial = bls::load_public_polynomial(&poly_path, backend)
            .wrap_err("failed to reload polynomial for triplet validation")?;
        let output = bls::load_dkg_output(&output_path, backend)
            .wrap_err("failed to reload DKG output for triplet validation")?;
        match bls::validate_dkg_triplet(&share, &polynomial, &output) {
            Ok(()) => true,
            Err(e) => {
                println!("  DKG triplet:    INVALID  ({e})");
                false
            }
        }
    } else {
        false
    };

    if triplet_ok {
        println!("  status: READY - threshold material is valid");
    } else {
        println!("  status: NOT READY - missing or invalid key material");
    }

    Ok(())
}

/// Export the DKG signing share from the storage directory to a specified path.
pub fn execute_dkg_export_share(
    storage_dir: &Path,
    output: &Path,
    backend: &KeyBackend,
) -> Result<()> {
    let share_path = storage_dir.join(DKG_SHARE_FILE);
    let poly_path = storage_dir.join(DKG_POLYNOMIAL_FILE);
    let output_path = storage_dir.join(DKG_OUTPUT_FILE);

    if !share_path.exists() {
        eyre::bail!("signing share not found at {}", share_path.display());
    }
    if !poly_path.exists() {
        eyre::bail!("polynomial not found at {}", poly_path.display());
    }
    if !output_path.exists() {
        eyre::bail!("DKG output not found at {}", output_path.display());
    }

    // Validate before exporting.
    let share =
        bls::load_signing_share(&share_path, backend).wrap_err("signing share is corrupted")?;
    let polynomial =
        bls::load_public_polynomial(&poly_path, backend).wrap_err("polynomial is corrupted")?;
    let output_artifact =
        bls::load_dkg_output(&output_path, backend).wrap_err("DKG output is corrupted")?;
    bls::validate_dkg_triplet(&share, &polynomial, &output_artifact)
        .wrap_err("DKG triplet is inconsistent")?;

    std::fs::create_dir_all(output)
        .wrap_err_with(|| format!("failed to create output dir: {}", output.display()))?;

    std::fs::copy(&share_path, output.join(DKG_SHARE_FILE))
        .wrap_err("failed to copy signing share")?;
    std::fs::copy(&poly_path, output.join(DKG_POLYNOMIAL_FILE))
        .wrap_err("failed to copy polynomial")?;
    std::fs::copy(&output_path, output.join(DKG_OUTPUT_FILE))
        .wrap_err("failed to copy DKG output")?;

    println!("exported DKG material to: {}", output.display());
    println!(
        "  {}  ->  {}",
        DKG_SHARE_FILE,
        output.join(DKG_SHARE_FILE).display()
    );
    println!(
        "  {}  ->  {}",
        DKG_POLYNOMIAL_FILE,
        output.join(DKG_POLYNOMIAL_FILE).display()
    );
    println!(
        "  {}  ->  {}",
        DKG_OUTPUT_FILE,
        output.join(DKG_OUTPUT_FILE).display()
    );

    Ok(())
}

/// Force-restart DKG by removing saved threshold material.
///
/// Deletes only the consensus signing share, polynomial, and DKG output files.
///
/// This maintenance command never touches enclave state or the permanent offer
/// key. The next node startup still passes the normal founding or existing-chain
/// gates; an existing identity without its exact offer key remains terminal.
pub fn execute_dkg_force_restart(storage_dir: &Path) -> Result<()> {
    let material_paths = [
        storage_dir.join(DKG_SHARE_FILE),
        storage_dir.join(DKG_POLYNOMIAL_FILE),
        storage_dir.join(DKG_OUTPUT_FILE),
    ];

    let mut removed = false;

    for material_path in material_paths {
        if material_path.exists() {
            std::fs::remove_file(&material_path)
                .wrap_err_with(|| format!("failed to remove: {}", material_path.display()))?;
            println!("  removed: {}", material_path.display());
            removed = true;
        }
    }

    if removed {
        println!();
        println!(
            "Consensus DKG material removed. Permanent TEE offer-key state was not modified; normal startup gates still apply."
        );
    } else {
        println!("No DKG material found in: {}", storage_dir.display());
    }

    Ok(())
}

/// Import DKG signing share and polynomial into the storage directory.
pub fn execute_dkg_import_share(
    share_file: &Path,
    polynomial_file: &Path,
    output_file: Option<&Path>,
    storage_dir: &Path,
    backend: &KeyBackend,
) -> Result<()> {
    let inferred_output_file;
    let output_file = match output_file {
        Some(path) => path,
        None => {
            inferred_output_file = share_file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(DKG_OUTPUT_FILE);
            inferred_output_file.as_path()
        }
    };

    // Validate the source files before importing.
    let share = bls::load_signing_share(share_file, backend)
        .wrap_err_with(|| format!("invalid signing share: {}", share_file.display()))?;
    let polynomial = bls::load_public_polynomial(polynomial_file, backend)
        .wrap_err_with(|| format!("invalid polynomial: {}", polynomial_file.display()))?;
    let output_artifact = bls::load_dkg_output(output_file, backend)
        .wrap_err_with(|| format!("invalid DKG output: {}", output_file.display()))?;
    bls::validate_dkg_triplet(&share, &polynomial, &output_artifact)
        .wrap_err("DKG import triplet is inconsistent")?;

    std::fs::create_dir_all(storage_dir)
        .wrap_err_with(|| format!("failed to create storage dir: {}", storage_dir.display()))?;

    std::fs::copy(share_file, storage_dir.join(DKG_SHARE_FILE))
        .wrap_err("failed to copy signing share")?;
    std::fs::copy(polynomial_file, storage_dir.join(DKG_POLYNOMIAL_FILE))
        .wrap_err("failed to copy polynomial")?;
    std::fs::copy(output_file, storage_dir.join(DKG_OUTPUT_FILE))
        .wrap_err("failed to copy DKG output")?;

    println!("imported DKG material into: {}", storage_dir.display());
    println!(
        "  share:       {} -> {}",
        share_file.display(),
        storage_dir.join(DKG_SHARE_FILE).display()
    );
    println!(
        "  polynomial:  {} -> {}",
        polynomial_file.display(),
        storage_dir.join(DKG_POLYNOMIAL_FILE).display()
    );
    println!(
        "  DKG output:  {} -> {}",
        output_file.display(),
        storage_dir.join(DKG_OUTPUT_FILE).display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reth_node_id_is_uncompressed_public_key_without_prefix() {
        let key = SigningKey::from_bytes((&outbe_primitives::test_keys::secret(7)).into()).unwrap();
        let node_id = reth_node_id_hex(key.verifying_key()).unwrap();

        assert_eq!(node_id.len(), 128);
        assert_eq!(hex::decode(node_id).unwrap().len(), 64);
    }

    #[test]
    fn dkg_bootstrap_writes_reth_p2p_secrets_and_bootnodes() {
        let tmp = tempfile::tempdir().unwrap();

        execute_dkg_bootstrap(tmp.path().to_path_buf(), 3, &KeyBackend::Plaintext).unwrap();

        let bootnodes_path = tmp.path().join(LOCALNET_RETH_BOOTNODES_FILE);
        let bootnodes = std::fs::read_to_string(bootnodes_path).unwrap();
        let bootnodes: Vec<_> = bootnodes.lines().collect();
        assert_eq!(bootnodes.len(), 3);

        for (i, bootnode) in bootnodes.iter().enumerate() {
            let port = LOCALNET_RETH_P2P_BASE_PORT + i as u16;
            let Some(rest) = bootnode.strip_prefix("enode://") else {
                panic!("bootnode does not start with enode://: {bootnode}");
            };
            let Some((node_id, addr)) = rest.split_once('@') else {
                panic!("bootnode missing @ separator: {bootnode}");
            };
            assert_eq!(node_id.len(), 128);
            assert_eq!(hex::decode(node_id).unwrap().len(), 64);
            assert_eq!(addr, format!("{LOCALNET_RETH_BOOTNODE_HOST}:{port}"));

            let secret_path = tmp
                .path()
                .join(format!("validator-{i}"))
                .join(LOCALNET_RETH_P2P_SECRET_FILE);
            let secret = std::fs::read_to_string(secret_path).unwrap();
            assert_eq!(secret.len(), 64);
            assert_eq!(hex::decode(secret).unwrap().len(), 32);
        }
    }
}
