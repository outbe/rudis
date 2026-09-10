use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use std::{fs, path::Path, process::Command};

fn read_canonical_secret(path: &Path) -> Vec<u8> {
    let encoded = fs::read(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    });
    assert_eq!(
        encoded.len(),
        64,
        "{} must contain 64 bytes",
        path.display()
    );
    assert!(
        encoded
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "{} must contain lowercase hex without a prefix or LF",
        path.display()
    );
    encoded
}

fn signing_key(encoded: &[u8]) -> SigningKey {
    SigningKey::from_slice(&hex::decode(encoded).expect("secret hex decodes"))
        .expect("secret is a valid secp256k1 scalar")
}

#[test]
fn validator_command_generates_every_runtime_key_and_delegation_command() {
    let output_dir = tempfile::tempdir().expect("temporary output directory");
    let output = Command::new(env!("CARGO_BIN_EXE_outbe-keygen"))
        .args([
            "validator",
            "--output-dir",
            output_dir.path().to_str().expect("UTF-8 temporary path"),
            "--chain-id",
            "7",
        ])
        .output()
        .expect("run outbe-keygen validator");
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let validator_evm = read_canonical_secret(&output_dir.path().join("evm-key.hex"));
    let reth_p2p = read_canonical_secret(&output_dir.path().join("reth-p2p-secret.hex"));
    let ocomp_evm = read_canonical_secret(&output_dir.path().join("ocomp-evm-key.hex"));
    assert_ne!(
        reth_p2p, validator_evm,
        "Reth must have its own identity key"
    );
    assert_ne!(
        ocomp_evm, validator_evm,
        "OCOMP must have its own operational key"
    );
    assert_ne!(ocomp_evm, reth_p2p, "OCOMP and Reth keys must be distinct");

    let ocomp_key = signing_key(&ocomp_evm);
    let point = ocomp_key.verifying_key().to_encoded_point(false);
    let ocomp_address = Address::from_raw_public_key(&point.as_bytes()[1..]);
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 keygen output");
    assert!(stdout.contains(&format!("address:      {ocomp_address}")));
    assert!(stdout.contains(&format!(
        "outbe-cli --private-key <validator-evm-key> validator delegate ocomp {ocomp_address}"
    )));
}

#[cfg(unix)]
#[test]
fn validator_command_protects_every_plaintext_runtime_key() {
    use std::os::unix::fs::PermissionsExt as _;

    let output_dir = tempfile::tempdir().expect("temporary output directory");
    let output = Command::new(env!("CARGO_BIN_EXE_outbe-keygen"))
        .args([
            "validator",
            "--output-dir",
            output_dir.path().to_str().expect("UTF-8 temporary path"),
            "--chain-id",
            "7",
        ])
        .output()
        .expect("run outbe-keygen validator");
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for name in ["evm-key.hex", "reth-p2p-secret.hex", "ocomp-evm-key.hex"] {
        let mode = fs::metadata(output_dir.path().join(name))
            .expect("secret metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name} must have mode 0600");
    }
}

#[test]
fn validator_command_refuses_each_preexisting_runtime_key_before_writing() {
    for name in ["reth-p2p-secret.hex", "ocomp-evm-key.hex"] {
        let output_dir = tempfile::tempdir().expect("temporary output directory");
        let existing = output_dir.path().join(name);
        fs::write(&existing, b"operator-owned").expect("write sentinel artifact");

        let output = Command::new(env!("CARGO_BIN_EXE_outbe-keygen"))
            .args([
                "validator",
                "--output-dir",
                output_dir.path().to_str().expect("UTF-8 temporary path"),
                "--chain-id",
                "7",
            ])
            .output()
            .expect("run outbe-keygen validator");

        assert!(!output.status.success(), "{name} must block generation");
        assert_eq!(
            fs::read(&existing).expect("read sentinel"),
            b"operator-owned"
        );
        assert!(!output_dir.path().join("signing-key.hex").exists());
        assert!(!output_dir.path().join("evm-key.hex").exists());
        assert!(!output_dir.path().join("radicle").exists());
    }
}
