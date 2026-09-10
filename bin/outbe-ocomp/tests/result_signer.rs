use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{symlink, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use alloy_primitives::B256;
use outbe_ocomp_protocol::committee::{verify_low_s_prehash, POC_KEY_EPOCH};

use outbe_ocomp::result_signer::{OcompKeyError, OcompSigner};

fn write_key(path: &Path, contents: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .expect("create key file");
    file.write_all(contents).expect("write key file");
    file.sync_all().expect("sync key file");
}

fn canonical_secret(secret: [u8; 32]) -> Vec<u8> {
    let mut encoded = hex::encode(secret).into_bytes();
    encoded.push(b'\n');
    encoded
}

#[test]
fn ocm_sig_001_strict_ocomp_key_signs_only_result_prehashes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let key_path = temporary.path().join("ocomp-key.hex");
    write_key(&key_path, &canonical_secret([7; 32]), 0o600);
    let owner_uid = fs::metadata(&key_path).expect("key metadata").uid();

    let signer = OcompSigner::from_file(&key_path, owner_uid).expect("load OCOMP key");
    assert_eq!(signer.key_epoch(), POC_KEY_EPOCH);
    let digest = B256::repeat_byte(0x41);
    let signature = signer
        .sign_result_digest(digest)
        .expect("sign result digest");
    verify_low_s_prehash(&signer.public_key_sec1(), digest, &signature)
        .expect("verify OCOMP signature");
}

#[test]
fn ocm_sig_001_ocomp_key_rejects_unsafe_files_and_noncanonical_bytes() {
    let cases: &[(&str, &[u8])] = &[
        (
            "missing-newline",
            b"0707070707070707070707070707070707070707070707070707070707070707",
        ),
        (
            "uppercase",
            b"070707070707070707070707070707070707070707070707070707070707070A\n",
        ),
        (
            "prefix",
            b"0x07070707070707070707070707070707070707070707070707070707070707\n",
        ),
        (
            "trailing-space",
            b"0707070707070707070707070707070707070707070707070707070707070707 \n",
        ),
        (
            "zero-scalar",
            b"0000000000000000000000000000000000000000000000000000000000000000\n",
        ),
    ];

    for (name, bytes) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join(name);
        write_key(&key_path, bytes, 0o600);
        let owner_uid = fs::metadata(&key_path).expect("key metadata").uid();
        assert!(
            OcompSigner::from_file(&key_path, owner_uid).is_err(),
            "{name} must be rejected"
        );
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let key_path = temporary.path().join("wrong-mode.hex");
    write_key(&key_path, &canonical_secret([7; 32]), 0o600);
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).expect("change key mode");
    let owner_uid = fs::metadata(&key_path).expect("key metadata").uid();
    assert!(matches!(
        OcompSigner::from_file(&key_path, owner_uid),
        Err(OcompKeyError::UnsafeFile { .. })
    ));
    assert!(matches!(
        OcompSigner::from_file(&key_path, owner_uid.saturating_add(1)),
        Err(OcompKeyError::UnsafeFile { .. })
    ));

    let target_path = temporary.path().join("target.hex");
    write_key(&target_path, &canonical_secret([8; 32]), 0o600);
    let symlink_path = temporary.path().join("symlink.hex");
    symlink(&target_path, &symlink_path).expect("create key symlink");
    assert!(matches!(
        OcompSigner::from_file(&symlink_path, owner_uid),
        Err(OcompKeyError::UnsafeFile { .. })
    ));
}
