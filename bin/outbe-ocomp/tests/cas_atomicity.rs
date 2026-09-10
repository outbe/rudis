use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{Arc, Barrier};
use std::thread;

use outbe_ocomp::cas::{CasError, CasLimits, CasWriterRole, FilesystemCas};
use outbe_ocomp_protocol::{encode_envelope, CodecLimits, ObjectKind, OCB1_HEADER_LEN};
use tempfile::tempdir;

fn object_path(root: &std::path::Path, digest: alloy_primitives::B256) -> std::path::PathBuf {
    let hex = format!("{digest:x}");
    root.join("objects").join(&hex[..2]).join(&hex[2..])
}

#[test]
fn concurrent_same_bytes_publish_one_verified_object() {
    let directory = tempdir().expect("CAS directory");
    let cas = Arc::new(
        FilesystemCas::open(
            directory.path(),
            CasWriterRole::Supervisor,
            CasLimits {
                max_object_bytes: 1024,
                max_total_bytes: 4096,
            },
        )
        .expect("open CAS"),
    );
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let cas = Arc::clone(&cas);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                cas.publish_bytes(b"same immutable object")
                    .expect("idempotent publish")
            })
        })
        .collect();
    let references: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("publisher thread"))
        .collect();
    assert!(references.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        cas.read_verified(&references[0])
            .expect("verified read")
            .bytes(),
        b"same immutable object"
    );
    assert_eq!(cas.object_count().expect("object count"), 1);
    assert_eq!(cas.staging_count().expect("staging count"), 0);
}

#[test]
fn corruption_or_symlink_is_detected_and_never_overwritten() {
    let directory = tempdir().expect("CAS directory");
    let cas = FilesystemCas::open(
        directory.path(),
        CasWriterRole::Supervisor,
        CasLimits {
            max_object_bytes: 1024,
            max_total_bytes: 4096,
        },
    )
    .expect("open CAS");
    let reference = cas
        .publish_bytes(b"authenticated bytes")
        .expect("publish object");
    let path = object_path(directory.path(), reference.transport_digest);

    fs::write(&path, b"corrupted transport")
        .expect("simulate same-length hostile writer corruption");
    assert!(matches!(
        cas.read_verified(&reference).expect_err("digest mismatch"),
        CasError::DigestMismatch { .. }
    ));
    assert!(matches!(
        cas.publish_bytes(b"authenticated bytes")
            .expect_err("existing corruption is not overwritten"),
        CasError::DigestMismatch { .. }
    ));
    assert_eq!(
        fs::read(&path).expect("corrupt object remains evidence"),
        b"corrupted transport"
    );

    fs::remove_file(&path).expect("remove corrupt temp fixture");
    let target = directory.path().join("attacker-controlled");
    fs::write(&target, b"authenticated bytes").expect("symlink target");
    symlink(&target, &path).expect("simulate symlink substitution");
    assert!(matches!(
        cas.read_verified(&reference).expect_err("symlink rejected"),
        CasError::UnsafeObject { .. }
    ));
}

#[test]
fn object_and_total_quota_fail_without_partial_publish() {
    let directory = tempdir().expect("CAS directory");
    let cas = FilesystemCas::open(
        directory.path(),
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 4,
            max_total_bytes: 6,
        },
    )
    .expect("open CAS");

    let first = cas.publish_bytes(b"abc").expect("first object");
    assert!(matches!(
        cas.publish_bytes(b"12345").expect_err("object cap"),
        CasError::ObjectLimitExceeded {
            limit: 4,
            actual: 5
        }
    ));
    assert!(matches!(
        cas.publish_bytes(b"defg").expect_err("total cap"),
        CasError::TotalLimitExceeded {
            limit: 6,
            attempted: 7
        }
    ));
    assert_eq!(
        cas.read_verified(&first)
            .expect("first object intact")
            .bytes(),
        b"abc"
    );
    assert_eq!(cas.object_count().expect("object count"), 1);
    assert_eq!(cas.staging_count().expect("staging count"), 0);
}

#[test]
fn expected_ocb1_kind_is_verified_from_the_consumed_bytes() {
    let directory = tempdir().expect("CAS directory");
    let cas = FilesystemCas::open(
        directory.path(),
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 1024,
            max_total_bytes: 4096,
        },
    )
    .expect("open CAS");
    let encoded = encode_envelope(
        ObjectKind::InputManifestV1,
        b"manifest fixture body",
        CodecLimits::new(64, 4, OCB1_HEADER_LEN + 64),
    )
    .unwrap();
    let mut reference = cas.publish_bytes(&encoded).unwrap();
    reference.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    cas.read_verified(&reference)
        .expect("matching OCB1 kind accepted");

    reference.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
    assert!(matches!(
        cas.read_verified(&reference)
            .expect_err("wrong semantic object kind rejected"),
        CasError::Ocb1KindMismatch { .. }
    ));
}

#[test]
fn symlinked_cas_root_is_rejected_before_creating_any_layout() {
    let directory = tempdir().expect("CAS parent");
    let target = directory.path().join("attacker-target");
    fs::create_dir(&target).expect("attacker target");
    let configured_root = directory.path().join("configured-cas");
    symlink(&target, &configured_root).expect("symlinked configured root");

    assert!(matches!(
        FilesystemCas::open(
            &configured_root,
            CasWriterRole::Supervisor,
            CasLimits {
                max_object_bytes: 1024,
                max_total_bytes: 4096,
            },
        )
        .expect_err("symlinked root must reject"),
        CasError::UnsafeObject { .. }
    ));
    assert!(
        fs::read_dir(&target)
            .expect("attacker target")
            .next()
            .is_none(),
        "root validation must precede CAS layout creation"
    );
}

#[test]
fn opening_preprovisioned_shared_layout_preserves_directory_permissions() {
    let directory = tempdir().expect("CAS parent");
    let root = directory.path().join("cas-v1");
    let objects = root.join("objects");
    let staging = root.join("staging").join("exporter");
    fs::create_dir_all(&objects).expect("preprovision objects");
    fs::create_dir_all(&staging).expect("preprovision exporter staging");

    for path in [&root, &objects, &staging] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))
            .expect("set preprovisioned permissions");
    }

    FilesystemCas::open(
        &root,
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 1024,
            max_total_bytes: 4096,
        },
    )
    .expect("open preprovisioned shared CAS");

    for path in [&root, &objects, &staging] {
        let mode = fs::metadata(path)
            .expect("preprovisioned directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750, "opening must not chmod {}", path.display());
    }
}
