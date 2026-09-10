// OCOMP-TEST-ID: OCM-SIG-001

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::B256;
use outbe_metadosis::config::poc_schema_limits;
use outbe_ocomp_protocol::{activation::SignOncePurpose, vote::ResultVoteSigningSubjectV1};

use outbe_ocomp::sign_once::{
    PersistenceBoundary, SignOnceDurability, SignOnceError, SignOnceStore, SignOnceSubjectV1,
};

struct FailAfterBoundary {
    boundary: PersistenceBoundary,
    fired: AtomicBool,
}

struct NoSpaceDurability;

impl SignOnceDurability for NoSpaceDurability {
    fn sync_file(&self, _file: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(28))
    }

    fn sync_directory(&self, directory: &File) -> io::Result<()> {
        directory.sync_all()
    }

    fn reached(&self, _boundary: PersistenceBoundary) -> io::Result<()> {
        Ok(())
    }
}

impl SignOnceDurability for FailAfterBoundary {
    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_directory(&self, directory: &File) -> io::Result<()> {
        directory.sync_all()
    }

    fn reached(&self, boundary: PersistenceBoundary) -> io::Result<()> {
        if boundary == self.boundary && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(io::Error::other(format!(
                "injected failure after {boundary:?}"
            )));
        }
        Ok(())
    }
}

fn subject(result_digest: B256) -> SignOnceSubjectV1 {
    SignOnceSubjectV1 {
        chain_id: 42,
        genesis_hash: B256::repeat_byte(0x10),
        fork_id: B256::repeat_byte(0x20),
        job_id: B256::repeat_byte(0x11),
        attempt: 0,
        protocol_bundle_hash: B256::repeat_byte(0x22),
        result_validator_set_epoch: 7,
        result_committee_set_hash: B256::repeat_byte(0x33),
        result_ocomp_binding_hash: B256::repeat_byte(0x34),
        ocomp_key_hash: B256::repeat_byte(0x35),
        key_epoch: 1,
        result_digest,
    }
}

fn expected_signing_digest(subject: SignOnceSubjectV1) -> B256 {
    ResultVoteSigningSubjectV1 {
        chain_id: subject.chain_id,
        genesis_hash: subject.genesis_hash,
        fork_id: subject.fork_id,
        protocol_bundle_hash: subject.protocol_bundle_hash,
        job_id: subject.job_id,
        attempt: subject.attempt,
        result_validator_set_epoch: subject.result_validator_set_epoch,
        result_committee_set_hash: subject.result_committee_set_hash,
        result_ocomp_binding_hash: subject.result_ocomp_binding_hash,
        ocomp_key_hash: subject.ocomp_key_hash,
        key_epoch: subject.key_epoch,
        purpose: SignOncePurpose::ResultSignature as u8,
        result_digest: subject.result_digest,
    }
    .signing_digest()
    .expect("fixture result-vote signing digest")
}

#[test]
fn ocm_sig_001_exact_replay_and_equivocation_survive_restart() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("sign-once");
    let signed = AtomicUsize::new(0);
    let first_subject = subject(B256::repeat_byte(0x44));
    let owner_uid = std::fs::metadata(temporary.path())
        .expect("temporary directory metadata")
        .uid();

    let store =
        SignOnceStore::open(root.clone(), owner_uid, poc_schema_limits()).expect("open store");
    let first = store
        .record_or_replay(first_subject, |digest| {
            assert_eq!(digest, expected_signing_digest(first_subject));
            signed.fetch_add(1, Ordering::SeqCst);
            Ok([0x55; 64])
        })
        .expect("record first signature");
    assert_eq!(first.result_digest, first_subject.result_digest);
    assert_eq!(first.signature_rs, [0x55; 64]);

    let replay = store
        .record_or_replay(first_subject, |_| {
            panic!("an exact replay must return the durable signature without signing again")
        })
        .expect("replay exact signature");
    assert_eq!(replay, first);
    assert_eq!(signed.load(Ordering::SeqCst), 1);

    drop(store);
    let reopened =
        SignOnceStore::open(root.clone(), owner_uid, poc_schema_limits()).expect("reopen store");
    let replay_after_restart = reopened
        .record_or_replay(first_subject, |_| {
            panic!("restart replay must not sign again")
        })
        .expect("replay after restart");
    assert_eq!(replay_after_restart, first);

    let conflicting = subject(B256::repeat_byte(0x66));
    assert!(matches!(
        reopened.record_or_replay(conflicting, |_| {
            panic!("an equivocation attempt must be refused before signing")
        }),
        Err(SignOnceError::Equivocation { .. })
    ));

    drop(reopened);
    let reopened = SignOnceStore::open(root, owner_uid, poc_schema_limits())
        .expect("reopen after equivocation");
    assert!(matches!(
        reopened.record_or_replay(conflicting, |_| {
            panic!("a restart must not erase equivocation protection")
        }),
        Err(SignOnceError::Equivocation { .. })
    ));
}

#[test]
fn ocm_sig_001_every_persistence_boundary_fails_closed_and_recovers_only_when_published() {
    for boundary in [
        PersistenceBoundary::Created,
        PersistenceBoundary::Written,
        PersistenceBoundary::FileSynced,
        PersistenceBoundary::Linked,
        PersistenceBoundary::DirectorySynced,
        PersistenceBoundary::PendingRemoved,
        PersistenceBoundary::CleanupDirectorySynced,
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("sign-once");
        let owner_uid = std::fs::metadata(temporary.path())
            .expect("temporary directory metadata")
            .uid();
        let first_subject = subject(B256::repeat_byte(0x77));
        let store = SignOnceStore::open_with_durability(
            root.clone(),
            owner_uid,
            poc_schema_limits(),
            Arc::new(FailAfterBoundary {
                boundary,
                fired: AtomicBool::new(false),
            }),
        )
        .expect("open faulted store");

        assert!(matches!(
            store.record_or_replay(first_subject, |_| Ok([0x88; 64])),
            Err(SignOnceError::Io { .. })
        ));
        assert!(matches!(
            store.record_or_replay(first_subject, |_| {
                panic!("an uncertain in-process store must not sign again")
            }),
            Err(SignOnceError::Disabled(_))
        ));
        drop(store);

        if matches!(
            boundary,
            PersistenceBoundary::Created
                | PersistenceBoundary::Written
                | PersistenceBoundary::FileSynced
        ) {
            assert!(matches!(
                SignOnceStore::open(root, owner_uid, poc_schema_limits()),
                Err(SignOnceError::UncertainState { .. })
            ));
        } else {
            let reopened = SignOnceStore::open(root, owner_uid, poc_schema_limits())
                .expect("published record must reconcile");
            let recovered = reopened
                .record_or_replay(first_subject, |_| {
                    panic!("a reconciled published record must not sign again")
                })
                .expect("replay reconciled record");
            assert_eq!(recovered.signature_rs, [0x88; 64]);
        }
    }
}

#[test]
fn ocm_sig_001_durable_reservation_precedes_signing_and_survives_restart() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("sign-once");
    let owner_uid = fs::metadata(temporary.path())
        .expect("temporary directory metadata")
        .uid();
    let first_subject = subject(B256::repeat_byte(0x79));
    let store = SignOnceStore::open_with_durability(
        root.clone(),
        owner_uid,
        poc_schema_limits(),
        Arc::new(FailAfterBoundary {
            boundary: PersistenceBoundary::Reserved,
            fired: AtomicBool::new(false),
        }),
    )
    .expect("open faulted store");

    assert!(matches!(
        store.record_or_replay(first_subject, |_| {
            panic!("the key must not be called before the reservation is durable")
        }),
        Err(SignOnceError::Io { .. })
    ));
    drop(store);

    let reopened = SignOnceStore::open(root, owner_uid, poc_schema_limits())
        .expect("reopen durable reservation");
    let conflicting = subject(B256::repeat_byte(0x7a));
    assert!(matches!(
        reopened.record_or_replay(conflicting, |_| {
            panic!("a conflicting digest must be rejected from the reservation")
        }),
        Err(SignOnceError::Equivocation { .. })
    ));
    let recovered = reopened
        .record_or_replay(first_subject, |_| Ok([0x7b; 64]))
        .expect("complete the reserved digest after restart");
    assert_eq!(recovered.signature_rs, [0x7b; 64]);
}

#[test]
fn ocm_sig_001_lost_response_reconnect_replays_the_durable_signature() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("sign-once");
    let owner_uid = fs::metadata(temporary.path())
        .expect("temporary directory metadata")
        .uid();
    let first_subject = subject(B256::repeat_byte(0x89));
    let store =
        SignOnceStore::open(root.clone(), owner_uid, poc_schema_limits()).expect("open store");
    store
        .record_or_replay(first_subject, |_| Ok([0x8a; 64]))
        .expect("durably publish signature before simulated response loss");
    drop(store);

    let reconnected =
        SignOnceStore::open(root, owner_uid, poc_schema_limits()).expect("reopen after disconnect");
    let replay = reconnected
        .record_or_replay(first_subject, |_| {
            panic!("reconnect must replay without another key operation")
        })
        .expect("replay durable signature");
    assert_eq!(replay.signature_rs, [0x8a; 64]);
}

#[test]
fn ocm_sig_001_full_corrupt_and_unsafe_storage_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let owner_uid = fs::metadata(temporary.path())
        .expect("temporary directory metadata")
        .uid();
    let full_root = temporary.path().join("full");
    let full = SignOnceStore::open_with_durability(
        full_root,
        owner_uid,
        poc_schema_limits(),
        Arc::new(NoSpaceDurability),
    )
    .expect("open capacity-fault store");
    let first_subject = subject(B256::repeat_byte(0x91));
    assert!(matches!(
        full.record_or_replay(first_subject, |_| Ok([0x92; 64])),
        Err(SignOnceError::Io { .. })
    ));
    assert!(matches!(
        full.record_or_replay(first_subject, |_| {
            panic!("a capacity-faulted store must disable signing")
        }),
        Err(SignOnceError::Disabled(_))
    ));

    let corrupt_root = temporary.path().join("corrupt");
    let store = SignOnceStore::open(corrupt_root.clone(), owner_uid, poc_schema_limits())
        .expect("open corruption fixture store");
    store
        .record_or_replay(first_subject, |_| Ok([0x93; 64]))
        .expect("install corruption fixture record");
    drop(store);
    let record_path = fs::read_dir(&corrupt_root)
        .expect("read sign-once directory")
        .next()
        .expect("one record")
        .expect("record entry")
        .path();
    let mut record = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&record_path)
        .expect("open record for corruption");
    record
        .write_all(b"not-a-canonical-sign-once-record")
        .expect("corrupt record");
    record.sync_all().expect("sync corrupted record");
    assert!(matches!(
        SignOnceStore::open(corrupt_root, owner_uid, poc_schema_limits()),
        Err(SignOnceError::CorruptRecord { .. })
    ));

    let unsafe_root = temporary.path().join("unsafe");
    fs::create_dir(&unsafe_root).expect("create unsafe root");
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755))
        .expect("set unsafe root mode");
    assert!(matches!(
        SignOnceStore::open(unsafe_root, owner_uid, poc_schema_limits()),
        Err(SignOnceError::UnsafeStore { .. })
    ));
}
