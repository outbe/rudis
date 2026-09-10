//! Immutable, Supervisor-owned sign-once authority for OCOMP result attestations.
//!
//! A caller supplies one typed result-signature subject, never an arbitrary
//! purpose. The store invokes the signing closure only when the slot is empty,
//! durably installs the complete canonical record without overwrite, and
//! returns an existing record for an exact retry.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use alloy_primitives::B256;
use outbe_ocomp_protocol::{
    activation::{SignOncePurpose, SignOnceRecordV1},
    vote::ResultVoteSigningSubjectV1,
    ProtocolError, SchemaLimits,
};

const DIRECTORY_MODE: u32 = 0o700;
const RECORD_MODE: u32 = 0o600;
const RECORD_SUFFIX: &str = ".ocb1";
const RESERVATION_SUFFIX: &str = ".reserved.ocb1";
const PENDING_PREFIX: &str = ".";
const PENDING_SUFFIX: &str = ".pending";
const MAX_RECORD_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignOnceSubjectV1 {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub protocol_bundle_hash: B256,
    pub result_validator_set_epoch: u64,
    pub result_committee_set_hash: B256,
    pub result_ocomp_binding_hash: B256,
    pub ocomp_key_hash: B256,
    pub key_epoch: u64,
    pub result_digest: B256,
}

impl SignOnceSubjectV1 {
    pub(crate) fn signing_digest(self) -> Result<B256, ProtocolError> {
        ResultVoteSigningSubjectV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            fork_id: self.fork_id,
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            ocomp_key_hash: self.ocomp_key_hash,
            key_epoch: self.key_epoch,
            purpose: SignOncePurpose::ResultSignature as u8,
            result_digest: self.result_digest,
        }
        .signing_digest()
    }

    fn record(self, signature_rs: [u8; 64]) -> SignOnceRecordV1 {
        SignOnceRecordV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            fork_id: self.fork_id,
            purpose: SignOncePurpose::ResultSignature,
            job_id: self.job_id,
            attempt: self.attempt,
            protocol_bundle_hash: self.protocol_bundle_hash,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            ocomp_key_hash: self.ocomp_key_hash,
            key_epoch: self.key_epoch,
            result_digest: self.result_digest,
            signature_rs,
        }
    }

    fn matches(self, record: &SignOnceRecordV1) -> bool {
        record.chain_id == self.chain_id
            && record.genesis_hash == self.genesis_hash
            && record.fork_id == self.fork_id
            && record.purpose == SignOncePurpose::ResultSignature
            && record.job_id == self.job_id
            && record.attempt == self.attempt
            && record.protocol_bundle_hash == self.protocol_bundle_hash
            && record.result_validator_set_epoch == self.result_validator_set_epoch
            && record.result_committee_set_hash == self.result_committee_set_hash
            && record.result_ocomp_binding_hash == self.result_ocomp_binding_hash
            && record.ocomp_key_hash == self.ocomp_key_hash
            && record.key_epoch == self.key_epoch
            && record.result_digest == self.result_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceBoundary {
    Reserved,
    Created,
    Written,
    FileSynced,
    Linked,
    DirectorySynced,
    PendingRemoved,
    CleanupDirectorySynced,
}

pub trait SignOnceDurability: Send + Sync {
    fn sync_file(&self, file: &File) -> std::io::Result<()>;
    fn sync_directory(&self, directory: &File) -> std::io::Result<()>;
    fn reached(&self, boundary: PersistenceBoundary) -> std::io::Result<()>;
}

#[derive(Debug, Default)]
struct OsSignOnceDurability;

impl SignOnceDurability for OsSignOnceDurability {
    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn sync_directory(&self, directory: &File) -> std::io::Result<()> {
        directory.sync_all()
    }

    fn reached(&self, _boundary: PersistenceBoundary) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct StoreState {
    disabled_reason: Option<String>,
}

pub struct SignOnceStore {
    root: PathBuf,
    expected_owner_uid: u32,
    limits: SchemaLimits,
    durability: Arc<dyn SignOnceDurability>,
    state: Mutex<StoreState>,
}

impl SignOnceStore {
    pub fn open(
        root: PathBuf,
        expected_owner_uid: u32,
        limits: SchemaLimits,
    ) -> Result<Self, SignOnceError> {
        Self::open_with_durability(
            root,
            expected_owner_uid,
            limits,
            Arc::new(OsSignOnceDurability),
        )
    }

    pub fn open_with_durability(
        root: PathBuf,
        expected_owner_uid: u32,
        limits: SchemaLimits,
        durability: Arc<dyn SignOnceDurability>,
    ) -> Result<Self, SignOnceError> {
        create_private_directory(&root)?;
        validate_directory(&root, expected_owner_uid)?;
        let store = Self {
            root,
            expected_owner_uid,
            limits,
            durability,
            state: Mutex::new(StoreState::default()),
        };
        store.reconcile_startup()?;
        Ok(store)
    }

    pub fn record_or_replay(
        &self,
        subject: SignOnceSubjectV1,
        sign: impl FnOnce(B256) -> Result<[u8; 64], String>,
    ) -> Result<SignOnceRecordV1, SignOnceError> {
        let mut state = self.lock()?;
        if let Some(reason) = &state.disabled_reason {
            return Err(SignOnceError::Disabled(reason.clone()));
        }

        let result = self.record_or_replay_locked(subject, sign);
        if let Err(error) = &result {
            if error.disables_store() {
                state.disabled_reason = Some(error.to_string());
            }
        }
        result
    }

    fn record_or_replay_locked(
        &self,
        subject: SignOnceSubjectV1,
        sign: impl FnOnce(B256) -> Result<[u8; 64], String>,
    ) -> Result<SignOnceRecordV1, SignOnceError> {
        let slot_id = subject.record([0; 64]).slot_id()?;
        let final_path = self.record_path(slot_id);
        if path_exists(&final_path)? {
            return self.require_exact_replay(&final_path, subject);
        }

        let reservation_path = self.reservation_path(slot_id);
        if path_exists(&reservation_path)? {
            self.require_exact_reservation(&reservation_path, subject)?;
        } else {
            self.reserve(&reservation_path, subject)?;
        }

        let signing_digest = subject.signing_digest()?;
        let record = subject.record(sign(signing_digest).map_err(SignOnceError::SigningFailed)?);
        let encoded = record.encode_canonical(&self.limits)?;
        if encoded.len() > MAX_RECORD_BYTES as usize {
            return Err(SignOnceError::CorruptRecord {
                path: final_path,
                reason: "canonical record exceeds the fixed byte bound",
            });
        }
        let pending_path = self.pending_path(slot_id);
        self.install(&pending_path, &final_path, &encoded)?;
        fs::remove_file(&reservation_path)
            .map_err(|source| self.io("remove committed reservation", &reservation_path, source))?;
        self.sync_root()?;
        Ok(record)
    }

    fn reserve(&self, path: &Path, subject: SignOnceSubjectV1) -> Result<(), SignOnceError> {
        let encoded = subject.record([0; 64]).encode_canonical(&self.limits)?;
        if encoded.len() > MAX_RECORD_BYTES as usize {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "canonical reservation exceeds the fixed byte bound",
            });
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(RECORD_MODE);
        let mut file = options
            .open(path)
            .map_err(|source| self.io("create sign-once reservation", path, source))?;
        file.write_all(&encoded)
            .map_err(|source| self.io("write sign-once reservation", path, source))?;
        self.durability
            .sync_file(&file)
            .map_err(|source| self.io("fsync sign-once reservation", path, source))?;
        self.sync_root()?;
        self.boundary(PersistenceBoundary::Reserved, path)
    }

    fn require_exact_reservation(
        &self,
        path: &Path,
        subject: SignOnceSubjectV1,
    ) -> Result<(), SignOnceError> {
        let reservation = self.read_record(path)?;
        if reservation.signature_rs != [0; 64] {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "reservation contains a signature",
            });
        }
        if subject.matches(&reservation) {
            Ok(())
        } else {
            Err(SignOnceError::Equivocation {
                job_id: subject.job_id,
                attempt: subject.attempt,
                recorded_digest: reservation.result_digest,
                requested_digest: subject.result_digest,
            })
        }
    }

    fn require_exact_replay(
        &self,
        path: &Path,
        subject: SignOnceSubjectV1,
    ) -> Result<SignOnceRecordV1, SignOnceError> {
        let existing = self.read_record(path)?;
        if subject.matches(&existing) {
            Ok(existing)
        } else {
            Err(SignOnceError::Equivocation {
                job_id: subject.job_id,
                attempt: subject.attempt,
                recorded_digest: existing.result_digest,
                requested_digest: subject.result_digest,
            })
        }
    }

    fn install(
        &self,
        pending_path: &Path,
        final_path: &Path,
        encoded: &[u8],
    ) -> Result<(), SignOnceError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(RECORD_MODE);
        let mut pending = options
            .open(pending_path)
            .map_err(|source| self.io("create pending record", pending_path, source))?;
        self.boundary(PersistenceBoundary::Created, pending_path)?;

        pending
            .write_all(encoded)
            .map_err(|source| self.io("write pending record", pending_path, source))?;
        self.boundary(PersistenceBoundary::Written, pending_path)?;

        self.durability
            .sync_file(&pending)
            .map_err(|source| self.io("fsync pending record", pending_path, source))?;
        self.boundary(PersistenceBoundary::FileSynced, pending_path)?;

        fs::hard_link(pending_path, final_path)
            .map_err(|source| self.io("publish no-clobber record", final_path, source))?;
        self.boundary(PersistenceBoundary::Linked, final_path)?;

        self.sync_root()?;
        self.boundary(PersistenceBoundary::DirectorySynced, &self.root)?;

        fs::remove_file(pending_path)
            .map_err(|source| self.io("remove published pending record", pending_path, source))?;
        self.boundary(PersistenceBoundary::PendingRemoved, pending_path)?;
        self.sync_root()?;
        self.boundary(PersistenceBoundary::CleanupDirectorySynced, &self.root)?;
        Ok(())
    }

    fn reconcile_startup(&self) -> Result<(), SignOnceError> {
        for entry in fs::read_dir(&self.root)
            .map_err(|source| self.io("scan sign-once directory", &self.root, source))?
        {
            let entry = entry
                .map_err(|source| self.io("read sign-once directory entry", &self.root, source))?;
            let name = entry.file_name();
            let path = entry.path();
            let Some(name) = name.to_str() else {
                return Err(SignOnceError::UnsafeStore {
                    path,
                    reason: "entry name is not UTF-8",
                });
            };

            if let Some(slot_hex) = pending_slot_hex(name) {
                self.reconcile_pending(&path, slot_hex)?;
            } else if reservation_slot_hex(name).is_none() && !name.ends_with(RECORD_SUFFIX) {
                return Err(SignOnceError::UnsafeStore {
                    path,
                    reason: "unexpected sign-once directory entry",
                });
            }
        }

        // Published hard links must be reconciled before reservations inspect
        // their final record; directory iteration order is not authoritative.
        for entry in fs::read_dir(&self.root)
            .map_err(|source| self.io("rescan sign-once reservations", &self.root, source))?
        {
            let entry = entry.map_err(|source| {
                self.io("read sign-once reservation entry", &self.root, source)
            })?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(SignOnceError::UnsafeStore {
                    path,
                    reason: "entry name is not UTF-8",
                });
            };
            if let Some(slot_hex) = reservation_slot_hex(name) {
                self.reconcile_reservation(&path, slot_hex)?;
            }
        }

        // A crash after the no-clobber link leaves the pending and published
        // names on the same inode. Reconcile all such pairs before validating
        // published link counts, independent of filesystem iteration order.
        for entry in fs::read_dir(&self.root)
            .map_err(|source| self.io("rescan sign-once directory", &self.root, source))?
        {
            let entry = entry
                .map_err(|source| self.io("read sign-once directory entry", &self.root, source))?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(SignOnceError::UnsafeStore {
                    path,
                    reason: "entry name is not UTF-8",
                });
            };
            if pending_slot_hex(name).is_some() {
                return Err(SignOnceError::UncertainState {
                    path,
                    reason: "pending record remained after startup reconciliation",
                });
            }
            if let Some(slot_hex) = reservation_slot_hex(name) {
                self.validate_reservation_path(&path, slot_hex)?;
                continue;
            }
            let record = self.read_record(&path)?;
            let expected = self.record_path(record.slot_id()?);
            if expected != path {
                return Err(SignOnceError::CorruptRecord {
                    path,
                    reason: "record filename does not match its typed slot",
                });
            }
        }
        Ok(())
    }

    fn reconcile_reservation(
        &self,
        reservation_path: &Path,
        slot_hex: &str,
    ) -> Result<(), SignOnceError> {
        self.validate_reservation_path(reservation_path, slot_hex)?;
        let final_path = self.root.join(format!("{slot_hex}{RECORD_SUFFIX}"));
        if !path_exists(&final_path)? {
            return Ok(());
        }
        let reservation = self.read_record(reservation_path)?;
        let final_record = self.read_record(&final_path)?;
        if reservation.signature_rs != [0; 64]
            || !records_share_subject(&reservation, &final_record)
        {
            return Err(SignOnceError::CorruptRecord {
                path: reservation_path.to_path_buf(),
                reason: "reservation does not match the published record",
            });
        }
        fs::remove_file(reservation_path).map_err(|source| {
            self.io(
                "remove reconciled sign-once reservation",
                reservation_path,
                source,
            )
        })?;
        self.sync_root()
    }

    fn validate_reservation_path(&self, path: &Path, slot_hex: &str) -> Result<(), SignOnceError> {
        require_lower_hex_32(slot_hex).map_err(|reason| SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason,
        })?;
        let reservation = self.read_record(path)?;
        if reservation.signature_rs != [0; 64]
            || self.reservation_path(reservation.slot_id()?) != path
        {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "invalid sign-once reservation",
            });
        }
        Ok(())
    }

    fn reconcile_pending(&self, pending_path: &Path, slot_hex: &str) -> Result<(), SignOnceError> {
        require_lower_hex_32(slot_hex).map_err(|reason| SignOnceError::UnsafeStore {
            path: pending_path.to_path_buf(),
            reason,
        })?;
        let final_path = self.root.join(format!("{slot_hex}{RECORD_SUFFIX}"));
        if !path_exists(&final_path)? {
            return Err(SignOnceError::UncertainState {
                path: pending_path.to_path_buf(),
                reason: "pending record exists without a published record",
            });
        }
        let pending_metadata =
            validated_linked_record_metadata(pending_path, self.expected_owner_uid)?;
        let final_metadata =
            validated_linked_record_metadata(&final_path, self.expected_owner_uid)?;
        if pending_metadata.dev() != final_metadata.dev()
            || pending_metadata.ino() != final_metadata.ino()
        {
            return Err(SignOnceError::UncertainState {
                path: pending_path.to_path_buf(),
                reason: "pending and published records are not the same inode",
            });
        }
        fs::remove_file(pending_path).map_err(|source| {
            self.io("reconcile published pending record", pending_path, source)
        })?;
        self.sync_root()?;
        let record = self.read_record(&final_path)?;
        let expected = self.record_path(record.slot_id()?);
        if expected != final_path {
            return Err(SignOnceError::CorruptRecord {
                path: final_path,
                reason: "reconciled record filename does not match its typed slot",
            });
        }
        Ok(())
    }

    fn read_record(&self, path: &Path) -> Result<SignOnceRecordV1, SignOnceError> {
        let metadata = validated_record_metadata(path, self.expected_owner_uid)?;
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record exceeds the fixed byte bound",
            });
        }
        let file =
            File::open(path).map_err(|source| self.io("open sign-once record", path, source))?;
        let opened_metadata = file
            .metadata()
            .map_err(|source| self.io("inspect opened sign-once record", path, source))?;
        validate_opened_record_metadata(path, &opened_metadata, self.expected_owner_uid)?;
        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(SignOnceError::UnsafeStore {
                path: path.to_path_buf(),
                reason: "sign-once record path changed while opening",
            });
        }
        if opened_metadata.len() > MAX_RECORD_BYTES {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "opened record exceeds the fixed byte bound",
            });
        }
        let mut encoded = Vec::with_capacity(opened_metadata.len() as usize);
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|source| self.io("read sign-once record", path, source))?;
        if encoded.len() > MAX_RECORD_BYTES as usize {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record grew beyond the fixed byte bound while reading",
            });
        }
        let record = SignOnceRecordV1::decode_canonical(&encoded, &self.limits).map_err(|_| {
            SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record is not canonical SignOnceRecordV1",
            }
        })?;
        if record.encode_canonical(&self.limits)? != encoded {
            return Err(SignOnceError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record canonical re-encoding differs",
            });
        }
        Ok(record)
    }

    fn record_path(&self, slot_id: B256) -> PathBuf {
        self.root
            .join(format!("{}{RECORD_SUFFIX}", lower_hex(slot_id.as_slice())))
    }

    fn pending_path(&self, slot_id: B256) -> PathBuf {
        self.root.join(format!(
            "{PENDING_PREFIX}{}{PENDING_SUFFIX}",
            lower_hex(slot_id.as_slice())
        ))
    }

    fn reservation_path(&self, slot_id: B256) -> PathBuf {
        self.root.join(format!(
            "{}{RESERVATION_SUFFIX}",
            lower_hex(slot_id.as_slice())
        ))
    }

    fn sync_root(&self) -> Result<(), SignOnceError> {
        let directory = File::open(&self.root)
            .map_err(|source| self.io("open sign-once directory", &self.root, source))?;
        self.durability
            .sync_directory(&directory)
            .map_err(|source| self.io("fsync sign-once directory", &self.root, source))
    }

    fn boundary(&self, boundary: PersistenceBoundary, path: &Path) -> Result<(), SignOnceError> {
        self.durability
            .reached(boundary)
            .map_err(|source| self.io("sign-once persistence boundary", path, source))
    }

    fn lock(&self) -> Result<MutexGuard<'_, StoreState>, SignOnceError> {
        self.state
            .lock()
            .map_err(|_| SignOnceError::Disabled("sign-once state mutex is poisoned".to_owned()))
    }

    fn io(&self, operation: &'static str, path: &Path, source: std::io::Error) -> SignOnceError {
        SignOnceError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

fn create_private_directory(path: &Path) -> Result<(), SignOnceError> {
    let mut builder = DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(SignOnceError::Io {
            operation: "create sign-once directory",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_directory(path: &Path, expected_owner_uid: u32) -> Result<(), SignOnceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SignOnceError::Io {
        operation: "stat sign-once directory",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once root is not a directory",
        });
    }
    if metadata.uid() != expected_owner_uid {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once directory has the wrong owner",
        });
    }
    if metadata.permissions().mode() & 0o777 != DIRECTORY_MODE {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once directory mode is not 0700",
        });
    }
    Ok(())
}

fn validated_record_metadata(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<fs::Metadata, SignOnceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SignOnceError::Io {
        operation: "stat sign-once record",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once record is not a regular file",
        });
    }
    if metadata.uid() != expected_owner_uid {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once record has the wrong owner",
        });
    }
    if metadata.permissions().mode() & 0o777 != RECORD_MODE {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once record mode is not 0600",
        });
    }
    if metadata.nlink() != 1 {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "sign-once record has an unexpected hard-link count",
        });
    }
    Ok(metadata)
}

fn validate_opened_record_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), SignOnceError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o777 != RECORD_MODE
        || metadata.nlink() != 1
    {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "opened sign-once record metadata is unsafe",
        });
    }
    Ok(())
}

fn validated_linked_record_metadata(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<fs::Metadata, SignOnceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SignOnceError::Io {
        operation: "stat linked sign-once record",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o777 != RECORD_MODE
        || metadata.nlink() != 2
    {
        return Err(SignOnceError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "published sign-once record link metadata is unsafe",
        });
    }
    Ok(metadata)
}

fn pending_slot_hex(name: &str) -> Option<&str> {
    name.strip_prefix(PENDING_PREFIX)
        .and_then(|name| name.strip_suffix(PENDING_SUFFIX))
}

fn reservation_slot_hex(name: &str) -> Option<&str> {
    name.strip_suffix(RESERVATION_SUFFIX)
}

fn records_share_subject(left: &SignOnceRecordV1, right: &SignOnceRecordV1) -> bool {
    left.chain_id == right.chain_id
        && left.genesis_hash == right.genesis_hash
        && left.fork_id == right.fork_id
        && left.purpose == right.purpose
        && left.job_id == right.job_id
        && left.attempt == right.attempt
        && left.protocol_bundle_hash == right.protocol_bundle_hash
        && left.result_validator_set_epoch == right.result_validator_set_epoch
        && left.result_committee_set_hash == right.result_committee_set_hash
        && left.result_ocomp_binding_hash == right.result_ocomp_binding_hash
        && left.ocomp_key_hash == right.ocomp_key_hash
        && left.key_epoch == right.key_epoch
        && left.result_digest == right.result_digest
}

fn require_lower_hex_32(value: &str) -> Result<(), &'static str> {
    if value.len() != 64 {
        return Err("slot filename is not 32-byte lowercase hex");
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("slot filename is not lowercase hex");
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn path_exists(path: &Path) -> Result<bool, SignOnceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SignOnceError::Io {
            operation: "inspect sign-once path",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignOnceError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(
        "OCOMP sign-once equivocation for job {job_id}, attempt {attempt}: \
         recorded {recorded_digest}, requested {requested_digest}"
    )]
    Equivocation {
        job_id: B256,
        attempt: u32,
        recorded_digest: B256,
        requested_digest: B256,
    },
    #[error("OCOMP sign-once store is disabled: {0}")]
    Disabled(String),
    #[error("OCOMP result-digest signing failed: {0}")]
    SigningFailed(String),
    #[error("OCOMP sign-once store is unsafe at {path}: {reason}")]
    UnsafeStore { path: PathBuf, reason: &'static str },
    #[error("OCOMP sign-once state is uncertain at {path}: {reason}")]
    UncertainState { path: PathBuf, reason: &'static str },
    #[error("OCOMP sign-once record is corrupt at {path}: {reason}")]
    CorruptRecord { path: PathBuf, reason: &'static str },
    #[error("OCOMP sign-once {operation} failed at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl SignOnceError {
    fn disables_store(&self) -> bool {
        matches!(
            self,
            Self::Disabled(_)
                | Self::UnsafeStore { .. }
                | Self::UncertainState { .. }
                | Self::CorruptRecord { .. }
                | Self::SigningFailed(_)
                | Self::Io { .. }
        )
    }
}
