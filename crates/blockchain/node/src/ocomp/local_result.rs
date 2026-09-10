//! Durable node-local authority for independently computed canonical Lysis results.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use alloy_primitives::B256;
use outbe_ocomp_protocol::{result::LysisResultV1, ProtocolError, SchemaLimits, OCB1_HEADER_LEN};

const DIRECTORY_MODE: u32 = 0o700;
const RECORD_MODE: u32 = 0o600;
const RECORD_SUFFIX: &str = ".lysis-result-v1.ocb1";
const PENDING_PREFIX: &str = ".";
const PENDING_SUFFIX: &str = ".pending";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedLocalLysisResultV1 {
    pub job_id: B256,
    pub result_digest: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedLocalLysisResultV1 {
    pub committed: CommittedLocalLysisResultV1,
    pub canonical_result: Vec<u8>,
}

/// Immutable node-local results keyed by the consensus `JobId`.
///
/// The store owns the publication boundary. Callers can commit one canonical
/// result, replay that exact result, or verify an independently computed value;
/// there is no replace/delete API that could turn a mismatch into acceptance.
pub struct LocalLysisResultStore {
    root: PathBuf,
    owner_uid: u32,
    limits: SchemaLimits,
    max_record_bytes: u64,
    lock: Mutex<()>,
}

impl LocalLysisResultStore {
    pub fn open(
        root: impl AsRef<Path>,
        limits: SchemaLimits,
    ) -> Result<Self, LocalLysisResultError> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let owner_uid = validate_directory(&root)?;
        let max_record_bytes = limits
            .codec
            .max_body_bytes
            .checked_add(OCB1_HEADER_LEN)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(LocalLysisResultError::InvalidLimits)?;
        let store = Self {
            root,
            owner_uid,
            limits,
            max_record_bytes,
            lock: Mutex::new(()),
        };
        store.reconcile_startup()?;
        Ok(store)
    }

    pub fn commit(
        &self,
        job_id: B256,
        canonical_result: &[u8],
    ) -> Result<CommittedLocalLysisResultV1, LocalLysisResultError> {
        let _guard = self.lock()?;
        let (result, committed) = self.require_canonical_result(job_id, canonical_result)?;
        let final_path = self.record_path(job_id);
        if path_exists(&final_path)? {
            let existing = self.read_record(&final_path)?;
            if existing == canonical_result {
                return Ok(committed);
            }
            return Err(LocalLysisResultError::Conflict {
                job_id,
                recorded_digest: digest_of(&existing, &self.limits)?,
                requested_digest: committed.result_digest,
            });
        }

        let pending_path = self.pending_path(job_id);
        self.install(&pending_path, &final_path, canonical_result)?;
        // Keep the typed decode above deliberately alive through publication:
        // the bytes were checked against this exact semantic result.
        debug_assert_eq!(result.job_id, job_id);
        Ok(committed)
    }

    pub fn load(
        &self,
        job_id: B256,
    ) -> Result<Option<LoadedLocalLysisResultV1>, LocalLysisResultError> {
        let _guard = self.lock()?;
        let path = self.record_path(job_id);
        if !path_exists(&path)? {
            return Ok(None);
        }
        let canonical_result = self.read_record(&path)?;
        let (_, committed) = self.require_canonical_result(job_id, &canonical_result)?;
        Ok(Some(LoadedLocalLysisResultV1 {
            committed,
            canonical_result,
        }))
    }

    pub fn verify_exact(
        &self,
        job_id: B256,
        expected: &LysisResultV1,
    ) -> Result<CommittedLocalLysisResultV1, LocalLysisResultError> {
        let _guard = self.lock()?;
        self.verify_exact_locked(job_id, expected)
    }

    fn verify_exact_locked(
        &self,
        job_id: B256,
        expected: &LysisResultV1,
    ) -> Result<CommittedLocalLysisResultV1, LocalLysisResultError> {
        if expected.job_id != job_id {
            return Err(LocalLysisResultError::JobIdMismatch {
                expected: job_id,
                actual: expected.job_id,
            });
        }
        let expected_bytes = expected.encode_canonical(&self.limits)?;
        let expected_digest = expected.result_digest(&self.limits)?;
        let path = self.record_path(job_id);
        if !path_exists(&path)? {
            return Err(LocalLysisResultError::Missing { job_id });
        }
        let recorded = self.read_record(&path)?;
        if recorded != expected_bytes {
            return Err(LocalLysisResultError::Mismatch {
                job_id,
                recorded_digest: digest_of(&recorded, &self.limits)?,
                expected_digest,
            });
        }
        Ok(CommittedLocalLysisResultV1 {
            job_id,
            result_digest: expected_digest,
        })
    }

    fn require_canonical_result(
        &self,
        job_id: B256,
        encoded: &[u8],
    ) -> Result<(LysisResultV1, CommittedLocalLysisResultV1), LocalLysisResultError> {
        if encoded.len() > self.max_record_bytes as usize {
            return Err(LocalLysisResultError::Oversized {
                actual: encoded.len(),
                maximum: self.max_record_bytes,
            });
        }
        let result = LysisResultV1::decode_canonical(encoded, &self.limits)?;
        if result.job_id != job_id {
            return Err(LocalLysisResultError::JobIdMismatch {
                expected: job_id,
                actual: result.job_id,
            });
        }
        if result.encode_canonical(&self.limits)? != encoded {
            return Err(LocalLysisResultError::NonCanonical);
        }
        let result_digest = result.result_digest(&self.limits)?;
        Ok((
            result,
            CommittedLocalLysisResultV1 {
                job_id,
                result_digest,
            },
        ))
    }

    fn install(
        &self,
        pending_path: &Path,
        final_path: &Path,
        encoded: &[u8],
    ) -> Result<(), LocalLysisResultError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(RECORD_MODE);
        let mut pending = options
            .open(pending_path)
            .map_err(|source| self.io("create pending result", pending_path, source))?;
        pending
            .write_all(encoded)
            .map_err(|source| self.io("write pending result", pending_path, source))?;
        pending
            .sync_all()
            .map_err(|source| self.io("fsync pending result", pending_path, source))?;
        fs::hard_link(pending_path, final_path)
            .map_err(|source| self.io("publish no-clobber result", final_path, source))?;
        self.sync_root()?;
        fs::remove_file(pending_path)
            .map_err(|source| self.io("remove published pending result", pending_path, source))?;
        self.sync_root()
    }

    fn reconcile_startup(&self) -> Result<(), LocalLysisResultError> {
        for entry in fs::read_dir(&self.root)
            .map_err(|source| self.io("scan local result directory", &self.root, source))?
        {
            let entry =
                entry.map_err(|source| self.io("read local result entry", &self.root, source))?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(LocalLysisResultError::UnsafeStore {
                    path,
                    reason: "entry name is not UTF-8",
                });
            };
            if let Some(job_hex) = pending_job_hex(name) {
                self.reconcile_pending(&path, job_hex)?;
            } else if !name.ends_with(RECORD_SUFFIX) {
                return Err(LocalLysisResultError::UnsafeStore {
                    path,
                    reason: "unexpected local result directory entry",
                });
            }
        }

        for entry in fs::read_dir(&self.root)
            .map_err(|source| self.io("rescan local result directory", &self.root, source))?
        {
            let entry =
                entry.map_err(|source| self.io("read local result entry", &self.root, source))?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(LocalLysisResultError::UnsafeStore {
                    path,
                    reason: "entry name is not UTF-8",
                });
            };
            if pending_job_hex(name).is_some() {
                return Err(LocalLysisResultError::UncertainState {
                    path,
                    reason: "pending result remained after startup reconciliation",
                });
            }
            let encoded = self.read_record(&path)?;
            let result = LysisResultV1::decode_canonical(&encoded, &self.limits).map_err(|_| {
                LocalLysisResultError::CorruptRecord {
                    path: path.clone(),
                    reason: "record is not a canonical LysisResultV1",
                }
            })?;
            result.result_digest(&self.limits).map_err(|_| {
                LocalLysisResultError::CorruptRecord {
                    path: path.clone(),
                    reason: "record fails Lysis semantic validation",
                }
            })?;
            if self.record_path(result.job_id) != path {
                return Err(LocalLysisResultError::CorruptRecord {
                    path,
                    reason: "record filename does not match JobId",
                });
            }
        }
        Ok(())
    }

    fn reconcile_pending(
        &self,
        pending_path: &Path,
        job_hex: &str,
    ) -> Result<(), LocalLysisResultError> {
        require_lower_hex_32(job_hex).map_err(|reason| LocalLysisResultError::UnsafeStore {
            path: pending_path.to_path_buf(),
            reason,
        })?;
        let final_path = self.root.join(format!("{job_hex}{RECORD_SUFFIX}"));
        if path_exists(&final_path)? {
            let pending = validated_linked_record_metadata(pending_path, self.owner_uid)?;
            let published = validated_linked_record_metadata(&final_path, self.owner_uid)?;
            if pending.dev() != published.dev() || pending.ino() != published.ino() {
                return Err(LocalLysisResultError::UncertainState {
                    path: pending_path.to_path_buf(),
                    reason: "pending and published results are not the same inode",
                });
            }
        } else {
            let encoded = self.read_pending_record(pending_path)?;
            let result = LysisResultV1::decode_canonical(&encoded, &self.limits).map_err(|_| {
                LocalLysisResultError::UncertainState {
                    path: pending_path.to_path_buf(),
                    reason: "unpublished pending result is incomplete or non-canonical",
                }
            })?;
            if lower_hex(result.job_id.as_slice()) != job_hex
                || result.result_digest(&self.limits).is_err()
            {
                return Err(LocalLysisResultError::UncertainState {
                    path: pending_path.to_path_buf(),
                    reason: "unpublished pending result does not match its durable slot",
                });
            }
            File::open(pending_path)
                .and_then(|file| file.sync_all())
                .map_err(|source| {
                    self.io("fsync recovered pending result", pending_path, source)
                })?;
            fs::hard_link(pending_path, &final_path)
                .map_err(|source| self.io("recover pending result", &final_path, source))?;
            self.sync_root()?;
        }
        fs::remove_file(pending_path)
            .map_err(|source| self.io("reconcile pending result", pending_path, source))?;
        self.sync_root()
    }

    fn read_record(&self, path: &Path) -> Result<Vec<u8>, LocalLysisResultError> {
        let metadata = validated_record_metadata(path, self.owner_uid, 1)?;
        self.read_bounded_opened(path, metadata)
    }

    fn read_pending_record(&self, path: &Path) -> Result<Vec<u8>, LocalLysisResultError> {
        let metadata = validated_record_metadata(path, self.owner_uid, 1)?;
        self.read_bounded_opened(path, metadata)
    }

    fn read_bounded_opened(
        &self,
        path: &Path,
        metadata: fs::Metadata,
    ) -> Result<Vec<u8>, LocalLysisResultError> {
        if metadata.len() > self.max_record_bytes {
            return Err(LocalLysisResultError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record exceeds the protocol byte bound",
            });
        }
        let file = File::open(path).map_err(|source| self.io("open local result", path, source))?;
        let opened = file
            .metadata()
            .map_err(|source| self.io("inspect opened local result", path, source))?;
        validate_opened_record_metadata(path, &opened, self.owner_uid)?;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            return Err(LocalLysisResultError::UnsafeStore {
                path: path.to_path_buf(),
                reason: "local result path changed while opening",
            });
        }
        let mut encoded = Vec::with_capacity(opened.len() as usize);
        file.take(self.max_record_bytes + 1)
            .read_to_end(&mut encoded)
            .map_err(|source| self.io("read local result", path, source))?;
        if encoded.len() > self.max_record_bytes as usize {
            return Err(LocalLysisResultError::CorruptRecord {
                path: path.to_path_buf(),
                reason: "record grew beyond the protocol byte bound",
            });
        }
        Ok(encoded)
    }

    fn record_path(&self, job_id: B256) -> PathBuf {
        self.root
            .join(format!("{}{RECORD_SUFFIX}", lower_hex(job_id.as_slice())))
    }

    fn pending_path(&self, job_id: B256) -> PathBuf {
        self.root.join(format!(
            "{PENDING_PREFIX}{}{PENDING_SUFFIX}",
            lower_hex(job_id.as_slice())
        ))
    }

    fn sync_root(&self) -> Result<(), LocalLysisResultError> {
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| self.io("fsync local result directory", &self.root, source))
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, LocalLysisResultError> {
        self.lock
            .lock()
            .map_err(|_| LocalLysisResultError::Poisoned)
    }

    fn io(
        &self,
        operation: &'static str,
        path: &Path,
        source: std::io::Error,
    ) -> LocalLysisResultError {
        LocalLysisResultError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

fn digest_of(encoded: &[u8], limits: &SchemaLimits) -> Result<B256, LocalLysisResultError> {
    Ok(LysisResultV1::decode_canonical(encoded, limits)?.result_digest(limits)?)
}

fn create_private_directory(path: &Path) -> Result<(), LocalLysisResultError> {
    let mut builder = DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(LocalLysisResultError::Io {
            operation: "create local result directory",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_directory(path: &Path) -> Result<u32, LocalLysisResultError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| LocalLysisResultError::Io {
        operation: "stat local result directory",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(LocalLysisResultError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "local result root is not a directory",
        });
    }
    if metadata.permissions().mode() & 0o777 != DIRECTORY_MODE {
        return Err(LocalLysisResultError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "local result directory mode is not 0700",
        });
    }
    Ok(metadata.uid())
}

fn validated_record_metadata(
    path: &Path,
    owner_uid: u32,
    expected_links: u64,
) -> Result<fs::Metadata, LocalLysisResultError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| LocalLysisResultError::Io {
        operation: "stat local result",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != RECORD_MODE
        || metadata.nlink() != expected_links
    {
        return Err(LocalLysisResultError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "local result metadata is unsafe",
        });
    }
    Ok(metadata)
}

fn validated_linked_record_metadata(
    path: &Path,
    owner_uid: u32,
) -> Result<fs::Metadata, LocalLysisResultError> {
    validated_record_metadata(path, owner_uid, 2)
}

fn validate_opened_record_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    owner_uid: u32,
) -> Result<(), LocalLysisResultError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != RECORD_MODE
        || metadata.nlink() != 1
    {
        return Err(LocalLysisResultError::UnsafeStore {
            path: path.to_path_buf(),
            reason: "opened local result metadata is unsafe",
        });
    }
    Ok(())
}

fn pending_job_hex(name: &str) -> Option<&str> {
    name.strip_prefix(PENDING_PREFIX)
        .and_then(|name| name.strip_suffix(PENDING_SUFFIX))
}

fn require_lower_hex_32(value: &str) -> Result<(), &'static str> {
    if value.len() != 64 {
        return Err("result filename is not 32-byte lowercase hex");
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("result filename is not lowercase hex");
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

fn path_exists(path: &Path) -> Result<bool, LocalLysisResultError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(LocalLysisResultError::Io {
            operation: "inspect local result path",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocalLysisResultError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("local Lysis result is missing for job {job_id}")]
    Missing { job_id: B256 },
    #[error(
        "conflicting local Lysis result for job {job_id}: recorded {recorded_digest}, \
         requested {requested_digest}"
    )]
    Conflict {
        job_id: B256,
        recorded_digest: B256,
        requested_digest: B256,
    },
    #[error(
        "local Lysis result mismatch for job {job_id}: recorded {recorded_digest}, \
         expected {expected_digest}"
    )]
    Mismatch {
        job_id: B256,
        recorded_digest: B256,
        expected_digest: B256,
    },
    #[error("local Lysis result JobId mismatch: expected {expected}, actual {actual}")]
    JobIdMismatch { expected: B256, actual: B256 },
    #[error("local Lysis result is not canonical")]
    NonCanonical,
    #[error("local Lysis result is {actual} bytes, above protocol bound {maximum}")]
    Oversized { actual: usize, maximum: u64 },
    #[error("OCOMP schema limits cannot define a local result file bound")]
    InvalidLimits,
    #[error("local Lysis result store mutex is poisoned")]
    Poisoned,
    #[error("local Lysis result store is unsafe at {path}: {reason}")]
    UnsafeStore { path: PathBuf, reason: &'static str },
    #[error("local Lysis result state is uncertain at {path}: {reason}")]
    UncertainState { path: PathBuf, reason: &'static str },
    #[error("local Lysis result record is corrupt at {path}: {reason}")]
    CorruptRecord { path: PathBuf, reason: &'static str },
    #[error("local Lysis result {operation} failed at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
