//! Digest-only filesystem CAS used by the fixed exporter and supervisor roles.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::B256;
use outbe_ocomp_protocol::{CasObjectRefV1, OCB1_HEADER_LEN, OCB1_MAGIC};
use sha3::{Digest, Keccak256};
use thiserror::Error;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasWriterRole {
    SnapshotExporter,
    Supervisor,
}

impl CasWriterRole {
    const fn staging_name(self) -> &'static str {
        match self {
            Self::SnapshotExporter => "exporter",
            Self::Supervisor => "supervisor",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasLimits {
    pub max_object_bytes: u64,
    pub max_total_bytes: u64,
}

impl CasLimits {
    fn validate(self) -> Result<Self, CasError> {
        if self.max_object_bytes == 0
            || self.max_total_bytes == 0
            || self.max_object_bytes > self.max_total_bytes
        {
            return Err(CasError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum CasError {
    #[error("CAS limits must be non-zero and the object limit cannot exceed total limit")]
    InvalidLimits,
    #[error("CAS object has {actual} bytes, exceeding object limit {limit}")]
    ObjectLimitExceeded { limit: u64, actual: u64 },
    #[error("CAS publish would use {attempted} bytes, exceeding total limit {limit}")]
    TotalLimitExceeded { limit: u64, attempted: u64 },
    #[error("CAS I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("CAS object at {path} is not a safe regular no-follow file")]
    UnsafeObject { path: PathBuf },
    #[error("CAS object length mismatch: expected {expected}, actual {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("CAS object digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch { expected: B256, actual: B256 },
    #[error("CAS object changed while the same descriptor was being verified")]
    ObjectChanged,
    #[error("CAS object expected OCB1 kind {expected:#06x} but has no valid OCB1 header")]
    InvalidOcb1Header { expected: u16 },
    #[error("CAS object OCB1 kind mismatch: expected {expected:#06x}, actual {actual:#06x}")]
    Ocb1KindMismatch { expected: u16, actual: u16 },
    #[error("CAS byte count does not fit this host")]
    LengthOverflow,
    #[error("CAS publication lock failed")]
    PublicationLock,
}

#[derive(Debug)]
pub struct VerifiedCasObject {
    reference: CasObjectRefV1,
    bytes: Vec<u8>,
}

impl VerifiedCasObject {
    #[must_use]
    pub fn reference(&self) -> CasObjectRefV1 {
        self.reference.clone()
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub struct FilesystemCas {
    root: PathBuf,
    objects: PathBuf,
    staging: PathBuf,
    limits: CasLimits,
}

impl FilesystemCas {
    pub fn open(
        root: impl AsRef<Path>,
        role: CasWriterRole,
        limits: CasLimits,
    ) -> Result<Self, CasError> {
        let limits = limits.validate()?;
        let root = root.as_ref().to_path_buf();
        create_directory(&root)?;
        reject_symlink_directory(&root)?;
        let objects = root.join("objects");
        let staging = root.join("staging").join(role.staging_name());
        create_directory(&objects)?;
        create_directory(&staging)?;
        let cas = Self {
            root,
            objects,
            staging,
            limits,
        };
        reject_symlink_directory(&cas.objects)?;
        reject_symlink_directory(&cas.staging)?;
        Ok(cas)
    }

    /// Streams the supplied bytes once into a same-filesystem staging file,
    /// computing the transport digest while writing.
    pub fn publish_bytes(&self, bytes: &[u8]) -> Result<CasObjectRefV1, CasError> {
        let declared = u64::try_from(bytes.len()).map_err(|_| CasError::LengthOverflow)?;
        if declared > self.limits.max_object_bytes {
            return Err(CasError::ObjectLimitExceeded {
                limit: self.limits.max_object_bytes,
                actual: declared,
            });
        }
        let _lock = PublicationLock::acquire(&self.root)?;
        let staging_path = self.next_staging_path();
        let result = self.publish_staged(&staging_path, bytes, declared);
        let _ = fs::remove_file(&staging_path);
        result
    }

    pub fn read_verified(&self, reference: &CasObjectRefV1) -> Result<VerifiedCasObject, CasError> {
        read_verified_object(&self.objects, self.limits, reference)
    }

    pub fn object_count(&self) -> Result<usize, CasError> {
        let mut count = 0_usize;
        for prefix in read_directory(&self.objects)? {
            let prefix = prefix.map_err(|source| CasError::Io {
                path: self.objects.clone(),
                source,
            })?;
            let prefix_path = prefix.path();
            let prefix_metadata =
                fs::symlink_metadata(&prefix_path).map_err(|source| CasError::Io {
                    path: prefix_path.clone(),
                    source,
                })?;
            if !prefix_metadata.file_type().is_dir() || prefix_metadata.file_type().is_symlink() {
                return Err(CasError::UnsafeObject { path: prefix_path });
            }
            for object in read_directory(&prefix_path)? {
                let object = object.map_err(|source| CasError::Io {
                    path: prefix_path.clone(),
                    source,
                })?;
                let path = object.path();
                let metadata = fs::symlink_metadata(&path).map_err(|source| CasError::Io {
                    path: path.clone(),
                    source,
                })?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(CasError::UnsafeObject { path });
                }
                count = count.checked_add(1).ok_or(CasError::LengthOverflow)?;
            }
        }
        Ok(count)
    }

    pub fn staging_count(&self) -> Result<usize, CasError> {
        read_directory(&self.staging)?.try_fold(0_usize, |count, entry| {
            let entry = entry.map_err(|source| CasError::Io {
                path: self.staging.clone(),
                source,
            })?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CasError::Io {
                path: entry.path(),
                source,
            })?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(CasError::UnsafeObject { path: entry.path() });
            }
            count.checked_add(1).ok_or(CasError::LengthOverflow)
        })
    }

    fn publish_staged(
        &self,
        staging_path: &Path,
        bytes: &[u8],
        declared: u64,
    ) -> Result<CasObjectRefV1, CasError> {
        let mut staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(staging_path)
            .map_err(|source| CasError::Io {
                path: staging_path.to_path_buf(),
                source,
            })?;
        let mut hasher = Keccak256::new();
        for chunk in bytes.chunks(64 * 1024) {
            staging.write_all(chunk).map_err(|source| CasError::Io {
                path: staging_path.to_path_buf(),
                source,
            })?;
            hasher.update(chunk);
        }
        staging.sync_all().map_err(|source| CasError::Io {
            path: staging_path.to_path_buf(),
            source,
        })?;
        let reference = CasObjectRefV1 {
            transport_digest: finalize_digest(hasher),
            encoded_bytes: declared,
            expected_ocb1_kind: None,
        };
        let path = self.object_path(reference.transport_digest);
        let parent = path.parent().ok_or(CasError::LengthOverflow)?;
        create_directory(parent)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                self.read_verified(&reference)?;
                return Ok(reference);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CasError::Io {
                    path: path.clone(),
                    source,
                });
            }
        }
        let attempted = self
            .used_bytes()?
            .checked_add(declared)
            .ok_or(CasError::LengthOverflow)?;
        if attempted > self.limits.max_total_bytes {
            return Err(CasError::TotalLimitExceeded {
                limit: self.limits.max_total_bytes,
                attempted,
            });
        }

        match fs::hard_link(staging_path, &path) {
            Ok(()) => {
                sync_directory(parent)?;
                fs::remove_file(staging_path).map_err(|source| CasError::Io {
                    path: staging_path.to_path_buf(),
                    source,
                })?;
                sync_directory(&self.staging)?;
                self.read_verified(&reference)?;
                Ok(reference)
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                self.read_verified(&reference)?;
                Ok(reference)
            }
            Err(source) => Err(CasError::Io { path, source }),
        }
    }

    fn used_bytes(&self) -> Result<u64, CasError> {
        let mut total = 0_u64;
        for prefix in read_directory(&self.objects)? {
            let prefix = prefix.map_err(|source| CasError::Io {
                path: self.objects.clone(),
                source,
            })?;
            let prefix_path = prefix.path();
            let prefix_metadata =
                fs::symlink_metadata(&prefix_path).map_err(|source| CasError::Io {
                    path: prefix_path.clone(),
                    source,
                })?;
            if !prefix_metadata.file_type().is_dir() || prefix_metadata.file_type().is_symlink() {
                return Err(CasError::UnsafeObject { path: prefix_path });
            }
            for object in read_directory(&prefix.path())? {
                let object = object.map_err(|source| CasError::Io {
                    path: prefix.path(),
                    source,
                })?;
                let path = object.path();
                let metadata = fs::symlink_metadata(&path).map_err(|source| CasError::Io {
                    path: path.clone(),
                    source,
                })?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(CasError::UnsafeObject { path });
                }
                total = total
                    .checked_add(metadata.len())
                    .ok_or(CasError::LengthOverflow)?;
            }
        }
        Ok(total)
    }

    fn object_path(&self, digest: B256) -> PathBuf {
        digest_object_path(&self.objects, digest)
    }

    fn next_staging_path(&self) -> PathBuf {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        self.staging
            .join(format!("{}-{sequence}.tmp", std::process::id()))
    }
}

#[derive(Debug)]
pub struct FilesystemCasReader {
    objects: PathBuf,
    limits: CasLimits,
}

impl FilesystemCasReader {
    pub fn open(root: impl AsRef<Path>, limits: CasLimits) -> Result<Self, CasError> {
        let limits = limits.validate()?;
        let objects = root.as_ref().join("objects");
        let metadata = fs::symlink_metadata(&objects).map_err(|source| CasError::Io {
            path: objects.clone(),
            source,
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(CasError::UnsafeObject { path: objects });
        }
        Ok(Self { objects, limits })
    }

    pub fn read_verified(&self, reference: &CasObjectRefV1) -> Result<VerifiedCasObject, CasError> {
        read_verified_object(&self.objects, self.limits, reference)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn read_verified_object(
    objects: &Path,
    limits: CasLimits,
    reference: &CasObjectRefV1,
) -> Result<VerifiedCasObject, CasError> {
    if reference.encoded_bytes > limits.max_object_bytes {
        return Err(CasError::ObjectLimitExceeded {
            limit: limits.max_object_bytes,
            actual: reference.encoded_bytes,
        });
    }
    let path = digest_object_path(objects, reference.transport_digest);
    let mut file = open_regular_nofollow(&path)?;
    let before = FileIdentity::read(&file, &path)?;
    if before.len != reference.encoded_bytes {
        return Err(CasError::LengthMismatch {
            expected: reference.encoded_bytes,
            actual: before.len,
        });
    }
    let capacity = usize::try_from(before.len).map_err(|_| CasError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut hasher = Keccak256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| CasError::Io {
            path: path.clone(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    let actual_len = u64::try_from(bytes.len()).map_err(|_| CasError::LengthOverflow)?;
    if actual_len != reference.encoded_bytes {
        return Err(CasError::LengthMismatch {
            expected: reference.encoded_bytes,
            actual: actual_len,
        });
    }
    let after = FileIdentity::read(&file, &path)?;
    if before != after {
        return Err(CasError::ObjectChanged);
    }
    let actual_digest = finalize_digest(hasher);
    if actual_digest != reference.transport_digest {
        return Err(CasError::DigestMismatch {
            expected: reference.transport_digest,
            actual: actual_digest,
        });
    }
    if let Some(expected) = reference.expected_ocb1_kind {
        if bytes.len() < OCB1_HEADER_LEN || bytes[..4] != OCB1_MAGIC {
            return Err(CasError::InvalidOcb1Header { expected });
        }
        let actual = u16::from_be_bytes([bytes[4], bytes[5]]);
        if actual != expected {
            return Err(CasError::Ocb1KindMismatch { expected, actual });
        }
    }
    Ok(VerifiedCasObject {
        reference: reference.clone(),
        bytes,
    })
}

impl FileIdentity {
    fn read(file: &File, path: &Path) -> Result<Self, CasError> {
        let metadata = file.metadata().map_err(|source| CasError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(CasError::UnsafeObject {
                path: path.to_path_buf(),
            });
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

struct PublicationLock {
    file: File,
}

impl PublicationLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, CasError> {
        let path = root.join(".publish.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o660)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| CasError::Io {
                path: path.clone(),
                source,
            })?;
        // SAFETY: `file` owns a live descriptor for the duration of the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(CasError::PublicationLock);
        }
        Ok(Self { file })
    }
}

impl Drop for PublicationLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open until after this drop body.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn open_regular_nofollow(path: &Path) -> Result<File, CasError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| {
            if source.raw_os_error() == Some(libc::ELOOP) {
                CasError::UnsafeObject {
                    path: path.to_path_buf(),
                }
            } else {
                CasError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            }
        })
}

fn create_directory(path: &Path) -> Result<(), CasError> {
    match fs::create_dir(path) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o770)).map_err(|source| {
                CasError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_symlink_directory(path)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty() && *parent != path)
            else {
                return Err(CasError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            };
            create_directory(parent)?;
            create_directory(path)
        }
        Err(source) => Err(CasError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn reject_symlink_directory(path: &Path) -> Result<(), CasError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CasError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CasError::UnsafeObject {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn read_directory(path: &Path) -> Result<fs::ReadDir, CasError> {
    fs::read_dir(path).map_err(|source| CasError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn sync_directory(path: &Path) -> Result<(), CasError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CasError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn finalize_digest(hasher: Keccak256) -> B256 {
    B256::from_slice(&hasher.finalize())
}

fn digest_object_path(objects: &Path, digest: B256) -> PathBuf {
    let hex = hex::encode(digest.as_slice());
    objects.join(&hex[..2]).join(&hex[2..])
}
