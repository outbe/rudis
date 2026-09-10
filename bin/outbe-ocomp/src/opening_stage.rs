//! Durable left-first acquisition of finalized Fidelity and Oracle openings.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    input::{
        AuthenticatedOpeningV1, CheckpointIdentityV1, MaterializedOpeningsV1, OpeningSourceKind,
    },
    opening::{OpeningSubjectsV1, MAX_FIDELITY_OWNERS_PER_OPENING},
    SchemaLimits,
};
use thiserror::Error;

use crate::{
    input_artifacts::{decode_fidelity_subject_key, decode_oracle_subject_key, InputArtifactError},
    input_inventory::{SealedTributeInventory, TributeInventoryError},
};

const DIRECTORY_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const SUBJECT_MAGIC: [u8; 8] = *b"OUTBOSJ1";
const OPENING_MAGIC: [u8; 8] = *b"OUTBOPN1";
const ORACLE_MAGIC: [u8; 8] = *b"OUTBOOR1";
const CONFLICT_MAGIC: [u8; 8] = *b"OUTBOCF1";
const SPLIT_MAGIC: [u8; 8] = *b"OUTBOSP1";
const DONE_MAGIC: [u8; 8] = *b"OUTBODN1";
const COMPLETE_MAGIC: [u8; 8] = *b"OUTBOCP1";
const SUBJECT_FILE: &str = "opening-stage.subject";
const ORACLE_FILE: &str = "oracle.opening";
const CONFLICT_FILE: &str = "oracle.conflict";
const COMPLETE_FILE: &str = "opening-stage.complete";
const TASKS_DIRECTORY: &str = "tasks";
const OPENINGS_DIRECTORY: &str = "openings";
const LOCK_FILE: &str = "opening-stage.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningStageSubjectV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub checkpoint: CheckpointIdentityV1,
    pub worldwide_day: u32,
    pub inventory_authority_digest: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpeningResolutionV1 {
    Complete(Box<MaterializedOpeningsV1>),
    Split,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningStageReportV1 {
    pub fidelity_opening_count: u32,
    pub oracle: AuthenticatedOpeningV1,
}

pub struct DurableOpeningStage {
    root: PathBuf,
    tasks: PathBuf,
    openings: PathBuf,
    subject: OpeningStageSubjectV1,
    limits: SchemaLimits,
    _lock: OpeningStageLock,
}

pub struct FidelityOpeningCursor {
    root: PathBuf,
    limits: SchemaLimits,
    next: u32,
    count: u32,
}

impl DurableOpeningStage {
    pub fn open_or_resume(
        root: impl AsRef<Path>,
        subject: OpeningStageSubjectV1,
        limits: SchemaLimits,
    ) -> Result<Self, OpeningStageError> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let lock = OpeningStageLock::acquire(&root)?;
        recover_regular_temps(&root)?;
        let subject_path = root.join(SUBJECT_FILE);
        let encoded_subject = encode_subject(&subject);
        persist_exact(&root, &subject_path, &encoded_subject)?;
        let tasks = root.join(TASKS_DIRECTORY);
        let openings = root.join(OPENINGS_DIRECTORY);
        create_private_directory(&tasks)?;
        create_private_directory(&openings)?;
        recover_regular_temps(&tasks)?;
        recover_regular_temps(&openings)?;
        Ok(Self {
            root,
            tasks,
            openings,
            subject,
            limits,
            _lock: lock,
        })
    }

    pub fn run(
        &mut self,
        inventory: &SealedTributeInventory,
        mut resolve: impl FnMut(&OpeningSubjectsV1) -> Result<OpeningResolutionV1, OpeningStageError>,
        mut verify: impl FnMut(
            &OpeningSubjectsV1,
            &AuthenticatedOpeningV1,
            &AuthenticatedOpeningV1,
        ) -> Result<(), OpeningStageError>,
        mut publish_fidelity: impl FnMut(AuthenticatedOpeningV1) -> Result<(), OpeningStageError>,
    ) -> Result<OpeningStageReportV1, OpeningStageError> {
        self.require_no_oracle_conflict()?;
        if inventory.authority_digest() != self.subject.inventory_authority_digest {
            return Err(OpeningStageError::Authority("Tribute inventory"));
        }
        let reference_isos = inventory.reference_isos();
        let mut owners = inventory.owner_batches()?;
        let mut start = 0_u64;
        let mut completed = 0_u32;
        while let Some(batch) = owners.next_batch(MAX_FIDELITY_OWNERS_PER_OPENING)? {
            self.process_task(
                start,
                batch,
                &reference_isos,
                &mut completed,
                &mut resolve,
                &mut verify,
                &mut publish_fidelity,
            )?;
            start = start
                .checked_add(MAX_FIDELITY_OWNERS_PER_OPENING as u64)
                .ok_or(OpeningStageError::IntegerOverflow)?;
        }
        if completed == 0 {
            return Err(OpeningStageError::Authority("empty Fidelity owner set"));
        }
        let oracle = self
            .read_oracle()?
            .ok_or(OpeningStageError::MissingOracle)?;
        persist_exact(
            &self.root,
            &self.root.join(COMPLETE_FILE),
            &encode_count(COMPLETE_MAGIC, completed),
        )?;
        Ok(OpeningStageReportV1 {
            fidelity_opening_count: completed,
            oracle,
        })
    }

    pub fn fidelity_cursor(&self, count: u32) -> FidelityOpeningCursor {
        FidelityOpeningCursor {
            root: self.openings.clone(),
            limits: self.limits,
            next: 0,
            count,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_task(
        &self,
        start: u64,
        owners: Vec<alloy_primitives::Address>,
        reference_isos: &[u16],
        completed: &mut u32,
        resolve: &mut impl FnMut(&OpeningSubjectsV1) -> Result<OpeningResolutionV1, OpeningStageError>,
        verify: &mut impl FnMut(
            &OpeningSubjectsV1,
            &AuthenticatedOpeningV1,
            &AuthenticatedOpeningV1,
        ) -> Result<(), OpeningStageError>,
        publish_fidelity: &mut impl FnMut(AuthenticatedOpeningV1) -> Result<(), OpeningStageError>,
    ) -> Result<(), OpeningStageError> {
        let count = u32::try_from(owners.len()).map_err(|_| OpeningStageError::IntegerOverflow)?;
        if count == 0 {
            return Err(OpeningStageError::Authority("empty opening task"));
        }
        let subjects = OpeningSubjectsV1 {
            owners: owners.clone(),
            reference_isos: reference_isos.to_vec(),
        };
        let done_path = self.task_path(start, count, "done");
        let split_path = self.task_path(start, count, "split");
        let done_exists = path_exists(&done_path)?;
        let split_exists = path_exists(&split_path)?;
        if done_exists && split_exists {
            return Err(OpeningStageError::Authority(
                "contradictory opening task markers",
            ));
        }
        if done_exists {
            let ordinal = decode_count(
                &read_bounded(&done_path, envelope_cap(&self.limits))?,
                DONE_MAGIC,
            )?;
            if ordinal != *completed {
                return Err(OpeningStageError::Authority("opening task ordinal"));
            }
            let opening = self.read_fidelity(ordinal)?;
            verify_fidelity_subject(&opening, &owners)?;
            let oracle = self
                .read_oracle()?
                .ok_or(OpeningStageError::MissingOracle)?;
            verify_oracle_subject(&oracle, self.subject.worldwide_day, reference_isos)?;
            verify(&subjects, &opening, &oracle)?;
            publish_fidelity(opening)?;
            *completed = completed
                .checked_add(1)
                .ok_or(OpeningStageError::IntegerOverflow)?;
            return Ok(());
        }
        if split_exists {
            let encoded = read_bounded(&split_path, envelope_cap(&self.limits))?;
            if encoded != encode_count(SPLIT_MAGIC, count) {
                return Err(OpeningStageError::Authority("opening split marker"));
            }
            return self.process_split(
                start,
                owners,
                reference_isos,
                completed,
                resolve,
                verify,
                publish_fidelity,
            );
        }
        let ordinal = *completed;
        let opening_path = self.opening_path(ordinal);
        if path_exists(&opening_path)? {
            let opening = self.read_fidelity(ordinal)?;
            verify_fidelity_subject(&opening, &owners)?;
            let oracle = self
                .read_oracle()?
                .ok_or(OpeningStageError::MissingOracle)?;
            verify_oracle_subject(&oracle, self.subject.worldwide_day, reference_isos)?;
            verify(&subjects, &opening, &oracle)?;
            publish_fidelity(opening)?;
            persist_exact(&self.tasks, &done_path, &encode_count(DONE_MAGIC, ordinal))?;
            *completed = completed
                .checked_add(1)
                .ok_or(OpeningStageError::IntegerOverflow)?;
            return Ok(());
        }
        match resolve(&subjects)? {
            OpeningResolutionV1::Split => {
                if owners.len() == 1 {
                    return Err(OpeningStageError::SingletonCapacity);
                }
                persist_exact(&self.tasks, &split_path, &encode_count(SPLIT_MAGIC, count))?;
                self.process_split(
                    start,
                    owners,
                    reference_isos,
                    completed,
                    resolve,
                    verify,
                    publish_fidelity,
                )
            }
            OpeningResolutionV1::Complete(openings) => {
                let MaterializedOpeningsV1 { fidelity, oracle } = *openings;
                verify_fidelity_subject(&fidelity, &owners)?;
                verify_oracle_subject(&oracle, self.subject.worldwide_day, reference_isos)?;
                verify(&subjects, &fidelity, &oracle)?;
                self.persist_or_verify_oracle(&oracle)?;
                persist_exact(
                    &self.openings,
                    &opening_path,
                    &encode_opening(OPENING_MAGIC, &fidelity, &self.limits)?,
                )?;
                publish_fidelity(fidelity)?;
                persist_exact(&self.tasks, &done_path, &encode_count(DONE_MAGIC, ordinal))?;
                *completed = completed
                    .checked_add(1)
                    .ok_or(OpeningStageError::IntegerOverflow)?;
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_split(
        &self,
        start: u64,
        mut owners: Vec<alloy_primitives::Address>,
        reference_isos: &[u16],
        completed: &mut u32,
        resolve: &mut impl FnMut(&OpeningSubjectsV1) -> Result<OpeningResolutionV1, OpeningStageError>,
        verify: &mut impl FnMut(
            &OpeningSubjectsV1,
            &AuthenticatedOpeningV1,
            &AuthenticatedOpeningV1,
        ) -> Result<(), OpeningStageError>,
        publish_fidelity: &mut impl FnMut(AuthenticatedOpeningV1) -> Result<(), OpeningStageError>,
    ) -> Result<(), OpeningStageError> {
        let midpoint = owners.len() / 2;
        if midpoint == 0 {
            return Err(OpeningStageError::SingletonCapacity);
        }
        let right = owners.split_off(midpoint);
        let right_start = start
            .checked_add(u64::try_from(midpoint).map_err(|_| OpeningStageError::IntegerOverflow)?)
            .ok_or(OpeningStageError::IntegerOverflow)?;
        self.process_task(
            start,
            owners,
            reference_isos,
            completed,
            resolve,
            verify,
            publish_fidelity,
        )?;
        self.process_task(
            right_start,
            right,
            reference_isos,
            completed,
            resolve,
            verify,
            publish_fidelity,
        )
    }

    fn persist_or_verify_oracle(
        &self,
        oracle: &AuthenticatedOpeningV1,
    ) -> Result<(), OpeningStageError> {
        let oracle_path = self.root.join(ORACLE_FILE);
        let candidate = encode_opening(ORACLE_MAGIC, oracle, &self.limits)?;
        if !path_exists(&oracle_path)? {
            return persist_exact(&self.root, &oracle_path, &candidate);
        }
        let existing = read_bounded(&oracle_path, envelope_cap(&self.limits))?;
        decode_opening(&existing, ORACLE_MAGIC, &self.limits)?;
        if existing == candidate {
            return Ok(());
        }
        let mut conflict = Vec::with_capacity(64);
        conflict.extend_from_slice(keccak256(&existing).as_slice());
        conflict.extend_from_slice(keccak256(&candidate).as_slice());
        persist_exact(
            &self.root,
            &self.root.join(CONFLICT_FILE),
            &encode_envelope(CONFLICT_MAGIC, &conflict),
        )?;
        Err(OpeningStageError::Abstained)
    }

    fn require_no_oracle_conflict(&self) -> Result<(), OpeningStageError> {
        let path = self.root.join(CONFLICT_FILE);
        if !path_exists(&path)? {
            return Ok(());
        }
        let encoded = read_bounded(&path, 104)?;
        if decode_envelope(&encoded, CONFLICT_MAGIC)?.len() != 64 {
            return Err(OpeningStageError::InvalidEnvelope);
        }
        Err(OpeningStageError::Abstained)
    }

    fn read_oracle(&self) -> Result<Option<AuthenticatedOpeningV1>, OpeningStageError> {
        let path = self.root.join(ORACLE_FILE);
        if !path_exists(&path)? {
            return Ok(None);
        }
        decode_opening(
            &read_bounded(&path, envelope_cap(&self.limits))?,
            ORACLE_MAGIC,
            &self.limits,
        )
        .map(Some)
    }

    fn read_fidelity(&self, ordinal: u32) -> Result<AuthenticatedOpeningV1, OpeningStageError> {
        let path = self.opening_path(ordinal);
        decode_opening(
            &read_bounded(&path, envelope_cap(&self.limits))?,
            OPENING_MAGIC,
            &self.limits,
        )
    }

    fn task_path(&self, start: u64, count: u32, suffix: &str) -> PathBuf {
        self.tasks.join(format!("{start:020}-{count:010}.{suffix}"))
    }

    fn opening_path(&self, ordinal: u32) -> PathBuf {
        self.openings.join(format!("{ordinal:010}.opening"))
    }
}

impl FidelityOpeningCursor {
    pub fn next_opening(&mut self) -> Result<Option<AuthenticatedOpeningV1>, OpeningStageError> {
        if self.next == self.count {
            return Ok(None);
        }
        let path = self.root.join(format!("{:010}.opening", self.next));
        let opening = decode_opening(
            &read_bounded(&path, envelope_cap(&self.limits))?,
            OPENING_MAGIC,
            &self.limits,
        )?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(OpeningStageError::IntegerOverflow)?;
        Ok(Some(opening))
    }
}

fn verify_fidelity_subject(
    opening: &AuthenticatedOpeningV1,
    owners: &[alloy_primitives::Address],
) -> Result<(), OpeningStageError> {
    if opening.source_kind != OpeningSourceKind::Fidelity
        || decode_fidelity_subject_key(&opening.canonical_subject_key.0)? != owners
    {
        return Err(OpeningStageError::Authority("Fidelity opening subject"));
    }
    Ok(())
}

fn verify_oracle_subject(
    opening: &AuthenticatedOpeningV1,
    worldwide_day: u32,
    reference_isos: &[u16],
) -> Result<(), OpeningStageError> {
    let (actual_day, actual_isos) = decode_oracle_subject_key(&opening.canonical_subject_key.0)?;
    if opening.source_kind != OpeningSourceKind::Oracle
        || actual_day != worldwide_day
        || actual_isos != reference_isos
    {
        return Err(OpeningStageError::Authority("Oracle opening subject"));
    }
    Ok(())
}

fn encode_subject(subject: &OpeningStageSubjectV1) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 * 7 + 26);
    body.extend_from_slice(subject.protocol_bundle_hash.as_slice());
    body.extend_from_slice(subject.job_id.as_slice());
    body.extend_from_slice(&subject.attempt.to_be_bytes());
    body.extend_from_slice(&subject.checkpoint.finalized_block_number.to_be_bytes());
    body.extend_from_slice(subject.checkpoint.finalized_block_hash.as_slice());
    body.extend_from_slice(subject.checkpoint.finalized_state_root.as_slice());
    body.extend_from_slice(subject.checkpoint.finalized_ce_root.as_slice());
    body.extend_from_slice(&subject.checkpoint.ce_schema_version.to_be_bytes());
    body.extend_from_slice(&subject.worldwide_day.to_be_bytes());
    body.extend_from_slice(subject.inventory_authority_digest.as_slice());
    encode_envelope(SUBJECT_MAGIC, &body)
}

fn encode_opening(
    magic: [u8; 8],
    opening: &AuthenticatedOpeningV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, OpeningStageError> {
    Ok(encode_envelope(
        magic,
        &opening.encode_canonical_record(limits)?,
    ))
}

fn decode_opening(
    encoded: &[u8],
    magic: [u8; 8],
    limits: &SchemaLimits,
) -> Result<AuthenticatedOpeningV1, OpeningStageError> {
    let body = decode_envelope(encoded, magic)?;
    let opening = AuthenticatedOpeningV1::decode_canonical_record(body, limits)?;
    if encode_opening(magic, &opening, limits)? != encoded {
        return Err(OpeningStageError::InvalidEnvelope);
    }
    Ok(opening)
}

fn encode_count(magic: [u8; 8], count: u32) -> Vec<u8> {
    encode_envelope(magic, &count.to_be_bytes())
}

fn decode_count(encoded: &[u8], magic: [u8; 8]) -> Result<u32, OpeningStageError> {
    let body = decode_envelope(encoded, magic)?;
    if body.len() != 4 {
        return Err(OpeningStageError::InvalidEnvelope);
    }
    Ok(u32::from_be_bytes(
        body.try_into()
            .map_err(|_| OpeningStageError::InvalidEnvelope)?,
    ))
}

fn encode_envelope(magic: [u8; 8], body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(40 + body.len());
    encoded.extend_from_slice(&magic);
    encoded.extend_from_slice(keccak256(body).as_slice());
    encoded.extend_from_slice(body);
    encoded
}

fn decode_envelope(encoded: &[u8], magic: [u8; 8]) -> Result<&[u8], OpeningStageError> {
    if encoded.len() < 40 || encoded[..8] != magic {
        return Err(OpeningStageError::InvalidEnvelope);
    }
    let expected = B256::from_slice(&encoded[8..40]);
    let body = &encoded[40..];
    if keccak256(body) != expected {
        return Err(OpeningStageError::InvalidEnvelope);
    }
    Ok(body)
}

fn envelope_cap(limits: &SchemaLimits) -> usize {
    limits.codec.max_body_bytes.saturating_add(40)
}

fn persist_exact(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), OpeningStageError> {
    if path_exists(path)? {
        if read_bounded(path, bytes.len())? == bytes {
            return Ok(());
        }
        return Err(OpeningStageError::Authority("durable opening replay"));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(OpeningStageError::InvalidEnvelope)?;
    let temp = root.join(format!("{file_name}.tmp"));
    if path_exists(&temp)? {
        return Err(OpeningStageError::AmbiguousTemporary(temp));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|source| io_error("create opening stage object", &temp, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("persist opening stage object", &temp, source))?;
    fs::rename(&temp, path)
        .map_err(|source| io_error("install opening stage object", path, source))?;
    sync_directory(root)
}

fn recover_regular_temps(root: &Path) -> Result<(), OpeningStageError> {
    let mut removed = false;
    for entry in
        fs::read_dir(root).map_err(|source| io_error("list opening stage", root, source))?
    {
        let entry = entry.map_err(|source| io_error("read opening stage", root, source))?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".tmp"))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect opening temp", &path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(OpeningStageError::AmbiguousTemporary(path));
        }
        fs::remove_file(&path).map_err(|source| io_error("remove opening temp", &path, source))?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), OpeningStageError> {
    reject_symlink_ancestors(path)?;
    fs::create_dir_all(path)
        .map_err(|source| io_error("create opening directory", path, source))?;
    reject_symlink_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect opening directory", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OpeningStageError::UnsafePath(path.to_path_buf()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|source| io_error("set opening directory permissions", path, source))
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), OpeningStageError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(OpeningStageError::UnsafePath(ancestor.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect opening ancestor", ancestor, source)),
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, OpeningStageError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect opening object", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OpeningStageError::UnsafePath(path.to_path_buf()));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| OpeningStageError::IntegerOverflow)?;
    if length > max_bytes {
        return Err(OpeningStageError::ObjectTooLarge);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open opening object", path, source))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read opening object", path, source))?;
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), OpeningStageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync opening directory", path, source))
}

fn path_exists(path: &Path) -> Result<bool, OpeningStageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect opening path", path, source)),
    }
}

struct OpeningStageLock {
    file: File,
}

impl OpeningStageLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, OpeningStageError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open opening lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the complete flock call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(OpeningStageError::Locked);
        }
        Ok(Self { file })
    }
}

impl Drop for OpeningStageLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open for the complete flock call.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug, Error)]
pub enum OpeningStageError {
    #[error("opening stage authority mismatch: {0}")]
    Authority(&'static str),
    #[error("opening capacity failed for one owner")]
    SingletonCapacity,
    #[error("opening stage Oracle authority is missing")]
    MissingOracle,
    #[error("opening stage permanently abstained after an Oracle authority conflict")]
    Abstained,
    #[error("opening stage is locked")]
    Locked,
    #[error("unsafe opening stage path: {0}")]
    UnsafePath(PathBuf),
    #[error("ambiguous opening stage temporary file: {0}")]
    AmbiguousTemporary(PathBuf),
    #[error("opening stage object exceeds its bound")]
    ObjectTooLarge,
    #[error("opening stage object has an invalid envelope")]
    InvalidEnvelope,
    #[error("opening stage integer overflow")]
    IntegerOverflow,
    #[error(transparent)]
    Protocol(#[from] outbe_ocomp_protocol::ProtocolError),
    #[error(transparent)]
    Inventory(#[from] TributeInventoryError),
    #[error(transparent)]
    Artifact(#[from] InputArtifactError),
    #[error("opening stage I/O failed during {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("opening resolver failed: {0}")]
    Resolver(String),
    #[error("durable opening verification failed: {0}")]
    Verification(String),
    #[error("Fidelity publication failed: {0}")]
    Publication(String),
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> OpeningStageError {
    OpeningStageError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
