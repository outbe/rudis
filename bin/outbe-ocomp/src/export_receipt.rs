//! Exporter-owned durable receipt for one published input manifest.
//!
//! Publishing input objects into CAS is not enough to make them eligible for
//! supervisor adoption. The RPC-driven exporter records an exact local
//! publication receipt after reconstructing and verifying the finalized input.
//! On restart it requires the same content-addressed receipt before reuse.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    input::{CheckpointIdentityV1, InputManifestV1},
    CasObjectRefV1, CommitSnapshotExportV1, ObjectKind, ProtocolError, SchemaLimits,
    SnapshotExportCommittedV1, SnapshotHandoffV1,
};
use thiserror::Error;

use crate::cas::{CasError, FilesystemCas, FilesystemCasReader};

const RECEIPT_MAGIC: [u8; 8] = *b"OUTBERC1";
const LOCATOR_MAGIC: [u8; 8] = *b"OUTBERL1";
const PREPARED_MAGIC: [u8; 8] = *b"OUTBEPD1";
const PREPARED_LOCATOR_MAGIC: [u8; 8] = *b"OUTBEPL1";
const CONFLICT_MAGIC: [u8; 8] = *b"OUTBERX1";
const FORMAT_VERSION: u16 = 1;
const DIRECTORY_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const LOCATOR_FILE: &str = "receipt.ref";
const LOCATOR_TEMP_FILE: &str = "receipt.ref.tmp";
const PREPARED_LOCATOR_FILE: &str = "prepared.ref";
const PREPARED_LOCATOR_TEMP_FILE: &str = "prepared.ref.tmp";
const CONFLICT_FILE: &str = "receipt.abstained";
const LOCK_FILE: &str = "receipt.lock";
const RECEIPT_JOB_OFFSET: usize = 10;
const RECEIPT_SOURCE_PIN_OFFSET: usize = 42;
const RECEIPT_LEASE_OFFSET: usize = 50;
const RECEIPT_CHECKPOINT_OFFSET: usize = 58;
const RECEIPT_MANIFEST_REF_OFFSET: usize = 164;
const RECEIPT_MANIFEST_HASH_OFFSET: usize = 206;
const RECEIPT_EXPORTED_PIN_OFFSET: usize = 238;
const RECEIPT_RECORD_HASH_OFFSET: usize = 246;
const RECEIPT_CHECKSUM_OFFSET: usize = 278;
const RECEIPT_FIXED_BYTES: usize = RECEIPT_CHECKSUM_OFFSET + 32;
const PREPARED_CHECKSUM_OFFSET: usize = RECEIPT_MANIFEST_HASH_OFFSET + 32;
const PREPARED_FIXED_BYTES: usize = PREPARED_CHECKSUM_OFFSET + 32;
const LOCATOR_FIXED_BYTES: usize = 8 + 2 + 32 + 8 + 32;
const CONFLICT_FIXED_BYTES: usize = 8 + 32 + 32 + 32;

pub struct ExportReceiptCandidate<'a> {
    pub handoff: &'a SnapshotHandoffV1,
    pub manifest_ref: &'a CasObjectRefV1,
    pub manifest_hash: B256,
    pub committed: &'a SnapshotExportCommittedV1,
}

pub struct ExportReceiptPreparation<'a> {
    pub handoff: &'a SnapshotHandoffV1,
    pub manifest_ref: &'a CasObjectRefV1,
    pub manifest_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportReceiptRecordOutcome {
    NewlyRecorded,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportReceiptV1 {
    job_id: B256,
    source_pin_generation: u64,
    lease_generation: u64,
    checkpoint: CheckpointIdentityV1,
    manifest_ref: CasObjectRefV1,
    manifest_hash: B256,
    exported_pin_generation: u64,
    export_record_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedExportV1 {
    job_id: B256,
    source_pin_generation: u64,
    lease_generation: u64,
    checkpoint: CheckpointIdentityV1,
    manifest_ref: CasObjectRefV1,
    manifest_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPreparedExport {
    prepared_ref: CasObjectRefV1,
    prepared: PreparedExportV1,
    manifest: InputManifestV1,
}

impl VerifiedPreparedExport {
    #[must_use]
    pub fn prepared_ref(&self) -> CasObjectRefV1 {
        self.prepared_ref.clone()
    }

    #[must_use]
    pub const fn job_id(&self) -> B256 {
        self.prepared.job_id
    }

    #[must_use]
    pub fn manifest_ref(&self) -> CasObjectRefV1 {
        self.prepared.manifest_ref.clone()
    }

    #[must_use]
    pub const fn manifest(&self) -> &InputManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub fn commit_request(&self) -> CommitSnapshotExportV1 {
        CommitSnapshotExportV1 {
            job_id: self.prepared.job_id,
            pin_generation: self.prepared.source_pin_generation,
            lease_generation: self.prepared.lease_generation,
            manifest_hash: self.prepared.manifest_hash,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExportReceipt {
    receipt_ref: CasObjectRefV1,
    receipt: ExportReceiptV1,
    manifest: InputManifestV1,
}

impl VerifiedExportReceipt {
    #[must_use]
    pub fn receipt_ref(&self) -> CasObjectRefV1 {
        self.receipt_ref.clone()
    }

    #[must_use]
    pub const fn job_id(&self) -> B256 {
        self.receipt.job_id
    }

    #[must_use]
    pub fn manifest_ref(&self) -> CasObjectRefV1 {
        self.receipt.manifest_ref.clone()
    }

    #[must_use]
    pub const fn manifest(&self) -> &InputManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub const fn source_pin_generation(&self) -> u64 {
        self.receipt.source_pin_generation
    }

    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.receipt.lease_generation
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &CheckpointIdentityV1 {
        &self.receipt.checkpoint
    }

    #[must_use]
    pub const fn manifest_hash(&self) -> B256 {
        self.receipt.manifest_hash
    }

    #[must_use]
    pub fn committed(&self) -> SnapshotExportCommittedV1 {
        SnapshotExportCommittedV1 {
            job_id: self.receipt.job_id,
            pin_generation: self.receipt.exported_pin_generation,
            record_hash: self.receipt.export_record_hash,
        }
    }

    #[must_use]
    pub fn commit_replay_request(&self) -> CommitSnapshotExportV1 {
        CommitSnapshotExportV1 {
            job_id: self.receipt.job_id,
            pin_generation: self.receipt.source_pin_generation,
            lease_generation: self.receipt.lease_generation,
            manifest_hash: self.receipt.manifest_hash,
        }
    }

    pub fn require_exact_node_replay(
        &self,
        replayed: &SnapshotExportCommittedV1,
    ) -> Result<(), ExportReceiptError> {
        require(replayed == &self.committed(), "node export commit replay")
    }
}

pub struct ExportReceiptStore {
    job_id: B256,
    root: PathBuf,
    limits: SchemaLimits,
    abstained: bool,
    _lock: ReceiptLock,
}

pub struct ExportReceiptReader {
    job_id: B256,
    root: PathBuf,
    limits: SchemaLimits,
}

impl ExportReceiptReader {
    pub fn try_open(
        base_root: impl AsRef<Path>,
        job_id: B256,
        limits: SchemaLimits,
    ) -> Result<Option<Self>, ExportReceiptError> {
        require(!job_id.is_zero(), "receipt reader job id")?;
        let base_root = base_root.as_ref();
        if !directory_exists(base_root)? {
            return Ok(None);
        }
        let root = base_root.join(hex::encode(job_id.as_slice()));
        if !directory_exists(&root)? {
            return Ok(None);
        }
        Self::open(base_root, job_id, limits).map(Some)
    }

    pub fn open(
        base_root: impl AsRef<Path>,
        job_id: B256,
        limits: SchemaLimits,
    ) -> Result<Self, ExportReceiptError> {
        require(!job_id.is_zero(), "receipt reader job id")?;
        inspect_private_directory(base_root.as_ref())?;
        let root = base_root.as_ref().join(hex::encode(job_id.as_slice()));
        inspect_private_directory(&root)?;
        reject_ambiguous_or_abstained(&root)?;
        inspect_known_entries(&root)?;
        Ok(Self {
            job_id,
            root,
            limits,
        })
    }

    pub fn load_exact(
        &self,
        reader: &FilesystemCasReader,
    ) -> Result<VerifiedExportReceipt, ExportReceiptError> {
        reject_ambiguous_or_abstained(&self.root)?;
        inspect_known_entries(&self.root)?;
        let prepared = load_prepared_at(&self.root, self.job_id, reader, &self.limits)?;
        let locator_path = self.root.join(LOCATOR_FILE);
        if !path_exists(&locator_path)? {
            return Err(ExportReceiptError::MissingReceipt);
        }
        let receipt_ref = decode_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
        let receipt_object = reader.read_verified(&receipt_ref)?;
        let receipt = decode_receipt(receipt_object.bytes())?;
        require(
            encode_receipt(&receipt) == receipt_object.bytes(),
            "canonical export receipt encoding",
        )?;
        require(receipt.job_id == self.job_id, "receipt reader job id")?;
        require(
            receipt_matches_prepared(&receipt, &prepared.prepared),
            "receipt prepared export",
        )?;
        let manifest = read_manifest(reader, &receipt.manifest_ref, &self.limits)?;
        validate_receipt_manifest(&receipt, &manifest, &self.limits)?;
        Ok(VerifiedExportReceipt {
            receipt_ref,
            receipt,
            manifest,
        })
    }
}

pub fn list_prepared_export_jobs(
    base_root: impl AsRef<Path>,
    max_jobs: usize,
) -> Result<Vec<B256>, ExportReceiptError> {
    if max_jobs == 0 {
        return Err(ExportReceiptError::InvalidJobLimit(max_jobs));
    }
    let base_root = base_root.as_ref();
    create_private_directory(base_root)?;
    let mut jobs = Vec::new();
    for entry in fs::read_dir(base_root)
        .map_err(|source| io_error("list receipt jobs", base_root, source))?
    {
        let entry = entry.map_err(|source| io_error("read receipt job", base_root, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect receipt job", &path, source))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(ExportReceiptError::InvalidJobDirectory(path));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExportReceiptError::InvalidJobDirectory(path.clone()))?;
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ExportReceiptError::InvalidJobDirectory(path));
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(&name, &mut bytes)
            .map_err(|_| ExportReceiptError::InvalidJobDirectory(path.clone()))?;
        let job_id = B256::from(bytes);
        require(!job_id.is_zero(), "prepared job id")?;
        if path_exists(&path.join(PREPARED_LOCATOR_FILE))?
            && !path_exists(&path.join(LOCATOR_FILE))?
        {
            jobs.push(job_id);
            if jobs.len() > max_jobs {
                return Err(ExportReceiptError::JobCapacityExceeded {
                    limit: max_jobs,
                    actual: jobs.len(),
                });
            }
        }
    }
    jobs.sort_unstable();
    Ok(jobs)
}

impl ExportReceiptStore {
    pub fn open(
        base_root: impl AsRef<Path>,
        job_id: B256,
        limits: SchemaLimits,
    ) -> Result<Self, ExportReceiptError> {
        require(!job_id.is_zero(), "receipt store job id")?;
        let base_root = base_root.as_ref();
        create_private_directory(base_root)?;
        let root = base_root.join(hex::encode(job_id.as_slice()));
        create_private_directory(&root)?;
        let lock = ReceiptLock::acquire(&root)?;
        if path_exists(&root.join(LOCATOR_TEMP_FILE))?
            || path_exists(&root.join(PREPARED_LOCATOR_TEMP_FILE))?
        {
            return Err(ExportReceiptError::AmbiguousTemporary(
                if path_exists(&root.join(PREPARED_LOCATOR_TEMP_FILE))? {
                    root.join(PREPARED_LOCATOR_TEMP_FILE)
                } else {
                    root.join(LOCATOR_TEMP_FILE)
                },
            ));
        }
        inspect_known_entries(&root)?;
        let abstained = path_exists(&root.join(CONFLICT_FILE))?;
        Ok(Self {
            job_id,
            root,
            limits,
            abstained,
            _lock: lock,
        })
    }

    pub fn record(
        &mut self,
        cas: &FilesystemCas,
        reader: &FilesystemCasReader,
        candidate: ExportReceiptCandidate<'_>,
    ) -> Result<(ExportReceiptRecordOutcome, VerifiedExportReceipt), ExportReceiptError> {
        let (_, prepared) = self.prepare(
            cas,
            reader,
            ExportReceiptPreparation {
                handoff: candidate.handoff,
                manifest_ref: candidate.manifest_ref,
                manifest_hash: candidate.manifest_hash,
            },
        )?;
        self.record_committed(cas, reader, &prepared, candidate.committed)
    }

    pub fn prepare(
        &mut self,
        cas: &FilesystemCas,
        reader: &FilesystemCasReader,
        preparation: ExportReceiptPreparation<'_>,
    ) -> Result<(ExportReceiptRecordOutcome, VerifiedPreparedExport), ExportReceiptError> {
        self.require_active()?;
        let prepared = derive_prepared(reader, &preparation, &self.limits)?;
        require(prepared.job_id == self.job_id, "receipt store job id")?;
        let canonical = encode_prepared(&prepared);
        let prepared_ref = cas.publish_bytes(&canonical)?;
        require(
            prepared_ref.expected_ocb1_kind.is_none(),
            "local prepared export CAS kind",
        )?;
        let published = reader.read_verified(&prepared_ref)?;
        require(
            published.bytes() == canonical,
            "exporter reads the exact prepared export",
        )?;

        let locator_path = self.root.join(PREPARED_LOCATOR_FILE);
        if path_exists(&locator_path)? {
            let existing_ref =
                decode_prepared_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
            if existing_ref != prepared_ref {
                self.latch_conflict(existing_ref.transport_digest, prepared_ref.transport_digest)?;
                return Err(ExportReceiptError::ConflictingReceipt);
            }
            let verified = self.load_prepared_exact(reader)?;
            require(
                verified.prepared == prepared,
                "exact prepared export replay",
            )?;
            return Ok((ExportReceiptRecordOutcome::ExactReplay, verified));
        }

        persist_atomic(
            &self.root,
            &self.root.join(PREPARED_LOCATOR_TEMP_FILE),
            &locator_path,
            &encode_prepared_locator(&prepared_ref)?,
        )?;
        Ok((
            ExportReceiptRecordOutcome::NewlyRecorded,
            self.load_prepared_exact(reader)?,
        ))
    }

    pub fn load_prepared_exact(
        &self,
        reader: &FilesystemCasReader,
    ) -> Result<VerifiedPreparedExport, ExportReceiptError> {
        self.require_active()?;
        load_prepared_at(&self.root, self.job_id, reader, &self.limits)
    }

    pub fn record_committed(
        &mut self,
        cas: &FilesystemCas,
        reader: &FilesystemCasReader,
        prepared: &VerifiedPreparedExport,
        committed: &SnapshotExportCommittedV1,
    ) -> Result<(ExportReceiptRecordOutcome, VerifiedExportReceipt), ExportReceiptError> {
        self.require_active()?;
        let durable_prepared = self.load_prepared_exact(reader)?;
        require(
            durable_prepared.prepared_ref == prepared.prepared_ref
                && durable_prepared.prepared == prepared.prepared,
            "durable prepared export",
        )?;
        let receipt = derive_receipt(&durable_prepared, committed)?;
        let canonical = encode_receipt(&receipt);
        let receipt_ref = cas.publish_bytes(&canonical)?;
        require(
            receipt_ref.expected_ocb1_kind.is_none(),
            "local export receipt CAS kind",
        )?;
        let published = reader.read_verified(&receipt_ref)?;
        require(
            published.bytes() == canonical,
            "exporter reads the exact published receipt",
        )?;

        let locator_path = self.root.join(LOCATOR_FILE);
        if path_exists(&locator_path)? {
            let existing_ref = decode_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
            if existing_ref != receipt_ref {
                self.latch_conflict(existing_ref.transport_digest, receipt_ref.transport_digest)?;
                return Err(ExportReceiptError::ConflictingReceipt);
            }
            let verified = self.load_exact(reader)?;
            require(verified.receipt == receipt, "exact export receipt replay")?;
            return Ok((ExportReceiptRecordOutcome::ExactReplay, verified));
        }

        persist_atomic(
            &self.root,
            &self.root.join(LOCATOR_TEMP_FILE),
            &locator_path,
            &encode_locator(&receipt_ref)?,
        )?;
        Ok((
            ExportReceiptRecordOutcome::NewlyRecorded,
            self.load_exact(reader)?,
        ))
    }

    pub fn load_exact(
        &self,
        reader: &FilesystemCasReader,
    ) -> Result<VerifiedExportReceipt, ExportReceiptError> {
        self.require_active()?;
        inspect_known_entries(&self.root)?;
        let locator_path = self.root.join(LOCATOR_FILE);
        if !path_exists(&locator_path)? {
            return Err(ExportReceiptError::MissingReceipt);
        }
        let receipt_ref = decode_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
        let receipt_object = reader.read_verified(&receipt_ref)?;
        let receipt = decode_receipt(receipt_object.bytes())?;
        require(
            encode_receipt(&receipt) == receipt_object.bytes(),
            "canonical export receipt encoding",
        )?;
        require(receipt.job_id == self.job_id, "receipt store job id")?;
        let prepared = self.load_prepared_exact(reader)?;
        require(
            receipt_matches_prepared(&receipt, &prepared.prepared),
            "receipt prepared export",
        )?;
        let manifest = read_manifest(reader, &receipt.manifest_ref, &self.limits)?;
        validate_receipt_manifest(&receipt, &manifest, &self.limits)?;
        Ok(VerifiedExportReceipt {
            receipt_ref,
            receipt,
            manifest,
        })
    }

    fn require_active(&self) -> Result<(), ExportReceiptError> {
        if self.abstained || path_exists(&self.root.join(CONFLICT_FILE))? {
            Err(ExportReceiptError::Abstained)
        } else {
            Ok(())
        }
    }

    fn latch_conflict(
        &mut self,
        existing: B256,
        candidate: B256,
    ) -> Result<(), ExportReceiptError> {
        let path = self.root.join(CONFLICT_FILE);
        if !path_exists(&path)? {
            let mut encoded = Vec::with_capacity(CONFLICT_FIXED_BYTES);
            encoded.extend_from_slice(&CONFLICT_MAGIC);
            encoded.extend_from_slice(existing.as_slice());
            encoded.extend_from_slice(candidate.as_slice());
            encoded.extend_from_slice(keccak256(&encoded).as_slice());
            persist_new(&self.root, &path, &encoded)?;
        }
        self.abstained = true;
        Ok(())
    }
}

fn derive_prepared(
    reader: &FilesystemCasReader,
    preparation: &ExportReceiptPreparation<'_>,
    limits: &SchemaLimits,
) -> Result<PreparedExportV1, ExportReceiptError> {
    let manifest = read_manifest(reader, preparation.manifest_ref, limits)?;
    let prepared = PreparedExportV1 {
        job_id: preparation.handoff.job_id,
        source_pin_generation: preparation.handoff.pin_generation,
        lease_generation: preparation.handoff.lease_generation,
        checkpoint: preparation.handoff.checkpoint.clone(),
        manifest_ref: preparation.manifest_ref.clone(),
        manifest_hash: preparation.manifest_hash,
    };
    require(
        prepared.source_pin_generation != 0 && prepared.lease_generation != 0,
        "snapshot generations",
    )?;
    validate_prepared_manifest(&prepared, &manifest, limits)?;
    Ok(prepared)
}

fn derive_receipt(
    prepared: &VerifiedPreparedExport,
    committed: &SnapshotExportCommittedV1,
) -> Result<ExportReceiptV1, ExportReceiptError> {
    require(
        committed.job_id == prepared.prepared.job_id,
        "publication receipt job id",
    )?;
    require(
        committed.pin_generation
            == prepared
                .prepared
                .source_pin_generation
                .checked_add(1)
                .ok_or(ExportReceiptError::IntegerOverflow)?,
        "exported pin generation",
    )?;
    require(
        !committed.record_hash.is_zero(),
        "publication receipt record hash",
    )?;
    Ok(ExportReceiptV1 {
        job_id: prepared.prepared.job_id,
        source_pin_generation: prepared.prepared.source_pin_generation,
        lease_generation: prepared.prepared.lease_generation,
        checkpoint: prepared.prepared.checkpoint.clone(),
        manifest_ref: prepared.prepared.manifest_ref.clone(),
        manifest_hash: prepared.prepared.manifest_hash,
        exported_pin_generation: committed.pin_generation,
        export_record_hash: committed.record_hash,
    })
}

fn load_prepared_at(
    root: &Path,
    job_id: B256,
    reader: &FilesystemCasReader,
    limits: &SchemaLimits,
) -> Result<VerifiedPreparedExport, ExportReceiptError> {
    inspect_known_entries(root)?;
    let locator_path = root.join(PREPARED_LOCATOR_FILE);
    if !path_exists(&locator_path)? {
        return Err(ExportReceiptError::MissingPreparation);
    }
    let prepared_ref = decode_prepared_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
    let prepared_object = reader.read_verified(&prepared_ref)?;
    let prepared = decode_prepared(prepared_object.bytes())?;
    require(
        encode_prepared(&prepared) == prepared_object.bytes(),
        "canonical prepared export encoding",
    )?;
    require(prepared.job_id == job_id, "prepared export job id")?;
    let manifest = read_manifest(reader, &prepared.manifest_ref, limits)?;
    validate_prepared_manifest(&prepared, &manifest, limits)?;
    Ok(VerifiedPreparedExport {
        prepared_ref,
        prepared,
        manifest,
    })
}

fn read_manifest(
    reader: &FilesystemCasReader,
    manifest_ref: &CasObjectRefV1,
    limits: &SchemaLimits,
) -> Result<InputManifestV1, ExportReceiptError> {
    require(
        manifest_ref.expected_ocb1_kind == Some(ObjectKind::InputManifestV1.tag()),
        "typed input manifest reference",
    )?;
    let manifest_object = reader.read_verified(manifest_ref)?;
    let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), limits)?;
    require(
        manifest.encode_canonical(limits)? == manifest_object.bytes(),
        "canonical input manifest encoding",
    )?;
    Ok(manifest)
}

fn validate_receipt_manifest(
    receipt: &ExportReceiptV1,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<(), ExportReceiptError> {
    require(receipt.job_id == manifest.job_id, "manifest job id")?;
    require(
        receipt.checkpoint == manifest.checkpoint,
        "manifest checkpoint",
    )?;
    require(
        receipt.manifest_hash == manifest.manifest_hash(limits)?,
        "manifest semantic hash",
    )
}

fn validate_prepared_manifest(
    prepared: &PreparedExportV1,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<(), ExportReceiptError> {
    require(prepared.job_id == manifest.job_id, "manifest job id")?;
    require(
        prepared.checkpoint == manifest.checkpoint,
        "manifest checkpoint",
    )?;
    require(
        prepared.manifest_hash == manifest.manifest_hash(limits)?,
        "manifest semantic hash",
    )
}

fn receipt_matches_prepared(receipt: &ExportReceiptV1, prepared: &PreparedExportV1) -> bool {
    receipt.job_id == prepared.job_id
        && receipt.source_pin_generation == prepared.source_pin_generation
        && receipt.lease_generation == prepared.lease_generation
        && receipt.checkpoint == prepared.checkpoint
        && receipt.manifest_ref == prepared.manifest_ref
        && receipt.manifest_hash == prepared.manifest_hash
}

fn encode_prepared(prepared: &PreparedExportV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PREPARED_FIXED_BYTES);
    encoded.extend_from_slice(&PREPARED_MAGIC);
    encoded.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(prepared.job_id.as_slice());
    encoded.extend_from_slice(&prepared.source_pin_generation.to_be_bytes());
    encoded.extend_from_slice(&prepared.lease_generation.to_be_bytes());
    encode_checkpoint(&mut encoded, &prepared.checkpoint);
    encoded.extend_from_slice(prepared.manifest_ref.transport_digest.as_slice());
    encoded.extend_from_slice(&prepared.manifest_ref.encoded_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &prepared
            .manifest_ref
            .expected_ocb1_kind
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(prepared.manifest_hash.as_slice());
    encoded.extend_from_slice(keccak256(&encoded).as_slice());
    encoded
}

fn decode_prepared(encoded: &[u8]) -> Result<PreparedExportV1, ExportReceiptError> {
    if encoded.len() != PREPARED_FIXED_BYTES
        || encoded[..8] != PREPARED_MAGIC
        || read_u16(encoded, 8)? != FORMAT_VERSION
        || keccak256(&encoded[..PREPARED_CHECKSUM_OFFSET])
            != B256::from_slice(&encoded[PREPARED_CHECKSUM_OFFSET..])
    {
        return Err(ExportReceiptError::InvalidEnvelope);
    }
    let expected_kind = read_u16(encoded, RECEIPT_MANIFEST_REF_OFFSET + 40)?;
    let prepared = PreparedExportV1 {
        job_id: read_b256(encoded, RECEIPT_JOB_OFFSET)?,
        source_pin_generation: read_u64(encoded, RECEIPT_SOURCE_PIN_OFFSET)?,
        lease_generation: read_u64(encoded, RECEIPT_LEASE_OFFSET)?,
        checkpoint: decode_checkpoint(encoded)?,
        manifest_ref: CasObjectRefV1 {
            transport_digest: read_b256(encoded, RECEIPT_MANIFEST_REF_OFFSET)?,
            encoded_bytes: read_u64(encoded, RECEIPT_MANIFEST_REF_OFFSET + 32)?,
            expected_ocb1_kind: Some(expected_kind),
        },
        manifest_hash: read_b256(encoded, RECEIPT_MANIFEST_HASH_OFFSET)?,
    };
    require(
        !prepared.job_id.is_zero()
            && prepared.source_pin_generation != 0
            && prepared.lease_generation != 0
            && !prepared.manifest_ref.transport_digest.is_zero()
            && prepared.manifest_ref.encoded_bytes != 0
            && expected_kind == ObjectKind::InputManifestV1.tag()
            && !prepared.manifest_hash.is_zero(),
        "prepared export non-zero fields",
    )?;
    Ok(prepared)
}

fn encode_receipt(receipt: &ExportReceiptV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(RECEIPT_FIXED_BYTES);
    encoded.extend_from_slice(&RECEIPT_MAGIC);
    encoded.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(receipt.job_id.as_slice());
    encoded.extend_from_slice(&receipt.source_pin_generation.to_be_bytes());
    encoded.extend_from_slice(&receipt.lease_generation.to_be_bytes());
    encode_checkpoint(&mut encoded, &receipt.checkpoint);
    encoded.extend_from_slice(receipt.manifest_ref.transport_digest.as_slice());
    encoded.extend_from_slice(&receipt.manifest_ref.encoded_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &receipt
            .manifest_ref
            .expected_ocb1_kind
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(receipt.manifest_hash.as_slice());
    encoded.extend_from_slice(&receipt.exported_pin_generation.to_be_bytes());
    encoded.extend_from_slice(receipt.export_record_hash.as_slice());
    encoded.extend_from_slice(keccak256(&encoded).as_slice());
    encoded
}

fn decode_receipt(encoded: &[u8]) -> Result<ExportReceiptV1, ExportReceiptError> {
    if encoded.len() != RECEIPT_FIXED_BYTES
        || encoded[..8] != RECEIPT_MAGIC
        || read_u16(encoded, 8)? != FORMAT_VERSION
        || keccak256(&encoded[..RECEIPT_CHECKSUM_OFFSET])
            != B256::from_slice(&encoded[RECEIPT_CHECKSUM_OFFSET..])
    {
        return Err(ExportReceiptError::InvalidEnvelope);
    }
    let expected_kind = read_u16(encoded, RECEIPT_MANIFEST_REF_OFFSET + 40)?;
    let receipt = ExportReceiptV1 {
        job_id: read_b256(encoded, RECEIPT_JOB_OFFSET)?,
        source_pin_generation: read_u64(encoded, RECEIPT_SOURCE_PIN_OFFSET)?,
        lease_generation: read_u64(encoded, RECEIPT_LEASE_OFFSET)?,
        checkpoint: decode_checkpoint(encoded)?,
        manifest_ref: CasObjectRefV1 {
            transport_digest: read_b256(encoded, RECEIPT_MANIFEST_REF_OFFSET)?,
            encoded_bytes: read_u64(encoded, RECEIPT_MANIFEST_REF_OFFSET + 32)?,
            expected_ocb1_kind: Some(expected_kind),
        },
        manifest_hash: read_b256(encoded, RECEIPT_MANIFEST_HASH_OFFSET)?,
        exported_pin_generation: read_u64(encoded, RECEIPT_EXPORTED_PIN_OFFSET)?,
        export_record_hash: read_b256(encoded, RECEIPT_RECORD_HASH_OFFSET)?,
    };
    require(
        !receipt.job_id.is_zero()
            && receipt.source_pin_generation != 0
            && receipt.lease_generation != 0
            && !receipt.manifest_ref.transport_digest.is_zero()
            && receipt.manifest_ref.encoded_bytes != 0
            && expected_kind == ObjectKind::InputManifestV1.tag()
            && !receipt.manifest_hash.is_zero()
            && receipt.exported_pin_generation != 0
            && !receipt.export_record_hash.is_zero(),
        "export receipt non-zero fields",
    )?;
    Ok(receipt)
}

fn encode_checkpoint(output: &mut Vec<u8>, checkpoint: &CheckpointIdentityV1) {
    output.extend_from_slice(&checkpoint.finalized_block_number.to_be_bytes());
    output.extend_from_slice(checkpoint.finalized_block_hash.as_slice());
    output.extend_from_slice(checkpoint.finalized_state_root.as_slice());
    output.extend_from_slice(checkpoint.finalized_ce_root.as_slice());
    output.extend_from_slice(&checkpoint.ce_schema_version.to_be_bytes());
}

fn decode_checkpoint(encoded: &[u8]) -> Result<CheckpointIdentityV1, ExportReceiptError> {
    Ok(CheckpointIdentityV1 {
        finalized_block_number: read_u64(encoded, RECEIPT_CHECKPOINT_OFFSET)?,
        finalized_block_hash: read_b256(encoded, RECEIPT_CHECKPOINT_OFFSET + 8)?,
        finalized_state_root: read_b256(encoded, RECEIPT_CHECKPOINT_OFFSET + 40)?,
        finalized_ce_root: read_b256(encoded, RECEIPT_CHECKPOINT_OFFSET + 72)?,
        ce_schema_version: read_u16(encoded, RECEIPT_CHECKPOINT_OFFSET + 104)?,
    })
}

fn encode_prepared_locator(reference: &CasObjectRefV1) -> Result<Vec<u8>, ExportReceiptError> {
    encode_locator_with_magic(reference, PREPARED_LOCATOR_MAGIC)
}

fn decode_prepared_locator(encoded: &[u8]) -> Result<CasObjectRefV1, ExportReceiptError> {
    decode_locator_with_magic(encoded, PREPARED_LOCATOR_MAGIC)
}

fn encode_locator(reference: &CasObjectRefV1) -> Result<Vec<u8>, ExportReceiptError> {
    encode_locator_with_magic(reference, LOCATOR_MAGIC)
}

fn encode_locator_with_magic(
    reference: &CasObjectRefV1,
    magic: [u8; 8],
) -> Result<Vec<u8>, ExportReceiptError> {
    require(
        reference.expected_ocb1_kind.is_none()
            && !reference.transport_digest.is_zero()
            && reference.encoded_bytes != 0,
        "export receipt locator reference",
    )?;
    let mut encoded = Vec::with_capacity(LOCATOR_FIXED_BYTES);
    encoded.extend_from_slice(&magic);
    encoded.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(reference.transport_digest.as_slice());
    encoded.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    encoded.extend_from_slice(keccak256(&encoded).as_slice());
    Ok(encoded)
}

fn decode_locator(encoded: &[u8]) -> Result<CasObjectRefV1, ExportReceiptError> {
    decode_locator_with_magic(encoded, LOCATOR_MAGIC)
}

fn decode_locator_with_magic(
    encoded: &[u8],
    magic: [u8; 8],
) -> Result<CasObjectRefV1, ExportReceiptError> {
    if encoded.len() != LOCATOR_FIXED_BYTES
        || encoded[..8] != magic
        || read_u16(encoded, 8)? != FORMAT_VERSION
        || keccak256(&encoded[..50]) != B256::from_slice(&encoded[50..])
    {
        return Err(ExportReceiptError::InvalidEnvelope);
    }
    let reference = CasObjectRefV1 {
        transport_digest: read_b256(encoded, 10)?,
        encoded_bytes: read_u64(encoded, 42)?,
        expected_ocb1_kind: None,
    };
    require(
        !reference.transport_digest.is_zero() && reference.encoded_bytes != 0,
        "export receipt locator",
    )?;
    Ok(reference)
}

fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, ExportReceiptError> {
    let mut file = open_regular_nofollow(path)?;
    let len = usize::try_from(
        file.metadata()
            .map_err(|source| io_error("stat file", path, source))?
            .len(),
    )
    .map_err(|_| ExportReceiptError::InvalidEnvelope)?;
    if len > cap {
        return Err(ExportReceiptError::InvalidEnvelope);
    }
    let mut encoded = Vec::with_capacity(len);
    file.read_to_end(&mut encoded)
        .map_err(|source| io_error("read file", path, source))?;
    if encoded.len() != len {
        return Err(ExportReceiptError::InvalidEnvelope);
    }
    Ok(encoded)
}

fn create_private_directory(path: &Path) -> Result<(), ExportReceiptError> {
    fs::create_dir_all(path).map_err(|source| io_error("create directory", path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ExportReceiptError::UnsafePath(path.to_path_buf()));
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|source| io_error("set directory permissions", path, source))
}

fn inspect_private_directory(path: &Path) -> Result<(), ExportReceiptError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ExportReceiptError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn directory_exists(path: &Path) -> Result<bool, ExportReceiptError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(ExportReceiptError::UnsafePath(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect directory", path, source)),
    }
}

fn reject_ambiguous_or_abstained(root: &Path) -> Result<(), ExportReceiptError> {
    for temp in [LOCATOR_TEMP_FILE, PREPARED_LOCATOR_TEMP_FILE] {
        let path = root.join(temp);
        if path_exists(&path)? {
            return Err(ExportReceiptError::AmbiguousTemporary(path));
        }
    }
    if path_exists(&root.join(CONFLICT_FILE))? {
        return Err(ExportReceiptError::Abstained);
    }
    Ok(())
}

fn inspect_known_entries(root: &Path) -> Result<(), ExportReceiptError> {
    for entry in fs::read_dir(root).map_err(|source| io_error("list directory", root, source))? {
        let entry = entry.map_err(|source| io_error("read directory", root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExportReceiptError::UnsafePath(entry.path()))?;
        if !matches!(
            name.as_str(),
            LOCATOR_FILE
                | LOCATOR_TEMP_FILE
                | PREPARED_LOCATOR_FILE
                | PREPARED_LOCATOR_TEMP_FILE
                | CONFLICT_FILE
                | LOCK_FILE
        ) {
            return Err(ExportReceiptError::UnexpectedEntry(entry.path()));
        }
        let metadata = entry
            .metadata()
            .map_err(|source| io_error("inspect entry", &entry.path(), source))?;
        if !metadata.file_type().is_file() {
            return Err(ExportReceiptError::UnsafePath(entry.path()));
        }
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, ExportReceiptError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(ExportReceiptError::UnsafePath(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("stat path", path, source)),
    }
}

fn open_regular_nofollow(path: &Path) -> Result<File, ExportReceiptError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open file", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect file", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ExportReceiptError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn persist_atomic(
    root: &Path,
    temp: &Path,
    final_path: &Path,
    encoded: &[u8],
) -> Result<(), ExportReceiptError> {
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temp)
            .map_err(|source| io_error("create temporary file", temp, source))?;
        file.write_all(encoded)
            .map_err(|source| io_error("write temporary file", temp, source))?;
        file.sync_all()
            .map_err(|source| io_error("fsync temporary file", temp, source))?;
        fs::rename(temp, final_path)
            .map_err(|source| io_error("publish file", final_path, source))?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn persist_new(root: &Path, path: &Path, encoded: &[u8]) -> Result<(), ExportReceiptError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("create file", path, source))?;
    file.write_all(encoded)
        .map_err(|source| io_error("write file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("fsync file", path, source))?;
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), ExportReceiptError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync directory", path, source))
}

fn read_u16(encoded: &[u8], start: usize) -> Result<u16, ExportReceiptError> {
    Ok(u16::from_be_bytes(
        encoded
            .get(start..start + 2)
            .ok_or(ExportReceiptError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| ExportReceiptError::InvalidEnvelope)?,
    ))
}

fn read_u64(encoded: &[u8], start: usize) -> Result<u64, ExportReceiptError> {
    Ok(u64::from_be_bytes(
        encoded
            .get(start..start + 8)
            .ok_or(ExportReceiptError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| ExportReceiptError::InvalidEnvelope)?,
    ))
}

fn read_b256(encoded: &[u8], start: usize) -> Result<B256, ExportReceiptError> {
    let bytes = encoded
        .get(start..start + 32)
        .ok_or(ExportReceiptError::InvalidEnvelope)?;
    Ok(B256::from_slice(bytes))
}

fn require(condition: bool, what: &'static str) -> Result<(), ExportReceiptError> {
    if condition {
        Ok(())
    } else {
        Err(ExportReceiptError::AuthorityMismatch(what))
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> ExportReceiptError {
    ExportReceiptError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct ReceiptLock {
    file: File,
}

impl ReceiptLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, ExportReceiptError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open receipt lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the duration of the call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(ExportReceiptError::LockHeld(path));
        }
        Ok(Self { file })
    }
}

impl Drop for ReceiptLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open until after this drop body.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug, Error)]
pub enum ExportReceiptError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error("export receipt authority mismatch: {0}")]
    AuthorityMismatch(&'static str),
    #[error("export receipt integer overflow")]
    IntegerOverflow,
    #[error("export receipt prepared-job scan limit must be positive, got {0}")]
    InvalidJobLimit(usize),
    #[error("export receipt prepared-job count exceeds cap: {actual} > {limit}")]
    JobCapacityExceeded { limit: usize, actual: usize },
    #[error("export receipt job directory is malformed or unsafe: {0}")]
    InvalidJobDirectory(PathBuf),
    #[error("export receipt is missing")]
    MissingReceipt,
    #[error("prepared export is missing")]
    MissingPreparation,
    #[error("a different export receipt was observed; this domain must abstain")]
    ConflictingReceipt,
    #[error("export receipt store is permanently abstained")]
    Abstained,
    #[error("export receipt envelope is malformed")]
    InvalidEnvelope,
    #[error("export receipt store contains an ambiguous temporary file at {0}")]
    AmbiguousTemporary(PathBuf),
    #[error("export receipt store contains an unexpected entry at {0}")]
    UnexpectedEntry(PathBuf),
    #[error("export receipt path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("export receipt store lock is already held at {0}")]
    LockHeld(PathBuf),
    #[error("export receipt I/O failed while trying to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
