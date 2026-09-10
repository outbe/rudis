//! Disk-backed authority for one finalized Tribute population.
//!
//! The input population may be arbitrarily larger than RAM. We therefore keep
//! only one bounded sort run in memory, merge runs with bounded fan-in, and
//! publish the immutable inventory header only after the CE root, exact count,
//! and nominal total have all closed.

use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    body_commitment, decode_tribute_v1, BoundedTributePartitionVerifier, Commitment,
    TributePartitionExpectationV1, TributePartitionRetentionStatsV1, TributePartitionWorkConfig,
    WwdEntityId, ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_ocomp_protocol::input::CheckpointIdentityV1;
use outbe_oracle::MAX_OCOMP_REFERENCE_ISOS;
use outbe_primitives::time::WorldwideDay;
use sha3::{Digest, Keccak256};
use thiserror::Error;

const DIRECTORY_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const HEADER_MAGIC: [u8; 8] = *b"OUTBTIH1";
const RUN_MAGIC: [u8; 8] = *b"OUTBTIR1";
const BODY_MAGIC: [u8; 8] = *b"OUTBTIB1";
const HEADER_FILE: &str = "inventory.header";
const OWNERS_FILE: &str = "owners.sorted";
const BODIES_FILE: &str = "tributes.spool";
const ISOS_FILE: &str = "reference-isos.bitmap";
const LOCK_FILE: &str = "inventory.lock";
const BUILD_DIRECTORY: &str = "building";
const OWNER_BYTES: usize = 20;
const ISO_BITMAP_BYTES: usize = 8_192;
const RUN_HEADER_BYTES: u64 = 16;
const BODY_HEADER_BYTES: u64 = 20;
// Work heartbeat cadence only; it does not cap the inventory population.
const INVENTORY_PROGRESS_RECORD_HEARTBEAT: u64 = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TributeInventorySubjectV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub checkpoint: CheckpointIdentityV1,
    pub worldwide_day: WorldwideDay,
    pub sealed_tribute_collection_root: B256,
    pub expected_tribute_count: u32,
    pub expected_nominal_total: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributeInventoryWorkConfig {
    pub owners_per_run: usize,
    pub merge_fan_in: usize,
    pub root_verifier: TributePartitionWorkConfig,
}

impl Default for TributeInventoryWorkConfig {
    fn default() -> Self {
        Self {
            owners_per_run: 4_096,
            merge_fan_in: 16,
            root_verifier: TributePartitionWorkConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TributeInventoryRecordV1 {
    pub tribute_id: WwdEntityId,
    pub commitment: Commitment,
    pub owner: Address,
    pub reference_iso: u16,
    pub nominal_amount_minor: U256,
    pub canonical_body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributeInventoryRetentionStatsV1 {
    pub current_owner_records: usize,
    pub peak_owner_records: usize,
    pub configured_owner_record_bound: usize,
    pub root_verifier: TributePartitionRetentionStatsV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryHeaderV1 {
    subject: TributeInventorySubjectV1,
    unique_owner_count: u64,
    owner_file_digest: B256,
    iso_bitmap_digest: B256,
    body_file_digest: B256,
    exact_body_bytes: u64,
}

pub struct TributeInventoryBuilder {
    root: PathBuf,
    build_root: PathBuf,
    subject: TributeInventorySubjectV1,
    work: TributeInventoryWorkConfig,
    root_verifier: Option<BoundedTributePartitionVerifier>,
    body_writer: Option<BodySpoolWriter>,
    owner_buffer: Vec<Address>,
    peak_owner_records: usize,
    run_count: u64,
    tribute_count: u32,
    nominal_total: U256,
    previous_tribute_id: Option<WwdEntityId>,
    iso_bitmap: Box<[u8; ISO_BITMAP_BYTES]>,
    _lock: InventoryLock,
}

pub struct SealedTributeInventory {
    root: PathBuf,
    header: InventoryHeaderV1,
    isos: Box<[u8; ISO_BITMAP_BYTES]>,
    _lock: InventoryLock,
}

pub struct OwnerBatchReader {
    file: File,
    remaining: u64,
    previous: Option<Address>,
}

pub struct TributeBodySpoolReader {
    file: File,
    remaining: u32,
    exact_body_bytes: u64,
    consumed_body_bytes: u64,
}

impl TributeInventoryBuilder {
    pub fn create(
        root: impl AsRef<Path>,
        subject: TributeInventorySubjectV1,
        work: TributeInventoryWorkConfig,
    ) -> Result<Self, TributeInventoryError> {
        if work.owners_per_run == 0 || work.merge_fan_in < 2 {
            return Err(TributeInventoryError::InvalidWorkConfig);
        }
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let lock = InventoryLock::acquire(&root)?;
        if path_exists(&root.join(HEADER_FILE))? {
            return Err(TributeInventoryError::AlreadySealed);
        }
        recover_unsealed_inventory(&root)?;
        let build_root = root.join(BUILD_DIRECTORY);
        remove_owned_build_directory(&build_root)?;
        fs::create_dir(&build_root)
            .map_err(|source| io_error("create inventory build directory", &build_root, source))?;
        fs::set_permissions(&build_root, fs::Permissions::from_mode(DIRECTORY_MODE))
            .map_err(|source| io_error("set inventory build permissions", &build_root, source))?;
        sync_directory(&root)?;
        let root_verifier = BoundedTributePartitionVerifier::create(
            build_root.join("root-verifier"),
            TributePartitionExpectationV1 {
                day: subject.worldwide_day,
                exact_leaf_count: subject.expected_tribute_count,
                expected_collection_root: subject.sealed_tribute_collection_root,
                commitment_scheme: ACTIVE_COMMITMENT_SCHEME,
            },
            work.root_verifier,
        )?;
        let mut iso_bitmap = Box::new([0_u8; ISO_BITMAP_BYTES]);
        set_iso(&mut iso_bitmap, 840);
        let body_writer = BodySpoolWriter::create(build_root.join(BODIES_FILE))?;
        Ok(Self {
            root,
            build_root,
            subject,
            work,
            root_verifier: Some(root_verifier),
            body_writer: Some(body_writer),
            owner_buffer: Vec::with_capacity(work.owners_per_run),
            peak_owner_records: 0,
            run_count: 0,
            tribute_count: 0,
            nominal_total: U256::ZERO,
            previous_tribute_id: None,
            iso_bitmap,
            _lock: lock,
        })
    }

    pub fn push(&mut self, record: TributeInventoryRecordV1) -> Result<(), TributeInventoryError> {
        if record.tribute_id.worldwide_day() != self.subject.worldwide_day {
            return Err(TributeInventoryError::Authority("Tribute worldwide day"));
        }
        if self
            .previous_tribute_id
            .is_some_and(|previous| previous >= record.tribute_id)
        {
            return Err(TributeInventoryError::Authority(
                "canonical Tribute stream order",
            ));
        }
        let decoded = decode_tribute_v1(&record.canonical_body)
            .map_err(|_| TributeInventoryError::Authority("canonical Tribute body"))?;
        if decoded.tribute_id != record.tribute_id
            || decoded.owner != record.owner
            || decoded.worldwide_day != self.subject.worldwide_day
            || decoded.reference_currency != record.reference_iso
            || decoded.nominal_amount_minor != record.nominal_amount_minor
        {
            return Err(TributeInventoryError::Authority(
                "canonical Tribute body fields",
            ));
        }
        let body_commitment = body_commitment(
            ACTIVE_COMMITMENT_SCHEME,
            BODY_SCHEMA_V1,
            record.tribute_id,
            &record.canonical_body,
        )
        .map_err(|_| TributeInventoryError::Authority("canonical Tribute body commitment"))?;
        if body_commitment != record.commitment {
            return Err(TributeInventoryError::Authority(
                "canonical Tribute body commitment",
            ));
        }
        self.root_verifier
            .as_mut()
            .expect("root verifier exists until inventory finish")
            .push(record.tribute_id, record.commitment)?;
        self.body_writer
            .as_mut()
            .expect("body writer exists until inventory finish")
            .write(&record.canonical_body)?;
        self.tribute_count = self
            .tribute_count
            .checked_add(1)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        self.nominal_total = self
            .nominal_total
            .checked_add(record.nominal_amount_minor)
            .ok_or(TributeInventoryError::NominalTotalOverflow)?;
        set_iso(&mut self.iso_bitmap, record.reference_iso);
        self.owner_buffer.push(record.owner);
        self.peak_owner_records = self.peak_owner_records.max(self.owner_buffer.len());
        self.previous_tribute_id = Some(record.tribute_id);
        if self.owner_buffer.len() == self.work.owners_per_run {
            self.flush_owner_run()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn retention_stats(&self) -> TributeInventoryRetentionStatsV1 {
        TributeInventoryRetentionStatsV1 {
            current_owner_records: self.owner_buffer.len(),
            peak_owner_records: self.peak_owner_records,
            configured_owner_record_bound: self.work.owners_per_run,
            root_verifier: self
                .root_verifier
                .as_ref()
                .expect("root verifier exists until inventory finish")
                .retention_stats(),
        }
    }

    pub fn finish(self) -> Result<SealedTributeInventory, TributeInventoryError> {
        self.finish_observing(|| {})
    }

    pub fn finish_observing(
        mut self,
        on_progress: impl Fn(),
    ) -> Result<SealedTributeInventory, TributeInventoryError> {
        if self.tribute_count != self.subject.expected_tribute_count {
            return Err(TributeInventoryError::CountMismatch {
                expected: self.subject.expected_tribute_count,
                actual: self.tribute_count,
            });
        }
        if self.nominal_total != self.subject.expected_nominal_total {
            return Err(TributeInventoryError::NominalTotalMismatch {
                expected: self.subject.expected_nominal_total,
                actual: self.nominal_total,
            });
        }
        let reference_iso_count = self
            .iso_bitmap
            .iter()
            .try_fold(0_usize, |total, byte| {
                total.checked_add(byte.count_ones() as usize)
            })
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        if reference_iso_count > MAX_OCOMP_REFERENCE_ISOS {
            return Err(TributeInventoryError::ReferenceIsoCountOutsideProtocol {
                limit: MAX_OCOMP_REFERENCE_ISOS,
                actual: reference_iso_count,
            });
        }
        self.root_verifier
            .take()
            .expect("root verifier exists until inventory finish")
            .finish_observing(&on_progress)?;
        let body_summary = self
            .body_writer
            .take()
            .expect("body writer exists until inventory finish")
            .finish()?;
        self.flush_owner_run()?;
        on_progress();
        let final_run = self.merge_owner_runs(&on_progress)?;
        let owners_tmp = self.root.join(format!("{OWNERS_FILE}.tmp"));
        let unique_owner_count =
            install_owner_file(final_run.as_deref(), &owners_tmp, &on_progress)?;
        let owner_file_digest = digest_file_observing(&owners_tmp, &on_progress)?;
        let bodies_tmp = self.root.join(format!("{BODIES_FILE}.tmp"));
        fs::rename(self.build_root.join(BODIES_FILE), &bodies_tmp)
            .map_err(|source| io_error("stage Tribute body spool", &bodies_tmp, source))?;
        let body_file_digest = digest_file_observing(&bodies_tmp, &on_progress)?;
        let isos_tmp = self.root.join(format!("{ISOS_FILE}.tmp"));
        persist_new(&isos_tmp, &self.iso_bitmap[..])?;
        let iso_bitmap_digest = B256::from_slice(&Keccak256::digest(&self.iso_bitmap[..]));
        fs::rename(&owners_tmp, self.root.join(OWNERS_FILE))
            .map_err(|source| io_error("install owner inventory", &owners_tmp, source))?;
        fs::rename(&isos_tmp, self.root.join(ISOS_FILE))
            .map_err(|source| io_error("install ISO inventory", &isos_tmp, source))?;
        fs::rename(&bodies_tmp, self.root.join(BODIES_FILE))
            .map_err(|source| io_error("install Tribute body spool", &bodies_tmp, source))?;
        sync_directory(&self.root)?;
        let header = InventoryHeaderV1 {
            subject: self.subject,
            unique_owner_count,
            owner_file_digest,
            iso_bitmap_digest,
            body_file_digest,
            exact_body_bytes: body_summary.exact_body_bytes,
        };
        persist_atomic(
            &self.root,
            &self.root.join(HEADER_FILE),
            &encode_header(&header),
        )?;
        remove_owned_build_directory(&self.build_root)?;
        sync_directory(&self.root)?;
        on_progress();
        Ok(SealedTributeInventory {
            root: self.root,
            header,
            isos: self.iso_bitmap,
            _lock: self._lock,
        })
    }

    fn flush_owner_run(&mut self) -> Result<(), TributeInventoryError> {
        if self.owner_buffer.is_empty() {
            return Ok(());
        }
        self.owner_buffer.sort_unstable();
        self.owner_buffer.dedup();
        let path = run_path(&self.build_root, 0, self.run_count);
        let mut writer = OwnerRunWriter::create(path)?;
        for owner in &self.owner_buffer {
            writer.write(*owner)?;
        }
        writer.finish()?;
        self.owner_buffer.clear();
        self.run_count = self
            .run_count
            .checked_add(1)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        Ok(())
    }

    fn merge_owner_runs(
        &self,
        on_progress: &impl Fn(),
    ) -> Result<Option<PathBuf>, TributeInventoryError> {
        if self.run_count == 0 {
            return Ok(None);
        }
        let fan_in = u64::try_from(self.work.merge_fan_in)
            .map_err(|_| TributeInventoryError::IntegerOverflow)?;
        let mut pass = 0_u32;
        let mut run_count = self.run_count;
        while run_count > 1 {
            let output_pass = pass
                .checked_add(1)
                .ok_or(TributeInventoryError::IntegerOverflow)?;
            let next_count = run_count
                .checked_add(fan_in - 1)
                .ok_or(TributeInventoryError::IntegerOverflow)?
                / fan_in;
            for output_index in 0..next_count {
                let start = output_index
                    .checked_mul(fan_in)
                    .ok_or(TributeInventoryError::IntegerOverflow)?;
                let end = start
                    .checked_add(fan_in)
                    .ok_or(TributeInventoryError::IntegerOverflow)?
                    .min(run_count);
                merge_run_group(
                    &self.build_root,
                    pass,
                    start,
                    end,
                    output_pass,
                    output_index,
                    on_progress,
                )?;
            }
            for index in 0..run_count {
                let path = run_path(&self.build_root, pass, index);
                fs::remove_file(&path)
                    .map_err(|source| io_error("remove merged owner run", &path, source))?;
            }
            sync_directory(&self.build_root)?;
            on_progress();
            pass = output_pass;
            run_count = next_count;
        }
        Ok(Some(run_path(&self.build_root, pass, 0)))
    }
}

impl SealedTributeInventory {
    pub fn open(
        root: impl AsRef<Path>,
        expected_subject: TributeInventorySubjectV1,
    ) -> Result<Self, TributeInventoryError> {
        Self::open_observing(root, expected_subject, || {})
    }

    pub fn open_observing(
        root: impl AsRef<Path>,
        expected_subject: TributeInventorySubjectV1,
        on_progress: impl Fn(),
    ) -> Result<Self, TributeInventoryError> {
        let root = root.as_ref().to_path_buf();
        inspect_private_directory(&root)?;
        let lock = InventoryLock::acquire(&root)?;
        let header = decode_header(&read_exact_file(&root.join(HEADER_FILE), header_len())?)?;
        if header.subject != expected_subject {
            return Err(TributeInventoryError::Authority("inventory subject"));
        }
        let owner_digest = digest_file_observing(&root.join(OWNERS_FILE), &on_progress)?;
        if owner_digest != header.owner_file_digest {
            return Err(TributeInventoryError::Corrupt("owner inventory digest"));
        }
        verify_owner_file(
            &root.join(OWNERS_FILE),
            header.unique_owner_count,
            &on_progress,
        )?;
        if digest_file_observing(&root.join(BODIES_FILE), &on_progress)? != header.body_file_digest
        {
            return Err(TributeInventoryError::Corrupt("Tribute body spool digest"));
        }
        verify_body_spool(
            &root.join(BODIES_FILE),
            expected_subject.expected_tribute_count,
            header.exact_body_bytes,
            &on_progress,
        )?;
        let iso_bytes = read_exact_file(&root.join(ISOS_FILE), ISO_BITMAP_BYTES)?;
        let mut isos = Box::new([0_u8; ISO_BITMAP_BYTES]);
        isos.copy_from_slice(&iso_bytes);
        if B256::from_slice(&Keccak256::digest(&isos[..])) != header.iso_bitmap_digest
            || !contains_iso(&isos, 840)
        {
            return Err(TributeInventoryError::Corrupt("reference ISO inventory"));
        }
        Ok(Self {
            root,
            header,
            isos,
            _lock: lock,
        })
    }

    #[must_use]
    pub const fn unique_owner_count(&self) -> u64 {
        self.header.unique_owner_count
    }

    #[must_use]
    pub fn authority_digest(&self) -> B256 {
        B256::from_slice(&Keccak256::digest(encode_header(&self.header)))
    }

    pub fn owner_batches(&self) -> Result<OwnerBatchReader, TributeInventoryError> {
        OwnerBatchReader::open(self.root.join(OWNERS_FILE), self.header.unique_owner_count)
    }

    pub fn reference_isos(&self) -> Vec<u16> {
        (u16::MIN..=u16::MAX)
            .filter(|iso| contains_iso(&self.isos, *iso))
            .collect()
    }

    pub fn tribute_bodies(&self) -> Result<TributeBodySpoolReader, TributeInventoryError> {
        TributeBodySpoolReader::open(
            self.root.join(BODIES_FILE),
            self.header.subject.expected_tribute_count,
            self.header.exact_body_bytes,
        )
    }
}

impl TributeBodySpoolReader {
    fn open(
        path: PathBuf,
        expected_count: u32,
        expected_body_bytes: u64,
    ) -> Result<Self, TributeInventoryError> {
        let mut file = open_regular_readonly(&path)?;
        let (remaining, exact_body_bytes) = read_body_header(&mut file, &path)?;
        if remaining != expected_count || exact_body_bytes != expected_body_bytes {
            return Err(TributeInventoryError::Corrupt("Tribute body spool header"));
        }
        Ok(Self {
            file,
            remaining,
            exact_body_bytes,
            consumed_body_bytes: 0,
        })
    }

    pub fn next_body(
        &mut self,
        max_body_bytes: usize,
    ) -> Result<Option<Vec<u8>>, TributeInventoryError> {
        if self.remaining == 0 {
            if self.consumed_body_bytes != self.exact_body_bytes {
                return Err(TributeInventoryError::Corrupt(
                    "Tribute body spool byte count",
                ));
            }
            return Ok(None);
        }
        let mut length = [0_u8; 4];
        self.file.read_exact(&mut length).map_err(|source| {
            io_error("read Tribute body length", Path::new(BODIES_FILE), source)
        })?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| TributeInventoryError::IntegerOverflow)?;
        if length == 0 || length > max_body_bytes {
            return Err(TributeInventoryError::BodyOutsideBound {
                limit: max_body_bytes,
                actual: length,
            });
        }
        let mut body = vec![0_u8; length];
        self.file
            .read_exact(&mut body)
            .map_err(|source| io_error("read Tribute body", Path::new(BODIES_FILE), source))?;
        self.remaining -= 1;
        self.consumed_body_bytes = self
            .consumed_body_bytes
            .checked_add(u64::try_from(length).map_err(|_| TributeInventoryError::IntegerOverflow)?)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        Ok(Some(body))
    }
}

impl OwnerBatchReader {
    fn open(path: PathBuf, expected_count: u64) -> Result<Self, TributeInventoryError> {
        let mut file = open_regular_readonly(&path)?;
        let count = read_run_header(&mut file, &path)?;
        if count != expected_count {
            return Err(TributeInventoryError::Corrupt("owner inventory count"));
        }
        Ok(Self {
            file,
            remaining: count,
            previous: None,
        })
    }

    pub fn next_batch(
        &mut self,
        max_owners: usize,
    ) -> Result<Option<Vec<Address>>, TributeInventoryError> {
        if max_owners == 0 {
            return Err(TributeInventoryError::InvalidWorkConfig);
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let take = usize::try_from(self.remaining.min(max_owners as u64))
            .map_err(|_| TributeInventoryError::IntegerOverflow)?;
        let mut owners = Vec::with_capacity(take);
        for _ in 0..take {
            let owner = read_owner(&mut self.file)?;
            if self.previous.is_some_and(|previous| previous >= owner) {
                return Err(TributeInventoryError::Corrupt("owner inventory order"));
            }
            self.previous = Some(owner);
            self.remaining -= 1;
            owners.push(owner);
        }
        Ok(Some(owners))
    }
}

struct BodySpoolWriter {
    path: PathBuf,
    file: File,
    count: u32,
    exact_body_bytes: u64,
}

struct BodySpoolSummary {
    exact_body_bytes: u64,
}

impl BodySpoolWriter {
    fn create(path: PathBuf) -> Result<Self, TributeInventoryError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)
            .map_err(|source| io_error("create Tribute body spool", &path, source))?;
        file.write_all(&BODY_MAGIC)
            .and_then(|()| file.write_all(&0_u32.to_be_bytes()))
            .and_then(|()| file.write_all(&0_u64.to_be_bytes()))
            .map_err(|source| io_error("write Tribute body spool header", &path, source))?;
        Ok(Self {
            path,
            file,
            count: 0,
            exact_body_bytes: 0,
        })
    }

    fn write(&mut self, body: &[u8]) -> Result<(), TributeInventoryError> {
        let length =
            u32::try_from(body.len()).map_err(|_| TributeInventoryError::BodyOutsideBound {
                limit: u32::MAX as usize,
                actual: body.len(),
            })?;
        if length == 0 {
            return Err(TributeInventoryError::BodyOutsideBound {
                limit: u32::MAX as usize,
                actual: 0,
            });
        }
        self.file
            .write_all(&length.to_be_bytes())
            .and_then(|()| self.file.write_all(body))
            .map_err(|source| io_error("write Tribute body spool", &self.path, source))?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        self.exact_body_bytes = self
            .exact_body_bytes
            .checked_add(u64::from(length))
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        Ok(())
    }

    fn finish(mut self) -> Result<BodySpoolSummary, TributeInventoryError> {
        self.file
            .seek(SeekFrom::Start(8))
            .and_then(|_| self.file.write_all(&self.count.to_be_bytes()))
            .and_then(|()| self.file.write_all(&self.exact_body_bytes.to_be_bytes()))
            .and_then(|()| self.file.sync_all())
            .map_err(|source| io_error("finish Tribute body spool", &self.path, source))?;
        Ok(BodySpoolSummary {
            exact_body_bytes: self.exact_body_bytes,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HeapOwner {
    owner: Address,
    reader_index: usize,
}

impl Ord for HeapOwner {
    fn cmp(&self, other: &Self) -> Ordering {
        self.owner
            .cmp(&other.owner)
            .then_with(|| self.reader_index.cmp(&other.reader_index))
    }
}

impl PartialOrd for HeapOwner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct OwnerRunReader {
    file: File,
    remaining: u64,
}

impl OwnerRunReader {
    fn open(path: PathBuf) -> Result<Self, TributeInventoryError> {
        let mut file = open_regular_readonly(&path)?;
        let remaining = read_run_header(&mut file, &path)?;
        Ok(Self { file, remaining })
    }

    fn next(&mut self) -> Result<Option<Address>, TributeInventoryError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        read_owner(&mut self.file).map(Some)
    }
}

struct OwnerRunWriter {
    path: PathBuf,
    file: File,
    count: u64,
}

impl OwnerRunWriter {
    fn create(path: PathBuf) -> Result<Self, TributeInventoryError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)
            .map_err(|source| io_error("create owner run", &path, source))?;
        file.write_all(&RUN_MAGIC)
            .and_then(|()| file.write_all(&0_u64.to_be_bytes()))
            .map_err(|source| io_error("write owner run header", &path, source))?;
        Ok(Self {
            path,
            file,
            count: 0,
        })
    }

    fn write(&mut self, owner: Address) -> Result<(), TributeInventoryError> {
        self.file
            .write_all(owner.as_slice())
            .map_err(|source| io_error("write owner run", &self.path, source))?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        Ok(())
    }

    fn finish(mut self) -> Result<u64, TributeInventoryError> {
        self.file
            .seek(SeekFrom::Start(8))
            .and_then(|_| self.file.write_all(&self.count.to_be_bytes()))
            .and_then(|()| self.file.sync_all())
            .map_err(|source| io_error("finish owner run", &self.path, source))?;
        Ok(self.count)
    }
}

fn merge_run_group(
    root: &Path,
    input_pass: u32,
    start: u64,
    end: u64,
    output_pass: u32,
    output_index: u64,
    on_progress: &impl Fn(),
) -> Result<(), TributeInventoryError> {
    let mut readers = Vec::with_capacity(
        usize::try_from(end - start).map_err(|_| TributeInventoryError::IntegerOverflow)?,
    );
    for index in start..end {
        readers.push(OwnerRunReader::open(run_path(root, input_pass, index))?);
    }
    let mut heap = BinaryHeap::new();
    for (reader_index, reader) in readers.iter_mut().enumerate() {
        if let Some(owner) = reader.next()? {
            heap.push(Reverse(HeapOwner {
                owner,
                reader_index,
            }));
        }
    }
    let mut writer = OwnerRunWriter::create(run_path(root, output_pass, output_index))?;
    let mut previous = None;
    let mut records_since_progress = 0_u64;
    while let Some(Reverse(item)) = heap.pop() {
        if previous != Some(item.owner) {
            writer.write(item.owner)?;
            previous = Some(item.owner);
        }
        if let Some(owner) = readers[item.reader_index].next()? {
            heap.push(Reverse(HeapOwner {
                owner,
                reader_index: item.reader_index,
            }));
        }
        records_since_progress = records_since_progress.saturating_add(1);
        if records_since_progress == INVENTORY_PROGRESS_RECORD_HEARTBEAT {
            on_progress();
            records_since_progress = 0;
        }
    }
    writer.finish()?;
    Ok(())
}

fn install_owner_file(
    final_run: Option<&Path>,
    destination: &Path,
    on_progress: &impl Fn(),
) -> Result<u64, TributeInventoryError> {
    if let Some(source) = final_run {
        let mut input = open_regular_readonly(source)?;
        let count = read_run_header(&mut input, source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(destination)
            .map_err(|source| io_error("create owner inventory", destination, source))?;
        output
            .write_all(&RUN_MAGIC)
            .and_then(|()| output.write_all(&count.to_be_bytes()))
            .map_err(|source| io_error("write owner inventory header", destination, source))?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|source| io_error("read owner inventory", destination, source))?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .map_err(|source| io_error("copy owner inventory", destination, source))?;
            on_progress();
        }
        output
            .sync_all()
            .map_err(|source| io_error("fsync owner inventory", destination, source))?;
        Ok(count)
    } else {
        OwnerRunWriter::create(destination.to_path_buf())?.finish()
    }
}

fn verify_owner_file(
    path: &Path,
    expected_count: u64,
    on_progress: &impl Fn(),
) -> Result<(), TributeInventoryError> {
    let mut reader = OwnerRunReader::open(path.to_path_buf())?;
    let mut count = 0_u64;
    let mut previous = None;
    let mut records_since_progress = 0_u64;
    while let Some(owner) = reader.next()? {
        if previous.is_some_and(|candidate| candidate >= owner) {
            return Err(TributeInventoryError::Corrupt("owner inventory order"));
        }
        previous = Some(owner);
        count = count
            .checked_add(1)
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        records_since_progress = records_since_progress.saturating_add(1);
        if records_since_progress == INVENTORY_PROGRESS_RECORD_HEARTBEAT {
            on_progress();
            records_since_progress = 0;
        }
    }
    if count != expected_count {
        return Err(TributeInventoryError::Corrupt("owner inventory count"));
    }
    Ok(())
}

fn encode_header(header: &InventoryHeaderV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(header_len());
    encoded.extend_from_slice(&HEADER_MAGIC);
    encoded.extend_from_slice(header.subject.protocol_bundle_hash.as_slice());
    encoded.extend_from_slice(header.subject.job_id.as_slice());
    encoded.extend_from_slice(&header.subject.attempt.to_be_bytes());
    encoded.extend_from_slice(
        &header
            .subject
            .checkpoint
            .finalized_block_number
            .to_be_bytes(),
    );
    encoded.extend_from_slice(header.subject.checkpoint.finalized_block_hash.as_slice());
    encoded.extend_from_slice(header.subject.checkpoint.finalized_state_root.as_slice());
    encoded.extend_from_slice(header.subject.checkpoint.finalized_ce_root.as_slice());
    encoded.extend_from_slice(&header.subject.checkpoint.ce_schema_version.to_be_bytes());
    encoded.extend_from_slice(&header.subject.worldwide_day.value().to_be_bytes());
    encoded.extend_from_slice(header.subject.sealed_tribute_collection_root.as_slice());
    encoded.extend_from_slice(&header.subject.expected_tribute_count.to_be_bytes());
    encoded.extend_from_slice(&header.subject.expected_nominal_total.to_be_bytes::<32>());
    encoded.extend_from_slice(&header.unique_owner_count.to_be_bytes());
    encoded.extend_from_slice(header.owner_file_digest.as_slice());
    encoded.extend_from_slice(header.iso_bitmap_digest.as_slice());
    encoded.extend_from_slice(header.body_file_digest.as_slice());
    encoded.extend_from_slice(&header.exact_body_bytes.to_be_bytes());
    encoded
}

fn decode_header(encoded: &[u8]) -> Result<InventoryHeaderV1, TributeInventoryError> {
    if encoded.len() != header_len() || encoded[..8] != HEADER_MAGIC {
        return Err(TributeInventoryError::Corrupt("inventory header"));
    }
    let mut offset = 8;
    let mut take = |count: usize| {
        let start = offset;
        offset += count;
        &encoded[start..offset]
    };
    let protocol_bundle_hash = B256::from_slice(take(32));
    let job_id = B256::from_slice(take(32));
    let attempt = u32::from_be_bytes(take(4).try_into().expect("fixed header slice"));
    let checkpoint = CheckpointIdentityV1 {
        finalized_block_number: u64::from_be_bytes(take(8).try_into().expect("fixed header slice")),
        finalized_block_hash: B256::from_slice(take(32)),
        finalized_state_root: B256::from_slice(take(32)),
        finalized_ce_root: B256::from_slice(take(32)),
        ce_schema_version: u16::from_be_bytes(take(2).try_into().expect("fixed header slice")),
    };
    let worldwide_day = WorldwideDay::new(u32::from_be_bytes(
        take(4).try_into().expect("fixed header slice"),
    ));
    let sealed_tribute_collection_root = B256::from_slice(take(32));
    let expected_tribute_count =
        u32::from_be_bytes(take(4).try_into().expect("fixed header slice"));
    let expected_nominal_total = U256::from_be_slice(take(32));
    let unique_owner_count = u64::from_be_bytes(take(8).try_into().expect("fixed header slice"));
    let owner_file_digest = B256::from_slice(take(32));
    let iso_bitmap_digest = B256::from_slice(take(32));
    let body_file_digest = B256::from_slice(take(32));
    let exact_body_bytes = u64::from_be_bytes(take(8).try_into().expect("fixed header slice"));
    let header = InventoryHeaderV1 {
        subject: TributeInventorySubjectV1 {
            protocol_bundle_hash,
            job_id,
            attempt,
            checkpoint,
            worldwide_day,
            sealed_tribute_collection_root,
            expected_tribute_count,
            expected_nominal_total,
        },
        unique_owner_count,
        owner_file_digest,
        iso_bitmap_digest,
        body_file_digest,
        exact_body_bytes,
    };
    if !header.subject.worldwide_day.is_valid() {
        return Err(TributeInventoryError::Corrupt("inventory worldwide day"));
    }
    Ok(header)
}

const fn header_len() -> usize {
    8 + 32 + 32 + 4 + 8 + 32 + 32 + 32 + 2 + 4 + 32 + 4 + 32 + 8 + 32 + 32 + 32 + 8
}

fn set_iso(bitmap: &mut [u8; ISO_BITMAP_BYTES], iso: u16) {
    let index = usize::from(iso);
    bitmap[index / 8] |= 1 << (index % 8);
}

fn contains_iso(bitmap: &[u8; ISO_BITMAP_BYTES], iso: u16) -> bool {
    let index = usize::from(iso);
    bitmap[index / 8] & (1 << (index % 8)) != 0
}

fn run_path(root: &Path, pass: u32, index: u64) -> PathBuf {
    root.join(format!("owners-{pass:010}-{index:020}.run"))
}

fn read_run_header(file: &mut File, path: &Path) -> Result<u64, TributeInventoryError> {
    let mut header = [0_u8; RUN_HEADER_BYTES as usize];
    file.read_exact(&mut header)
        .map_err(|source| io_error("read owner run header", path, source))?;
    if header[..8] != RUN_MAGIC {
        return Err(TributeInventoryError::Corrupt("owner run magic"));
    }
    let count = u64::from_be_bytes(header[8..].try_into().expect("fixed run header"));
    let expected_len = RUN_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(OWNER_BYTES as u64)
                .ok_or(TributeInventoryError::IntegerOverflow)?,
        )
        .ok_or(TributeInventoryError::IntegerOverflow)?;
    let actual_len = file
        .metadata()
        .map_err(|source| io_error("stat owner run", path, source))?
        .len();
    if actual_len != expected_len {
        return Err(TributeInventoryError::Corrupt("owner run length"));
    }
    Ok(count)
}

fn read_body_header(file: &mut File, path: &Path) -> Result<(u32, u64), TributeInventoryError> {
    let mut header = [0_u8; BODY_HEADER_BYTES as usize];
    file.read_exact(&mut header)
        .map_err(|source| io_error("read Tribute body spool header", path, source))?;
    if header[..8] != BODY_MAGIC {
        return Err(TributeInventoryError::Corrupt("Tribute body spool magic"));
    }
    let count = u32::from_be_bytes(header[8..12].try_into().expect("fixed body header"));
    let exact_body_bytes =
        u64::from_be_bytes(header[12..20].try_into().expect("fixed body header"));
    Ok((count, exact_body_bytes))
}

fn verify_body_spool(
    path: &Path,
    expected_count: u32,
    expected_body_bytes: u64,
    on_progress: &impl Fn(),
) -> Result<(), TributeInventoryError> {
    let mut file = open_regular_readonly(path)?;
    let (count, exact_body_bytes) = read_body_header(&mut file, path)?;
    if count != expected_count || exact_body_bytes != expected_body_bytes {
        return Err(TributeInventoryError::Corrupt("Tribute body spool header"));
    }
    let mut observed_body_bytes = 0_u64;
    for index in 0..count {
        let mut length = [0_u8; 4];
        file.read_exact(&mut length)
            .map_err(|source| io_error("read Tribute body length", path, source))?;
        let length = u32::from_be_bytes(length);
        if length == 0 {
            return Err(TributeInventoryError::Corrupt("empty Tribute body"));
        }
        observed_body_bytes = observed_body_bytes
            .checked_add(u64::from(length))
            .ok_or(TributeInventoryError::IntegerOverflow)?;
        file.seek(SeekFrom::Current(i64::from(length)))
            .map_err(|source| io_error("scan Tribute body spool", path, source))?;
        if u64::from(index + 1) % INVENTORY_PROGRESS_RECORD_HEARTBEAT == 0 {
            on_progress();
        }
    }
    let position = file
        .stream_position()
        .map_err(|source| io_error("close Tribute body spool", path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error("stat Tribute body spool", path, source))?
        .len();
    if observed_body_bytes != expected_body_bytes || position != length {
        return Err(TributeInventoryError::Corrupt("Tribute body spool closure"));
    }
    Ok(())
}

fn read_owner(file: &mut File) -> Result<Address, TributeInventoryError> {
    let mut bytes = [0_u8; OWNER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read owner inventory", Path::new(OWNERS_FILE), source))?;
    Ok(Address::from(bytes))
}

fn digest_file_observing(
    path: &Path,
    on_progress: &impl Fn(),
) -> Result<B256, TributeInventoryError> {
    let mut file = open_regular_readonly(path)?;
    let mut hasher = Keccak256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash inventory file", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        on_progress();
    }
    Ok(B256::from_slice(&hasher.finalize()))
}

fn create_private_directory(path: &Path) -> Result<(), TributeInventoryError> {
    reject_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(TributeInventoryError::UnsafePath(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|source| io_error("create inventory directory", path, source))?;
        }
        Err(source) => return Err(io_error("inspect inventory directory", path, source)),
    }
    reject_symlink_ancestors(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|source| io_error("set inventory directory permissions", path, source))
}

fn inspect_private_directory(path: &Path) -> Result<(), TributeInventoryError> {
    reject_symlink_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect inventory directory", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TributeInventoryError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), TributeInventoryError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TributeInventoryError::UnsafePath(ancestor.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect inventory ancestor", ancestor, source)),
        }
    }
    Ok(())
}

fn open_regular_readonly(path: &Path) -> Result<File, TributeInventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect inventory file", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TributeInventoryError::UnsafePath(path.to_path_buf()));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open inventory file", path, source))
}

fn read_exact_file(path: &Path, expected: usize) -> Result<Vec<u8>, TributeInventoryError> {
    let mut file = open_regular_readonly(path)?;
    let actual = usize::try_from(
        file.metadata()
            .map_err(|source| io_error("stat inventory file", path, source))?
            .len(),
    )
    .map_err(|_| TributeInventoryError::IntegerOverflow)?;
    if actual != expected {
        return Err(TributeInventoryError::Corrupt("inventory file length"));
    }
    let mut bytes = vec![0_u8; expected];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read inventory file", path, source))?;
    Ok(bytes)
}

fn persist_new(path: &Path, bytes: &[u8]) -> Result<(), TributeInventoryError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|source| io_error("create inventory file", path, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("persist inventory file", path, source))
}

fn persist_atomic(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), TributeInventoryError> {
    let temp = path.with_extension("tmp");
    if path_exists(&temp)? {
        let metadata = fs::symlink_metadata(&temp)
            .map_err(|source| io_error("inspect inventory temp", &temp, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(TributeInventoryError::UnsafePath(temp));
        }
        fs::remove_file(&temp)
            .map_err(|source| io_error("remove inventory temp", &temp, source))?;
    }
    persist_new(&temp, bytes)?;
    fs::rename(&temp, path).map_err(|source| io_error("install inventory file", path, source))?;
    sync_directory(root)
}

fn remove_owned_build_directory(path: &Path) -> Result<(), TributeInventoryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(TributeInventoryError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => {
            fs::remove_dir_all(path)
                .map_err(|source| io_error("remove incomplete inventory build", path, source))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect inventory build directory", path, source)),
    }
}

fn recover_unsealed_inventory(root: &Path) -> Result<(), TributeInventoryError> {
    let mut removed = false;
    for path in [
        root.join(OWNERS_FILE),
        root.join(ISOS_FILE),
        root.join(BODIES_FILE),
        root.join(format!("{OWNERS_FILE}.tmp")),
        root.join(format!("{ISOS_FILE}.tmp")),
        root.join(format!("{BODIES_FILE}.tmp")),
        root.join(HEADER_FILE).with_extension("tmp"),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(TributeInventoryError::UnsafePath(path));
            }
            Ok(_) => {
                fs::remove_file(&path).map_err(|source| {
                    io_error("remove incomplete inventory file", &path, source)
                })?;
                removed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("inspect incomplete inventory file", &path, source))
            }
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), TributeInventoryError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| io_error("fsync inventory directory", path, source))
}

fn path_exists(path: &Path) -> Result<bool, TributeInventoryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect inventory path", path, source)),
    }
}

struct InventoryLock {
    file: File,
}

impl InventoryLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, TributeInventoryError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open inventory lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the complete flock call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(TributeInventoryError::Locked);
        }
        Ok(Self { file })
    }
}

impl Drop for InventoryLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open for the complete flock call.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[derive(Debug, Error)]
pub enum TributeInventoryError {
    #[error("invalid Tribute inventory work configuration")]
    InvalidWorkConfig,
    #[error("Tribute inventory is already sealed")]
    AlreadySealed,
    #[error("Tribute inventory is locked by another writer")]
    Locked,
    #[error("unsafe Tribute inventory path: {0}")]
    UnsafePath(PathBuf),
    #[error("Tribute inventory authority mismatch: {0}")]
    Authority(&'static str),
    #[error("corrupt Tribute inventory: {0}")]
    Corrupt(&'static str),
    #[error("Tribute count mismatch: expected {expected}, got {actual}")]
    CountMismatch { expected: u32, actual: u32 },
    #[error("Tribute nominal total mismatch: expected {expected}, got {actual}")]
    NominalTotalMismatch { expected: U256, actual: U256 },
    #[error("Tribute inventory nominal total overflow")]
    NominalTotalOverflow,
    #[error("reference ISO count {actual} exceeds existing OCOMP protocol bound {limit}")]
    ReferenceIsoCountOutsideProtocol { limit: usize, actual: usize },
    #[error("canonical Tribute body has {actual} bytes outside per-body bound {limit}")]
    BodyOutsideBound { limit: usize, actual: usize },
    #[error("Tribute inventory integer overflow")]
    IntegerOverflow,
    #[error(transparent)]
    Partition(#[from] outbe_compressed_entities::TributePartitionReconstructionError),
    #[error("Tribute inventory I/O failed during {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> TributeInventoryError {
    TributeInventoryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

use std::os::unix::fs::PermissionsExt;
