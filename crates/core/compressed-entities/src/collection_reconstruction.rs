//! Bounded-RAM reconstruction of one sealed Tribute partition.

use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::{
    collection::{collection_root, partition_collection_key, CeDomain, CollectionError},
    schema::Collection,
    sharding::{aggregate_b256_shard_roots, shard_index},
    smt::{derive_tree_key, SortedPoseidonRootReducer, TreeKey, TreeLeaf},
    Commitment, PartitionRef, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
};

const EXPECTATION_MAGIC: [u8; 8] = *b"OUTBTPV1";
const RUN_MAGIC: [u8; 8] = *b"OUTBTRV1";
const RUN_HEADER_BYTES: u64 = 16;
const RUN_RECORD_BYTES: u64 = 68;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePartitionExpectationV1 {
    pub day: WorldwideDay,
    pub exact_leaf_count: u32,
    pub expected_collection_root: B256,
    pub commitment_scheme: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePartitionWorkConfig {
    pub records_per_run: usize,
    pub merge_fan_in: usize,
}

impl Default for TributePartitionWorkConfig {
    fn default() -> Self {
        Self {
            records_per_run: 4_096,
            merge_fan_in: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedTributePartition {
    pub collection_root: B256,
    pub exact_leaf_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePartitionRetentionStatsV1 {
    pub current_buffered_records: usize,
    pub peak_buffered_records: usize,
    pub configured_record_bound: usize,
}

pub struct BoundedTributePartitionVerifier {
    scratch_root: PathBuf,
    expectation: TributePartitionExpectationV1,
    work: TributePartitionWorkConfig,
    buffered: Vec<RunRecord>,
    peak_buffered_records: usize,
    pushed_count: u32,
    run_count: u64,
}

impl BoundedTributePartitionVerifier {
    pub fn create(
        scratch_root: impl AsRef<Path>,
        expectation: TributePartitionExpectationV1,
        work: TributePartitionWorkConfig,
    ) -> Result<Self, TributePartitionReconstructionError> {
        if !expectation.day.is_valid() {
            return Err(CollectionError::InvalidTributeWwd(expectation.day.value()).into());
        }
        if expectation.commitment_scheme != ACTIVE_COMMITMENT_SCHEME {
            return Err(
                TributePartitionReconstructionError::UnsupportedCommitmentScheme(
                    expectation.commitment_scheme,
                ),
            );
        }
        if work.records_per_run == 0 || work.merge_fan_in < 2 {
            return Err(TributePartitionReconstructionError::InvalidWorkConfig);
        }
        let scratch_root = scratch_root.as_ref().to_path_buf();
        fs::create_dir(&scratch_root)
            .map_err(|source| io_error("create scratch directory", &scratch_root, source))?;
        let header_path = scratch_root.join("expectation.header");
        let mut header = Vec::with_capacity(8 + 4 + 4 + 32 + 4 + 8 + 8);
        header.extend_from_slice(&EXPECTATION_MAGIC);
        header.extend_from_slice(&expectation.day.value().to_be_bytes());
        header.extend_from_slice(&expectation.exact_leaf_count.to_be_bytes());
        header.extend_from_slice(expectation.expected_collection_root.as_slice());
        header.extend_from_slice(&expectation.commitment_scheme.to_be_bytes());
        header.extend_from_slice(
            &u64::try_from(work.records_per_run)
                .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?
                .to_be_bytes(),
        );
        header.extend_from_slice(
            &u64::try_from(work.merge_fan_in)
                .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?
                .to_be_bytes(),
        );
        persist_new(&header_path, &header)?;
        sync_directory(&scratch_root)?;
        Ok(Self {
            scratch_root,
            expectation,
            work,
            buffered: Vec::with_capacity(work.records_per_run),
            peak_buffered_records: 0,
            pushed_count: 0,
            run_count: 0,
        })
    }

    pub fn push(
        &mut self,
        entity_id: WwdEntityId,
        commitment: Commitment,
    ) -> Result<(), TributePartitionReconstructionError> {
        if entity_id.worldwide_day() != self.expectation.day {
            return Err(CollectionError::TributeDayMismatch {
                expected: self.expectation.day.value(),
                actual: entity_id.worldwide_day().value(),
            }
            .into());
        }
        let actual = self
            .pushed_count
            .checked_add(1)
            .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
        if actual > self.expectation.exact_leaf_count {
            return Err(TributePartitionReconstructionError::CountMismatch {
                expected: self.expectation.exact_leaf_count,
                actual,
            });
        }
        let key = derive_tree_key(Collection::Tribute, entity_id)
            .map_err(|error| TributePartitionReconstructionError::Tree(error.to_string()))?;
        let shard = shard_index(key, CeDomain::Tribute.shard_count())
            .map_err(|error| TributePartitionReconstructionError::Tree(error.to_string()))?;
        let leaf = TreeLeaf::from_be_bytes(*commitment.as_bytes())
            .map_err(|error| TributePartitionReconstructionError::Tree(error.to_string()))?;
        self.buffered.push(RunRecord { shard, key, leaf });
        self.peak_buffered_records = self.peak_buffered_records.max(self.buffered.len());
        self.pushed_count = actual;
        if self.buffered.len() == self.work.records_per_run {
            self.flush_run()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn retention_stats(&self) -> TributePartitionRetentionStatsV1 {
        TributePartitionRetentionStatsV1 {
            current_buffered_records: self.buffered.len(),
            peak_buffered_records: self.peak_buffered_records,
            configured_record_bound: self.work.records_per_run,
        }
    }

    pub fn finish(self) -> Result<VerifiedTributePartition, TributePartitionReconstructionError> {
        self.finish_observing(|| {})
    }

    pub fn finish_observing(
        mut self,
        on_progress: impl Fn(),
    ) -> Result<VerifiedTributePartition, TributePartitionReconstructionError> {
        if self.pushed_count != self.expectation.exact_leaf_count {
            return Err(TributePartitionReconstructionError::CountMismatch {
                expected: self.expectation.exact_leaf_count,
                actual: self.pushed_count,
            });
        }
        self.flush_run()?;
        on_progress();
        let final_run = self.merge_runs(&on_progress)?;
        let root = self.reduce_sorted_run(final_run.as_deref(), &on_progress)?;
        if root != self.expectation.expected_collection_root {
            return Err(TributePartitionReconstructionError::RootMismatch {
                expected: self.expectation.expected_collection_root,
                actual: root,
            });
        }
        Ok(VerifiedTributePartition {
            collection_root: root,
            exact_leaf_count: self.pushed_count,
        })
    }

    fn flush_run(&mut self) -> Result<(), TributePartitionReconstructionError> {
        if self.buffered.is_empty() {
            return Ok(());
        }
        self.buffered.sort_unstable();
        if self
            .buffered
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key)
        {
            return Err(CollectionError::DuplicateTributeKey.into());
        }
        let path = run_path(&self.scratch_root, 0, self.run_count);
        let count = u64::try_from(self.buffered.len())
            .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?;
        let mut writer = RunWriter::create(path, count)?;
        for record in &self.buffered {
            writer.write(*record)?;
        }
        writer.finish()?;
        self.buffered.clear();
        self.run_count = self
            .run_count
            .checked_add(1)
            .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
        Ok(())
    }

    fn merge_runs(
        &self,
        on_progress: &impl Fn(),
    ) -> Result<Option<PathBuf>, TributePartitionReconstructionError> {
        if self.run_count == 0 {
            return Ok(None);
        }
        let fan_in = u64::try_from(self.work.merge_fan_in)
            .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?;
        let mut pass = 0_u32;
        let mut run_count = self.run_count;
        while run_count > 1 {
            let output_pass = pass
                .checked_add(1)
                .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
            let next_count = run_count
                .checked_add(fan_in - 1)
                .ok_or(TributePartitionReconstructionError::IntegerOverflow)?
                / fan_in;
            for output_index in 0..next_count {
                let start = output_index
                    .checked_mul(fan_in)
                    .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
                let end = start
                    .checked_add(fan_in)
                    .ok_or(TributePartitionReconstructionError::IntegerOverflow)?
                    .min(run_count);
                self.merge_run_group(pass, start, end, output_pass, output_index, on_progress)?;
            }
            for input_index in 0..run_count {
                let path = run_path(&self.scratch_root, pass, input_index);
                fs::remove_file(&path)
                    .map_err(|source| io_error("remove merged run", &path, source))?;
            }
            sync_directory(&self.scratch_root)?;
            on_progress();
            pass = output_pass;
            run_count = next_count;
        }
        Ok(Some(run_path(&self.scratch_root, pass, 0)))
    }

    fn merge_run_group(
        &self,
        input_pass: u32,
        start: u64,
        end: u64,
        output_pass: u32,
        output_index: u64,
        on_progress: &impl Fn(),
    ) -> Result<(), TributePartitionReconstructionError> {
        let reader_count = usize::try_from(end - start)
            .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?;
        let mut readers = Vec::with_capacity(reader_count);
        let mut output_count = 0_u64;
        for input_index in start..end {
            let reader = RunReader::open(run_path(&self.scratch_root, input_pass, input_index))?;
            output_count = output_count
                .checked_add(reader.record_count)
                .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
            readers.push(reader);
        }
        let output_path = run_path(&self.scratch_root, output_pass, output_index);
        let mut writer = RunWriter::create(output_path, output_count)?;
        let mut heap = BinaryHeap::new();
        for (reader_index, reader) in readers.iter_mut().enumerate() {
            if let Some(record) = reader.next_record()? {
                heap.push(HeapItem {
                    record,
                    reader_index,
                });
            }
        }
        while let Some(item) = heap.pop() {
            writer.write(item.record)?;
            on_progress();
            if let Some(record) = readers[item.reader_index].next_record()? {
                heap.push(HeapItem {
                    record,
                    reader_index: item.reader_index,
                });
            }
        }
        for reader in readers {
            reader.finish()?;
        }
        writer.finish()
    }

    fn reduce_sorted_run(
        &self,
        run: Option<&Path>,
        on_progress: &impl Fn(),
    ) -> Result<B256, TributePartitionReconstructionError> {
        let mut roots = vec![B256::ZERO; CeDomain::Tribute.shard_count() as usize];
        if let Some(path) = run {
            let mut reader = RunReader::open(path.to_path_buf())?;
            let mut current_shard = None;
            let mut reducer = SortedPoseidonRootReducer::new();
            while let Some(record) = reader.next_record()? {
                let derived_shard = shard_index(record.key, CeDomain::Tribute.shard_count())
                    .map_err(|error| {
                        TributePartitionReconstructionError::Tree(error.to_string())
                    })?;
                if record.shard != derived_shard {
                    return Err(TributePartitionReconstructionError::CorruptRun(
                        path.to_path_buf(),
                    ));
                }
                if current_shard.is_some_and(|shard| shard != record.shard) {
                    let shard = current_shard
                        .take()
                        .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
                    roots[usize::try_from(shard)
                        .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?] =
                        B256::from(reducer.finish().map_err(map_tree)?.as_bytes());
                    reducer = SortedPoseidonRootReducer::new();
                }
                current_shard = Some(record.shard);
                reducer.push(record.key, record.leaf).map_err(|error| {
                    if error == crate::smt::TreeError::DuplicateKey {
                        TributePartitionReconstructionError::Collection(
                            CollectionError::DuplicateTributeKey,
                        )
                    } else {
                        map_tree(error)
                    }
                })?;
                on_progress();
            }
            if let Some(shard) = current_shard {
                roots[usize::try_from(shard)
                    .map_err(|_| TributePartitionReconstructionError::IntegerOverflow)?] =
                    B256::from(reducer.finish().map_err(map_tree)?.as_bytes());
            }
            reader.finish()?;
        }
        let shard_top_root = aggregate_b256_shard_roots(&roots)
            .map_err(|error| TributePartitionReconstructionError::Tree(error.to_string()))?;
        let (_, key) = partition_collection_key(PartitionRef::TributeWwd(self.expectation.day))?;
        collection_root(CeDomain::Tribute, key, shard_top_root).map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunRecord {
    shard: u32,
    key: TreeKey,
    leaf: TreeLeaf,
}

impl Ord for RunRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.shard
            .cmp(&other.shard)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for RunRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeapItem {
    record: RunRecord,
    reader_index: usize,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .record
            .cmp(&self.record)
            .then_with(|| other.reader_index.cmp(&self.reader_index))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct RunWriter {
    path: PathBuf,
    file: File,
    expected_count: u64,
    written_count: u64,
}

impl RunWriter {
    fn create(
        path: PathBuf,
        expected_count: u64,
    ) -> Result<Self, TributePartitionReconstructionError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| io_error("create sort run", &path, source))?;
        file.write_all(&RUN_MAGIC)
            .and_then(|()| file.write_all(&expected_count.to_be_bytes()))
            .map_err(|source| io_error("write sort run header", &path, source))?;
        Ok(Self {
            path,
            file,
            expected_count,
            written_count: 0,
        })
    }

    fn write(&mut self, record: RunRecord) -> Result<(), TributePartitionReconstructionError> {
        self.file
            .write_all(&record.shard.to_be_bytes())
            .and_then(|()| self.file.write_all(&record.key.as_bytes()))
            .and_then(|()| self.file.write_all(&record.leaf.as_bytes()))
            .map_err(|source| io_error("write sort run", &self.path, source))?;
        self.written_count = self
            .written_count
            .checked_add(1)
            .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
        Ok(())
    }

    fn finish(self) -> Result<(), TributePartitionReconstructionError> {
        if self.written_count != self.expected_count {
            return Err(TributePartitionReconstructionError::CorruptRun(self.path));
        }
        self.file
            .sync_all()
            .map_err(|source| io_error("fsync sort run", &self.path, source))
    }
}

struct RunReader {
    path: PathBuf,
    file: File,
    record_count: u64,
    read_count: u64,
}

impl RunReader {
    fn open(path: PathBuf) -> Result<Self, TributePartitionReconstructionError> {
        let mut file =
            File::open(&path).map_err(|source| io_error("open sort run", &path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| io_error("inspect sort run", &path, source))?;
        if !metadata.file_type().is_file() {
            return Err(TributePartitionReconstructionError::CorruptRun(path));
        }
        let mut magic = [0_u8; 8];
        let mut count = [0_u8; 8];
        file.read_exact(&mut magic)
            .and_then(|()| file.read_exact(&mut count))
            .map_err(|source| io_error("read sort run header", &path, source))?;
        let record_count = u64::from_be_bytes(count);
        let expected_bytes = RUN_HEADER_BYTES
            .checked_add(
                record_count
                    .checked_mul(RUN_RECORD_BYTES)
                    .ok_or(TributePartitionReconstructionError::IntegerOverflow)?,
            )
            .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
        if magic != RUN_MAGIC || metadata.len() != expected_bytes {
            return Err(TributePartitionReconstructionError::CorruptRun(path));
        }
        Ok(Self {
            path,
            file,
            record_count,
            read_count: 0,
        })
    }

    fn next_record(&mut self) -> Result<Option<RunRecord>, TributePartitionReconstructionError> {
        if self.read_count == self.record_count {
            return Ok(None);
        }
        let mut shard = [0_u8; 4];
        let mut key = [0_u8; 32];
        let mut leaf = [0_u8; 32];
        self.file
            .read_exact(&mut shard)
            .and_then(|()| self.file.read_exact(&mut key))
            .and_then(|()| self.file.read_exact(&mut leaf))
            .map_err(|source| io_error("read sort run", &self.path, source))?;
        self.read_count = self
            .read_count
            .checked_add(1)
            .ok_or(TributePartitionReconstructionError::IntegerOverflow)?;
        Ok(Some(RunRecord {
            shard: u32::from_be_bytes(shard),
            key: TreeKey::from_be_bytes(key).map_err(map_tree)?,
            leaf: TreeLeaf::from_be_bytes(leaf).map_err(map_tree)?,
        }))
    }

    fn finish(self) -> Result<(), TributePartitionReconstructionError> {
        if self.read_count == self.record_count {
            Ok(())
        } else {
            Err(TributePartitionReconstructionError::CorruptRun(self.path))
        }
    }
}

#[derive(Debug, Error)]
pub enum TributePartitionReconstructionError {
    #[error(transparent)]
    Collection(#[from] CollectionError),
    #[error("unsupported Tribute commitment scheme {0}")]
    UnsupportedCommitmentScheme(u32),
    #[error("Tribute reconstruction work config is invalid")]
    InvalidWorkConfig,
    #[error("Tribute leaf count mismatch: expected {expected}, got {actual}")]
    CountMismatch { expected: u32, actual: u32 },
    #[error("Tribute collection root mismatch: expected {expected}, got {actual}")]
    RootMismatch { expected: B256, actual: B256 },
    #[error("Tribute partition tree reconstruction failed: {0}")]
    Tree(String),
    #[error("Tribute reconstruction integer overflow")]
    IntegerOverflow,
    #[error("corrupt Tribute reconstruction run at {0}")]
    CorruptRun(PathBuf),
    #[error("Tribute reconstruction I/O failed during {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn run_path(root: &Path, pass: u32, index: u64) -> PathBuf {
    root.join(format!("run-{pass:010}-{index:020}.bin"))
}

fn persist_new(path: &Path, bytes: &[u8]) -> Result<(), TributePartitionReconstructionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create scratch object", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write scratch object", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("fsync scratch object", path, source))
}

fn sync_directory(path: &Path) -> Result<(), TributePartitionReconstructionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync scratch directory", path, source))
}

fn map_tree(error: crate::smt::TreeError) -> TributePartitionReconstructionError {
    TributePartitionReconstructionError::Tree(error.to_string())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> TributePartitionReconstructionError {
    TributePartitionReconstructionError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;

    use super::*;
    use crate::{derive_poseidon_entity_id, schema::Collection};

    #[test]
    fn reconstruction_matches_the_eager_root_with_every_shard_populated() {
        let day = WorldwideDay::new(20_260_901);
        let mut selected = [None; 16];
        for value in 1_u64..20_000 {
            let mut owner = [0_u8; 20];
            owner[12..].copy_from_slice(&value.to_be_bytes());
            let entity_id = derive_poseidon_entity_id(Address::from(owner), day).unwrap();
            let key = derive_tree_key(Collection::Tribute, entity_id).unwrap();
            let shard = shard_index(key, CeDomain::Tribute.shard_count()).unwrap();
            let mut commitment = [0_u8; 32];
            commitment[24..].copy_from_slice(&(value + 1).to_be_bytes());
            selected[usize::try_from(shard).unwrap()]
                .get_or_insert((entity_id, Commitment::try_from(commitment).unwrap()));
            if selected.iter().all(Option::is_some) {
                break;
            }
        }
        let leaves = selected.into_iter().map(Option::unwrap).collect::<Vec<_>>();
        let expected =
            crate::collection::tribute_partition_root_from_leaves(day, leaves.iter().copied())
                .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = BoundedTributePartitionVerifier::create(
            directory.path().join("all-shards"),
            TributePartitionExpectationV1 {
                day,
                exact_leaf_count: 16,
                expected_collection_root: expected,
                commitment_scheme: ACTIVE_COMMITMENT_SCHEME,
            },
            TributePartitionWorkConfig {
                records_per_run: 3,
                merge_fan_in: 2,
            },
        )
        .unwrap();
        for (entity_id, commitment) in leaves.into_iter().rev() {
            verifier.push(entity_id, commitment).unwrap();
        }
        assert_eq!(verifier.finish().unwrap().collection_root, expected);
    }
}
