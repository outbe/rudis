use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use alloy_primitives::{keccak256, B256};
use criterion::{black_box, BenchmarkId, Criterion};
use outbe_compressed_entities::{
    bench_support::{aggregate_shard_roots, candidate_checksum, derived_shard, field_word},
    CandidateCacheLimits, CeMdbx, Commitment, CompressedTreeService, EntityRef,
    EnvironmentIdentity, ExactParentIdentity, FinalLeafMutation, FinalizedMarker, WwdEntityId,
    ACTIVE_COMMITMENT_SCHEME, K_CANDIDATES, LOCAL_STORAGE_SCHEMA_VERSION,
};
use tempfile::TempDir;

const VENDOR_REVISION: &str = "ad555350c866b2265d87d2d7fbd146fbc918bfe5";
const DATASET_SHARD_COUNT: u32 = 32;

#[derive(Clone, Copy)]
enum Distribution {
    Uniform,
    Concentrated,
}

impl Distribution {
    const fn label(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Concentrated => "concentrated",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "uniform" => Some(Self::Uniform),
            "concentrated" => Some(Self::Concentrated),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Insert,
    Update,
    Delete,
    Mixed,
}

impl Operation {
    const fn label(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Mixed => "mixed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "insert" => Some(Self::Insert),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "mixed" => Some(Self::Mixed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Shape {
    label: &'static str,
    existing: usize,
    touched: usize,
}

const SHAPES: [Shape; 2] = [
    Shape {
        label: "small",
        existing: 256,
        touched: 32,
    },
    Shape {
        label: "large",
        existing: 4_096,
        touched: 256,
    },
];

fn shape(value: &str) -> Option<Shape> {
    SHAPES.into_iter().find(|shape| shape.label == value)
}

struct Fixture {
    directory: TempDir,
    service: CompressedTreeService,
    parent: ExactParentIdentity,
    block_hash: B256,
    mutations: Vec<FinalLeafMutation>,
    dataset_checksum: B256,
    descriptor: String,
    mdbx_bytes_before: u64,
    mdbx_allocated_bytes_before: u64,
}

struct ManifestRecord {
    descriptor: String,
    dataset_checksum: B256,
    expected_root: B256,
    batch_checksum: B256,
    staged_bytes: usize,
    changed_shards: usize,
    branch_records: usize,
    leaf_records: usize,
    mdbx_bytes_before: u64,
    mdbx_bytes_after: u64,
    mdbx_allocated_bytes_before: u64,
    mdbx_allocated_bytes_after: u64,
}

struct Workload {
    seed_mutations: Vec<FinalLeafMutation>,
    mutations: Vec<FinalLeafMutation>,
    dataset_checksum: B256,
}

static MANIFEST: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();

fn entity(counter: u64) -> EntityRef {
    let mut bytes = [0_u8; WwdEntityId::len_bytes()];
    bytes[..4].copy_from_slice(&(counter as u32).to_be_bytes());
    bytes[28..].copy_from_slice(&counter.to_be_bytes());
    let identity = WwdEntityId::try_from(bytes.as_slice()).expect("fixed benchmark identity");
    match counter % 3 {
        0 => EntityRef::Tribute(identity),
        1 => EntityRef::NodItem(identity),
        _ => EntityRef::NodBucket(identity),
    }
}

fn commitment(counter: u64) -> Commitment {
    Commitment::try_from(field_word(counter.max(1))).expect("canonical benchmark commitment")
}

fn selected_entities(count: usize, distribution: Distribution, start: u64) -> Vec<EntityRef> {
    let mut selected = Vec::with_capacity(count);
    let mut per_shard = vec![0_usize; DATASET_SHARD_COUNT as usize];
    let target_per_shard = count.div_ceil(DATASET_SHARD_COUNT as usize);
    let concentrated_shard = 0;
    let mut counter = start;
    while selected.len() < count {
        let candidate = entity(counter);
        counter = counter.wrapping_add(1);
        let shard =
            derived_shard(candidate, DATASET_SHARD_COUNT).expect("production key derivation");
        let accept = match distribution {
            Distribution::Uniform => {
                let slot = &mut per_shard[shard as usize];
                if *slot >= target_per_shard {
                    false
                } else {
                    *slot += 1;
                    true
                }
            }
            Distribution::Concentrated => shard == concentrated_shard,
        };
        if accept {
            selected.push(candidate);
        }
    }
    selected
}

fn dataset_checksum(entities: impl IntoIterator<Item = EntityRef>) -> B256 {
    let mut bytes = Vec::new();
    for entity in entities {
        bytes.push(match entity {
            EntityRef::Tribute(_) => 1,
            EntityRef::NodItem(_) => 2,
            EntityRef::NodBucket(_) => 3,
        });
        bytes.extend_from_slice(entity.entity_id().as_slice());
    }
    keccak256(bytes)
}

fn environment(_shard_count: u32, genesis_hash: B256) -> EnvironmentIdentity {
    EnvironmentIdentity {
        local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
        chain_id: 9_009,
        genesis_hash,
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        topology: outbe_compressed_entities::CeTopologyV1.encode(),
        tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
        vendor_revision: VENDOR_REVISION.to_owned(),
    }
}

fn workload(shape: Shape, distribution: Distribution, operation: Operation) -> Workload {
    let existing = selected_entities(shape.existing, distribution, 1);
    let seed_mutations = existing
        .iter()
        .copied()
        .enumerate()
        .map(|(index, entity)| FinalLeafMutation {
            entity,
            final_leaf: Some(commitment(10_000 + index as u64)),
        })
        .collect::<Vec<_>>();
    let touched_existing = existing
        .iter()
        .copied()
        .take(shape.touched)
        .collect::<Vec<_>>();
    let inserted = selected_entities(shape.touched, distribution, 1_000_000);
    let mutations =
        match operation {
            Operation::Insert => inserted
                .iter()
                .copied()
                .enumerate()
                .map(|(index, entity)| FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment(20_000 + index as u64)),
                })
                .collect(),
            Operation::Update => touched_existing
                .iter()
                .copied()
                .enumerate()
                .map(|(index, entity)| FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment(30_000 + index as u64)),
                })
                .collect(),
            Operation::Delete => touched_existing
                .iter()
                .copied()
                .map(|entity| FinalLeafMutation {
                    entity,
                    final_leaf: None,
                })
                .collect(),
            Operation::Mixed => {
                let quarter = shape.touched / 4;
                let mut output = Vec::with_capacity(shape.touched);
                output.extend(touched_existing[..quarter].iter().copied().enumerate().map(
                    |(index, entity)| FinalLeafMutation {
                        entity,
                        final_leaf: Some(commitment(40_000 + index as u64)),
                    },
                ));
                output.extend(touched_existing[quarter..quarter * 2].iter().copied().map(
                    |entity| FinalLeafMutation {
                        entity,
                        final_leaf: None,
                    },
                ));
                output.extend(
                    inserted[..shape.touched / 2]
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(index, entity)| FinalLeafMutation {
                            entity,
                            final_leaf: Some(commitment(50_000 + index as u64)),
                        }),
                );
                output
            }
        };
    let checksum = dataset_checksum(
        existing
            .iter()
            .copied()
            .chain(mutations.iter().map(|mutation| mutation.entity)),
    );
    Workload {
        seed_mutations,
        mutations,
        dataset_checksum: checksum,
    }
}

fn build_fixture(
    shard_count: u32,
    shape: Shape,
    distribution: Distribution,
    operation: Operation,
) -> Fixture {
    let workload = workload(shape, distribution, operation);
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let genesis_hash = B256::repeat_byte(9);
    let genesis_root =
        outbe_compressed_entities::sealed_root(B256::ZERO).expect("ADR-010 empty authority");
    let genesis = FinalizedMarker {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        height: 0,
        block_hash: genesis_hash,
        parent_block_hash: B256::ZERO,
        parent_root: B256::ZERO,
        new_root: genesis_root,
    };
    let db = CeMdbx::open(
        directory.path(),
        environment(shard_count, genesis_hash),
        genesis,
    )
    .expect("benchmark MDBX");
    let service = CompressedTreeService::new(
        db,
        CandidateCacheLimits {
            max_candidates: 2,
            max_encoded_bytes: 256 * 1024 * 1024,
        },
    )
    .expect("benchmark tree service");

    let parent = service
        .open_parent(ExactParentIdentity {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            block_number: 0,
            block_hash: genesis_hash,
            root: genesis_root,
        })
        .expect("genesis parent");
    let provisional = parent
        .prepare_seal(1, &workload.seed_mutations, &[])
        .expect("seed seal");
    let seed_root = provisional.new_root();
    let seed_hash = B256::from(field_word(90_010));
    service
        .publish_candidate(seed_hash, provisional)
        .expect("seed publication");
    service
        .apply_finalized(1, seed_hash, seed_root)
        .expect("seed finalization");

    let descriptor = format!(
        "k={shard_count}/{}/{}/{}",
        shape.label,
        distribution.label(),
        operation.label(),
    );
    let mdbx_bytes_before = directory_bytes(directory.path());
    let mdbx_allocated_bytes_before = directory_allocated_bytes(directory.path());
    Fixture {
        directory,
        service,
        parent: ExactParentIdentity {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            block_number: 1,
            block_hash: seed_hash,
            root: seed_root,
        },
        block_hash: B256::from(field_word(90_011)),
        mutations: workload.mutations,
        dataset_checksum: workload.dataset_checksum,
        descriptor,
        mdbx_bytes_before,
        mdbx_allocated_bytes_before,
    }
}

fn measured_full_path(
    fixture: Fixture,
) -> (TempDir, CompressedTreeService, ManifestRecord, Duration) {
    let Fixture {
        directory,
        service,
        parent,
        block_hash,
        mutations,
        dataset_checksum,
        descriptor,
        mdbx_bytes_before,
        mdbx_allocated_bytes_before,
    } = fixture;
    let started = Instant::now();
    let parent = service.open_parent(parent).expect("exact parent open");
    let provisional = parent
        .prepare_seal(2, black_box(&mutations), &[])
        .expect("sharded proof and seal");
    let root = provisional.new_root();
    service
        .publish_candidate(block_hash, provisional)
        .expect("candidate publication");
    let candidate = service
        .candidate(2, block_hash)
        .expect("candidate lookup")
        .expect("published candidate");
    black_box(
        service
            .apply_finalized(2, block_hash, root)
            .expect("atomic finalized apply"),
    );
    let measured = started.elapsed();
    let record = ManifestRecord {
        descriptor,
        dataset_checksum,
        expected_root: candidate.new_root(),
        batch_checksum: candidate_checksum(&candidate),
        staged_bytes: candidate.encoded_size(),
        changed_shards: candidate.changed_shard_count(),
        branch_records: candidate.branch_change_count(),
        leaf_records: candidate.leaf_change_count(),
        mdbx_bytes_before,
        mdbx_bytes_after: 0,
        mdbx_allocated_bytes_before,
        mdbx_allocated_bytes_after: 0,
    };
    drop(candidate);
    drop(parent);
    (directory, service, record, measured)
}

fn measured_proof_seal(fixture: Fixture) -> Duration {
    let started = Instant::now();
    let parent = fixture
        .service
        .open_parent(fixture.parent)
        .expect("exact parent open");
    let provisional = parent
        .prepare_seal(2, black_box(&fixture.mutations), &[])
        .expect("sharded proof and seal");
    black_box(provisional.new_root());
    started.elapsed()
}

fn measured_aggregation(fixture: Fixture) -> Duration {
    let parent = fixture
        .service
        .open_parent(fixture.parent)
        .expect("exact parent open");
    let provisional = parent
        .prepare_seal(2, &fixture.mutations, &[])
        .expect("sharded proof and seal");
    let roots = outbe_compressed_entities::bench_support::candidate_shard_roots(&provisional);
    let started = Instant::now();
    black_box(aggregate_shard_roots(black_box(&roots)).expect("shard aggregation"));
    started.elapsed()
}

fn measured_finalized_apply(fixture: Fixture) -> Duration {
    let parent = fixture
        .service
        .open_parent(fixture.parent)
        .expect("exact parent open");
    let provisional = parent
        .prepare_seal(2, &fixture.mutations, &[])
        .expect("sharded proof and seal");
    let root = provisional.new_root();
    fixture
        .service
        .publish_candidate(fixture.block_hash, provisional)
        .expect("candidate publication");
    let started = Instant::now();
    black_box(
        fixture
            .service
            .apply_finalized(2, fixture.block_hash, root)
            .expect("atomic finalized apply"),
    );
    started.elapsed()
}

fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .expect("benchmark directory")
        .map(|entry| {
            let entry = entry.expect("benchmark directory entry");
            let metadata = entry.metadata().expect("benchmark metadata");
            if metadata.is_dir() {
                directory_bytes(&entry.path())
            } else {
                metadata.len()
            }
        })
        .sum()
}

fn directory_allocated_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .expect("benchmark directory")
        .map(|entry| {
            let entry = entry.expect("benchmark directory entry");
            let metadata = entry.metadata().expect("benchmark metadata");
            if metadata.is_dir() {
                directory_allocated_bytes(&entry.path())
            } else {
                allocated_file_bytes(&metadata)
            }
        })
        .sum()
}

#[cfg(unix)]
fn allocated_file_bytes(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_file_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

fn retain_manifest(record: ManifestRecord) {
    let descriptor = record.descriptor.clone();
    let json = serde_json::json!({
        "case": descriptor,
        "dataset_checksum": format!("{:#x}", record.dataset_checksum),
        "expected_root": format!("{:#x}", record.expected_root),
        "batch_checksum": format!("{:#x}", record.batch_checksum),
        "staged_bytes": record.staged_bytes,
        "changed_shards": record.changed_shards,
        "branch_records": record.branch_records,
        "leaf_records": record.leaf_records,
        "mdbx_bytes_before": record.mdbx_bytes_before,
        "mdbx_bytes_after": record.mdbx_bytes_after,
        "mdbx_allocated_bytes_before": record.mdbx_allocated_bytes_before,
        "mdbx_allocated_bytes_after": record.mdbx_allocated_bytes_after,
    })
    .to_string();
    MANIFEST
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("manifest lock")
        .entry(descriptor)
        .or_insert(json);
}

fn sidecar_path(directory: &Path) -> PathBuf {
    let mut path = directory.as_os_str().to_os_string();
    path.push(".adr009.json");
    PathBuf::from(path)
}

fn cold_prepare(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 4 {
        return Err(
            "usage: cold-prepare <K> <small|large> <uniform|concentrated> <insert|update|delete|mixed>"
                .to_owned(),
        );
    }
    let shard_count = arguments[0]
        .parse::<u32>()
        .map_err(|error| format!("invalid K: {error}"))?;
    if !K_CANDIDATES.contains(&shard_count) {
        return Err(format!("K must be one of {K_CANDIDATES:?}"));
    }
    let shape = shape(&arguments[1]).ok_or_else(|| "invalid shape".to_owned())?;
    let distribution =
        Distribution::parse(&arguments[2]).ok_or_else(|| "invalid distribution".to_owned())?;
    let operation =
        Operation::parse(&arguments[3]).ok_or_else(|| "invalid operation".to_owned())?;
    let Fixture {
        directory,
        service,
        parent,
        block_hash,
        mutations: _,
        dataset_checksum,
        descriptor,
        mdbx_bytes_before,
        mdbx_allocated_bytes_before,
    } = build_fixture(shard_count, shape, distribution, operation);
    drop(service);
    let directory = directory.keep();
    let sidecar = sidecar_path(&directory);
    let record = serde_json::json!({
        "version": 1,
        "fixture_dir": directory.display().to_string(),
        "case": descriptor,
        "shard_count": shard_count,
        "shape": shape.label,
        "distribution": distribution.label(),
        "operation": operation.label(),
        "parent_block_number": parent.block_number,
        "parent_block_hash": format!("{:#x}", parent.block_hash),
        "parent_root": format!("{:#x}", parent.root),
        "block_hash": format!("{:#x}", block_hash),
        "dataset_checksum": format!("{:#x}", dataset_checksum),
        "mdbx_bytes_before": mdbx_bytes_before,
        "mdbx_allocated_bytes_before": mdbx_allocated_bytes_before,
    });
    fs::write(
        &sidecar,
        serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write cold sidecar: {error}"))?;
    println!(
        "ADR009_COLD_FIXTURE {}",
        serde_json::json!({
            "fixture_dir": directory.display().to_string(),
            "sidecar": sidecar.display().to_string(),
        })
    );
    Ok(())
}

fn cold_run(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 2 || arguments[1] != "cache-drop-reviewed-and-completed" {
        return Err("usage: cold-run <fixture-dir> cache-drop-reviewed-and-completed".to_owned());
    }
    let directory = PathBuf::from(&arguments[0]);
    let metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(sidecar_path(&directory))
            .map_err(|error| format!("read cold sidecar: {error}"))?,
    )
    .map_err(|error| format!("decode cold sidecar: {error}"))?;
    let text = |name: &str| -> Result<&str, String> {
        metadata[name]
            .as_str()
            .ok_or_else(|| format!("missing string field {name}"))
    };
    let number = |name: &str| -> Result<u64, String> {
        metadata[name]
            .as_u64()
            .ok_or_else(|| format!("missing integer field {name}"))
    };
    if number("version")? != 1 {
        return Err("unsupported cold fixture version".to_owned());
    }
    let shard_count = u32::try_from(number("shard_count")?)
        .map_err(|_| "shard_count does not fit u32".to_owned())?;
    let shape = shape(text("shape")?).ok_or_else(|| "invalid shape".to_owned())?;
    let distribution = Distribution::parse(text("distribution")?)
        .ok_or_else(|| "invalid distribution".to_owned())?;
    let operation =
        Operation::parse(text("operation")?).ok_or_else(|| "invalid operation".to_owned())?;
    let parent = ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: number("parent_block_number")?,
        block_hash: text("parent_block_hash")?
            .parse()
            .map_err(|error| format!("invalid parent block hash: {error}"))?,
        root: text("parent_root")?
            .parse()
            .map_err(|error| format!("invalid parent root: {error}"))?,
    };
    let block_hash: B256 = text("block_hash")?
        .parse()
        .map_err(|error| format!("invalid block hash: {error}"))?;
    let expected_dataset_checksum: B256 = text("dataset_checksum")?
        .parse()
        .map_err(|error| format!("invalid dataset checksum: {error}"))?;
    let mdbx_bytes_before = number("mdbx_bytes_before")?;
    let mdbx_allocated_bytes_before = number("mdbx_allocated_bytes_before")?;
    let workload = workload(shape, distribution, operation);
    if workload.dataset_checksum != expected_dataset_checksum {
        return Err("cold fixture dataset checksum drift".to_owned());
    }

    let genesis_hash = B256::repeat_byte(9);
    let genesis_root =
        outbe_compressed_entities::sealed_root(B256::ZERO).map_err(|error| error.to_string())?;
    let genesis = FinalizedMarker {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        height: 0,
        block_hash: genesis_hash,
        parent_block_hash: B256::ZERO,
        parent_root: B256::ZERO,
        new_root: genesis_root,
    };
    let started = Instant::now();
    let db = CeMdbx::open(&directory, environment(shard_count, genesis_hash), genesis)
        .map_err(|error| format!("open cold MDBX fixture: {error}"))?;
    let service = CompressedTreeService::new(
        db,
        CandidateCacheLimits {
            max_candidates: 2,
            max_encoded_bytes: 256 * 1024 * 1024,
        },
    )
    .map_err(|error| format!("open cold tree service: {error}"))?;
    let parent_tree = service
        .open_parent(parent)
        .map_err(|error| format!("open cold exact parent: {error}"))?;
    let provisional = parent_tree
        .prepare_seal(2, &workload.mutations, &[])
        .map_err(|error| format!("cold proof and seal: {error}"))?;
    let root = provisional.new_root();
    service
        .publish_candidate(block_hash, provisional)
        .map_err(|error| format!("cold candidate publication: {error}"))?;
    let candidate = service
        .candidate(2, block_hash)
        .map_err(|error| format!("cold candidate lookup: {error}"))?
        .ok_or_else(|| "cold candidate missing after publication".to_owned())?;
    service
        .apply_finalized(2, block_hash, root)
        .map_err(|error| format!("cold finalized apply: {error}"))?;
    let elapsed = started.elapsed();
    let record = serde_json::json!({
        "case": text("case")?,
        "cache_state": "operator-attested-cold-after-reviewed-external-drop",
        "samples": 1,
        "includes_environment_open": true,
        "elapsed_ns": u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        "dataset_checksum": format!("{:#x}", workload.dataset_checksum),
        "expected_root": format!("{:#x}", candidate.new_root()),
        "batch_checksum": format!("{:#x}", candidate_checksum(&candidate)),
        "staged_bytes": candidate.encoded_size(),
        "changed_shards": candidate.changed_shard_count(),
        "branch_records": candidate.branch_change_count(),
        "leaf_records": candidate.leaf_change_count(),
        "mdbx_bytes_before": mdbx_bytes_before,
        "mdbx_bytes_after": directory_bytes(&directory),
        "mdbx_allocated_bytes_before": mdbx_allocated_bytes_before,
        "mdbx_allocated_bytes_after": directory_allocated_bytes(&directory),
    });
    println!("ADR009_COLD_MANIFEST {record}");
    Ok(())
}

fn benchmark_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("adr009_real_key_full_path");
    group.sample_size(10);
    for shard_count in K_CANDIDATES {
        for shape in SHAPES {
            for distribution in [Distribution::Uniform, Distribution::Concentrated] {
                for operation in [
                    Operation::Insert,
                    Operation::Update,
                    Operation::Delete,
                    Operation::Mixed,
                ] {
                    let name = format!(
                        "k={shard_count}/{}/{}/{}",
                        shape.label,
                        distribution.label(),
                        operation.label(),
                    );
                    group.bench_with_input(
                        BenchmarkId::new("full_path", &name),
                        &(shard_count, shape, distribution, operation),
                        |bench, &(k, shape, distribution, operation)| {
                            bench.iter_custom(|iterations| {
                                let mut measured = Duration::ZERO;
                                for _ in 0..iterations {
                                    let fixture = build_fixture(k, shape, distribution, operation);
                                    let (directory, service, mut record, elapsed) =
                                        measured_full_path(fixture);
                                    measured += elapsed;
                                    record.mdbx_bytes_after = directory_bytes(directory.path());
                                    record.mdbx_allocated_bytes_after =
                                        directory_allocated_bytes(directory.path());
                                    retain_manifest(record);
                                    drop(service);
                                }
                                measured
                            });
                        },
                    );
                    for (phase, measure) in [
                        ("proof_seal", measured_proof_seal as fn(Fixture) -> Duration),
                        (
                            "aggregation",
                            measured_aggregation as fn(Fixture) -> Duration,
                        ),
                        (
                            "finalized_apply",
                            measured_finalized_apply as fn(Fixture) -> Duration,
                        ),
                    ] {
                        group.bench_with_input(
                            BenchmarkId::new(phase, &name),
                            &(shard_count, shape, distribution, operation),
                            |bench, &(k, shape, distribution, operation)| {
                                bench.iter_custom(|iterations| {
                                    let mut measured = Duration::ZERO;
                                    for _ in 0..iterations {
                                        measured += measure(build_fixture(
                                            k,
                                            shape,
                                            distribution,
                                            operation,
                                        ));
                                    }
                                    measured
                                });
                            },
                        );
                    }
                }
            }
        }
    }
    group.finish();
    if let Some(manifest) = MANIFEST.get() {
        for record in manifest.lock().expect("manifest lock").values() {
            eprintln!("ADR009_MANIFEST {record}");
        }
    }
}

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let command_arguments = arguments
        .iter()
        .skip(1)
        .filter(|argument| argument.as_str() != "--bench")
        .cloned()
        .collect::<Vec<_>>();
    let result = match command_arguments.first().map(String::as_str) {
        Some("cold-prepare") => cold_prepare(&command_arguments[1..]),
        Some("cold-run") => cold_run(&command_arguments[1..]),
        _ => {
            let mut criterion = Criterion::default().configure_from_args();
            benchmark_matrix(&mut criterion);
            criterion.final_summary();
            Ok(())
        }
    };
    if let Err(error) = result {
        eprintln!("ADR009 benchmark error: {error}");
        std::process::exit(2);
    }
}
