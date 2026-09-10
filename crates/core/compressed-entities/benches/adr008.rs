use alloy_primitives::B256;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use outbe_compressed_entities::{
    bench_support::{field_b256, field_word, staged_batch, Adr008SmtHarness},
    CeMdbx, EnvironmentIdentity, FinalizedMarker, StagedTreeBatch, ACTIVE_COMMITMENT_SCHEME,
    LOCAL_STORAGE_SCHEMA_VERSION,
};
use tempfile::TempDir;

const TREE_ENTRIES: u64 = 256;
const PROOF_ENTRIES: u64 = 32;
const STAGED_RECORDS: usize = 64;

fn mutations(round: u64) -> Vec<([u8; 32], [u8; 32])> {
    (1..=TREE_ENTRIES)
        .map(|key| (field_word(key), field_word(key + round + TREE_ENTRIES)))
        .collect()
}

fn seeded_tree() -> Adr008SmtHarness {
    let mut tree = Adr008SmtHarness::empty();
    tree.update_all(&mutations(0))
        .expect("valid benchmark seed");
    tree
}

fn benchmark_smt(c: &mut Criterion) {
    let mut group = c.benchmark_group("adr008_unsharded_smt");

    group.bench_function("cold_update_all", |bench| {
        bench.iter_batched(
            || (Adr008SmtHarness::empty(), mutations(1)),
            |(mut tree, updates)| black_box(tree.update_all(black_box(&updates)).unwrap()),
            // MDBX environments map a production-sized address space. Holding
            // Criterion's input batch alive concurrently exhausted virtual
            // memory; one complete environment per iteration measures the
            // same production settings without retaining sibling mappings.
            BatchSize::PerIteration,
        );
    });

    let mut warm_tree = seeded_tree();
    let mut round = 1_u64;
    group.bench_function("warm_update_all", |bench| {
        bench.iter(|| {
            round = round.wrapping_add(1);
            let updates = mutations(round);
            black_box(warm_tree.update_all(black_box(&updates)).unwrap())
        });
    });

    let proof_keys: Vec<_> = (1..=PROOF_ENTRIES).map(field_word).collect();
    group.bench_function("cold_build_and_exact_parent_proof", |bench| {
        bench.iter(|| {
            let tree = seeded_tree();
            black_box(tree.proof(black_box(&proof_keys)).unwrap())
        });
    });

    let proof_tree = seeded_tree();
    let root = proof_tree.root().unwrap();
    let proof = proof_tree.proof(&proof_keys).unwrap();
    let proof_leaves: Vec<_> = (1..=PROOF_ENTRIES)
        .map(|key| (field_word(key), field_word(key + TREE_ENTRIES)))
        .collect();
    group.bench_function("warm_exact_parent_proof_verify", |bench| {
        bench.iter(|| {
            proof_tree
                .verify(root, black_box(&proof), black_box(&proof_leaves))
                .unwrap();
            black_box(())
        });
    });
    group.finish();
}

struct BenchMdbx {
    _directory: TempDir,
    store: CeMdbx,
    marker: FinalizedMarker,
}

fn open_mdbx() -> BenchMdbx {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let genesis_hash = B256::repeat_byte(1);
    let marker = FinalizedMarker {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        height: 0,
        block_hash: genesis_hash,
        parent_block_hash: B256::ZERO,
        parent_root: B256::ZERO,
        new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
    };
    let store = CeMdbx::open(
        directory.path(),
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: 1,
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: outbe_compressed_entities::CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        },
        marker,
    )
    .expect("benchmark MDBX");
    BenchMdbx {
        _directory: directory,
        store,
        marker,
    }
}

fn next_batch(state: &BenchMdbx, record_count: usize) -> StagedTreeBatch {
    let height = state.marker.height + 1;
    let block_hash = B256::from(field_word(height + 10_000));
    let new_root = if record_count == 0 {
        state.marker.new_root
    } else {
        field_b256(height + 1)
    };
    staged_batch(
        height,
        block_hash,
        state.marker.block_hash,
        state.marker.new_root,
        new_root,
        record_count,
    )
    .unwrap()
}

fn benchmark_mdbx(c: &mut Criterion) {
    let mut group = c.benchmark_group("adr008_finalized_mdbx");

    group.bench_function("cold_open_and_staged_apply", |bench| {
        bench.iter_batched(
            open_mdbx,
            |mut state| {
                let batch = next_batch(&state, STAGED_RECORDS);
                black_box(state.store.apply_finalized(&batch).unwrap());
                state.marker = batch.marker(ACTIVE_COMMITMENT_SCHEME);
            },
            BatchSize::SmallInput,
        );
    });

    let mut warm = open_mdbx();
    group.bench_function("warm_staged_apply", |bench| {
        bench.iter(|| {
            let batch = next_batch(&warm, STAGED_RECORDS);
            black_box(warm.store.apply_finalized(&batch).unwrap());
            warm.marker = batch.marker(ACTIVE_COMMITMENT_SCHEME);
        });
    });

    let mut no_change = open_mdbx();
    group.bench_function("warm_no_change_identity_apply", |bench| {
        bench.iter(|| {
            let batch = next_batch(&no_change, 0);
            black_box(no_change.store.apply_finalized(&batch).unwrap());
            no_change.marker = batch.marker(ACTIVE_COMMITMENT_SCHEME);
        });
    });
    group.finish();
}

criterion_group!(adr008, benchmark_smt, benchmark_mdbx);
criterion_main!(adr008);
