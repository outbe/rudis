use std::{sync::Arc, time::Duration};

use alloy_consensus::Header;
use alloy_eips::BlockNumHash;
use alloy_primitives::B256;
use mongodb::sync::Client;
use outbe_node::projection::{
    prepare_offchain_data_projection, validate_offchain_data_checkpoint,
    OffchainDataProjectionConfig,
};
use outbe_offchain_data::{FinalizedBlock, OffchainDataProjection, ProjectionConfig};
use outbe_offchain_storage::{MongoStorage, MongoStorageConfig};
use outbe_primitives::chain::DEVNET_CHAIN_ID;
use reth_chainspec::ChainInfo;
use reth_ethereum::Block;
use reth_provider::{
    test_utils::MockEthProvider, BlockHashReader, BlockIdReader, BlockNumReader, ProviderResult,
};

#[test]
fn rocksdb_startup_reopens_durable_checkpoint_and_rejects_wrong_chain_or_hash() {
    use outbe_offchain_storage::{RocksDbConfig, StorageBackend, StorageConfig, StorageProvider};
    let root = tempfile::tempdir().unwrap();
    let config = OffchainDataProjectionConfig {
        chain_id: DEVNET_CHAIN_ID,
        genesis_hash: B256::repeat_byte(0x11),
        storage: StorageConfig {
            start_block: 1,
            backend: StorageBackend::RocksDb(RocksDbConfig {
                path: root.path().join("primary"),
                secondary_path: root.path().join("secondary"),
            }),
        },
    };
    let canonical = MockEthProvider::new();
    let hash = add_empty_block(&canonical, 1, 1);
    let canonical = FinalizedMockProvider::new(canonical, BlockNumHash::new(1, hash));
    {
        let storage = StorageProvider::new(config.storage.clone())
            .unwrap()
            .open_writer()
            .unwrap();
        let mut projection = OffchainDataProjection::open(
            ProjectionConfig {
                chain_id: config.chain_id,
                genesis_hash: config.genesis_hash,
                start_block: 1,
            },
            storage.reader.clone(),
            storage.writer.clone(),
        )
        .unwrap();
        projection
            .project_block(&FinalizedBlock {
                number: 1,
                hash,
                receipts: vec![],
            })
            .unwrap();
    }
    for _ in 0..2 {
        let prepared = prepare_offchain_data_projection(config.clone()).unwrap();
        validate_offchain_data_checkpoint(prepared, &canonical)
            .map(drop)
            .unwrap();
    }
    let wrong_canonical = MockEthProvider::new();
    let wrong_hash = add_empty_block(&wrong_canonical, 1, 2);
    let wrong_canonical =
        FinalizedMockProvider::new(wrong_canonical, BlockNumHash::new(1, wrong_hash));
    let prepared = prepare_offchain_data_projection(config.clone()).unwrap();
    assert!(validate_offchain_data_checkpoint(prepared, &wrong_canonical).is_err());
    let mut wrong_identity = config.clone();
    wrong_identity.genesis_hash = B256::repeat_byte(0x99);
    assert!(prepare_offchain_data_projection(wrong_identity).is_err());
    // Failed preparation releases its primary handle too.
    let prepared = prepare_offchain_data_projection(config).unwrap();
    validate_offchain_data_checkpoint(prepared, &canonical)
        .map(drop)
        .unwrap();
}

#[test]
#[ignore = "requires OUTBE_TEST_STANDALONE_MONGODB_URI"]
fn standalone_mongodb_is_rejected_during_startup_preparation() {
    let uri = std::env::var("OUTBE_TEST_STANDALONE_MONGODB_URI")
        .expect("set OUTBE_TEST_STANDALONE_MONGODB_URI before running this test");
    drop(
        prepare_offchain_data_projection(config(
            uri,
            isolated_database("standalone_rejected"),
            DEVNET_CHAIN_ID,
        ))
        .err()
        .expect("standalone MongoDB must not produce a ready projection"),
    );
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn replica_set_passes_startup_and_persisted_identity_is_validated() {
    let uri = std::env::var("OUTBE_TEST_MONGODB_URI")
        .expect("set OUTBE_TEST_MONGODB_URI before running this test");
    let database = isolated_database("replica_ready");
    let client = Client::with_uri_str(&uri).unwrap();
    client.database(&database).drop().run().unwrap();

    let canonical_mock = MockEthProvider::new();
    let checkpoint_hash = add_empty_block(&canonical_mock, 1, 1);
    let canonical_provider =
        FinalizedMockProvider::new(canonical_mock, BlockNumHash::new(1, checkpoint_hash));
    let first = config(uri.clone(), database.clone(), DEVNET_CHAIN_ID);
    let storage = Arc::new(
        MongoStorage::connect(MongoStorageConfig {
            uri: uri.clone(),
            database: database.clone(),
        })
        .unwrap(),
    );
    let mut projector = OffchainDataProjection::open(
        ProjectionConfig {
            chain_id: first.chain_id,
            genesis_hash: first.genesis_hash,
            start_block: first.storage.start_block,
        },
        storage.clone(),
        storage,
    )
    .unwrap();
    projector
        .project_block(&FinalizedBlock {
            number: 1,
            hash: checkpoint_hash,
            receipts: Vec::new(),
        })
        .unwrap();

    let prepared = prepare_offchain_data_projection(first.clone())
        .expect("transaction-capable replica set must pass MongoDB startup preparation");
    validate_offchain_data_checkpoint(prepared, &canonical_provider)
        .map(drop)
        .expect("transaction-capable replica set must pass startup preparation");
    let prepared = prepare_offchain_data_projection(first.clone())
        .expect("matching managed state must pass MongoDB startup preparation");
    validate_offchain_data_checkpoint(prepared, &canonical_provider)
        .map(drop)
        .expect("matching managed state must reopen successfully");

    let wrong_canonical_mock = MockEthProvider::new();
    let wrong_hash = add_empty_block(&wrong_canonical_mock, 1, 2);
    let wrong_canonical_provider =
        FinalizedMockProvider::new(wrong_canonical_mock, BlockNumHash::new(1, wrong_hash));
    assert_ne!(checkpoint_hash, wrong_hash);
    let prepared = prepare_offchain_data_projection(first)
        .expect("matching managed state must pass MongoDB startup preparation");
    drop(
        validate_offchain_data_checkpoint(prepared, &wrong_canonical_provider)
            .err()
            .expect("mismatched canonical checkpoint hash must stop startup"),
    );

    let mut wrong_identity = config(uri, database.clone(), DEVNET_CHAIN_ID);
    wrong_identity.genesis_hash = B256::repeat_byte(0x22);
    drop(
        prepare_offchain_data_projection(wrong_identity)
            .err()
            .expect("mismatched persisted chain identity must stop startup"),
    );

    client.database(&database).drop().run().unwrap();
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn second_active_projection_writer_is_rejected_until_the_first_releases_its_lease() {
    let uri = std::env::var("OUTBE_TEST_MONGODB_URI")
        .expect("set OUTBE_TEST_MONGODB_URI before running this test");
    let database = isolated_database("single_writer");
    let client = Client::with_uri_str(&uri).unwrap();
    client.database(&database).drop().run().unwrap();
    let projection_config = config(uri, database.clone(), DEVNET_CHAIN_ID);

    let first = prepare_offchain_data_projection(projection_config.clone())
        .expect("first projection writer must acquire the database lease");
    let second_error = prepare_offchain_data_projection(projection_config.clone())
        .err()
        .expect("second active writer must be rejected");
    assert!(second_error
        .to_string()
        .contains("eight-second total deadline"));

    drop(first);
    let restarted_at = std::time::Instant::now();
    prepare_offchain_data_projection(projection_config)
        .map(drop)
        .expect("clean writer shutdown must release the database lease");
    assert!(
        restarted_at.elapsed() < Duration::from_secs(3),
        "clean shutdown must release ownership without waiting for lease expiry"
    );
    client.database(&database).drop().run().unwrap();
}

struct FinalizedMockProvider {
    inner: MockEthProvider,
    finalized: BlockNumHash,
}

impl FinalizedMockProvider {
    fn new(inner: MockEthProvider, finalized: BlockNumHash) -> Self {
        Self { inner, finalized }
    }
}

impl BlockHashReader for FinalizedMockProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BlockNumReader for FinalizedMockProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.inner.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        self.inner.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        self.inner.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        self.inner.block_number(hash)
    }
}

impl BlockIdReader for FinalizedMockProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(self.finalized))
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(self.finalized))
    }
}

fn add_empty_block(provider: &MockEthProvider, number: u64, timestamp: u64) -> B256 {
    let header = Header {
        number,
        timestamp,
        ..Default::default()
    };
    let hash = header.hash_slow();
    provider.add_block(hash, Block::new(header, Default::default()));
    hash
}

fn config(uri: String, database: String, chain_id: u64) -> OffchainDataProjectionConfig {
    OffchainDataProjectionConfig {
        chain_id,
        genesis_hash: B256::repeat_byte(0x11),
        storage: outbe_offchain_storage::StorageConfig {
            start_block: 1,
            backend: outbe_offchain_storage::StorageBackend::MongoDb(MongoStorageConfig {
                uri,
                database,
            }),
        },
    }
}

fn isolated_database(test_name: &str) -> String {
    format!("outbe_node_startup_{}_{}", std::process::id(), test_name)
}

#[test]
fn rocksdb_secondary_checkpoint_is_frozen_and_next_session_catches_up() {
    use outbe_node::projection::{ocomp_projection_contains, OcompProjectionContainment};
    use outbe_offchain_data::read_projection_state;
    use outbe_offchain_storage::{RocksDbConfig, StorageBackend, StorageConfig, StorageProvider};
    use outbe_primitives::projection::ProjectionCheckpoint;

    let root = tempfile::tempdir().unwrap();
    let provider = StorageProvider::new(StorageConfig {
        start_block: 1,
        backend: StorageBackend::RocksDb(RocksDbConfig {
            path: root.path().join("primary"),
            secondary_path: root.path().join("secondary"),
        }),
    })
    .unwrap();
    let storage = provider.open_writer().unwrap();
    let config = ProjectionConfig {
        chain_id: DEVNET_CHAIN_ID,
        genesis_hash: B256::repeat_byte(0x11),
        start_block: 1,
    };
    let mut projection =
        OffchainDataProjection::open(config, storage.reader.clone(), storage.writer.clone())
            .unwrap();
    let canonical = MockEthProvider::new();
    let hashes = (1..=3)
        .map(|number| add_empty_block(&canonical, number, number))
        .collect::<Vec<_>>();
    let canonical = FinalizedMockProvider::new(canonical, BlockNumHash::new(3, hashes[2]));
    let required = ProjectionCheckpoint {
        block_number: 2,
        block_hash: hashes[1],
    };
    let source = provider.read_source("exporter-lane-v1").unwrap();
    let mut frozen = None;
    for number in 1..=3 {
        projection
            .project_block(&FinalizedBlock {
                number,
                hash: hashes[number as usize - 1],
                receipts: vec![],
            })
            .unwrap();
        let reader = if number == 1 {
            let reader = source.open_session().unwrap();
            frozen = Some(reader.clone());
            reader
        } else {
            provider
                .read_source("exporter-lane-v2")
                .unwrap()
                .open_session()
                .unwrap()
        };
        let checkpoint = read_projection_state(config, reader)
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap();
        let containment = ocomp_projection_contains(checkpoint, required, &canonical).unwrap();
        assert_eq!(
            matches!(containment, OcompProjectionContainment::Behind { .. }),
            number == 1
        );
        assert_eq!(
            read_projection_state(config, frozen.as_ref().unwrap().clone())
                .unwrap()
                .unwrap()
                .checkpoint
                .unwrap()
                .block_number,
            1
        );
    }
    drop(frozen);
    assert_eq!(
        read_projection_state(config, source.open_session().unwrap())
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap()
            .block_number,
        3
    );
}
