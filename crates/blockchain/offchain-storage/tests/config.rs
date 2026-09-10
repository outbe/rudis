use std::path::Path;

use outbe_offchain_storage::{StorageBackend, StorageConfig, StorageErrorKind};

const ROCKS: &str = "version = 1\nbackend = 'rocksdb'\n[rocksdb]\npath = 'data/offchain'\nsecondary_path = 'ocomp/secondary'\n";

#[test]
fn config_resolves_paths_from_file_and_roundtrips() {
    let config = StorageConfig::from_toml(ROCKS, Path::new("/node/offchain-storage.toml")).unwrap();
    assert_eq!(config.start_block, 1);
    assert_eq!(config.backend_name(), "rocksdb");
    let StorageBackend::RocksDb(paths) = &config.backend else {
        panic!("wrong backend")
    };
    assert_eq!(paths.path, Path::new("/node/data/offchain"));
    assert_eq!(paths.secondary_path, Path::new("/node/ocomp/secondary"));
    assert_eq!(
        StorageConfig::from_toml(
            &config.to_toml().unwrap(),
            Path::new("/elsewhere/config.toml")
        )
        .unwrap(),
        config
    );
}

#[test]
fn mongodb_config_preserves_settings_and_redacts_diagnostics() {
    let source = "version=1\nbackend='mongodb'\nstart_block=12\n[mongodb]\nuri='mongodb://user:supersecret@localhost/'\ndatabase='projection'";
    let config = StorageConfig::from_toml(source, Path::new("/node/config.toml")).unwrap();
    assert_eq!(config.start_block, 12);
    assert!(!format!("{config:?}").contains("supersecret"));
    let malformed = source.replace("uri='mongodb", "uri=['mongodb");
    let error = StorageConfig::from_toml(&malformed, Path::new("/node/config.toml")).unwrap_err();
    assert!(!format!("{error:?}").contains("supersecret"));
    assert_eq!(
        StorageConfig::from_toml(&config.to_toml().unwrap(), Path::new("/node/config.toml"))
            .unwrap(),
        config
    );
}

#[test]
fn config_rejects_ambiguous_incomplete_and_overlapping_settings() {
    for source in [
        ROCKS.replace("version = 1", "version = 2"),
        ROCKS.replace("backend = 'rocksdb'", "backend = 'unknown'"),
        ROCKS.replace("backend = 'rocksdb'\n", ""),
        ROCKS.replace("secondary_path", "typo_path"),
        ROCKS.replace("'data/offchain'", "''"),
        ROCKS.replace("'ocomp/secondary'", "'data/offchain/child'"),
        ROCKS.replace("'ocomp/secondary'", "'data/offchain/../offchain'"),
        format!("{ROCKS}\n[mongodb]\nuri='mongodb://localhost'\ndatabase='projection'\n"),
        "version=1\nbackend='mongodb'\n[mongodb]\nuri=''\ndatabase='projection'".to_owned(),
    ] {
        assert_eq!(
            StorageConfig::from_toml(&source, Path::new("/node/config.toml"))
                .unwrap_err()
                .kind(),
            StorageErrorKind::InvalidArgument
        );
    }
}

#[test]
fn load_requires_an_existing_file() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("offchain-storage.toml");
    assert!(StorageConfig::load(&path).is_err());
    std::fs::write(&path, ROCKS).unwrap();
    assert_eq!(
        StorageConfig::load(&path).unwrap().backend_name(),
        "rocksdb"
    );
}
