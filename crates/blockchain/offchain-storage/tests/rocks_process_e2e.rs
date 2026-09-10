//! Real-process storage E2E. These complement (not replace) the network OCOMP lane.

use std::{
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, RocksDbReader, RocksDbStorage,
    StorageReader, StorageWriter, Value,
};

const ROOT_ENV: &str = "OUTBE_ROCKS_PROCESS_TEST_ROOT";

struct WriterProcess(Child);

impl Drop for WriterProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_writer(root: &Path) -> WriterProcess {
    WriterProcess(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rocks_writer_child", "--nocapture"])
            .env(ROOT_ENV, root)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_file(process: &mut WriterProcess, file: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !file.exists() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "writer exited before {}",
            file.display()
        );
        assert!(
            Instant::now() < deadline,
            "writer timed out before {}",
            file.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn batch(generation: u64) -> AtomicWriteBatch {
    let value = Value::new(generation.to_be_bytes().to_vec()).unwrap();
    AtomicWriteBatch::from_operations(
        ["bodies", "indexes", "checkpoint"]
            .map(|namespace| {
                AtomicWriteOperation::put(
                    Namespace::new(namespace).unwrap(),
                    Key::new(b"record".to_vec()).unwrap(),
                    value.clone(),
                )
            })
            .to_vec(),
    )
}

fn assert_generation(reader: &dyn StorageReader, generation: u64) {
    for namespace in ["bodies", "indexes", "checkpoint"] {
        let record = reader
            .get(
                Namespace::new(namespace).unwrap(),
                &Key::new(b"record".to_vec()).unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(record.as_bytes(), generation.to_be_bytes());
    }
}

#[test]
fn rocks_writer_child() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let root = Path::new(&root);
    let writer = RocksDbStorage::open(root.join("primary")).unwrap();
    writer.apply_atomic(&batch(1)).unwrap();
    std::fs::write(root.join("ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("advance").exists() {
        assert!(Instant::now() < deadline, "parent abandoned writer");
        thread::sleep(Duration::from_millis(5));
    }
    writer.apply_atomic(&batch(2)).unwrap();
    std::fs::write(root.join("advanced"), b"durable").unwrap();
    // Parent kills this process without unwinding/destructors, after the durable ACK.
    thread::sleep(Duration::from_secs(30));
    panic!("parent did not terminate writer");
}

#[test]
fn process_crash_preserves_atomic_checkpoint_and_secondary_sessions() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary");
    let mut child = spawn_writer(root.path());
    wait_file(&mut child, &root.path().join("ready"));
    assert!(
        RocksDbStorage::open(&primary).is_err(),
        "second process cannot own primary"
    );
    let first = RocksDbReader::open(&primary, &root.path().join("lane_a")).unwrap();
    assert_generation(&first, 1);
    std::fs::write(root.path().join("advance"), b"advance").unwrap();
    wait_file(&mut child, &root.path().join("advanced"));
    let second = RocksDbReader::open(&primary, &root.path().join("lane_b")).unwrap();
    assert_generation(&first, 1);
    assert_generation(&second, 2);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let reopened = RocksDbStorage::open(&primary).unwrap();
    assert_generation(&reopened, 2);
    reopened.apply_atomic(&batch(2)).unwrap();
    assert_generation(&reopened, 2);
    drop(first);
    let fresh = RocksDbReader::open(&primary, &root.path().join("lane_a")).unwrap();
    assert_generation(&fresh, 2);
}
