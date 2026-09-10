use alloy_primitives::B256;
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    nod_materialization::MaterializationReferenceStoreV1,
};

#[test]
fn durable_materialization_references_survive_restart_and_release_only_the_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let cas_root = directory.path().join("cas");
    let reference_root = directory.path().join("materialization-refs");
    let limits = CasLimits {
        max_object_bytes: 64,
        max_total_bytes: 64,
    };
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::Supervisor, limits).unwrap();
    let object = cas.publish_bytes(&[0x11; 64]).unwrap();
    let job_id = B256::repeat_byte(0x22);

    MaterializationReferenceStoreV1::open(&reference_root)
        .unwrap()
        .pin_exact(job_id, std::slice::from_ref(&object))
        .unwrap();
    assert!(cas.publish_bytes(&[0x33; 64]).is_err());
    drop(cas);

    let restarted = MaterializationReferenceStoreV1::open(&reference_root).unwrap();
    assert_eq!(
        restarted.load_exact(job_id).unwrap(),
        Some(vec![object.clone()])
    );
    let reader = FilesystemCasReader::open(&cas_root, limits).unwrap();
    assert_eq!(reader.read_verified(&object).unwrap().bytes(), &[0x11; 64]);
    let restarted_writer =
        FilesystemCas::open(&cas_root, CasWriterRole::Supervisor, limits).unwrap();
    assert!(restarted_writer.publish_bytes(&[0x33; 64]).is_err());

    restarted.release(job_id).unwrap();
    assert_eq!(restarted.load_exact(job_id).unwrap(), None);
    assert_eq!(reader.read_verified(&object).unwrap().bytes(), &[0x11; 64]);
}

#[test]
fn an_exact_pin_replays_but_a_conflicting_dependency_set_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let store = MaterializationReferenceStoreV1::open(directory.path()).unwrap();
    let job_id = B256::repeat_byte(0x33);
    let first = outbe_ocomp_protocol::CasObjectRefV1 {
        transport_digest: B256::repeat_byte(0x44),
        encoded_bytes: 10,
        expected_ocb1_kind: None,
    };
    let conflicting = outbe_ocomp_protocol::CasObjectRefV1 {
        transport_digest: B256::repeat_byte(0x55),
        encoded_bytes: 10,
        expected_ocb1_kind: None,
    };

    store
        .pin_exact(job_id, std::slice::from_ref(&first))
        .unwrap();
    store.pin_exact(job_id, &[first]).unwrap();
    assert!(store.pin_exact(job_id, &[conflicting]).is_err());
}
