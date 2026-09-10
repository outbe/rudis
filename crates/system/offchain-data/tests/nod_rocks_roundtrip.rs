//! Isolate canonical NOD serialization and durable RocksDB byte preservation.

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    body_commitment, decode_nod_item_v1, encode_nod_item_v1, NodItemBodyV1, StoredBody,
    WwdEntityId, ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_offchain_storage::{Key, Namespace, RocksDbStorage, StorageReader, StorageWriter, Value};
use outbe_primitives::time::WorldwideDay;

#[test]
fn nod_bytes_and_commitment_survive_rocksdb_write_read_and_reopen() {
    let day = WorldwideDay::new(20260906);
    let nod = NodItemBodyV1 {
        nod_id: WwdEntityId::from_day_and_digest(day, B256::repeat_byte(0xa5)),
        owner: Address::repeat_byte(0x73),
        gratis_load_minor: U256::from_be_bytes([0xa7; 32]),
        worldwide_day: day,
        league_id: 257,
        floor_price_minor: U256::from(123_456_789),
        bucket_key: B256::repeat_byte(0xff),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_788_652_800,
    };
    let payload = encode_nod_item_v1(&nod).unwrap();
    let expected_commitment = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        nod.nod_id,
        &payload,
    )
    .unwrap();
    let stored_bytes = StoredBody::new_v1(payload.clone()).unwrap().encode();
    let value = Value::new(stored_bytes.clone()).unwrap();
    let namespace = Namespace::new("nods").unwrap();
    let key = Key::new(nod.nod_id.as_slice().to_vec()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rocksdb");

    let assert_roundtrip = |storage: &RocksDbStorage, stage: &str| {
        let read_value = storage.get(namespace.clone(), &key).unwrap().unwrap();
        assert_eq!(read_value.as_bytes(), stored_bytes, "stored bytes: {stage}");
        let read_body = StoredBody::decode(read_value.as_bytes()).unwrap();
        assert_eq!(read_body.payload(), payload, "payload bytes: {stage}");
        let actual_commitment = body_commitment(
            ACTIVE_COMMITMENT_SCHEME,
            read_body.schema_version(),
            nod.nod_id,
            read_body.payload(),
        )
        .unwrap();
        assert_eq!(
            actual_commitment, expected_commitment,
            "commitment: {stage}"
        );
        assert_eq!(
            decode_nod_item_v1(read_body.payload()).unwrap(),
            nod,
            "NOD fields: {stage}"
        );
    };

    let storage = RocksDbStorage::open(&path).unwrap();
    storage.put(namespace.clone(), &key, &value).unwrap();
    assert_roundtrip(&storage, "after write");
    drop(storage);

    let reopened = RocksDbStorage::open(&path).unwrap();
    assert_roundtrip(&reopened, "after close and reopen");
}
