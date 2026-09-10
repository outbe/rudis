use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::WwdEntityId;
use outbe_offchain_storage::{
    AtomicWriteBatch, Key, MemoryStorage, Namespace, StorageReaderHandle, StorageWriterHandle,
    Value,
};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{
    RetainedTributePin, RetainedTributeReader, RetainedTributeWriter, TributeData,
    TributeRepositoryError, TributeRepositoryReader, TributeRepositoryWriter,
    OCOMP_RETAINED_TRIBUTES_NAMESPACE,
};

fn tribute(day: WorldwideDay, discriminator: u8) -> TributeData {
    TributeData {
        tribute_id: WwdEntityId::from_day_and_digest(day, [discriminator; 32]),
        owner: Address::repeat_byte(discriminator),
        worldwide_day: day,
        issuance_amount_minor: U256::from(1_000_u64),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(700_u64),
        reference_currency: 840,
        tribute_price_minor: U256::from(2_u64),
        exclude_from_intex_issuance: false,
    }
}

#[test]
fn atomic_retirement_keeps_exact_job_scoped_bytes_until_exact_job_gc() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let current_reader = TributeRepositoryReader::new(reader.clone());
    let current_writer = TributeRepositoryWriter::new(reader.clone(), writer.clone());
    let retained = RetainedTributeReader::new(reader.clone());
    let retained_writer = RetainedTributeWriter::new(reader, writer.clone());
    let day = WorldwideDay::new(20260724);
    let body = tribute(day, 0x31);
    current_writer.put(&body).unwrap();

    let first = RetainedTributePin {
        input_lease_id: B256::repeat_byte(0x41),
        worldwide_day: day,
    };
    let second = RetainedTributePin {
        input_lease_id: B256::repeat_byte(0x42),
        worldwide_day: day,
    };
    let first_copy = retained
        .plan_retain_current(first, body.tribute_id)
        .unwrap();
    let second_copy = retained
        .plan_retain_current(second, body.tribute_id)
        .unwrap();
    let mut current = current_reader
        .projection_session(&[body.tribute_id])
        .unwrap();
    let current_delete = current.delete(body.tribute_id).unwrap();

    let mut retirement = AtomicWriteBatch::new();
    retirement.extend(first_copy.operations().iter().cloned());
    retirement.extend(second_copy.operations().iter().cloned());
    retirement.extend(current_delete.operations().iter().cloned());
    writer.apply_atomic(&retirement).unwrap();

    assert!(current_reader.get(body.tribute_id).unwrap().is_none());
    for pin in [first, second] {
        let page = retained.list_by_day(pin, None, 4).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].tribute_id, body.tribute_id);
        assert_eq!(
            retained
                .get_current_or_retained(pin, body.tribute_id, page.records[0].body_commitment,)
                .unwrap()
                .unwrap()
                .payload(),
            outbe_compressed_entities::encode_tribute_v1(&outbe_tribute::canonical_body(&body))
                .unwrap()
        );
    }

    assert!(retained_writer
        .release_input_lease_page(first.input_lease_id)
        .unwrap());
    assert!(retained
        .list_by_day(first, None, 4)
        .unwrap()
        .records
        .is_empty());
    assert_eq!(
        retained.list_by_day(second, None, 4).unwrap().records.len(),
        1
    );

    assert!(retained_writer
        .release_input_lease_page(first.input_lease_id)
        .unwrap());
    assert!(retained_writer
        .release_input_lease_page(second.input_lease_id)
        .unwrap());
    assert!(retained
        .list_by_day(second, None, 4)
        .unwrap()
        .records
        .is_empty());
}

#[test]
fn immutable_retained_key_rejects_changed_bytes_instead_of_overwriting_them() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let current_writer = TributeRepositoryWriter::new(reader.clone(), writer.clone());
    let retained = RetainedTributeReader::new(reader);
    let day = WorldwideDay::new(20260724);
    let body = tribute(day, 0x51);
    current_writer.put(&body).unwrap();
    let pin = RetainedTributePin {
        input_lease_id: B256::repeat_byte(0x61),
        worldwide_day: day,
    };

    let initial = retained.plan_retain_current(pin, body.tribute_id).unwrap();
    writer.apply_atomic(&initial).unwrap();
    let reference = retained.list_by_day(pin, None, 1).unwrap().records[0];
    let retained_key = Key::new(
        [
            pin.input_lease_id.as_slice(),
            &day.value().to_be_bytes(),
            body.tribute_id.as_slice(),
            reference.body_commitment.as_slice(),
        ]
        .concat(),
    )
    .unwrap();
    writer
        .put(
            Namespace::new(OCOMP_RETAINED_TRIBUTES_NAMESPACE).unwrap(),
            &retained_key,
            &Value::new(vec![0xff]).unwrap(),
        )
        .unwrap();

    assert!(matches!(
        retained.plan_retain_current(pin, body.tribute_id),
        Err(TributeRepositoryError::CanonicalBody(_))
            | Err(TributeRepositoryError::ConflictingRetainedBody { .. })
    ));
}

#[test]
fn retained_selector_rejects_a_body_from_another_worldwide_day() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let current_writer = TributeRepositoryWriter::new(reader.clone(), writer);
    let retained = RetainedTributeReader::new(reader);
    let body = tribute(WorldwideDay::new(20260724), 0x71);
    current_writer.put(&body).unwrap();
    let wrong_day = RetainedTributePin {
        input_lease_id: B256::repeat_byte(0x72),
        worldwide_day: WorldwideDay::new(20260725),
    };

    assert!(matches!(
        retained.plan_retain_current(wrong_day, body.tribute_id),
        Err(TributeRepositoryError::RetainedDayMismatch { .. })
    ));
}

#[test]
fn release_pages_across_the_work_shard_boundary_without_dropping_the_last_tribute() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let current_writer = TributeRepositoryWriter::new(reader.clone(), writer.clone());
    let retained = RetainedTributeReader::new(reader);
    let retained_writer = RetainedTributeWriter::new(storage.clone(), writer.clone());
    let day = WorldwideDay::new(20260724);
    let pin = RetainedTributePin {
        input_lease_id: B256::repeat_byte(0x81),
        worldwide_day: day,
    };
    let mut last_id = None;

    for ordinal in 0_u16..=256 {
        // The identity keeps only `digest[4..]`, so a discriminator in the
        // leading four bytes would collapse every ordinal onto one identity.
        let mut discriminator = [0_u8; 32];
        discriminator[4..6].copy_from_slice(&ordinal.to_be_bytes());
        let body = TributeData {
            tribute_id: WwdEntityId::from_day_and_digest(day, discriminator),
            owner: Address::repeat_byte(0x82),
            worldwide_day: day,
            issuance_amount_minor: U256::from(1_000_u64),
            issuance_currency: 840,
            nominal_amount_minor: U256::from(700_u64),
            reference_currency: 840,
            tribute_price_minor: U256::from(2_u64),
            exclude_from_intex_issuance: false,
        };
        last_id = Some(body.tribute_id);
        current_writer.put(&body).unwrap();
        let retain = retained.plan_retain_current(pin, body.tribute_id).unwrap();
        writer.apply_atomic(&retain).unwrap();
    }

    assert!(!retained_writer
        .release_input_lease_page(pin.input_lease_id)
        .unwrap());
    let second_page = retained.list_by_day(pin, None, 2).unwrap();
    assert_eq!(second_page.records.len(), 1);
    assert_eq!(second_page.records[0].tribute_id, last_id.unwrap());

    assert!(retained_writer
        .release_input_lease_page(pin.input_lease_id)
        .unwrap());
    assert!(retained
        .list_by_day(pin, None, 1)
        .unwrap()
        .records
        .is_empty());
    assert!(retained_writer
        .release_input_lease_page(pin.input_lease_id)
        .unwrap());
}
