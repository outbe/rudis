use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    body_commitment, decode_nod_bucket_v1, decode_nod_item_v1, encode_nod_bucket_v1,
    encode_nod_item_v1, WwdEntityId, ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_nod::{
    canonical_bucket, canonical_bucket_id, canonical_item, from_canonical_bucket,
    from_canonical_item, precompile::INod, NodBucketState, NodItemState,
};
use outbe_primitives::time::WorldwideDay;

fn identity(day: WorldwideDay, seed: U256) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(day, seed.to_be_bytes::<32>())
}

fn assert_item_roundtrip(record: NodItemState) {
    let payload = encode_nod_item_v1(&canonical_item(&record)).unwrap();
    let commitment = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        record.nod_id,
        &payload,
    )
    .unwrap();
    let event = INod::NodBodyStored {
        nodId: record.nod_id.to_u256(),
        commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
        schemaVersion: BODY_SCHEMA_V1,
        previousCommitment: B256::ZERO,
        newCommitment: B256::from(*commitment.as_bytes()),
        canonicalPayload: Bytes::from(payload.clone()),
    };

    let log = event.encode_log_data();
    let decoded = INod::NodBodyStored::decode_log_data(&log).unwrap();
    let decoded_id = WwdEntityId::from(decoded.nodId);
    let reconstructed = from_canonical_item(decode_nod_item_v1(&decoded.canonicalPayload).unwrap());

    assert_eq!(log.topics(), &[INod::NodBodyStored::SIGNATURE_HASH]);
    assert_eq!(decoded_id, record.nod_id);
    assert_eq!(decoded.commitmentSchemeVersion, ACTIVE_COMMITMENT_SCHEME);
    assert_eq!(decoded.schemaVersion, BODY_SCHEMA_V1);
    assert_eq!(decoded.previousCommitment, B256::ZERO);
    assert_eq!(decoded.newCommitment, B256::from(*commitment.as_bytes()));
    assert_eq!(decoded.canonicalPayload.as_ref(), payload);
    assert_eq!(reconstructed.nod_id, record.nod_id);
    assert_eq!(reconstructed.owner, record.owner);
    assert_eq!(reconstructed.gratis_load_minor, record.gratis_load_minor);
    assert_eq!(reconstructed.worldwide_day, record.worldwide_day);
    assert_eq!(reconstructed.league_id, record.league_id);
    assert_eq!(reconstructed.floor_price_minor, record.floor_price_minor);
    assert_eq!(reconstructed.bucket_key, record.bucket_key);
    assert_eq!(reconstructed.issuance_currency, record.issuance_currency);
    assert_eq!(reconstructed.reference_currency, record.reference_currency);
    assert_eq!(reconstructed.issued_at, record.issued_at);
}

fn assert_bucket_roundtrip(record: NodBucketState) {
    let bucket_id = canonical_bucket_id(&record);
    let payload = encode_nod_bucket_v1(&canonical_bucket(&record)).unwrap();
    let commitment = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        bucket_id,
        &payload,
    )
    .unwrap();
    let event = INod::NodBucketBodyStored {
        bucketId: bucket_id.to_u256(),
        commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
        schemaVersion: BODY_SCHEMA_V1,
        previousCommitment: B256::ZERO,
        newCommitment: B256::from(*commitment.as_bytes()),
        canonicalPayload: Bytes::from(payload.clone()),
    };

    let log = event.encode_log_data();
    let decoded = INod::NodBucketBodyStored::decode_log_data(&log).unwrap();
    let decoded_id = WwdEntityId::from(decoded.bucketId);
    let reconstructed =
        from_canonical_bucket(decode_nod_bucket_v1(&decoded.canonicalPayload).unwrap());

    assert_eq!(log.topics(), &[INod::NodBucketBodyStored::SIGNATURE_HASH]);
    assert_eq!(decoded_id, bucket_id);
    assert_eq!(decoded.commitmentSchemeVersion, ACTIVE_COMMITMENT_SCHEME);
    assert_eq!(decoded.schemaVersion, BODY_SCHEMA_V1);
    assert_eq!(decoded.previousCommitment, B256::ZERO);
    assert_eq!(decoded.newCommitment, B256::from(*commitment.as_bytes()));
    assert_eq!(decoded.canonicalPayload.as_ref(), payload);
    assert_eq!(reconstructed.bucket_key, record.bucket_key);
    assert_eq!(reconstructed.worldwide_day, record.worldwide_day);
    assert_eq!(reconstructed.floor_price_minor, record.floor_price_minor);
    assert_eq!(reconstructed.is_qualified, record.is_qualified);
    assert_eq!(reconstructed.total_nods, record.total_nods);
    assert_eq!(reconstructed.entry_price_minor, record.entry_price_minor);
    assert_eq!(reconstructed.reference_currency, record.reference_currency);
}

#[test]
fn stored_events_carry_exact_canonical_nod_bodies_and_commitments() {
    let zero_day = WorldwideDay::new(0);
    assert_item_roundtrip(NodItemState {
        nod_id: identity(zero_day, U256::ZERO),
        owner: Address::ZERO,
        gratis_load_minor: U256::ZERO,
        worldwide_day: zero_day,
        league_id: 0,
        floor_price_minor: U256::ZERO,
        bucket_key: B256::ZERO,
        issuance_currency: 0,
        reference_currency: 0,
        issued_at: 0,
    });
    let max_day = WorldwideDay::new(u32::MAX);
    assert_item_roundtrip(NodItemState {
        nod_id: identity(max_day, U256::MAX),
        owner: Address::repeat_byte(u8::MAX),
        gratis_load_minor: U256::MAX,
        worldwide_day: max_day,
        league_id: u16::MAX,
        floor_price_minor: U256::MAX,
        bucket_key: B256::repeat_byte(u8::MAX),
        issuance_currency: u16::MAX,
        reference_currency: u16::MAX,
        issued_at: u64::MAX,
    });
    assert_bucket_roundtrip(NodBucketState {
        bucket_key: B256::ZERO,
        worldwide_day: WorldwideDay::new(0),
        floor_price_minor: U256::ZERO,
        is_qualified: false,
        total_nods: 0,
        entry_price_minor: U256::ZERO,
        reference_currency: 0,
    });
    assert_bucket_roundtrip(NodBucketState {
        bucket_key: B256::repeat_byte(u8::MAX),
        worldwide_day: WorldwideDay::new(u32::MAX),
        floor_price_minor: U256::MAX,
        is_qualified: true,
        total_nods: u64::MAX,
        entry_price_minor: U256::MAX,
        reference_currency: u16::MAX,
    });
}

#[test]
fn transition_event_signatures_topics_and_delete_payloads_are_pinned() {
    assert_eq!(
        INod::NodBodyStored::SIGNATURE_HASH,
        keccak256("NodBodyStored(uint256,uint32,uint32,bytes32,bytes32,bytes)")
    );
    assert_eq!(
        INod::NodBucketBodyStored::SIGNATURE_HASH,
        keccak256("NodBucketBodyStored(uint256,uint32,uint32,bytes32,bytes32,bytes)")
    );
    assert_eq!(
        INod::NodBodyDeleted::SIGNATURE_HASH,
        keccak256("NodBodyDeleted(uint256,bytes32)")
    );
    assert_eq!(
        INod::NodBucketBodyDeleted::SIGNATURE_HASH,
        keccak256("NodBucketBodyDeleted(uint256,bytes32)")
    );

    let day = WorldwideDay::new(20_260_715);
    let nod_id = identity(day, U256::MAX);
    let previous_item = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        nod_id,
        b"non-empty canonical Nod item fixture",
    )
    .unwrap();
    let item_log = INod::NodBodyDeleted {
        nodId: nod_id.to_u256(),
        previousCommitment: B256::from(*previous_item.as_bytes()),
    }
    .encode_log_data();
    let decoded_item = INod::NodBodyDeleted::decode_log_data(&item_log).unwrap();
    assert_eq!(item_log.topics(), &[INod::NodBodyDeleted::SIGNATURE_HASH]);
    assert_eq!(WwdEntityId::from(decoded_item.nodId), nod_id);
    assert_eq!(
        decoded_item.previousCommitment,
        B256::from(*previous_item.as_bytes())
    );

    let bucket_key = B256::repeat_byte(0xab);
    let bucket_id = WwdEntityId::from_day_and_digest(day, bucket_key.0);
    let previous_bucket = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        bucket_id,
        b"non-empty canonical Nod bucket fixture",
    )
    .unwrap();
    let bucket_log = INod::NodBucketBodyDeleted {
        bucketId: bucket_id.to_u256(),
        previousCommitment: B256::from(*previous_bucket.as_bytes()),
    }
    .encode_log_data();
    let decoded_bucket = INod::NodBucketBodyDeleted::decode_log_data(&bucket_log).unwrap();
    assert_eq!(
        bucket_log.topics(),
        &[INod::NodBucketBodyDeleted::SIGNATURE_HASH]
    );
    assert_eq!(WwdEntityId::from(decoded_bucket.bucketId), bucket_id);
    assert_eq!(
        decoded_bucket.previousCommitment,
        B256::from(*previous_bucket.as_bytes())
    );
}
