use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    body_commitment, decode_tribute_v1, encode_tribute_v1, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
    BODY_SCHEMA_V1,
};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{canonical_body, from_canonical_body, precompile::ITribute, TributeData};

fn identity(day: WorldwideDay, seed: U256) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(day, seed.to_be_bytes::<32>())
}

fn assert_roundtrip(record: TributeData) {
    let payload = encode_tribute_v1(&canonical_body(&record)).unwrap();
    let commitment = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        record.tribute_id,
        &payload,
    )
    .unwrap();
    let event = ITribute::TributeBodyStored {
        tributeId: record.tribute_id.to_u256(),
        commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
        schemaVersion: BODY_SCHEMA_V1,
        previousCommitment: B256::ZERO,
        newCommitment: B256::from(*commitment.as_bytes()),
        canonicalPayload: Bytes::from(payload.clone()),
    };

    let decoded = ITribute::TributeBodyStored::decode_log_data(&event.encode_log_data()).unwrap();
    let decoded_id = WwdEntityId::from(decoded.tributeId);
    let reconstructed = from_canonical_body(decode_tribute_v1(&decoded.canonicalPayload).unwrap());

    assert_eq!(decoded_id, record.tribute_id);
    assert_eq!(decoded.canonicalPayload.as_ref(), payload);
    assert_eq!(decoded.newCommitment, B256::from(*commitment.as_bytes()));
    assert_eq!(reconstructed.tribute_id, record.tribute_id);
    assert_eq!(reconstructed.owner, record.owner);
    assert_eq!(reconstructed.worldwide_day, record.worldwide_day);
    assert_eq!(
        reconstructed.issuance_amount_minor,
        record.issuance_amount_minor
    );
    assert_eq!(reconstructed.issuance_currency, record.issuance_currency);
    assert_eq!(
        reconstructed.nominal_amount_minor,
        record.nominal_amount_minor
    );
    assert_eq!(reconstructed.reference_currency, record.reference_currency);
    assert_eq!(
        reconstructed.tribute_price_minor,
        record.tribute_price_minor
    );
    assert_eq!(
        reconstructed.exclude_from_intex_issuance,
        record.exclude_from_intex_issuance
    );
}

#[test]
fn stored_event_carries_the_exact_canonical_body_and_commitment() {
    let day = WorldwideDay::new(20_241_220);
    assert_roundtrip(TributeData {
        tribute_id: identity(day, U256::from(1)),
        owner: Address::ZERO,
        worldwide_day: day,
        issuance_amount_minor: U256::ZERO,
        issuance_currency: 0,
        nominal_amount_minor: U256::ZERO,
        reference_currency: 0,
        tribute_price_minor: U256::ZERO,
        exclude_from_intex_issuance: false,
    });
    let max_day = WorldwideDay::new(u32::MAX);
    assert_roundtrip(TributeData {
        tribute_id: identity(max_day, U256::MAX),
        owner: Address::repeat_byte(u8::MAX),
        worldwide_day: max_day,
        issuance_amount_minor: U256::MAX,
        issuance_currency: u16::MAX,
        nominal_amount_minor: U256::MAX,
        reference_currency: u16::MAX,
        tribute_price_minor: U256::MAX,
        exclude_from_intex_issuance: true,
    });
}

#[test]
fn transition_event_signatures_and_delete_receipt_are_pinned() {
    assert_eq!(
        ITribute::TributeBodyStored::SIGNATURE_HASH,
        keccak256("TributeBodyStored(uint256,uint32,uint32,bytes32,bytes32,bytes)")
    );
    assert_eq!(
        ITribute::TributeBodyDeleted::SIGNATURE_HASH,
        keccak256("TributeBodyDeleted(uint256,bytes32)")
    );
    let tribute_id = identity(WorldwideDay::new(20_241_220), U256::MAX);
    let previous = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        tribute_id,
        b"non-empty canonical fixture",
    )
    .unwrap();
    let log = ITribute::TributeBodyDeleted {
        tributeId: tribute_id.to_u256(),
        previousCommitment: B256::from(*previous.as_bytes()),
    }
    .encode_log_data();
    let decoded = ITribute::TributeBodyDeleted::decode_log_data(&log).unwrap();
    assert_eq!(log.topics().len(), 1);
    assert_eq!(WwdEntityId::from(decoded.tributeId), tribute_id);
    assert_eq!(decoded.previousCommitment, B256::from(*previous.as_bytes()));
}
