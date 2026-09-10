// OCOMP-TEST-ID: OCM-BND-003

use alloy_primitives::B256;
use outbe_ocomp_protocol::{
    codec::{CanonicalReader, CodecLimits},
    common::BoundedBytes,
    control::PreparedVoteTransactionV1,
    vote::OcompVoteAccountabilityV1,
    SchemaLimits,
};

const CODEC: CodecLimits = CodecLimits::new(4_096, 4, 4_096);
const LIMITS: SchemaLimits = SchemaLimits {
    codec: CODEC,
    max_bounded_bytes: 8,
    max_proof_bytes: 8,
    max_opening_bytes: 8,
    max_collection_items: 4,
    max_action_items: 4,
    max_chunk_items: 4,
    max_unit_inputs: 4,
    max_result_chunk_bytes: 8,
    max_control_body_bytes: 8,
};

#[test]
fn collection_cap_plus_one_rejects_before_reserving_items() {
    let encoded = 5_u32.to_be_bytes();
    let mut reader = CanonicalReader::new(&encoded, CODEC).unwrap();
    assert!(reader
        .read_vec::<u64>(4, 8, |input| input.read_u64())
        .is_err());
    assert_eq!(reader.allocation_stats().reservations, 0);
    assert_eq!(reader.allocation_stats().reserved_bytes, 0);
}

#[test]
fn prepared_vote_cap_plus_one_rejects_before_body_encode() {
    let response = PreparedVoteTransactionV1 {
        canonical_vote: BoundedBytes(vec![0; LIMITS.max_control_body_bytes + 1]),
        raw_transaction: BoundedBytes(vec![1]),
        transaction_hash: B256::repeat_byte(1),
    };
    assert!(response.encode_body(&LIMITS).is_err());
}

#[test]
fn vote_state_rejects_slot_count_different_from_declared_n_before_crypto_work() {
    let mut accountability =
        OcompVoteAccountabilityV1::empty([1; 32].into(), 1, [2; 32].into(), [3; 32].into(), 4, 3)
            .unwrap();
    accountability.slots.push(None);
    let error = accountability
        .validate_semantics(&LIMITS)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "invalid invariant: accountability slot count");
}

#[test]
fn prepared_vote_decode_rejects_a_truncated_body() {
    let response = PreparedVoteTransactionV1 {
        canonical_vote: BoundedBytes(vec![1, 2]),
        raw_transaction: BoundedBytes(vec![3, 4]),
        transaction_hash: B256::repeat_byte(1),
    };
    let mut encoded = response.encode_body(&LIMITS).unwrap();
    encoded.pop();
    assert!(PreparedVoteTransactionV1::decode_body(&encoded, &LIMITS).is_err());
}
