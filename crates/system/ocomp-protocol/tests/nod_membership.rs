use alloy_primitives::{address, B256, U256};
use outbe_ocomp_protocol::{
    list::streaming_ordered_list_membership_proof,
    profile::poc_schema_limits,
    registry::ListKind,
    result::{ActiveNodSetV1, NodActionV1, NodMembershipProofV1},
    StreamingOrderedListRoot,
};

const WWD: u32 = 20_260_726;

fn entity_id(seed: u8) -> B256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&WWD.to_be_bytes());
    bytes[31] = seed;
    B256::from(bytes)
}

fn action(ordinal: u32) -> NodActionV1 {
    NodActionV1 {
        raw_ordinal: ordinal,
        tribute_id: entity_id(ordinal as u8 + 1),
        nod_id: entity_id(ordinal as u8 + 101),
        owner: address!("1000000000000000000000000000000000000001"),
        wwd: WWD,
        league_id: 7,
        floor_price_minor: U256::from(1_000 + ordinal),
        gratis_load_minor: U256::from(100 + ordinal),
        entry_price_minor: U256::from(20 + ordinal),
        cost_amount_minor: U256::from(120 + ordinal),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_785_024_000,
        bucket_key: B256::with_last_byte(ordinal as u8 + 1),
    }
}

fn fixture() -> (ActiveNodSetV1, NodMembershipProofV1) {
    let limits = poc_schema_limits();
    let actions = (0..3).map(action).collect::<Vec<_>>();
    let canonical_actions = actions
        .iter()
        .map(|action| action.encode_canonical_record(&limits).unwrap())
        .collect::<Vec<_>>();
    let mut root = StreamingOrderedListRoot::new(ListKind::NodActions, 3).unwrap();
    for action in &canonical_actions {
        root.push(action, limits.codec.max_body_bytes).unwrap();
    }
    let nod_root = root.finish().unwrap();
    let membership_siblings = streaming_ordered_list_membership_proof(
        ListKind::NodActions,
        3,
        1,
        &canonical_actions,
        limits.codec.max_body_bytes,
    )
    .unwrap();
    let authority = ActiveNodSetV1 {
        job_id: B256::with_last_byte(11),
        program_semantics_hash: B256::with_last_byte(12),
        worldwide_day: WWD,
        generation: 4,
        nod_root,
        nod_count: 3,
    };
    let proof = NodMembershipProofV1 {
        job_id: authority.job_id,
        program_semantics_hash: authority.program_semantics_hash,
        worldwide_day: authority.worldwide_day,
        generation: authority.generation,
        nod_ordinal: 1,
        action: actions[1].clone(),
        membership_siblings,
    };
    (authority, proof)
}

#[test]
fn finalized_active_nod_accepts_its_canonical_membership_proof() {
    let limits = poc_schema_limits();
    let (authority, proof) = fixture();

    let verified = proof.verify_against(&authority, &limits).unwrap();

    assert_eq!(verified, &proof.action);
}

#[test]
fn altered_nod_body_is_not_a_member_of_the_active_nod_root() {
    let limits = poc_schema_limits();
    let (authority, mut proof) = fixture();
    proof.action.cost_amount_minor += U256::from(1);

    assert!(proof.verify_against(&authority, &limits).is_err());
}

#[test]
fn altered_merkle_path_is_not_a_member_of_the_active_nod_root() {
    let limits = poc_schema_limits();
    let (authority, mut proof) = fixture();
    proof.membership_siblings[0] = B256::with_last_byte(99);

    assert!(proof.verify_against(&authority, &limits).is_err());
}

#[test]
fn proof_cannot_be_substituted_across_active_jobs_or_generations() {
    let limits = poc_schema_limits();
    let (authority, proof) = fixture();

    let mut different_job = authority;
    different_job.job_id = B256::with_last_byte(44);
    assert!(proof.verify_against(&different_job, &limits).is_err());

    let mut different_program = authority;
    different_program.program_semantics_hash = B256::with_last_byte(45);
    assert!(proof.verify_against(&different_program, &limits).is_err());

    let mut different_generation = authority;
    different_generation.generation += 1;
    assert!(proof
        .verify_against(&different_generation, &limits)
        .is_err());

    let mut different_day = authority;
    different_day.worldwide_day += 1;
    assert!(proof.verify_against(&different_day, &limits).is_err());
}

#[test]
fn nod_proof_round_trip_preserves_the_verified_public_read() {
    let limits = poc_schema_limits();
    let (authority, proof) = fixture();

    let encoded = proof.encode_canonical_record(&limits).unwrap();
    let decoded = NodMembershipProofV1::decode_canonical_record(&encoded, &limits).unwrap();

    assert_eq!(
        decoded.verify_against(&authority, &limits).unwrap(),
        &proof.action
    );
}
