use alloy_primitives::{Address, B256, U256};
use outbe_ocomp_protocol::{
    abi::{encode_materialize_certified_nods_calldata, NOD_FACTORY_ADDRESS},
    list::{ordered_list_root, streaming_ordered_list_membership_proof, OrderedListLimits},
    nod_materialization::{
        verify_nod_materialization_batch, NodMaterializationBatchV1, NodMaterializationHeadV1,
    },
    profile::poc_schema_limits,
    result::NodActionV1,
    system_carrier::{
        classify_ocomp_system_carrier, OcompSystemCarrierCandidate, OcompSystemCarrierError,
        OcompSystemCarrierView, MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
        OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
    },
    ListKind,
};

const WWD: u32 = 20_260_812;

fn entity_id(seed: u32) -> B256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&WWD.to_be_bytes());
    bytes[28..].copy_from_slice(&seed.to_be_bytes());
    B256::from(bytes)
}

fn action(ordinal: u32) -> NodActionV1 {
    NodActionV1 {
        raw_ordinal: ordinal,
        tribute_id: entity_id(ordinal + 1),
        nod_id: entity_id(ordinal + 101),
        owner: Address::from_word(B256::from(U256::from(ordinal + 1))),
        wwd: WWD,
        league_id: 1,
        floor_price_minor: U256::from(500),
        gratis_load_minor: U256::from(1_000),
        entry_price_minor: U256::from(510),
        cost_amount_minor: U256::from(2),
        issuance_currency: 840,
        reference_currency: 840,
        issued_at: 1_700_000_000,
        bucket_key: B256::from(U256::from(ordinal + 201)),
    }
}

fn population(count: u32) -> (Vec<NodActionV1>, B256, Vec<Vec<B256>>) {
    let limits = poc_schema_limits();
    let actions = (0..count).map(action).collect::<Vec<_>>();
    let encoded = actions
        .iter()
        .map(|action| action.encode_canonical_record(&limits).unwrap())
        .collect::<Vec<_>>();
    let root = ordered_list_root(
        ListKind::NodActions,
        &encoded,
        OrderedListLimits::new(512, limits.max_bounded_bytes, 1 << 20),
    )
    .unwrap();
    let proofs = (0..count)
        .map(|ordinal| {
            streaming_ordered_list_membership_proof(
                ListKind::NodActions,
                count,
                ordinal,
                encoded.iter(),
                limits.max_bounded_bytes,
            )
            .unwrap()
        })
        .collect();
    (actions, root, proofs)
}

fn head(root: B256, count: u32, cursor: u32) -> NodMaterializationHeadV1 {
    NodMaterializationHeadV1 {
        queue_sequence: 1,
        job_id: B256::repeat_byte(0x11),
        program_semantics_hash: B256::repeat_byte(0x22),
        worldwide_day: WWD,
        generation: 1,
        nod_root: root,
        nod_count: count,
        next_nod_ordinal: cursor,
        last_progress_height: 90,
    }
}

fn batch(
    actions: &[NodActionV1],
    proofs: &[Vec<B256>],
    first: u32,
    count: usize,
    subtree_height: usize,
) -> NodMaterializationBatchV1 {
    NodMaterializationBatchV1 {
        queue_sequence: 1,
        first_nod_ordinal: first,
        actions: actions[first as usize..first as usize + count].to_vec(),
        root_path: proofs[first as usize][subtree_height..].to_vec(),
    }
}

#[test]
fn canonical_batch_and_head_roundtrip_without_redundant_authority_fields() {
    let limits = poc_schema_limits();
    let (actions, root, proofs) = population(10);
    let head = head(root, 10, 0);
    let batch = batch(&actions, &proofs, 0, 8, 3);

    assert_eq!(
        NodMaterializationHeadV1::decode_canonical(
            &head.encode_canonical(&limits).unwrap(),
            &limits
        )
        .unwrap(),
        head
    );
    assert_eq!(
        NodMaterializationBatchV1::decode_canonical(
            &batch.encode_canonical(&limits).unwrap(),
            &limits
        )
        .unwrap(),
        batch
    );
}

#[test]
fn batch_codec_enforces_the_frozen_action_and_root_path_ceilings() {
    let limits = poc_schema_limits();
    let mut empty = NodMaterializationBatchV1 {
        queue_sequence: 1,
        first_nod_ordinal: 0,
        actions: Vec::new(),
        root_path: Vec::new(),
    };
    assert!(empty.encode_canonical(&limits).is_err());

    empty.actions = (0..=256).map(action).collect();
    assert!(empty.encode_canonical(&limits).is_err());

    empty.actions.truncate(1);
    empty.root_path = vec![B256::ZERO; 33];
    assert!(empty.encode_canonical(&limits).is_err());
}

#[test]
fn shared_root_path_verifies_a_full_batch_and_a_padded_final_remainder() {
    let limits = poc_schema_limits();
    let (actions, root, proofs) = population(10);

    let first = batch(&actions, &proofs, 0, 8, 3);
    let verified = verify_nod_materialization_batch(&first, &head(root, 10, 0), 3, &limits)
        .expect("full batch");
    assert_eq!(verified.actions(), &actions[..8]);

    let final_batch = batch(&actions, &proofs, 8, 2, 3);
    let verified = verify_nod_materialization_batch(&final_batch, &head(root, 10, 8), 3, &limits)
        .expect("final padded remainder");
    assert_eq!(verified.actions(), &actions[8..]);
}

#[test]
fn short_nonfinal_misaligned_unordered_and_bad_root_batches_are_rejected() {
    let limits = poc_schema_limits();
    let (actions, root, proofs) = population(17);

    let short = batch(&actions, &proofs, 0, 7, 3);
    assert!(verify_nod_materialization_batch(&short, &head(root, 17, 0), 3, &limits).is_err());

    let misaligned = batch(&actions, &proofs, 8, 8, 3);
    assert!(
        verify_nod_materialization_batch(&misaligned, &head(root, 17, 7), 3, &limits,).is_err()
    );

    let mut unordered = batch(&actions, &proofs, 0, 8, 3);
    unordered.actions.swap(0, 1);
    assert!(verify_nod_materialization_batch(&unordered, &head(root, 17, 0), 3, &limits,).is_err());

    let mut bad_root_path = batch(&actions, &proofs, 0, 8, 3);
    bad_root_path.root_path[0] = B256::repeat_byte(0xff);
    assert!(
        verify_nod_materialization_batch(&bad_root_path, &head(root, 17, 0), 3, &limits,).is_err()
    );
}

#[test]
fn materialization_uses_the_existing_strict_ocomp_system_carrier_lane() {
    let limits = poc_schema_limits();
    let (actions, _root, proofs) = population(10);
    let batch = batch(&actions, &proofs, 0, 8, 3);
    let input = encode_materialize_certified_nods_calldata(&batch, &limits).unwrap();
    let candidate = classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            is_eip1559: true,
            to: Some(NOD_FACTORY_ADDRESS),
            value: U256::ZERO,
            input: &input,
            gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            max_fee_per_gas: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: Some(0),
        },
        &limits,
    )
    .unwrap()
    .expect("materialization carrier");

    assert!(matches!(
        candidate,
        OcompSystemCarrierCandidate::NodMaterialization {
            queue_sequence: 1,
            first_nod_ordinal: 0
        }
    ));
}

#[test]
fn materialization_carrier_rejects_every_noncanonical_envelope_field() {
    let limits = poc_schema_limits();
    let (actions, _root, proofs) = population(8);
    let batch = batch(&actions, &proofs, 0, 8, 3);
    let input = encode_materialize_certified_nods_calldata(&batch, &limits).unwrap();
    let canonical = OcompSystemCarrierView {
        is_eip1559: true,
        to: Some(NOD_FACTORY_ADDRESS),
        value: U256::ZERO,
        input: &input,
        gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        max_fee_per_gas: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: Some(0),
    };

    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            to: Some(Address::repeat_byte(0xaa)),
            ..canonical
        },
        &limits,
    )
    .unwrap()
    .is_none());
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            is_eip1559: false,
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::NotEip1559)));
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            value: U256::from(1),
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::NonZeroValue)));
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT + 1,
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::WrongGasLimit { .. })));
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            max_fee_per_gas: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS - 1,
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::FeeCapTooLow { .. })));
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            max_priority_fee_per_gas: Some(1),
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::NonZeroPriorityFee)));

    let malformed = &input[..4];
    assert!(classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            input: malformed,
            ..canonical
        },
        &limits,
    )
    .is_err_and(|error| matches!(error, OcompSystemCarrierError::MalformedMaterialization(_))));
}
