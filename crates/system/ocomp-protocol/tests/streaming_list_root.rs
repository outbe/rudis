use outbe_ocomp_protocol::list::{
    leaf_hash, node_hash, pad_hash, streaming_ordered_list_membership_proof,
    verify_ordered_list_membership,
};
use outbe_ocomp_protocol::{
    ordered_list_root, registry::ListKind, OrderedListLimits, StreamingOrderedListRoot,
};

#[test]
fn streaming_root_matches_the_frozen_ordered_list_scheme_without_a_catalog_vector() {
    let limits = OrderedListLimits::new(16, 64, 16 * 32);
    for count in 1_u32..=9 {
        let items = (0..count)
            .map(|index| format!("unit-{index}").into_bytes())
            .collect::<Vec<_>>();
        let expected =
            ordered_list_root(ListKind::UnitSpecificationsArtifacts, &items, limits).unwrap();

        let mut streaming =
            StreamingOrderedListRoot::new(ListKind::UnitSpecificationsArtifacts, count).unwrap();
        for item in &items {
            streaming.push(item, 64).unwrap();
        }
        assert_eq!(streaming.finish().unwrap(), expected);
    }
}

#[test]
fn streaming_root_requires_the_exact_declared_population() {
    let mut root = StreamingOrderedListRoot::new(ListKind::UnitSpecificationsArtifacts, 3).unwrap();
    root.push(b"first", 64).unwrap();
    root.push(b"second", 64).unwrap();
    assert!(root.finish().is_err());

    let mut root = StreamingOrderedListRoot::new(ListKind::UnitSpecificationsArtifacts, 1).unwrap();
    root.push(b"first", 64).unwrap();
    assert!(root.push(b"extra", 64).is_err());
}

#[test]
fn ordered_list_membership_binds_item_position_population_and_root() {
    let kind = ListKind::UnitSpecificationsArtifacts;
    let items = [
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ];
    let expected =
        ordered_list_root(kind, &items, OrderedListLimits::new(16, 64, 16 * 32)).unwrap();
    let left_root = node_hash(
        kind,
        1,
        0,
        leaf_hash(kind, 0, items[0]).unwrap(),
        leaf_hash(kind, 1, items[1]).unwrap(),
    )
    .unwrap();
    let proof = [pad_hash(kind, 3).unwrap(), left_root];

    verify_ordered_list_membership(kind, 3, 2, items[2], &proof, expected).unwrap();
    assert!(verify_ordered_list_membership(kind, 3, 2, b"changed", &proof, expected).is_err());
    assert!(verify_ordered_list_membership(kind, 3, 1, items[2], &proof, expected).is_err());
    assert!(verify_ordered_list_membership(kind, 4, 2, items[2], &proof, expected).is_err());

    let mut changed_proof = proof;
    changed_proof[0] = leaf_hash(kind, 3, b"not padding").unwrap();
    assert!(
        verify_ordered_list_membership(kind, 3, 2, items[2], &changed_proof, expected).is_err()
    );
}

#[test]
fn streaming_membership_proof_uses_exact_order_with_bounded_frontier_memory() {
    let kind = ListKind::UnitSpecificationsArtifacts;
    for count in [1_u32, 2, 3, 257] {
        for target in [0, count / 2, count - 1] {
            let proof = streaming_ordered_list_membership_proof(
                kind,
                count,
                target,
                (0..count).map(|index| index.to_be_bytes()),
                4,
            )
            .unwrap();
            let target_item = target.to_be_bytes();
            let expected = {
                let mut root = StreamingOrderedListRoot::new(kind, count).unwrap();
                for index in 0..count {
                    root.push(&index.to_be_bytes(), 4).unwrap();
                }
                root.finish().unwrap()
            };
            verify_ordered_list_membership(kind, count, target, &target_item, &proof, expected)
                .unwrap();
            assert!(proof.len() <= u32::BITS as usize);
        }
    }
}
