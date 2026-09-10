mod support;

use std::collections::BTreeSet;

use alloy_primitives::{address, b256, B256, U256};
use outbe_ocomp_protocol::{
    codec::{
        decode_envelope, encode_envelope, ensure_strictly_increasing, require_canonical_reencoding,
        CanonicalReader, CanonicalWriter, CodecLimits, OCB1_HEADER_LEN,
    },
    hash::{framed_preimage, hash_framed, verify_framed_hash},
    list::{leaf_hash, node_hash, ordered_list_root, pad_hash, root_hash, OrderedListLimits},
    registry::{
        HashDomain, ListKind, ObjectKind, FIDELITY_OPENING_CODEC_DESCRIPTOR,
        FIDELITY_OPENING_CODEC_ID, OPENING_CODEC_REGISTRY_HASH, ORACLE_OPENING_CODEC_DESCRIPTOR,
        ORACLE_OPENING_CODEC_ID, TRIBUTE_BODY_CODEC_DESCRIPTOR, TRIBUTE_BODY_CODEC_ID,
    },
    ProtocolError,
};

use support::{envelope as independent_envelope, framed_hash as independent_hash};
use support::{ordered_root as independent_ordered_root, IndependentEncoder, IndependentReader};

const CODEC_LIMITS: CodecLimits = CodecLimits::new(4_096, 32, 4_096);
const LIST_LIMITS: OrderedListLimits = OrderedListLimits::new(16, 128, 512);

#[test]
fn production_scalar_bytes_match_independent_encoder() {
    let mut production = CanonicalWriter::new(CODEC_LIMITS);
    production.write_u8(u8::MAX).unwrap();
    production.write_u16(u16::MAX).unwrap();
    production.write_u32(u32::MAX).unwrap();
    production.write_u64(u64::MAX).unwrap();
    production.write_u128(u128::MAX).unwrap();
    production.write_u256(U256::MAX).unwrap();
    production
        .write_b256(b256!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ))
        .unwrap();
    production
        .write_address20(address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
        .unwrap();
    production.write_b256(B256::from([0xcc; 32])).unwrap();
    production.write_bool(false).unwrap();
    production.write_bool(true).unwrap();
    production
        .write_option::<u16>(None, |writer, value| writer.write_u16(*value))
        .unwrap();
    production
        .write_option(Some(&0x1234_u16), |writer, value| writer.write_u16(*value))
        .unwrap();
    production.write_bounded_bytes(&[1, 2, 3], 3).unwrap();
    production.write_utf8("λ", 2).unwrap();
    production.write_ascii("OCB1", 4).unwrap();
    production
        .write_vec(&[7_u16, 8_u16], 2, |writer, value| writer.write_u16(*value))
        .unwrap();

    let mut independent = IndependentEncoder::new();
    independent.u8(u8::MAX);
    independent.u16(u16::MAX);
    independent.u32(u32::MAX);
    independent.u64(u64::MAX);
    independent.u128(u128::MAX);
    independent.fixed(&[0xff; 32]);
    independent.fixed(&[0xaa; 32]);
    independent.fixed(&[0xbb; 20]);
    independent.fixed(&[0xcc; 32]);
    independent.boolean(false);
    independent.boolean(true);
    independent.u8(0);
    independent.u8(1);
    independent.u16(0x1234);
    independent.bounded(&[1, 2, 3]);
    independent.bounded("λ".as_bytes());
    independent.bounded(b"OCB1");
    independent.u32(2);
    independent.u16(7);
    independent.u16(8);

    assert_eq!(production.as_slice(), independent.finish());
}

#[test]
fn zero_and_exact_cap_boundaries_have_one_canonical_form() {
    let mut writer = CanonicalWriter::new(CodecLimits::new(32, 1, 64));
    writer.write_u8(0).unwrap();
    writer.write_u16(0).unwrap();
    writer.write_u32(0).unwrap();
    writer.write_u64(0).unwrap();
    writer.write_u128(0).unwrap();
    assert_eq!(writer.as_slice(), &[0; 31]);
    writer.write_u8(0).unwrap();
    assert_eq!(writer.len(), 32);
    assert!(matches!(
        writer.write_u8(0),
        Err(ProtocolError::CapacityExceeded {
            what: "canonical body bytes",
            limit: 32,
            actual: 33
        })
    ));

    let exact = encode_envelope(
        ObjectKind::JobIntentV1,
        &[0; 4],
        CodecLimits::new(4, 1, OCB1_HEADER_LEN + 4),
    )
    .unwrap();
    assert_eq!(exact.len(), OCB1_HEADER_LEN + 4);
    assert!(matches!(
        encode_envelope(
            ObjectKind::JobIntentV1,
            &[0; 5],
            CodecLimits::new(4, 1, OCB1_HEADER_LEN + 5)
        ),
        Err(ProtocolError::CapacityExceeded {
            what: "OCB1 body bytes",
            limit: 4,
            actual: 5
        })
    ));
}

#[test]
fn production_reader_round_trips_every_scalar_and_collection() {
    let mut writer = CanonicalWriter::new(CODEC_LIMITS);
    writer.write_u8(1).unwrap();
    writer.write_u16(2).unwrap();
    writer.write_u32(3).unwrap();
    writer.write_u64(4).unwrap();
    writer.write_u128(5).unwrap();
    writer.write_u256(U256::from(6)).unwrap();
    writer.write_b256(B256::repeat_byte(7)).unwrap();
    writer
        .write_address20(address!("0808080808080808080808080808080808080808"))
        .unwrap();
    writer.write_b256(B256::from([9; 32])).unwrap();
    writer.write_bool(true).unwrap();
    writer
        .write_option(Some(&10_u16), |output, value| output.write_u16(*value))
        .unwrap();
    writer.write_utf8("tribute", 32).unwrap();
    writer.write_ascii("NOD", 32).unwrap();
    writer
        .write_vec(&[11_u32, 12], 2, |output, value| output.write_u32(*value))
        .unwrap();

    let mut reader = CanonicalReader::new(writer.as_slice(), CODEC_LIMITS).unwrap();
    assert_eq!(reader.read_u8().unwrap(), 1);
    assert_eq!(reader.read_u16().unwrap(), 2);
    assert_eq!(reader.read_u32().unwrap(), 3);
    assert_eq!(reader.read_u64().unwrap(), 4);
    assert_eq!(reader.read_u128().unwrap(), 5);
    assert_eq!(reader.read_u256().unwrap(), U256::from(6));
    assert_eq!(reader.read_b256().unwrap(), B256::repeat_byte(7));
    assert_eq!(
        reader.read_address20().unwrap(),
        address!("0808080808080808080808080808080808080808")
    );
    assert_eq!(reader.read_b256().unwrap(), B256::from([9; 32]));
    assert!(reader.read_bool().unwrap());
    assert_eq!(
        reader.read_option(CanonicalReader::read_u16).unwrap(),
        Some(10)
    );
    assert_eq!(reader.read_utf8(32).unwrap(), "tribute");
    assert_eq!(reader.read_ascii(32).unwrap(), "NOD");
    assert_eq!(
        reader.read_vec(2, 4, CanonicalReader::read_u32).unwrap(),
        [11, 12]
    );
    assert_eq!(reader.finish().unwrap().reservations, 1);
}

#[test]
fn independent_reader_decodes_production_body() {
    let mut production = CanonicalWriter::new(CODEC_LIMITS);
    production.write_bool(true).unwrap();
    production.write_u16(0x1234).unwrap();
    production.write_bounded_bytes(b"lysis", 16).unwrap();
    let mut independent = IndependentReader::new(production.as_slice());
    assert_eq!(independent.boolean(), Some(true));
    assert_eq!(independent.u16(), Some(0x1234));
    assert_eq!(independent.bounded(), Some(b"lysis".as_slice()));
    assert!(independent.finished());
}

#[test]
fn option_boolean_enum_and_text_reject_unknown_or_invalid_values() {
    let mut boolean = CanonicalReader::new(&[2], CODEC_LIMITS).unwrap();
    assert_eq!(
        boolean.read_bool(),
        Err(ProtocolError::InvalidBoolean {
            offset: 0,
            value: 2
        })
    );

    let mut option = CanonicalReader::new(&[2], CODEC_LIMITS).unwrap();
    assert_eq!(
        option.read_option(CanonicalReader::read_u8),
        Err(ProtocolError::InvalidOptionTag {
            offset: 0,
            value: 2
        })
    );

    let mut enum_u8 = CanonicalReader::new(&[3], CODEC_LIMITS).unwrap();
    assert_eq!(
        enum_u8.read_enum_u8(&[1, 2]),
        Err(ProtocolError::UnknownEnum { width: 8, value: 3 })
    );
    let mut enum_u16 = CanonicalReader::new(&[0, 3], CODEC_LIMITS).unwrap();
    assert_eq!(
        enum_u16.read_enum_u16(&[1, 2]),
        Err(ProtocolError::UnknownEnum {
            width: 16,
            value: 3
        })
    );

    let mut invalid_utf8 = CanonicalReader::new(&[0, 0, 0, 1, 0xff], CODEC_LIMITS).unwrap();
    assert!(matches!(
        invalid_utf8.read_utf8(1),
        Err(ProtocolError::InvalidUtf8 { .. })
    ));
    let mut invalid_ascii = CanonicalReader::new(&[0, 0, 0, 2, 0xce, 0xbb], CODEC_LIMITS).unwrap();
    assert!(matches!(
        invalid_ascii.read_ascii(2),
        Err(ProtocolError::InvalidAscii { .. })
    ));
}

#[test]
fn cap_plus_one_rejects_before_collection_allocation() {
    let encoded = [0, 0, 0, 3, 1, 2, 3];
    let mut reader = CanonicalReader::new(&encoded, CODEC_LIMITS).unwrap();
    let error = reader.read_vec(2, 1, CanonicalReader::read_u8).unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::CapacityExceeded {
            what: "collection item count",
            limit: 2,
            actual: 3
        }
    ));
    assert_eq!(reader.allocation_stats().reservations, 0);
    assert_eq!(reader.allocation_stats().reserved_bytes, 0);

    let allocation_limited = CodecLimits::new(32, 4, 1);
    let mut reader = CanonicalReader::new(&[0, 0, 0, 1, 1, 0], allocation_limited).unwrap();
    let error = reader
        .read_vec(1, 2, CanonicalReader::read_u16)
        .unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::CapacityExceeded {
            what: "collection allocation bytes",
            ..
        }
    ));
    assert_eq!(reader.allocation_stats().reservations, 0);
}

#[test]
fn truncation_trailing_bytes_and_field_caps_fail_closed() {
    let full = [0, 0, 0, 3, 1, 2, 3];
    for end in 0..full.len() {
        let mut reader = CanonicalReader::new(&full[..end], CODEC_LIMITS).unwrap();
        assert!(reader.read_bounded_bytes(3).is_err(), "prefix {end}");
    }

    let mut trailing = CanonicalReader::new(&[1, 2], CODEC_LIMITS).unwrap();
    assert_eq!(trailing.read_u8().unwrap(), 1);
    assert_eq!(
        trailing.finish(),
        Err(ProtocolError::TrailingBytes {
            offset: 1,
            remaining: 1
        })
    );

    let mut too_long = CanonicalReader::new(&full, CODEC_LIMITS).unwrap();
    assert!(matches!(
        too_long.read_bounded_bytes(2),
        Err(ProtocolError::CapacityExceeded { .. })
    ));

    let mut writer = CanonicalWriter::new(CodecLimits::new(2, 2, 16));
    writer.write_u16(1).unwrap();
    assert!(matches!(
        writer.write_u8(2),
        Err(ProtocolError::CapacityExceeded { .. })
    ));
}

#[test]
fn logical_map_order_is_strict_and_unique() {
    assert_eq!(ensure_strictly_increasing(&[1, 2, 3]), Ok(()));
    assert_eq!(
        ensure_strictly_increasing(&[1, 2, 2]),
        Err(ProtocolError::DuplicateEntry { index: 2 })
    );
    assert_eq!(
        ensure_strictly_increasing(&[1, 3, 2]),
        Err(ProtocolError::OutOfOrderEntry { index: 2 })
    );
}

#[test]
fn ocb1_envelope_matches_independent_encoder_and_is_exact() {
    let body = [0xde, 0xad, 0xbe, 0xef];
    let production = encode_envelope(ObjectKind::JobIntentV1, &body, CODEC_LIMITS).unwrap();
    assert_eq!(
        production,
        independent_envelope(ObjectKind::JobIntentV1.tag(), &body)
    );
    let decoded = decode_envelope(&production, CODEC_LIMITS).unwrap();
    assert_eq!(decoded.kind, ObjectKind::JobIntentV1);
    assert_eq!(decoded.body, body);
    assert_eq!(production.len(), OCB1_HEADER_LEN + body.len());
    require_canonical_reencoding(&production, &production).unwrap();

    let mut alternate = production.clone();
    alternate.push(0);
    assert_eq!(
        require_canonical_reencoding(&production, &alternate),
        Err(ProtocolError::NonCanonicalEncoding)
    );
}

#[test]
fn ocb1_rejects_unknown_kind_version_length_truncation_and_trailing() {
    let valid = independent_envelope(ObjectKind::JobIntentV1.tag(), &[1, 2]);

    let mut unknown_kind = valid.clone();
    unknown_kind[4..6].copy_from_slice(&0xffff_u16.to_be_bytes());
    assert_eq!(
        decode_envelope(&unknown_kind, CODEC_LIMITS),
        Err(ProtocolError::UnknownObjectKind(0xffff))
    );

    let mut version = valid.clone();
    version[6..8].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        decode_envelope(&version, CODEC_LIMITS),
        Err(ProtocolError::UnsupportedSchemaVersion(2))
    );

    for end in 0..OCB1_HEADER_LEN {
        assert!(matches!(
            decode_envelope(&valid[..end], CODEC_LIMITS),
            Err(ProtocolError::UnexpectedEof { .. })
        ));
    }
    let mut wrong_length = valid.clone();
    wrong_length[8..12].copy_from_slice(&3_u32.to_be_bytes());
    assert!(matches!(
        decode_envelope(&wrong_length, CODEC_LIMITS),
        Err(ProtocolError::BodyLengthMismatch { .. })
    ));
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(matches!(
        decode_envelope(&trailing, CODEC_LIMITS),
        Err(ProtocolError::BodyLengthMismatch { .. })
    ));
    let body_limited = CodecLimits::new(1, 1, 64);
    assert!(matches!(
        decode_envelope(&valid, body_limited),
        Err(ProtocolError::CapacityExceeded {
            what: "OCB1 body bytes",
            ..
        })
    ));
}

#[test]
fn every_envelope_byte_mutation_fails_expected_commitment() {
    let body = [1, 0, 7, 0, 0, 0, 1, 0xaa];
    let canonical = encode_envelope(ObjectKind::JobIntentV1, &body, CODEC_LIMITS).unwrap();
    let expected = hash_framed(HashDomain::Intent, &canonical).unwrap();

    for index in 0..canonical.len() {
        let mut mutated = canonical.clone();
        mutated[index] ^= 1;
        assert_eq!(
            verify_framed_hash(HashDomain::Intent, &mutated, expected),
            Err(ProtocolError::HashMismatch),
            "byte {index}"
        );
    }
}

#[test]
fn registered_domain_framing_matches_independent_implementation() {
    let payload = b"canonical payload";
    for domain in HashDomain::ALL {
        assert!(domain.as_str().is_ascii());
        let preimage = framed_preimage(*domain, payload).unwrap();
        assert_eq!(
            hash_framed(*domain, payload).unwrap(),
            independent_hash(domain.as_str(), payload)
        );
        assert_eq!(
            alloy_primitives::keccak256(preimage),
            independent_hash(domain.as_str(), payload)
        );
    }
}

#[test]
fn domain_and_length_framing_prevent_concatenation_collisions() {
    assert_ne!(
        independent_hash("OUTBE_OCOMP_JOB_V1", b"ab"),
        independent_hash("OUTBE_OCOMP_JOB_V1", b"a")
    );
    assert_ne!(
        independent_hash("OUTBE_OCOMP_JOB_V1", b"ab"),
        independent_hash("OUTBE_OCOMP_INTENT_V1", b"ab")
    );
    let domains: BTreeSet<_> = HashDomain::ALL
        .iter()
        .map(|domain| domain.as_str())
        .collect();
    assert_eq!(domains.len(), HashDomain::ALL.len());
}

#[test]
fn ordered_list_empty_leaf_pad_node_and_root_match_independent_implementation() {
    let cases: &[&[&[u8]]] = &[&[], &[b"one"], &[b"one", b"two"], &[b"a", b"b", b"c"]];
    for items in cases {
        let production = ordered_list_root(ListKind::NodActions, items, LIST_LIMITS).unwrap();
        let independent = independent_ordered_root(ListKind::NodActions.id(), items);
        assert_eq!(production, independent, "item count {}", items.len());
    }

    let leaf = leaf_hash(ListKind::NodActions, 0, b"a").unwrap();
    assert_eq!(
        root_hash(ListKind::NodActions, 1, 0, leaf).unwrap(),
        independent_ordered_root(ListKind::NodActions.id(), &[b"a"])
    );

    let leaf_0 = leaf_hash(ListKind::NodActions, 0, b"a").unwrap();
    let leaf_1 = leaf_hash(ListKind::NodActions, 1, b"b").unwrap();
    let leaf_2 = leaf_hash(ListKind::NodActions, 2, b"c").unwrap();
    let pad_3 = pad_hash(ListKind::NodActions, 3).unwrap();
    let left = node_hash(ListKind::NodActions, 1, 0, leaf_0, leaf_1).unwrap();
    let right = node_hash(ListKind::NodActions, 1, 1, leaf_2, pad_3).unwrap();
    let tree = node_hash(ListKind::NodActions, 2, 0, left, right).unwrap();
    assert_eq!(
        root_hash(ListKind::NodActions, 3, 2, tree).unwrap(),
        independent_ordered_root(ListKind::NodActions.id(), &[b"a", b"b", b"c"])
    );
}

#[test]
fn ordered_list_commits_kind_count_position_and_value() {
    let base = ordered_list_root(ListKind::NodActions, &[b"a", b"b"], LIST_LIMITS).unwrap();
    assert_ne!(
        base,
        ordered_list_root(ListKind::ContributorActions, &[b"a", b"b"], LIST_LIMITS).unwrap()
    );
    assert_ne!(
        base,
        ordered_list_root(ListKind::NodActions, &[b"b", b"a"], LIST_LIMITS).unwrap()
    );
    assert_ne!(
        base,
        ordered_list_root(ListKind::NodActions, &[b"a"], LIST_LIMITS).unwrap()
    );
    assert_ne!(
        base,
        ordered_list_root(ListKind::NodActions, &[b"a", b"c"], LIST_LIMITS).unwrap()
    );
}

#[test]
fn ordered_list_caps_fail_before_internal_tree_allocation() {
    assert!(matches!(
        ordered_list_root(
            ListKind::NodActions,
            &[b"a", b"b"],
            OrderedListLimits::new(1, 1, 64)
        ),
        Err(ProtocolError::CapacityExceeded {
            what: "ordered-list item count",
            ..
        })
    ));
    assert!(matches!(
        ordered_list_root(
            ListKind::NodActions,
            &[b"aa"],
            OrderedListLimits::new(1, 1, 64)
        ),
        Err(ProtocolError::CapacityExceeded {
            what: "ordered-list item bytes",
            ..
        })
    ));
    assert!(matches!(
        ordered_list_root(
            ListKind::NodActions,
            &[b"a"],
            OrderedListLimits::new(1, 1, 31)
        ),
        Err(ProtocolError::CapacityExceeded {
            what: "ordered-list tree allocation bytes",
            ..
        })
    ));
}

#[test]
fn generated_registry_is_complete_and_unique() {
    assert_eq!(ObjectKind::ALL.len(), 36);
    assert_eq!(HashDomain::ALL.len(), 50);
    assert_eq!(ListKind::ALL.len(), 13);
    assert_eq!(ObjectKind::ProtocolBundleV1.tag(), 0x0001);
    assert_eq!(ObjectKind::OcompJobRecordV1.tag(), 0x001e);
    assert_eq!(ObjectKind::NodMaterializationBatchV1.tag(), 0x0027);
    assert_eq!(ObjectKind::NodMaterializationHeadV1.tag(), 0x0028);
    assert_eq!(
        ObjectKind::try_from(0x000f),
        Err(ProtocolError::UnknownObjectKind(0x000f))
    );
    assert_eq!(
        ObjectKind::try_from(0x0011),
        Err(ProtocolError::UnknownObjectKind(0x0011))
    );
    assert_eq!(
        ObjectKind::try_from(0x001a),
        Err(ProtocolError::UnknownObjectKind(0x001a))
    );
    assert_eq!(ListKind::NodActions.id(), 1);
    assert_eq!(ListKind::RawTributeCoverage.id(), 8);
    assert_eq!(ListKind::FidelityOpenings.id(), 9);
    assert_eq!(ListKind::OracleOpenings.id(), 10);
    assert_eq!(ListKind::ResultChunkHashes.id(), 11);
    assert_eq!(ListKind::LysisLeagueFractions.id(), 12);
    assert_eq!(ListKind::LysisGratisLeafPrefixes.id(), 13);
    assert_eq!(
        ObjectKind::try_from(0xffff),
        Err(ProtocolError::UnknownObjectKind(0xffff))
    );
    assert_eq!(
        ListKind::try_from(0xffff),
        Err(ProtocolError::UnknownListKind(0xffff))
    );
}

#[test]
fn generated_input_codec_ids_match_independent_descriptor_hashes() {
    fn codec_id(role: u16, version: u16, descriptor: &str) -> B256 {
        let mut payload = IndependentEncoder::new();
        payload.u16(role);
        payload.u16(version);
        payload.u32(u32::try_from(descriptor.len()).unwrap());
        payload.fixed(descriptor.as_bytes());
        independent_hash("OUTBE_OCOMP_CODEC_DESCRIPTOR_V1", &payload.finish())
    }

    assert_eq!(
        codec_id(1, 1, TRIBUTE_BODY_CODEC_DESCRIPTOR),
        TRIBUTE_BODY_CODEC_ID
    );
    assert_eq!(
        codec_id(2, 1, FIDELITY_OPENING_CODEC_DESCRIPTOR),
        FIDELITY_OPENING_CODEC_ID
    );
    assert_eq!(
        codec_id(3, 1, ORACLE_OPENING_CODEC_DESCRIPTOR),
        ORACLE_OPENING_CODEC_ID
    );

    let mut opening_registry = IndependentEncoder::new();
    opening_registry.u16(2);
    opening_registry.u8(1);
    opening_registry.fixed(FIDELITY_OPENING_CODEC_ID.as_slice());
    opening_registry.u8(2);
    opening_registry.fixed(ORACLE_OPENING_CODEC_ID.as_slice());
    assert_eq!(
        independent_hash(
            "OUTBE_OCOMP_OPENING_CODEC_REGISTRY_V1",
            &opening_registry.finish()
        ),
        OPENING_CODEC_REGISTRY_HASH
    );
}
