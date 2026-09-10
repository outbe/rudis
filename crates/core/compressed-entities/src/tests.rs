use alloy_primitives::{Address, B256, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::time::WorldwideDay;

use crate::{
    body_commitment, decode_nod_bucket_v1, decode_nod_item_v1, decode_stored_tribute_v1,
    decode_tribute_v1, derive_poseidon_entity_id, encode_nod_bucket_v1, encode_nod_item_v1,
    encode_tribute_v1, identity_field, pbytes, CanonicalBodyError, CommitmentError,
    NodBucketBodyV1, NodItemBodyV1, StoredBody, TributeBodyV1, WwdEntityId,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, CES1_TAG_BASE, TAG_BODY, TAG_BYTES_ABSORB,
    TAG_BYTES_FINAL, TAG_BYTES_INIT, TAG_ID, TAG_KEY, TAG_LEAF, TAG_SMT_BASE, TAG_SMT_NORMAL,
    TAG_SMT_ZERO,
};
use crate::{schema::CompressedEntitiesSchema, state::State};

#[path = "tests/adr007.rs"]
mod adr007;
#[path = "tests/adr008_scope.rs"]
mod adr008_scope;
#[path = "tests/adr011.rs"]
mod adr011;

fn commitment_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../vectors/ces1-noble-poseidon.json")).unwrap()
}

fn json_hex(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn json_bytes32(value: &serde_json::Value) -> [u8; 32] {
    json_hex(value).try_into().unwrap()
}

fn field_to_be32(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}

fn tagged_poseidon(tag: u64, inputs: &[Fr]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(tag)).unwrap();
    field_to_be32(hasher.hash(inputs).unwrap())
}

fn raw_leaf(scheme: u32, schema: u32, identity: WwdEntityId, payload: &[u8]) -> [u8; 32] {
    let identity_f = Fr::from_be_bytes_mod_order(&pbytes(TAG_ID, identity.as_slice()).unwrap());
    let body_f = Fr::from_be_bytes_mod_order(&pbytes(TAG_BODY, payload).unwrap());
    tagged_poseidon(
        TAG_LEAF,
        &[
            Fr::from(scheme),
            Fr::from(schema),
            identity_f,
            Fr::from(payload.len() as u64),
            body_f,
        ],
    )
}

fn tag_value(name: &str) -> u64 {
    match name {
        "TAG_BYTES_INIT" => TAG_BYTES_INIT,
        "TAG_BYTES_ABSORB" => TAG_BYTES_ABSORB,
        "TAG_BYTES_FINAL" => TAG_BYTES_FINAL,
        "TAG_ID" => TAG_ID,
        "TAG_KEY" => TAG_KEY,
        "TAG_BODY" => TAG_BODY,
        "TAG_LEAF" => TAG_LEAF,
        "TAG_SMT_BASE" => TAG_SMT_BASE,
        "TAG_SMT_NORMAL" => TAG_SMT_NORMAL,
        "TAG_SMT_ZERO" => TAG_SMT_ZERO,
        other => panic!("unknown CES1 vector tag {other}"),
    }
}

#[test]
fn tribute_v1_uses_one_strict_canonical_protobuf_representation() {
    let body = TributeBodyV1 {
        tribute_id: WwdEntityId::from_day_and_digest(WorldwideDay::from(1), [0x11; 32]),
        owner: Address::repeat_byte(0x22),
        worldwide_day: WorldwideDay::from(1),
        issuance_amount_minor: U256::from(1),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(2),
        reference_currency: 978,
        tribute_price_minor: U256::from(3),
        exclude_from_intex_issuance: true,
    };
    let expected = hex::decode(concat!(
        "0a2000000001",
        "11111111111111111111111111111111111111111111111111111111",
        "1214",
        "2222222222222222222222222222222222222222",
        "1801",
        "22200000000000000000000000000000000000000000000000000000000000000001",
        "28c806",
        "32200000000000000000000000000000000000000000000000000000000000000002",
        "38d207",
        "42200000000000000000000000000000000000000000000000000000000000000003",
        "4801"
    ))
    .unwrap();

    let payload = encode_tribute_v1(&body).unwrap();
    assert_eq!(payload, expected);
    assert_eq!(decode_tribute_v1(&payload).unwrap(), body);

    let stored = StoredBody::new_v1(payload.clone()).unwrap();
    let canonical_envelope = stored.encode();
    assert_eq!(StoredBody::decode(&canonical_envelope).unwrap(), stored);

    let mut unknown_field = payload;
    unknown_field.extend_from_slice(&[0x50, 0x01]);
    assert!(decode_tribute_v1(&unknown_field).is_err());
}

#[test]
fn nod_item_v1_uses_one_strict_canonical_protobuf_representation() {
    let body = NodItemBodyV1 {
        nod_id: WwdEntityId::from_day_and_digest(WorldwideDay::from(1), [0x11; 32]),
        owner: Address::repeat_byte(0x22),
        gratis_load_minor: U256::from(1),
        worldwide_day: WorldwideDay::from(1),
        league_id: 2,
        floor_price_minor: U256::from(2),
        bucket_key: B256::repeat_byte(0x33),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 5,
    };
    let expected = hex::decode(concat!(
        "0a2000000001",
        "11111111111111111111111111111111111111111111111111111111",
        "1214",
        "2222222222222222222222222222222222222222",
        "1a200000000000000000000000000000000000000000000000000000000000000001",
        "2001",
        "2802",
        "32200000000000000000000000000000000000000000000000000000000000000002",
        "3a20",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "48c806",
        "50d207",
        "5805"
    ))
    .unwrap();

    let payload = encode_nod_item_v1(&body).unwrap();
    assert_eq!(payload, expected);
    assert_eq!(decode_nod_item_v1(&payload).unwrap(), body);
}

/// Field 12 carried the Nod's settled flag until settlement moved to a PayNote
/// spend at mine time. It was written only when a Nod was settled, so retiring
/// it left every live body's bytes untouched — but a body that does carry it
/// describes state this schema no longer has, and must be refused rather than
/// quietly decoded without it.
#[test]
fn a_nod_item_carrying_the_retired_settled_field_is_rejected() {
    let body = NodItemBodyV1 {
        nod_id: WwdEntityId::from_day_and_digest(WorldwideDay::from(1), [0x11; 32]),
        owner: Address::repeat_byte(0x22),
        gratis_load_minor: U256::from(1),
        worldwide_day: WorldwideDay::from(1),
        league_id: 2,
        floor_price_minor: U256::from(2),
        bucket_key: B256::repeat_byte(0x33),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 5,
    };
    let payload = encode_nod_item_v1(&body).unwrap();
    assert!(decode_nod_item_v1(&payload).is_ok());

    // `0x60, 0x01` is field 12, varint wire type, value 1 — the settled marker.
    let mut settled = payload.clone();
    settled.extend_from_slice(&[0x60, 0x01]);
    assert!(matches!(
        decode_nod_item_v1(&settled),
        Err(CanonicalBodyError::UnknownField { field: 12 })
    ));
}

/// Field 8 carried the Nod's cost until it became a derivation from the
/// bucket's entry price and the Nod's gratis load. Every body wrote it, so
/// retiring it is a deliberate wire break: a body that still carries it states
/// a cost this schema no longer owns, and must be refused rather than decoded
/// with the value dropped on the floor.
#[test]
fn a_nod_item_carrying_the_retired_cost_field_is_rejected() {
    // The exact bytes this schema produced before the cost became a derivation
    // from the bucket's entry price and the Nod's gratis load: field 8 sitting
    // in its canonical position between `bucket_key` and `issuance_currency`.
    let with_cost = hex::decode(concat!(
        "0a2000000001",
        "11111111111111111111111111111111111111111111111111111111",
        "1214",
        "2222222222222222222222222222222222222222",
        "1a200000000000000000000000000000000000000000000000000000000000000001",
        "2001",
        "2802",
        "32200000000000000000000000000000000000000000000000000000000000000002",
        "3a20",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "42200000000000000000000000000000000000000000000000000000000000000003",
        "48c806",
        "50d207",
        "5805"
    ))
    .unwrap();

    assert!(matches!(
        decode_nod_item_v1(&with_cost),
        Err(CanonicalBodyError::UnknownField { field: 8 })
    ));
}

#[test]
fn nod_bucket_v1_uses_one_strict_canonical_protobuf_representation() {
    let body = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(0x33),
        worldwide_day: WorldwideDay::from(1),
        floor_price_minor: U256::from(1),
        is_qualified: true,
        total_nods: 2,
        entry_price_minor: U256::from(3),
        reference_currency: 840,
    };
    let expected = hex::decode(concat!(
        "0a20",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "1001",
        "1a200000000000000000000000000000000000000000000000000000000000000001",
        "2001",
        "2802",
        "32200000000000000000000000000000000000000000000000000000000000000003",
        "38c806"
    ))
    .unwrap();

    let payload = encode_nod_bucket_v1(&body).unwrap();
    assert_eq!(payload, expected);
    assert_eq!(decode_nod_bucket_v1(&payload).unwrap(), body);

    // Field 7 is omitted on zero, so bodies written before the currency
    // existed keep their exact prior bytes. This is what keeps the pinned
    // `ces1-noble-poseidon` bucket payload and leaf byte-identical.
    let unpriced = NodBucketBodyV1 {
        reference_currency: 0,
        ..body.clone()
    };
    let unpriced_payload = encode_nod_bucket_v1(&unpriced).unwrap();
    assert_eq!(unpriced_payload.as_slice(), &expected[..expected.len() - 3]);
    assert_eq!(
        decode_nod_bucket_v1(&unpriced_payload).unwrap(),
        unpriced,
        "a body without field 7 must decode to reference_currency 0"
    );

    // An explicitly-encoded zero is a second encoding of the same body and
    // must be rejected by the strict re-encode check.
    let mut explicit_zero = unpriced_payload.clone();
    explicit_zero.extend_from_slice(&[0x38, 0x00]);
    assert!(matches!(
        decode_nod_bucket_v1(&explicit_zero),
        Err(CanonicalBodyError::ExplicitDefault { field: 7 })
    ));
}

#[test]
fn entity_derivation_and_leaf_commitment_bind_every_declared_input() {
    let owner = Address::repeat_byte(0x42);
    let day = WorldwideDay::from(2026_0716);
    let identity = derive_poseidon_entity_id(owner, day).unwrap();
    assert_eq!(identity.worldwide_day(), day);
    assert_eq!(
        identity_field(identity).unwrap(),
        pbytes(TAG_ID, identity.as_slice()).unwrap()
    );

    let payload = vec![0x11; 62];
    let leaf = body_commitment(ACTIVE_COMMITMENT_SCHEME, 1, identity, &payload).unwrap();
    assert!(!leaf.is_zero());
    assert_ne!(
        body_commitment(
            ACTIVE_COMMITMENT_SCHEME,
            1,
            WwdEntityId::from_day_and_digest(day, [0x99; 32]),
            &payload
        )
        .unwrap(),
        leaf
    );
    let mut changed_payload = payload.clone();
    changed_payload[31] ^= 1;
    assert_ne!(
        body_commitment(ACTIVE_COMMITMENT_SCHEME, 1, identity, &changed_payload).unwrap(),
        leaf
    );
    assert!(body_commitment(2, 1, identity, &payload).is_err());
    assert!(body_commitment(ACTIVE_COMMITMENT_SCHEME, 2, identity, &payload).is_err());
}

#[test]
fn commitment_accepts_only_nonzero_canonical_bn254_elements() {
    assert!(matches!(
        crate::Commitment::try_from([0_u8; 32]),
        Err(CommitmentError::ZeroPresentLeaf)
    ));

    let modulus = Fr::MODULUS.to_bytes_be();
    let mut modulus_be32 = [0_u8; 32];
    modulus_be32[32 - modulus.len()..].copy_from_slice(&modulus);
    assert!(matches!(
        crate::Commitment::try_from(modulus_be32),
        Err(CommitmentError::NonCanonicalFieldElement)
    ));
}

#[test]
fn typed_stored_body_and_wire_profile_reject_alternative_representations() {
    let vectors = commitment_vectors();
    let canonical = json_hex(&vectors["bodies"][0]["payload_hex"]);

    let unsupported = StoredBody::new(2, canonical.clone()).unwrap().encode();
    assert!(matches!(
        decode_stored_tribute_v1(&unsupported),
        Err(CanonicalBodyError::UnsupportedSchema { actual: 2 })
    ));

    for artifact in vectors["rejection_artifacts"]["protobuf"]
        .as_array()
        .unwrap()
    {
        let kind = artifact["kind"].as_str().unwrap();
        match kind {
            "unknown_field" => assert!(matches!(
                decode_tribute_v1(&json_hex(&artifact["payload_hex"])),
                Err(CanonicalBodyError::UnknownField { field: 10 })
            )),
            "duplicate_field" => assert!(matches!(
                decode_tribute_v1(&json_hex(&artifact["payload_hex"])),
                Err(CanonicalBodyError::NonAscendingOrDuplicateField { field: 1 })
            )),
            "non_minimal_key" => assert!(matches!(
                decode_tribute_v1(&json_hex(&artifact["payload_hex"])),
                Err(CanonicalBodyError::NonMinimalVarint)
            )),
            "explicit_default" => assert!(matches!(
                decode_tribute_v1(&json_hex(&artifact["payload_hex"])),
                Err(CanonicalBodyError::ExplicitDefault { field: 3 })
            )),
            "empty_stored_payload" | "zero_stored_schema" => {
                assert!(StoredBody::decode(&json_hex(&artifact["stored_body_hex"])).is_err())
            }
            other => panic!("unknown canonical rejection vector {other}"),
        }
    }
}

#[test]
fn protobuf_profile_rejects_order_length_width_wire_and_range_violations() {
    fn shorten_length_delimited(mut payload: Vec<u8>, marker: [u8; 2]) -> Vec<u8> {
        let start = payload
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("canonical field marker must exist");
        let original_len = usize::from(marker[1]);
        payload[start + 1] = marker[1] - 1;
        payload.remove(start + 2 + original_len - 1);
        payload
    }

    let tribute = TributeBodyV1 {
        tribute_id: WwdEntityId::from_day_and_digest(WorldwideDay::from(1), [0x11; 32]),
        owner: Address::repeat_byte(0x22),
        worldwide_day: WorldwideDay::from(1),
        issuance_amount_minor: U256::from(1),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(2),
        reference_currency: 978,
        tribute_price_minor: U256::from(3),
        exclude_from_intex_issuance: true,
    };
    let canonical_tribute = encode_tribute_v1(&tribute).unwrap();

    // Move field 2 before field 1 while keeping both fields individually valid.
    let mut out_of_order = Vec::with_capacity(canonical_tribute.len());
    out_of_order.extend_from_slice(&canonical_tribute[34..56]);
    out_of_order.extend_from_slice(&canonical_tribute[..34]);
    out_of_order.extend_from_slice(&canonical_tribute[56..]);
    assert!(matches!(
        decode_tribute_v1(&out_of_order),
        Err(CanonicalBodyError::MissingField { field: 1 })
    ));

    assert!(matches!(
        decode_tribute_v1(&[0x0a, 0x80]),
        Err(CanonicalBodyError::MalformedProtobuf)
    ));
    assert!(matches!(
        decode_tribute_v1(&shorten_length_delimited(
            canonical_tribute.clone(),
            [0x0a, 0x20],
        )),
        Err(CanonicalBodyError::InvalidEntityId(_))
    ));

    let nod_item = NodItemBodyV1 {
        nod_id: WwdEntityId::from_day_and_digest(WorldwideDay::from(1), [0x11; 32]),
        owner: Address::repeat_byte(0x22),
        gratis_load_minor: U256::from(1),
        worldwide_day: WorldwideDay::from(1),
        league_id: 2,
        floor_price_minor: U256::from(2),
        bucket_key: B256::repeat_byte(0x33),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 5,
    };
    assert!(matches!(
        decode_nod_item_v1(&shorten_length_delimited(
            encode_nod_item_v1(&nod_item).unwrap(),
            [0x12, 0x14],
        )),
        Err(CanonicalBodyError::InvalidFixedWidth {
            field: 2,
            expected: 20,
            actual: 19,
        })
    ));

    let nod_bucket = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(0x33),
        worldwide_day: WorldwideDay::from(1),
        floor_price_minor: U256::from(1),
        is_qualified: true,
        total_nods: 2,
        entry_price_minor: U256::from(3),
        reference_currency: 840,
    };
    assert!(matches!(
        decode_nod_bucket_v1(&shorten_length_delimited(
            encode_nod_bucket_v1(&nod_bucket).unwrap(),
            [0x0a, 0x20],
        )),
        Err(CanonicalBodyError::InvalidFixedWidth {
            field: 1,
            expected: 32,
            actual: 31,
        })
    ));

    let mut wrong_wire_type = canonical_tribute.clone();
    wrong_wire_type[0] = 0x08;
    assert!(matches!(
        decode_tribute_v1(&wrong_wire_type),
        Err(CanonicalBodyError::WrongWireType { field: 1 })
    ));

    let currency = canonical_tribute
        .windows(3)
        .position(|window| window == [0x28, 0xc8, 0x06])
        .unwrap();
    let mut u16_overflow = canonical_tribute;
    u16_overflow.splice(currency..currency + 3, [0x28, 0x80, 0x80, 0x04]);
    assert!(matches!(
        decode_tribute_v1(&u16_overflow),
        Err(CanonicalBodyError::IntegerOutOfRange { field: 5 })
    ));
}

#[test]
fn schema_v4_has_one_root_retirement_journal_and_keeps_reserved_slots_empty() {
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        let state = State::new(storage.clone());
        state.ensure_schema().unwrap();
        assert_eq!(
            state.root().unwrap(),
            crate::sealed_root(B256::ZERO).unwrap()
        );
        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.storage_schema_version.read().unwrap(), 4);
        assert_eq!(schema.reserved_2.read().unwrap(), U256::ZERO);
        assert_eq!(schema.reserved_3.read().unwrap(), U256::ZERO);
    });
}

#[test]
fn schema_v2_to_v4_migration_requires_every_overlay_list_to_be_empty() {
    let root = crate::sealed_root(B256::ZERO).unwrap();
    let mut clean = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut clean, |storage| {
        let schema = CompressedEntitiesSchema::new(storage.clone());
        schema.storage_schema_version.write(2).unwrap();
        schema
            .last_smt_root
            .write(U256::from_be_slice(root.as_slice()))
            .unwrap();
        State::new(storage).ensure_schema().unwrap();
        assert_eq!(schema.storage_schema_version.read().unwrap(), 4);
    });

    let mut dirty = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut dirty, |storage| {
        let schema = CompressedEntitiesSchema::new(storage.clone());
        schema.storage_schema_version.write(2).unwrap();
        schema
            .last_smt_root
            .write(U256::from_be_slice(root.as_slice()))
            .unwrap();
        schema.retirement_touched.push(20_260_717).unwrap();
        assert!(State::new(storage).ensure_schema().is_err());
        assert_eq!(schema.storage_schema_version.read().unwrap(), 2);
    });
}

#[test]
fn commitment_golden_vectors_are_pinned() {
    let vectors = commitment_vectors();
    assert_eq!(
        vectors["implementation"].as_str().unwrap(),
        "@noble/curves generic Poseidon permutation"
    );
    assert_eq!(vectors["implementation_version"], "1.6.0");
    assert_eq!(
        vectors["bn254_scalar_modulus"].as_str().unwrap(),
        hex::encode(Fr::MODULUS.to_bytes_be())
    );

    let tags = vectors["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 10);
    for vector in tags {
        let name = vector["name"].as_str().unwrap();
        let tag = tag_value(name);
        assert_eq!(vector["decimal"].as_str().unwrap(), tag.to_string());
        assert_eq!(vector["hex"].as_str().unwrap(), format!("0x{tag:064x}"));
        let inputs = vector["representative_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| Fr::from(value.as_str().unwrap().parse::<u64>().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            hex::encode(tagged_poseidon(tag, &inputs)),
            vector["output"].as_str().unwrap()
        );
    }
    assert_eq!(tag_value("TAG_BYTES_INIT"), CES1_TAG_BASE + 1);

    for vector in vectors["pbytes"].as_array().unwrap() {
        let bytes = json_hex(&vector["input_hex"]);
        assert_eq!(bytes.len(), vector["length"].as_u64().unwrap() as usize);
        assert_eq!(vector["object_tag"], "TAG_BODY");
        assert_eq!(
            hex::encode(pbytes(TAG_BODY, &bytes).unwrap()),
            vector["output"].as_str().unwrap()
        );
    }
}

/// The identity-dependent half of the CES1 conformance set.
///
/// These vectors were produced by an independent `@noble/curves` Poseidon, which
/// is the entire point of the file: regenerating them from this crate would turn
/// a cross-implementation check into a tautology. Narrowing identities to 32
/// bytes changed every Poseidon input here, so the vectors must be reproduced by
/// re-running that reference against the new identities before this can run
/// again. The tag and `pbytes` vectors above are identity-independent and still
/// cover the permutation itself.
#[ignore = "CES1 identity/body vectors need regeneration from the @noble/curves reference for 32-byte identities"]
#[test]
fn commitment_identity_and_body_golden_vectors_are_pinned() {
    let vectors = commitment_vectors();
    for vector in vectors["identities"].as_array().unwrap() {
        let identity = WwdEntityId::try_from(json_hex(&vector["identity_hex"]).as_slice()).unwrap();
        assert_eq!(identity.worldwide_day().value(), vector["worldwide_day"]);
        match vector["kind"].as_str().unwrap() {
            "tribute" | "nod_item" => {
                let owner = Address::from_slice(&json_hex(&vector["owner_hex"]));
                assert_eq!(
                    derive_poseidon_entity_id(owner, identity.worldwide_day()).unwrap(),
                    identity
                );
            }
            "nod_bucket" => assert_eq!(
                identity.body().as_slice(),
                &json_hex(&vector["bucket_key_hex"])[4..],
            ),
            other => panic!("unknown identity vector {other}"),
        }
        assert_eq!(
            hex::encode(identity_field(identity).unwrap()),
            vector["identity_field"].as_str().unwrap()
        );
    }

    for vector in vectors["bodies"].as_array().unwrap() {
        let identity = WwdEntityId::try_from(json_hex(&vector["identity_hex"]).as_slice()).unwrap();
        let payload = json_hex(&vector["payload_hex"]);
        match vector["kind"].as_str().unwrap() {
            "tribute" => assert_eq!(
                encode_tribute_v1(&decode_tribute_v1(&payload).unwrap()).unwrap(),
                payload
            ),
            "nod_item" => assert_eq!(
                encode_nod_item_v1(&decode_nod_item_v1(&payload).unwrap()).unwrap(),
                payload
            ),
            "nod_bucket" => assert_eq!(
                encode_nod_bucket_v1(&decode_nod_bucket_v1(&payload).unwrap()).unwrap(),
                payload
            ),
            other => panic!("unknown body vector {other}"),
        }
        let stored = StoredBody::decode(&json_hex(&vector["stored_body_hex"])).unwrap();
        assert_eq!(stored.schema_version(), vector["schema_version"]);
        assert_eq!(stored.payload(), payload);
        assert_eq!(
            hex::encode(
                body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, identity, &payload)
                    .unwrap()
                    .as_bytes()
            ),
            vector["leaf"].as_str().unwrap()
        );
    }

    let schema = &vectors["schema_variation"];
    let identity = WwdEntityId::try_from(json_hex(&schema["identity_hex"]).as_slice()).unwrap();
    let payload = json_hex(&schema["payload_hex"]);
    assert_eq!(
        schema["active_schema_version"].as_u64().unwrap() as u32,
        BODY_SCHEMA_V1
    );
    assert_eq!(
        hex::encode(raw_leaf(1, 1, identity, &payload)),
        schema["scheme_1_schema_1_leaf"]
    );
    assert_eq!(
        hex::encode(raw_leaf(1, 2, identity, &payload)),
        schema["scheme_1_schema_2_leaf"]
    );
    assert_ne!(
        schema["scheme_1_schema_1_leaf"],
        schema["scheme_1_schema_2_leaf"]
    );
    assert!(body_commitment(
        1,
        schema["rejected_schema_version"].as_u64().unwrap() as u32,
        identity,
        &payload
    )
    .is_err());

    for dimension in ["identity", "payload"] {
        let vector = &vectors["bit_flips"][dimension];
        let original_identity = WwdEntityId::try_from(
            json_hex(&vectors["bit_flips"]["identity"]["original_hex"]).as_slice(),
        )
        .unwrap();
        let original_payload = json_hex(&vectors["bit_flips"]["payload"]["original_hex"]);
        let (changed_identity, changed_payload) = if dimension == "identity" {
            (
                WwdEntityId::try_from(json_hex(&vector["flipped_hex"]).as_slice()).unwrap(),
                original_payload.clone(),
            )
        } else {
            (original_identity, json_hex(&vector["flipped_hex"]))
        };
        assert_eq!(
            hex::encode(raw_leaf(1, 1, original_identity, &original_payload)),
            vector["original_leaf"]
        );
        assert_eq!(
            hex::encode(raw_leaf(1, 1, changed_identity, &changed_payload)),
            vector["flipped_leaf"]
        );
        assert_ne!(vector["original_leaf"], vector["flipped_leaf"]);
    }

    let rejected = &vectors["rejection_artifacts"];
    assert!(matches!(
        crate::Commitment::try_from(json_bytes32(&rejected["zero_present_leaf"])),
        Err(CommitmentError::ZeroPresentLeaf)
    ));
    assert!(matches!(
        crate::Commitment::try_from(json_bytes32(&rejected["field_element_at_modulus"])),
        Err(CommitmentError::NonCanonicalFieldElement)
    ));
    assert_eq!(
        rejected["unsupported_schema_version"],
        schema["rejected_schema_version"]
    );
    assert!(body_commitment(
        rejected["unsupported_commitment_scheme_version"]
            .as_u64()
            .unwrap() as u32,
        1,
        identity,
        &payload
    )
    .is_err());
    assert!(body_commitment(1, 1, identity, &json_hex(&rejected["empty_payload_hex"])).is_err());
}
