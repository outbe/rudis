use std::str::FromStr;

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::stablecoin::{
    decode_canonical_stablecoin_create, encode_canonical_stablecoin_create, is_supported_iso4217,
    iso_4217_alpha, predict_stablecoin, stablecoin_address, stablecoin_token_id,
    stablecoin_token_id_preimage, StablecoinCodecError, StablecoinCreatePayload, ISO_4217_ALPHA,
    ISO_4217_NUMERIC_CODES, ISO_4217_SNAPSHOT_PUBLISHED, ISO_4217_SNAPSHOT_SHA256,
};
use proptest::prelude::*;
use serde::Deserialize;

const VALID: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/valid.json"
));
const VALID_UNICODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/valid-unicode.json"
));
const INVALID_CASES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/invalid-cases.json"
));
const IDENTITY_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/identity-vectors.json"
));
const CANONICAL_JSON_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/canonical-json-vectors.json"
));
const ISO_4217_SNAPSHOT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/iso-4217-snapshot.json"
));

#[derive(Deserialize)]
struct InvalidCase {
    name: String,
    input: String,
    error: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityCorpus {
    generator: String,
    vectors: Vec<IdentityVector>,
    tail_collision: TailCollision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityVector {
    name: String,
    chain_id: u64,
    factory: String,
    issuer: String,
    ticker: String,
    prefix: String,
    preimage: String,
    token_id: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TailCollision {
    prefix: String,
    first_token_id: String,
    second_token_id: String,
    token: String,
}

#[derive(Deserialize)]
struct CanonicalJsonCorpus {
    generator: String,
    vectors: Vec<CanonicalJsonVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalJsonVector {
    name: String,
    json: String,
    utf8_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Iso4217Snapshot {
    source: String,
    published: String,
    source_sha256: String,
    numeric_codes: Vec<u16>,
    alpha_codes: Vec<String>,
}

#[test]
fn canonical_payloads_decode_and_reencode_byte_identically() {
    let payload = decode_canonical_stablecoin_create(VALID).unwrap();
    assert_eq!(payload.issuer, Address::repeat_byte(0x11));
    assert_eq!(payload.name, "Example Dollar");
    assert_eq!(payload.ticker, "EXUSD");
    assert_eq!(payload.iso4217, 840);
    assert_eq!(payload.decimals, 6);
    assert_eq!(payload.supply_cap, U256::from(1_000_000_000_000u64));
    assert_eq!(payload.policy_id, U256::from(1));
    assert_eq!(encode_canonical_stablecoin_create(&payload).unwrap(), VALID);

    let unicode = decode_canonical_stablecoin_create(VALID_UNICODE).unwrap();
    assert_eq!(unicode.name, "Dólar 日本");
    assert_eq!(unicode.supply_cap, U256::MAX);
    assert_eq!(unicode.policy_id, U256::ZERO);
    assert_eq!(
        encode_canonical_stablecoin_create(&unicode).unwrap(),
        VALID_UNICODE
    );
}

#[test]
fn independent_json_vectors_match_complete_canonical_bytes() {
    let corpus: CanonicalJsonCorpus = serde_json::from_str(CANONICAL_JSON_VECTORS).unwrap();
    assert!(corpus.generator.starts_with("Node.js"));
    for vector in corpus.vectors {
        let independent_bytes = hex::decode(&vector.utf8_hex).unwrap();
        assert_eq!(independent_bytes, vector.json.as_bytes(), "{}", vector.name);
        let payload = decode_canonical_stablecoin_create(&independent_bytes).unwrap();
        assert_eq!(
            encode_canonical_stablecoin_create(&payload).unwrap(),
            independent_bytes,
            "{}",
            vector.name
        );
    }
}

#[test]
fn pinned_iso_snapshot_matches_the_production_set() {
    let snapshot: Iso4217Snapshot = serde_json::from_str(ISO_4217_SNAPSHOT).unwrap();
    assert!(snapshot.source.starts_with("https://www.six-group.com/"));
    assert_eq!(snapshot.published, ISO_4217_SNAPSHOT_PUBLISHED);
    assert_eq!(snapshot.source_sha256, ISO_4217_SNAPSHOT_SHA256);
    assert_eq!(snapshot.numeric_codes, ISO_4217_NUMERIC_CODES);

    assert_eq!(snapshot.alpha_codes.len(), ISO_4217_ALPHA.len());
    for ((expected, alpha), code) in snapshot
        .alpha_codes
        .iter()
        .zip(ISO_4217_ALPHA)
        .zip(ISO_4217_NUMERIC_CODES)
    {
        assert_eq!(expected.as_bytes(), alpha, "alpha for {code}");
        assert!(alpha.iter().all(u8::is_ascii_uppercase), "alpha for {code}");
    }
    assert!(snapshot
        .numeric_codes
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert!(ISO_4217_NUMERIC_CODES
        .iter()
        .copied()
        .all(is_supported_iso4217));
    assert!(!is_supported_iso4217(1));
    assert!(!is_supported_iso4217(975));
}

#[test]
fn invalid_corpus_has_stable_error_classes() {
    let cases: Vec<InvalidCase> = serde_json::from_str(INVALID_CASES).unwrap();
    assert!(cases.len() >= 17);
    for case in cases {
        let error = decode_canonical_stablecoin_create(case.input.as_bytes()).unwrap_err();
        assert_eq!(error_class(&error), case.error, "case {}", case.name);
    }
}

#[test]
fn malformed_utf8_json_and_trailing_bytes_are_rejected() {
    assert_eq!(
        decode_canonical_stablecoin_create(&[0xff]),
        Err(StablecoinCodecError::InvalidUtf8)
    );
    assert_eq!(
        decode_canonical_stablecoin_create(b"{"),
        Err(StablecoinCodecError::InvalidJson)
    );

    let mut trailing = VALID.to_vec();
    trailing.push(b'\n');
    assert_eq!(
        decode_canonical_stablecoin_create(&trailing),
        Err(StablecoinCodecError::NonCanonicalEncoding)
    );
}

#[test]
fn metadata_and_decimal_boundaries_are_explicit() {
    let mut payload = StablecoinCreatePayload {
        issuer: Address::with_last_byte(1),
        name: "N".repeat(64),
        ticker: "XY".to_owned(),
        iso4217: 999,
        decimals: 18,
        supply_cap: U256::MAX,
        policy_id: U256::MAX,
    };
    let encoded = encode_canonical_stablecoin_create(&payload).unwrap();
    assert_eq!(
        decode_canonical_stablecoin_create(&encoded).unwrap(),
        payload
    );

    payload.name.push('N');
    assert_eq!(
        encode_canonical_stablecoin_create(&payload),
        Err(StablecoinCodecError::InvalidName)
    );

    let overflow = String::from(
        "{\"version\":1,\"kind\":\"StablecoinCreate\",\"issuer\":\"0x1111111111111111111111111111111111111111\",\"name\":\"X\",\"ticker\":\"XY\",\"iso4217\":840,\"decimals\":0,\"supplyCap\":\"115792089237316195423570985008687907853269984665640564039457584007913129639936\",\"policyId\":\"0\"}",
    );
    assert_eq!(
        decode_canonical_stablecoin_create(overflow.as_bytes()),
        Err(StablecoinCodecError::InvalidSupplyCap)
    );
}

#[test]
fn independent_identity_vectors_match_exact_preimages_ids_and_addresses() {
    let corpus: IdentityCorpus = serde_json::from_str(IDENTITY_VECTORS).unwrap();
    assert!(corpus.generator.starts_with("Foundry cast"));
    for vector in corpus.vectors {
        let factory = Address::from_str(&vector.factory).unwrap();
        let issuer = Address::from_str(&vector.issuer).unwrap();
        let prefix = decode_prefix(&vector.prefix);
        let expected_preimage = decode_hex(&vector.preimage);
        let expected_id = B256::from_str(&vector.token_id).unwrap();
        let expected_token = Address::from_str(&vector.token).unwrap();

        assert_eq!(
            stablecoin_token_id_preimage(vector.chain_id, factory, issuer, &vector.ticker).unwrap(),
            expected_preimage,
            "preimage {}",
            vector.name
        );
        assert_eq!(
            stablecoin_token_id(vector.chain_id, factory, issuer, &vector.ticker).unwrap(),
            expected_id,
            "token id {}",
            vector.name
        );
        assert_eq!(
            predict_stablecoin(vector.chain_id, factory, issuer, &vector.ticker, prefix).unwrap(),
            (expected_id, expected_token),
            "prediction {}",
            vector.name
        );
    }
}

#[test]
fn different_full_ids_with_the_same_144_bit_tail_map_to_the_same_class_address() {
    let corpus: IdentityCorpus = serde_json::from_str(IDENTITY_VECTORS).unwrap();
    let collision = corpus.tail_collision;
    let prefix = decode_prefix(&collision.prefix);
    let first = B256::from_str(&collision.first_token_id).unwrap();
    let second = B256::from_str(&collision.second_token_id).unwrap();
    let expected = Address::from_str(&collision.token).unwrap();

    assert_ne!(first, second);
    assert_eq!(&first.as_slice()[14..], &second.as_slice()[14..]);
    assert_eq!(stablecoin_address(first, prefix), expected);
    assert_eq!(stablecoin_address(second, prefix), expected);
}

proptest! {
    #[test]
    fn accepted_payloads_roundtrip_without_normalization(
        issuer_tail in 1u8..=u8::MAX,
        cap in 1u128..=u128::MAX,
        policy in any::<u128>(),
        decimals in 0u8..=18,
        iso_index in 0usize..ISO_4217_NUMERIC_CODES.len(),
    ) {
        let payload = StablecoinCreatePayload {
            issuer: Address::with_last_byte(issuer_tail),
            name: format!("Token {issuer_tail}"),
            ticker: format!("T{issuer_tail}"),
            iso4217: ISO_4217_NUMERIC_CODES[iso_index],
            decimals,
            supply_cap: U256::from(cap),
            policy_id: U256::from(policy),
        };
        let encoded = encode_canonical_stablecoin_create(&payload).unwrap();
        prop_assert_eq!(decode_canonical_stablecoin_create(&encoded).unwrap(), payload);

        let mut noncanonical = encoded;
        noncanonical.insert(1, b' ');
        prop_assert_eq!(
            decode_canonical_stablecoin_create(&noncanonical),
            Err(StablecoinCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn class_address_is_exact_prefix_plus_144_bit_tail(
        token_id in any::<[u8; 32]>(),
        prefix in any::<[u8; 2]>(),
    ) {
        let token_id = B256::from(token_id);
        let address = stablecoin_address(token_id, prefix);
        prop_assert_eq!(&address.as_slice()[..2], &prefix);
        prop_assert_eq!(&address.as_slice()[2..], &token_id.as_slice()[14..]);
    }
}

fn error_class(error: &StablecoinCodecError) -> &'static str {
    match error {
        StablecoinCodecError::InvalidUtf8 => "InvalidUtf8",
        StablecoinCodecError::InvalidJson => "InvalidJson",
        StablecoinCodecError::NonCanonicalEncoding => "NonCanonicalEncoding",
        StablecoinCodecError::UnsupportedVersion(_) => "UnsupportedVersion",
        StablecoinCodecError::InvalidKind => "InvalidKind",
        StablecoinCodecError::InvalidFactory => "InvalidFactory",
        StablecoinCodecError::InvalidIssuer => "InvalidIssuer",
        StablecoinCodecError::InvalidName => "InvalidName",
        StablecoinCodecError::InvalidTicker => "InvalidTicker",
        StablecoinCodecError::InvalidIso4217(_) => "InvalidIso4217",
        StablecoinCodecError::InvalidDecimals(_) => "InvalidDecimals",
        StablecoinCodecError::InvalidSupplyCap => "InvalidSupplyCap",
        StablecoinCodecError::InvalidPolicyId => "InvalidPolicyId",
        _ => "Unknown",
    }
}

fn decode_prefix(value: &str) -> [u8; 2] {
    let mut prefix = [0u8; 2];
    hex::decode_to_slice(value.strip_prefix("0x").unwrap(), &mut prefix).unwrap();
    prefix
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value.strip_prefix("0x").unwrap()).unwrap()
}

#[test]
fn every_pinned_code_resolves_to_its_own_letters() {
    for (code, alpha) in ISO_4217_NUMERIC_CODES.iter().zip(ISO_4217_ALPHA) {
        assert_eq!(iso_4217_alpha(*code), Some(*alpha), "alpha for {code}");
    }
}

#[test]
fn a_code_outside_the_pinned_list_has_no_letters() {
    // 0 and 500 are not assigned; 1000 is past the three-digit range.
    for code in [0u16, 500, 1000] {
        assert_eq!(iso_4217_alpha(code), None, "unexpected alpha for {code}");
    }
}
