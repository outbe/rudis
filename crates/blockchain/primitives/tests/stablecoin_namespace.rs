use std::str::FromStr;

use alloy_primitives::{Address, B256};
use outbe_primitives::{
    addresses::{
        is_stablecoin_address, STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS,
        STABLECOIN_MARKER_CODE, STABLECOIN_POLICY_REGISTRY_ADDRESS,
    },
    chain::{
        DEVNET_CHAIN_ID, DEVNET_CHAIN_NAME, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME, TESTNET_CHAIN_ID,
        TESTNET_CHAIN_NAME,
    },
    stablecoin::{predict_stablecoin, stablecoin_token_id_preimage},
};
use serde::Deserialize;

const NETWORK_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/network-address-vectors.json"
));

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkCorpus {
    generator: String,
    factory: String,
    policy_registry: String,
    prefix: String,
    marker: String,
    networks: Vec<NetworkVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkVector {
    name: String,
    chain_id: u64,
    issuer: String,
    ticker: String,
    preimage: String,
    token_id: String,
    token: String,
}

#[test]
fn stablecoin_constants_are_exact_and_class_disjoint() {
    assert_eq!(
        STABLECOIN_FACTORY_ADDRESS,
        Address::from_str("0x000000000000000000000000000000000000ee0f").unwrap()
    );
    assert_eq!(
        STABLECOIN_POLICY_REGISTRY_ADDRESS,
        Address::from_str("0x000000000000000000000000000000000000ee10").unwrap()
    );
    assert_eq!(STABLECOIN_ADDRESS_PREFIX, [0x53, 0xc0]);
    assert_eq!(STABLECOIN_MARKER_CODE, [0xef]);
    assert!(!is_stablecoin_address(STABLECOIN_FACTORY_ADDRESS));
    assert!(!is_stablecoin_address(STABLECOIN_POLICY_REGISTRY_ADDRESS));
}

#[test]
fn independent_network_vectors_pin_current_supported_geneses() {
    let corpus: NetworkCorpus = serde_json::from_str(NETWORK_VECTORS).unwrap();
    assert!(corpus.generator.starts_with("Foundry cast"));
    assert_eq!(
        Address::from_str(&corpus.factory).unwrap(),
        STABLECOIN_FACTORY_ADDRESS
    );
    assert_eq!(
        Address::from_str(&corpus.policy_registry).unwrap(),
        STABLECOIN_POLICY_REGISTRY_ADDRESS
    );
    assert_eq!(decode_prefix(&corpus.prefix), STABLECOIN_ADDRESS_PREFIX);
    assert_eq!(
        hex::decode(corpus.marker.trim_start_matches("0x")).unwrap(),
        STABLECOIN_MARKER_CODE
    );
    assert_eq!(corpus.networks.len(), 3);

    for vector in corpus.networks {
        match vector.name.as_str() {
            DEVNET_CHAIN_NAME => assert_eq!(vector.chain_id, DEVNET_CHAIN_ID),
            TESTNET_CHAIN_NAME => assert_eq!(vector.chain_id, TESTNET_CHAIN_ID),
            MAINNET_CHAIN_NAME => assert_eq!(vector.chain_id, MAINNET_CHAIN_ID),
            other => panic!("unexpected network vector {other}"),
        }
        let issuer = Address::from_str(&vector.issuer).unwrap();
        let expected_preimage = hex::decode(vector.preimage.trim_start_matches("0x")).unwrap();
        let expected_id = B256::from_str(&vector.token_id).unwrap();
        let expected_token = Address::from_str(&vector.token).unwrap();
        assert_eq!(
            stablecoin_token_id_preimage(
                vector.chain_id,
                STABLECOIN_FACTORY_ADDRESS,
                issuer,
                &vector.ticker,
            )
            .unwrap(),
            expected_preimage
        );
        assert_eq!(
            predict_stablecoin(
                vector.chain_id,
                STABLECOIN_FACTORY_ADDRESS,
                issuer,
                &vector.ticker,
                STABLECOIN_ADDRESS_PREFIX,
            )
            .unwrap(),
            (expected_id, expected_token)
        );
        assert!(is_stablecoin_address(expected_token));
    }
}

fn decode_prefix(value: &str) -> [u8; 2] {
    let mut prefix = [0u8; 2];
    hex::decode_to_slice(value.trim_start_matches("0x"), &mut prefix).unwrap();
    prefix
}
