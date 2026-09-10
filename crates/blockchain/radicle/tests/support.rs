#![allow(dead_code)]

use alloy_primitives::{Address, B256};
use commonware_cryptography::{bls12381, Signer};
use outbe_radicle::endpoint::{
    sign_response, AnchorSnapshot, AuthorityRecord, ChainIdentity, EndpointAddress,
    EndpointResponseBody, PeerId, SignedEndpointResponse,
};

pub const CHAIN_ID: u64 = 70_860_602;
pub const GENESIS_HASH: B256 = B256::repeat_byte(0x11);
pub const ANCHOR_HASH: B256 = B256::repeat_byte(0x22);

pub fn key(seed: u64) -> bls12381::PrivateKey {
    bls12381::PrivateKey::from_seed(seed)
}

pub fn peer(key: &bls12381::PrivateKey) -> PeerId {
    PeerId::from_public_key(&key.public_key())
}

pub fn body(request_id: [u8; 32], validator: Address, node_id: [u8; 32]) -> EndpointResponseBody {
    EndpointResponseBody {
        request_id,
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
        validator,
        node_id,
        addresses: vec![EndpointAddress::dns("rpc.n1.testnet.outbe.net", 8776).unwrap()],
        anchor_number: 100,
        anchor_hash: ANCHOR_HASH,
        valid_until: 200,
    }
}

pub fn signed(
    request_id: [u8; 32],
    validator: Address,
    node_id: [u8; 32],
    key: &bls12381::PrivateKey,
) -> SignedEndpointResponse {
    sign_response(body(request_id, validator, node_id), key).unwrap()
}

pub fn snapshot(
    validator: Address,
    node_id: [u8; 32],
    key: &bls12381::PrivateKey,
) -> AnchorSnapshot {
    AnchorSnapshot::new(
        100,
        ANCHOR_HASH,
        vec![AuthorityRecord {
            validator,
            peer: peer(key),
            node_id,
        }],
    )
    .unwrap()
}

pub fn chain() -> ChainIdentity {
    ChainIdentity {
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
    }
}
