mod support;

use alloy_primitives::{Address, B256};
use outbe_radicle::endpoint::{
    EndpointAddress, EndpointFrame, EndpointRequest, EndpointResponseBody, SignedEndpointResponse,
    WireError, MAX_ADDRESSES, MAX_ENDPOINT_FRAME_BYTES,
};

#[test]
fn request_vector() {
    let request = EndpointRequest::new([0xAB; 32]).unwrap();
    let encoded = EndpointFrame::Request(request.clone()).encode();
    assert_eq!(encoded.len(), 38);
    assert_eq!(
        hex::encode(&encoded),
        format!("4f5241440001{}", "ab".repeat(32))
    );
    assert_eq!(
        EndpointFrame::decode(&encoded).unwrap(),
        EndpointFrame::Request(request)
    );
}

#[test]
fn response_vector() {
    let addresses = vec![
        EndpointAddress::ipv4([10, 0, 0, 1], 8776).unwrap(),
        EndpointAddress::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8776).unwrap(),
        EndpointAddress::dns("rpc.n1.testnet.outbe.net", 8776).unwrap(),
    ];
    let body = EndpointResponseBody {
        request_id: [1; 32],
        chain_id: support::CHAIN_ID,
        genesis_hash: support::GENESIS_HASH,
        validator: Address::repeat_byte(0x33),
        node_id: [0x44; 32],
        addresses,
        anchor_number: 100,
        anchor_hash: support::ANCHOR_HASH,
        valid_until: 200,
    };
    let response = outbe_radicle::endpoint::sign_response(body, &support::key(42)).unwrap();
    let frame = EndpointFrame::Response(Box::new(response.clone()));
    let encoded = frame.encode();

    assert_eq!(&encoded[..6], b"ORAD\x01\x01");
    assert_eq!(&encoded[6..38], &[1; 32]);
    assert_eq!(&encoded[38..46], &support::CHAIN_ID.to_be_bytes());
    assert_ne!(encoded.last_chunk::<96>().unwrap(), &[0; 96]);
    let mut expected = Vec::new();
    expected.extend_from_slice(b"ORAD\x01\x01");
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&support::CHAIN_ID.to_be_bytes());
    expected.extend_from_slice(support::GENESIS_HASH.as_slice());
    expected.extend_from_slice(Address::repeat_byte(0x33).as_slice());
    expected.extend_from_slice(&[0x44; 32]);
    expected.push(3);
    expected.extend_from_slice(&[0, 10, 0, 0, 1, 0x22, 0x48]);
    expected.extend_from_slice(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x22, 0x48,
    ]);
    expected.extend_from_slice(b"\x02\x18rpc.n1.testnet.outbe.net\x22\x48");
    expected.extend_from_slice(&100u64.to_be_bytes());
    expected.extend_from_slice(support::ANCHOR_HASH.as_slice());
    expected.extend_from_slice(&200u64.to_be_bytes());
    expected.extend_from_slice(response.signature());
    assert_eq!(encoded, expected);
    assert_eq!(EndpointFrame::decode(&encoded).unwrap(), frame);
}

#[test]
fn max_response_size() {
    let mut addresses = Vec::new();
    for suffix in b'a'..=b'p' {
        let host = format!(
            "{}{}.{}.{}.{}",
            "a".repeat(62),
            char::from(suffix),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        );
        addresses.push(EndpointAddress::dns(&host, 8776).unwrap());
    }
    assert_eq!(addresses.len(), MAX_ADDRESSES);
    let body = EndpointResponseBody {
        request_id: [7; 32],
        chain_id: 1,
        genesis_hash: B256::ZERO,
        validator: Address::ZERO,
        node_id: [8; 32],
        addresses,
        anchor_number: 1,
        anchor_hash: B256::ZERO,
        valid_until: 2,
    };
    let response = outbe_radicle::endpoint::sign_response(body, &support::key(43)).unwrap();
    let encoded = EndpointFrame::Response(Box::new(response)).encode();
    assert_eq!(encoded.len(), MAX_ENDPOINT_FRAME_BYTES);
    assert!(EndpointFrame::decode(&encoded).is_ok());
}

#[test]
fn wire_rejections() {
    assert_eq!(EndpointRequest::new([0; 32]), Err(WireError::ZeroRequestId));
    assert_eq!(EndpointFrame::decode(b"NOPE"), Err(WireError::Truncated));

    let mut wrong_magic = EndpointFrame::Request(EndpointRequest::new([1; 32]).unwrap()).encode();
    wrong_magic[0] = b'X';
    assert_eq!(EndpointFrame::decode(&wrong_magic), Err(WireError::Magic));

    let mut wrong_version = EndpointFrame::Request(EndpointRequest::new([1; 32]).unwrap()).encode();
    wrong_version[5] = 2;
    assert_eq!(
        EndpointFrame::decode(&wrong_version),
        Err(WireError::Version(2))
    );

    let oversized = vec![0; MAX_ENDPOINT_FRAME_BYTES + 1];
    assert_eq!(EndpointFrame::decode(&oversized), Err(WireError::Oversized));

    let body = support::body([1; 32], Address::repeat_byte(1), [2; 32]);
    assert_eq!(
        SignedEndpointResponse::new(body, [0; 96]),
        Err(WireError::SignatureEncoding)
    );
}

#[test]
fn response_address_order() {
    let base = EndpointResponseBody {
        request_id: [1; 32],
        chain_id: 1,
        genesis_hash: B256::ZERO,
        validator: Address::ZERO,
        node_id: [1; 32],
        addresses: vec![
            EndpointAddress::dns("z.example", 1).unwrap(),
            EndpointAddress::dns("a.example", 1).unwrap(),
        ],
        anchor_number: 1,
        anchor_hash: B256::ZERO,
        valid_until: 2,
    };
    assert_eq!(
        SignedEndpointResponse::new(base, [0; 96]),
        Err(WireError::AddressOrder)
    );
}
