mod support;

use alloy_primitives::Address;
use outbe_radicle::endpoint::{
    EndpointProtocol, IdError, ProtocolError, ReceiveOutcome, RequestIdSource,
    MAX_FUTURE_ANCHOR_DISTANCE, MAX_PENDING_REQUESTS, MAX_UNKNOWN_ANCHORS, REQUEST_TIMEOUT_MS,
    UNKNOWN_ANCHOR_TIMEOUT_MS,
};
use std::collections::VecDeque;

#[derive(Debug)]
struct Ids(VecDeque<[u8; 32]>);

impl Ids {
    fn from(values: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self(values.into_iter().collect())
    }
}

impl RequestIdSource for Ids {
    fn next_id(&mut self) -> Result<[u8; 32], IdError> {
        self.0.pop_front().ok_or(IdError::Unavailable)
    }
}

#[test]
fn pending_lifecycle() {
    let signer = support::key(20);
    let peer = support::peer(&signer);
    let validator = Address::repeat_byte(0x20);
    let node_id = [0x21; 32];
    let snapshot = support::snapshot(validator, node_id, &signer);
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from([[1; 32], [2; 32]]));

    let request = protocol.request(peer, 10).unwrap();
    assert_eq!(request.request_id(), [1; 32]);
    assert_eq!(
        protocol.request(peer, 10),
        Err(ProtocolError::AlreadyPending)
    );

    let response = support::signed([1; 32], validator, node_id, &signer);
    let outcome = protocol
        .receive(peer, response.clone(), 100, Some(&snapshot), 11)
        .unwrap();
    assert!(matches!(outcome, ReceiveOutcome::Verified(_)));
    assert_eq!(
        protocol.receive(peer, response, 100, Some(&snapshot), 12),
        Err(ProtocolError::Unsolicited)
    );

    protocol.request(peer, 20).unwrap();
    protocol.expire(20 + REQUEST_TIMEOUT_MS);
    assert_eq!(protocol.stats().pending, 0);

    let timed = support::signed([2; 32], validator, node_id, &signer);
    assert_eq!(
        protocol.receive(peer, timed, 100, Some(&snapshot), 20 + REQUEST_TIMEOUT_MS),
        Err(ProtocolError::Unsolicited)
    );
}

#[test]
fn unknown_anchor_lifecycle() {
    let signer = support::key(21);
    let peer = support::peer(&signer);
    let validator = Address::repeat_byte(0x22);
    let node_id = [0x23; 32];
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from([[3; 32], [4; 32]]));
    protocol.request(peer, 0).unwrap();

    let mut body = support::body([3; 32], validator, node_id);
    body.anchor_number = 101;
    body.anchor_hash = alloy_primitives::B256::repeat_byte(0x88);
    body.valid_until = 200;
    let response = outbe_radicle::endpoint::sign_response(body, &signer).unwrap();
    assert_eq!(
        protocol.receive(peer, response, 100, None, 1).unwrap(),
        ReceiveOutcome::Queued { anchor_number: 101 }
    );
    assert_eq!(
        protocol.request(peer, 2),
        Err(ProtocolError::AlreadyPending)
    );

    let future_snapshot = outbe_radicle::endpoint::AnchorSnapshot::new(
        101,
        alloy_primitives::B256::repeat_byte(0x88),
        vec![outbe_radicle::endpoint::AuthorityRecord {
            validator,
            peer,
            node_id,
        }],
    )
    .unwrap();
    let resolved = protocol.resolve(&future_snapshot, 101, 3);
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].result.is_ok());
    assert_eq!(protocol.stats().queued, 0);
}

#[test]
fn send_failure_releases_peer() {
    let signer = support::key(23);
    let peer = support::peer(&signer);
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from([[11; 32], [12; 32]]));
    let request = protocol.request(peer, 0).unwrap();
    protocol.send_failed(peer, request.request_id());
    assert_eq!(protocol.stats().pending, 0);
    assert!(protocol.request(peer, 1).is_ok());
}

#[test]
fn queued_id_and_expiry() {
    let signer = support::key(24);
    let peer = support::peer(&signer);
    let validator = Address::repeat_byte(0x26);
    let node_id = [0x27; 32];
    let duplicate = [13; 32];
    let mut protocol = EndpointProtocol::new(
        support::chain(),
        Ids::from(std::iter::repeat_n(duplicate, 9)),
    );
    protocol.request(peer, 0).unwrap();
    let mut body = support::body(duplicate, validator, node_id);
    body.anchor_number = 101;
    body.anchor_hash = alloy_primitives::B256::repeat_byte(0x91);
    protocol
        .receive(
            peer,
            outbe_radicle::endpoint::sign_response(body, &signer).unwrap(),
            100,
            None,
            1,
        )
        .unwrap();
    assert_eq!(
        protocol.request(support::peer(&support::key(25)), 2),
        Err(ProtocolError::RequestIdExhausted)
    );
    protocol.expire(1 + UNKNOWN_ANCHOR_TIMEOUT_MS);
    assert_eq!(protocol.stats().queued, 0);
}

#[test]
fn unknown_capacity_consumes_pending() {
    let ids = (1..=(MAX_UNKNOWN_ANCHORS as u16 + 2)).map(|n| {
        let mut id = [0; 32];
        id[..2].copy_from_slice(&n.to_be_bytes());
        id
    });
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from(ids));
    for seed in 1..=MAX_UNKNOWN_ANCHORS as u64 {
        let signer = support::key(30_000 + seed);
        let peer = support::peer(&signer);
        let request = protocol.request(peer, 0).unwrap();
        let mut body = support::body(
            request.request_id(),
            Address::repeat_byte((seed % 255) as u8),
            [seed as u8; 32],
        );
        body.anchor_number = 101;
        body.anchor_hash = alloy_primitives::B256::repeat_byte(0x92);
        protocol
            .receive(
                peer,
                outbe_radicle::endpoint::sign_response(body, &signer).unwrap(),
                100,
                None,
                1,
            )
            .unwrap();
    }
    let signer = support::key(40_000);
    let peer = support::peer(&signer);
    let request = protocol.request(peer, 2).unwrap();
    let mut body = support::body(request.request_id(), Address::repeat_byte(0xfe), [0xfe; 32]);
    body.anchor_number = 101;
    body.anchor_hash = alloy_primitives::B256::repeat_byte(0x92);
    assert_eq!(
        protocol.receive(
            peer,
            outbe_radicle::endpoint::sign_response(body, &signer).unwrap(),
            100,
            None,
            3,
        ),
        Err(ProtocolError::Capacity)
    );
    assert_eq!(protocol.stats().pending, 0);
    assert_eq!(protocol.stats().queued, MAX_UNKNOWN_ANCHORS);
}

#[test]
fn pending_capacity_and_collision() {
    let ids = (1..=(MAX_PENDING_REQUESTS as u16 + 9)).map(|n| {
        let mut id = [0; 32];
        id[..2].copy_from_slice(&n.to_be_bytes());
        id
    });
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from(ids));
    for seed in 1..=MAX_PENDING_REQUESTS as u64 {
        protocol
            .request(support::peer(&support::key(seed)), 0)
            .unwrap();
    }
    assert_eq!(
        protocol.request(support::peer(&support::key(9999)), 0),
        Err(ProtocolError::Capacity)
    );

    let duplicate = [9; 32];
    let mut collision = EndpointProtocol::new(
        support::chain(),
        Ids::from(std::iter::repeat_n(duplicate, 9)),
    );
    collision
        .request(support::peer(&support::key(10001)), 0)
        .unwrap();
    assert_eq!(
        collision.request(support::peer(&support::key(10002)), 0),
        Err(ProtocolError::RequestIdExhausted)
    );
}

#[test]
fn future_distance_is_terminal() {
    let signer = support::key(22);
    let peer = support::peer(&signer);
    let validator = Address::repeat_byte(0x24);
    let node_id = [0x25; 32];
    let mut protocol = EndpointProtocol::new(support::chain(), Ids::from([[5; 32], [6; 32]]));
    protocol.request(peer, 0).unwrap();
    let mut body = support::body([5; 32], validator, node_id);
    body.anchor_number = 100 + MAX_FUTURE_ANCHOR_DISTANCE + 1;
    body.valid_until = body.anchor_number + 1;
    let response = outbe_radicle::endpoint::sign_response(body, &signer).unwrap();
    assert_eq!(
        protocol.receive(peer, response, 100, None, 1),
        Err(ProtocolError::FutureDistance)
    );
    assert_eq!(protocol.stats().pending, 0);
    assert!(protocol.request(peer, 2).is_ok());
}

#[test]
fn future_envelope_and_exact_snapshot() {
    let signer = support::key(26);
    let peer = support::peer(&signer);
    let validator = Address::repeat_byte(0x28);
    let node_id = [0x29; 32];
    let mut protocol =
        EndpointProtocol::new(support::chain(), Ids::from([[21; 32], [22; 32], [23; 32]]));

    protocol.request(peer, 0).unwrap();
    let mut expired = support::body([21; 32], validator, node_id);
    expired.anchor_number = 101;
    expired.anchor_hash = alloy_primitives::B256::repeat_byte(0xa1);
    expired.valid_until = 100;
    assert_eq!(
        protocol.receive(
            peer,
            outbe_radicle::endpoint::sign_response(expired, &signer).unwrap(),
            100,
            None,
            1,
        ),
        Err(ProtocolError::Verification(
            outbe_radicle::endpoint::VerifyError::Expired,
        ))
    );
    assert_eq!(protocol.stats().queued, 0);

    let request = protocol.request(peer, 2).unwrap();
    let mut future = support::body(request.request_id(), validator, node_id);
    future.anchor_number = 101;
    future.anchor_hash = alloy_primitives::B256::repeat_byte(0xa2);
    protocol
        .receive(
            peer,
            outbe_radicle::endpoint::sign_response(future, &signer).unwrap(),
            100,
            None,
            3,
        )
        .unwrap();

    let wrong_snapshot = support::snapshot(validator, node_id, &signer);
    assert!(protocol.resolve(&wrong_snapshot, 101, 4).is_empty());
    assert_eq!(protocol.stats().queued, 1);
}
