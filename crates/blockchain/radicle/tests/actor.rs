mod support;

use alloy_primitives::Address;
use outbe_radicle::endpoint::{
    EndpointActor, EndpointFrame, EndpointProtocol, IdError, RequestIdSource,
};
use std::collections::VecDeque;

#[derive(Debug)]
struct Ids(VecDeque<[u8; 32]>);

impl Ids {
    fn many(count: usize) -> Self {
        let ids = (1..=count as u64).map(|n| {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&n.to_be_bytes());
            id
        });
        Self(ids.collect())
    }
}

impl RequestIdSource for Ids {
    fn next_id(&mut self) -> Result<[u8; 32], IdError> {
        self.0.pop_front().ok_or(IdError::Unavailable)
    }
}

#[tokio::test]
async fn actor_mesh() {
    let protocol = EndpointProtocol::new(support::chain(), Ids::many(8));
    let (actor, handle) = EndpointActor::new(protocol);
    let task = tokio::spawn(actor.run());

    for seed in 1..=3 {
        let signer = support::key(100 + seed);
        let peer = support::peer(&signer);
        let validator = Address::repeat_byte(seed as u8);
        let node_id = [seed as u8; 32];
        let request_bytes = handle.request(peer, 0).await.unwrap();
        let EndpointFrame::Request(request) = EndpointFrame::decode(&request_bytes).unwrap() else {
            panic!("request frame expected");
        };
        let response = support::signed(request.request_id(), validator, node_id, &signer);
        let snapshot = support::snapshot(validator, node_id, &signer);
        let outcome = handle
            .response(peer, response, 100, Some(snapshot), 1)
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            outbe_radicle::endpoint::ReceiveOutcome::Verified(_)
        ));
    }

    let stats = handle.stats().await.unwrap();
    assert_eq!(stats.pending, 0);

    let signer = support::key(500);
    let peer = support::peer(&signer);
    let request_bytes = handle.request(peer, 2).await.unwrap();
    let EndpointFrame::Request(request) = EndpointFrame::decode(&request_bytes).unwrap() else {
        panic!("request frame expected");
    };
    handle
        .send_failed(peer, request.request_id())
        .await
        .unwrap();
    assert_eq!(handle.stats().await.unwrap().pending, 0);
    handle.shutdown().await.unwrap();
    task.await.unwrap();
}
