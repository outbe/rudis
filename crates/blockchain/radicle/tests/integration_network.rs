use alloy_primitives::{Address, B256};
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::{bls12381, Signer as _};
use commonware_p2p::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_runtime::{IoBuf, IoBufs};
use outbe_radicle::{
    endpoint::{
        sign_response, AnchorSnapshot, AuthorityRecord, ChainIdentity, EndpointAddress,
        EndpointFrame, EndpointRequest, EndpointResponseBody, PeerId, VerificationContext,
        MAX_ENDPOINT_TTL_BLOCKS,
    },
    integration::{
        EndpointNetwork, LocalEndpointIdentity, LocalEndpointIdentityChannel, RadicleStatusChannel,
        RadicleVotingGate, RadicleVotingGateError,
    },
    manager::{EndpointResolver as _, FinalizedBlock, FinalizedSnapshot, FinalizedValidator},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

type SentFrames = Arc<Mutex<Vec<(bls12381::PublicKey, Vec<u8>)>>>;

#[derive(Clone)]
struct MockSender {
    sent: SentFrames,
}

struct MockChecked<'a> {
    sender: &'a MockSender,
    recipients: Vec<bls12381::PublicKey>,
}

impl CheckedSender for MockChecked<'_> {
    type PublicKey = bls12381::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.recipients.clone()
    }

    fn send(self, message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        let bytes = message.into().coalesce().as_ref().to_vec();
        let mut sent = self.sender.sent.lock().unwrap();
        for peer in self.recipients {
            sent.push((peer, bytes.clone()));
        }
        Unreliable::Outcome(Feedback::Ok)
    }
}

impl LimitedSender for MockSender {
    type PublicKey = bls12381::PublicKey;
    type Checked<'a> = MockChecked<'a>;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, std::time::SystemTime> {
        let recipients = match recipients {
            Recipients::One(peer) => vec![peer],
            Recipients::Some(peers) => peers,
            Recipients::All => panic!("endpoint protocol never broadcasts"),
        };
        Ok(MockChecked {
            sender: self,
            recipients,
        })
    }
}

#[derive(Debug)]
struct MockReceiver {
    receiver: mpsc::UnboundedReceiver<(bls12381::PublicKey, IoBuf)>,
}

impl Receiver for MockReceiver {
    type Error = std::io::Error;
    type PublicKey = bls12381::PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| std::io::ErrorKind::BrokenPipe.into())
    }
}

fn snapshot(
    height: u64,
    signer_a: &bls12381::PrivateKey,
    signer_b: &bls12381::PrivateKey,
    include_a: bool,
) -> FinalizedSnapshot {
    let mut validators = vec![FinalizedValidator {
        address: Address::repeat_byte(0x22),
        peer: PeerId::from_public_key(&signer_b.public_key()),
        node_id: Some([2_u8; 32]),
    }];
    if include_a {
        validators.push(FinalizedValidator {
            address: Address::repeat_byte(0x11),
            peer: PeerId::from_public_key(&signer_a.public_key()),
            node_id: Some([1_u8; 32]),
        });
    }
    FinalizedSnapshot {
        block: FinalizedBlock {
            number: height,
            hash: B256::with_last_byte(height as u8),
        },
        validators,
        registry_generation: 0,
        repositories: vec![],
    }
}

fn anchor(snapshot: &FinalizedSnapshot) -> AnchorSnapshot {
    AnchorSnapshot::new(
        snapshot.block.number,
        snapshot.block.hash,
        snapshot
            .validators
            .iter()
            .filter_map(|validator| {
                Some(AuthorityRecord {
                    validator: validator.address,
                    peer: validator.peer,
                    node_id: validator.node_id?,
                })
            })
            .collect(),
    )
    .unwrap()
}

fn response(
    request_id: [u8; 32],
    snapshot: &FinalizedSnapshot,
    signer: &bls12381::PrivateKey,
    address: Address,
    node_id: [u8; 32],
    port: u16,
) -> outbe_radicle::endpoint::SignedEndpointResponse {
    sign_response(
        EndpointResponseBody {
            request_id,
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
            validator: address,
            node_id,
            addresses: vec![EndpointAddress::ipv4([198, 51, 100, node_id[0]], port).unwrap()],
            anchor_number: snapshot.block.number,
            anchor_hash: snapshot.block.hash,
            valid_until: snapshot
                .block
                .number
                .checked_add(MAX_ENDPOINT_TTL_BLOCKS)
                .unwrap(),
        },
        signer,
    )
    .unwrap()
}

async fn wait_for_frames(sent: &SentFrames, count: usize) -> Vec<(bls12381::PublicKey, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let frames = sent.lock().unwrap().clone();
            if frames.len() >= count {
                return frames;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn request_response_and_signed_evidence() {
    let signer_a = bls12381::PrivateKey::from_seed(1);
    let signer_b = bls12381::PrivateKey::from_seed(2);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sender = MockSender { sent: sent.clone() };
    let (incoming, receiver) = mpsc::unbounded_channel();
    let (gate, status) = RadicleStatusChannel::enabled(Address::repeat_byte(0x11), [1_u8; 32]);
    gate.mark_startup_ready();
    let (service, resolver, evidence) = EndpointNetwork::build(
        ChainIdentity {
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
        },
        status,
    );
    let local = LocalEndpointIdentity {
        validator: Address::repeat_byte(0x11),
        node_id: [1_u8; 32],
        addresses: vec![EndpointAddress::dns("a.example.com", 8776).unwrap()],
    };
    let (_, local) = LocalEndpointIdentityChannel::create(local);
    let task =
        tokio::spawn(service.run(sender, MockReceiver { receiver }, signer_a.clone(), local));
    let current = snapshot(10, &signer_a, &signer_b, true);

    assert!(resolver.refresh(&current).await.unwrap().is_empty());
    let frames = wait_for_frames(&sent, 1).await;
    let request = match EndpointFrame::decode(&frames[0].1).unwrap() {
        EndpointFrame::Request(request) => request,
        other => panic!("expected request, got {other:?}"),
    };
    let signed = response(
        request.request_id(),
        &current,
        &signer_b,
        Address::repeat_byte(0x22),
        [2_u8; 32],
        8776,
    );
    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Response(Box::new(signed.clone()))
                .encode()
                .into(),
        ))
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if evidence.snapshot().len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let refreshed = resolver.refresh(&current).await.unwrap();
    assert_eq!(refreshed.len(), 1);
    let proof = &evidence.snapshot()[0];
    assert_eq!(proof.response, signed);
    assert_eq!(
        proof.encoded_frame,
        EndpointFrame::Response(Box::new(signed.clone())).encode()
    );
    outbe_radicle::endpoint::verify_response(
        PeerId::from_public_key(&signer_b.public_key()),
        &proof.response,
        &anchor(&current),
        VerificationContext {
            chain: ChainIdentity {
                chain_id: 70_860_602,
                genesis_hash: B256::repeat_byte(0xaa),
            },
            current_height: current.block.number,
        },
    )
    .unwrap();

    resolver.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn response_gate() {
    let signer_a = bls12381::PrivateKey::from_seed(11);
    let signer_b = bls12381::PrivateKey::from_seed(12);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sender = MockSender { sent: sent.clone() };
    let (incoming, receiver) = mpsc::unbounded_channel();
    let (gate, status) = RadicleStatusChannel::enabled(Address::repeat_byte(0x11), [1_u8; 32]);
    let (service, resolver, _evidence) = EndpointNetwork::build(
        ChainIdentity {
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
        },
        status,
    );
    let task = tokio::spawn(
        service.run(
            sender,
            MockReceiver { receiver },
            signer_a.clone(),
            LocalEndpointIdentityChannel::create(LocalEndpointIdentity {
                validator: Address::repeat_byte(0x11),
                node_id: [1_u8; 32],
                addresses: vec![EndpointAddress::dns("a.example.com", 8776).unwrap()],
            })
            .1,
        ),
    );
    let joining = snapshot(20, &signer_a, &signer_b, false);
    resolver.refresh(&joining).await.unwrap();
    let baseline = wait_for_frames(&sent, 1).await.len();

    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Request(EndpointRequest::new([9_u8; 32]).unwrap())
                .encode()
                .into(),
        ))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let responses = sent
        .lock()
        .unwrap()
        .iter()
        .skip(baseline)
        .filter(|(_, bytes)| matches!(EndpointFrame::decode(bytes), Ok(EndpointFrame::Response(_))))
        .count();
    assert_eq!(responses, 0);

    let bound = snapshot(21, &signer_a, &signer_b, true);
    resolver.refresh(&bound).await.unwrap();
    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Request(EndpointRequest::new([10_u8; 32]).unwrap())
                .encode()
                .into(),
        ))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let responses = sent
        .lock()
        .unwrap()
        .iter()
        .skip(baseline)
        .filter(|(_, bytes)| matches!(EndpointFrame::decode(bytes), Ok(EndpointFrame::Response(_))))
        .count();
    assert_eq!(responses, 0);

    gate.mark_startup_ready();
    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Request(EndpointRequest::new([11_u8; 32]).unwrap())
                .encode()
                .into(),
        ))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let responses = sent
                .lock()
                .unwrap()
                .iter()
                .skip(baseline)
                .filter(|(_, bytes)| {
                    matches!(EndpointFrame::decode(bytes), Ok(EndpointFrame::Response(_)))
                })
                .count();
            if responses == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    gate.set_voting_gate(RadicleVotingGate::Fatal(
        RadicleVotingGateError::BindingMismatch,
    ));
    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Request(EndpointRequest::new([12_u8; 32]).unwrap())
                .encode()
                .into(),
        ))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let responses = sent
        .lock()
        .unwrap()
        .iter()
        .skip(baseline)
        .filter(|(_, bytes)| matches!(EndpointFrame::decode(bytes), Ok(EndpointFrame::Response(_))))
        .count();
    assert_eq!(responses, 1);

    resolver.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn live_local_endpoint_identity_replaces_addresses_and_suppresses_stale_responses() {
    let signer_a = bls12381::PrivateKey::from_seed(31);
    let signer_b = bls12381::PrivateKey::from_seed(32);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sender = MockSender { sent: sent.clone() };
    let (incoming, receiver) = mpsc::unbounded_channel();
    let (gate, status) = RadicleStatusChannel::enabled(Address::repeat_byte(0x11), [1_u8; 32]);
    gate.mark_startup_ready();
    let (service, resolver, _evidence) = EndpointNetwork::build(
        ChainIdentity {
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
        },
        status,
    );
    let (publisher, local) = LocalEndpointIdentityChannel::create(LocalEndpointIdentity {
        validator: Address::repeat_byte(0x11),
        node_id: [1_u8; 32],
        addresses: vec![EndpointAddress::dns("a.example.com", 8776).unwrap()],
    });
    let task =
        tokio::spawn(service.run(sender, MockReceiver { receiver }, signer_a.clone(), local));
    let current = snapshot(40, &signer_a, &signer_b, true);
    resolver.refresh(&current).await.unwrap();
    let baseline = wait_for_frames(&sent, 1).await.len();

    let send_request = |request_id: u8| {
        incoming
            .send((
                signer_b.public_key(),
                EndpointFrame::Request(EndpointRequest::new([request_id; 32]).unwrap())
                    .encode()
                    .into(),
            ))
            .unwrap();
    };
    let response_addresses = || {
        sent.lock()
            .unwrap()
            .iter()
            .skip(baseline)
            .filter_map(|(_, bytes)| match EndpointFrame::decode(bytes).ok()? {
                EndpointFrame::Response(response) => Some(response.body().addresses.clone()),
                EndpointFrame::Request(_) => None,
            })
            .collect::<Vec<_>>()
    };

    send_request(41);
    tokio::time::timeout(Duration::from_secs(1), async {
        while response_addresses().len() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        response_addresses()[0],
        vec![EndpointAddress::dns("a.example.com", 8776).unwrap()]
    );

    assert!(publisher.update(
        [1_u8; 32],
        vec![EndpointAddress::dns("a.example.com", 9776).unwrap()]
    ));
    send_request(42);
    tokio::time::timeout(Duration::from_secs(1), async {
        while response_addresses().len() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        response_addresses()[1],
        vec![EndpointAddress::dns("a.example.com", 9776).unwrap()]
    );

    publisher.unavailable();
    send_request(43);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(response_addresses().len(), 2);

    assert!(!publisher.update(
        [9_u8; 32],
        vec![EndpointAddress::dns("wrong.example.com", 10776).unwrap()]
    ));
    send_request(44);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(response_addresses().len(), 2);

    assert!(publisher.update(
        [1_u8; 32],
        vec![EndpointAddress::ipv4([198, 51, 100, 1], 11776).unwrap()]
    ));
    send_request(45);
    tokio::time::timeout(Duration::from_secs(1), async {
        while response_addresses().len() != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        response_addresses()[2],
        vec![EndpointAddress::ipv4([198, 51, 100, 1], 11776).unwrap()]
    );

    resolver.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn future_anchor_evidence_is_published_only_after_exact_resolution() {
    let signer_a = bls12381::PrivateKey::from_seed(21);
    let signer_b = bls12381::PrivateKey::from_seed(22);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sender = MockSender { sent: sent.clone() };
    let (incoming, receiver) = mpsc::unbounded_channel();
    let (gate, status) = RadicleStatusChannel::enabled(Address::repeat_byte(0x11), [1_u8; 32]);
    gate.mark_startup_ready();
    let (service, resolver, evidence) = EndpointNetwork::build(
        ChainIdentity {
            chain_id: 70_860_602,
            genesis_hash: B256::repeat_byte(0xaa),
        },
        status,
    );
    let task = tokio::spawn(
        service.run(
            sender,
            MockReceiver { receiver },
            signer_a.clone(),
            LocalEndpointIdentityChannel::create(LocalEndpointIdentity {
                validator: Address::repeat_byte(0x11),
                node_id: [1_u8; 32],
                addresses: vec![EndpointAddress::dns("a.example.com", 8776).unwrap()],
            })
            .1,
        ),
    );
    let at_30 = snapshot(30, &signer_a, &signer_b, true);
    let at_31 = snapshot(31, &signer_a, &signer_b, true);
    resolver.refresh(&at_30).await.unwrap();
    let frames = wait_for_frames(&sent, 1).await;
    let request_id = match EndpointFrame::decode(&frames[0].1).unwrap() {
        EndpointFrame::Request(request) => request.request_id(),
        _ => unreachable!(),
    };
    let signed = response(
        request_id,
        &at_31,
        &signer_b,
        Address::repeat_byte(0x22),
        [2_u8; 32],
        9776,
    );
    incoming
        .send((
            signer_b.public_key(),
            EndpointFrame::Response(Box::new(signed)).encode().into(),
        ))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(evidence.snapshot().is_empty());

    resolver.refresh(&at_31).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while evidence.snapshot().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    resolver.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}
