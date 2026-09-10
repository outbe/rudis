#![allow(dead_code)]

use alloy_primitives::{Address, B256};
use commonware_cryptography::{bls12381, Signer as _};
use outbe_radicle::{
    endpoint::{EndpointAddress, PeerId, VerifiedEndpoint},
    manager::{
        BoxFuture, ControlSession, DisconnectDisposition, EndpointResolver, FinalizedBlock,
        FinalizedFeed, FinalizedSnapshot, FinalizedValidator, HeartwoodControl, ManagerError,
        RepoId, RepositoryStatus, SessionDirection, SnapshotReader,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;

pub const SELF: Address = Address::repeat_byte(1);
pub const LOCAL_NODE: [u8; 32] = [1; 32];

pub fn block(number: u64) -> FinalizedBlock {
    FinalizedBlock {
        number,
        hash: B256::with_last_byte(number as u8),
    }
}

pub fn validator(index: u8) -> FinalizedValidator {
    FinalizedValidator {
        address: Address::repeat_byte(index),
        peer: peer(index),
        node_id: Some([index; 32]),
    }
}

pub fn snapshot(number: u64, count: u8, repositories: Vec<RepoId>) -> FinalizedSnapshot {
    FinalizedSnapshot {
        block: block(number),
        validators: (1..=count).map(validator).collect(),
        registry_generation: repositories.len() as u64,
        repositories,
    }
}

pub fn endpoint(index: u8, anchor: u64, port: u16) -> VerifiedEndpoint {
    VerifiedEndpoint {
        validator: Address::repeat_byte(index),
        peer: peer(index),
        node_id: [index; 32],
        addresses: vec![EndpointAddress::dns(&format!("n{index}.outbe.test"), port).unwrap()],
        anchor_number: anchor,
        anchor_hash: block(anchor).hash,
        valid_until: anchor + 100,
    }
}

fn peer(index: u8) -> PeerId {
    let signer = bls12381::PrivateKey::from_seed(u64::from(index));
    PeerId::from_public_key(&signer.public_key())
}

#[derive(Clone)]
pub struct Feed {
    events: Arc<Mutex<Vec<&'static str>>>,
    sample: Arc<Mutex<Result<Option<FinalizedBlock>, ManagerError>>>,
    receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<FinalizedBlock>>>>,
    sender: mpsc::UnboundedSender<FinalizedBlock>,
}

impl Feed {
    pub fn new(sample: FinalizedBlock) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            sample: Arc::new(Mutex::new(Ok(Some(sample)))),
            receiver: Arc::new(Mutex::new(Some(receiver))),
            sender,
        }
    }

    pub fn push(&self, block: FinalizedBlock) {
        self.sender.send(block).unwrap();
    }

    pub fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
}

impl FinalizedFeed for Feed {
    fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<FinalizedBlock>, ManagerError> {
        self.events.lock().unwrap().push("subscribe");
        self.receiver
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| ManagerError::Finality("already subscribed".into()))
    }

    fn sample(&self) -> BoxFuture<'_, Result<Option<FinalizedBlock>, ManagerError>> {
        self.events.lock().unwrap().push("sample");
        let sample = self.sample.lock().unwrap().clone();
        Box::pin(async move { sample })
    }
}

#[derive(Clone, Default)]
pub struct Snapshots {
    values: Arc<Mutex<BTreeMap<FinalizedBlock, FinalizedSnapshot>>>,
    reads: Arc<Mutex<Vec<FinalizedBlock>>>,
}

impl Snapshots {
    pub fn insert(&self, snapshot: FinalizedSnapshot) {
        self.values.lock().unwrap().insert(snapshot.block, snapshot);
    }

    pub fn reads(&self) -> Vec<FinalizedBlock> {
        self.reads.lock().unwrap().clone()
    }
}

impl SnapshotReader for Snapshots {
    fn read_exact(&self, block: FinalizedBlock) -> Result<FinalizedSnapshot, ManagerError> {
        self.reads.lock().unwrap().push(block);
        self.values
            .lock()
            .unwrap()
            .get(&block)
            .cloned()
            .ok_or_else(|| ManagerError::Provider("lagging".into()))
    }
}

#[derive(Clone, Default)]
pub struct Endpoints {
    values: Arc<Mutex<BTreeMap<Address, VerifiedEndpoint>>>,
    fail: Arc<Mutex<bool>>,
}

impl Endpoints {
    pub fn set(&self, endpoint: VerifiedEndpoint) {
        self.values
            .lock()
            .unwrap()
            .insert(endpoint.validator, endpoint);
    }

    pub fn remove(&self, validator: Address) {
        self.values.lock().unwrap().remove(&validator);
    }

    pub fn fail(&self, fail: bool) {
        *self.fail.lock().unwrap() = fail;
    }
}

impl EndpointResolver for Endpoints {
    fn refresh<'a>(
        &'a self,
        snapshot: &'a FinalizedSnapshot,
    ) -> BoxFuture<'a, Result<Vec<VerifiedEndpoint>, ManagerError>> {
        Box::pin(async move {
            if *self.fail.lock().unwrap() {
                return Err(ManagerError::Endpoint("unavailable".into()));
            }
            let active = snapshot
                .validators
                .iter()
                .map(|validator| validator.address)
                .collect::<BTreeSet<_>>();
            Ok(self
                .values
                .lock()
                .unwrap()
                .values()
                .filter(|endpoint| active.contains(&endpoint.validator))
                .cloned()
                .collect())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Connect([u8; 32], EndpointAddress),
    Disconnect([u8; 32], EndpointAddress),
    Seed(RepoId),
}

#[derive(Clone)]
pub struct Control {
    node_id: [u8; 32],
    sessions: Arc<Mutex<Vec<ControlSession>>>,
    calls: Arc<Mutex<Vec<Call>>>,
    fail_sessions: Arc<Mutex<bool>>,
    fail_connect: Arc<Mutex<BTreeSet<[u8; 32]>>>,
    fail_seed: Arc<Mutex<BTreeSet<RepoId>>>,
    disconnect_disposition: Arc<Mutex<DisconnectDisposition>>,
}

impl Control {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            sessions: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            fail_sessions: Arc::new(Mutex::new(false)),
            fail_connect: Arc::new(Mutex::new(BTreeSet::new())),
            fail_seed: Arc::new(Mutex::new(BTreeSet::new())),
            disconnect_disposition: Arc::new(Mutex::new(DisconnectDisposition::Disconnected)),
        }
    }

    pub fn add_session(&self, session: ControlSession) {
        self.sessions.lock().unwrap().push(session);
    }

    pub fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn fail_sessions(&self, fail: bool) {
        *self.fail_sessions.lock().unwrap() = fail;
    }

    pub fn fail_connect(&self, node_id: [u8; 32], fail: bool) {
        if fail {
            self.fail_connect.lock().unwrap().insert(node_id);
        } else {
            self.fail_connect.lock().unwrap().remove(&node_id);
        }
    }

    pub fn fail_seed(&self, repo: RepoId, fail: bool) {
        if fail {
            self.fail_seed.lock().unwrap().insert(repo);
        } else {
            self.fail_seed.lock().unwrap().remove(&repo);
        }
    }

    pub fn set_disconnect(&self, disposition: DisconnectDisposition) {
        *self.disconnect_disposition.lock().unwrap() = disposition;
    }
}

impl HeartwoodControl for Control {
    fn node_id(&self) -> BoxFuture<'_, Result<[u8; 32], ManagerError>> {
        let node_id = self.node_id;
        Box::pin(async move { Ok(node_id) })
    }

    fn sessions(&self) -> BoxFuture<'_, Result<Vec<ControlSession>, ManagerError>> {
        Box::pin(async move {
            if *self.fail_sessions.lock().unwrap() {
                Err(ManagerError::Control("offline".into()))
            } else {
                Ok(self.sessions.lock().unwrap().clone())
            }
        })
    }

    fn connect<'a>(
        &'a self,
        node_id: [u8; 32],
        addresses: &'a [EndpointAddress],
    ) -> BoxFuture<'a, Result<EndpointAddress, ManagerError>> {
        Box::pin(async move {
            let address = addresses
                .first()
                .cloned()
                .ok_or_else(|| ManagerError::Control("no address".into()))?;
            self.calls
                .lock()
                .unwrap()
                .push(Call::Connect(node_id, address.clone()));
            if self.fail_connect.lock().unwrap().contains(&node_id) {
                return Err(ManagerError::Control("connect failed".into()));
            }
            self.sessions.lock().unwrap().push(ControlSession {
                node_id,
                address: address.clone(),
                direction: SessionDirection::Outbound,
                connected: true,
            });
            Ok(address)
        })
    }

    fn disconnect<'a>(
        &'a self,
        node_id: [u8; 32],
        expected: &'a EndpointAddress,
    ) -> BoxFuture<'a, Result<DisconnectDisposition, ManagerError>> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Disconnect(node_id, expected.clone()));
            let disposition = *self.disconnect_disposition.lock().unwrap();
            if matches!(
                disposition,
                DisconnectDisposition::Disconnected | DisconnectDisposition::AlreadyAbsent
            ) {
                self.sessions.lock().unwrap().retain(|session| {
                    session.node_id != node_id
                        || session.direction != SessionDirection::Outbound
                        || &session.address != expected
                });
            }
            Ok(disposition)
        })
    }

    fn seed(&self, repo: RepoId) -> BoxFuture<'_, Result<(), ManagerError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(Call::Seed(repo));
            if self.fail_seed.lock().unwrap().contains(&repo) {
                Err(ManagerError::Control("seed failed".into()))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Clone, Default)]
pub struct Availability {
    available: Arc<Mutex<BTreeSet<RepoId>>>,
    fail: Arc<Mutex<bool>>,
}

impl Availability {
    pub fn set(&self, repo: RepoId, available: bool) {
        if available {
            self.available.lock().unwrap().insert(repo);
        } else {
            self.available.lock().unwrap().remove(&repo);
        }
    }

    pub fn fail(&self, fail: bool) {
        *self.fail.lock().unwrap() = fail;
    }
}

impl RepositoryStatus for Availability {
    fn available(&self, repo: RepoId) -> BoxFuture<'_, Result<bool, ManagerError>> {
        Box::pin(async move {
            if *self.fail.lock().unwrap() {
                Err(ManagerError::Status("offline".into()))
            } else {
                Ok(self.available.lock().unwrap().contains(&repo))
            }
        })
    }
}

pub fn inbound(index: u8, anchor: u64) -> ControlSession {
    ControlSession {
        node_id: [index; 32],
        address: endpoint(index, anchor, 8776).addresses[0].clone(),
        direction: SessionDirection::Inbound,
        connected: true,
    }
}

pub fn outbound(index: u8, anchor: u64, port: u16) -> ControlSession {
    ControlSession {
        node_id: [index; 32],
        address: endpoint(index, anchor, port).addresses[0].clone(),
        direction: SessionDirection::Outbound,
        connected: true,
    }
}

pub fn pending_outbound(index: u8, anchor: u64, port: u16) -> ControlSession {
    let mut session = outbound(index, anchor, port);
    session.connected = false;
    session
}

pub fn repo(byte: u8) -> RepoId {
    RepoId::repeat_byte(byte)
}

pub fn pop_call(calls: &mut VecDeque<Call>) -> Call {
    calls.pop_front().expect("missing call")
}
