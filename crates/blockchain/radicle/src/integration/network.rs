use crate::integration::{RadicleStatusHandle, RadicleVotingGate};
use crate::{
    endpoint::{
        sign_response, AnchorSnapshot, AuthorityRecord, ChainIdentity, EndpointActor,
        EndpointAddress, EndpointFrame, EndpointHandle, EndpointProtocol, EndpointResponseBody,
        OsRequestIds, PeerId, ReceiveOutcome, SignedEndpointResponse, VerifiedEndpoint,
        HANDLE_DEADLINE, MAX_ADDRESSES, MAX_ENDPOINT_TTL_BLOCKS, UNKNOWN_ANCHOR_TIMEOUT_MS,
    },
    manager::{BoxFuture, EndpointResolver, FinalizedSnapshot, ManagerError, RadicleManagerHandle},
};
use alloy_primitives::Address;
use commonware_cryptography::{bls12381, Signer as _};
use commonware_p2p::{CheckedSender as _, LimitedSender, Receiver, Recipients};
use commonware_runtime::IoBuf;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEndpointIdentity {
    pub validator: Address,
    pub node_id: [u8; 32],
    pub addresses: Vec<EndpointAddress>,
}

pub struct LocalEndpointIdentityChannel;

#[derive(Clone)]
pub struct LocalEndpointIdentityPublisher {
    validator: Address,
    expected_node_id: [u8; 32],
    sender: watch::Sender<Option<LocalEndpointIdentity>>,
}

#[derive(Clone)]
pub struct LocalEndpointIdentityHandle {
    validator: Address,
    receiver: watch::Receiver<Option<LocalEndpointIdentity>>,
}

impl LocalEndpointIdentityChannel {
    #[must_use]
    pub fn create(
        initial: LocalEndpointIdentity,
    ) -> (LocalEndpointIdentityPublisher, LocalEndpointIdentityHandle) {
        let validator = initial.validator;
        let expected_node_id = initial.node_id;
        let (sender, receiver) = watch::channel(Some(initial));
        (
            LocalEndpointIdentityPublisher {
                validator,
                expected_node_id,
                sender,
            },
            LocalEndpointIdentityHandle {
                validator,
                receiver,
            },
        )
    }
}

impl LocalEndpointIdentityPublisher {
    pub fn update(&self, node_id: [u8; 32], mut addresses: Vec<EndpointAddress>) -> bool {
        addresses.sort();
        let valid = node_id == self.expected_node_id
            && !addresses.is_empty()
            && addresses.len() <= MAX_ADDRESSES
            && !addresses.windows(2).any(|pair| pair[0] == pair[1]);
        self.sender
            .send_replace(valid.then_some(LocalEndpointIdentity {
                validator: self.validator,
                node_id,
                addresses,
            }));
        valid
    }

    pub fn unavailable(&self) {
        self.sender.send_replace(None);
    }
}

impl LocalEndpointIdentityHandle {
    fn current(&self) -> Option<LocalEndpointIdentity> {
        self.receiver.borrow().clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEndpointEvidence {
    pub peer: PeerId,
    pub response: SignedEndpointResponse,
    pub encoded_frame: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct EndpointEvidenceHandle(Arc<RwLock<BTreeMap<PeerId, SignedEndpointEvidence>>>);

impl EndpointEvidenceHandle {
    #[must_use]
    pub fn snapshot(&self) -> Vec<SignedEndpointEvidence> {
        self.0
            .read()
            .expect("endpoint evidence lock poisoned")
            .values()
            .cloned()
            .collect()
    }
}

pub struct EndpointNetwork;

pub struct EndpointNetworkService {
    chain: ChainIdentity,
    actor: Option<EndpointActor<OsRequestIds>>,
    handle: EndpointHandle,
    commands: mpsc::Receiver<NetworkCommand>,
    evidence: EndpointEvidenceHandle,
    status: RadicleStatusHandle,
}

#[derive(Clone)]
pub struct EndpointNetworkResolver {
    commands: mpsc::Sender<NetworkCommand>,
}

enum NetworkCommand {
    Refresh {
        snapshot: FinalizedSnapshot,
        result: oneshot::Sender<Result<Vec<VerifiedEndpoint>, ManagerError>>,
    },
    Shutdown {
        result: oneshot::Sender<Result<(), ManagerError>>,
    },
}

impl EndpointNetwork {
    #[must_use]
    pub fn build(
        chain: ChainIdentity,
        status: RadicleStatusHandle,
    ) -> (
        EndpointNetworkService,
        EndpointNetworkResolver,
        EndpointEvidenceHandle,
    ) {
        let protocol = EndpointProtocol::new(chain, OsRequestIds);
        let (actor, handle) = EndpointActor::new(protocol);
        let (commands, receiver) = mpsc::channel(256);
        let evidence = EndpointEvidenceHandle::default();
        (
            EndpointNetworkService {
                chain,
                actor: Some(actor),
                handle,
                commands: receiver,
                evidence: evidence.clone(),
                status,
            },
            EndpointNetworkResolver { commands },
            evidence,
        )
    }
}

impl EndpointNetworkResolver {
    pub async fn shutdown(&self) -> Result<(), ManagerError> {
        let (result, response) = oneshot::channel();
        tokio::time::timeout(HANDLE_DEADLINE, async {
            self.commands
                .send(NetworkCommand::Shutdown { result })
                .await
                .map_err(|_| ManagerError::Endpoint("shutdown mailbox closed".into()))?;
            response
                .await
                .map_err(|_| ManagerError::Endpoint("shutdown acknowledgement closed".into()))?
        })
        .await
        .map_err(|_| ManagerError::ShutdownDeadline("endpoint"))?
    }
}

impl EndpointResolver for EndpointNetworkResolver {
    fn refresh<'a>(
        &'a self,
        snapshot: &'a FinalizedSnapshot,
    ) -> BoxFuture<'a, Result<Vec<VerifiedEndpoint>, ManagerError>> {
        Box::pin(async move {
            let (result, response) = oneshot::channel();
            self.commands
                .try_send(NetworkCommand::Refresh {
                    snapshot: snapshot.clone(),
                    result,
                })
                .map_err(|_| ManagerError::Stopped)?;
            tokio::time::timeout(HANDLE_DEADLINE, response)
                .await
                .map_err(|_| ManagerError::Endpoint("endpoint refresh deadline exceeded".into()))?
                .map_err(|_| ManagerError::Stopped)?
        })
    }
}

impl EndpointNetworkService {
    pub async fn run<S, R>(
        mut self,
        mut sender: S,
        mut receiver: R,
        signer: bls12381::PrivateKey,
        local: LocalEndpointIdentityHandle,
    ) -> Result<(), ManagerError>
    where
        S: LimitedSender<PublicKey = bls12381::PublicKey> + Send + 'static,
        R: Receiver<PublicKey = bls12381::PublicKey> + Send + 'static,
        R::Error: std::fmt::Display,
    {
        // Dropping or unwinding the network service also aborts its owned actor.
        let mut actor = JoinSet::new();
        actor.spawn(
            self.actor
                .take()
                .expect("endpoint service may only run once")
                .run(),
        );
        let mut current = None;
        let mut queued = BTreeMap::<PeerId, (SignedEndpointResponse, u64)>::new();
        let mut shutdown_ack = None;
        let outcome = loop {
            tokio::select! {
                joined = actor.join_next() => {
                    break Err(match joined {
                        Some(Err(error)) => ManagerError::Task(format!("endpoint actor: {error}")),
                        _ => ManagerError::Endpoint("endpoint actor stopped unexpectedly".into()),
                    });
                }
                command = self.commands.recv() => {
                    match command {
                        Some(NetworkCommand::Refresh { snapshot, result }) => {
                            let refreshed = self.refresh(
                                &mut sender,
                                local.validator,
                                &snapshot,
                                &mut queued,
                            ).await;
                            current = Some(snapshot);
                            let _ = result.send(refreshed);
                        }
                        Some(NetworkCommand::Shutdown { result }) => {
                            shutdown_ack = Some(result);
                            break Ok(());
                        }
                        None => break Ok(()),
                    }
                }
                received = receiver.recv() => {
                    let (peer, bytes) = match received {
                        Ok(received) => received,
                        Err(error) => break Err(ManagerError::Endpoint(error.to_string())),
                    };
                    if let Err(error) = self.receive(
                        &mut sender,
                        &signer,
                        &local,
                        current.as_ref(),
                        &mut queued,
                        (peer, bytes),
                    ).await {
                        break Err(error);
                    }
                }
            }
        };
        self.commands.close();
        let cleanup = if actor.is_empty() {
            Ok(())
        } else {
            stop_actor(&self.handle, &mut actor).await
        };
        // Preserve a transport failure even if cleanup also fails.
        let outcome = match (outcome, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(ManagerError::Task(format!(
                "{error}; endpoint actor cleanup also failed: {cleanup}"
            ))),
        };
        if let Some(result) = shutdown_ack {
            let _ = result.send(outcome.clone());
        }
        outcome
    }

    async fn refresh<S>(
        &self,
        sender: &mut S,
        local_validator: Address,
        snapshot: &FinalizedSnapshot,
        queued: &mut BTreeMap<PeerId, (SignedEndpointResponse, u64)>,
    ) -> Result<Vec<VerifiedEndpoint>, ManagerError>
    where
        S: LimitedSender<PublicKey = bls12381::PublicKey>,
    {
        let anchor = anchor(snapshot)?;
        let now = now_millis();
        queued.retain(|_, (_, deadline)| *deadline > now);
        for resolved in self
            .handle
            .resolve(anchor.clone(), snapshot.block.number, now)
            .await
            .map_err(|error| ManagerError::Endpoint(error.to_string()))?
        {
            let raw = queued.remove(&resolved.peer).map(|(response, _)| response);
            if let (Ok(verified), Some(response)) = (resolved.result, raw) {
                self.publish(resolved.peer, response, verified);
            }
        }
        self.prune(snapshot);

        for validator in snapshot
            .validators
            .iter()
            .filter(|validator| validator.address != local_validator && validator.node_id.is_some())
        {
            let request = match self.handle.request(validator.peer, now).await {
                Ok(request) => request,
                Err(_) => continue,
            };
            let request_id = match EndpointFrame::decode(&request) {
                Ok(EndpointFrame::Request(request)) => request.request_id(),
                _ => continue,
            };
            if !send(sender, validator.peer, request) {
                let _ = self.handle.send_failed(validator.peer, request_id).await;
            }
        }
        Ok(self
            .evidence
            .snapshot()
            .into_iter()
            .map(|proof| verified_from_response(proof.peer, &proof.response))
            .collect())
    }

    async fn receive<S>(
        &self,
        sender: &mut S,
        signer: &bls12381::PrivateKey,
        local: &LocalEndpointIdentityHandle,
        snapshot: Option<&FinalizedSnapshot>,
        queued: &mut BTreeMap<PeerId, (SignedEndpointResponse, u64)>,
        received: (bls12381::PublicKey, IoBuf),
    ) -> Result<(), ManagerError>
    where
        S: LimitedSender<PublicKey = bls12381::PublicKey>,
    {
        let (sender_key, bytes) = received;
        let peer = PeerId::from_public_key(&sender_key);
        match EndpointFrame::decode(bytes.as_ref()) {
            Ok(EndpointFrame::Request(request)) => {
                if self.status.snapshot().voting_gate != RadicleVotingGate::SignerAllowed {
                    return Ok(());
                }
                let Some(local) = local.current() else {
                    return Ok(());
                };
                let Some(snapshot) = snapshot else {
                    return Ok(());
                };
                let Some(validator) = snapshot.validators.iter().find(|validator| {
                    validator.address == local.validator
                        && validator.peer == PeerId::from_public_key(&signer.public_key())
                        && validator.node_id == Some(local.node_id)
                }) else {
                    return Ok(());
                };
                let Some(valid_until) = snapshot.block.number.checked_add(MAX_ENDPOINT_TTL_BLOCKS)
                else {
                    return Ok(());
                };
                let response = sign_response(
                    EndpointResponseBody {
                        request_id: request.request_id(),
                        chain_id: self.chain.chain_id,
                        genesis_hash: self.chain.genesis_hash,
                        validator: validator.address,
                        node_id: local.node_id,
                        addresses: local.addresses.clone(),
                        anchor_number: snapshot.block.number,
                        anchor_hash: snapshot.block.hash,
                        valid_until,
                    },
                    signer,
                )
                .map_err(|error| ManagerError::Endpoint(error.to_string()))?;
                let _ = send(
                    sender,
                    peer,
                    EndpointFrame::Response(Box::new(response)).encode(),
                );
            }
            Ok(EndpointFrame::Response(response)) => {
                let Some(snapshot) = snapshot else {
                    return Ok(());
                };
                let response = *response;
                let anchor = (response.body().anchor_number == snapshot.block.number)
                    .then(|| anchor(snapshot))
                    .transpose()?;
                match self
                    .handle
                    .response(
                        peer,
                        response.clone(),
                        snapshot.block.number,
                        anchor,
                        now_millis(),
                    )
                    .await
                {
                    Ok(ReceiveOutcome::Verified(verified)) => {
                        self.publish(peer, response, verified);
                    }
                    Ok(ReceiveOutcome::Queued { .. }) => {
                        queued.insert(
                            peer,
                            (
                                response,
                                now_millis().saturating_add(UNKNOWN_ANCHOR_TIMEOUT_MS),
                            ),
                        );
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
        Ok(())
    }

    fn publish(&self, peer: PeerId, response: SignedEndpointResponse, _verified: VerifiedEndpoint) {
        let encoded_frame = EndpointFrame::Response(Box::new(response.clone())).encode();
        self.evidence
            .0
            .write()
            .expect("endpoint evidence lock poisoned")
            .insert(
                peer,
                SignedEndpointEvidence {
                    peer,
                    response,
                    encoded_frame,
                },
            );
    }

    fn prune(&self, snapshot: &FinalizedSnapshot) {
        self.evidence
            .0
            .write()
            .expect("endpoint evidence lock poisoned")
            .retain(|peer, proof| {
                let body = proof.response.body();
                body.valid_until > snapshot.block.number
                    && snapshot.validators.iter().any(|validator| {
                        validator.address == body.validator
                            && validator.peer == *peer
                            && validator.node_id == Some(body.node_id)
                    })
            });
    }
}

/// Drain the manager before closing its endpoint dependency. Each stage gets
/// `deadline`, including endpoint cleanup after a manager failure or timeout.
/// The manager reserves up to one second within its budget for abort-and-join.
pub async fn shutdown_bounded<E>(
    deadline: Duration,
    manager: RadicleManagerHandle,
    endpoint: E,
) -> Result<(), ManagerError>
where
    E: Future<Output = Result<(), ManagerError>>,
{
    let manager = manager.shutdown_bounded(deadline).await;
    let endpoint = tokio::time::timeout(deadline, endpoint)
        .await
        .unwrap_or(Err(ManagerError::ShutdownDeadline("endpoint")));
    match (manager, endpoint) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(manager), Err(endpoint)) => Err(ManagerError::Shutdown {
            manager: Box::new(manager),
            endpoint: Box::new(endpoint),
        }),
    }
}

async fn stop_actor(handle: &EndpointHandle, actor: &mut JoinSet<()>) -> Result<(), ManagerError> {
    let end = tokio::time::Instant::now() + HANDLE_DEADLINE;
    let drain_end = end - Duration::from_secs(1);
    let stopped = tokio::time::timeout_at(drain_end, handle.shutdown())
        .await
        .map_err(|_| ManagerError::ShutdownDeadline("endpoint actor"))
        .and_then(|result| {
            result.map_err(|error| match error {
                crate::endpoint::HandleError::Deadline => {
                    ManagerError::ShutdownDeadline("endpoint actor")
                }
                error => ManagerError::Endpoint(error.to_string()),
            })
        });
    if stopped.is_err() {
        actor.abort_all();
    }
    let join_end = if stopped.is_err() { end } else { drain_end };
    match tokio::time::timeout_at(join_end, actor.join_next()).await {
        Ok(Some(Ok(()))) => stopped,
        // Keep the failure that required cancellation, including a closed ACK.
        Ok(Some(Err(error))) if error.is_cancelled() && stopped.is_err() => stopped,
        // A panic carries more information than the closed ACK it caused.
        Ok(Some(Err(error))) => Err(ManagerError::Task(format!("endpoint actor: {error}"))),
        Ok(None) => Err(ManagerError::Endpoint("endpoint actor join missing".into())),
        Err(_) => {
            actor.abort_all();
            match tokio::time::timeout_at(end, actor.join_next()).await {
                Ok(Some(Err(error))) if !error.is_cancelled() => {
                    Err(ManagerError::Task(format!("endpoint actor: {error}")))
                }
                Ok(_) => Err(ManagerError::ShutdownDeadline("endpoint actor")),
                Err(_) => Err(ManagerError::ShutdownDeadline(
                    "endpoint actor cancellation",
                )),
            }
        }
    }
}

fn anchor(snapshot: &FinalizedSnapshot) -> Result<AnchorSnapshot, ManagerError> {
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
    .map_err(|error| ManagerError::Snapshot(error.to_string()))
}

fn verified_from_response(peer: PeerId, response: &SignedEndpointResponse) -> VerifiedEndpoint {
    let body = response.body();
    VerifiedEndpoint {
        validator: body.validator,
        peer,
        node_id: body.node_id,
        addresses: body.addresses.clone(),
        anchor_number: body.anchor_number,
        anchor_hash: body.anchor_hash,
        valid_until: body.valid_until,
    }
}

fn send<S>(sender: &mut S, peer: PeerId, bytes: Vec<u8>) -> bool
where
    S: LimitedSender<PublicKey = bls12381::PublicKey>,
{
    let Ok(public_key) = peer.to_public_key() else {
        return false;
    };
    sender
        .check(Recipients::One(public_key))
        .map(|checked| checked.send(bytes, false).accepted())
        .unwrap_or(false)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use crate::{endpoint::HandleError, integration::RadicleStatusChannel};
    use alloy_primitives::B256;
    use commonware_actor::{Feedback, Unreliable};
    use commonware_p2p::CheckedSender;
    use commonware_runtime::IoBufs;

    #[derive(Clone)]
    struct NoSend;

    impl LimitedSender for NoSend {
        type PublicKey = bls12381::PublicKey;
        type Checked<'a> = NoSend;

        fn check(
            &mut self,
            _: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            Err(SystemTime::now())
        }
    }

    impl CheckedSender for NoSend {
        type PublicKey = bls12381::PublicKey;

        fn recipients(&self) -> Vec<Self::PublicKey> {
            vec![]
        }

        fn send(self, _: impl Into<IoBufs> + Send, _: bool) -> Unreliable<Feedback> {
            panic!("sender is never admitted")
        }
    }

    #[derive(Debug)]
    struct TestReceiver(mpsc::UnboundedReceiver<(bls12381::PublicKey, IoBuf)>);

    impl Receiver for TestReceiver {
        type PublicKey = bls12381::PublicKey;
        type Error = std::io::Error;

        async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
            self.0.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "transport closed witness")
            })
        }
    }

    struct Running {
        task: tokio::task::JoinHandle<Result<(), ManagerError>>,
        resolver: EndpointNetworkResolver,
        handle: EndpointHandle,
        incoming: mpsc::UnboundedSender<(bls12381::PublicKey, IoBuf)>,
    }

    fn network() -> Running {
        let (_, status) = RadicleStatusChannel::enabled(Address::ZERO, [1; 32]);
        let (service, resolver, _) = EndpointNetwork::build(
            ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            status,
        );
        let handle = service.handle.clone();
        let (_, local) = LocalEndpointIdentityChannel::create(LocalEndpointIdentity {
            validator: Address::ZERO,
            node_id: [1; 32],
            addresses: vec![EndpointAddress::dns("local.example", 8776).unwrap()],
        });
        let (incoming, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(service.run(
            NoSend,
            TestReceiver(receiver),
            bls12381::PrivateKey::from_seed(1),
            local,
        ));
        Running {
            task,
            resolver,
            handle,
            incoming,
        }
    }

    #[tokio::test]
    async fn explicit_shutdown_ack_follows_actor_cleanup() {
        let running = network();
        running.handle.stats().await.unwrap();
        running.resolver.shutdown().await.unwrap();
        assert_eq!(running.handle.stats().await, Err(HandleError::Closed));
        running.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transport_failure_is_preserved_and_actor_reaped() {
        let running = network();
        running.handle.stats().await.unwrap();
        drop(running.incoming);
        assert_eq!(
            running.task.await.unwrap(),
            Err(ManagerError::Endpoint("transport closed witness".into()))
        );
        assert_eq!(running.handle.stats().await, Err(HandleError::Closed));
        assert!(running.resolver.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn closing_network_commands_reaps_actor() {
        let running = network();
        running.handle.stats().await.unwrap();
        drop(running.resolver);
        tokio::time::timeout(Duration::from_secs(1), running.task)
            .await
            .expect("command closure must terminate the actor")
            .unwrap()
            .unwrap();
        assert_eq!(running.handle.stats().await, Err(HandleError::Closed));
    }

    #[tokio::test]
    async fn network_cancellation_aborts_actor() {
        let running = network();
        running.handle.stats().await.unwrap();
        running.task.abort();
        assert!(running.task.await.unwrap_err().is_cancelled());
        assert_eq!(running.handle.stats().await, Err(HandleError::Closed));
    }

    #[tokio::test]
    async fn actor_panic_after_ack_is_not_success() {
        let (actor, handle) = EndpointActor::new(EndpointProtocol::new(
            ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            OsRequestIds,
        ));
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            actor.run().await;
            panic!("actor panic after ack witness");
        });
        let error = stop_actor(&handle, &mut tasks).await.unwrap_err();
        assert!(
            matches!(error, ManagerError::Task(ref message) if message.contains("actor panic after ack witness"))
        );
        assert!(tasks.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_actor_is_aborted_and_reaped_after_ack() {
        let (actor, handle) = EndpointActor::new(EndpointProtocol::new(
            ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            OsRequestIds,
        ));
        let (alive, mut dropped) = oneshot::channel::<()>();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _alive = alive;
            actor.run().await;
            std::future::pending::<()>().await;
        });
        assert_eq!(
            stop_actor(&handle, &mut tasks).await,
            Err(ManagerError::ShutdownDeadline("endpoint actor"))
        );
        assert!(tasks.is_empty());
        assert_eq!(
            dropped.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn actor_cancellation_panic_is_not_a_deadline() {
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("actor cancellation panic witness");
            }
        }
        let (actor, handle) = EndpointActor::new(EndpointProtocol::new(
            ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            OsRequestIds,
        ));
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            actor.run().await;
            let _guard = PanicOnDrop;
            std::future::pending::<()>().await;
        });
        let error = stop_actor(&handle, &mut tasks).await.unwrap_err();
        assert!(tasks.is_empty());
        assert!(
            matches!(error, ManagerError::Task(ref message) if message.contains("actor cancellation panic witness"))
        );
    }

    #[tokio::test]
    async fn shutdown_preserves_closed_acknowledgement() {
        let (commands, mut receiver) = mpsc::channel(1);
        let resolver = EndpointNetworkResolver { commands };
        let responder = tokio::spawn(async move {
            let Some(NetworkCommand::Shutdown { result }) = receiver.recv().await else {
                panic!("expected shutdown");
            };
            drop(result);
        });
        assert_eq!(
            resolver.shutdown().await,
            Err(ManagerError::Endpoint(
                "shutdown acknowledgement closed".into()
            ))
        );
        responder.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_full_mailbox_waits_until_deadline() {
        let (commands, _receiver) = mpsc::channel(1);
        let (result, _response) = oneshot::channel();
        assert!(commands
            .try_send(NetworkCommand::Shutdown { result })
            .is_ok());
        let resolver = EndpointNetworkResolver { commands };
        let started = tokio::time::Instant::now();
        assert_eq!(
            resolver.shutdown().await,
            Err(ManagerError::ShutdownDeadline("endpoint"))
        );
        assert_eq!(started.elapsed(), HANDLE_DEADLINE);
    }

    #[tokio::test]
    async fn shutdown_closed_mailbox_is_not_deadline() {
        let (commands, receiver) = mpsc::channel(1);
        drop(receiver);
        let resolver = EndpointNetworkResolver { commands };
        assert_eq!(
            resolver.shutdown().await,
            Err(ManagerError::Endpoint("shutdown mailbox closed".into()))
        );
    }
}
