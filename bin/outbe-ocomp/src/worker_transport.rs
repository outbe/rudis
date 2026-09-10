//! Axum registration/status plus a TCP ZeroMQ command channel for OCOMP workers.
// OCOMP-TEST-ID: OCM-WTR-001

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use alloy_primitives::{keccak256, B256};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use outbe_ocomp_protocol::{RunUnitV1, SchemaLimits, UnitFinishedV1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeromq::{Endpoint, RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

use crate::control::EndpointIdentity;

pub const MAX_REGISTERED_WORKERS: usize = 4;
const WORKER_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);
const WORK_LEASE_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WORK_RESULT_TIMEOUT: Duration = Duration::from_secs(7_200);
const DISPATCH_CANCEL_POLL: Duration = Duration::from_millis(100);
const DISPATCH_WAIT_REPORT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRegistrationV1 {
    pub chain_id: u64,
    pub genesis_hash: String,
    pub process_nonce: String,
    pub protocol_bundle_hash: String,
    pub max_control_body_bytes: usize,
}

impl WorkerRegistrationV1 {
    pub fn from_identity(identity: EndpointIdentity, limits: SchemaLimits) -> Self {
        Self {
            chain_id: identity.chain_id,
            genesis_hash: format!("{:#x}", identity.genesis_hash),
            process_nonce: format!("{:#x}", identity.boot_nonce),
            protocol_bundle_hash: format!("{:#x}", identity.protocol_bundle_hash),
            max_control_body_bytes: limits.max_control_body_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRegistrationResponseV1 {
    pub worker_id: String,
    pub registry_generation: u64,
    pub lease_timeout_ms: u64,
    pub message_endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseV1 {
    pub worker_id: String,
    pub lease_id: String,
    pub unit_id: String,
    pub delivery_attempt: u32,
    pub lease_timeout_ms: u64,
    pub run_unit_body_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLeaseRefV1 {
    pub worker_id: String,
    pub lease_id: String,
    pub unit_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCompletionV1 {
    pub worker_id: String,
    pub lease_id: String,
    pub unit_id: String,
    pub finished_body_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorCommandV1 {
    Work {
        lease: WorkLeaseV1,
        registry_generation: u64,
    },
    Cancel {
        lease: WorkerLeaseRefV1,
        registry_generation: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerEventV1 {
    Ready {
        worker_id: String,
        registry_generation: u64,
    },
    Accepted {
        lease: WorkerLeaseRefV1,
        registry_generation: u64,
    },
    Heartbeat {
        lease: WorkerLeaseRefV1,
        registry_generation: u64,
    },
    Completed {
        completion: WorkerCompletionV1,
        registry_generation: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerApiStatusV1 {
    pub registry_generation: u64,
    pub registered_workers: usize,
    pub connected_workers: usize,
    pub busy_workers: usize,
    pub accepted_leases: usize,
    pub queued_units: usize,
    pub max_workers: usize,
}

#[derive(Clone, Debug, Serialize)]
struct HealthV1 {
    status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ApiErrorV1 {
    code: &'static str,
    message: String,
}

#[derive(Clone, Copy)]
struct WorkerApiDurations {
    registration: Duration,
    lease: Duration,
    idle: Duration,
    result: Duration,
}

impl Default for WorkerApiDurations {
    fn default() -> Self {
        Self {
            registration: WORKER_REGISTRATION_TIMEOUT,
            lease: WORK_LEASE_TIMEOUT,
            idle: WORKER_IDLE_TIMEOUT,
            result: WORK_RESULT_TIMEOUT,
        }
    }
}

pub struct SupervisorWorkerServerV1 {
    state: Arc<WorkerApiState>,
    address: SocketAddr,
    message_address: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct SupervisorWorkerDispatcherV1 {
    state: Arc<WorkerApiState>,
}

impl SupervisorWorkerServerV1 {
    pub fn start(
        address: SocketAddr,
        identity: EndpointIdentity,
        registry_generation: u64,
        limits: SchemaLimits,
    ) -> Result<Self, WorkerApiErrorV1> {
        if !address.ip().is_loopback() || registry_generation == 0 {
            return Err(WorkerApiErrorV1::InvalidConfiguration);
        }
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let thread = std::thread::Builder::new()
            .name("ocomp-worker-transport".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("ocomp-worker-transport-runtime")
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match tokio::net::TcpListener::bind(address).await {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let bound_address = match listener.local_addr() {
                        Ok(address) => address,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let mut router = RouterSocket::new();
                    let requested_message_address = match derive_message_address(address) {
                        Ok(address) => address,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let bound_message_endpoint = match router
                        .bind(&format!("tcp://{requested_message_address}"))
                        .await
                    {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let message_address = match bound_message_endpoint {
                        Endpoint::Tcp(_, port) => SocketAddr::new(address.ip(), port),
                        _ => {
                            let _ = ready_tx.send(Err("ZeroMQ did not bind a TCP endpoint".into()));
                            return;
                        }
                    };
                    let state_for_server = Arc::new(WorkerApiState::new(
                        identity,
                        registry_generation,
                        limits,
                        WorkerApiDurations::default(),
                        format!("tcp://{message_address}"),
                    ));
                    let mut http_shutdown = shutdown_rx.clone();
                    let http_state = Arc::clone(&state_for_server);
                    let http = tokio::spawn(async move {
                        let _ = axum::serve(listener, worker_router(http_state))
                            .with_graceful_shutdown(async move {
                                while !*http_shutdown.borrow() {
                                    if http_shutdown.changed().await.is_err() {
                                        break;
                                    }
                                }
                            })
                            .await;
                    });
                    if ready_tx
                        .send(Ok((
                            Arc::clone(&state_for_server),
                            bound_address,
                            message_address,
                        )))
                        .is_err()
                    {
                        return;
                    }
                    run_message_router(router, state_for_server, shutdown_rx).await;
                    http.abort();
                    let _ = http.await;
                });
            })
            .map_err(|error| WorkerApiErrorV1::Start(error.to_string()))?;
        let (state, address, message_address) = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| WorkerApiErrorV1::Start(error.to_string()))?
            .map_err(WorkerApiErrorV1::Start)?;
        Ok(Self {
            state,
            address,
            message_address,
            shutdown,
            thread: Some(thread),
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub const fn message_address(&self) -> SocketAddr {
        self.message_address
    }

    pub fn registered_workers(&self) -> Result<usize, WorkerApiErrorV1> {
        Ok(self.state.status()?.connected_workers)
    }

    pub fn dispatch(&self, request: &RunUnitV1) -> Result<UnitFinishedV1, WorkerApiErrorV1> {
        self.state.dispatch(request, None)
    }

    pub fn dispatch_with_cancel(
        &self,
        request: &RunUnitV1,
        cancelled: &AtomicBool,
    ) -> Result<UnitFinishedV1, WorkerApiErrorV1> {
        self.state.dispatch(request, Some(cancelled))
    }

    pub fn dispatcher(&self) -> SupervisorWorkerDispatcherV1 {
        SupervisorWorkerDispatcherV1 {
            state: Arc::clone(&self.state),
        }
    }

    pub fn status(&self) -> Result<WorkerApiStatusV1, WorkerApiErrorV1> {
        self.state.status()
    }
}

impl SupervisorWorkerDispatcherV1 {
    pub fn dispatch(&self, request: &RunUnitV1) -> Result<UnitFinishedV1, WorkerApiErrorV1> {
        self.state.dispatch(request, None)
    }

    pub fn dispatch_with_cancel(
        &self,
        request: &RunUnitV1,
        cancelled: &AtomicBool,
    ) -> Result<UnitFinishedV1, WorkerApiErrorV1> {
        self.state.dispatch(request, Some(cancelled))
    }

    pub fn status(&self) -> Result<WorkerApiStatusV1, WorkerApiErrorV1> {
        self.state.status()
    }
}

impl Drop for SupervisorWorkerServerV1 {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct WorkerApiState {
    identity: EndpointIdentity,
    registry_generation: u64,
    limits: SchemaLimits,
    durations: WorkerApiDurations,
    message_endpoint: String,
    next_id: AtomicU64,
    inner: Mutex<WorkerRegistry>,
    worker_registered: Condvar,
    wake: tokio::sync::Notify,
}

#[derive(Default)]
struct WorkerRegistry {
    workers: BTreeMap<B256, WorkerRecord>,
    pending: VecDeque<QueuedWork>,
    outbound: VecDeque<(B256, SupervisorCommandV1)>,
}

struct WorkerRecord {
    process_nonce: B256,
    last_seen: Instant,
    connected: bool,
    active: Option<ActiveLease>,
    last_completed: Option<CompletedLease>,
}

struct CompletedLease {
    lease_id: B256,
    unit_id: B256,
    body_digest: B256,
}

struct QueuedWork {
    queue_id: u64,
    unit_id: B256,
    body: Vec<u8>,
    delivery_attempt: u32,
    completion: mpsc::SyncSender<UnitFinishedV1>,
}

struct ActiveLease {
    lease_id: B256,
    deadline: Instant,
    accepted: bool,
    work: QueuedWork,
}

impl WorkerApiState {
    fn new(
        identity: EndpointIdentity,
        registry_generation: u64,
        limits: SchemaLimits,
        durations: WorkerApiDurations,
        message_endpoint: String,
    ) -> Self {
        Self {
            identity,
            registry_generation,
            limits,
            durations,
            message_endpoint,
            next_id: AtomicU64::new(1),
            inner: Mutex::new(WorkerRegistry::default()),
            worker_registered: Condvar::new(),
            wake: tokio::sync::Notify::new(),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, WorkerRegistry>, WorkerApiErrorV1> {
        self.inner.lock().map_err(|_| WorkerApiErrorV1::Poisoned)
    }

    fn register(
        &self,
        request: WorkerRegistrationV1,
    ) -> Result<WorkerRegistrationResponseV1, WorkerApiErrorV1> {
        let genesis_hash = parse_b256(&request.genesis_hash)?;
        let process_nonce = parse_b256(&request.process_nonce)?;
        let protocol_bundle_hash = parse_b256(&request.protocol_bundle_hash)?;
        if process_nonce.is_zero()
            || request.chain_id != self.identity.chain_id
            || genesis_hash != self.identity.genesis_hash
            || protocol_bundle_hash != self.identity.protocol_bundle_hash
            || request.max_control_body_bytes != self.limits.max_control_body_bytes
        {
            return Err(WorkerApiErrorV1::IdentityMismatch);
        }
        let now = Instant::now();
        let mut registry = self.lock()?;
        self.cleanup_expired(&mut registry, now);
        if let Some(worker_id) = registry.workers.iter().find_map(|(worker_id, worker)| {
            (worker.process_nonce == process_nonce).then_some(*worker_id)
        }) {
            let requeue = registry
                .workers
                .get_mut(&worker_id)
                .and_then(|worker| {
                    worker.last_seen = now;
                    worker.connected = false;
                    worker.active.take()
                })
                .map(|mut active| {
                    active.work.delivery_attempt = active.work.delivery_attempt.saturating_add(1);
                    active.work
                });
            if let Some(work) = requeue {
                registry.pending.push_back(work);
            }
            self.wake.notify_one();
            return Ok(self.registration_response(worker_id));
        }
        if registry.workers.len() >= MAX_REGISTERED_WORKERS {
            return Err(WorkerApiErrorV1::RegistryFull);
        }
        let worker_id = self.derive_id(b"OCOMP_WORKER_ID_V1", process_nonce.as_slice());
        registry.workers.insert(
            worker_id,
            WorkerRecord {
                process_nonce,
                last_seen: now,
                connected: false,
                active: None,
                last_completed: None,
            },
        );
        Ok(self.registration_response(worker_id))
    }

    fn registration_response(&self, worker_id: B256) -> WorkerRegistrationResponseV1 {
        WorkerRegistrationResponseV1 {
            worker_id: format!("{worker_id:#x}"),
            registry_generation: self.registry_generation,
            lease_timeout_ms: duration_ms(self.durations.lease),
            message_endpoint: self.message_endpoint.clone(),
        }
    }

    fn ready(&self, route: B256, worker_id: &str) -> Result<(), WorkerApiErrorV1> {
        let worker_id = parse_b256(worker_id)?;
        if worker_id != route {
            return Err(WorkerApiErrorV1::IdentityMismatch);
        }
        let mut registry = self.lock()?;
        let worker = registry
            .workers
            .get_mut(&worker_id)
            .ok_or(WorkerApiErrorV1::UnknownWorker)?;
        worker.connected = true;
        worker.last_seen = Instant::now();
        drop(registry);
        self.worker_registered.notify_all();
        self.wake.notify_one();
        Ok(())
    }

    fn handle_event(&self, route: B256, event: WorkerEventV1) -> Result<(), WorkerApiErrorV1> {
        let result = match event {
            WorkerEventV1::Ready {
                worker_id,
                registry_generation,
            } => {
                self.require_generation(registry_generation)?;
                self.ready(route, &worker_id)
            }
            WorkerEventV1::Accepted {
                lease,
                registry_generation,
            } => {
                self.require_generation(registry_generation)?;
                self.require_route(route, &lease.worker_id)?;
                self.accepted(lease)
            }
            WorkerEventV1::Heartbeat {
                lease,
                registry_generation,
            } => {
                self.require_generation(registry_generation)?;
                self.require_route(route, &lease.worker_id)?;
                self.heartbeat(lease)
            }
            WorkerEventV1::Completed {
                completion,
                registry_generation,
            } => {
                self.require_generation(registry_generation)?;
                self.require_route(route, &completion.worker_id)?;
                self.complete(completion)
            }
        };
        self.wake.notify_one();
        result
    }

    fn require_generation(&self, generation: u64) -> Result<(), WorkerApiErrorV1> {
        if generation == self.registry_generation {
            Ok(())
        } else {
            Err(WorkerApiErrorV1::StaleGeneration)
        }
    }

    fn require_route(&self, route: B256, worker_id: &str) -> Result<(), WorkerApiErrorV1> {
        if parse_b256(worker_id)? == route {
            Ok(())
        } else {
            Err(WorkerApiErrorV1::IdentityMismatch)
        }
    }

    fn accepted(&self, request: WorkerLeaseRefV1) -> Result<(), WorkerApiErrorV1> {
        self.touch_lease(request, true)
    }

    fn heartbeat(&self, request: WorkerLeaseRefV1) -> Result<(), WorkerApiErrorV1> {
        self.touch_lease(request, false)
    }

    fn touch_lease(
        &self,
        request: WorkerLeaseRefV1,
        mark_accepted: bool,
    ) -> Result<(), WorkerApiErrorV1> {
        let worker_id = parse_b256(&request.worker_id)?;
        let lease_id = parse_b256(&request.lease_id)?;
        let unit_id = parse_b256(&request.unit_id)?;
        let now = Instant::now();
        let mut registry = self.lock()?;
        self.cleanup_expired(&mut registry, now);
        let worker = registry
            .workers
            .get_mut(&worker_id)
            .ok_or(WorkerApiErrorV1::UnknownWorker)?;
        let active = worker.active.as_mut().ok_or(WorkerApiErrorV1::StaleLease)?;
        if active.lease_id != lease_id || active.work.unit_id != unit_id {
            return Err(WorkerApiErrorV1::StaleLease);
        }
        if !mark_accepted && !active.accepted {
            return Err(WorkerApiErrorV1::LeaseNotAccepted);
        }
        worker.last_seen = now;
        active.deadline = now + self.durations.lease;
        active.accepted |= mark_accepted;
        Ok(())
    }

    fn complete(&self, request: WorkerCompletionV1) -> Result<(), WorkerApiErrorV1> {
        let worker_id = parse_b256(&request.worker_id)?;
        let lease_id = parse_b256(&request.lease_id)?;
        let unit_id = parse_b256(&request.unit_id)?;
        let body = hex::decode(&request.finished_body_hex)
            .map_err(|_| WorkerApiErrorV1::MalformedRequest)?;
        if body.len() > self.limits.max_control_body_bytes {
            return Err(WorkerApiErrorV1::MalformedRequest);
        }
        let finished = UnitFinishedV1::decode_body(&body, &self.limits)
            .map_err(|_| WorkerApiErrorV1::MalformedRequest)?;
        if finished.unit_id != unit_id {
            return Err(WorkerApiErrorV1::StaleLease);
        }
        let body_digest = keccak256(&body);
        let now = Instant::now();
        let mut registry = self.lock()?;
        self.cleanup_expired(&mut registry, now);
        let worker = registry
            .workers
            .get_mut(&worker_id)
            .ok_or(WorkerApiErrorV1::UnknownWorker)?;
        if let Some(completed) = worker.last_completed.as_ref() {
            if completed.lease_id == lease_id && completed.unit_id == unit_id {
                if completed.body_digest != body_digest {
                    return Err(WorkerApiErrorV1::ConflictingCompletion);
                }
                worker.last_seen = now;
                return Ok(());
            }
        }
        let active = worker.active.as_ref().ok_or(WorkerApiErrorV1::StaleLease)?;
        if active.lease_id != lease_id || active.work.unit_id != unit_id || !active.accepted {
            return Err(WorkerApiErrorV1::StaleLease);
        }
        let active = worker.active.take().ok_or(WorkerApiErrorV1::StaleLease)?;
        worker.last_seen = now;
        worker.last_completed = Some(CompletedLease {
            lease_id,
            unit_id,
            body_digest,
        });
        drop(registry);
        active
            .work
            .completion
            .send(finished)
            .map_err(|_| WorkerApiErrorV1::DispatchCancelled)
    }

    fn dispatch(
        &self,
        request: &RunUnitV1,
        cancelled: Option<&AtomicBool>,
    ) -> Result<UnitFinishedV1, WorkerApiErrorV1> {
        if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
            return Err(WorkerApiErrorV1::DispatchCancelled);
        }
        let body = request
            .encode_body(&self.limits)
            .map_err(|error| WorkerApiErrorV1::Protocol(error.to_string()))?;
        let spec = outbe_ocomp_protocol::unit::UnitSpecV1::decode_canonical(
            &request.canonical_unit_spec.0,
            &self.limits,
        )
        .map_err(|error| WorkerApiErrorV1::Protocol(error.to_string()))?;
        let unit_id = spec
            .unit_id(&self.limits)
            .map_err(|error| WorkerApiErrorV1::Protocol(error.to_string()))?;
        let deadline = Instant::now() + self.durations.registration;
        let mut registry = self.lock()?;
        loop {
            if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                return Err(WorkerApiErrorV1::DispatchCancelled);
            }
            self.cleanup_expired(&mut registry, Instant::now());
            if registry.workers.values().any(|worker| worker.connected) {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(WorkerApiErrorV1::NoRegisteredWorkers);
            }
            let timeout = deadline
                .saturating_duration_since(now)
                .min(DISPATCH_CANCEL_POLL);
            let (next, _) = self
                .worker_registered
                .wait_timeout(registry, timeout)
                .map_err(|_| WorkerApiErrorV1::Poisoned)?;
            registry = next;
        }
        let queue_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        registry.pending.push_back(QueuedWork {
            queue_id,
            unit_id,
            body,
            delivery_attempt: 1,
            completion: completion_tx,
        });
        drop(registry);
        self.wake.notify_one();
        let result_deadline = Instant::now() + self.durations.result;
        let waiting_since = Instant::now();
        let mut last_report = Instant::now();
        loop {
            if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                self.cancel(queue_id)?;
                return Err(WorkerApiErrorV1::DispatchCancelled);
            }
            let remaining = result_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cancel(queue_id)?;
                return Err(WorkerApiErrorV1::ResultTimeout);
            }
            match completion_rx.recv_timeout(remaining.min(DISPATCH_CANCEL_POLL)) {
                Ok(finished) => return Ok(finished),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if last_report.elapsed() >= DISPATCH_WAIT_REPORT_INTERVAL {
                        last_report = Instant::now();
                        self.report_dispatch_wait(queue_id, unit_id, waiting_since);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.cancel(queue_id)?;
                    return Err(WorkerApiErrorV1::DispatchCancelled);
                }
            }
        }
    }

    fn report_dispatch_wait(&self, queue_id: u64, unit_id: B256, waiting_since: Instant) {
        let Ok(registry) = self.lock() else {
            return;
        };
        let queued = registry
            .pending
            .iter()
            .any(|work| work.queue_id == queue_id);
        let connected = registry
            .workers
            .values()
            .filter(|worker| worker.connected)
            .count();
        let leased = registry.workers.values().any(|worker| {
            worker
                .active
                .as_ref()
                .is_some_and(|lease| lease.work.queue_id == queue_id)
        });
        drop(registry);
        eprintln!(
            "OCOMP supervisor still waiting for a worker result: unit={unit_id:#x} \
queue_id={queue_id} queued={queued} leased={leased} connected_workers={connected} \
waited_secs={}",
            waiting_since.elapsed().as_secs()
        );
    }

    fn cancel(&self, queue_id: u64) -> Result<(), WorkerApiErrorV1> {
        let mut registry = self.lock()?;
        registry.pending.retain(|work| work.queue_id != queue_id);
        let mut cancellation = None;
        for (worker_id, worker) in &mut registry.workers {
            if worker
                .active
                .as_ref()
                .is_some_and(|lease| lease.work.queue_id == queue_id)
            {
                if let Some(active) = worker.active.take() {
                    worker.connected = false;
                    cancellation = Some((
                        *worker_id,
                        SupervisorCommandV1::Cancel {
                            lease: WorkerLeaseRefV1 {
                                worker_id: format!("{worker_id:#x}"),
                                lease_id: format!("{:#x}", active.lease_id),
                                unit_id: format!("{:#x}", active.work.unit_id),
                            },
                            registry_generation: self.registry_generation,
                        },
                    ));
                }
                break;
            }
        }
        if let Some(cancellation) = cancellation {
            registry.outbound.push_back(cancellation);
        }
        drop(registry);
        self.wake.notify_one();
        Ok(())
    }

    fn drain_commands(&self) -> Result<Vec<(B256, SupervisorCommandV1)>, WorkerApiErrorV1> {
        let now = Instant::now();
        let mut registry = self.lock()?;
        self.cleanup_expired(&mut registry, now);
        let mut commands = registry.outbound.drain(..).collect::<Vec<_>>();
        let available = registry
            .workers
            .iter()
            .filter_map(|(worker_id, worker)| {
                (worker.connected && worker.active.is_none()).then_some(*worker_id)
            })
            .collect::<Vec<_>>();
        for worker_id in available {
            let Some(work) = registry.pending.pop_front() else {
                break;
            };
            let mut lease_material = Vec::with_capacity(72);
            lease_material.extend_from_slice(worker_id.as_slice());
            lease_material.extend_from_slice(work.unit_id.as_slice());
            lease_material.extend_from_slice(&work.queue_id.to_be_bytes());
            let lease_id = self.derive_id(b"OCOMP_WORK_LEASE_V1", &lease_material);
            let active = ActiveLease {
                lease_id,
                deadline: now + self.durations.lease,
                accepted: false,
                work,
            };
            let lease = self.lease_response(worker_id, &active);
            registry
                .workers
                .get_mut(&worker_id)
                .ok_or(WorkerApiErrorV1::UnknownWorker)?
                .active = Some(active);
            commands.push((
                worker_id,
                SupervisorCommandV1::Work {
                    lease,
                    registry_generation: self.registry_generation,
                },
            ));
        }
        Ok(commands)
    }

    fn status(&self) -> Result<WorkerApiStatusV1, WorkerApiErrorV1> {
        let mut registry = self.lock()?;
        self.cleanup_expired(&mut registry, Instant::now());
        Ok(WorkerApiStatusV1 {
            registry_generation: self.registry_generation,
            registered_workers: registry.workers.len(),
            connected_workers: registry
                .workers
                .values()
                .filter(|worker| worker.connected)
                .count(),
            busy_workers: registry
                .workers
                .values()
                .filter(|worker| worker.active.is_some())
                .count(),
            accepted_leases: registry
                .workers
                .values()
                .filter(|worker| worker.active.as_ref().is_some_and(|lease| lease.accepted))
                .count(),
            queued_units: registry.pending.len(),
            max_workers: MAX_REGISTERED_WORKERS,
        })
    }

    fn lease_response(&self, worker_id: B256, active: &ActiveLease) -> WorkLeaseV1 {
        WorkLeaseV1 {
            worker_id: format!("{worker_id:#x}"),
            lease_id: format!("{:#x}", active.lease_id),
            unit_id: format!("{:#x}", active.work.unit_id),
            delivery_attempt: active.work.delivery_attempt,
            lease_timeout_ms: duration_ms(self.durations.lease),
            run_unit_body_hex: hex::encode(&active.work.body),
        }
    }

    fn cleanup_expired(&self, registry: &mut WorkerRegistry, now: Instant) {
        let mut requeue = Vec::new();
        let mut cancellations = Vec::new();
        registry.workers.retain(|worker_id, worker| {
            if worker
                .active
                .as_ref()
                .is_some_and(|active| active.deadline <= now)
            {
                if let Some(mut active) = worker.active.take() {
                    cancellations.push((
                        *worker_id,
                        SupervisorCommandV1::Cancel {
                            lease: WorkerLeaseRefV1 {
                                worker_id: format!("{worker_id:#x}"),
                                lease_id: format!("{:#x}", active.lease_id),
                                unit_id: format!("{:#x}", active.work.unit_id),
                            },
                            registry_generation: self.registry_generation,
                        },
                    ));
                    active.work.delivery_attempt = active.work.delivery_attempt.saturating_add(1);
                    requeue.push(active.work);
                    worker.connected = false;
                }
            }
            worker.active.is_some() || now.duration_since(worker.last_seen) <= self.durations.idle
        });
        registry.pending.extend(requeue);
        registry.outbound.extend(cancellations);
    }

    fn derive_id(&self, domain: &[u8], material: &[u8]) -> B256 {
        let counter = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut bytes = Vec::with_capacity(domain.len() + material.len() + 16);
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.registry_generation.to_be_bytes());
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(material);
        keccak256(bytes)
    }
}

fn worker_router(state: Arc<WorkerApiState>) -> Router {
    let max_body = state
        .limits
        .max_control_body_bytes
        .saturating_mul(2)
        .saturating_add(8_192);
    Router::new()
        .route("/health", get(health))
        .route("/v1/status", get(status_handler))
        .route("/v1/workers/register", post(register))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

async fn health() -> Json<HealthV1> {
    Json(HealthV1 { status: "ok" })
}

async fn status_handler(
    State(state): State<Arc<WorkerApiState>>,
) -> Result<Json<WorkerApiStatusV1>, WorkerApiErrorV1> {
    state.status().map(Json)
}

async fn register(
    State(state): State<Arc<WorkerApiState>>,
    Json(request): Json<WorkerRegistrationV1>,
) -> Result<Json<WorkerRegistrationResponseV1>, WorkerApiErrorV1> {
    state.register(request).map(Json).map_err(|error| {
        eprintln!("OCOMP worker registration rejected: {error}");
        error
    })
}

async fn run_message_router(
    router: RouterSocket,
    state: Arc<WorkerApiState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let (mut sender, mut receiver) = router.split();
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            message = receiver.recv() => {
                match message
                    .map_err(|error| WorkerApiErrorV1::MessageTransport(error.to_string()))
                    .and_then(|message| decode_worker_event(message, state.limits.max_control_body_bytes))
                    .and_then(|(route, event)| state.handle_event(route, event))
                {
                    Ok(()) => {}
                    Err(error) => eprintln!("OCOMP worker message rejected: {error}"),
                }
            }
            _ = state.wake.notified() => {}
            _ = cleanup.tick() => {}
        }
        let commands = match state.drain_commands() {
            Ok(commands) => commands,
            Err(error) => {
                eprintln!("OCOMP worker command drain failed: {error}");
                continue;
            }
        };
        for (route, command) in commands {
            match encode_supervisor_command(route, &command) {
                Ok(message) => {
                    if let Err(error) = sender.send(message).await {
                        eprintln!("OCOMP worker command send failed: {error}");
                    }
                }
                Err(error) => eprintln!("OCOMP worker command encode failed: {error}"),
            }
        }
    }
}

fn decode_worker_event(
    message: ZmqMessage,
    max_body_bytes: usize,
) -> Result<(B256, WorkerEventV1), WorkerApiErrorV1> {
    let frames = message.into_vec();
    if frames.len() != 2 || frames[1].len() > max_body_bytes.saturating_mul(2).saturating_add(8_192)
    {
        return Err(WorkerApiErrorV1::MalformedRequest);
    }
    let route = std::str::from_utf8(&frames[0])
        .map_err(|_| WorkerApiErrorV1::MalformedRequest)
        .and_then(parse_b256)?;
    let event =
        serde_json::from_slice(&frames[1]).map_err(|_| WorkerApiErrorV1::MalformedRequest)?;
    Ok((route, event))
}

fn encode_supervisor_command(
    route: B256,
    command: &SupervisorCommandV1,
) -> Result<ZmqMessage, WorkerApiErrorV1> {
    let body = serde_json::to_vec(command).map_err(|_| WorkerApiErrorV1::MalformedRequest)?;
    ZmqMessage::try_from(vec![Bytes::from(format!("{route:#x}")), Bytes::from(body)])
        .map_err(|_| WorkerApiErrorV1::MalformedRequest)
}

fn derive_message_address(http: SocketAddr) -> Result<SocketAddr, WorkerApiErrorV1> {
    if http.port() != 0 {
        let port = http
            .port()
            .checked_add(1)
            .ok_or(WorkerApiErrorV1::InvalidConfiguration)?;
        return Ok(SocketAddr::new(http.ip(), port));
    }
    Ok(SocketAddr::new(http.ip(), 0))
}

impl IntoResponse for WorkerApiErrorV1 {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let (response_status, code) = match self {
            WorkerApiErrorV1::MalformedRequest | WorkerApiErrorV1::Protocol(_) => {
                (StatusCode::BAD_REQUEST, "malformed_request")
            }
            WorkerApiErrorV1::IdentityMismatch => (StatusCode::FORBIDDEN, "identity_mismatch"),
            WorkerApiErrorV1::UnknownWorker => (StatusCode::NOT_FOUND, "unknown_worker"),
            WorkerApiErrorV1::RegistryFull => (StatusCode::SERVICE_UNAVAILABLE, "registry_full"),
            WorkerApiErrorV1::StaleLease => (StatusCode::CONFLICT, "stale_lease"),
            WorkerApiErrorV1::LeaseNotAccepted => (StatusCode::CONFLICT, "lease_not_accepted"),
            WorkerApiErrorV1::ConflictingCompletion => {
                (StatusCode::CONFLICT, "conflicting_completion")
            }
            WorkerApiErrorV1::StaleGeneration => (StatusCode::CONFLICT, "stale_generation"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (response_status, Json(ApiErrorV1 { code, message })).into_response()
    }
}

fn parse_b256(value: &str) -> Result<B256, WorkerApiErrorV1> {
    B256::from_str(value).map_err(|_| WorkerApiErrorV1::MalformedRequest)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug, Error)]
pub enum WorkerApiErrorV1 {
    #[error("invalid Supervisor worker transport configuration")]
    InvalidConfiguration,
    #[error("failed to start Supervisor worker transport: {0}")]
    Start(String),
    #[error("worker registration or message is malformed")]
    MalformedRequest,
    #[error("worker identity does not match the Supervisor domain")]
    IdentityMismatch,
    #[error("Supervisor worker registry is full")]
    RegistryFull,
    #[error("worker is not registered")]
    UnknownWorker,
    #[error("worker lease is stale or belongs to another unit")]
    StaleLease,
    #[error("worker lease must be accepted before heartbeat")]
    LeaseNotAccepted,
    #[error("completion retry does not match the already accepted result")]
    ConflictingCompletion,
    #[error("no OCOMP worker registered before the deadline")]
    NoRegisteredWorkers,
    #[error("worker result did not arrive before the bounded deadline")]
    ResultTimeout,
    #[error("worker dispatch was cancelled")]
    DispatchCancelled,
    #[error("worker registry generation is stale")]
    StaleGeneration,
    #[error("worker TCP ZeroMQ transport failed: {0}")]
    MessageTransport(String),
    #[error("worker registry lock is poisoned")]
    Poisoned,
    #[error("worker protocol body is invalid: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use outbe_ocomp_protocol::common::BoundedBytes;
    use outbe_ocomp_protocol::unit::{EntityIdHalfOpenRange, UnitInterval, UnitPhase, UnitSpecV1};
    use zeromq::util::PeerIdentity;

    fn identity() -> EndpointIdentity {
        EndpointIdentity {
            chain_id: 41,
            genesis_hash: B256::repeat_byte(0x41),
            boot_nonce: B256::repeat_byte(0x42),
            protocol_bundle_hash: B256::repeat_byte(0x43),
        }
    }

    fn request(marker: u8) -> RunUnitV1 {
        let limits = crate::control::poc_schema_limits();
        let spec = UnitSpecV1 {
            protocol_bundle_hash: identity().protocol_bundle_hash,
            job_id: B256::repeat_byte(marker),
            attempt: 0,
            phase: UnitPhase::Enumerate,
            interval: UnitInterval::EntityIdRange(EntityIdHalfOpenRange {
                start: B256::from([marker; 32]),
                end: None,
            }),
            canonical_ordered_inputs: Vec::new(),
            lysis_program_semantics_hash: B256::repeat_byte(0x44),
            planner_spec_version: 1,
            reducer_spec_version: 1,
        };
        RunUnitV1 {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            plan_hash: B256::repeat_byte(marker.wrapping_add(1)),
            unit_index: 0,
            canonical_unit_spec: BoundedBytes(spec.encode_canonical(&limits).unwrap()),
            unit_membership_siblings: Vec::new(),
            plan_ref: outbe_ocomp_protocol::CasObjectRefV1 {
                transport_digest: B256::repeat_byte(marker.wrapping_add(2)),
                encoded_bytes: 1,
                expected_ocb1_kind: None,
            },
            input_manifest_ref: outbe_ocomp_protocol::CasObjectRefV1 {
                transport_digest: B256::repeat_byte(marker.wrapping_add(3)),
                encoded_bytes: 1,
                expected_ocb1_kind: None,
            },
            ordered_input_refs: Vec::new(),
        }
    }

    fn dealer_command(message: ZmqMessage) -> SupervisorCommandV1 {
        let frames = message.into_vec();
        assert_eq!(frames.len(), 1);
        serde_json::from_slice(&frames[0]).expect("decode Supervisor command")
    }

    async fn dealer_event(sender: &mut zeromq::DealerSendHalf, event: &WorkerEventV1) {
        sender
            .send(serde_json::to_vec(event).unwrap().into())
            .await
            .expect("send Worker event");
    }

    #[test]
    fn registry_accepts_four_workers_and_rejects_fifth() {
        let limits = crate::control::poc_schema_limits();
        let state = WorkerApiState::new(
            identity(),
            7,
            limits,
            WorkerApiDurations::default(),
            "tcp://127.0.0.1:9766".into(),
        );
        for ordinal in 0_u8..4 {
            let mut worker = identity();
            worker.boot_nonce = B256::repeat_byte(0x50 + ordinal);
            state
                .register(WorkerRegistrationV1::from_identity(worker, limits))
                .expect("register worker");
        }
        let mut fifth = identity();
        fifth.boot_nonce = B256::repeat_byte(0x60);
        assert!(matches!(
            state.register(WorkerRegistrationV1::from_identity(fifth, limits)),
            Err(WorkerApiErrorV1::RegistryFull)
        ));
        assert_eq!(state.status().unwrap().registered_workers, 4);
    }

    #[test]
    fn cancelled_dispatch_does_not_wait_for_registration_timeout() {
        let limits = crate::control::poc_schema_limits();
        let state = WorkerApiState::new(
            identity(),
            7,
            limits,
            WorkerApiDurations::default(),
            "tcp://127.0.0.1:9766".into(),
        );
        let cancelled = AtomicBool::new(true);
        let request = RunUnitV1 {
            protocol_bundle_hash: identity().protocol_bundle_hash,
            job_id: B256::repeat_byte(0x71),
            attempt: 0,
            plan_hash: B256::repeat_byte(0x72),
            unit_index: 0,
            canonical_unit_spec: outbe_ocomp_protocol::common::BoundedBytes(Vec::new()),
            unit_membership_siblings: Vec::new(),
            plan_ref: outbe_ocomp_protocol::CasObjectRefV1 {
                transport_digest: B256::repeat_byte(0x73),
                encoded_bytes: 1,
                expected_ocb1_kind: None,
            },
            input_manifest_ref: outbe_ocomp_protocol::CasObjectRefV1 {
                transport_digest: B256::repeat_byte(0x74),
                encoded_bytes: 1,
                expected_ocb1_kind: None,
            },
            ordered_input_refs: Vec::new(),
        };
        assert!(matches!(
            state.dispatch(&request, Some(&cancelled)),
            Err(WorkerApiErrorV1::DispatchCancelled)
        ));
    }

    #[test]
    fn router_cancel_delivery_returns_worker_to_ready_for_the_next_unit() {
        let limits = crate::control::poc_schema_limits();
        let server =
            SupervisorWorkerServerV1::start("127.0.0.1:0".parse().unwrap(), identity(), 7, limits)
                .expect("start Axum and ZeroMQ worker server");
        let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
        let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(1);
        let http_address = server.address();
        let worker = std::thread::spawn(move || {
            let mut worker_identity = identity();
            worker_identity.boot_nonce = B256::repeat_byte(0x55);
            let registration: WorkerRegistrationResponseV1 = reqwest::blocking::Client::new()
                .post(format!("http://{http_address}/v1/workers/register"))
                .json(&WorkerRegistrationV1::from_identity(
                    worker_identity,
                    limits,
                ))
                .send()
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let peer: PeerIdentity = registration.worker_id.parse().unwrap();
                    let mut options = zeromq::SocketOptions::default();
                    options.peer_identity(peer);
                    let mut socket = zeromq::DealerSocket::with_options(options);
                    socket
                        .connect(&registration.message_endpoint)
                        .await
                        .unwrap();
                    let (mut sender, mut receiver) = socket.split();
                    dealer_event(
                        &mut sender,
                        &WorkerEventV1::Ready {
                            worker_id: registration.worker_id.clone(),
                            registry_generation: registration.registry_generation,
                        },
                    )
                    .await;

                    let first = match dealer_command(receiver.recv().await.unwrap()) {
                        SupervisorCommandV1::Work {
                            lease,
                            registry_generation,
                        } => {
                            assert_eq!(registry_generation, registration.registry_generation);
                            lease
                        }
                        SupervisorCommandV1::Cancel { .. } => panic!("expected first Work"),
                    };
                    dealer_event(
                        &mut sender,
                        &WorkerEventV1::Accepted {
                            lease: WorkerLeaseRefV1 {
                                worker_id: first.worker_id.clone(),
                                lease_id: first.lease_id.clone(),
                                unit_id: first.unit_id.clone(),
                            },
                            registry_generation: registration.registry_generation,
                        },
                    )
                    .await;
                    accepted_tx.send(()).unwrap();

                    match dealer_command(receiver.recv().await.unwrap()) {
                        SupervisorCommandV1::Cancel {
                            lease,
                            registry_generation,
                        } => {
                            assert_eq!(registry_generation, registration.registry_generation);
                            assert_eq!(lease.lease_id, first.lease_id);
                            assert_eq!(lease.unit_id, first.unit_id);
                        }
                        SupervisorCommandV1::Work { .. } => panic!("expected Cancel"),
                    }
                    dealer_event(
                        &mut sender,
                        &WorkerEventV1::Ready {
                            worker_id: registration.worker_id.clone(),
                            registry_generation: registration.registry_generation,
                        },
                    )
                    .await;
                    cancelled_tx.send(()).unwrap();

                    let second = match dealer_command(receiver.recv().await.unwrap()) {
                        SupervisorCommandV1::Work { lease, .. } => lease,
                        SupervisorCommandV1::Cancel { .. } => panic!("expected replacement Work"),
                    };
                    let reference = WorkerLeaseRefV1 {
                        worker_id: second.worker_id.clone(),
                        lease_id: second.lease_id.clone(),
                        unit_id: second.unit_id.clone(),
                    };
                    dealer_event(
                        &mut sender,
                        &WorkerEventV1::Accepted {
                            lease: reference,
                            registry_generation: registration.registry_generation,
                        },
                    )
                    .await;
                    let unit_id = second.unit_id.parse().unwrap();
                    dealer_event(
                        &mut sender,
                        &WorkerEventV1::Completed {
                            completion: WorkerCompletionV1 {
                                worker_id: second.worker_id,
                                lease_id: second.lease_id,
                                unit_id: second.unit_id,
                                finished_body_hex: hex::encode(
                                    UnitFinishedV1 {
                                        unit_id,
                                        status: outbe_ocomp_protocol::UnitFinishedStatus::Failed,
                                        exact_staged_bytes: 0,
                                        transport_digest: B256::ZERO,
                                    }
                                    .encode_body(&limits)
                                    .unwrap(),
                                ),
                            },
                            registry_generation: registration.registry_generation,
                        },
                    )
                    .await;
                });
        });

        let cancelled = Arc::new(AtomicBool::new(false));
        let dispatch_cancelled = Arc::clone(&cancelled);
        let dispatcher = server.dispatcher();
        let first_request = request(0x70);
        let first_dispatch = std::thread::spawn(move || {
            dispatcher.dispatch_with_cancel(&first_request, &dispatch_cancelled)
        });
        accepted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            first_dispatch.join().unwrap(),
            Err(WorkerApiErrorV1::DispatchCancelled)
        ));
        cancelled_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let replacement = server.dispatch(&request(0x80)).unwrap();
        assert_eq!(
            replacement.status,
            outbe_ocomp_protocol::UnitFinishedStatus::Failed
        );
        worker.join().unwrap();
    }

    #[test]
    fn expired_lease_is_requeued_and_stale_completion_conflicts() {
        let limits = crate::control::poc_schema_limits();
        let durations = WorkerApiDurations {
            registration: Duration::from_millis(50),
            lease: Duration::from_millis(20),
            idle: Duration::from_secs(1),
            result: Duration::from_secs(1),
        };
        let state = WorkerApiState::new(
            identity(),
            7,
            limits,
            durations,
            "tcp://127.0.0.1:9766".into(),
        );
        let mut first_identity = identity();
        first_identity.boot_nonce = B256::repeat_byte(0x51);
        let first = state
            .register(WorkerRegistrationV1::from_identity(first_identity, limits))
            .unwrap();
        let mut second_identity = identity();
        second_identity.boot_nonce = B256::repeat_byte(0x52);
        let second = state
            .register(WorkerRegistrationV1::from_identity(second_identity, limits))
            .unwrap();
        let first_id = parse_b256(&first.worker_id).unwrap();
        state.ready(first_id, &first.worker_id).unwrap();

        let (tx, _rx) = mpsc::sync_channel(1);
        state.lock().unwrap().pending.push_back(QueuedWork {
            queue_id: 1,
            unit_id: B256::repeat_byte(0x91),
            body: vec![1, 2, 3],
            delivery_attempt: 1,
            completion: tx,
        });
        let first_lease = match state.drain_commands().unwrap().pop().unwrap().1 {
            SupervisorCommandV1::Work { lease, .. } => lease,
            SupervisorCommandV1::Cancel { .. } => panic!("expected work command"),
        };
        assert!(matches!(
            state.heartbeat(WorkerLeaseRefV1 {
                worker_id: first_lease.worker_id.clone(),
                lease_id: first_lease.lease_id.clone(),
                unit_id: first_lease.unit_id.clone(),
            }),
            Err(WorkerApiErrorV1::LeaseNotAccepted)
        ));
        state
            .accepted(WorkerLeaseRefV1 {
                worker_id: first_lease.worker_id.clone(),
                lease_id: first_lease.lease_id.clone(),
                unit_id: first_lease.unit_id.clone(),
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        state
            .lock()
            .unwrap()
            .workers
            .get_mut(&first_id)
            .unwrap()
            .connected = false;
        let second_id = parse_b256(&second.worker_id).unwrap();
        state.ready(second_id, &second.worker_id).unwrap();
        let second_lease = match state.drain_commands().unwrap().pop().unwrap().1 {
            SupervisorCommandV1::Work { lease, .. } => lease,
            SupervisorCommandV1::Cancel { .. } => panic!("expected work command"),
        };
        assert_eq!(second_lease.delivery_attempt, 2);
        assert_ne!(first_lease.lease_id, second_lease.lease_id);
        assert!(matches!(
            state.complete(WorkerCompletionV1 {
                worker_id: first_lease.worker_id,
                lease_id: first_lease.lease_id,
                unit_id: first_lease.unit_id,
                finished_body_hex: hex::encode(
                    UnitFinishedV1 {
                        unit_id: B256::repeat_byte(0x91),
                        status: outbe_ocomp_protocol::UnitFinishedStatus::Failed,
                        exact_staged_bytes: 0,
                        transport_digest: B256::ZERO,
                    }
                    .encode_body(&limits)
                    .unwrap(),
                ),
            }),
            Err(WorkerApiErrorV1::StaleLease)
        ));
        state
            .accepted(WorkerLeaseRefV1 {
                worker_id: second_lease.worker_id.clone(),
                lease_id: second_lease.lease_id.clone(),
                unit_id: second_lease.unit_id.clone(),
            })
            .unwrap();
        let completion = WorkerCompletionV1 {
            worker_id: second_lease.worker_id,
            lease_id: second_lease.lease_id,
            unit_id: second_lease.unit_id,
            finished_body_hex: hex::encode(
                UnitFinishedV1 {
                    unit_id: B256::repeat_byte(0x91),
                    status: outbe_ocomp_protocol::UnitFinishedStatus::Failed,
                    exact_staged_bytes: 0,
                    transport_digest: B256::ZERO,
                }
                .encode_body(&limits)
                .unwrap(),
            ),
        };
        state.complete(completion.clone()).unwrap();
        state.complete(completion.clone()).unwrap();
        let mut conflicting = completion;
        conflicting.finished_body_hex = hex::encode(
            UnitFinishedV1 {
                unit_id: B256::repeat_byte(0x91),
                status: outbe_ocomp_protocol::UnitFinishedStatus::Success,
                exact_staged_bytes: 1,
                transport_digest: B256::repeat_byte(0x92),
            }
            .encode_body(&limits)
            .unwrap(),
        );
        assert!(matches!(
            state.complete(conflicting),
            Err(WorkerApiErrorV1::ConflictingCompletion)
        ));
    }

    #[test]
    fn stalled_http_connection_does_not_block_health_or_status() {
        let limits = crate::control::poc_schema_limits();
        let server =
            SupervisorWorkerServerV1::start("127.0.0.1:0".parse().unwrap(), identity(), 7, limits)
                .expect("start Axum and ZeroMQ worker server");
        let mut stalled = std::net::TcpStream::connect(server.address())
            .expect("open deliberately incomplete HTTP connection");
        stalled
            .write_all(b"POST /v1/workers/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n")
            .expect("write incomplete HTTP headers");

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let health_response = client
            .get(format!("http://{}/health", server.address()))
            .send()
            .expect("health remains independently serviceable");
        assert_eq!(health_response.status(), reqwest::StatusCode::OK);
        let status: WorkerApiStatusV1 = client
            .get(format!("http://{}/v1/status", server.address()))
            .send()
            .expect("status remains independently serviceable")
            .json()
            .expect("decode status");
        assert_eq!(status.registered_workers, 0);
        assert_eq!(status.connected_workers, 0);
        assert_eq!(status.max_workers, 4);
    }
}
