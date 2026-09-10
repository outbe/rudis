use super::{
    fsm::{evaluate_phase, PhaseInput, PhaseMode},
    types::{
        DisconnectDisposition, FinalizedBlock, FinalizedSnapshot, ManagerConfig,
        ManagerDependencies, ManagerError, ManagerPhase, ManagerStatus, PhaseError,
        SessionDirection,
    },
};
use crate::endpoint::{EndpointAddress, VerifiedEndpoint};
use alloy_primitives::Address;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    time::Instant,
};

pub struct RadicleManager;

pub struct RadicleManagerHandle {
    status: watch::Receiver<ManagerStatus>,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

struct Runtime {
    config: ManagerConfig,
    dependencies: ManagerDependencies,
    status: ManagerStatus,
    status_tx: watch::Sender<ManagerStatus>,
    current: Option<FinalizedSnapshot>,
    pending: Option<FinalizedBlock>,
    endpoint_cache: BTreeMap<Address, VerifiedEndpoint>,
    managed: BTreeMap<[u8; 32], EndpointAddress>,
    was_ready: bool,
    retry_attempt: u32,
    next_retry: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlReconciliation {
    sidecar_available: bool,
    converged: bool,
}

impl RadicleManager {
    #[must_use]
    pub fn start(config: ManagerConfig, dependencies: ManagerDependencies) -> RadicleManagerHandle {
        // Subscription must exist before the sample so finality cannot advance
        // in the gap between those operations.
        let finalized = dependencies.finality.subscribe();
        let mut initial_status = ManagerStatus {
            phase: ManagerPhase::JoiningUnbound,
            ..ManagerStatus::default()
        };
        if finalized.is_err() {
            initial_status.provider_failures = 1;
            initial_status.phase = ManagerPhase::RuntimeDegraded;
        }
        let (status_tx, status) = watch::channel(initial_status.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut runtime = Runtime {
            config,
            dependencies,
            status: initial_status,
            status_tx,
            current: None,
            pending: None,
            endpoint_cache: BTreeMap::new(),
            managed: BTreeMap::new(),
            was_ready: false,
            retry_attempt: 0,
            next_retry: None,
        };
        let join = tokio::spawn(async move {
            if let Ok(finalized) = finalized {
                runtime.run(finalized, shutdown_rx).await;
            }
        });
        RadicleManagerHandle {
            status,
            shutdown: Some(shutdown_tx),
            join,
        }
    }
}

impl RadicleManagerHandle {
    #[must_use]
    pub fn status(&self) -> ManagerStatus {
        self.status.borrow().clone()
    }

    #[must_use]
    pub fn signed_peers(&self) -> Vec<VerifiedEndpoint> {
        self.status.borrow().signed_peers.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), ManagerError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        (&mut self.join)
            .await
            .map_err(|error| ManagerError::Task(format!("manager: {error}")))
    }

    /// Own the task through graceful shutdown and bounded cancellation. Reserve
    /// up to one second of `deadline` for joining after aborting a stalled task.
    pub(crate) async fn shutdown_bounded(mut self, deadline: Duration) -> Result<(), ManagerError> {
        let end = Instant::now() + deadline;
        let drain_end = end - (deadline / 2).min(Duration::from_secs(1));
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        match tokio::time::timeout_at(drain_end, &mut self.join).await {
            Ok(result) => result.map_err(|error| ManagerError::Task(format!("manager: {error}"))),
            Err(_) => {
                self.join.abort();
                match tokio::time::timeout_at(end, &mut self.join).await {
                    Ok(Err(error)) if !error.is_cancelled() => {
                        Err(ManagerError::Task(format!("manager: {error}")))
                    }
                    Ok(_) => Err(ManagerError::ShutdownDeadline("manager")),
                    Err(_) => Err(ManagerError::ShutdownDeadline("manager cancellation")),
                }
            }
        }
    }
}

impl Drop for RadicleManagerHandle {
    fn drop(&mut self) {
        // An outer cancellation can only request abort here. The bounded shutdown
        // path retains this handle and awaits completion before returning.
        self.join.abort();
    }
}

impl Runtime {
    async fn run(
        &mut self,
        mut finalized: tokio::sync::mpsc::UnboundedReceiver<FinalizedBlock>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        match self.dependencies.finality.sample().await {
            Ok(Some(block)) => {
                if let Some(retry) = self.accept_target(block).await {
                    self.update_retry(retry);
                }
            }
            Ok(None) => {}
            Err(_) => {
                self.status.provider_failures += 1;
                self.publish();
                self.update_retry(true);
            }
        }

        let mut repair = tokio::time::interval(self.config.repair_interval);
        repair.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        repair.tick().await;
        loop {
            let retry_deadline = self
                .next_retry
                .unwrap_or_else(|| Instant::now() + std::time::Duration::from_secs(86_400));
            tokio::select! {
                _ = &mut shutdown => break,
                Some(block) = finalized.recv() => {
                    if let Some(retry) = self.accept_target(block).await {
                        self.update_retry(retry);
                    }
                },
                _ = tokio::time::sleep_until(retry_deadline), if self.next_retry.is_some() => {
                    self.next_retry = None;
                    let retry = self.repair().await;
                    self.update_retry(retry);
                },
                _ = repair.tick(), if self.next_retry.is_none() => {
                    let retry = self.repair().await;
                    self.update_retry(retry);
                },
                else => break,
            }
        }
    }

    async fn accept_target(&mut self, target: FinalizedBlock) -> Option<bool> {
        if let Some(pending) = self.pending {
            if target.number < pending.number {
                self.status.finality_regressions += 1;
                self.publish();
                return None;
            }
            if target.number == pending.number {
                if target.hash != pending.hash {
                    self.status.finality_conflicts += 1;
                    self.publish();
                }
                return None;
            }
        }
        if let Some(seen) = self.status.last_seen_finalized {
            if target.number < seen.number {
                self.status.finality_regressions += 1;
                self.publish();
                return None;
            }
            if target.number == seen.number {
                if target.hash != seen.hash {
                    self.status.finality_conflicts += 1;
                    self.publish();
                }
                return None;
            }
        }
        self.retry_attempt = 0;
        self.next_retry = None;
        self.pending = Some(target);
        Some(self.load_pending().await)
    }

    async fn load_pending(&mut self) -> bool {
        let Some(target) = self.pending else {
            return false;
        };
        match self.dependencies.snapshots.read_exact(target) {
            Ok(snapshot) if snapshot.block == target => {
                self.pending = None;
                self.status.last_seen_finalized = Some(target);
                self.current = Some(snapshot);
                self.reconcile().await
            }
            Ok(_) | Err(_) => {
                self.status.provider_failures += 1;
                self.publish();
                true
            }
        }
    }

    async fn repair(&mut self) -> bool {
        if self.pending.is_some() {
            self.load_pending().await
        } else if self.current.is_some() {
            self.reconcile().await
        } else {
            false
        }
    }

    fn update_retry(&mut self, retry: bool) {
        if !retry {
            self.retry_attempt = 0;
            self.next_retry = None;
            return;
        }
        if self.next_retry.is_some() {
            return;
        }
        let target = self.pending.or(self.status.last_seen_finalized);
        let delay = self
            .config
            .retry
            .delay(self.retry_attempt, self.config.self_validator, target);
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        self.next_retry = Some(Instant::now() + delay);
    }

    async fn reconcile(&mut self) -> bool {
        let Some(snapshot) = self.current.clone() else {
            return false;
        };
        let mut retry = false;
        if let Ok(refreshed) = self.dependencies.endpoints.refresh(&snapshot).await {
            for endpoint in refreshed {
                self.endpoint_cache.insert(endpoint.validator, endpoint);
            }
        } else {
            self.status.endpoint_failures += 1;
            retry = true;
        }
        self.retain_current_endpoints(&snapshot);

        let self_binding = snapshot
            .validators
            .iter()
            .find(|validator| validator.address == self.config.self_validator)
            .and_then(|validator| validator.node_id);
        let desired = self.desired(&snapshot);
        self.status.resolved_peer_count = desired.len();
        self.status.unresolved_peer_count = snapshot
            .validators
            .iter()
            .filter(|validator| validator.address != self.config.self_validator)
            .count()
            .saturating_sub(desired.len());
        self.status.signed_peers = desired.values().cloned().collect();

        let local_node_id = match self.dependencies.control.node_id().await {
            Ok(node_id) if node_id == self.config.local_node_id => Some(node_id),
            Ok(_) => {
                self.status.uds_failures += 1;
                self.set_phase_error(PhaseError::BindingMismatch);
                self.observe_repositories(&snapshot).await;
                self.publish();
                return true;
            }
            Err(_) => None,
        };
        let phase = evaluate_phase(PhaseInput {
            mode: PhaseMode::Validator,
            sidecar_available: local_node_id.is_some(),
            local_node_id,
            finalized_binding: self_binding,
            was_ready: self.was_ready,
        });
        let phase = match phase {
            Ok(phase) => {
                self.status.phase_error = None;
                phase
            }
            Err(error) => {
                self.status.uds_failures += u64::from(local_node_id.is_none());
                self.set_phase_error(error);
                self.observe_repositories(&snapshot).await;
                self.publish();
                return true;
            }
        };
        self.status.phase = phase;

        let control = self.reconcile_control(&snapshot, &desired).await;
        retry |= self.observe_repositories(&snapshot).await;
        if control.converged {
            self.status.last_converged_finalized = Some(snapshot.block);
            self.status.phase = phase;
            self.status.phase_error = None;
            self.was_ready |= self.status.phase == ManagerPhase::Ready;
        } else if control.sidecar_available {
            // A live local Heartwood runtime can be temporarily unable to dial
            // or seed a remote target. Keep the binding-derived phase and retry
            // the incomplete desired state without misclassifying the sidecar
            // itself as unavailable.
            self.status.phase = phase;
            self.status.phase_error = None;
            self.was_ready |= self.status.phase == ManagerPhase::Ready;
            retry = true;
        } else {
            if self.was_ready {
                self.status.phase = ManagerPhase::RuntimeDegraded;
                self.status.phase_error = None;
            } else {
                self.set_phase_error(PhaseError::SidecarUnavailable);
            }
            retry = true;
        }
        self.publish();
        retry
    }

    fn set_phase_error(&mut self, error: PhaseError) {
        self.status.phase_error = Some(error);
        self.status.phase = if self.was_ready {
            ManagerPhase::RuntimeDegraded
        } else {
            ManagerPhase::JoiningUnbound
        };
    }

    fn retain_current_endpoints(&mut self, snapshot: &FinalizedSnapshot) {
        let bindings = snapshot
            .validators
            .iter()
            .filter_map(|validator| {
                validator
                    .node_id
                    .map(|node_id| (validator.address, (validator.peer, node_id)))
            })
            .collect::<BTreeMap<_, _>>();
        self.endpoint_cache.retain(|validator, endpoint| {
            bindings.get(validator).is_some_and(|(peer, node_id)| {
                endpoint.peer == *peer
                    && endpoint.node_id == *node_id
                    && endpoint.valid_until > snapshot.block.number
                    && endpoint.anchor_number <= snapshot.block.number
            })
        });
    }

    fn desired(&self, snapshot: &FinalizedSnapshot) -> BTreeMap<[u8; 32], VerifiedEndpoint> {
        snapshot
            .validators
            .iter()
            .filter(|validator| validator.address != self.config.self_validator)
            .filter_map(|validator| {
                let node_id = validator.node_id?;
                let endpoint = self.endpoint_cache.get(&validator.address)?;
                Some((node_id, endpoint.clone()))
            })
            .collect()
    }

    async fn reconcile_control(
        &mut self,
        snapshot: &FinalizedSnapshot,
        desired: &BTreeMap<[u8; 32], VerifiedEndpoint>,
    ) -> ControlReconciliation {
        let Ok(mut sessions) = self.dependencies.control.sessions().await else {
            self.status.uds_failures += 1;
            return ControlReconciliation {
                sidecar_available: false,
                converged: false,
            };
        };
        let mut converged = true;

        for session in sessions
            .iter()
            .filter(|session| session.direction == SessionDirection::Outbound)
        {
            self.managed
                .insert(session.node_id, session.address.clone());
        }

        let mut blocked = BTreeSet::new();
        let stale = self
            .managed
            .iter()
            .filter_map(|(node_id, address)| {
                let keep = desired
                    .get(node_id)
                    .is_some_and(|peer| peer.addresses.contains(address));
                (!keep).then_some((*node_id, address.clone()))
            })
            .collect::<Vec<_>>();
        for (node_id, address) in stale {
            match self
                .dependencies
                .control
                .disconnect(node_id, &address)
                .await
            {
                Ok(DisconnectDisposition::Disconnected | DisconnectDisposition::AlreadyAbsent) => {
                    self.managed.remove(&node_id);
                    sessions.retain(|session| {
                        session.node_id != node_id
                            || session.direction != SessionDirection::Outbound
                            || session.address != address
                    });
                }
                Ok(DisconnectDisposition::Inbound) => {
                    self.managed.remove(&node_id);
                }
                Ok(DisconnectDisposition::NotConnected | DisconnectDisposition::AddressChanged)
                | Err(_) => {
                    blocked.insert(node_id);
                    converged = false;
                }
            }
        }

        for (node_id, endpoint) in desired {
            if blocked.contains(node_id) {
                continue;
            }
            let connected = sessions.iter().any(|session| {
                session.node_id == *node_id
                    && session.connected
                    && (session.direction == SessionDirection::Inbound
                        || endpoint.addresses.contains(&session.address))
            });
            if connected {
                if let Some(session) = sessions.iter().find(|session| {
                    session.node_id == *node_id
                        && session.connected
                        && session.direction == SessionDirection::Outbound
                        && endpoint.addresses.contains(&session.address)
                }) {
                    self.managed.insert(*node_id, session.address.clone());
                }
                continue;
            }
            match self
                .dependencies
                .control
                .connect(*node_id, &endpoint.addresses)
                .await
            {
                Ok(address) => {
                    self.managed.insert(*node_id, address);
                }
                Err(_) => {
                    converged = false;
                }
            }
        }

        for repo in &snapshot.repositories {
            if self.dependencies.control.seed(*repo).await.is_err() {
                converged = false;
            }
        }
        match self.dependencies.control.sessions().await {
            Ok(sessions) => {
                self.status.connected_peer_count = sessions
                    .into_iter()
                    .filter(|session| session.connected && desired.contains_key(&session.node_id))
                    .map(|session| session.node_id)
                    .collect::<BTreeSet<_>>()
                    .len();
                ControlReconciliation {
                    sidecar_available: true,
                    converged,
                }
            }
            Err(_) => {
                self.status.uds_failures += 1;
                self.status.connected_peer_count = 0;
                ControlReconciliation {
                    sidecar_available: false,
                    converged: false,
                }
            }
        }
    }

    async fn observe_repositories(&mut self, snapshot: &FinalizedSnapshot) -> bool {
        let mut available = 0;
        let mut retry = false;
        for repo in &snapshot.repositories {
            match self.dependencies.repository_status.available(*repo).await {
                Ok(true) => available += 1,
                Ok(false) => {}
                Err(_) => {
                    self.status.tcp_status_failures += 1;
                    retry = true;
                }
            }
        }
        self.status.desired_repository_count = snapshot.repositories.len();
        self.status.available_repository_count = available;
        self.status.pending_repository_count = snapshot.repositories.len() - available;
        retry
    }

    fn publish(&self) {
        self.status_tx.send_replace(self.status.clone());
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use crate::integration::shutdown_bounded;

    fn handle(join: tokio::task::JoinHandle<()>) -> RadicleManagerHandle {
        let (_, status) = watch::channel(ManagerStatus::default());
        RadicleManagerHandle {
            status,
            shutdown: None,
            join,
        }
    }

    #[tokio::test]
    async fn shutdown_preserves_manager_panic() {
        let manager = handle(tokio::spawn(async { panic!("manager panic witness") }));
        let error = manager.shutdown().await.unwrap_err();
        assert!(
            matches!(error, ManagerError::Task(ref message) if message.contains("manager panic witness"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_timeout_reaps_owned_manager_before_endpoint_cleanup() {
        let (alive, mut dropped) = oneshot::channel::<()>();
        let (started, ready) = oneshot::channel();
        let manager = handle(tokio::spawn(async move {
            let _alive = alive;
            let _ = started.send(());
            std::future::pending::<()>().await;
        }));
        let task = manager.join.abort_handle();
        ready.await.unwrap();
        let error = shutdown_bounded(Duration::from_secs(2), manager, async {
            assert!(
                task.is_finished(),
                "manager must finish before endpoint cleanup"
            );
            assert_eq!(
                dropped.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            );
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(error, ManagerError::ShutdownDeadline("manager"));
        assert!(task.is_finished());
    }

    #[tokio::test]
    async fn shutdown_drains_owned_manager_before_endpoint() {
        let (shutdown, requested) = oneshot::channel();
        let (request, mut requests) = tokio::sync::mpsc::unbounded_channel::<oneshot::Sender<()>>();
        let endpoint = tokio::spawn(async move {
            // The draining manager still needs a live endpoint to finish its task.
            requests.recv().await.unwrap().send(()).unwrap();
            assert!(requests.recv().await.is_none());
        });
        let mut manager = handle(tokio::spawn(async move {
            requested.await.unwrap();
            let (response, received) = oneshot::channel();
            request.send(response).unwrap();
            received.await.unwrap();
        }));
        manager.shutdown = Some(shutdown);
        let task = manager.join.abort_handle();
        shutdown_bounded(Duration::from_secs(2), manager, async {
            assert!(task.is_finished());
            endpoint.await.unwrap();
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_preserves_manager_panic_and_still_cleans_endpoint() {
        let manager = handle(tokio::spawn(async { panic!("manager panic witness") }));
        let task = manager.join.abort_handle();
        let error = shutdown_bounded(Duration::from_secs(2), manager, async {
            assert!(task.is_finished());
            Err(ManagerError::Endpoint("transport closed witness".into()))
        })
        .await
        .unwrap_err();
        let ManagerError::Shutdown { manager, endpoint } = error else {
            panic!("both shutdown failures must be retained");
        };
        assert!(
            matches!(*manager, ManagerError::Task(ref message) if message.contains("manager panic witness"))
        );
        assert_eq!(
            *endpoint,
            ManagerError::Endpoint("transport closed witness".into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_preserves_manager_destructor_panic() {
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("manager cancellation panic witness");
            }
        }
        let (started, ready) = oneshot::channel();
        let manager = handle(tokio::spawn(async move {
            let _guard = PanicOnDrop;
            let _ = started.send(());
            std::future::pending::<()>().await;
        }));
        ready.await.unwrap();
        let task = manager.join.abort_handle();
        let error = shutdown_bounded(Duration::from_secs(2), manager, async { Ok(()) })
            .await
            .unwrap_err();
        assert!(task.is_finished());
        assert!(
            matches!(error, ManagerError::Task(ref message) if message.contains("manager cancellation panic witness"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_bounds_both_stages_and_cleans_endpoint_after_manager_timeout() {
        let manager = handle(tokio::spawn(std::future::pending::<()>()));
        let task = manager.join.abort_handle();
        let start = Instant::now();
        let error = shutdown_bounded(Duration::from_secs(2), manager, async {
            assert!(task.is_finished());
            std::future::pending::<Result<(), ManagerError>>().await
        })
        .await
        .unwrap_err();
        assert_eq!(
            error,
            ManagerError::Shutdown {
                manager: Box::new(ManagerError::ShutdownDeadline("manager")),
                endpoint: Box::new(ManagerError::ShutdownDeadline("endpoint")),
            }
        );
        assert!(start.elapsed() <= Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn unreapable_manager_returns_cancellation_deadline() {
        // A running blocking task cannot be cancelled. Keep a release channel so
        // the test itself always cleans it up, including if an assertion fails.
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, ready) = oneshot::channel();
        let (finished, done) = oneshot::channel();
        let manager = handle(tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = blocked.recv();
            let _ = finished.send(());
        }));
        ready.await.unwrap();
        let task = manager.join.abort_handle();
        let stopped = shutdown_bounded(Duration::from_secs(2), manager, async { Ok(()) });
        tokio::pin!(stopped);
        assert!(futures::poll!(&mut stopped).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        let error = stopped.await.unwrap_err();
        let was_finished = task.is_finished();
        release.send(()).unwrap();
        done.await.unwrap();
        assert_eq!(
            error,
            ManagerError::ShutdownDeadline("manager cancellation")
        );
        assert!(
            !was_finished,
            "an unreaped task must not be reported as reaped"
        );
    }

    #[tokio::test]
    async fn dropping_manager_aborts_owned_task() {
        let (alive, dropped) = oneshot::channel::<()>();
        let manager = handle(tokio::spawn(async move {
            let _alive = alive;
            std::future::pending::<()>().await;
        }));
        drop(manager);
        assert!(tokio::time::timeout(Duration::from_secs(1), dropped)
            .await
            .expect("manager must be dropped with handle")
            .is_err());
    }
}
