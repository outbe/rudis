//! Shared Salvo observability surface for the standalone OCOMP roles.
// OCOMP-TEST-ID: OCM-WOBS-001

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use outbe_ocomp_protocol::UnitFinishedStatus;
use salvo::affix_state;
use salvo::conn::Listener as _;
use salvo::prelude::*;
use salvo::request_id::RequestId;
use salvo::server::ServerHandle;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HEALTH_STALE_AFTER: Duration = Duration::from_secs(30);
static PROMETHEUS_HANDLE: OnceLock<Result<PrometheusHandle, String>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPhaseV1 {
    Registering,
    Idle,
    Working,
    Cancelling,
    Disconnected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkerStatusV1 {
    pub phase: WorkerPhaseV1,
    pub worker_id: Option<String>,
    pub registry_generation: Option<u64>,
    pub lease_id: Option<String>,
    pub unit_id: Option<String>,
    pub last_loop_activity_ms_ago: u64,
}

#[derive(Clone, Debug, Serialize)]
struct HealthV1 {
    status: &'static str,
}

struct WorkerStatusState {
    phase: WorkerPhaseV1,
    worker_id: Option<String>,
    registry_generation: Option<u64>,
    lease_id: Option<String>,
    unit_id: Option<String>,
    last_loop_activity: Instant,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotExporterPhaseV1 {
    Starting,
    Reconciling,
    Idle,
    Exporting,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotExporterStatusV1 {
    pub phase: SnapshotExporterPhaseV1,
    pub current_bundle: Option<String>,
    pub current_job: Option<String>,
    pub last_error: Option<String>,
    pub pending_jobs: u64,
    pub last_activity_ms_ago: u64,
    pub last_successful_reconcile_ms_ago: u64,
}

struct SnapshotExporterStatusState {
    phase: SnapshotExporterPhaseV1,
    current_bundle: Option<String>,
    current_job: Option<String>,
    last_error: Option<String>,
    pending_jobs: u64,
    healthy: bool,
    last_activity: Instant,
    last_successful_reconcile: Instant,
}

struct ObservabilityServerParts {
    address: SocketAddr,
    handle: ServerHandle,
    thread: Option<JoinHandle<()>>,
}

pub struct WorkerObservabilityServerV1 {
    state: Arc<Mutex<WorkerStatusState>>,
    address: SocketAddr,
    handle: ServerHandle,
    thread: Option<JoinHandle<()>>,
}

impl WorkerObservabilityServerV1 {
    pub fn start(address: SocketAddr) -> Result<Self, WorkerObservabilityErrorV1> {
        require_loopback(address)?;
        let state = Arc::new(Mutex::new(WorkerStatusState {
            phase: WorkerPhaseV1::Registering,
            worker_id: None,
            registry_generation: None,
            lease_id: None,
            unit_id: None,
            last_loop_activity: Instant::now(),
        }));
        let prometheus = prometheus_handle()?;
        let parts = start_server(
            address,
            "ocomp-worker-observability",
            worker_router(Arc::clone(&state), prometheus),
        )?;
        metrics::counter!("outbe_ocomp_worker_process_starts_total").increment(1);
        Ok(Self {
            state,
            address: parts.address,
            handle: parts.handle,
            thread: parts.thread,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn registering(&self) {
        self.update(WorkerPhaseV1::Registering, None, None, None, None, false);
    }

    pub fn idle(&self, worker_id: String, registry_generation: u64) {
        self.update(
            WorkerPhaseV1::Idle,
            Some(worker_id),
            Some(registry_generation),
            None,
            None,
            true,
        );
    }

    pub fn working(
        &self,
        worker_id: String,
        registry_generation: u64,
        lease_id: String,
        unit_id: String,
    ) {
        metrics::counter!("outbe_ocomp_worker_units_started_total").increment(1);
        self.update(
            WorkerPhaseV1::Working,
            Some(worker_id),
            Some(registry_generation),
            Some(lease_id),
            Some(unit_id),
            true,
        );
    }

    pub fn cancelling(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = WorkerPhaseV1::Cancelling;
            state.last_loop_activity = Instant::now();
        }
    }

    pub fn disconnected(&self) {
        metrics::counter!("outbe_ocomp_worker_disconnects_total").increment(1);
        if let Ok(mut state) = self.state.lock() {
            state.phase = WorkerPhaseV1::Disconnected;
        }
    }

    pub fn completed(&self, status: UnitFinishedStatus) {
        let outcome = match status {
            UnitFinishedStatus::Success => "success",
            UnitFinishedStatus::Failed => "failed",
        };
        metrics::counter!("outbe_ocomp_worker_units_completed_total", "outcome" => outcome)
            .increment(1);
    }

    pub fn cancelled(&self) {
        metrics::counter!("outbe_ocomp_worker_units_completed_total", "outcome" => "cancelled")
            .increment(1);
    }

    pub fn touch(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_loop_activity = Instant::now();
        }
    }

    pub fn status(&self) -> Result<WorkerStatusV1, WorkerObservabilityErrorV1> {
        snapshot(&self.state)
    }

    fn update(
        &self,
        phase: WorkerPhaseV1,
        worker_id: Option<String>,
        registry_generation: Option<u64>,
        lease_id: Option<String>,
        unit_id: Option<String>,
        loop_activity: bool,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = phase;
            state.worker_id = worker_id;
            state.registry_generation = registry_generation;
            state.lease_id = lease_id;
            state.unit_id = unit_id;
            if loop_activity {
                state.last_loop_activity = Instant::now();
            }
        }
    }
}

pub struct SnapshotExporterObservabilityServerV1 {
    state: Arc<Mutex<SnapshotExporterStatusState>>,
    address: SocketAddr,
    handle: ServerHandle,
    thread: Option<JoinHandle<()>>,
}

impl SnapshotExporterObservabilityServerV1 {
    pub fn start(address: SocketAddr) -> Result<Self, WorkerObservabilityErrorV1> {
        require_loopback(address)?;
        let state = Arc::new(Mutex::new(SnapshotExporterStatusState {
            phase: SnapshotExporterPhaseV1::Starting,
            current_bundle: None,
            current_job: None,
            last_error: None,
            pending_jobs: 0,
            healthy: false,
            last_activity: Instant::now(),
            last_successful_reconcile: Instant::now(),
        }));
        let prometheus = prometheus_handle()?;
        let parts = start_server(
            address,
            "ocomp-snapshot-exporter-observability",
            snapshot_exporter_router(Arc::clone(&state), prometheus),
        )?;
        metrics::counter!("outbe_ocomp_snapshot_exporter_process_starts_total").increment(1);
        Ok(Self {
            state,
            address: parts.address,
            handle: parts.handle,
            thread: parts.thread,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn begin_reconcile(&self) {
        if let Ok(mut state) = self.state.lock() {
            // A retry attempt is progress, not proof of health. Only a complete
            // successful reconciliation clears the previous failure.
            state.phase = SnapshotExporterPhaseV1::Reconciling;
            state.current_bundle = None;
            state.current_job = None;
            state.healthy = false;
            state.last_activity = Instant::now();
        }
    }

    pub fn exporting(&self, bundle: String, job: String) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_export_attempts_total").increment(1);
        if let Ok(mut state) = self.state.lock() {
            if state.phase != SnapshotExporterPhaseV1::Error {
                state.phase = SnapshotExporterPhaseV1::Exporting;
            }
            state.current_bundle = Some(bundle);
            state.current_job = Some(job);
            state.last_activity = Instant::now();
        }
    }

    pub fn export_progress(&self) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_progress_events_total").increment(1);
        if let Ok(mut state) = self.state.lock() {
            state.last_activity = Instant::now();
        }
    }

    pub fn committed(&self) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_commits_total").increment(1);
    }

    pub fn late_ack_ignored(&self) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_late_acks_ignored_total").increment(1);
        if let Ok(mut state) = self.state.lock() {
            state.last_activity = Instant::now();
        }
    }

    pub fn discovery_error(&self, error: String) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_discovery_errors_total").increment(1);
        self.set_error(error);
    }

    pub fn export_error(&self, error: String) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_export_errors_total").increment(1);
        self.set_error(error);
    }

    pub fn startup_error(&self, error: String) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_startup_errors_total").increment(1);
        self.set_error(error);
    }

    pub fn reconcile_succeeded(&self, pending_jobs: u64) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_reconcile_cycles_total", "outcome" => "success")
            .increment(1);
        if let Ok(mut state) = self.state.lock() {
            state.phase = SnapshotExporterPhaseV1::Idle;
            state.current_bundle = None;
            state.current_job = None;
            state.last_error = None;
            state.pending_jobs = pending_jobs;
            state.healthy = true;
            state.last_activity = Instant::now();
            state.last_successful_reconcile = Instant::now();
        }
    }

    pub fn reconcile_failed(&self, pending_jobs: u64) {
        metrics::counter!("outbe_ocomp_snapshot_exporter_reconcile_cycles_total", "outcome" => "error")
            .increment(1);
        if let Ok(mut state) = self.state.lock() {
            state.pending_jobs = pending_jobs;
        }
    }

    pub fn status(&self) -> Result<SnapshotExporterStatusV1, WorkerObservabilityErrorV1> {
        snapshot_exporter_snapshot(&self.state)
    }

    fn set_error(&self, error: String) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = SnapshotExporterPhaseV1::Error;
            state.last_error = Some(error);
            state.healthy = false;
            state.last_activity = Instant::now();
        }
    }
}

impl Drop for WorkerObservabilityServerV1 {
    fn drop(&mut self) {
        self.handle.stop_forceful();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SnapshotExporterObservabilityServerV1 {
    fn drop(&mut self) {
        self.handle.stop_forceful();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn prometheus_handle() -> Result<PrometheusHandle, WorkerObservabilityErrorV1> {
    PROMETHEUS_HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(WorkerObservabilityErrorV1::Recorder)
}

fn start_server(
    address: SocketAddr,
    thread_name: &'static str,
    router: Router,
) -> Result<ObservabilityServerParts, WorkerObservabilityErrorV1> {
    require_loopback(address)?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            runtime.block_on(async move {
                let acceptor = match salvo::conn::TcpListener::new(address).try_bind().await {
                    Ok(acceptor) => acceptor,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let bound_address = match acceptor.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let server = Server::new(acceptor).max_connections(32);
                let handle = server.handle();
                if ready_tx.send(Ok((bound_address, handle))).is_err() {
                    return;
                }
                server.serve(router).await;
            });
        })
        .map_err(|error| WorkerObservabilityErrorV1::Start(error.to_string()))?;
    let (address, handle) = ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|error| WorkerObservabilityErrorV1::Start(error.to_string()))?
        .map_err(WorkerObservabilityErrorV1::Start)?;
    Ok(ObservabilityServerParts {
        address,
        handle,
        thread: Some(thread),
    })
}

fn require_loopback(address: SocketAddr) -> Result<(), WorkerObservabilityErrorV1> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(WorkerObservabilityErrorV1::InvalidAddress(address))
    }
}

fn worker_router(state: Arc<Mutex<WorkerStatusState>>, prometheus: PrometheusHandle) -> Router {
    Router::new()
        .hoop(RequestId::new())
        .hoop(affix_state::inject(state))
        .hoop(affix_state::inject(prometheus))
        .push(Router::with_path("healthz").get(worker_healthz))
        .push(Router::with_path("status").get(worker_status))
        .push(Router::with_path("metrics").get(worker_metrics))
}

#[handler]
async fn worker_healthz(depot: &Depot, res: &mut Response) {
    let healthy = depot
        .get_typed::<Arc<Mutex<WorkerStatusState>>>()
        .ok()
        .and_then(|state| state.lock().ok().map(|state| worker_is_healthy(&state)))
        .unwrap_or(false);
    render_health(healthy, res);
}

#[handler]
async fn worker_status(depot: &Depot, res: &mut Response) {
    let result = depot
        .get_typed::<Arc<Mutex<WorkerStatusState>>>()
        .map_err(|_| WorkerObservabilityErrorV1::MissingState)
        .and_then(snapshot);
    match result {
        Ok(snapshot) => res.render(Json(snapshot)),
        Err(error) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain(error.to_string()));
        }
    };
}

#[handler]
async fn worker_metrics(depot: &Depot, res: &mut Response) {
    match depot.get_typed::<Arc<Mutex<WorkerStatusState>>>() {
        Ok(state) => {
            match state.lock() {
                Ok(state) => {
                    metrics::gauge!("outbe_ocomp_worker_healthy")
                        .set(if worker_is_healthy(&state) { 1.0 } else { 0.0 });
                    metrics::gauge!("outbe_ocomp_worker_loop_activity_age_seconds")
                        .set(state.last_loop_activity.elapsed().as_secs_f64());
                }
                Err(_) => metrics::gauge!("outbe_ocomp_worker_healthy").set(0.0),
            }
        }
        Err(_) => metrics::gauge!("outbe_ocomp_worker_healthy").set(0.0),
    }
    render_metrics(depot, res);
}

fn snapshot_exporter_router(
    state: Arc<Mutex<SnapshotExporterStatusState>>,
    prometheus: PrometheusHandle,
) -> Router {
    Router::new()
        .hoop(RequestId::new())
        .hoop(affix_state::inject(state))
        .hoop(affix_state::inject(prometheus))
        .push(Router::with_path("healthz").get(snapshot_exporter_healthz))
        .push(Router::with_path("status").get(snapshot_exporter_status))
        .push(Router::with_path("metrics").get(snapshot_exporter_metrics))
}

#[handler]
async fn snapshot_exporter_healthz(depot: &Depot, res: &mut Response) {
    let healthy = depot
        .get_typed::<Arc<Mutex<SnapshotExporterStatusState>>>()
        .ok()
        .and_then(|state| {
            state
                .lock()
                .ok()
                .map(|state| snapshot_exporter_is_healthy(&state))
        })
        .unwrap_or(false);
    render_health(healthy, res);
}

#[handler]
async fn snapshot_exporter_status(depot: &Depot, res: &mut Response) {
    let result = depot
        .get_typed::<Arc<Mutex<SnapshotExporterStatusState>>>()
        .map_err(|_| WorkerObservabilityErrorV1::MissingState)
        .and_then(snapshot_exporter_snapshot);
    match result {
        Ok(snapshot) => res.render(Json(snapshot)),
        Err(error) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain(error.to_string()));
        }
    };
}

#[handler]
async fn snapshot_exporter_metrics(depot: &Depot, res: &mut Response) {
    match depot.get_typed::<Arc<Mutex<SnapshotExporterStatusState>>>() {
        Ok(state) => match state.lock() {
            Ok(state) => {
                metrics::gauge!("outbe_ocomp_snapshot_exporter_healthy").set(
                    if snapshot_exporter_is_healthy(&state) {
                        1.0
                    } else {
                        0.0
                    },
                );
                metrics::gauge!("outbe_ocomp_snapshot_exporter_activity_age_seconds")
                    .set(state.last_activity.elapsed().as_secs_f64());
                metrics::gauge!("outbe_ocomp_snapshot_exporter_reconcile_age_seconds")
                    .set(state.last_successful_reconcile.elapsed().as_secs_f64());
                metrics::gauge!("outbe_ocomp_snapshot_exporter_pending_jobs")
                    .set(state.pending_jobs as f64);
            }
            Err(_) => metrics::gauge!("outbe_ocomp_snapshot_exporter_healthy").set(0.0),
        },
        Err(_) => metrics::gauge!("outbe_ocomp_snapshot_exporter_healthy").set(0.0),
    }
    render_metrics(depot, res);
}

fn render_health(healthy: bool, res: &mut Response) {
    if healthy {
        res.render(Json(HealthV1 { status: "ok" }));
    } else {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.render(Json(HealthV1 { status: "error" }));
    }
}

fn render_metrics(depot: &Depot, res: &mut Response) {
    match depot.get_typed::<PrometheusHandle>() {
        Ok(prometheus) => {
            prometheus.run_upkeep();
            res.render(Text::Plain(prometheus.render()));
        }
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain("Prometheus recorder is unavailable"));
        }
    };
}

fn worker_is_healthy(state: &WorkerStatusState) -> bool {
    matches!(
        state.phase,
        WorkerPhaseV1::Idle | WorkerPhaseV1::Working | WorkerPhaseV1::Cancelling
    ) && state.last_loop_activity.elapsed() <= HEALTH_STALE_AFTER
}

fn snapshot_exporter_is_healthy(state: &SnapshotExporterStatusState) -> bool {
    state.healthy && state.last_activity.elapsed() <= HEALTH_STALE_AFTER
}

fn snapshot(
    state: &Arc<Mutex<WorkerStatusState>>,
) -> Result<WorkerStatusV1, WorkerObservabilityErrorV1> {
    let state = state
        .lock()
        .map_err(|_| WorkerObservabilityErrorV1::Poisoned)?;
    Ok(WorkerStatusV1 {
        phase: state.phase,
        worker_id: state.worker_id.clone(),
        registry_generation: state.registry_generation,
        lease_id: state.lease_id.clone(),
        unit_id: state.unit_id.clone(),
        last_loop_activity_ms_ago: u64::try_from(state.last_loop_activity.elapsed().as_millis())
            .unwrap_or(u64::MAX),
    })
}

fn snapshot_exporter_snapshot(
    state: &Arc<Mutex<SnapshotExporterStatusState>>,
) -> Result<SnapshotExporterStatusV1, WorkerObservabilityErrorV1> {
    let state = state
        .lock()
        .map_err(|_| WorkerObservabilityErrorV1::Poisoned)?;
    Ok(SnapshotExporterStatusV1 {
        phase: state.phase,
        current_bundle: state.current_bundle.clone(),
        current_job: state.current_job.clone(),
        last_error: state.last_error.clone(),
        pending_jobs: state.pending_jobs,
        last_activity_ms_ago: u64::try_from(state.last_activity.elapsed().as_millis())
            .unwrap_or(u64::MAX),
        last_successful_reconcile_ms_ago: u64::try_from(
            state.last_successful_reconcile.elapsed().as_millis(),
        )
        .unwrap_or(u64::MAX),
    })
}

#[derive(Debug, Error)]
pub enum WorkerObservabilityErrorV1 {
    #[error("worker observability address {0} must be a loopback endpoint")]
    InvalidAddress(SocketAddr),
    #[error("failed to start Worker Salvo observability server: {0}")]
    Start(String),
    #[error("failed to install the OCOMP Prometheus recorder: {0}")]
    Recorder(String),
    #[error("Worker observability state is unavailable")]
    MissingState,
    #[error("Worker observability state lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_and_status_remain_available_while_worker_is_busy() {
        let server = WorkerObservabilityServerV1::start("127.0.0.1:0".parse().unwrap())
            .expect("start Worker observability");
        server.working("worker-1".into(), 7, "lease-1".into(), "unit-1".into());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        let status: WorkerStatusV1 = client
            .get(format!("http://{}/status", server.address()))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(status.phase, WorkerPhaseV1::Working);
        assert_eq!(status.lease_id.as_deref(), Some("lease-1"));
        let metrics = client
            .get(format!("http://{}/metrics", server.address()))
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert!(metrics.contains("outbe_ocomp_worker_units_started_total"));
        assert!(metrics.contains("outbe_ocomp_worker_healthy 1"));
    }

    #[test]
    fn worker_health_is_fail_closed_while_disconnected() {
        let server = WorkerObservabilityServerV1::start("127.0.0.1:0".parse().unwrap())
            .expect("start Worker observability");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server.idle("worker-1".into(), 1);
        server.state.lock().unwrap().last_loop_activity =
            Instant::now() - HEALTH_STALE_AFTER - Duration::from_millis(1);
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server.touch();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        server.idle("worker-1".into(), 1);
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        server.disconnected();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn snapshot_exporter_reuses_the_same_health_status_and_metrics_surface() {
        let server = SnapshotExporterObservabilityServerV1::start("127.0.0.1:0".parse().unwrap())
            .expect("start SnapshotExporter observability");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server.exporting("bundle-1".into(), "job-1".into());
        server.export_progress();
        server.committed();
        server.reconcile_succeeded(0);
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        let status: SnapshotExporterStatusV1 = client
            .get(format!("http://{}/status", server.address()))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(status.phase, SnapshotExporterPhaseV1::Idle);
        let metrics = client
            .get(format!("http://{}/metrics", server.address()))
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert!(metrics.contains("outbe_ocomp_snapshot_exporter_commits_total"));
        assert!(metrics.contains("outbe_ocomp_snapshot_exporter_healthy 1"));
    }

    #[test]
    fn failed_exporter_cycle_cannot_be_masked_by_a_later_lane() {
        let server = SnapshotExporterObservabilityServerV1::start("127.0.0.1:0".parse().unwrap())
            .expect("start SnapshotExporter observability");
        server.begin_reconcile();
        server.discovery_error("first lane failed".into());
        server.exporting("second-bundle".into(), "second-job".into());
        server.committed();
        server.reconcile_failed(1);

        let status = server.status().expect("status");
        assert_eq!(status.phase, SnapshotExporterPhaseV1::Error);
        assert_eq!(status.last_error.as_deref(), Some("first lane failed"));
        assert_eq!(status.pending_jobs, 1);
    }

    #[test]
    fn streaming_export_health_tracks_durable_progress_without_a_job_size_timeout() {
        let server = SnapshotExporterObservabilityServerV1::start("127.0.0.1:0".parse().unwrap())
            .expect("start SnapshotExporter observability");
        server.begin_reconcile();
        server.export_error("previous cycle failed".into());
        server.reconcile_failed(1);
        server.begin_reconcile();
        server.exporting("bundle-1".into(), "large-job".into());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        let status = server.status().expect("retry status");
        assert_eq!(status.phase, SnapshotExporterPhaseV1::Exporting);
        assert_eq!(status.last_error.as_deref(), Some("previous cycle failed"));

        server.state.lock().unwrap().last_activity =
            Instant::now() - HEALTH_STALE_AFTER - Duration::from_millis(1);
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server.export_progress();
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server.reconcile_succeeded(0);
        assert_eq!(
            client
                .get(format!("http://{}/healthz", server.address()))
                .send()
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
    }

    #[test]
    fn observability_endpoints_remain_loopback_only() {
        assert!(matches!(
            WorkerObservabilityServerV1::start("0.0.0.0:0".parse().unwrap()),
            Err(WorkerObservabilityErrorV1::InvalidAddress(_))
        ));
        assert!(matches!(
            SnapshotExporterObservabilityServerV1::start("0.0.0.0:0".parse().unwrap()),
            Err(WorkerObservabilityErrorV1::InvalidAddress(_))
        ));
    }
}
