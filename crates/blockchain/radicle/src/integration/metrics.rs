use super::{RadicleStatusSnapshot, RadicleVotingGate};

#[derive(Default)]
pub struct RadicleMetrics {
    previous: FailureTotals,
}

#[derive(Clone, Copy, Default)]
struct FailureTotals {
    finality_regressions: u64,
    finality_conflicts: u64,
    provider_failures: u64,
    endpoint_failures: u64,
    uds_failures: u64,
    tcp_status_failures: u64,
}

impl RadicleMetrics {
    pub fn record(&mut self, status: &RadicleStatusSnapshot) {
        let manager = &status.manager;
        let phase = match manager.phase {
            crate::manager::ManagerPhase::Disabled => 0.0,
            crate::manager::ManagerPhase::JoiningUnbound => 1.0,
            crate::manager::ManagerPhase::Ready => 2.0,
            crate::manager::ManagerPhase::RuntimeDegraded => 3.0,
        };
        metrics::gauge!("outbe_radicle_phase").set(phase);
        set_finality(
            "outbe_radicle_last_seen_finalized_known",
            "outbe_radicle_last_seen_finalized_height",
            manager.last_seen_finalized.map(|block| block.number),
        );
        set_finality(
            "outbe_radicle_last_converged_finalized_known",
            "outbe_radicle_last_converged_finalized_height",
            manager.last_converged_finalized.map(|block| block.number),
        );
        metrics::gauge!("outbe_radicle_desired_peers")
            .set((manager.resolved_peer_count + manager.unresolved_peer_count) as f64);
        metrics::gauge!("outbe_radicle_resolved_peers").set(manager.resolved_peer_count as f64);
        metrics::gauge!("outbe_radicle_unresolved_peers").set(manager.unresolved_peer_count as f64);
        metrics::gauge!("outbe_radicle_connected_peers").set(manager.connected_peer_count as f64);
        metrics::gauge!("outbe_radicle_desired_repositories")
            .set(manager.desired_repository_count as f64);
        metrics::gauge!("outbe_radicle_available_repositories")
            .set(manager.available_repository_count as f64);
        metrics::gauge!("outbe_radicle_pending_repositories")
            .set(manager.pending_repository_count as f64);
        if let Some(node_id) = status.local_node_id {
            metrics::gauge!("outbe_radicle_identity", "node_id" => hex::encode(node_id)).set(1.0);
        }

        let current = FailureTotals {
            finality_regressions: manager.finality_regressions,
            finality_conflicts: manager.finality_conflicts,
            provider_failures: manager.provider_failures,
            endpoint_failures: manager.endpoint_failures,
            uds_failures: manager.uds_failures,
            tcp_status_failures: manager.tcp_status_failures,
        };
        increment(
            "outbe_radicle_finality_regressions_total",
            current.finality_regressions,
            self.previous.finality_regressions,
        );
        increment(
            "outbe_radicle_finality_conflicts_total",
            current.finality_conflicts,
            self.previous.finality_conflicts,
        );
        increment(
            "outbe_radicle_provider_failures_total",
            current.provider_failures,
            self.previous.provider_failures,
        );
        increment(
            "outbe_radicle_endpoint_failures_total",
            current.endpoint_failures,
            self.previous.endpoint_failures,
        );
        increment(
            "outbe_radicle_uds_failures_total",
            current.uds_failures,
            self.previous.uds_failures,
        );
        increment(
            "outbe_radicle_tcp_status_failures_total",
            current.tcp_status_failures,
            self.previous.tcp_status_failures,
        );
        self.previous = current;

        let _ = status.voting_gate == RadicleVotingGate::SignerAllowed;
    }
}

fn set_finality(known: &'static str, height: &'static str, value: Option<u64>) {
    metrics::gauge!(known).set(f64::from(value.is_some()));
    metrics::gauge!(height).set(value.unwrap_or_default() as f64);
}

fn increment(name: &'static str, current: u64, previous: u64) {
    if current >= previous {
        metrics::counter!(name).increment(current - previous);
    }
}
