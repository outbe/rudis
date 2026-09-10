//! Health and status HTTP server for the price-feeder daemon.
//!
//! Provides `/health` and `/status` endpoints for operator monitoring.
//! Runs as a background tokio task alongside the main feeder loop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Shared feeder health state, updated by the main loop.
pub struct FeederHealth {
    /// Block number of the last successful vote submission.
    pub last_vote_block: AtomicU64,
    /// Unix timestamp of the last successful vote submission.
    pub last_vote_time: AtomicU64,
    /// Total number of votes successfully submitted.
    pub votes_submitted: AtomicU64,
    /// Total number of votes that failed submission.
    pub votes_failed: AtomicU64,
    /// Current vote period.
    pub current_period: AtomicU64,
    /// Configured vote period in blocks.
    pub vote_period: u64,
}

impl FeederHealth {
    pub fn new(vote_period: u64) -> Self {
        Self {
            last_vote_block: AtomicU64::new(0),
            last_vote_time: AtomicU64::new(0),
            votes_submitted: AtomicU64::new(0),
            votes_failed: AtomicU64::new(0),
            current_period: AtomicU64::new(0),
            vote_period,
        }
    }

    pub fn record_success(&self, block: u64) {
        self.last_vote_block.store(block, Ordering::Relaxed);
        self.last_vote_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        self.votes_submitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.votes_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_period(&self, period: u64) {
        self.current_period.store(period, Ordering::Relaxed);
    }

    fn is_healthy(&self) -> bool {
        let last = self.last_vote_time.load(Ordering::Relaxed);
        if last == 0 {
            // No vote submitted yet - healthy if daemon just started
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Healthy if last vote was within 5 * vote_period * 12s (generous window)
        let max_age = self.vote_period * 12 * 5;
        now.saturating_sub(last) < max_age
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "healthy": self.is_healthy(),
            "last_vote_block": self.last_vote_block.load(Ordering::Relaxed),
            "last_vote_time": self.last_vote_time.load(Ordering::Relaxed),
            "votes_submitted": self.votes_submitted.load(Ordering::Relaxed),
            "votes_failed": self.votes_failed.load(Ordering::Relaxed),
            "current_period": self.current_period.load(Ordering::Relaxed),
            "vote_period": self.vote_period,
        })
    }
}

/// Starts the health HTTP server on the given bind address.
///
/// Serves:
/// - `GET /health` - 200 if healthy, 503 if not
/// - `GET /status` - JSON with full feeder state
///
/// Returns immediately; the server runs as a background task.
pub async fn start_health_server(bind_addr: &str, health: Arc<FeederHealth>) -> eyre::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(addr = bind_addr, "health server listening");

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "health server accept error");
                    continue;
                }
            };

            let health = health.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, body) = match path {
                    "/health" => {
                        if health.is_healthy() {
                            ("200 OK", "{\"status\":\"ok\"}".to_string())
                        } else {
                            (
                                "503 Service Unavailable",
                                "{\"status\":\"unhealthy\"}".to_string(),
                            )
                        }
                    }
                    "/status" => {
                        let json = health.to_json();
                        (
                            "200 OK",
                            serde_json::to_string_pretty(&json).unwrap_or_default(),
                        )
                    }
                    _ => ("404 Not Found", "{\"error\":\"not found\"}".to_string()),
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_new_is_healthy() {
        let h = FeederHealth::new(2);
        assert!(h.is_healthy());
    }

    #[test]
    fn test_health_after_success() {
        let h = FeederHealth::new(2);
        h.record_success(100);
        assert!(h.is_healthy());
        assert_eq!(h.votes_submitted.load(Ordering::Relaxed), 1);
        assert_eq!(h.last_vote_block.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_health_failure_count() {
        let h = FeederHealth::new(2);
        h.record_failure();
        h.record_failure();
        assert_eq!(h.votes_failed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_health_json() {
        let h = FeederHealth::new(2);
        h.record_success(42);
        h.set_period(21);
        let j = h.to_json();
        assert_eq!(j["last_vote_block"], 42);
        assert_eq!(j["current_period"], 21);
        assert_eq!(j["vote_period"], 2);
        assert_eq!(j["healthy"], true);
    }

    #[tokio::test]
    async fn test_health_server_starts() {
        let health = Arc::new(FeederHealth::new(2));
        // Use port 0 to let OS assign a free port
        let result = start_health_server("127.0.0.1:0", health).await;
        assert!(result.is_ok());
    }
}
