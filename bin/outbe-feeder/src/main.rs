//! Outbe price-feeder daemon.
//!
//! Fetches prices from external providers, aggregates them via VWAP,
//! and submits oracle votes to the on-chain Oracle precompile.

mod abi;
mod aggregator;
mod config;
mod fixed;
mod health;
mod oracle_client;
mod provider;
mod vote_builder;

use std::sync::Arc;

use clap::Parser;
use eyre::Result;
use tracing::{error, info, warn};

use crate::config::FeederConfig;
use crate::health::FeederHealth;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownReason {
    Sigint,
    Sigterm,
}

impl ShutdownReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sigint => "SIGINT",
            Self::Sigterm => "SIGTERM",
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> ShutdownReason {
    let sigterm_kind = tokio::signal::unix::SignalKind::terminate();
    let mut sigterm = match tokio::signal::unix::signal(sigterm_kind) {
        Ok(signal) => Some(signal),
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler; falling back to SIGINT only");
            None
        }
    };

    if let Some(sigterm) = sigterm.as_mut() {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    warn!(error = %e, "SIGINT handler failed");
                }
                ShutdownReason::Sigint
            }
            _ = sigterm.recv() => ShutdownReason::Sigterm,
        }
    } else {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "SIGINT handler failed");
        }
        ShutdownReason::Sigint
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> ShutdownReason {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!(error = %e, "SIGINT handler failed");
    }
    ShutdownReason::Sigint
}

#[derive(Parser)]
#[command(name = "outbe-feeder", about = "Outbe price oracle feeder daemon")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "feeder.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "outbe_feeder=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = FeederConfig::load(&cli.config)?;
    config.validate()?;

    // ORC-AUD-039: Warn about plaintext key usage.
    // Production deployments should use an encrypted keystore or OS keyring.
    warn!("private key loaded from plaintext config - use an encrypted keystore in production");

    info!(
        rpc = %config.chain.rpc_endpoint,
        pairs = config.currency_pairs.len(),
        "starting outbe-feeder"
    );

    run_feeder(config).await
}

async fn run_feeder(config: FeederConfig) -> Result<()> {
    let providers = provider::create_providers(&config)?;
    let wallet = oracle_client::create_wallet(&config.account)?;
    let vote_period = config.oracle.vote_period;

    // Start health server
    let health_bind = config
        .health
        .as_ref()
        .map(|h| h.bind_address.clone())
        .unwrap_or_else(|| "0.0.0.0:9002".to_string());
    let health_enabled = config.health.as_ref().map(|h| h.enabled).unwrap_or(true);
    let health = Arc::new(FeederHealth::new(vote_period));

    if health_enabled {
        health::start_health_server(&health_bind, health.clone()).await?;
    }

    let mut last_voted_period: u64 = 0;
    let base_interval = std::time::Duration::from_secs(config.oracle.poll_interval_secs);
    let mut backoff = base_interval;
    let max_backoff = std::time::Duration::from_secs(60);

    let mut shutdown = std::pin::pin!(shutdown_signal());

    loop {
        // Poll current block height via JSON-RPC
        let block_number = tokio::select! {
            result = oracle_client::get_block_number(&config.chain.rpc_endpoint) => result,
            reason = &mut shutdown => {
                info!(signal = reason.as_str(), "shutdown signal received during block polling, exiting gracefully");
                return Ok(());
            }
        };

        let height = match block_number {
            Ok(h) => {
                backoff = base_interval; // reset on success
                h
            }
            Err(e) => {
                warn!(error = %e, backoff_secs = backoff.as_secs(), "failed to fetch block number, backing off");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {},
                    reason = &mut shutdown => {
                        info!(signal = reason.as_str(), "shutdown signal received during backoff, exiting gracefully");
                        return Ok(());
                    }
                }
                backoff = (backoff * 2).min(max_backoff); // exponential backoff, cap at 60s
                continue;
            }
        };

        // Check if next block is a vote period boundary
        let next_block = height + 1;
        // vote_period > 0 is guaranteed by config.validate() at startup
        let current_period = next_block / vote_period;

        health.set_period(current_period);

        if current_period > last_voted_period {
            // Preflight: check on-chain oracle params before spending gas
            let preflight = tokio::select! {
                result = oracle_client::preflight_check(
                    &config.chain.rpc_endpoint,
                    vote_period,
                    &config.account.validator_address,
                ) => result,
                reason = &mut shutdown => {
                    info!(signal = reason.as_str(), "shutdown signal received during preflight, exiting gracefully");
                    return Ok(());
                }
            };

            match preflight {
                oracle_client::PreflightResult::Skip(reason) => {
                    warn!(reason, "preflight check failed, skipping vote");
                    last_voted_period = current_period;
                    tokio::select! {
                        _ = tokio::time::sleep(base_interval) => {},
                        reason = &mut shutdown => {
                            info!(signal = reason.as_str(), "shutdown signal received after preflight skip, exiting gracefully");
                            return Ok(());
                        }
                    }
                    continue;
                }
                oracle_client::PreflightResult::Ok => {}
            }

            info!(
                height,
                next_block,
                period = current_period,
                "vote period boundary - submitting"
            );

            // Fetch prices from all providers
            let prices = tokio::select! {
                result = aggregator::fetch_and_aggregate(&providers, &config) => result,
                reason = &mut shutdown => {
                    info!(signal = reason.as_str(), "shutdown signal received during price aggregation, exiting gracefully");
                    return Ok(());
                }
            };

            // Always advance period after attempting - prevents retry storms
            // on persistent failures (nonce conflicts, RPC errors, etc.).
            last_voted_period = current_period;

            match prices {
                Ok(aggregated) if !aggregated.is_empty() => {
                    // Build and submit vote
                    let calldata = vote_builder::encode_vote(&aggregated);

                    // Decode calldata back and log exactly what goes on-chain
                    if let Ok(decoded) = vote_builder::decode_vote_log(&calldata) {
                        info!(vote = %decoded, "vote calldata");
                    }

                    match oracle_client::submit_vote(
                        &config.chain.rpc_endpoint,
                        &wallet,
                        config.chain.chain_id,
                        &calldata,
                        config.chain.gasless_oracle_votes,
                    )
                    .await
                    {
                        Ok(tx_hash) => {
                            info!(%tx_hash, pairs = aggregated.len(), "oracle vote submitted");
                            health.record_success(height);
                        }
                        Err(e) => {
                            error!(error = ?e, "failed to submit oracle vote, skipping period");
                            health.record_failure();
                        }
                    }
                }
                Ok(_) => {
                    warn!("no price data available, skipping vote");
                }
                Err(e) => {
                    error!(error = %e, "price aggregation failed");
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(base_interval) => {},
            reason = &mut shutdown => {
                info!(signal = reason.as_str(), "shutdown signal received, exiting gracefully");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_reason_labels_are_stable() {
        assert_eq!(ShutdownReason::Sigint.as_str(), "SIGINT");
        assert_eq!(ShutdownReason::Sigterm.as_str(), "SIGTERM");
    }
}
