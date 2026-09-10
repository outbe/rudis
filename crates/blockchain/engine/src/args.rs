//! Consensus CLI arguments.

use std::{fmt, net::SocketAddr, path::PathBuf};

use outbe_primitives::tee_attestation_v1::AttestationMode;

/// Local authorization protocol used between one node and its enclave.
///
/// This is deliberately independent from [`AttestationMode`]: a development
/// network may run a production NodeHost-authorized enclave inside real SGX
/// while publishing only `GramineDirectDev` evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum TeeSessionMode {
    /// Preserve the historical policy defaults: DCAP uses NodeHost; the
    /// hardware-free development lane uses its separate development transport.
    #[default]
    PolicyDefault,
    /// Require the authenticated, sealed production NodeHost session.
    ProductionNodeHost,
    /// Require the separate development/mock transport.
    Development,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedTeeSession {
    ProductionNodeHost,
    Development,
}

impl TeeSessionMode {
    pub fn resolve(self, policy: AttestationMode) -> Result<ResolvedTeeSession, &'static str> {
        match (self, policy) {
            (Self::PolicyDefault, AttestationMode::DcapRequired)
            | (Self::ProductionNodeHost, _) => Ok(ResolvedTeeSession::ProductionNodeHost),
            (Self::PolicyDefault | Self::Development, AttestationMode::GramineDirectDev) => {
                Ok(ResolvedTeeSession::Development)
            }
            (Self::Development, AttestationMode::DcapRequired) => {
                Err("DcapRequired forbids the development enclave session")
            }
        }
    }
}

/// Path to the shared offchain-storage TOML, loaded by the node at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffchainDataArgs {
    pub storage_config: PathBuf,
}

/// CLI arguments for the Outbe consensus layer.
#[derive(Clone, clap::Args)]
pub struct ConsensusArgs {
    /// Run as active consensus participant (validator).
    /// When false, runs as full node (sync + RPC only, no block production).
    #[arg(long = "validator", default_value_t = false)]
    pub is_validator: bool,

    /// Path to the BLS12-381 individual signing key file (32-byte scalar, hex-encoded).
    #[arg(long = "consensus.signing-key", value_name = "PATH")]
    pub signing_key: Option<PathBuf>,

    /// Path to the secp256k1 EVM key used to sign system transaction artifacts.
    /// Defaults to sibling `evm-key.hex` next to `--consensus.signing-key`.
    #[arg(long = "validator.evm-key", value_name = "PATH")]
    pub validator_evm_key: Option<PathBuf>,

    /// Path to the BLS12-381 signing share file (hex-encoded).
    /// Generated via centralized DKG bootstrap and distributed to validators.
    #[arg(long = "consensus.signing-share", value_name = "PATH")]
    pub signing_share: Option<PathBuf>,

    /// Path to the BLS12-381 public polynomial file (hex-encoded).
    /// Used to verify partial signatures from other validators.
    #[arg(long = "consensus.public-polynomial", value_name = "PATH")]
    pub public_polynomial: Option<PathBuf>,

    /// Path to the full DKG output artifact (hex-encoded).
    /// Required with manual share + polynomial provisioning for fresh bootstrap or true reshare continuity.
    #[arg(long = "consensus.dkg-output", value_name = "PATH")]
    pub dkg_output: Option<PathBuf>,

    /// P2P listen address for consensus network.
    #[arg(long = "consensus.listen-addr", default_value = "127.0.0.1:30400")]
    pub listen_address: SocketAddr,

    /// Directory for consensus data storage.
    /// Defaults to `<datadir>/consensus` if not set.
    #[arg(long = "consensus.storage-dir", value_name = "PATH")]
    pub storage_dir: Option<PathBuf>,

    /// Directory for validator key material (DKG shares, polynomials, output).
    /// Defaults to `<datadir>/keys` if not set.
    /// Kept separate from consensus storage so operators can snapshot `data/`
    /// without overwriting per-validator key material.
    #[arg(long = "consensus.keys-dir", value_name = "PATH")]
    pub keys_dir: Option<PathBuf>,

    /// Trust the existing EL head when consensus-finalized height is 0.
    /// This is consensus-archive recovery after a storage wipe; it never bypasses
    /// the permanent offer-key gate or regenerates a lost enclave identity.
    /// Only allowed on testnet/devnet chains (rejected on mainnet chain_id).
    #[arg(long = "testnet.trust-el-head", default_value_t = false)]
    pub trust_el_head: bool,

    /// Signed proposer clock offset for deterministic local testnet scenarios.
    /// Rejected on mainnet; normal nodes omit it and use the system clock.
    #[arg(long = "testnet.unix-time-offset-secs", value_name = "SECONDS")]
    pub testnet_unix_time_offset_secs: Option<i64>,

    /// Comma-separated list of bootstrap peers for P2P discovery.
    /// Format: `<hex_bls_pubkey>@<host:port>` (e.g. `aabb...ff@1.2.3.4:30400`).
    /// Used only as a bootstrap/discovery hint. Validator membership and target
    /// P2P addresses are read from chain state.
    #[arg(long = "consensus.peers", value_delimiter = ',', value_name = "PEER")]
    pub consensus_peers: Vec<String>,

    /// Use P2P defaults optimized for local network environments.
    ///
    /// Production/default mode uses Commonware's recommended authenticated lookup
    /// settings. Local testnets should pass this flag to allow private IPs and
    /// faster peer redial/ping timings.
    #[arg(long = "consensus.use-local-defaults", default_value_t = false)]
    pub use_local_defaults: bool,

    /// Time (ms) to prepare proposal transactions before resolving the payload.
    #[arg(long = "consensus.payload-resolve-time-ms", default_value_t = 200)]
    pub payload_resolve_time_ms: u64,

    /// Minimum time (ms) before sending a proposal to keep block times stable.
    #[arg(long = "consensus.payload-return-time-ms", default_value_t = 450)]
    pub payload_return_time_ms: u64,

    // Simplex leader / certification timeouts are NOT CLI flags. They are
    // consensus-critical and must be identical across all validators, so the
    // only sources of truth are the `outbe_consensus::timing` defaults and
    // `genesis.json` (`leaderTimeoutMs` / `certificationTimeoutMs`). A per-node
    // CLI override could desync timings and fork the network.
    /// Number of worker threads for the consensus runtime.
    #[arg(long = "consensus.worker-threads", default_value_t = 3)]
    pub worker_threads: usize,

    /// BLS key storage backend: plaintext, encrypted, or os-level.
    /// - `plaintext`: hex files on disk (default, suitable for development)
    /// - `encrypted`: AES-256-GCM + Argon2id; requires --bls-passphrase
    /// - `os-level`: macOS Keychain / Linux Secret Service
    #[arg(
        long = "bls-key-backend",
        default_value = "plaintext",
        value_name = "BACKEND"
    )]
    pub bls_key_backend: String,

    /// Passphrase for the `encrypted` BLS key backend.
    /// Can also be provided via the BLS_PASSPHRASE environment variable.
    #[arg(long = "bls-passphrase", env = "BLS_PASSPHRASE", value_name = "SECRET")]
    pub bls_passphrase: Option<String>,

    /// Path or `host:port` endpoint for the `outbe-tee-enclave` sidecar.
    /// Every `teeAttestationV1` ChainSpec requires it. The local session is
    /// selected independently from the genesis-fixed attestation policy:
    /// `DcapRequired` always needs NodeHost, while `GramineDirectDev` can use
    /// either the development transport or an explicitly selected production
    /// NodeHost session. Missing or rejected transport stops startup and never
    /// selects an in-process stub or another attestation mode.
    #[arg(long = "tee-enclave-socket", value_name = "PATH")]
    pub tee_enclave_socket: Option<PathBuf>,

    /// Local node-to-enclave authorization protocol. This never changes the
    /// genesis-fixed attestation policy and never provides a fallback. Use
    /// `production-node-host` with a GramineDirectDev chain to run the
    /// production enclave under real SGX with remote attestation disabled.
    #[arg(
        long = "tee-session-mode",
        value_enum,
        default_value_t = TeeSessionMode::PolicyDefault
    )]
    pub tee_session_mode: TeeSessionMode,

    /// Local liveness deadline (seconds) for the one-time TEE DKG + bootstrap on a
    /// fresh chain (block 0). The whole ceremony must finish before block 1; if it
    /// times out (or fails), node startup fails fast and the node halts rather than
    /// proceeding into a permanently un-bootstrapped chain. Local only - not a
    /// consensus rule.
    #[arg(
        long = "tee-bootstrap-timeout-secs",
        value_name = "SECS",
        default_value_t = 60
    )]
    pub tee_bootstrap_timeout_secs: u64,

    /// Interval between TEE-enclave canary probes (known-plaintext decrypt +
    /// health telemetry). `0` disables the canary. Signal only - it never gates
    /// consensus participation.
    #[arg(long = "tee-canary.interval-secs", default_value_t = 30)]
    pub tee_canary_interval_secs: u64,

    /// Consecutive canary failures before `rudis_consensusStatus.enclave`
    /// reports `degraded` (transport-unreachable reports `unavailable`
    /// immediately).
    #[arg(long = "tee-canary.failure-threshold", default_value_t = 3)]
    pub tee_canary_failure_threshold: u64,

    /// Interval, in seconds of canonical block time, between pending-pool
    /// snapshots. A transaction present in two consecutive snapshots has stayed
    /// pending for at least one full interval without being mined and is
    /// evicted, so the effective pending lifetime is one to two intervals.
    /// Node-local pool policy; it never affects block validity. Keep the value
    /// uniform across the fleet so every node sheds a stuck transaction at the
    /// same rate.
    #[arg(long = "txpool.outbe.pending-staleness-secs", default_value_t = 600)]
    pub txpool_pending_staleness_secs: u64,

    /// Heartwood native control socket used for bounded identity, configuration,
    /// and topology reconciliation. Required only in validator mode.
    #[arg(long = "radicle.control-socket", value_name = "PATH")]
    pub radicle_control_socket: Option<PathBuf>,

    /// Loopback-only read-only status endpoint exposed by `outbe-radicle`.
    /// Repository availability is observable through this endpoint but never
    /// gates consensus.
    #[arg(long = "radicle.status-address", value_name = "SOCKET")]
    pub radicle_status_address: Option<SocketAddr>,

    /// Run as a FOLLOWER: cold-sync finalized blocks from this upstream node and
    /// verify them against the committee (anchored on the genesis validator set,
    /// read from the node's own genesis state), instead of running the consensus
    /// engine. The lightweight full-node path. Mutually exclusive with
    /// `--validator`.
    #[arg(long = "upstream", value_name = "URL", conflicts_with = "is_validator")]
    pub upstream: Option<String>,

    /// Dev only: follow without verifying consensus certificates (EL-only sync).
    /// Requires `--upstream`.
    #[arg(
        long = "upstream.nocertify",
        default_value_t = false,
        requires = "upstream"
    )]
    pub upstream_nocertify: bool,

    /// Shared offchain-storage TOML for this node and its snapshot exporter.
    #[arg(long = "projection.storage-config", value_name = "PATH")]
    pub projection_storage_config: Option<PathBuf>,
}

impl fmt::Debug for ConsensusArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsensusArgs")
            .field("is_validator", &self.is_validator)
            .field("listen_address", &self.listen_address)
            .field("trust_el_head", &self.trust_el_head)
            .field(
                "testnet_unix_time_offset_secs",
                &self.testnet_unix_time_offset_secs,
            )
            .field("use_local_defaults", &self.use_local_defaults)
            .field("worker_threads", &self.worker_threads)
            .field("bls_key_backend", &self.bls_key_backend)
            .field("bls_passphrase_configured", &self.bls_passphrase.is_some())
            .field("tee_enclave_configured", &self.tee_enclave_socket.is_some())
            .field("tee_session_mode", &self.tee_session_mode)
            .field(
                "radicle_control_socket_configured",
                &self.radicle_control_socket.is_some(),
            )
            .field(
                "radicle_status_address_configured",
                &self.radicle_status_address.is_some(),
            )
            .field("upstream_configured", &self.upstream.is_some())
            .field(
                "offchain_data_configured",
                &self.projection_storage_config.is_some(),
            )
            .field("projection_storage_config", &self.projection_storage_config)
            .finish_non_exhaustive()
    }
}

impl ConsensusArgs {
    /// Validate argument consistency.
    ///
    /// - `--validator` without `--consensus.signing-key` -> error
    /// - `--consensus.signing-key` without `--validator` -> warning (ignored key)
    /// - `--bls-key-backend encrypted` without `--bls-passphrase` -> error
    pub fn validate(&self) -> eyre::Result<()> {
        self.offchain_data()?;
        if self.txpool_pending_staleness_secs == 0 {
            eyre::bail!("--txpool.outbe.pending-staleness-secs must be greater than zero");
        }
        // Follower mode (`--upstream`) is the lightweight full-node path and must
        // not be combined with validator/consensus participation. (clap's
        // `conflicts_with` also enforces this on the CLI; this covers programmatic
        // construction and gives a clear message.)
        if self.upstream.is_some() && self.is_validator {
            eyre::bail!("--upstream (follower mode) is mutually exclusive with --validator");
        }
        if self.upstream_nocertify && self.upstream.is_none() {
            eyre::bail!("--upstream.nocertify requires --upstream");
        }
        if self.is_validator && self.signing_key.is_none() {
            eyre::bail!(
                "--validator requires --consensus.signing-key. \
                 Provide the path to your BLS signing key file."
            );
        }
        if self.is_validator {
            if self.radicle_control_socket.is_none() {
                eyre::bail!("--validator requires --radicle.control-socket");
            }
            let status = self
                .radicle_status_address
                .ok_or_else(|| eyre::eyre!("--validator requires --radicle.status-address"))?;
            if !status.ip().is_loopback() {
                eyre::bail!("--radicle.status-address must be loopback-only");
            }
        } else if self.radicle_control_socket.is_some() || self.radicle_status_address.is_some() {
            eyre::bail!("Radicle flags require --validator");
        }
        if !self.is_validator && self.signing_key.is_some() {
            tracing::warn!(
                "--consensus.signing-key provided without --validator; \
                 the signing key will be ignored. Add --validator to run as a validator."
            );
        }
        if !self.is_validator && self.validator_evm_key.is_some() {
            tracing::warn!(
                "--validator.evm-key provided without --validator; \
                 the EVM signer key will be ignored. Add --validator to run as a validator."
            );
        }
        // Two valid manual-provisioning shapes:
        //   * signer triplet: all of signing-share + public-polynomial + dkg-output.
        //   * verifier-join pair: public-polynomial + dkg-output WITHOUT signing-share
        //     - a node joining a running chain that has no threshold share yet; it runs
        //     the consensus engine in verifier (follow/verify) mode and acquires a share
        //     at the next DKG reshare. Any other partial combination is an error.
        let (share, poly, output) = (
            self.signing_share.is_some(),
            self.public_polynomial.is_some(),
            self.dkg_output.is_some(),
        );
        let signer_triplet = share && poly && output;
        let verifier_pair = !share && poly && output;
        if (share || poly || output) && !signer_triplet && !verifier_pair {
            eyre::bail!(
                "manual DKG provisioning requires either all of --consensus.signing-share, \
                 --consensus.public-polynomial, --consensus.dkg-output (signer), or \
                 --consensus.public-polynomial + --consensus.dkg-output without \
                 --consensus.signing-share (verifier-join)."
            );
        }
        if self.bls_key_backend == "encrypted" && self.bls_passphrase.is_none() {
            eyre::bail!(
                "--bls-key-backend encrypted requires --bls-passphrase or BLS_PASSPHRASE env var."
            );
        }
        Ok(())
    }

    /// Returns the required configuration path. The node loads the document once at startup.
    pub fn offchain_data(&self) -> eyre::Result<OffchainDataArgs> {
        let path = self.projection_storage_config.as_ref().ok_or_else(|| {
            eyre::eyre!("offchain storage is required; provide --projection.storage-config")
        })?;
        if path.as_os_str().is_empty() {
            eyre::bail!("--projection.storage-config must not be empty");
        }
        Ok(OffchainDataArgs {
            storage_config: path.clone(),
        })
    }

    /// Effective validator EVM-key path.
    ///
    /// Returns `None` for full-node mode. In validator mode, an explicit
    /// `--validator.evm-key` wins; otherwise the default is sibling
    /// `evm-key.hex` next to `--consensus.signing-key`.
    pub fn effective_validator_evm_key(&self) -> eyre::Result<Option<PathBuf>> {
        if !self.is_validator {
            return Ok(None);
        }
        if let Some(path) = &self.validator_evm_key {
            return Ok(Some(path.clone()));
        }
        let Some(signing_key) = &self.signing_key else {
            return Err(eyre::eyre!(
                "--validator requires --consensus.signing-key before deriving default --validator.evm-key"
            ));
        };
        Ok(Some(
            signing_key
                .parent()
                .map(|parent| parent.join("evm-key.hex"))
                .unwrap_or_else(|| PathBuf::from("evm-key.hex")),
        ))
    }

    /// Parse the `--bls-key-backend` argument into a [`KeyBackend`].
    pub fn key_backend(&self) -> eyre::Result<outbe_consensus::bls::KeyBackend> {
        match self.bls_key_backend.as_str() {
            "plaintext" => Ok(outbe_consensus::bls::KeyBackend::Plaintext),
            "encrypted" => {
                let passphrase = self
                    .bls_passphrase
                    .clone()
                    .ok_or_else(|| eyre::eyre!("encrypted backend requires passphrase"))?;
                Ok(outbe_consensus::bls::KeyBackend::Encrypted(passphrase))
            }
            "os-level" => Ok(outbe_consensus::bls::KeyBackend::OsLevel),
            other => Err(eyre::eyre!(
                "unknown BLS key backend: {other} (expected: plaintext, encrypted, os-level)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestConsensusCli {
        #[command(flatten)]
        consensus: ConsensusArgs,
    }

    impl fmt::Debug for TestConsensusCli {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestConsensusCli")
                .finish_non_exhaustive()
        }
    }

    fn default_args() -> ConsensusArgs {
        ConsensusArgs {
            is_validator: false,
            signing_key: None,
            validator_evm_key: None,
            signing_share: None,
            public_polynomial: None,
            dkg_output: None,
            listen_address: "127.0.0.1:30400".parse().unwrap(),
            storage_dir: None,
            keys_dir: None,
            trust_el_head: false,
            testnet_unix_time_offset_secs: None,
            consensus_peers: vec![],
            use_local_defaults: false,
            payload_resolve_time_ms: 200,
            payload_return_time_ms: 450,
            worker_threads: 3,
            bls_key_backend: "plaintext".to_string(),
            bls_passphrase: None,
            tee_enclave_socket: None,
            tee_session_mode: TeeSessionMode::PolicyDefault,
            tee_bootstrap_timeout_secs: 60,
            tee_canary_interval_secs: 30,
            tee_canary_failure_threshold: 3,
            txpool_pending_staleness_secs: 600,
            upstream: None,
            upstream_nocertify: false,
            projection_storage_config: Some("/tmp/offchain-storage.toml".into()),
            radicle_control_socket: None,
            radicle_status_address: None,
        }
    }

    #[test]
    fn test_full_node_without_key_ok() {
        assert!(default_args().validate().is_ok());
    }

    #[test]
    fn local_tee_session_mode_is_independent_from_attestation_policy() {
        use outbe_primitives::tee_attestation_v1::AttestationMode;

        assert_eq!(
            TeeSessionMode::PolicyDefault
                .resolve(AttestationMode::DcapRequired)
                .unwrap(),
            ResolvedTeeSession::ProductionNodeHost
        );
        assert_eq!(
            TeeSessionMode::PolicyDefault
                .resolve(AttestationMode::GramineDirectDev)
                .unwrap(),
            ResolvedTeeSession::Development
        );
        assert_eq!(
            TeeSessionMode::ProductionNodeHost
                .resolve(AttestationMode::GramineDirectDev)
                .unwrap(),
            ResolvedTeeSession::ProductionNodeHost
        );
        assert_eq!(
            TeeSessionMode::Development
                .resolve(AttestationMode::GramineDirectDev)
                .unwrap(),
            ResolvedTeeSession::Development
        );
        assert!(TeeSessionMode::Development
            .resolve(AttestationMode::DcapRequired)
            .is_err());
    }

    #[test]
    fn validator_and_full_node_require_storage_configuration_path() {
        for is_validator in [false, true] {
            let mut args = default_args();
            args.is_validator = is_validator;
            args.projection_storage_config = None;
            assert!(args
                .validate()
                .unwrap_err()
                .to_string()
                .contains("required"));
            args.projection_storage_config = Some("".into());
            assert!(args
                .offchain_data()
                .unwrap_err()
                .to_string()
                .contains("empty"));
            args.projection_storage_config = Some("/node/offchain-storage.toml".into());
            assert_eq!(
                args.offchain_data().unwrap().storage_config,
                std::path::Path::new("/node/offchain-storage.toml")
            );
        }
    }

    #[test]
    fn cli_parses_only_file_based_projection_configuration() {
        let cli = TestConsensusCli::try_parse_from([
            "test",
            "--projection.storage-config",
            "/node/offchain-storage.toml",
        ])
        .unwrap();
        assert_eq!(
            cli.consensus.offchain_data().unwrap().storage_config,
            std::path::Path::new("/node/offchain-storage.toml")
        );
        for (flag, value) in [
            ("--projection.mongodb-uri", "mongodb://mongo:27017"),
            ("--projection.mongodb-database", "projection"),
            ("--projection.start-block", "1"),
        ] {
            assert!(TestConsensusCli::try_parse_from(["test", flag, value]).is_err());
        }
    }

    #[test]
    fn automatic_tee_renewal_options_are_rejected_after_worker_removal() {
        for obsolete in [
            ["--tee-renewal.relay-key", "/tmp/relay-key.hex"],
            ["--tee-renewal.rpc-url", "http://127.0.0.1:8545"],
            ["--tee-renewal.poll-secs", "30"],
            ["--tee-renewal.warning-blocks", "600"],
            ["--tee-renewal.critical-blocks", "120"],
        ] {
            assert!(
                TestConsensusCli::try_parse_from(["test", obsolete[0], obsolete[1]]).is_err(),
                "obsolete automatic-renewal option still parses: {}",
                obsolete[0]
            );
        }
    }

    #[test]
    fn debug_output_redacts_operator_secrets() {
        let mut args = default_args();
        args.bls_passphrase = Some("bls-secret-value".to_owned());
        args.upstream = Some("https://user:upstream-secret@example.test".to_owned());
        args.projection_storage_config = Some("/node/offchain-storage.toml".into());

        let args_debug = format!("{args:?}");
        let config_debug = format!("{:?}", args.offchain_data().unwrap());

        for secret in ["bls-secret-value", "upstream-secret", "mongo-secret"] {
            assert!(!args_debug.contains(secret));
            assert!(!config_debug.contains(secret));
        }
        assert!(args_debug.contains("offchain_data_configured: true"));
        assert!(config_debug.contains("storage_config"));
    }

    #[test]
    fn test_follower_upstream_ok_without_validator() {
        let mut args = default_args();
        args.upstream = Some("http://upstream:8545".to_string());
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_follower_upstream_conflicts_with_validator() {
        let mut args = default_args();
        args.upstream = Some("http://upstream:8545".to_string());
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/key.hex"));
        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "error: {err}");
    }

    #[test]
    fn test_nocertify_requires_upstream() {
        let mut args = default_args();
        args.upstream_nocertify = true;
        let err = args.validate().unwrap_err().to_string();
        assert!(
            err.contains("--upstream.nocertify requires --upstream"),
            "error: {err}"
        );
    }

    #[test]
    fn test_validator_without_signing_key_errors() {
        let mut args = default_args();
        args.is_validator = true;
        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("--consensus.signing-key"), "error: {err}");
    }

    #[test]
    fn test_validator_with_signing_key_ok() {
        let mut args = default_args();
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/key.hex"));
        args.radicle_control_socket = Some(PathBuf::from("/tmp/radicle.sock"));
        args.radicle_status_address = Some("127.0.0.1:8777".parse().unwrap());
        assert!(args.validate().is_ok());
    }

    #[test]
    fn radicle_flags_are_required_for_validators() {
        let mut args = default_args();
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/key.hex"));

        let error = args.validate().unwrap_err().to_string();
        assert!(error.contains("--radicle.control-socket"), "error: {error}");

        args.radicle_control_socket = Some(PathBuf::from("/tmp/radicle.sock"));
        let error = args.validate().unwrap_err().to_string();
        assert!(error.contains("--radicle.status-address"), "error: {error}");
    }

    #[test]
    fn radicle_status_must_be_loopback() {
        let mut args = default_args();
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/key.hex"));
        args.radicle_control_socket = Some(PathBuf::from("/tmp/radicle.sock"));
        args.radicle_status_address = Some("192.0.2.1:8777".parse().unwrap());

        let error = args.validate().unwrap_err().to_string();
        assert!(error.contains("loopback"), "error: {error}");
    }

    #[test]
    fn radicle_flags_are_rejected_outside_validator_mode() {
        let mut args = default_args();
        args.radicle_control_socket = Some(PathBuf::from("/tmp/radicle.sock"));
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("--validator"));

        args.radicle_control_socket = None;
        args.radicle_status_address = Some("127.0.0.1:8777".parse().unwrap());
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("--validator"));

        args.upstream = Some("http://upstream:8545".to_owned());
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("--validator"));
    }

    #[test]
    fn test_manual_dkg_material_requires_complete_triplet() {
        let mut args = default_args();
        args.signing_share = Some(PathBuf::from("/tmp/dkg_share.hex"));
        args.public_polynomial = Some(PathBuf::from("/tmp/dkg_polynomial.hex"));
        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("manual DKG provisioning"), "error: {err}");

        args.dkg_output = Some(PathBuf::from("/tmp/dkg_output.hex"));
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validator_evm_key_default_is_sibling_to_signing_key() {
        let mut args = default_args();
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/validator-1/signing-key.hex"));
        assert_eq!(
            args.effective_validator_evm_key().unwrap(),
            Some(PathBuf::from("/tmp/validator-1/evm-key.hex"))
        );
    }

    #[test]
    fn test_validator_evm_key_explicit_wins() {
        let mut args = default_args();
        args.is_validator = true;
        args.signing_key = Some(PathBuf::from("/tmp/validator-1/signing-key.hex"));
        args.validator_evm_key = Some(PathBuf::from("/secure/evm.hex"));
        assert_eq!(
            args.effective_validator_evm_key().unwrap(),
            Some(PathBuf::from("/secure/evm.hex"))
        );
    }

    #[test]
    fn test_full_node_ignores_validator_evm_key() {
        let mut args = default_args();
        args.validator_evm_key = Some(PathBuf::from("/secure/evm.hex"));
        assert!(args.validate().is_ok());
        assert_eq!(args.effective_validator_evm_key().unwrap(), None);
    }

    #[test]
    fn test_cli_parses_validator_evm_key() {
        let cli = TestConsensusCli::try_parse_from([
            "test",
            "--validator",
            "--consensus.signing-key",
            "/tmp/signing-key.hex",
            "--validator.evm-key",
            "/tmp/evm-key.hex",
        ])
        .unwrap();
        assert_eq!(
            cli.consensus.validator_evm_key,
            Some(PathBuf::from("/tmp/evm-key.hex"))
        );
    }

    #[test]
    fn test_signing_key_without_validator_warns_but_ok() {
        let mut args = default_args();
        args.signing_key = Some(PathBuf::from("/tmp/key.hex"));
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_encrypted_backend_without_passphrase_errors() {
        let mut args = default_args();
        args.bls_key_backend = "encrypted".to_string();
        args.bls_passphrase = None;
        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("passphrase"), "error: {err}");
    }

    #[test]
    fn test_encrypted_backend_with_passphrase_ok() {
        let mut args = default_args();
        args.bls_key_backend = "encrypted".to_string();
        args.bls_passphrase = Some("secret".to_string());
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_key_backend_parsing() {
        let mut args = default_args();

        args.bls_key_backend = "plaintext".to_string();
        assert!(matches!(
            args.key_backend().unwrap(),
            outbe_consensus::bls::KeyBackend::Plaintext
        ));

        args.bls_key_backend = "encrypted".to_string();
        args.bls_passphrase = Some("pass".to_string());
        assert!(matches!(
            args.key_backend().unwrap(),
            outbe_consensus::bls::KeyBackend::Encrypted(_)
        ));

        args.bls_key_backend = "os-level".to_string();
        assert!(matches!(
            args.key_backend().unwrap(),
            outbe_consensus::bls::KeyBackend::OsLevel
        ));

        args.bls_key_backend = "invalid".to_string();
        assert!(args.key_backend().is_err());
    }

    #[test]
    fn test_plaintext_backward_compatibility() {
        // Default is plaintext - existing setups continue working.
        let args = default_args();
        assert_eq!(args.bls_key_backend, "plaintext");
        assert!(matches!(
            args.key_backend().unwrap(),
            outbe_consensus::bls::KeyBackend::Plaintext
        ));
    }

    #[test]
    fn test_p2p_profile_defaults_to_production() {
        let args = default_args();
        assert!(!args.use_local_defaults);
    }

    #[test]
    fn test_removed_fee_recipient_flag_is_rejected() {
        let err = TestConsensusCli::try_parse_from([
            "test",
            "--consensus.fee-recipient",
            "0x0000000000000000000000000000000000000001",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--consensus.fee-recipient"),
            "unexpected clap error: {err}"
        );
    }

    #[test]
    fn test_removed_validators_flag_is_rejected() {
        let err = TestConsensusCli::try_parse_from([
            "test",
            "--consensus.validators",
            "/tmp/validators.json",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--consensus.validators"),
            "unexpected clap error: {err}"
        );
    }

    #[test]
    fn test_removed_execution_watchdog_fatal_flag_is_rejected() {
        let err = TestConsensusCli::try_parse_from([
            "test",
            "--consensus.execution-watchdog-fatal-enabled",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--consensus.execution-watchdog-fatal-enabled"),
            "unexpected clap error: {err}"
        );
    }

    #[test]
    fn test_removed_leader_timeout_flag_is_rejected() {
        // Leader/cert timeouts are genesis-only now; the CLI flags were removed.
        let err =
            TestConsensusCli::try_parse_from(["test", "--consensus.leader-timeout-ms", "30000"])
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("--consensus.leader-timeout-ms"),
            "unexpected clap error: {err}"
        );
    }

    #[test]
    fn test_removed_certification_timeout_flag_is_rejected() {
        let err = TestConsensusCli::try_parse_from([
            "test",
            "--consensus.certification-timeout-ms",
            "30000",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--consensus.certification-timeout-ms"),
            "unexpected clap error: {err}"
        );
    }
}
