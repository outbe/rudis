//! Shared entrypoint for the enclave binaries.
//!
//! Both the production `outbe-tee-enclave` and the dev `outbe-tee-enclave-mock`
//! binaries are thin shims over [`run`]; the only difference is the [`RunOpts`]
//! they pass. Keeping the orchestration here (arg parsing, key init, boot config,
//! listener selection, serve dispatch) guarantees the two binaries share one code
//! path - the node always talks to *an* enclave over the same Noise-IK channel.
//!
//! `run` returns a process exit code instead of calling `std::process::exit`
//! directly, so the shims own the single exit point and the body stays testable.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

use alloy_primitives::B256;
use rand_core::RngCore as _;
use zeroize::Zeroizing;

use crate::initialization::InitializationState;
use crate::keys::EnclaveKeys;
use crate::seal::EnclaveBootConfig;
use crate::transport::{serve, serve_tcp};
use outbe_primitives::tee_attestation_v1::{AttestationMode, NetworkBindingV1};

/// Per-binary behavior knobs. The production binary uses [`RunOpts::prod`]; the
/// dev mock binary has its feature-gated constructor. The private field prevents
/// an external production caller from selecting development behavior.
#[derive(Clone, Copy, Debug)]
pub struct RunOpts {
    /// True for the unattested dev mock binary (stable sealing key and
    /// gramine-direct semantics). Never set in the production binary.
    #[cfg(feature = "mock")]
    mock: bool,
}

impl RunOpts {
    /// Production binary: real Gramine attestation/sealing surface, no mock code.
    pub fn prod() -> Self {
        Self {
            #[cfg(feature = "mock")]
            mock: false,
        }
    }

    /// Dev mock binary (only compiled under `--features mock`).
    #[cfg(feature = "mock")]
    pub fn mock() -> Self {
        Self { mock: true }
    }

    #[cfg(feature = "mock")]
    fn is_mock(self) -> bool {
        self.mock
    }

    #[cfg(not(feature = "mock"))]
    fn is_mock(self) -> bool {
        false
    }
}

/// Run the enclave server. Returns a process exit code (0 = success).
pub fn run(opts: RunOpts) -> i32 {
    crate::telemetry::mark_process_start();
    let args: Vec<String> = std::env::args().collect();

    // Diagnostic mode: read the real Gramine /dev/attestation surface and exit.
    // Run under `gramine-direct`/`gramine-sgx` to observe what hardware exposes.
    if args.iter().any(|a| a == "--probe-attestation") {
        crate::gramine::probe_to_stderr();
        return 0;
    }

    let Some(socket) = arg_value(&args, "--socket") else {
        eprintln!("usage: outbe-tee-enclave --socket <path>");
        return 2;
    };

    #[cfg(feature = "mock")]
    if opts.is_mock() {
        eprintln!(
            "outbe-tee-enclave-mock: MOCK ENCLAVE - deterministic quote + stable sealing key, \
             NOT confidential (dev/CI only, never production)"
        );
    }

    let chain_id = B256::from(
        arg_value(&args, "--chain-id")
            .and_then(|h| parse_hex32(&h))
            .unwrap_or([0u8; 32]),
    );
    let development_network_binding =
        match resolve_development_network_binding(&args, opts.is_mock(), chain_id) {
            Ok(binding) => binding,
            Err(error) => {
                eprintln!("outbe-tee-enclave: development network binding failed: {error}");
                return 2;
            }
        };

    // Detect the real attestation environment up front so the startup banner
    // tells the truth (hardware-attested vs unattested) instead of claiming SGX.
    let attest = crate::gramine::attestation_type();
    if attest.is_hardware() {
        eprintln!(
            "outbe-tee-enclave: MODE = gramine-sgx - hardware attestation ENABLED ({})",
            attest.label()
        );
    } else if attest.sgx_present() {
        // Real SGX, but remote attestation not configured: EGETKEY sealing works
        // (confidential at rest), yet no DCAP quote can be produced. Not "no SGX".
        eprintln!(
            "outbe-tee-enclave: MODE = gramine-sgx - remote attestation DISABLED ({}); \
             EGETKEY sealing available, NOT remote-attested (configure \
             sgx.remote_attestation = \"dcap\" for production)",
            attest.label()
        );
    } else {
        eprintln!(
            "outbe-tee-enclave: MODE = {} - attestation DISABLED, NOT confidential \
             (no SGX hardware; use gramine-sgx for production)",
            attest.label()
        );
    }

    #[cfg(feature = "mock")]
    let tribute_offer_secret = if opts.is_mock() {
        dev_bytes_from_env("TEE_DEV_OFFER_SECRET", [0x07; 32])
    } else {
        [0u8; 32]
    };
    #[cfg(not(feature = "mock"))]
    let tribute_offer_secret = [0u8; 32];
    // Explicit, deterministic DKG identity seed (dev/CI): `--dkg-seed <hex32>` or
    // env `TEE_DEV_DKG_SEED`. The gramine-direct mock path uses this since it has
    // no EGETKEY and so cannot persist a self-generated identity across restart.
    let cli_dkg_seed = arg_value(&args, "--dkg-seed").and_then(|hex| parse_hex32(&hex));
    #[cfg(feature = "mock")]
    let cli_dkg_seed = if opts.is_mock() {
        cli_dkg_seed.or_else(|| {
            std::env::var("TEE_DEV_DKG_SEED")
                .ok()
                .and_then(|h| parse_hex32(&h))
        })
    } else {
        cli_dkg_seed
    };
    // Production accepts only an enclave-generated, successfully sealed seed.
    // Explicit deterministic seeds and the offer-secret fallback are mock-only.
    let identity = match resolve_enclave_identity_seed(&args, cli_dkg_seed, opts.is_mock()) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("outbe-tee-enclave: identity init failed: {error}");
            return 1;
        }
    };
    let identity_id = identity.description;
    let keys = match EnclaveKeys::new_with_identity_seed(
        tribute_offer_secret,
        identity.seed,
        identity.network_binding,
    ) {
        Ok(keys) => keys,
        Err(err) => {
            eprintln!("outbe-tee-enclave: key init failed: {err}");
            return 1;
        }
    };

    // Seal/unseal boot configuration. Production requires it; an explicitly
    // selected development process may omit it and starts as a fresh keyless
    // identity on its separate chain.
    let boot = match build_boot_config(&args, &keys) {
        Ok(boot) => boot,
        Err(code) => return code,
    };

    // Resident chain id from `--chain-id` (default ZERO), bound INDEPENDENTLY of
    // sealing: it scopes every state-key derivation and the owner-authorized
    // fidelity query, which cross-checks it against the node's chain. Sourcing it
    // from `--chain-id` here (not from the seal-only boot config) is what lets a
    // non-sealing enclave still answer chain-scoped queries.
    // Shared, write-once permanent offer-key slot. It is restored only after the
    // sealed initialization manifest has established the exact network binding.
    let offer_key: crate::transport::SharedTributeOfferKey =
        std::sync::Arc::new(std::sync::OnceLock::new());

    #[cfg(feature = "mock")]
    let initialization = if opts.is_mock() {
        InitializationState::development_for_network(
            development_network_binding.expect("mock binding was required above"),
        )
    } else {
        let Some(boot) = boot.clone() else {
            eprintln!(
                "outbe-tee-enclave: production mode requires --tee-dir for write-once node authorization"
            );
            return 2;
        };
        match InitializationState::production(boot, &keys) {
            Ok(state) => state,
            Err(error) => {
                eprintln!("outbe-tee-enclave: initialization state failed: {error}");
                return 1;
            }
        }
    };
    #[cfg(not(feature = "mock"))]
    let initialization = {
        let _ = development_network_binding;
        let Some(boot) = boot.clone() else {
            eprintln!(
                "outbe-tee-enclave: production mode requires --tee-dir for write-once node authorization"
            );
            return 2;
        };
        match InitializationState::production(boot, &keys) {
            Ok(state) => state,
            Err(error) => {
                eprintln!("outbe-tee-enclave: initialization state failed: {error}");
                return 1;
            }
        }
    };
    if let Some(cfg) = boot.as_deref() {
        let network_binding = match initialization.network_binding() {
            Ok(Some(binding)) => Some(binding),
            Ok(None) if cfg.sealed_root_path().exists() => {
                eprintln!(
                    "outbe-tee-enclave: sealed permanent offer key exists without sealed initialization authority"
                );
                return 1;
            }
            Ok(None) => None,
            Err(error) => {
                eprintln!("outbe-tee-enclave: initialization binding unavailable: {error}");
                return 1;
            }
        };
        if let Some(network_binding) = network_binding {
            match crate::transport::unseal_tribute_offer_and_group_sig_on_boot(cfg, network_binding)
            {
                Ok(Some(derived)) => {
                    let _ = offer_key.set(derived);
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("outbe-tee-enclave: {error}");
                    return 1;
                }
            }
        }
    }
    let chain_id = initialization
        .network_binding()
        .ok()
        .flatten()
        .map(|binding| B256::from(binding.chain_id))
        .unwrap_or(chain_id);
    let keys = std::sync::Arc::new(keys);
    let initialization = std::sync::Arc::new(initialization);

    // A `host:port` endpoint listens on TCP (required under Gramine, whose
    // pathname UDS are process-internal so a host process cannot reach them);
    // anything else is a UDS path. The Noise-IK handshake authenticates +
    // encrypts every byte either way, so the carrier choice does not weaken the
    // channel.
    let result = if socket.contains(':') {
        // The TCP carrier is loopback-only. It exists solely because Gramine
        // pathname UDS are process-internal (unreachable from the host); it must
        // never expose the enclave off-host. Reject any non-loopback bind. (Noise-IK
        // still authenticates + encrypts every byte regardless of carrier - this
        // guard is defense-in-depth so a misconfigured `--socket 0.0.0.0:port`
        // cannot accidentally publish the enclave.)
        if !is_loopback_endpoint(&socket) {
            eprintln!(
                "outbe-tee-enclave: refusing to bind non-loopback TCP endpoint {socket} \
                 (the TCP carrier is 127.0.0.1/::1 only)"
            );
            return 2;
        }
        let listener = match std::net::TcpListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("outbe-tee-enclave: bind tcp {socket} failed: {err}");
                return 1;
            }
        };
        eprintln!(
            "outbe-tee-enclave: listening on tcp://{socket} (attestation: {}; enclave identity: {identity_id})",
            attest.label()
        );
        serve_tcp(&listener, keys, boot, offer_key, initialization, chain_id)
    } else {
        // Fresh socket; UDS mode 0600 (owner-only), per plan section "Transport".
        let _ = std::fs::remove_file(&socket);
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("outbe-tee-enclave: bind {socket} failed: {err}");
                return 1;
            }
        };
        // Best-effort 0600 (non-fatal under Gramine - the bound UDS is an
        // emulated socket object, not a chmod-able host file).
        if let Err(err) = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!("outbe-tee-enclave: chmod 0600 {socket} failed (continuing): {err}");
        }
        eprintln!(
            "outbe-tee-enclave: listening on {socket} (attestation: {}; enclave identity: {identity_id})",
            attest.label()
        );
        serve(&listener, keys, boot, offer_key, initialization, chain_id)
    };
    if let Err(err) = result {
        eprintln!("outbe-tee-enclave: serve error: {err}");
        return 1;
    }
    0
}

fn resolve_development_network_binding(
    args: &[String],
    mock: bool,
    chain_id: B256,
) -> Result<Option<NetworkBindingV1>, String> {
    let encoded = arg_value(args, "--dev-network-binding");
    if !mock {
        return encoded
            .is_none()
            .then_some(None)
            .ok_or_else(|| "--dev-network-binding is accepted only by the mock binary".to_owned());
    }
    let encoded = encoded.ok_or_else(|| {
        "mock binary requires --dev-network-binding <canonical NetworkBindingV1 hex>".to_owned()
    })?;
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))
        .map_err(|error| format!("decode --dev-network-binding hex: {error}"))?;
    let binding = NetworkBindingV1::decode_canonical(&bytes)
        .map_err(|error| format!("decode canonical NetworkBindingV1: {error}"))?;
    if binding.attestation_mode != AttestationMode::GramineDirectDev {
        return Err("development network binding must use GramineDirectDev mode".to_owned());
    }
    if B256::from(binding.chain_id) != chain_id {
        return Err("development network binding chain id does not match --chain-id".to_owned());
    }
    Ok(Some(binding))
}

/// Resolve the one seed backing every persistent enclave identity key.
///
/// Development may use an explicit deterministic seed or its fixed test seed.
/// Production restores an existing valid sealed seed or creates one in enclave
/// memory on first boot. Initialization durably seals it with the ChainSpec
/// network binding before publishing NodeHost authority. Existing unreadable
/// state is never overwritten. If node authorization exists but the identity is
/// missing, startup fails: there is no recovery or implicit identity rotation.
struct EnclaveIdentitySeedResolution {
    seed: Option<Zeroizing<[u8; 32]>>,
    network_binding: Option<outbe_primitives::tee_attestation_v1::NetworkBindingV1>,
    description: &'static str,
}

impl std::fmt::Debug for EnclaveIdentitySeedResolution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnclaveIdentitySeedResolution")
            .field("network_binding", &self.network_binding)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

fn resolve_enclave_identity_seed(
    args: &[String],
    cli_seed: Option<[u8; 32]>,
    development: bool,
) -> Result<EnclaveIdentitySeedResolution, String> {
    #[cfg(feature = "mock")]
    if development {
        return Ok(EnclaveIdentitySeedResolution {
            seed: cli_seed.map(Zeroizing::new),
            network_binding: None,
            description: if cli_seed.is_some() {
                "explicit development seed"
            } else {
                "development test seed"
            },
        });
    }
    #[cfg(not(feature = "mock"))]
    let _ = development;
    if cli_seed.is_some() {
        return Err("--dkg-seed and TEE_DEV_DKG_SEED are development-only".to_string());
    }

    let tee_dir = arg_value(args, "--tee-dir")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "production requires --tee-dir for sealed identity".to_string())?;
    let (sealing_key, key_policy) = crate::transport::sealing_key()
        .ok_or_else(|| "production identity requires an SGX sealing key".to_string())?;

    // Running SGX SVN for the anti-rollback floor, read from the local report.
    let isv_svn = crate::gramine::local_report_measurements(&[0u8; 64])
        .map(|m| m.isv_svn)
        .unwrap_or(0);
    std::fs::create_dir_all(&tee_dir)
        .map_err(|error| format!("create identity directory {}: {error}", tee_dir.display()))?;
    std::fs::set_permissions(&tee_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("chmod identity directory {}: {error}", tee_dir.display()))?;
    let path = tee_dir.join("sealed_identity.bin");

    match std::fs::read(&path) {
        Ok(blob) => {
            let unsealed = crate::seal::unseal_network_bound_payload(&blob, &sealing_key, isv_svn)
                .map_err(|error| {
                    format!(
                        "sealed identity at {} is unusable and will not be replaced: {error}",
                        path.display()
                    )
                })?;
            if !unsealed.group_sig.is_empty() {
                return Err(format!(
                    "sealed identity at {} contains unexpected group-signature bytes",
                    path.display()
                ));
            }
            return Ok(EnclaveIdentitySeedResolution {
                seed: Some(unsealed.tribute_offer_secret),
                network_binding: Some(unsealed.network_binding),
                description: "self-generated (restored from network-bound seal)",
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("read sealed identity {}: {error}", path.display()));
        }
    }

    let authorization_path = tee_dir.join("sealed_node_authorization_v1.bin");
    match std::fs::symlink_metadata(&authorization_path) {
        Ok(_) => {
            return Err(format!(
                "sealed identity is missing while node authorization exists at {}; old identity cannot be recovered",
                authorization_path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect sealed node authorization {}: {error}",
                authorization_path.display()
            ));
        }
    }

    // First boot only: generate in enclave memory. Initialization seals the seed
    // with the signed NetworkBinding before it persists NodeHost authorization.
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(&mut *seed);
    let _ = (sealing_key, key_policy, isv_svn);
    Ok(EnclaveIdentitySeedResolution {
        seed: Some(seed),
        network_binding: None,
        description: "self-generated (fresh, pending network-bound seal)",
    })
}

/// Build the optional seal/unseal boot configuration from CLI args.
///
/// Returns `Ok(Some)` only when `--tee-dir <path>` is supplied; the directory is
/// created (best-effort 0700) and `--chain-id <hex32>` binds the sealing AAD.
/// Absent `--tee-dir` is permitted only for the explicitly selected development
/// process and returns `Ok(None)` with no durable permanent key. Production
/// rejects that configuration before serving. `Err(code)` propagates a fatal
/// setup failure; `isv_svn` is the anti-rollback floor for unseal.
fn build_boot_config(
    args: &[String],
    keys: &EnclaveKeys,
) -> Result<Option<std::sync::Arc<EnclaveBootConfig>>, i32> {
    let Some(tee_dir) = arg_value(args, "--tee-dir").map(std::path::PathBuf::from) else {
        return Ok(None);
    };
    if let Err(err) = std::fs::create_dir_all(&tee_dir) {
        eprintln!(
            "outbe-tee-enclave: create --tee-dir {} failed: {err}",
            tee_dir.display()
        );
        return Err(1);
    }
    // Owner-only (0700); best-effort under Gramine (emulated FS is not chmod-able).
    if let Err(err) = std::fs::set_permissions(&tee_dir, std::fs::Permissions::from_mode(0o700)) {
        eprintln!(
            "outbe-tee-enclave: chmod 0700 {} failed (continuing): {err}",
            tee_dir.display()
        );
    }
    let chain_id = arg_value(args, "--chain-id")
        .and_then(|h| parse_hex32(&h))
        .unwrap_or_else(|| {
            eprintln!(
                "outbe-tee-enclave: --tee-dir set without a valid --chain-id; \
                 sealing AAD uses ZERO chain_id"
            );
            [0u8; 32]
        });
    let cfg = EnclaveBootConfig::new(chain_id, tee_dir, keys.isv_svn());
    eprintln!(
        "outbe-tee-enclave: sealing enabled (tee_dir={}, isv_svn={})",
        cfg.tee_dir.display(),
        cfg.isv_svn,
    );
    Ok(Some(std::sync::Arc::new(cfg)))
}

/// Return the value following `flag` in `args`, if present.
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Read a 32-byte hex value from `var` (optional `0x`); fall back to `default`
/// on absence or malformed input.
#[cfg(feature = "mock")]
fn dev_bytes_from_env(var: &str, default: [u8; 32]) -> [u8; 32] {
    std::env::var(var)
        .ok()
        .and_then(|value| parse_hex32(&value))
        .unwrap_or(default)
}

/// Parse a 32-byte hex string (optional `0x`); `None` on malformed input.
fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    match hex::decode(trimmed) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        }
        _ => None,
    }
}

/// True iff `endpoint` is an `ip:port` whose IP is loopback (`127.0.0.0/8` or
/// `::1`). A non-IP host (e.g. `example.com:7000`) does not parse as a
/// `SocketAddr` and is rejected - the TCP carrier must never bind a routable
/// address.
fn is_loopback_endpoint(endpoint: &str) -> bool {
    endpoint
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, U256};
    use outbe_primitives::tee_attestation_v1::{AttestationMode, NetworkBindingV1};

    use super::{
        is_loopback_endpoint, resolve_development_network_binding, resolve_enclave_identity_seed,
    };

    fn development_binding(mode: AttestationMode) -> NetworkBindingV1 {
        NetworkBindingV1 {
            chain_id: U256::from(424_242u64).to_be_bytes(),
            genesis_hash: B256::repeat_byte(0x5b),
            attestation_mode: mode,
        }
    }

    fn development_args(binding: NetworkBindingV1) -> Vec<String> {
        vec![
            "outbe-tee-enclave-mock".to_owned(),
            "--dev-network-binding".to_owned(),
            hex::encode(binding.encode_canonical().unwrap()),
        ]
    }

    #[test]
    fn mock_network_binding_is_required_and_must_be_canonical() {
        let chain_id = B256::from(development_binding(AttestationMode::GramineDirectDev).chain_id);
        let missing = resolve_development_network_binding(&[], true, chain_id).unwrap_err();
        assert!(missing.contains("requires --dev-network-binding"));

        let malformed = resolve_development_network_binding(
            &[
                "outbe-tee-enclave-mock".to_owned(),
                "--dev-network-binding".to_owned(),
                "not-hex".to_owned(),
            ],
            true,
            chain_id,
        )
        .unwrap_err();
        assert!(malformed.contains("decode --dev-network-binding hex"));
    }

    #[test]
    fn mock_network_binding_rejects_production_mode_and_another_chain() {
        let direct = development_binding(AttestationMode::GramineDirectDev);
        let production = development_binding(AttestationMode::DcapRequired);
        let mode_error = resolve_development_network_binding(
            &development_args(production),
            true,
            B256::from(production.chain_id),
        )
        .unwrap_err();
        assert!(mode_error.contains("GramineDirectDev"));

        let chain_error = resolve_development_network_binding(
            &development_args(direct),
            true,
            B256::repeat_byte(0x77),
        )
        .unwrap_err();
        assert!(chain_error.contains("does not match --chain-id"));
    }

    #[test]
    fn mock_network_binding_accepts_the_matching_development_binding() {
        let binding = development_binding(AttestationMode::GramineDirectDev);
        assert_eq!(
            resolve_development_network_binding(
                &development_args(binding),
                true,
                B256::from(binding.chain_id),
            )
            .unwrap(),
            Some(binding)
        );
    }

    #[test]
    fn production_binary_rejects_the_development_only_flag() {
        let binding = development_binding(AttestationMode::GramineDirectDev);
        let error = resolve_development_network_binding(
            &development_args(binding),
            false,
            B256::from(binding.chain_id),
        )
        .unwrap_err();
        assert!(error.contains("accepted only by the mock binary"));
    }

    fn production_args(root: &std::path::Path) -> Vec<String> {
        vec![
            "outbe-tee-enclave".to_string(),
            "--tee-dir".to_string(),
            root.display().to_string(),
            "--chain-id".to_string(),
            hex::encode([0x41; 32]),
        ]
    }

    #[test]
    fn loopback_endpoint_accepts_only_loopback_ips() {
        assert!(is_loopback_endpoint("127.0.0.1:7000"));
        assert!(is_loopback_endpoint("127.0.0.5:7000"));
        assert!(is_loopback_endpoint("[::1]:7000"));
        // Non-loopback / routable -> reject.
        assert!(!is_loopback_endpoint("0.0.0.0:7000"));
        assert!(!is_loopback_endpoint("10.0.0.5:7000"));
        assert!(!is_loopback_endpoint("192.168.1.2:7000"));
        // Non-IP host -> reject (cannot prove loopback).
        assert!(!is_loopback_endpoint("example.com:7000"));
        assert!(!is_loopback_endpoint("localhost:7000"));
    }

    #[test]
    fn production_identity_rejects_development_seed() {
        let root = tempfile::tempdir().unwrap();
        let error =
            resolve_enclave_identity_seed(&production_args(root.path()), Some([0x77; 32]), false)
                .unwrap_err();
        assert!(error.contains("development-only"));
        assert!(!root.path().join("sealed_identity.bin").exists());
    }

    #[test]
    fn first_production_identity_is_owner_only_and_restores_exactly() {
        let root = tempfile::tempdir().unwrap();
        let args = production_args(root.path());
        let first = resolve_enclave_identity_seed(&args, None, false).unwrap();
        let path = root.path().join("sealed_identity.bin");
        assert!(!path.exists());
        assert!(first.seed.is_some());
        assert!(first.network_binding.is_none());
    }

    #[test]
    fn corrupt_production_identity_is_not_replaced() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sealed_identity.bin");
        let corrupt = b"corrupt-sealed-identity";
        std::fs::write(&path, corrupt).unwrap();
        let error =
            resolve_enclave_identity_seed(&production_args(root.path()), None, false).unwrap_err();
        assert!(error.contains("will not be replaced"));
        assert_eq!(std::fs::read(path).unwrap(), corrupt);
    }

    #[test]
    fn missing_identity_with_existing_authorization_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let authorization = root.path().join("sealed_node_authorization_v1.bin");
        std::fs::write(&authorization, b"existing-authorization").unwrap();
        let error =
            resolve_enclave_identity_seed(&production_args(root.path()), None, false).unwrap_err();
        assert!(error.contains("old identity cannot be recovered"));
        assert!(!root.path().join("sealed_identity.bin").exists());
        assert_eq!(
            std::fs::read(authorization).unwrap(),
            b"existing-authorization"
        );
    }
}
