//! Local Radicle client setup for an Outbe network.
//!
//! A stock `rad auth` writes a config that points at the public Radicle seeds
//! and seeds every repository it is offered. Neither is right for an Outbe
//! network: the peers are this chain's validators, and the repositories worth
//! holding are the ones registered in the `RadicleRegistry` precompile.
//!
//! `rad init` rewrites the network-facing part of that config from chain
//! state - validator set, Radicle NodeId bindings and P2P hosts are all read
//! over RPC, never hard-coded - and leaves the identity keys untouched.

use std::{
    fs,
    net::SocketAddr,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{bail, eyre, Result, WrapErr};
use outbe_primitives::consensus_p2p::{decode_versioned, P2pAddress, P2pIngress};
use serde_json::{json, Map, Value};

use crate::{
    abi::{self, IValidatorSet},
    rpc::Rpc,
};

/// Heartwood's replication port. Validators run the sidecar on this port; the
/// chain records their consensus P2P endpoint, not the Radicle one, so the host
/// comes from chain state and the port from here.
const DEFAULT_RADICLE_PORT: u16 = 8776;

/// Where `rad start` binds by default. Loopback: a client node has no reason to
/// accept inbound connections.
const DEFAULT_LISTEN: &str = "127.0.0.1:8790";

#[derive(Subcommand)]
pub enum RadCmd {
    /// Rewrite the Radicle config to talk to this chain's validators only.
    Init {
        /// Radicle home. Defaults to `$RAD_HOME`, then `~/.radicle`.
        #[arg(long)]
        home: Option<PathBuf>,
        /// Replication port the validators' sidecars listen on.
        #[arg(long, default_value_t = DEFAULT_RADICLE_PORT)]
        radicle_port: u16,
        /// Node alias recorded in the config.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Start `radicle-node` against the configured home.
    Start {
        #[arg(long)]
        home: Option<PathBuf>,
        /// Address to listen on.
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: String,
        /// `radicle-node` binary to run.
        #[arg(long, default_value = "radicle-node")]
        binary: String,
    },
    /// Stop the node started by `rad start`.
    Stop {
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Stop then start the node.
    Restart {
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: String,
        #[arg(long, default_value = "radicle-node")]
        binary: String,
    },
    /// Show the local node state and how it compares to chain state.
    Status {
        #[arg(long)]
        home: Option<PathBuf>,
    },
}

impl RadCmd {
    pub async fn run(self, client: &(impl Rpc + Sync)) -> Result<()> {
        match self {
            Self::Init {
                home,
                radicle_port,
                alias,
            } => init(client, resolve_home(home)?, radicle_port, alias).await,
            Self::Start {
                home,
                listen,
                binary,
            } => start(&resolve_home(home)?, &listen, &binary),
            Self::Stop { home } => stop(&resolve_home(home)?),
            Self::Restart {
                home,
                listen,
                binary,
            } => {
                let home = resolve_home(home)?;
                // A stop on a node that is not running is not an error here:
                // restart's contract is "running afterwards", not "was running".
                let _ = stop(&home);
                wait_for_exit(&home);
                start(&home, &listen, &binary)
            }
            Self::Status { home } => status(client, &resolve_home(home)?).await,
        }
    }
}

/// One validator's Radicle peer, as recorded on chain.
#[derive(Debug, PartialEq, Eq)]
struct Peer {
    validator: Address,
    node_id: String,
    host: String,
    port: u16,
}

impl Peer {
    fn address(&self) -> String {
        format!("{}@{}:{}", self.node_id, self.host, self.port)
    }
}

fn resolve_home(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(home) = explicit {
        return Ok(home);
    }
    if let Ok(home) = std::env::var("RAD_HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    let base = std::env::var("HOME").wrap_err("neither --home, RAD_HOME nor HOME is set")?;
    Ok(PathBuf::from(base).join(".radicle"))
}

fn config_path(home: &Path) -> PathBuf {
    home.join("config.json")
}

fn pid_path(home: &Path) -> PathBuf {
    home.join("node").join("outbe-rad.pid")
}

fn log_path(home: &Path) -> PathBuf {
    home.join("node").join("outbe-rad.log")
}

async fn init(
    client: &(impl Rpc + Sync),
    home: PathBuf,
    radicle_port: u16,
    alias: Option<String>,
) -> Result<()> {
    if !home.join("keys").join("radicle.pub").is_file() {
        bail!(
            "no Radicle identity in {}: run `rad auth` first - it creates the keys, \
             this command only rewrites the network settings",
            home.display()
        );
    }

    let peers = read_peers(client, radicle_port).await?;
    if peers.is_empty() {
        bail!("the chain reports no validators with a Radicle NodeId binding");
    }

    let path = config_path(&home);
    let mut config = read_config(&path)?;
    let node = config
        .entry("node".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(node) = node.as_object_mut() else {
        bail!("`node` in {} is not an object", path.display());
    };

    node.insert(
        "connect".to_string(),
        Value::Array(
            peers
                .iter()
                .map(|peer| Value::String(peer.address()))
                .collect(),
        ),
    );
    // Static peers: talk to exactly this list, no dynamic discovery.
    node.insert("peers".to_string(), json!({ "type": "static" }));
    // Block by default; repositories are added explicitly with `rad seed`.
    // Without this the node accepts every announcement it hears.
    node.insert("seedingPolicy".to_string(), json!({ "default": "block" }));
    // A client is not a relay. The validators' sidecars run `relay: always`
    // because they are reachable seeds with external addresses; setting it on a
    // loopback client stops sessions from establishing at all.
    node.insert("relay".to_string(), Value::String("auto".to_string()));
    if let Some(alias) = alias {
        node.insert("alias".to_string(), Value::String(alias));
    }
    // The single reason a freshly authed node reaches the public network: these
    // are seeded into the default config and are not part of `node`.
    config.insert("preferredSeeds".to_string(), Value::Array(Vec::new()));

    write_config(&path, &config)?;

    println!("Radicle home:  {}", home.display());
    println!("Config:        {}", path.display());
    println!("Peers ({}):", peers.len());
    for peer in &peers {
        println!("  {}  {}", peer.validator, peer.address());
    }
    println!();
    println!("preferredSeeds cleared, peers set to static, seeding policy set to block.");
    println!("Start the node with `outbe-cli rad start`.");
    Ok(())
}

/// Reads every validator's Radicle peer address from chain state.
///
/// The chain binds a NodeId per validator but records only the consensus P2P
/// endpoint, so the host is taken from there and paired with `radicle_port`.
/// Validators without a binding or without a P2P address are skipped: they are
/// not reachable as Radicle peers, and a partial list is more useful than none.
async fn read_peers(client: &(impl Rpc + Sync), radicle_port: u16) -> Result<Vec<Peer>> {
    let output = client
        .eth_call(
            abi::VALIDATOR_SET_ADDR,
            &IValidatorSet::getValidatorsCall {}.abi_encode(),
        )
        .await
        .wrap_err("getValidators eth_call failed")?;
    let validators = IValidatorSet::getValidatorsCall::abi_decode_returns(&output)
        .wrap_err("decode validator set")?;

    let mut peers = Vec::with_capacity(validators.len());
    for validator in validators {
        let output = client
            .eth_call(
                abi::VALIDATOR_SET_ADDR,
                &IValidatorSet::getRadicleNodeIdCall { validator }.abi_encode(),
            )
            .await
            .wrap_err_with(|| format!("getRadicleNodeId({validator}) eth_call failed"))?;
        let node_id = IValidatorSet::getRadicleNodeIdCall::abi_decode_returns(&output)
            .wrap_err("decode Radicle NodeId")?;
        if node_id.is_zero() {
            continue;
        }

        let output = client
            .eth_call(
                abi::VALIDATOR_SET_ADDR,
                &IValidatorSet::getP2pAddressCall {
                    validatorAddress: validator,
                }
                .abi_encode(),
            )
            .await
            .wrap_err_with(|| format!("getP2pAddress({validator}) eth_call failed"))?;
        let p2p = IValidatorSet::getP2pAddressCall::abi_decode_returns(&output)
            .wrap_err("decode P2P address")?;
        if p2p.version == 0 && p2p.encoded.is_empty() {
            continue;
        }
        let decoded = decode_versioned(p2p.version, &p2p.encoded).map_err(|error| {
            eyre!("validator {validator} has an undecodable P2P address: {error}")
        })?;

        peers.push(Peer {
            validator,
            node_id: encode_node_id(node_id.as_slice())?,
            host: host_of(&decoded),
            port: radicle_port,
        });
    }
    Ok(peers)
}

/// The reachable host of a consensus P2P address. Asymmetric addresses are
/// dialled at their ingress, which is the side that accepts connections.
fn host_of(address: &P2pAddress) -> String {
    match address {
        P2pAddress::Symmetric(socket) => socket.ip().to_string(),
        P2pAddress::Asymmetric { ingress, .. } => match ingress {
            P2pIngress::Socket(socket) => socket.ip().to_string(),
            P2pIngress::Dns { host, .. } => host.clone(),
        },
    }
}

/// Renders a 32-byte Ed25519 public key as Heartwood addresses it: the
/// multicodec `ed25519-pub` prefix, base58btc, under multibase prefix `z`.
fn encode_node_id(raw: &[u8]) -> Result<String> {
    if raw.len() != 32 {
        bail!("Radicle NodeId must be 32 bytes, got {}", raw.len());
    }
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(&[0xed, 0x01]);
    payload.extend_from_slice(raw);
    Ok(format!("z{}", base58_encode(&payload)))
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(input: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = usize::from(byte);
        for digit in digits.iter_mut() {
            carry += usize::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = input.iter().take_while(|&&byte| byte == 0).count();
    let mut out = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for &digit in digits.iter().rev() {
        out.push(char::from(BASE58[usize::from(digit)]));
    }
    out
}

fn read_config(path: &Path) -> Result<Map<String, Value>> {
    if !path.is_file() {
        return Ok(Map::new());
    }
    let raw =
        fs::read_to_string(path).wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .wrap_err_with(|| format!("{} is not valid JSON", path.display()))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => {
            bail!("{} must contain a JSON object", path.display());
        }
    }
}

fn write_config(path: &Path, config: &Map<String, Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let mut rendered = serde_json::to_string_pretty(config).wrap_err("failed to render config")?;
    rendered.push('\n');
    fs::write(path, rendered).wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn start(home: &Path, listen: &str, binary: &str) -> Result<()> {
    listen
        .parse::<SocketAddr>()
        .wrap_err_with(|| format!("`--listen {listen}` is not a socket address"))?;
    let path = config_path(home);
    if !path.is_file() {
        bail!(
            "no config at {}: run `outbe-cli rad init` first",
            path.display()
        );
    }
    if let Some(pid) = running_pid(home) {
        println!("Already running (pid {pid}).");
        return Ok(());
    }

    // Unix domain socket paths are capped near 104 bytes and Heartwood puts its
    // control socket inside the home, so a deep home fails at bind time with an
    // opaque error. Say so here instead.
    let socket = home.join("node").join("control.sock");
    if socket.as_os_str().len() > 100 {
        bail!(
            "Radicle home is too deep: the control socket path {} would exceed the \
             Unix socket limit - use a shorter --home",
            socket.display()
        );
    }

    let node_dir = home.join("node");
    fs::create_dir_all(&node_dir)
        .wrap_err_with(|| format!("failed to create {}", node_dir.display()))?;
    let log = fs::File::create(log_path(home))
        .wrap_err_with(|| format!("failed to create {}", log_path(home).display()))?;
    let errors = log
        .try_clone()
        .wrap_err("failed to duplicate the log handle")?;

    let child = Command::new(binary)
        .arg("--listen")
        .arg(listen)
        .env("RAD_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errors))
        // Own process group: without it the node stays in this shell's group and
        // dies with it - a Ctrl-C, a closed SSH session or a timeout signalling
        // the group would take the node down with the command that started it.
        .process_group(0)
        .spawn()
        .wrap_err_with(|| format!("failed to start `{binary}` - is it on PATH?"))?;

    fs::write(pid_path(home), child.id().to_string())
        .wrap_err_with(|| format!("failed to write {}", pid_path(home).display()))?;

    println!("Started {binary} (pid {}) on {listen}.", child.id());
    println!("Home: {}", home.display());
    println!("Log:  {}", log_path(home).display());
    Ok(())
}

fn stop(home: &Path) -> Result<()> {
    let Some(pid) = running_pid(home) else {
        println!("Not running.");
        let _ = fs::remove_file(pid_path(home));
        return Ok(());
    };
    let status = Command::new("kill")
        .arg(pid.to_string())
        .status()
        .wrap_err("failed to run `kill`")?;
    if !status.success() {
        bail!("failed to stop pid {pid}");
    }
    let _ = fs::remove_file(pid_path(home));
    println!("Stopped pid {pid}.");
    Ok(())
}

/// Polls until the stopped process is gone, so a restart does not race the old
/// node for the control socket. Bounded: a node that ignores SIGTERM should not
/// hang the command.
fn wait_for_exit(home: &Path) {
    for _ in 0..50 {
        if running_pid(home).is_none() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The pid recorded by `rad start`, if that process is still alive.
fn running_pid(home: &Path) -> Option<u32> {
    let raw = fs::read_to_string(pid_path(home)).ok()?;
    let pid: u32 = raw.trim().parse().ok()?;
    let alive = Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?
        .success();
    alive.then_some(pid)
}

async fn status(client: &(impl Rpc + Sync), home: &Path) -> Result<()> {
    println!("Home:    {}", home.display());
    match running_pid(home) {
        Some(pid) => println!("Node:    running (pid {pid})"),
        None => println!("Node:    stopped"),
    }

    let path = config_path(home);
    if !path.is_file() {
        println!("Config:  absent - run `outbe-cli rad init`");
        return Ok(());
    }
    let config = read_config(&path)?;
    let configured = config
        .get("node")
        .and_then(|node| node.get("connect"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let seeds = config
        .get("preferredSeeds")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let policy = config
        .get("node")
        .and_then(|node| node.get("seedingPolicy"))
        .and_then(|policy| policy.get("default"))
        .and_then(Value::as_str)
        .unwrap_or("unset");
    println!("Config:  {}", path.display());
    println!("  preferredSeeds: {seeds} (want 0)");
    println!("  seedingPolicy:  {policy} (want block)");

    // The chain is the source of truth: report drift rather than the config's
    // own account of itself.
    let expected = read_peers(client, DEFAULT_RADICLE_PORT).await?;
    println!("Peers:");
    for peer in &expected {
        let want = peer.address();
        let present = configured.iter().any(|entry| entry == &want);
        println!("  {} {}", if present { "ok     " } else { "MISSING" }, want);
    }
    for entry in &configured {
        if !expected.iter().any(|peer| &peer.address() == entry) {
            println!("  EXTRA   {entry}");
        }
    }
    if seeds != 0
        || policy != "block"
        || expected.iter().any(|p| !configured.contains(&p.address()))
    {
        println!();
        println!("Run `outbe-cli rad init` to bring the config back in line.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;
    use std::net::{IpAddr, Ipv4Addr};

    /// The NodeId of testnet validator-0, as reported by `rudis_radicleStatus`
    /// and rendered by `rad node status`.
    #[test]
    fn encodes_a_node_id_the_way_heartwood_does() {
        let raw = hex::decode("5dd9f53e725b3a569c03586b63666e01090f42ac6303002bddebdf90b1965989")
            .unwrap();
        assert_eq!(
            encode_node_id(&raw).unwrap(),
            "z6MkkmciyXgcgygztXke2stXVDeMo8ybiduckp5QbLnSNDKE"
        );
    }

    #[test]
    fn rejects_a_node_id_of_the_wrong_width() {
        assert!(encode_node_id(&[0u8; 31]).is_err());
        assert!(encode_node_id(&[0u8; 33]).is_err());
    }

    #[test]
    fn base58_keeps_leading_zeros_as_ones() {
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
        assert_eq!(base58_encode(&[]), "");
    }

    #[test]
    fn takes_the_ingress_host_of_an_asymmetric_address() {
        let ingress = P2pIngress::Socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            30400,
        ));
        let egress = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30400);
        let address = P2pAddress::Asymmetric { ingress, egress };
        assert_eq!(host_of(&address), "10.0.0.1");

        let dns = P2pAddress::Asymmetric {
            ingress: P2pIngress::Dns {
                host: "n1.testnet.outbe.net".to_string(),
                port: 30400,
            },
            egress,
        };
        assert_eq!(host_of(&dns), "n1.testnet.outbe.net");

        let symmetric = P2pAddress::Symmetric(egress);
        assert_eq!(host_of(&symmetric), "10.0.0.2");
    }

    #[test]
    fn peer_renders_a_heartwood_dial_address() {
        let peer = Peer {
            validator: Address::repeat_byte(0x11),
            node_id: "z6Mktest".to_string(),
            host: "10.0.0.1".to_string(),
            port: 8776,
        };
        assert_eq!(peer.address(), "z6Mktest@10.0.0.1:8776");
    }

    #[test]
    fn init_rewrites_only_the_network_settings() {
        let home = tempfile::tempdir().unwrap();
        let path = config_path(home.path());
        fs::write(
            &path,
            r#"{"preferredSeeds":["z6Mkpublic@seed.radicle.at:8776"],
                "publicExplorer":"https://radicle.network/$rid",
                "node":{"alias":"mine","listen":["0.0.0.0:8776"],
                        "peers":{"type":"dynamic"},
                        "seedingPolicy":{"default":"allow","scope":"all"}}}"#,
        )
        .unwrap();

        let mut config = read_config(&path).unwrap();
        let node = config.get_mut("node").unwrap().as_object_mut().unwrap();
        node.insert("connect".to_string(), json!(["z6Mka@10.0.0.1:8776"]));
        node.insert("peers".to_string(), json!({ "type": "static" }));
        node.insert("seedingPolicy".to_string(), json!({ "default": "block" }));
        config.insert("preferredSeeds".to_string(), json!([]));
        write_config(&path, &config).unwrap();

        let written = read_config(&path).unwrap();
        let node = written.get("node").unwrap();
        // Rewritten.
        assert_eq!(written.get("preferredSeeds").unwrap(), &json!([]));
        assert_eq!(node.get("peers").unwrap(), &json!({ "type": "static" }));
        assert_eq!(
            node.get("seedingPolicy").unwrap(),
            &json!({ "default": "block" })
        );
        // Preserved: identity and unrelated settings are not ours to touch.
        assert_eq!(node.get("alias").unwrap(), "mine");
        assert_eq!(node.get("listen").unwrap(), &json!(["0.0.0.0:8776"]));
        assert!(written.contains_key("publicExplorer"));
    }

    #[test]
    fn init_refuses_a_home_without_an_identity() {
        let home = tempfile::tempdir().unwrap();
        assert!(!home.path().join("keys").join("radicle.pub").is_file());
    }

    #[test]
    fn resolves_home_from_the_explicit_flag_first() {
        let explicit = PathBuf::from("/tmp/explicit-home");
        assert_eq!(resolve_home(Some(explicit.clone())).unwrap(), explicit);
    }

    #[test]
    fn reports_no_pid_when_nothing_was_started() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(running_pid(home.path()), None);
    }

    #[test]
    fn parses_every_subcommand() {
        for args in [
            vec!["outbe-cli", "rad", "init"],
            vec!["outbe-cli", "rad", "init", "--radicle-port", "9000"],
            vec!["outbe-cli", "rad", "start"],
            vec!["outbe-cli", "rad", "start", "--listen", "127.0.0.1:9999"],
            vec!["outbe-cli", "rad", "stop"],
            vec!["outbe-cli", "rad", "restart"],
            vec!["outbe-cli", "rad", "status"],
        ] {
            assert!(
                Cli::try_parse_from(&args).is_ok(),
                "failed to parse {args:?}"
            );
        }
    }
}
