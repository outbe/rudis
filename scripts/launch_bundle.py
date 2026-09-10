"""Render the per-machine launch bundle that goes with a generated genesis.

`create_genesis.py` calls this once the genesis is written. For each founding
validator it emits one directory of runnable scripts - storage setup, TEE enclave,
Radicle sidecar, the node itself, and the price feeder - plus the reth bootnode
list and a DEPLOY.md that walks an operator through bringing the network up.

Nothing here invents protocol values: ports, hosts and addresses come from the
same network.yaml, and the identities come from the key directory.
"""

from __future__ import annotations

import json
import hashlib
import secrets
import shutil
import tarfile
import shlex
import stat
from pathlib import Path
from typing import Any

from offchain_storage import ensure as ensure_storage, settings as storage_settings

# One layout for every founder: they run on separate machines, so they share
# the same ports. Any of these is overridable from the yaml.
DEFAULT_PORTS = {
    "reth_p2p_port": 30303,
    "reth_discv5_port": 31303,
    "rpc_port": 8545,
    "authrpc_port": 8551,
    "metrics_port": 9101,
    "radicle_port": 8776,
    "radicle_status_port": 8876,
    "tee_enclave_port": 17000,
    "feeder_health_port": 9002,
    "mongodb_port": 27017,
    "public_rpc_port": 80,
    "public_radicle_status_port": 8080,
}

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

MONGO_IMAGE = "mongo:7"

# Protocol ceiling on the validator set, mirroring the ValidatorSet precompile
# default. Used to size the Radicle sidecar's connection limits so validators
# joining later do not require a restart of everyone already running.
DEFAULT_MAX_VALIDATORS = 128
OCOMP_BUNDLE_LANE_STRIDE = 6


def quote(value: Any) -> str:
    return shlex.quote(str(value))


def port_of(config: dict[str, Any], name: str) -> int:
    return int(config.get(name, DEFAULT_PORTS[name]))


def embedded_ocomp_endpoint_port(config: dict[str, Any], consensus_port: int) -> int:
    """Return the node-owned Worker registration endpoint.

    The node derives this endpoint directly from its consensus listener.
    """
    if not 1 <= consensus_port < 65535:
        raise ValueError(
            f"consensus port leaves no embedded OCOMP endpoint: {consensus_port}"
        )
    endpoint_port = consensus_port + 1
    return endpoint_port


def write_script(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n\n" + body.strip() + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ---------------------------------------------------------------------------
# Node transport identity
# ---------------------------------------------------------------------------


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P)
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P)
    lam %= SECP256K1_P
    x3 = (lam * lam - x1 - x2) % SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _point_mul(scalar: int, point):
    result, addend = None, point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise ValueError("invalid secp256k1 scalar")
    return result


def ensure_reth_p2p_secret(directory: Path) -> str:
    """Return the enode node id, minting a stable p2p identity when absent.

    Without a persisted secret reth picks a fresh identity on every restart and
    the bootnode list stops resolving. This is a transport identity only: it
    signs no consensus message and holds no funds.
    """
    path = directory / "reth-p2p-secret.hex"
    if path.is_file():
        raw = path.read_text().strip().removeprefix("0x")
        if len(raw) != 64:
            raise ValueError(f"{path} must hold 32 bytes of hex")
    else:
        while True:
            candidate = secrets.token_bytes(32)
            if 1 <= int.from_bytes(candidate, "big") < SECP256K1_N:
                raw = candidate.hex()
                break
        path.write_text(raw)
        path.chmod(0o600)
    x, y = _point_mul(int(raw, 16), SECP256K1_G)
    return f"{x:064x}{y:064x}"


def ensure_ocomp_evm_key(directory: Path) -> None:
    """The embedded OCOMP runtime signs its submissions with this key.

    It defaults to a copy of the validator's own EVM key, which the chain always
    accepts as the sender. Operators wanting a dedicated operational key replace
    this file and register it with `outbe-cli validator delegate ocomp <addr>`.
    """
    ocomp_key = directory / "ocomp-evm-key.hex"
    if ocomp_key.is_file():
        return
    ocomp_key.write_text((directory / "evm-key.hex").read_text().strip() + "\n")
    ocomp_key.chmod(0o600)


def format_enode_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


# ---------------------------------------------------------------------------
# Per-component scripts
# ---------------------------------------------------------------------------


def storage_script(*, index: int, base_dir: str, mongo_uri: str) -> str:
    directory = f"{base_dir}/validator-{index}"
    return f"""
cd {quote(directory)}
backend="$(python3 {quote(base_dir)}/offchain_storage.py backend offchain-storage.toml)"
if python3 {quote(base_dir)}/offchain_storage.py matches-mongodb offchain-storage.toml --mongo-uri {quote(mongo_uri)} && [ -x ./run-mongodb.sh ]; then
  exec ./run-mongodb.sh
fi
# RocksDB is opened by the node. An external MongoDB is managed by its operator.
echo "projection backend: $backend (offchain-storage.toml)"
"""


def mongodb_script(*, config: dict[str, Any], index: int) -> str:
    port = port_of(config, "mongodb_port")
    name = f"outbe-mongo-{index}"
    return f"""
# Transaction-capable MongoDB the node projects finalized Tribute and Nod
# bodies into. A single-node replica set satisfies the majority read/write
# concern the execution path requires.
NAME={quote(name)}
PORT={port}
VOLUME="$NAME-data"

if [ -n "$(docker ps -q -f name="^$NAME$")" ]; then
  echo "$NAME already running"
  exit 0
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$NAME" \\
  -p 127.0.0.1:$PORT:$PORT \\
  -v "$VOLUME":/data/db \\
  --restart unless-stopped \\
  {MONGO_IMAGE} --replSet rs0 --bind_ip_all --port $PORT

echo "waiting for MongoDB..."
until docker exec "$NAME" mongosh --quiet --port "$PORT" --eval 'db.runCommand({{ping:1}})' >/dev/null 2>&1; do
  sleep 1
done
docker exec "$NAME" mongosh --quiet --port "$PORT" --eval \\
  'try {{ rs.status() }} catch (e) {{ rs.initiate({{_id:"rs0",members:[{{_id:0,host:"127.0.0.1:"+{port}}}]}}) }}' >/dev/null
echo "MongoDB ready on 127.0.0.1:$PORT (replica set rs0)"
"""


def enclave_script(*, config: dict[str, Any], index: int, base_dir: str) -> str:
    tee = config["tee"]
    mode = str(tee["mode"])
    enclave_dir = str(config.get("enclave_dir", f"{base_dir}/enclave"))
    enclave_runner = str(config.get("enclave_runner", "./run-enclave.sh"))
    chain_id_hex = f"0x{int(config['chain_id']):064x}"
    port = port_of(config, "tee_enclave_port")
    endpoint = f"127.0.0.1:{port}"
    image = str(config.get("enclave_image", "outbe-tee-enclave:latest"))
    validator_dir = f"{base_dir}/validator-{index}"
    name = f"outbe-enclave-{index}"

    if mode == "dcap-required":
        # Production runs the enclave natively under gramine-sgx, the way the
        # live network does: the SGX driver, the AESM socket and the sealed
        # state all live on the host, and a container only adds a layer between
        # the enclave and the hardware it must attest against.
        return f"""
# TEE enclave under gramine-sgx, on the host. Requires the SGX driver
# (/dev/sgx_enclave, /dev/sgx_provision) and a running aesmd.service.
# The node refuses to start until this answers on {endpoint}.
mkdir -p {quote(validator_dir + "/tee")}

for device in /dev/sgx_enclave /dev/sgx_provision; do
  [ -e "$device" ] || {{ echo "missing $device: SGX driver not loaded" >&2; exit 1; }}
done
systemctl is-active --quiet aesmd.service \\
  || {{ echo "aesmd.service is not running; DCAP quoting will fail" >&2; exit 1; }}

cd {quote(enclave_dir)}
exec {quote(enclave_runner)} \\
  --socket {quote(endpoint)} \\
  --tee-dir {quote(validator_dir + "/tee")} \\
  --chain-id {chain_id_hex}
"""
    # The genesis policy permits unattested execution; the launch profile decides
    # whether hardware isolation is mandatory. Keep it aligned with node_script.
    if config.get("enclave_sgx", True):
        manifest = f"{enclave_dir}/outbe-tee-enclave.manifest.sgx"
        return f"""
# Unattested SGX: hardware isolation and sealing, no DCAP/PCCS dependency.
# An explicitly selected hardware profile never falls back to gramine-direct.
if [ ! -e /dev/sgx_enclave ] && [ ! -e /dev/sgx/enclave ]; then
  echo "SGX hardware required by enclave_sgx; no enclave device found" >&2
  exit 1
fi
[ -f {quote(manifest)} ] || {{ echo "signed SGX manifest missing" >&2; exit 1; }}
python3 - {quote(manifest)} <<'PY_MANIFEST'
import sys, tomllib
with open(sys.argv[1], "rb") as source:
    manifest = tomllib.load(source)
if manifest.get("sgx", {{}}).get("remote_attestation", "none") != "none":
    sys.exit("gramine-direct-dev requires SGX remote attestation none")
PY_MANIFEST
cd {quote(enclave_dir)}
exec ${{SUDO:-$([ "$(id -u)" = 0 ] || echo sudo)}} gramine-sgx outbe-tee-enclave \\
  --socket {quote(endpoint)} \\
  --tee-dir {quote(enclave_dir + "/tee")} \\
  --chain-id {chain_id_hex}
"""

    return f"""
# Unattested development profile without SGX, selected by enclave_sgx: false.
mkdir -p {quote(validator_dir + "/tee")}
docker rm -f {quote(name)} >/dev/null 2>&1 || true
exec docker run --rm --name {quote(name)} \\
  --network host \\
  --log-driver local --log-opt max-size=10m --log-opt max-file=3 \\
  --security-opt seccomp=unconfined \\
  -v {quote(base_dir + "/test-sgx-signing-key.pem")}:/run/secrets/outbe-test-sgx-key.pem:ro \\
  -v {quote(validator_dir + "/tee")}:/tee \\
  {quote(image)} \\
  --socket {quote(endpoint)} \\
  --dkg-seed {index + 1:064x} \\
  --tee-dir /tee \\
  --chain-id {chain_id_hex}
"""


def radicle_script(
    *,
    config: dict[str, Any],
    index: int,
    host: str,
    keys_dir: str,
    repo_root: str,
) -> str:
    port = port_of(config, "radicle_port")
    status_port = port_of(config, "radicle_status_port")
    home = f"{keys_dir}/validator-{index}/radicle"
    binary = str(config.get("radicle_binary", "outbe-radicle"))
    validator_set = config.get("validator_set")
    max_validators = int(
        (validator_set or {}).get("max_validators", DEFAULT_MAX_VALIDATORS)
    )
    return f"""
# Validator-owned Radicle sidecar. The node refuses to start as a validator
# without its control socket, and the status endpoint must stay loopback-only.
#
# `outbe-keygen validator` creates only keys/; the sidecar additionally
# requires its working directories to exist, owner-only, before it will start.
for directory in storage node cobs; do
  path={quote(home)}/"$directory"
  [ -d "$path" ] || mkdir -m 700 -- "$path"
done

# A crash or a hard restart leaves the control socket behind, and Heartwood
# then refuses to start believing another node holds it. Clear it when nothing
# is actually listening, so a systemd restart recovers on its own.
socket={quote(home + "/node/outbe-control.sock")}
if [ -S "$socket" ] && ! pgrep -f "outbe-radicle .*{quote(home)}" >/dev/null 2>&1; then
  rm -f "$socket"
fi

exec {quote(binary)} \\
  --home {quote(home)} \\
  --control-socket {quote(home + "/node/outbe-control.sock")} \\
  --listen 0.0.0.0:{port} \\
  --status-listen 127.0.0.1:{status_port} \\
  `# connection ceiling, not the current set size: the sidecar tracks the` \\
  `# validator set from chain state, so a set that grows must not need a` \\
  `# restart. Sized by the protocol maximum the ValidatorSet enforces.` \\
  --max-validators {max_validators} \\
  --external-inbound-reserve {int(config.get("radicle_external_inbound_reserve", 16))} \\
  --advertise {quote(f"{host}:{port}")}
"""


def node_script(
    *,
    config: dict[str, Any],
    index: int,
    base_dir: str,
    keys_dir: str,
    repo_root: str,
    consensus_port: int,
    host: str,
    identity: dict[str, Any],
) -> str:
    binary = str(config.get("node_binary", "outbe-chain"))
    # Which TEE transport the node must speak. `dcap-required` always uses the
    # authenticated sealed session. `gramine-direct-dev` is ambiguous on its
    # own: the genesis says "no Intel collateral", but the enclave may still be
    # a real gramine-sgx one - that is the SGX-without-DCAP profile - and a
    # real enclave speaks the production session, not the mock transport. The
    # policy default would pick the mock one and the node would fail with
    # "development enclave connection failed", so state it explicitly.
    session_mode = (
        "  --tee-session-mode production-node-host \\\n"
        if config["tee"]["mode"] == "dcap-required"
        or config.get("enclave_sgx", True)
        else ""
    )
    validator_keys = f"{keys_dir}/validator-{index}"
    validator_dir = f"{base_dir}/validator-{index}"
    radicle_home = f"{validator_keys}/radicle"
    return f"""
# Validator node: execution, consensus and the embedded OCOMP runtime in one
# process. OCOMP needs no separate daemon - it runs inside this binary and
# reads its keys from <datadir>/../ocomp/domain-v1.
KEYS={quote(validator_keys)}
DATA={quote(validator_dir + "/data")}
DOMAIN={quote(validator_dir + "/ocomp/domain-v1")}
BUNDLE_HASH={quote(identity["protocol_bundle_hash"])}

mkdir -p "$DATA" "$DOMAIN/protocol-bundles-v1" {quote(validator_dir + "/logs")}
install -m 600 "$KEYS/ocomp-key-v1.hex" "$DOMAIN/ocomp-key-v1.hex"
install -m 600 "$KEYS/ocomp-evm-key.hex" "$DOMAIN/ocomp-evm-key.hex"
# Preserve the V1 compatibility path and publish the same canonical bytes in
# the hash-addressed catalog used by successor-aware Nodes and exporters.
install -m 640 {quote(base_dir + "/protocol-bundle-v1.ocb1")} "$DOMAIN/protocol-bundle-v1.ocb1"
install -m 640 {quote(base_dir + "/protocol-bundles-v1")}/"${{BUNDLE_HASH#0x}}.ocb1" \
  "$DOMAIN/protocol-bundles-v1/${{BUNDLE_HASH#0x}}.ocb1"

if [ -f {quote(validator_dir + "/ocomp-bundles.env")} ]; then
  source {quote(validator_dir + "/ocomp-bundles.env")}
  export OCOMP_PROTOCOL_BUNDLE_HASHES
fi

# reth reads the p2p key from the file verbatim, so normalize it in place.
printf '%s' "$(tr -d '[:space:]' < "$KEYS/reth-p2p-secret.hex")" > "$KEYS/reth-p2p-secret.hex"

# A debug build needs a larger thread stack: block 1 lazily initializes k256's
# secp256k1 tables in an unoptimized frame that overflows reth's default.
export RUST_MIN_STACK="${{RUST_MIN_STACK:-16777216}}"

exec {quote(binary)} node \\
  --validator \\
{session_mode}\
  --chain {quote(base_dir + "/genesis.json")} \\
  --datadir "$DATA" \\
  --engine.persistence-threshold 0 \\
  --engine.memory-block-buffer-target 0 \\
  --consensus.signing-key "$KEYS/signing-key.hex" \\
  --validator.evm-key "$KEYS/evm-key.hex" \\
  --consensus.listen-addr 0.0.0.0:{consensus_port} \\
  --consensus.storage-dir {quote(validator_dir + "/consensus")} \\
  --radicle.control-socket {quote(radicle_home + "/node/outbe-control.sock")} \\
  --radicle.status-address 127.0.0.1:{port_of(config, "radicle_status_port")} \\
  --tee-enclave-socket 127.0.0.1:{port_of(config, "tee_enclave_port")} \\
  --projection.storage-config {quote(base_dir + f"/validator-{index}/offchain-storage.toml")} \\
  --http --http.addr 127.0.0.1 --http.port {port_of(config, "rpc_port")} \\
  --http.api eth,net,web3,rudis \\
  --authrpc.port {port_of(config, "authrpc_port")} \\
  --port {port_of(config, "reth_p2p_port")} \\
  --discovery.port {port_of(config, "reth_p2p_port")} \\
  --nat extip:{host} \\
  --discovery.v5.addr 0.0.0.0 \\
  --discovery.v5.port {port_of(config, "reth_discv5_port")} \\
  --p2p-secret-key "$KEYS/reth-p2p-secret.hex" \\
  --bootnodes "$(grep -v '^[[:space:]]*#' {quote(base_dir + "/reth-bootnodes.txt")} | paste -sd, -)" \\
  --metrics 127.0.0.1:{port_of(config, "metrics_port")} \\
  --ipcpath "$DATA/reth.ipc" \\
  --log.file.directory {quote(validator_dir + "/logs")}
"""


def feeder_config(
    *, config: dict[str, Any], index: int, validator: dict[str, Any], signer_key: str
) -> str:
    oracle = config.get("oracle", {}).get("config", {})
    price_provider = str(config.get("price_provider", "mock_http"))
    source_quote = str(
        config.get(
            "price_source_quote",
            "840" if price_provider == "mock_http" else "USDT",
        )
    )
    if price_provider == "mock_http":
        provider_endpoint = f'''[[provider_endpoints]]
name = "mock_http"
rest = "{config.get("price_feed_rest", "https://prc.testnet.outbe.net")}"'''
    elif price_provider in {"binance", "kraken", "okx", "gate", "huobi", "mexc", "coinbase"}:
        websocket = str(config.get("price_feed_websocket", "")).strip()
        websocket_line = f'\nwebsocket = "{websocket}"' if websocket else ""
        provider_endpoint = f'''[[provider_endpoints]]
name = "{price_provider}"{websocket_line}'''
    else:
        provider_endpoint = ""
    return f"""# Price oracle feeder for validator-{index}.
[chain]
rpc_endpoint = "http://127.0.0.1:{port_of(config, "rpc_port")}"
chain_id = {int(config["chain_id"])}
gasless_oracle_votes = true

[account]
private_key = "0x{signer_key}"
validator_address = "{validator["address"]}"

[oracle]
vote_period = {int(oracle.get("vote_period", 8))}
poll_interval_secs = 2

[health]
enabled = true
bind_address = "127.0.0.1:{port_of(config, "feeder_health_port")}"

# The feeder only accepts provider names from its built-in list (mock, pyth,
# chainlink, binance, kraken, okx, gate, huobi, mexc, coinbase, mock_http); an
# invented name is rejected at startup. `mock_http` uses the configured REST
# endpoint; exchange providers use live WebSocket market streams.
{provider_endpoint}

[[currency_pairs]]
base = "rudis"
quote = "840"

[[currency_pairs.sources]]
provider = "{price_provider}"
base = "COEN"
quote = "{source_quote}"

[[deviation_thresholds]]
base = "rudis"
threshold = "2.0"
"""


def feeder_script(*, config: dict[str, Any], index: int, base_dir: str, repo_root: str) -> str:
    binary = str(config.get("feeder_binary", "outbe-feeder"))
    return f"""
# Price oracle feeder. Start it once the node serves RPC; oracle votes are
# rejected before the chain produces blocks.
exec {quote(binary)} --config {quote(f"{base_dir}/validator-{index}/feeder.toml")}
"""


def start_all_script(
    *, config: dict[str, Any], index: int, base_dir: str, ocomp_endpoint_port: int
) -> str:
    directory = f"{base_dir}/validator-{index}"
    status_port = port_of(config, "radicle_status_port")
    rpc_port = port_of(config, "rpc_port")
    return f"""
# Bring up the configured storage, enclave, Radicle and node in dependency order.
cd {quote(directory)}
mkdir -p logs

./run-storage.sh

# run-enclave.sh execs into the enclave, so it must be backgrounded: calling it
# directly would replace this script and nothing below would ever run.
nohup ./run-enclave.sh > logs/enclave.log 2>&1 &
echo $! > enclave.pid
echo "waiting for the enclave..."
for _ in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/{{TEE_PORT}}) 2>/dev/null; then exec 3>&-; break; fi
  sleep 1
done

nohup ./run-radicle.sh > logs/radicle.log 2>&1 &
echo $! > radicle.pid
echo "waiting for the Radicle sidecar..."
for _ in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/{status_port}) 2>/dev/null; then exec 3>&-; break; fi
  sleep 1
done

nohup ./run-node.sh > logs/node.log 2>&1 &
echo $! > node.pid
echo "waiting for RPC..."
for _ in $(seq 1 180); do
  if (exec 3<>/dev/tcp/127.0.0.1/{rpc_port}) 2>/dev/null; then exec 3>&-; break; fi
  sleep 1
done

nohup ./run-feeder.sh > logs/feeder.log 2>&1 &
echo $! > feeder.pid

# The node owns the embedded OCOMP Supervisor. Wait for its registration
# endpoint before starting the external SnapshotExporter and Worker clients.
ocomp_ready=0
for _ in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/{ocomp_endpoint_port}) 2>/dev/null; then
    exec 3>&-
    ocomp_ready=1
    break
  fi
  sleep 1
done
if [ "$ocomp_ready" -ne 1 ]; then
  echo "node-owned OCOMP endpoint 127.0.0.1:{ocomp_endpoint_port} did not become ready" >&2
  exit 1
fi
nohup ./run-ocomp-exporter.sh > logs/ocomp-exporter.log 2>&1 &
echo $! > ocomp-exporter.pid
nohup ./run-ocomp-worker.sh > logs/ocomp-worker.log 2>&1 &
echo $! > ocomp-worker.pid

echo
echo "validator-{index} started:"
echo "  node:    logs/node.log    (pid $(cat node.pid))"
echo "  radicle: logs/radicle.log (pid $(cat radicle.pid))"
echo "  feeder:  logs/feeder.log  (pid $(cat feeder.pid))"
echo "  ocomp:   embedded Supervisor in node, logs/ocomp-exporter.log, logs/ocomp-worker.log"
echo "  enclave: docker logs outbe-enclave-{index}"
if [ "$(python3 {quote(base_dir)}/offchain_storage.py backend offchain-storage.toml)" = mongodb ]; then
  echo "  mongo:   docker logs outbe-mongo-{index}"
fi
"""


def stop_all_script(*, index: int, base_dir: str) -> str:
    directory = f"{base_dir}/validator-{index}"
    return f"""
cd {quote(directory)}
for name in ocomp-worker ocomp-exporter feeder node radicle enclave; do
  if [ -f "$name.pid" ]; then
    pid="$(cat "$name.pid")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "stopped $name (pid $pid)"
    fi
    rm -f "$name.pid"
  fi
done
docker stop outbe-enclave-{index} >/dev/null 2>&1 && echo "stopped enclave" || true
if [ "$(python3 {quote(base_dir)}/offchain_storage.py backend offchain-storage.toml)" = mongodb ]; then
  echo "MongoDB left running; stop it with: docker stop outbe-mongo-{index}"
fi
"""


# ---------------------------------------------------------------------------
# OCOMP roles
# ---------------------------------------------------------------------------


def ocomp_identity(genesis_path: Path, keys_dir: Path) -> dict[str, Any]:
    """Read the identity the OCOMP roles must be started with.

    chain id, genesis hash and install hash are plain fields of the genesis.
    The protocol bundle hash is not: it sits inside the canonical install
    bytes, right after the genesis hash and the fork id, both of which are
    known here - so it is located by anchoring on the genesis hash rather than
    by a bare offset. Every role validates the value against the bundle file it
    loads and exits with `HashMismatch` if it disagrees, so a wrong read fails
    immediately and loudly instead of producing a subtly wrong network.
    """
    genesis = json.loads(genesis_path.read_text())
    config = genesis.get("config", {})
    install = config.get("ocompForkInstallV1")
    if not install:
        raise ValueError(f"{genesis_path} has no OCOMP install; cannot launch OCOMP roles")
    canonical = bytes.fromhex(str(install["canonicalBytes"]).removeprefix("0x"))
    genesis_hash = bytes.fromhex(genesis_hash_of(keys_dir).removeprefix("0x"))
    anchor = canonical.find(genesis_hash)
    if anchor < 0:
        raise ValueError("OCOMP install does not carry this genesis hash")
    # request profile order: genesis_hash, fork_id, protocol_bundle_hash
    bundle_hash = canonical[anchor + 64 : anchor + 96]
    if len(bundle_hash) != 32:
        raise ValueError("OCOMP install is truncated before the protocol bundle hash")
    return {
        "chain_id": int(config["chainId"]),
        "genesis_hash": "0x" + genesis_hash.hex(),
        "protocol_bundle_hash": "0x" + bundle_hash.hex(),
        "install_hash": str(install["installHash"]),
    }


def genesis_hash_of(keys_dir: Path) -> str:
    """The genesis hash the OCOMP registrations were minted against.

    create_genesis.py records it beside each registration it mints, which is
    exactly the value the install document carries.
    """
    for marker in sorted(keys_dir.glob("validator-*/ocomp-registration-v1.genesis-hash")):
        return marker.read_text().strip()
    raise ValueError(
        f"no OCOMP registration marker under {keys_dir}; cannot identify the genesis "
        f"the OCOMP roles must run against"
    )


def ocomp_role_preamble(*, config: dict[str, Any], index: int, base_dir: str, identity: dict[str, Any]) -> str:
    return f"""
export OUTBE_OCOMP_BASE_PATH={quote(base_dir)}
export OCOMP_VALIDATOR_INDEX={index}
export OCOMP_CHAIN_ID={identity["chain_id"]}
export OCOMP_GENESIS_HASH={identity["genesis_hash"]}
export OCOMP_BOOT_NONCE=0x{f"{index + 1:02x}" * 32}
export OCOMP_PROTOCOL_BUNDLE_HASH={identity["protocol_bundle_hash"]}
export OCOMP_PROTOCOL_BUNDLE_HASHES={identity["protocol_bundle_hash"]}
export OCOMP_REGISTRY_GENERATION=1
export OUTBE_OCOMP_RPC_URL="http://127.0.0.1:{port_of(config, "rpc_port")}"
"""


def ocomp_exporter_script(
    *,
    config: dict[str, Any],
    index: int,
    base_dir: str,
    identity: dict[str, Any],
    ocomp_endpoint_port: int,
) -> str:
    binary = str(config.get("ocomp_binary", "outbe-ocomp"))
    return f"""
# OCOMP SnapshotExporter: materializes the finalized inputs the Workers read.
{ocomp_role_preamble(config=config, index=index, base_dir=base_dir, identity=identity).strip()}
if [ -f {quote(base_dir + f"/validator-{index}/ocomp-bundles.env")} ]; then
  # Operator-owned allow-list. Add the staged hash here and restart only the
  # exporter before submitting the Update proposal.
  source {quote(base_dir + f"/validator-{index}/ocomp-bundles.env")}
  export OCOMP_PROTOCOL_BUNDLE_HASHES
fi
export OUTBE_OCOMP_STORAGE_CONFIG={quote(base_dir + f"/validator-{index}/offchain-storage.toml")}

exec {quote(binary)} snapshot-exporter \\
  --supervisor-address 127.0.0.1:{ocomp_endpoint_port}
"""


def ocomp_worker_script(
    *,
    config: dict[str, Any],
    index: int,
    base_dir: str,
    identity: dict[str, Any],
    ocomp_endpoint_port: int,
    ordinal: int = 0,
) -> str:
    binary = str(config.get("ocomp_binary", "outbe-ocomp"))
    # Same shape the harness uses: first byte identifies the host, the last
    # four the worker ordinal, so every worker process gets a distinct nonce.
    nonce = f"{index + 1:02x}" + "00" * 27 + f"{ordinal:08x}"
    return f"""
# OCOMP Worker {ordinal}: runs the active-bundle computation and signs its result.
{ocomp_role_preamble(config=config, index=index, base_dir=base_dir, identity=identity).strip()}
source {quote(base_dir + f"/validator-{index}/ocomp-active.env")}
: "${{OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH:?missing active bundle hash}}"
BUNDLE_NAME="${{OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH#0x}}.ocb1"
[ -f {quote(base_dir + f"/validator-{index}/ocomp/domain-v1/protocol-bundles-v1")}/"$BUNDLE_NAME" ] || {{
  echo "active bundle is not installed: $BUNDLE_NAME" >&2
  exit 1
}}
export OCOMP_PROTOCOL_BUNDLE_HASH="$OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH"

exec {quote(binary)} worker \\
  --chain-id {identity["chain_id"]} \\
  --genesis-hash {identity["genesis_hash"]} \\
  --boot-nonce 0x{nonce} \\
  --worker-ordinal {ordinal} \\
  --protocol-bundle-hash "$OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH" \\
  --supervisor-address 127.0.0.1:{ocomp_endpoint_port}
"""


def ocomp_successor_worker_script(
    *,
    config: dict[str, Any],
    index: int,
    base_dir: str,
    identity: dict[str, Any],
    ocomp_endpoint_port: int,
) -> str:
    binary = str(config.get("ocomp_binary", "outbe-ocomp"))
    successor_endpoint = ocomp_endpoint_port + OCOMP_BUNDLE_LANE_STRIDE
    if successor_endpoint > 65535:
        raise ValueError("consensus port leaves no OCOMP successor endpoint")
    nonce = f"{index + 1:02x}" + "00" * 26 + "01" + "00000000"
    return f"""
# Dormant V2 Worker lane. The operator writes ocomp-successor.env and starts
# its systemd unit before the Update proposal; activation itself starts no
# process and changes no local files.
{ocomp_role_preamble(config=config, index=index, base_dir=base_dir, identity=identity).strip()}
source {quote(base_dir + f"/validator-{index}/ocomp-successor.env")}
: "${{OCOMP_SUCCESSOR_PROTOCOL_BUNDLE_HASH:?missing successor bundle hash}}"
BUNDLE_NAME="${{OCOMP_SUCCESSOR_PROTOCOL_BUNDLE_HASH#0x}}.ocb1"
[ -f {quote(base_dir + f"/validator-{index}/ocomp/domain-v1/protocol-bundles-v1")}/"$BUNDLE_NAME" ] || {{
  echo "successor bundle is not installed: $BUNDLE_NAME" >&2
  exit 1
}}
export OCOMP_PROTOCOL_BUNDLE_HASH="$OCOMP_SUCCESSOR_PROTOCOL_BUNDLE_HASH"

exec {quote(binary)} worker \
  --chain-id {identity["chain_id"]} \
  --genesis-hash {identity["genesis_hash"]} \
  --boot-nonce 0x{nonce} \
  --worker-ordinal 0 \
  --protocol-bundle-hash "$OCOMP_SUCCESSOR_PROTOCOL_BUNDLE_HASH" \
  --supervisor-address 127.0.0.1:{successor_endpoint}
"""

# ---------------------------------------------------------------------------
# Signed enclave
# ---------------------------------------------------------------------------
#
# The enclave is signed ONCE, where the signing key lives, and the signed
# artifacts travel in the bundle. Signing per machine instead gives every host
# its own mr_signer - four different enclave identities on one network, which
# a `dcap-required` genesis (it pins a single mrsigner) would reject outright.
# The private key never enters the bundle.

SIGNED_ENCLAVE_FILES = (
    "outbe-tee-enclave",
    "outbe-tee-enclave.manifest",
    "outbe-tee-enclave.manifest.sgx",
    "outbe-tee-enclave.sig",
)


def stage_signed_enclave(*, config: dict[str, Any], output_dir: Path) -> dict[str, str] | None:
    """Copy the signed enclave into the bundle and report its identity.

    `signed_enclave_dir` points at the directory holding the artifacts produced
    by `gramine-sgx-sign` on the build host. Without it the bundle carries no
    enclave and each machine has to sign its own - allowed, but it is the very
    thing that produces mismatched identities, so say so out loud.
    """
    source = config.get("signed_enclave_dir")
    if not source:
        return None
    source_dir = Path(str(source))
    staged = output_dir / "enclave"
    staged.mkdir(parents=True, exist_ok=True)
    for name in SIGNED_ENCLAVE_FILES:
        origin = source_dir / name
        if not origin.is_file():
            raise ValueError(
                f"`signed_enclave_dir` is missing {name}. Sign the enclave on the "
                f"build host first (gramine-manifest + gramine-sgx-sign) and point "
                f"this at the directory holding the result."
            )
        shutil.copy2(origin, staged / name)
    # A private key in the bundle would be handed to every machine; refuse.
    for stray in source_dir.glob("*.pem"):
        if (staged / stray.name).exists():
            (staged / stray.name).unlink()
    return {"path": str(staged)}


# ---------------------------------------------------------------------------
# Public entry point (caddy)
# ---------------------------------------------------------------------------
#
# The node binds RPC to loopback on purpose, so something has to publish it.
# caddy terminates the public listener and reverse-proxies to 127.0.0.1, which
# keeps the node itself unreachable from the internet and gives one place to
# add CORS, TLS or auth later. This mirrors how the live testnet is fronted.


def caddyfile(*, config: dict[str, Any], host: str) -> str:
    """Caddy site for one validator: RPC and the Radicle status endpoint.

    Radicle's replication port is raw p2p, not HTTP, so it stays a plain port
    (already opened between the machines) and is not proxied here.
    """
    rpc_port = port_of(config, "rpc_port")
    status_port = port_of(config, "radicle_status_port")
    public_rpc = int(config.get("public_rpc_port", 80))
    public_radicle = int(config.get("public_radicle_status_port", 8080))
    return f"""# Generated for {host}. Plain HTTP on the public address: no TLS,
# because these hosts are addressed by IP and have no certificate names.
{{
	auto_https off
	admin off
}}

# Ethereum JSON-RPC
:{public_rpc} {{
	@options method OPTIONS
	handle @options {{
		header {{
			Access-Control-Allow-Origin *
			Access-Control-Allow-Methods "GET, POST, OPTIONS"
			Access-Control-Allow-Headers "Content-Type"
			Access-Control-Max-Age 86400
		}}
		respond 204
	}}
	handle {{
		reverse_proxy 127.0.0.1:{rpc_port} {{
			header_up X-Real-IP {{remote_host}}
			header_down -Access-Control-Allow-Origin
		}}
		header Access-Control-Allow-Origin *
	}}
}}

# Radicle sidecar status (read-only JSON)
:{public_radicle} {{
	handle {{
		reverse_proxy 127.0.0.1:{status_port} {{
			header_up X-Real-IP {{remote_host}}
		}}
		header Access-Control-Allow-Origin *
	}}
}}
"""


def caddy_install_script(*, config: dict[str, Any], base_dir: str, index: int) -> str:
    public_rpc = int(config.get("public_rpc_port", 80))
    public_radicle = int(config.get("public_radicle_status_port", 8080))
    return f"""
# Publish this validator's RPC and Radicle status through caddy.
if ! command -v caddy >/dev/null; then
  echo "installing caddy..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \\
    | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \\
    | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq caddy >/dev/null
fi

sudo install -m 644 {quote(base_dir + f"/validator-{index}/Caddyfile")} /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy 2>/dev/null || sudo systemctl restart caddy

# Let the world reach the published ports; the node's own ports stay loopback.
sudo ufw allow {public_rpc}/tcp >/dev/null 2>&1 || true
sudo ufw allow {public_radicle}/tcp >/dev/null 2>&1 || true

echo "published:"
echo "  RPC            http://$(curl -s -m 5 ifconfig.me || echo '<this-host>'):{public_rpc}"
echo "  Radicle status http://$(curl -s -m 5 ifconfig.me || echo '<this-host>'):{public_radicle}"
"""


# ---------------------------------------------------------------------------
# systemd units
# ---------------------------------------------------------------------------
#
# The run-*.sh scripts each exec one process in the foreground, which is
# exactly what a systemd service wants. Units give us what a shell-launched
# background process cannot: the processes survive the session that started
# them, restart on failure, order themselves by dependency, and are inspected
# with journalctl instead of scattered log files.


UNIT_ROLES = (
    ("enclave", "TEE enclave", None),
    ("radicle", "Radicle sidecar", "outbe-enclave@%i.service"),
    ("node", "validator node", "outbe-radicle@%i.service"),
    ("ocomp-exporter", "OCOMP SnapshotExporter", "outbe-node@%i.service"),
    ("ocomp-worker", "OCOMP Worker", "outbe-node@%i.service"),
    ("ocomp-successor-worker", "OCOMP successor Worker", "outbe-node@%i.service"),
    ("feeder", "price oracle feeder", "outbe-node@%i.service"),
)


def systemd_unit(*, role: str, description: str, after: str | None, base_dir: str) -> str:
    """One templated unit per role; %i is the validator index."""
    ordering = ""
    if after:
        ordering = f"After={after}\nRequires={after}\n"
    # The enclave runs under sudo inside the script, so let systemd own it as
    # root directly and drop the sudo indirection.
    user = "root" if role == "enclave" else "ubuntu"
    return f"""[Unit]
Description=Outbe {description} (validator %i)
After=network-online.target{"" if not after else ""}
{ordering}
[Service]
Type=simple
User={user}
WorkingDirectory={base_dir}/validator-%i
ExecStart={base_dir}/validator-%i/run-{role}.sh
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def write_systemd_units(output_dir: Path, base_dir: str) -> None:
    unit_dir = output_dir / "systemd"
    unit_dir.mkdir(parents=True, exist_ok=True)
    for role, description, after in UNIT_ROLES:
        unit = systemd_unit(
            role=role, description=description, after=after, base_dir=base_dir
        )
        (unit_dir / f"outbe-{role}@.service").write_text(unit)

    install = f"""
# Install and start every Outbe service for validator $1 on this machine.
INDEX="${{1:?usage: install-systemd.sh <validator-index>}}"

sudo install -m 644 {quote(base_dir)}/systemd/outbe-*@.service /etc/systemd/system/
sudo systemctl daemon-reload

# Prepare the backend selected in this validator's offchain-storage.toml.
{quote(base_dir)}/validator-"$INDEX"/run-storage.sh

for role in enclave radicle node ocomp-exporter ocomp-worker feeder; do
  sudo systemctl enable --now "outbe-$role@$INDEX.service"
done

echo
echo "services for validator $INDEX:"
systemctl list-units 'outbe-*' --no-pager --no-legend | sed 's/^/  /'
echo
echo "follow one with: journalctl -u outbe-node@$INDEX -f"
"""
    write_script(output_dir / "install-systemd.sh", install)


def preflight_script(*, config: dict[str, Any], base_dir: str, index: int) -> str:
    """Check, on this machine, everything that silently breaks a launch.

    Every item here cost a real debugging session: a genesis that differs
    between machines, a mismatched enclave identity, leftover state from an
    earlier genesis, and ports already held by a previous run.
    """
    tee_port = port_of(config, "tee_enclave_port")
    rpc_port = port_of(config, "rpc_port")
    return f"""
# Read-only pre-launch check for validator {index}. Exits non-zero on anything
# that would make the network fail after start rather than before.
cd {quote(base_dir)}
fail=0
note() {{ printf '  %-42s %s\\n' "$1" "$2"; }}

note "genesis sha256" "$(sha256sum genesis.json | cut -c1-16)"
note "protocol bundle sha256" "$(sha256sum protocol-bundle-v1.ocb1 | cut -c1-16)"
echo "  ^ these two must be identical on every machine"

if [ -f outbe-tee-enclave.sig ]; then
  note "enclave mr_enclave" "$(gramine-sgx-sigstruct-view outbe-tee-enclave.sig 2>/dev/null | grep -oE 'mr_enclave: [0-9a-f]+' | cut -c13-28)"
  note "enclave mr_signer" "$(gramine-sgx-sigstruct-view outbe-tee-enclave.sig 2>/dev/null | grep -oE 'mr_signer: [0-9a-f]+' | cut -c12-27)"
  echo "  ^ mr_signer must match across machines; a per-host key breaks dcap-required"
else
  note "enclave signature" "MISSING"; fail=1
fi

# State from an earlier genesis makes the node exit with
# 'projection identity does not match configured chain'.
for stale in validator-{index}/data validator-{index}/consensus tee; do
  [ -e "$stale" ] && {{ note "leftover state" "$stale - remove before a new genesis"; fail=1; }}
done
if [ "$(python3 offchain_storage.py backend validator-{index}/offchain-storage.toml)" = mongodb ] && command -v docker >/dev/null; then
  dbs=$(docker exec outbe-mongo-{index} mongosh --quiet --eval \\
    'db.adminCommand({{listDatabases:1}}).databases.map(x=>x.name).filter(n=>/outbe/.test(n)).length' 2>/dev/null | tail -1)
  [ "${{dbs:-0}}" != "0" ] && {{ note "mongo projections" "$dbs left from an earlier run"; fail=1; }}
fi

for port in {tee_port} {rpc_port}; do
  ss -ltn 2>/dev/null | grep -q ":$port " && {{ note "port $port" "already in use"; fail=1; }}
done

if [ "$fail" = 0 ]; then echo; echo "  preflight OK"; else echo; echo "  preflight FAILED"; fi
exit "$fail"
"""


# ---------------------------------------------------------------------------
# Per-machine distribution
# ---------------------------------------------------------------------------
#
# The point of the bundle is that nothing is assembled by hand afterwards.
# Each machine gets one archive holding everything it needs and nothing that
# belongs to another validator, plus a checksum manifest so a half-finished
# copy is caught before the network is started rather than after.


def build_distribution(
    *,
    output_dir: Path,
    validators: list[dict[str, Any]],
    keys_dir: Path,
    base_dir: str,
) -> list[str]:
    """Pack one self-contained archive per machine. Returns their names."""
    dist = output_dir / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    dist.mkdir(parents=True)

    shared = [
        output_dir / "genesis.json",
        output_dir / "protocol-bundle-v1.ocb1",
        output_dir / "reth-bootnodes.txt",
        output_dir / "DEPLOY.md",
        output_dir / "install-systemd.sh",
        output_dir / "offchain_storage.py",
    ]
    enclave_dir = output_dir / "enclave"
    systemd_dir = output_dir / "systemd"
    bundle_catalog_dir = output_dir / "protocol-bundles-v1"

    names = []
    for index in range(len(validators)):
        staging = dist / f"validator-{index}"
        staging.mkdir()
        for item in shared:
            if item.is_file():
                shutil.copy2(item, staging / item.name)
        if systemd_dir.is_dir():
            shutil.copytree(systemd_dir, staging / "systemd")
        if bundle_catalog_dir.is_dir():
            shutil.copytree(bundle_catalog_dir, staging / "protocol-bundles-v1")
        if enclave_dir.is_dir():
            shutil.copytree(enclave_dir, staging / "enclave")
        # This machine's run scripts and ONLY this machine's key material.
        shutil.copytree(output_dir / f"validator-{index}", staging / f"validator-{index}")
        keys_target = staging / "keys" / f"validator-{index}"
        keys_target.parent.mkdir(exist_ok=True)
        shutil.copytree(keys_dir / f"validator-{index}", keys_target)

        archive = dist / f"validator-{index}.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for entry in sorted(staging.iterdir()):
                tar.add(entry, arcname=entry.name)
        shutil.rmtree(staging)
        names.append(archive.name)

    # One manifest over the archives: a truncated copy or a stale archive from
    # an earlier run is then a checksum mismatch, not a mystery at boot.
    lines = []
    for name in names:
        digest = hashlib.sha256((dist / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (dist / "SHA256SUMS").write_text("\n".join(lines) + "\n")

    unpack = f"""
# Unpack this machine's archive into {base_dir}. Run it ON the target machine,
# from the directory holding validator-<index>.tgz.
INDEX="${{1:?usage: unpack.sh <validator-index>}}"
ARCHIVE="validator-$INDEX.tgz"

[ -f "$ARCHIVE" ] || {{ echo "no $ARCHIVE here" >&2; exit 1; }}
if command -v sha256sum >/dev/null && [ -f SHA256SUMS ]; then
  grep " $ARCHIVE\\$" SHA256SUMS | sha256sum -c - || {{ echo "checksum mismatch" >&2; exit 1; }}
fi

sudo mkdir -p {quote(base_dir)}
sudo chown "$USER" {quote(base_dir)}
tar xzf "$ARCHIVE" -C {quote(base_dir)}
chmod -R go-rwx {quote(base_dir)}/keys

# The signed enclave, when the bundle carries one, belongs next to the binaries.
if [ -d {quote(base_dir)}/enclave ]; then
  sudo install -m 755 {quote(base_dir)}/enclave/outbe-tee-enclave {quote(base_dir)}/
  sudo install -m 644 {quote(base_dir)}/enclave/outbe-tee-enclave.manifest* {quote(base_dir)}/
  sudo install -m 644 {quote(base_dir)}/enclave/outbe-tee-enclave.sig {quote(base_dir)}/
fi

echo "unpacked into {base_dir}; next: ./install-systemd.sh $INDEX"
"""
    write_script(dist / "unpack.sh", unpack)
    return names


# ---------------------------------------------------------------------------
# DEPLOY.md
# ---------------------------------------------------------------------------


def deploy_markdown(
    *,
    config: dict[str, Any],
    validators: list[dict[str, Any]],
    base_dir: str,
    keys_dir: str,
    local_keys_dir: Path,
    enodes: list[str],
) -> str:
    chain_id = int(config["chain_id"])
    mode = str(config["tee"]["mode"])
    consensus_port = validators[0]["p2p_address"].rsplit(":", 1)[1]
    rows = "\n".join(
        f"| validator-{index} | `{validator['p2p_address']}` | `{validator['address']}` |"
        for index, validator in enumerate(validators)
    )
    bootnode_lines = "\n".join(f"  - `{enode}`" for enode in enodes)
    dev_warning = (
        ""
        if mode == "dcap-required"
        else (
            "\n> **`gramine-direct-dev`**: the enclave runs unattested. Use it for a "
            "devnet only. A production network needs `tee.mode: dcap-required`, real "
            "SGX hardware, and the exact release measurements.\n"
        )
    )
    return f"""# Deploying this network

Chain id `{chain_id}`, four founding validators, TEE mode `{mode}`.
{dev_warning}
| Machine | Consensus p2p | Validator address |
|---|---|---|
{rows}

Everything below was generated from your `network.yaml`. Ports are identical on
every machine, because each founder runs on its own host.

## 1. Copy files to each machine

Every machine gets the shared files plus **only its own** key directory:

```bash
# from this directory on the operator workstation, for machine N (0..3):
ssh <machine-N> "mkdir -p {base_dir} {keys_dir}"
scp genesis.json reth-bootnodes.txt protocol-bundle-v1.ocb1 <machine-N>:{base_dir}/
scp -r protocol-bundles-v1 <machine-N>:{base_dir}/
scp -r validator-N <machine-N>:{base_dir}/
scp -r {local_keys_dir}/validator-N <machine-N>:{keys_dir}/
```

`validator-N/` holds the run scripts; the key directory holds the secrets.
Never copy one validator's key directory to another machine.

## 2. Open the ports

Between the four machines:

| Port | Purpose |
|---|---|
| `{consensus_port}` | Commonware consensus p2p |
| `{port_of(config, "reth_p2p_port")}` | reth p2p (TCP + UDP) |
| `{port_of(config, "reth_discv5_port")}` | reth discv5 (UDP) |
| `{port_of(config, "radicle_port")}` | Radicle replication |

Everything else stays on loopback and must not be exposed: RPC
`{port_of(config, "rpc_port")}`, authrpc `{port_of(config, "authrpc_port")}`,
metrics `{port_of(config, "metrics_port")}`, Radicle status
`{port_of(config, "radicle_status_port")}`, the enclave socket
`{port_of(config, "tee_enclave_port")}`, optional MongoDB
`{port_of(config, "mongodb_port")}`, and the feeder health endpoint
`{port_of(config, "feeder_health_port")}`.

## 3. Prerequisites on every machine

- Python 3.11+ - reads the shared storage TOML at launch
- Docker - the TEE enclave and optional MongoDB run as containers
- `outbe-cli` on the machine you verify from (step 5)
- the `outbe-chain`, `outbe-ocomp`, `outbe-radicle` and `outbe-feeder` binaries on `PATH`
  (or set `node_binary`, `radicle_binary` and `feeder_binary` in the yaml to
  absolute paths and regenerate)
- for `dcap-required`: SGX hardware exposing `/dev/sgx_enclave` and
  `/dev/sgx_provision`

## 4. Start each machine

```bash
cd {base_dir}/validator-N
./preflight.sh N        # verifies genesis/enclave/state before anything starts
sudo {base_dir}/install-systemd.sh N
```

`install-systemd.sh` installs one templated unit per role and starts them in
dependency order, so the processes outlive the shell that launched them and
come back on failure. `preflight.sh` is read-only: run it first and compare the
genesis and enclave digests it prints across all four machines - they must be
identical.

`start-all.sh` starts the components in dependency order - configured storage, enclave,
Radicle sidecar, node, feeder - and writes pids and logs into
`{base_dir}/validator-N/`. To run one component in the foreground instead, call
its script directly: `run-storage.sh`, `run-enclave.sh`, `run-radicle.sh`,
`run-node.sh`, `run-feeder.sh`. `stop-all.sh` reverses it.

**Start all four machines within a few minutes of each other.** Block 1 carries
the founding DKG ceremony and needs every genesis validator online - unlike a
later reshare it does not complete on a threshold. If it fails, stop all four,
delete `{base_dir}/validator-N/data` on each machine, and start again; the
genesis itself stays valid.

## 5. Verify

```bash
# height advances on each machine
curl -s -X POST http://127.0.0.1:{port_of(config, "rpc_port")} \\
  -H 'content-type: application/json' \\
  -d '{{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}}'

# all four validators active
outbe-cli --rpc-url http://127.0.0.1:{port_of(config, "rpc_port")} validator list

# feeder health
curl -s http://127.0.0.1:{port_of(config, "feeder_health_port")}/health
```

The network is healthy when every machine reports an advancing non-zero block
number and `validator list` shows four active validators.

## What runs where

| Component | Process | Notes |
|---|---|---|
| Execution + consensus | `outbe-chain node` | one binary, no Engine API split |
| OCOMP Supervisor | embedded in `outbe-chain node` | ExEx hands out work and submits results |
| OCOMP SnapshotExporter | `outbe-ocomp snapshot-exporter` | own process; materializes finalized inputs |
| OCOMP Worker | `outbe-ocomp worker` | initial lane plus one dormant successor lane |
| TEE enclave | Docker container | the node refuses to start without it |
| Radicle | `outbe-radicle` | validator startup requires its control socket |
| Price feeder | `outbe-feeder` | submits oracle votes |
| Projection store | `offchain-storage.toml` | RocksDB by default; MongoDB requires a replica set |

## Storage configuration

Node and SnapshotExporter share `validator-N/offchain-storage.toml`. New bundles
select RocksDB with `data/offchain` and `ocomp/domain-v1/exporter-v1/rocksdb-secondary`,
relative to that TOML. There is one node-owned primary and an exporter secondary
per protocol bundle. Both processes must run on the same host.

To select MongoDB when generating a bundle, set `offchain_storage.backend: mongodb`
in the network YAML. The generator creates per-validator databases and a managed
local replica-set script. Override `offchain_storage.mongodb.uri` for an external
replica set; that service is managed by its operator. A custom `mongodb.database`
is a prefix and receives `_validator_N`. Inspect the resulting TOML
before launching. Runtime backend changes require editing that file and restarting
both processes. Existing data is not migrated when the backend changes.

Regeneration preserves existing TOML bytes, including operator settings. The old
`projection.mongodb-*`, `projection.start-block`, and Mongo runtime environment
variables are removed. The node accepts `--projection.storage-config`; the exporter
reads `OUTBE_OCOMP_STORAGE_CONFIG`.

## Notes

- The OCOMP Supervisor is the node-owned ExEx. `start-all.sh` waits for its
  embedded registration endpoint, then starts only the external SnapshotExporter
  and Worker clients over loopback. The SnapshotExporter reads the node's
  projection through an independent read session. RocksDB uses a local secondary
  directory per protocol bundle; MongoDB uses primary/majority reads. Durable discovery authority lives
  under its local spool; ZeroMQ on the separately allocated loopback control port
  carries only fixed-size OfferRef/AckRef values.
- The embedded OCOMP Supervisor signs its submissions with `ocomp-evm-key.hex`,
  which defaults to a copy of the validator's own EVM key. To use a dedicated
  operational key, replace that file and register it on-chain with
  `outbe-cli validator delegate ocomp <address>`.
- An OCOMP successor is installed as `protocol-bundles-v1/<hash>.ocb1` before
  its Update proposal. Put both hashes in `validator-N/ocomp-bundles.env`, put
  the successor hash in `validator-N/ocomp-successor.env`, restart the Node and
  SnapshotExporter before the proposal, and start
  `outbe-ocomp-successor-worker@N`. Do not restart anything at activation.
- `reth-bootnodes.txt` pins each machine's reth identity:
{bootnode_lines}
- Re-running `create_genesis.py` without the pinned `timestamp:` produces a
  different genesis hash and invalidates the OCOMP registrations. Keep the
  timestamp that is now in your yaml.
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def render(
    *,
    config: dict[str, Any],
    validators: list[dict[str, Any]],
    genesis_path: Path,
    keys_dir: Path,
    repo_root: Path,
) -> None:
    output_dir = genesis_path.parent
    # Paths as they will exist on the target machines. They default to this
    # workstation's layout so a single-host trial run works unchanged.
    base_dir = str(config.get("remote_base_dir", output_dir))
    remote_keys_dir = str(config.get("remote_keys_dir", keys_dir))

    enodes = []
    for index, validator in enumerate(validators):
        directory = keys_dir / f"validator-{index}"
        host = validator["p2p_address"].rsplit(":", 1)[0]
        node_id = ensure_reth_p2p_secret(directory)
        ensure_ocomp_evm_key(directory)
        enodes.append(
            f"enode://{node_id}@{format_enode_host(host)}:{port_of(config, 'reth_p2p_port')}"
        )
    (output_dir / "reth-bootnodes.txt").write_text("\n".join(enodes) + "\n")
    shutil.copy2(Path(__file__).with_name("offchain_storage.py"), output_dir / "offchain_storage.py")
    identity = ocomp_identity(genesis_path, keys_dir)
    bundle_catalog = output_dir / "protocol-bundles-v1"
    bundle_catalog.mkdir(parents=True, exist_ok=True)
    initial_catalog_bundle = bundle_catalog / (
        identity["protocol_bundle_hash"].removeprefix("0x") + ".ocb1"
    )
    shutil.copy2(output_dir / "protocol-bundle-v1.ocb1", initial_catalog_bundle)

    for index, validator in enumerate(validators):
        directory = output_dir / f"validator-{index}"
        host, _, consensus_port = validator["p2p_address"].rpartition(":")
        ocomp_endpoint_port = embedded_ocomp_endpoint_port(config, int(consensus_port))

        storage = ensure_storage(directory / "offchain-storage.toml", storage_settings(
            config, database=f"outbe_projection_validator_{index}", validator_index=index,
            mongo_uri=f"mongodb://127.0.0.1:{port_of(config, 'mongodb_port')}/?replicaSet=rs0",
        ))
        if storage["backend"] == "mongodb":
            write_script(directory / "run-mongodb.sh", mongodb_script(config=config, index=index))
        write_script(directory / "run-storage.sh", storage_script(index=index, base_dir=base_dir, mongo_uri=f"mongodb://127.0.0.1:{port_of(config, 'mongodb_port')}/?replicaSet=rs0"))
        write_script(
            directory / "run-enclave.sh",
            enclave_script(config=config, index=index, base_dir=base_dir),
        )
        write_script(
            directory / "run-radicle.sh",
            radicle_script(
                config=config,
                index=index,
                host=host,
                keys_dir=remote_keys_dir,
                repo_root=str(repo_root),
            ),
        )
        write_script(
            directory / "run-node.sh",
            node_script(
                config=config,
                index=index,
                base_dir=base_dir,
                keys_dir=remote_keys_dir,
                repo_root=str(repo_root),
                consensus_port=int(consensus_port),
                host=host,
                identity=identity,
            ),
        )
        write_script(
            directory / "run-feeder.sh",
            feeder_script(config=config, index=index, base_dir=base_dir, repo_root=str(repo_root)),
        )
        (directory / "Caddyfile").write_text(caddyfile(config=config, host=host))
        write_script(
            directory / "preflight.sh",
            preflight_script(
                config=config,
                base_dir=base_dir,
                index=index,
            ),
        )
        write_script(
            directory / "install-caddy.sh",
            caddy_install_script(config=config, base_dir=base_dir, index=index),
        )
        write_script(
            directory / "run-ocomp-exporter.sh",
            ocomp_exporter_script(
                config=config,
                index=index,
                base_dir=base_dir,
                identity=identity,
                ocomp_endpoint_port=ocomp_endpoint_port,
            ),
        )
        write_script(
            directory / "run-ocomp-worker.sh",
            ocomp_worker_script(
                config=config,
                index=index,
                base_dir=base_dir,
                identity=identity,
                ocomp_endpoint_port=ocomp_endpoint_port,
            ),
        )
        write_script(
            directory / "run-ocomp-successor-worker.sh",
            ocomp_successor_worker_script(
                config=config,
                index=index,
                base_dir=base_dir,
                identity=identity,
                ocomp_endpoint_port=ocomp_endpoint_port,
            ),
        )
        (directory / "ocomp-bundles.env").write_text(
            f'OCOMP_PROTOCOL_BUNDLE_HASHES={identity["protocol_bundle_hash"]}\n'
        )
        (directory / "ocomp-active.env").write_text(
            f'OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH={identity["protocol_bundle_hash"]}\n'
        )
        signer_key = (
            (keys_dir / f"validator-{index}" / "evm-key.hex")
            .read_text()
            .strip()
            .removeprefix("0x")
        )
        feeder_path = directory / "feeder.toml"
        feeder_path.write_text(
            feeder_config(
                config=config, index=index, validator=validator, signer_key=signer_key
            )
        )
        feeder_path.chmod(0o600)
        write_script(
            directory / "start-all.sh",
            start_all_script(
                config=config,
                index=index,
                base_dir=base_dir,
                ocomp_endpoint_port=ocomp_endpoint_port,
            ).replace("{TEE_PORT}", str(port_of(config, "tee_enclave_port"))),
        )
        write_script(directory / "stop-all.sh", stop_all_script(index=index, base_dir=base_dir))

    stage_signed_enclave(config=config, output_dir=output_dir)
    write_systemd_units(output_dir, base_dir)

    build_distribution(
        output_dir=output_dir,
        validators=validators,
        keys_dir=keys_dir,
        base_dir=base_dir,
    )

    (output_dir / "DEPLOY.md").write_text(
        deploy_markdown(
            config=config,
            validators=validators,
            base_dir=base_dir,
            keys_dir=remote_keys_dir,
            local_keys_dir=keys_dir,
            enodes=enodes,
        )
    )
