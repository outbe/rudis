#!/usr/bin/env python3
"""Create a complete Outbe genesis.json from one network.yaml.

The yaml carries the minimum: which machines run the founding validators and
where their key material lives. Everything else - public keys, Radicle node
ids, OCOMP registrations, precompile storage, the OCOMP and TEE manifests -
is derived from the key directory and written into the genesis in one run.

    python3 scripts/create_genesis.py network.yaml

    chain_id: 424242
    keys_dir: ./keys          # keys_dir/validator-N/ per founder
    validators:
      - 10.0.0.1
      - 10.0.0.2
      - 10.0.0.3
      - 10.0.0.4
    tee:
      mode: gramine-direct-dev

Each keys_dir/validator-N/ is what `outbe-keygen validator` produces:
signing-key.hex (BLS), evm-key.hex, radicle/keys/radicle.pub, and optionally
ocomp-registration-v1.ocb1. A missing OCOMP registration is generated here:
its proof of possession signs the seeded genesis hash, which exists only
after seeding, so it cannot be produced before this run.

See scripts/network.example.yaml for every optional parameter and its
default. The yaml dialect is a strict subset (nested mappings, lists of
scalars, lists of flat mappings, ints, booleans, quoted/plain strings, `#`
comments); anything else is a hard error naming the line.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

sys.path.insert(0, str(SCRIPT_DIR))
import launch_bundle  # noqa: E402  (sibling module, path set just above)

# Canonical production baseline: every protocol parameter a network.yaml does not set comes
# from this file, so the defaults have exactly one home - and it is the same
# yaml format, readable and runnable on its own.
BASE_PROFILE_PATH = SCRIPT_DIR / "testnet.yaml"

DEFAULT_CHAIN_ID = 424242
# Devnet and Testnet may select either `gramine-direct-dev` or `dcap-required`.
# Mainnet requires `dcap-required`. The selected mode is bound into the genesis policy
# and cannot change through successor-policy activation.
DEVNET_CHAIN_ID = 424242
TESTNET_CHAIN_ID = 70860602
MAINNET_CHAIN_ID = 676
NETWORK_IDENTITIES = {
    "devnet": (DEVNET_CHAIN_ID, "outbe-devnet-1"),
    "testnet": (TESTNET_CHAIN_ID, "rudis-rehearsal"),
    "mainnet": (MAINNET_CHAIN_ID, "outbe-mainnet-1"),
}
DEFAULT_GAS_LIMIT = "0x1c9c380"
DEFAULT_EPOCH_LENGTH_BLOCKS = 300
DEFAULT_DKG_PREPARE_WINDOW_BLOCKS = 30
DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS = 30
DEFAULT_CONSENSUS_P2P_PORT = 30400
DEFAULT_PREFUND_COEN_UNITS = 10_000 * 10**18
FOUNDER_COUNT = 4

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# Protocol sections forwarded to the seeder, deep-merged over the baseline.
SEED_SECTIONS = (
    # Protocol timings. seed_genesis copies these into config.outbeProtocol,
    # where the runtime reads the Metadosis day windows and the OCOMP vote
    # window from; leaving them out means the chain runs on its built-in
    # defaults, which is rarely what a devnet or a test network wants.
    "protocol_constants",
    "balance",
    "staking",
    "rewards",
    "validator_set",
    "radicle_registry",
    "metadosis",
    "oracle",
    "gems",
    "tributes",
    "intex_factory",
    "gem_profile",
    "vault_router",
    "contracts",
    "tee_policy",
)

TOP_LEVEL_KEYS = {
    "offchain_storage",
    "network",
    "validators",
    "keys_dir",
    "chain_id",
    "tee",
    "output",
    "chain_binary",
    "keygen_binary",
    "consensus_p2p_port",
    "gas_limit",
    "timestamp",
    "epoch_length_blocks",
    "dkg_prepare_window_blocks",
    "dkg_activation_grace_blocks",
    "prefund_coen_units",
    "worldwide_day",
    "fresh_metadosis",
    "contracts_dir",
    "canon_dir",
    "enclave_image",
    "enclave_dir",
    "enclave_runner",
    "enclave_sgx",
    "signed_enclave_dir",
    "allow_stale_timestamp",
    "node_binary",
    "ocomp_binary",
    "radicle_binary",
    "radicle_external_inbound_reserve",
    "feeder_binary",
    "remote_base_dir",
    "remote_keys_dir",
    "price_provider",
    "public_rpc_port",
    "public_radicle_status_port",
    "price_feed_rest",
    "price_feed_websocket",
    *launch_bundle.DEFAULT_PORTS,
    *SEED_SECTIONS,
}

TEE_KEYS = {
    "mode",
    "mrenclave",
    "mrsigner",
    "isv_prod_id",
    "minimum_isv_svn",
    "minimum_tcb_evaluation_data_number",
}


# ---------------------------------------------------------------------------
# Strict-subset YAML parser
# ---------------------------------------------------------------------------
#
# Supported: nested mappings, lists of scalars, lists of flat mappings, ints,
# booleans, quoted and plain strings, `#` comments, and the empty literals `[]`
# and `{}`. Everything else is a hard error naming the line, so a config never
# parses into something other than what it looks like. PyYAML is deliberately
# not required: these scripts run on operator machines and in offline genesis
# ceremonies where installing a package is friction.


class YamlError(ValueError):
    def __init__(self, path: Path, line_no: int, message: str):
        super().__init__(f"{path}:{line_no}: {message}")


def _parse_scalar(raw: str, *, path: Path, line_no: int) -> Any:
    raw = raw.strip()
    if not raw:
        raise YamlError(path, line_no, "empty value; write an explicit scalar")
    if raw[0] in "\"'":
        quote = raw[0]
        if len(raw) < 2 or raw[-1] != quote or raw.count(quote) != 2:
            raise YamlError(path, line_no, "unterminated or nested quotes")
        return raw[1:-1]
    if raw == "[]":
        return []
    if raw == "{}":
        return {}
    for marker in ("&", "*", "|", ">", "{", "[", "%", "@", "`"):
        if raw.startswith(marker):
            raise YamlError(
                path,
                line_no,
                f"unsupported YAML construct {marker!r}; use plain key: value "
                f"(only the empty literals [] and {{}} are accepted inline)",
            )
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw in ("null", "~"):
        raise YamlError(path, line_no, "null values are not supported; omit the key")
    try:
        return int(raw, 10)
    except ValueError:
        return raw


def _split_key(line: str, *, path: Path, line_no: int) -> tuple[str, str]:
    # A key ends at the first ':' followed by a space or end of line, so hex
    # values and `host:port` entries stay unambiguous.
    for pos, char in enumerate(line):
        if char == ":" and (pos + 1 == len(line) or line[pos + 1] == " "):
            key = line[:pos].strip()
            if not key:
                raise YamlError(path, line_no, "empty mapping key")
            if key[0] in "\"'":
                parsed = _parse_scalar(key, path=path, line_no=line_no)
                if not isinstance(parsed, str):
                    raise YamlError(path, line_no, "mapping key must be a string")
                key = parsed
            return key, line[pos + 1 :].strip()
    raise YamlError(path, line_no, "expected `key: value` or `key:`")


def _strip_comment(line: str) -> str:
    in_quote: str | None = None
    for pos, char in enumerate(line):
        if in_quote:
            if char == in_quote:
                in_quote = None
        elif char in "\"'":
            in_quote = char
        elif char == "#" and (pos == 0 or line[pos - 1] in " \t"):
            return line[:pos]
    return line


def _looks_like_mapping(body: str) -> bool:
    for pos, char in enumerate(body):
        if char == ":" and (pos + 1 == len(body) or body[pos + 1] == " "):
            return True
    return False


def load_yaml(path: Path) -> dict[str, Any]:
    """Parse the supported YAML subset into plain dicts/lists/scalars."""
    numbered: list[tuple[int, int, str]] = []  # (line_no, indent, content)
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "\t" in raw:
            raise YamlError(path, line_no, "tabs are not allowed; use spaces")
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        numbered.append((line_no, indent, stripped.strip()))

    pos = 0

    def parse_mapping(indent: int) -> dict[str, Any]:
        nonlocal pos
        mapping: dict[str, Any] = {}
        while pos < len(numbered):
            line_no, line_indent, content = numbered[pos]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise YamlError(path, line_no, "unexpected indentation")
            if content.startswith("- "):
                raise YamlError(
                    path, line_no, "list item where a mapping key was expected"
                )
            key, rest = _split_key(content, path=path, line_no=line_no)
            if key in mapping:
                raise YamlError(path, line_no, f"duplicate key {key!r}")
            pos += 1
            if rest:
                mapping[key] = _parse_scalar(rest, path=path, line_no=line_no)
                continue
            if pos >= len(numbered) or numbered[pos][1] <= indent:
                raise YamlError(path, line_no, f"key {key!r} has no value")
            child_indent = numbered[pos][1]
            if numbered[pos][2].startswith("- "):
                mapping[key] = parse_list(child_indent)
            else:
                mapping[key] = parse_mapping(child_indent)
        return mapping

    def parse_list(indent: int) -> list[Any]:
        nonlocal pos
        items: list[Any] = []
        while pos < len(numbered):
            line_no, line_indent, content = numbered[pos]
            if line_indent < indent:
                break
            if line_indent > indent or not content.startswith("- "):
                raise YamlError(path, line_no, "inconsistent list indentation")
            body = content[2:].strip()
            if not body:
                raise YamlError(path, line_no, "empty list item")
            pos += 1
            if not _looks_like_mapping(body):
                items.append(_parse_scalar(body, path=path, line_no=line_no))
                continue
            # Flat mapping item: `- key: value` plus continuation lines
            # indented past the dash.
            key, rest = _split_key(body, path=path, line_no=line_no)
            if not rest:
                raise YamlError(path, line_no, f"list item key {key!r} has no value")
            item: dict[str, Any] = {key: _parse_scalar(rest, path=path, line_no=line_no)}
            item_indent = indent + 2
            while pos < len(numbered):
                next_no, next_indent, next_content = numbered[pos]
                if next_indent != item_indent or next_content.startswith("- "):
                    break
                next_key, next_rest = _split_key(
                    next_content, path=path, line_no=next_no
                )
                if next_key in item:
                    raise YamlError(path, next_no, f"duplicate key {next_key!r}")
                if not next_rest:
                    raise YamlError(
                        path,
                        next_no,
                        "nested structures inside list items are not supported",
                    )
                item[next_key] = _parse_scalar(next_rest, path=path, line_no=next_no)
                pos += 1
            items.append(item)
        return items

    result = parse_mapping(0)
    if pos != len(numbered):
        raise YamlError(path, numbered[pos][0], "could not parse from this line on")
    return result


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def deep_merge(base: Any, override: Any) -> Any:
    """Scalars and lists replace; mappings merge key by key."""
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = deep_merge(base.get(key), value) if key in base else value
        return merged
    return override


def validate_config(config: dict[str, Any]) -> None:
    unknown = sorted(set(config) - TOP_LEVEL_KEYS)
    if unknown:
        raise ValueError(
            f"unknown key(s): {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(TOP_LEVEL_KEYS))}"
        )
    launch_bundle.storage_settings(config, database="validation", mongo_uri="mongodb://localhost")
    hosts = config.get("validators")
    if not isinstance(hosts, list) or len(hosts) != FOUNDER_COUNT:
        raise ValueError(
            f"`validators` must list exactly {FOUNDER_COUNT} hosts "
            f"(OCOMP V1 fixes the founding committee at four)"
        )
    for index, host in enumerate(hosts):
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"validators[{index}] must be a host or IP string")
    if "keys_dir" not in config:
        raise ValueError("`keys_dir` is required: it holds validator-N/ key material")
    tee = config.get("tee")
    if not isinstance(tee, dict):
        raise ValueError("`tee` section with `mode` is required")
    unknown_tee = sorted(set(tee) - TEE_KEYS)
    if unknown_tee:
        raise ValueError(f"unknown tee key(s): {', '.join(unknown_tee)}")
    network, chain_id, _ = network_identity(config)
    if "enclave_sgx" in config and not isinstance(config["enclave_sgx"], bool):
        raise ValueError("enclave_sgx must be a boolean")
    mode = tee.get("mode")
    if mode not in ("gramine-direct-dev", "dcap-required"):
        raise ValueError("tee.mode must be gramine-direct-dev or dcap-required")
    if network == "mainnet":
        if mode != "dcap-required":
            raise ValueError("Mainnet requires tee.mode dcap-required")
        if "protocol_constants" in config:
            raise ValueError(
                "Mainnet forbids protocol_constants overrides and uses canonical production defaults"
            )
        endpoint = str(config.get("price_feed_rest", ""))
        if not endpoint:
            raise ValueError("Mainnet requires an explicit production price feed REST endpoint")
        if "testnet" in endpoint.lower():
            raise ValueError("Mainnet may not use a testnet price endpoint")
    if mode == "gramine-direct-dev" and chain_id not in (
        DEVNET_CHAIN_ID,
        TESTNET_CHAIN_ID,
    ):
        raise ValueError(
            f"tee.mode gramine-direct-dev requires the devnet or testnet chain id "
            f"({DEVNET_CHAIN_ID} or {TESTNET_CHAIN_ID}), not {chain_id}"
        )
    if mode == "dcap-required":
        if chain_id not in (DEVNET_CHAIN_ID, TESTNET_CHAIN_ID, MAINNET_CHAIN_ID):
            raise ValueError(
                f"tee.mode dcap-required requires a canonical Outbe chain id, not {chain_id}"
            )
        image = str(config.get("enclave_image", ""))
        if re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image) is None:
            raise ValueError(
                "tee.mode dcap-required needs `enclave_image` pinned to an immutable "
                "digest (name@sha256:<64 lowercase hex>), not a mutable tag"
            )

    # Every endpoint the launch scripts bind, on one machine.
    ports = {
        name: port_value
        for name in launch_bundle.DEFAULT_PORTS
        if (port_value := int(config.get(name, launch_bundle.DEFAULT_PORTS[name])))
    }
    consensus_port = int(config.get("consensus_p2p_port", DEFAULT_CONSENSUS_P2P_PORT))
    ports["consensus_p2p_port"] = consensus_port
    ports["ocomp_embedded_port"] = launch_bundle.embedded_ocomp_endpoint_port(
        config, consensus_port
    )
    seen: dict[int, str] = {}
    for name, port_value in sorted(ports.items()):
        if not 1 <= port_value <= 65535:
            raise ValueError(f"{name} is outside 1..65535: {port_value}")
        if port_value in seen:
            raise ValueError(
                f"port collision: {seen[port_value]} and {name} both use {port_value}"
            )
        seen[port_value] = name


def network_identity(config: dict[str, Any]) -> tuple[str, int, str]:
    chain_id = int(config.get("chain_id", DEFAULT_CHAIN_ID))
    inferred = next(
        (name for name, (known_id, _) in NETWORK_IDENTITIES.items() if known_id == chain_id),
        None,
    )
    if inferred is None:
        raise ValueError(f"unknown Outbe chain id {chain_id}")
    requested = config.get("network")
    if requested is None:
        if inferred == "mainnet":
            raise ValueError("Mainnet chain id 676 requires explicit `network: mainnet`")
        requested = inferred
    if requested not in NETWORK_IDENTITIES:
        raise ValueError(f"unknown Outbe network {requested!r}")
    expected_id, chain_name = NETWORK_IDENTITIES[requested]
    if chain_id != expected_id:
        raise ValueError(
            f"{requested} requires chain id {expected_id}, not {chain_id}"
        )
    return requested, chain_id, chain_name


# ---------------------------------------------------------------------------
# Key material discovery
# ---------------------------------------------------------------------------


def _point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
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


def _point_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    if scalar <= 0 or scalar >= SECP256K1_N:
        raise ValueError("secp256k1 scalar out of range")
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise ValueError("invalid secp256k1 scalar produced the point at infinity")
    return result


def evm_address_from_key_file(path: Path, keccak256) -> str:
    raw = path.read_text().strip().removeprefix("0x")
    if len(raw) != 64:
        raise ValueError(f"{path} must hold a 32-byte secp256k1 key in hex")
    x, y = _point_mul(int(raw, 16), SECP256K1_G)
    public_key = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + keccak256(public_key)[12:].hex()


def radicle_node_id_from_public_key(path: Path) -> str:
    try:
        algorithm, encoded, *_ = path.read_text().split()
    except (OSError, ValueError) as error:
        raise ValueError(f"invalid Radicle public key {path}") from error
    if algorithm != "ssh-ed25519":
        raise ValueError(f"Radicle public key {path} must use ssh-ed25519")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValueError(f"invalid Radicle public key encoding in {path}") from error

    def field(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(payload):
            raise ValueError(f"truncated Radicle public key {path}")
        length = int.from_bytes(payload[offset : offset + 4], "big")
        start, end = offset + 4, offset + 4 + length
        if end > len(payload):
            raise ValueError(f"truncated Radicle public key {path}")
        return payload[start:end], end

    kind, offset = field(0)
    node_id, offset = field(offset)
    if kind != b"ssh-ed25519" or len(node_id) != 32 or offset != len(payload):
        raise ValueError(f"invalid Ed25519 Radicle public key {path}")
    return node_id.hex()


def bls_public_key(keygen_binary: str, signing_key: Path) -> str:
    """Ask outbe-keygen for the MinPk public key; the BLS curve maths lives in
    the binary and is not reimplemented here."""
    result = subprocess.run(
        [keygen_binary, "show-pubkey", "--key", str(signing_key)],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("public key:"):
            value = line.split(":", 1)[1].strip().removeprefix("0x")
            if len(value) != 96:
                raise ValueError(f"{signing_key}: BLS public key is not 48 bytes")
            return value
    raise ValueError(f"outbe-keygen printed no public key for {signing_key}")


def discover_validators(
    *,
    config: dict[str, Any],
    keys_dir: Path,
    keygen_binary: str,
    keccak256,
) -> list[dict[str, Any]]:
    """Build the founder manifest from the yaml hosts plus the key directory."""
    default_port = int(config.get("consensus_p2p_port", DEFAULT_CONSENSUS_P2P_PORT))
    validators = []
    for index, entry in enumerate(config["validators"]):
        # Founders sit on separate machines, so they share one port unless an
        # entry pins its own as `host:port`.
        host, _, explicit_port = str(entry).strip().partition(":")
        port = int(explicit_port) if explicit_port else default_port
        directory = keys_dir / f"validator-{index}"
        if not directory.is_dir():
            raise ValueError(f"missing key directory for validator {index}: {directory}")
        signing_key = directory / "signing-key.hex"
        evm_key = directory / "evm-key.hex"
        radicle_pub = directory / "radicle" / "keys" / "radicle.pub"
        for required in (signing_key, evm_key, radicle_pub):
            if not required.is_file():
                raise ValueError(
                    f"validator {index}: {required} not found; generate the bundle "
                    f"with `outbe-keygen validator --output-dir {directory}`"
                )
        validators.append(
            {
                "address": evm_address_from_key_file(evm_key, keccak256),
                "public_key": bls_public_key(keygen_binary, signing_key),
                "radicle_node_id": "0x" + radicle_node_id_from_public_key(radicle_pub),
                "p2p_address": f"{host}:{port}",
            }
        )
    return validators


# ---------------------------------------------------------------------------
# Genesis assembly
# ---------------------------------------------------------------------------


# A genesis carries a TEE lease that starts counting at its own timestamp. Boot
# a chain from a genesis stamped far in the past and block 1 dies on
# `requested lease is already expired` - a runtime revert that says nothing
# about the real cause. Refuse to build one instead.
MAX_GENESIS_AGE_SECONDS = 6 * 60 * 60


def build_base_genesis(config: dict[str, Any]) -> dict[str, Any]:
    timestamp = int(config.get("timestamp", int(time.time())))
    age = int(time.time()) - timestamp
    if age > MAX_GENESIS_AGE_SECONDS and not config.get("allow_stale_timestamp"):
        raise ValueError(
            f"`timestamp: {timestamp}` is {age // 3600}h in the past. The TEE lease "
            f"runs from the genesis timestamp, so block 1 would fail with "
            f"'requested lease is already expired'. Drop the key to stamp now, or "
            f"set `allow_stale_timestamp: true` to reproduce an existing genesis."
        )
    # An explicit genesisTime pins the ValidatorSet epoch start; without it the
    # seeder falls back to the wall clock and the genesis hash - which the
    # OCOMP registrations sign - changes on every run.
    genesis_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "config": {
            "chainId": int(config.get("chain_id", DEFAULT_CHAIN_ID)),
            "genesisTime": genesis_time,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "mergeNetsplitBlock": 0,
            "terminalTotalDifficulty": 0,
            "terminalTotalDifficultyPassed": True,
            "shanghaiTime": 0,
            "cancunTime": 0,
            "pragueTime": 0,
            "epochLengthBlocks": int(
                config.get("epoch_length_blocks", DEFAULT_EPOCH_LENGTH_BLOCKS)
            ),
            "dkgPrepareWindowBlocks": int(
                config.get(
                    "dkg_prepare_window_blocks", DEFAULT_DKG_PREPARE_WINDOW_BLOCKS
                )
            ),
            "dkgActivationGraceBlocks": int(
                config.get(
                    "dkg_activation_grace_blocks", DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS
                )
            ),
        },
        "nonce": "0x0",
        "timestamp": hex(timestamp),
        "extraData": "0x",
        "gasLimit": str(config.get("gas_limit", DEFAULT_GAS_LIMIT)),
        "difficulty": "0x0",
        "mixHash": "0x" + "00" * 32,
        "coinbase": "0x" + "00" * 20,
        "alloc": {},
    }


def prefund_validators(
    genesis: dict[str, Any], config: dict[str, Any], validators: list[dict[str, Any]]
) -> None:
    prefund = int(config.get("prefund_coen_units", DEFAULT_PREFUND_COEN_UNITS))
    if prefund == 0:
        return
    alloc = genesis.setdefault("alloc", {})
    for validator in validators:
        alloc.setdefault(validator["address"], {}).setdefault("balance", hex(prefund))


def build_seed(config: dict[str, Any]) -> dict[str, Any]:
    """Protocol sections for the seeder: the baseline profile with this
    network's overrides merged on top."""
    baseline = load_yaml(BASE_PROFILE_PATH)
    seed = {
        section: baseline[section] for section in SEED_SECTIONS if section in baseline
    }
    for section in SEED_SECTIONS:
        if section in config:
            seed[section] = deep_merge(seed.get(section), config[section])
    return seed


def load_seed_genesis_module():
    spec = importlib.util.spec_from_file_location(
        "seed_genesis", SCRIPT_DIR / "seed_genesis.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {SCRIPT_DIR / 'seed_genesis.py'}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_seed_stage(
    *,
    module,
    work_dir: Path,
    base_genesis: dict[str, Any],
    seed: dict[str, Any],
    validators: list[dict[str, Any]],
    config: dict[str, Any],
    quiet: bool = False,
) -> Path:
    """Render the declarative config into a seeded genesis.

    The calculation itself lives in seed_genesis.apply_seed: storage slot
    layout, keccak-derived mapping keys, and the active WorldwideDay resolved
    against the genesis timestamp. It is called directly with in-memory values,
    so nothing round-trips through an intermediate seed file.
    """
    # The seeded OFFERING worldwide-day must track the genesis date, or the
    # runtime derives a different active day and metadosis wedges. An explicit
    # value always wins, including alongside fresh_metadosis: the two do
    # different things - the day retargets the S-curve peak and NOD references,
    # fresh_metadosis drops the pre-seeded OFFERING day itself.
    if "worldwide_day" in config:
        # Present-but-None means the caller decided there is no retarget, which
        # is what seed_genesis.py's CLI passes when `--worldwide-day` is absent.
        raw_day = config["worldwide_day"]
        worldwide_day = None if raw_day is None else int(raw_day)
    elif config.get("fresh_metadosis"):
        worldwide_day = None
    else:
        timestamp = int(base_genesis["timestamp"], 16)
        worldwide_day = module.timestamp_to_utc_date_key(timestamp)

    seeded = deepcopy(base_genesis)
    call = lambda: module.apply_seed(  # noqa: E731
        seeded,
        seed,
        validators,
        contracts_dir=str(config.get("contracts_dir", SCRIPT_DIR / "contracts")),
        canon_dir=str(config.get("canon_dir", SCRIPT_DIR / "canon")),
        worldwide_day=worldwide_day,
        fresh_metadosis=bool(config.get("fresh_metadosis")),
    )
    if quiet:
        with redirect_stdout(io.StringIO()):
            call()
    else:
        call()

    # The OCOMP and TEE stages are the node binary's own subcommands, so the
    # seeded genesis reaches them as a file.
    seeded_path = work_dir / "genesis.seeded.json"
    seeded_path.write_text(json.dumps(seeded, indent=2))
    (work_dir / "validators.json").write_text(json.dumps(validators, indent=2))
    return seeded_path


def seed_genesis_from_config(
    *,
    base_genesis: dict[str, Any],
    seed: dict[str, Any],
    validators: list[dict[str, Any]],
    contracts_dir: str,
    canon_dir: str | None = None,
    worldwide_day: int | None = None,
    fresh_metadosis: bool = False,
) -> dict[str, Any]:
    """Seed one genesis from an explicit profile, without the OCOMP/TEE stages.

    This is the entry point `seed_genesis.py` uses so its CLI - the one the e2e
    harness and the localnet scripts call - creates its genesis through exactly
    the same code path as a yaml-driven deployment. The profile is used as
    given: callers that want the baseline merged do that themselves, so a
    partial profile never silently gains sections it did not ask for.
    """
    module = load_seed_genesis_module()
    # `worldwide_day` is set unconditionally, including to None: this caller
    # states the day explicitly rather than letting it be derived from the
    # genesis timestamp, so `--worldwide-day`-less runs keep the profile's own
    # authored day exactly as they did before.
    settings: dict[str, Any] = {
        "contracts_dir": contracts_dir,
        "worldwide_day": worldwide_day,
    }
    if canon_dir is not None:
        settings["canon_dir"] = canon_dir
    if fresh_metadosis:
        settings["fresh_metadosis"] = True
    with tempfile.TemporaryDirectory(prefix="outbe-seed-") as tmp:
        seeded_path = run_seed_stage(
            module=module,
            work_dir=Path(tmp),
            base_genesis=base_genesis,
            seed=seed,
            validators=validators,
            config=settings,
        )
        return json.loads(seeded_path.read_text())


def resolve_binary(config: dict[str, Any], key: str, name: str) -> str:
    explicit = config.get(key)
    candidates = (
        [Path(str(explicit)), REPO_ROOT / str(explicit)]
        if explicit
        else [
            REPO_ROOT / "target" / "release" / name,
            REPO_ROOT / "target" / "debug" / name,
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise ValueError(f"{name} binary not found; build it or set `{key}` in the yaml")


def ensure_ocomp_registrations(
    *,
    chain_binary: str,
    keygen_binary: str,
    work_dir: Path,
    seeded_genesis: Path,
    keys_dir: Path,
    validators: list[dict[str, Any]],
    allow_generation: bool = True,
) -> Path:
    """Collect one registration per founder into a staging directory, minting
    the missing ones. The proof of possession signs the seeded genesis hash, so
    a registration can only be produced once that hash exists."""
    validate_ocomp_registration_inventory(
        keys_dir=keys_dir,
        validator_count=len(validators),
        allow_generation=allow_generation,
    )
    bindings_path = work_dir / "ocomp-bindings-v1.json"
    subprocess.run(
        [
            chain_binary,
            "ocomp",
            "bindings",
            "--input",
            str(seeded_genesis),
            "--validators",
            str(work_dir / "validators.json"),
            "--output",
            str(bindings_path),
        ],
        check=True,
    )
    bindings = json.loads(bindings_path.read_text())
    chain_id, genesis_hash = bindings["chainId"], bindings["genesisHash"]

    staging = work_dir / "registrations"
    minted = False
    for index, validator in enumerate(validators):
        source_dir = keys_dir / f"validator-{index}"
        registration = source_dir / "ocomp-registration-v1.ocb1"
        # Marker recording which genesis hash a registration minted here signs.
        # A registration carried in from a validator's own machine has no
        # marker; the node binary validates that one when it installs it.
        marker = source_dir / "ocomp-registration-v1.genesis-hash"
        if registration.is_file():
            if marker.is_file() and marker.read_text().strip() != str(genesis_hash):
                raise SystemExit(
                    f"validator-{index}: {registration.name} signs genesis hash "
                    f"{marker.read_text().strip()}, but this run seeds "
                    f"{genesis_hash}.\n"
                    f"Either pin the original `timestamp:` in the yaml, or delete "
                    f"{registration} and {source_dir / 'ocomp-key-v1.hex'} on every "
                    f"validator to mint a fresh pair for this genesis."
                )
            continue
        print(f"  minting OCOMP registration for validator-{index}")
        subprocess.run(
            [
                keygen_binary,
                "ocomp",
                "--output-dir",
                str(source_dir),
                "--chain-id",
                str(chain_id),
                "--genesis-hash",
                str(genesis_hash),
                "--validator-address",
                validator["address"],
                "--consensus-bls-min-pk",
                "0x" + validator["public_key"],
            ],
            check=True,
            capture_output=True,
        )
        marker.write_text(f"{genesis_hash}\n")
        minted = True

    for index in range(len(validators)):
        destination = staging / f"validator-{index}"
        destination.mkdir(parents=True)
        shutil.copy2(
            keys_dir / f"validator-{index}" / "ocomp-registration-v1.ocb1",
            destination / "ocomp-registration-v1.ocb1",
        )
    if minted:
        print(
            f"  registrations signed genesis hash {genesis_hash}; pin "
            f"`timestamp: {int(json.loads(seeded_genesis.read_text())['timestamp'], 16)}` "
            f"in the yaml to reproduce this exact genesis"
        )
    return staging


def validate_ocomp_registration_inventory(
    *, keys_dir: Path, validator_count: int, allow_generation: bool
) -> None:
    if allow_generation:
        return
    missing = [
        index
        for index in range(validator_count)
        if not (keys_dir / f"validator-{index}" / "ocomp-registration-v1.ocb1").is_file()
    ]
    if missing:
        rendered = ", ".join(f"validator-{index}" for index in missing)
        raise ValueError(
            "Mainnet requires operator-provided OCOMP registration files; missing "
            + rendered
        )


def run_ocomp_stage(
    *,
    chain_binary: str,
    work_dir: Path,
    seeded_genesis: Path,
    registrations_dir: Path,
    protocol_bundle_output: Path,
    keys_dir: Path,
) -> Path:
    ocomp_genesis = work_dir / "genesis.ocomp.json"
    result = subprocess.run(
        [
            chain_binary,
            "ocomp",
            "genesis",
            "--input",
            str(seeded_genesis),
            "--validators",
            str(work_dir / "validators.json"),
            "--registrations-dir",
            str(registrations_dir),
            "--output",
            str(ocomp_genesis),
            "--protocol-bundle-output",
            str(protocol_bundle_output),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        if "does not match this genesis" in message:
            raise SystemExit(
                f"{message}\n\n"
                f"An OCOMP registration signs one exact genesis hash. This run "
                f"seeds a different one - most often because `timestamp:` is not "
                f"pinned in the yaml, so each run stamps the current time.\n"
                f"Pin the timestamp the registrations were minted for, or delete "
                f"ocomp-registration-v1.ocb1 and ocomp-key-v1.hex under "
                f"{keys_dir}/validator-*/ to mint a fresh pair for this genesis."
            )
        raise SystemExit(message or "outbe-chain ocomp genesis failed")
    print(result.stdout.strip())
    return ocomp_genesis


def run_tee_stage(
    *,
    chain_binary: str,
    ocomp_genesis: Path,
    output: Path,
    config: dict[str, Any],
) -> None:
    tee = config["tee"]
    cmd = [
        chain_binary,
        "tee",
        "genesis",
        "--input",
        str(ocomp_genesis),
        "--output",
        str(output),
        "--mode",
        str(tee["mode"]),
    ]
    dcap_options = {
        "--mrenclave": tee.get("mrenclave"),
        "--mrsigner": tee.get("mrsigner"),
        "--isv-prod-id": tee.get("isv_prod_id"),
        "--minimum-isv-svn": tee.get("minimum_isv_svn"),
        "--minimum-tcb-evaluation-data-number": tee.get(
            "minimum_tcb_evaluation_data_number"
        ),
    }
    if tee["mode"] == "dcap-required":
        missing = sorted(name for name, value in dcap_options.items() if value is None)
        if missing:
            raise ValueError(
                "tee.mode dcap-required needs exact release values: " + ", ".join(missing)
            )
        for name, value in dcap_options.items():
            cmd.extend([name, str(value)])
    elif any(value is not None for value in dcap_options.values()):
        raise ValueError("tee.mode gramine-direct-dev forbids DCAP measurement values")
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a complete Outbe genesis.json from one network.yaml"
    )
    parser.add_argument("config", type=Path, help="Path to network.yaml")
    parser.add_argument(
        "--output",
        type=Path,
        help="Output genesis path (default: `output` from the yaml, else ./genesis.json)",
    )
    args = parser.parse_args()

    config_path = args.config.resolve()
    config = load_yaml(args.config)
    validate_config(config)
    network, chain_id, chain_name = network_identity(config)

    def relative_to_config(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else config_path.parent / candidate

    keys_dir = relative_to_config(str(config["keys_dir"])).resolve()
    if not keys_dir.is_dir():
        raise SystemExit(f"keys_dir is not a directory: {keys_dir}")

    output = args.output or relative_to_config(str(config.get("output", "genesis.json")))
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing genesis: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    protocol_bundle_output = output.parent / "protocol-bundle-v1.ocb1"
    if protocol_bundle_output.exists():
        raise SystemExit(
            f"refusing to overwrite existing protocol bundle: {protocol_bundle_output}"
        )

    chain_binary = resolve_binary(config, "chain_binary", "outbe-chain")
    keygen_binary = resolve_binary(config, "keygen_binary", "outbe-keygen")
    module = load_seed_genesis_module()

    validators = discover_validators(
        config=config,
        keys_dir=keys_dir,
        keygen_binary=keygen_binary,
        keccak256=module.keccak256,
    )
    print("Founding validators:")
    for index, validator in enumerate(validators):
        print(f"  validator-{index}  {validator['p2p_address']}  {validator['address']}")
    print()

    base_genesis = build_base_genesis(config)
    prefund_validators(base_genesis, config, validators)
    seed = build_seed(config)

    with tempfile.TemporaryDirectory(prefix="outbe-genesis-") as tmp:
        work_dir = Path(tmp)
        seeded = run_seed_stage(
            module=module,
            work_dir=work_dir,
            base_genesis=base_genesis,
            seed=seed,
            validators=validators,
            config=config,
        )
        registrations_dir = ensure_ocomp_registrations(
            chain_binary=chain_binary,
            keygen_binary=keygen_binary,
            work_dir=work_dir,
            seeded_genesis=seeded,
            keys_dir=keys_dir,
            validators=validators,
            allow_generation=network != "mainnet",
        )
        ocomp_genesis = run_ocomp_stage(
            chain_binary=chain_binary,
            work_dir=work_dir,
            seeded_genesis=seeded,
            registrations_dir=registrations_dir,
            protocol_bundle_output=protocol_bundle_output,
            keys_dir=keys_dir,
        )
        try:
            run_tee_stage(
                chain_binary=chain_binary,
                ocomp_genesis=ocomp_genesis,
                output=output,
                config=config,
            )
        except BaseException:
            # A later stage failing must not leave the protocol bundle behind:
            # the next run refuses to overwrite it and the operator is stuck
            # with a half-written directory and no way forward.
            protocol_bundle_output.unlink(missing_ok=True)
            raise

    launch_bundle.render(
        config=config,
        validators=validators,
        genesis_path=output,
        keys_dir=keys_dir,
        repo_root=REPO_ROOT,
    )
    identity_path = output.parent / "network-identity.json"
    identity_path.write_text(
        json.dumps(
            {"network": network, "chainId": chain_id, "chainName": chain_name},
            indent=2,
        )
        + "\n"
    )

    print()
    print(f"genesis:         {output}")
    print(f"protocol bundle: {protocol_bundle_output}")
    print(f"bootnodes:       {output.parent / 'reth-bootnodes.txt'}")
    print(f"launch scripts:  {output.parent}/validator-N/")
    print(f"instructions:    {output.parent / 'DEPLOY.md'}")
    print(f"network identity:{identity_path}")


if __name__ == "__main__":
    main()
