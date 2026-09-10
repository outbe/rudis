#!/usr/bin/env python3
"""
Prepare a complete four-founder Outbe network bundle.

Inputs:
  - genesis.base.json: base chain config and initial alloc
  - seed-testnet.json or equivalent runtime seed config
  - validators.json: genesis validator public keys, EVM addresses, and consensus p2p addresses

Outputs:
  - genesis.json: seeded chain state with ValidatorSet/Staking/Rewards/precompile storage
    plus canonical block-1 OCOMP and TEE manifests
  - protocol-bundle-v1.ocb1 and per-validator OCOMP key/PoP registrations
  - reth-bootnodes.txt: stable Reth enodes for --bootnodes
  - validator-N/evm-key.hex: validator EVM key material when present in validators.json
  - validator-N/reth-p2p-secret.hex: stable Reth p2p node identity keys
  - commands/validator-N.sh: runnable node command per validator
  - commands/enclave-N.sh: matching Gramine enclave command per validator
  - network.md: human-readable launch plan with addresses, ports, and commands

OCOMP V1 requires exactly four founding validators with threshold 3. Generated
founders get fresh consensus identity, EVM, Reth and OCOMP keys. The permanent
offer key and threshold shares are created only by the live block-1 founding
ceremony; this tool deliberately does not precompute a conflicting DKG triplet.
Existing-validator mode requires the complete matching identity material; the
script never emits a knowingly partial launch command.
"""

from __future__ import annotations

import copy

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from offchain_storage import ensure as ensure_storage, load as load_storage, settings as storage_settings


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

DEFAULT_PREFUND_COEN_UNITS = 10_000 * 10**18
DEVNET_CHAIN_ID = 424242
TESTNET_CHAIN_ID = 70860602
MAINNET_CHAIN_ID = 676
NETWORK_IDENTITIES = {
    "devnet": (DEVNET_CHAIN_ID, "outbe-devnet-1"),
    "testnet": (TESTNET_CHAIN_ID, "rudis-rehearsal"),
    "mainnet": (MAINNET_CHAIN_ID, "outbe-mainnet-1"),
}
# OCOMP jobs can live for 1,868 blocks. The canonical localnet and retained
# final-artifact fixture use a 300-block epoch, so the fixed eight-epoch
# committee snapshot ring retains 7 * 300 = 2,100 blocks of history.
DEFAULT_EPOCH_LENGTH_BLOCKS = 300
DEFAULT_DKG_PREPARE_WINDOW_BLOCKS = 30
DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS = 30
DEFAULT_GAS_LIMIT = "0x1c9c380"


def resolve_network_profile(
    network: str | None, chain_id: int | None, tee_mode: str
) -> tuple[str, int, str]:
    if chain_id is None:
        if tee_mode == "dcap-required":
            raise ValueError("dcap-required requires an explicit --chain-id")
        chain_id = DEVNET_CHAIN_ID
    inferred = next(
        (name for name, (known_id, _) in NETWORK_IDENTITIES.items() if known_id == chain_id),
        None,
    )
    if inferred is None:
        raise ValueError(f"unknown Outbe chain id {chain_id}")
    if network is None:
        if inferred == "mainnet":
            raise ValueError("Mainnet chain id 676 requires --network mainnet")
        network = inferred
    if network not in NETWORK_IDENTITIES:
        raise ValueError(f"unknown Outbe network {network!r}")
    expected_id, chain_name = NETWORK_IDENTITIES[network]
    if chain_id != expected_id:
        raise ValueError(f"{network} requires chain id {expected_id}, not {chain_id}")
    if network == "mainnet" and tee_mode != "dcap-required":
        raise ValueError("Mainnet requires --tee-mode dcap-required")
    if tee_mode == "gramine-direct-dev" and network not in ("devnet", "testnet"):
        raise ValueError("gramine-direct-dev requires the devnet or testnet profile")
    if tee_mode == "dcap-required" and network not in (
        "devnet",
        "testnet",
        "mainnet",
    ):
        raise ValueError("dcap-required requires a canonical Outbe network profile")
    return network, chain_id, chain_name


def validate_mainnet_options(args: argparse.Namespace) -> None:
    forbidden = (
        ("generate_validators", "--generate-validators"),
        ("include_private_keys", "--include-private-keys"),
        ("use_local_defaults", "--use-local-defaults"),
        ("force_reth_secrets", "--force-reth-secrets"),
    )
    for attribute, option in forbidden:
        if getattr(args, attribute, None):
            raise ValueError(f"Mainnet forbids {option}")


def require_mainnet_ocomp_material(material_dir: Path, count: int) -> None:
    required = ("ocomp-key-v1.hex", "ocomp-registration-v1.ocb1")
    missing = [
        str(material_dir / f"validator-{index}" / name)
        for index in range(count)
        for name in required
        if not (material_dir / f"validator-{index}" / name).is_file()
    ]
    if missing:
        raise ValueError(
            "Mainnet requires operator-owned OCOMP material; missing "
            + ", ".join(missing)
        )


def load_json(path: Path) -> Any:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


PRIVATE_VALIDATOR_FIELDS = {
    "private_key",
    "evm_private_key",
    "ecdsa_private_key",
    "evm_key",
    "reth_p2p_secret_hex",
    "reth_p2p_secret",
}


def sanitized_validators_for_output(validators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in validator.items() if key not in PRIVATE_VALIDATOR_FIELDS}
        for validator in validators
    ]


def default_base_genesis(
    *,
    chain_id: int,
    epoch_length_blocks: int,
    dkg_prepare_window_blocks: int,
    dkg_activation_grace_blocks: int,
    gas_limit: str,
) -> dict[str, Any]:
    return {
        "config": {
            "chainId": chain_id,
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
            "epochLengthBlocks": epoch_length_blocks,
            "dkgPrepareWindowBlocks": dkg_prepare_window_blocks,
            "dkgActivationGraceBlocks": dkg_activation_grace_blocks,
        },
        "nonce": "0x0",
        "timestamp": hex(int(time.time())),
        "extraData": "0x",
        "gasLimit": gas_limit,
        "difficulty": "0x0",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {},
    }


def normalize_hex(value: str, *, expected_len: int | None = None, field: str = "hex") -> str:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"{field} must be {expected_len} hex chars, got {len(raw)}")
    try:
        bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    return raw


def parse_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
            raise ValueError(f"invalid host:port: {value}")
        host = value[1:end]
        port_s = value[end + 2 :]
    else:
        if ":" not in value:
            raise ValueError(f"invalid host:port: {value}")
        host, port_s = value.rsplit(":", 1)
    if not host:
        raise ValueError(f"missing host in host:port: {value}")
    port = int(port_s)
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid port in host:port: {value}")
    return host, port


def format_enode_host(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def compact_hex_balance(amount: int) -> str:
    if amount < 0:
        raise ValueError("balance cannot be negative")
    return hex(amount)


def point_add(
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


def point_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    if scalar <= 0 or scalar >= SECP256K1_N:
        raise ValueError("secp256k1 scalar out of range")
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    k = scalar
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    if result is None:
        raise ValueError("invalid secp256k1 scalar produced point at infinity")
    return result


def generate_reth_secret_hex() -> str:
    while True:
        scalar = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= scalar < SECP256K1_N:
            return f"{scalar:064x}"


def reth_node_id_from_secret(secret_hex: str) -> str:
    raw = normalize_hex(secret_hex, expected_len=64, field="reth p2p secret")
    scalar = int(raw, 16)
    x, y = point_mul(scalar, SECP256K1_G)
    return f"{x:064x}{y:064x}"


def validator_field(validator: dict[str, Any], names: list[str]) -> str | None:
    for name in names:
        value = validator.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def validator_reth_address(
    validator: dict[str, Any],
    index: int,
    *,
    reth_p2p_base_port: int,
) -> str:
    explicit = validator_field(validator, ["reth_p2p_address", "reth_address", "reth"])
    if explicit is not None:
        parse_host_port(explicit)
        return explicit
    consensus_address = validator_field(validator, ["p2p_address"])
    if consensus_address is None:
        raise ValueError(f"validator {index} missing required p2p_address")
    host, _ = parse_host_port(consensus_address)
    return f"{host}:{reth_p2p_base_port + index}"


def validator_consensus_address(validator: dict[str, Any], index: int) -> str:
    value = validator_field(validator, ["p2p_address"])
    if value is None:
        raise ValueError(f"validator {index} missing required p2p_address")
    parse_host_port(value)
    return value


def validator_signing_key_path(
    validator: dict[str, Any],
    index: int,
    *,
    runtime_base_dir: str,
) -> str:
    explicit = validator_field(validator, ["signing_key_path", "bls_signing_key_path"])
    if explicit is not None:
        return explicit
    return f"{runtime_base_dir}/validator-{index}/signing-key.hex"


def validator_wallet_info(validator: dict[str, Any]) -> tuple[str, str | None]:
    address = validator_field(validator, ["address"])
    if address is None:
        raise ValueError("validator missing address")
    private_key = validator_field(
        validator,
        ["private_key", "evm_private_key", "ecdsa_private_key", "evm_key"],
    )
    return address, private_key


def parse_hosts(args: argparse.Namespace, expected: int) -> list[str]:
    values: list[str] = []
    if args.validator_hosts:
        values.extend(
            host.strip()
            for host in args.validator_hosts.split(",")
            if host.strip()
        )
    if args.validator_hosts_file:
        values.extend(
            line.strip()
            for line in args.validator_hosts_file.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    if not values:
        raise ValueError("--generate-validators requires --validator-hosts or --validator-hosts-file")
    for value in values:
        if ":" in value:
            raise ValueError(
                "validator hosts must be hosts/IPs only, without ports; ports are assigned by the script"
            )
    if len(values) == 1:
        pattern = values[0]
        if "{i}" in pattern or "%d" in pattern:
            return [
                pattern.replace("{i}", str(index)).replace("%d", str(index))
                for index in range(expected)
            ]
        return values * expected
    if len(values) != expected:
        raise ValueError(
            f"expected {expected} validator hosts, got {len(values)}"
        )
    return values


def run_founder_identity_generation(
    *,
    chain_binary: str,
    output_dir: Path,
    count: int,
) -> None:
    cmd = [
        chain_binary,
        "dkg",
        "identities",
        "--output-dir",
        str(output_dir),
        "--validators",
        str(count),
    ]
    subprocess.run(cmd, check=True)


def update_generated_validators(
    *,
    validators_path: Path,
    hosts: list[str],
    consensus_p2p_base_port: int,
    reth_p2p_base_port: int,
) -> list[dict[str, Any]]:
    validators = load_json(validators_path)
    if not isinstance(validators, list):
        raise ValueError("generated validators.json must contain a JSON array")
    if len(validators) != len(hosts):
        raise ValueError(
            f"generated validator count {len(validators)} does not match host count {len(hosts)}"
        )
    for index, validator in enumerate(validators):
        if not isinstance(validator, dict):
            raise ValueError(f"generated validator {index} must be an object")
        host = hosts[index]
        validator["p2p_address"] = f"{host}:{consensus_p2p_base_port + index}"
        validator["reth_p2p_address"] = f"{host}:{reth_p2p_base_port + index}"
    write_json(validators_path, validators)
    return validators


def generated_wallet_private_keys(output_dir: Path, count: int) -> dict[int, str]:
    keys: dict[int, str] = {}
    for index in range(count):
        path = output_dir / f"validator-{index}" / "evm-key.hex"
        if path.exists():
            raw = normalize_hex(path.read_text(), expected_len=64, field=f"validator {index} evm key")
            keys[index] = "0x" + raw
    return keys


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
        start = offset + 4
        end = start + length
        if end > len(payload):
            raise ValueError(f"truncated Radicle public key {path}")
        return payload[start:end], end

    kind, offset = field(0)
    node_id, offset = field(offset)
    if kind != b"ssh-ed25519" or len(node_id) != 32 or offset != len(payload):
        raise ValueError(f"invalid Ed25519 Radicle public key {path}")
    return node_id.hex()


def generate_founder_radicle_material(
    *, keygen_binary: str, output_dir: Path, validators: list[dict[str, Any]]
) -> None:
    for index, validator in enumerate(validators):
        home = output_dir / f"validator-{index}" / "radicle"
        subprocess.run(
            [keygen_binary, "radicle", "--output-dir", str(home)],
            check=True,
        )
        validator["radicle_node_id"] = "0x" + radicle_node_id_from_public_key(
            home / "keys" / "radicle.pub"
        )


def validate_founder_radicle_material(
    validators: list[dict[str, Any]], material_dir: Path, count: int
) -> None:
    if len(validators) != count:
        raise ValueError(
            f"founder validator count {len(validators)} does not match material count {count}"
        )
    seen: set[str] = set()
    for index, validator in enumerate(validators):
        configured = normalize_hex(
            str(validator.get("radicle_node_id", "")),
            expected_len=64,
            field=f"validator {index} radicle_node_id",
        )
        if configured == "00" * 32:
            raise ValueError(f"validator {index} radicle_node_id must not be zero")
        if configured in seen:
            raise ValueError(f"duplicate Radicle NodeId for validator {index}")
        seen.add(configured)
        public_key = material_dir / f"validator-{index}" / "radicle/keys/radicle.pub"
        secret_key = material_dir / f"validator-{index}" / "radicle/keys/radicle"
        if not secret_key.is_file():
            raise ValueError(f"founder material is missing {secret_key}")
        actual = radicle_node_id_from_public_key(public_key)
        if actual != configured:
            raise ValueError(
                f"validator-{index} Radicle NodeId does not match validators.json"
            )


def import_founder_material(
    source: Path,
    output_dir: Path,
    count: int,
    validators: list[dict[str, Any]],
    *,
    include_ocomp: bool = False,
) -> None:
    validate_founder_radicle_material(validators, source, count)
    required_private = ("signing-key.hex", "evm-key.hex")
    for index in range(count):
        destination = output_dir / f"validator-{index}"
        destination.mkdir(parents=True, exist_ok=True)
        for name in required_private:
            source_path = source / f"validator-{index}" / name
            if not source_path.is_file():
                raise ValueError(f"founder material is missing {source_path}")
            destination_path = destination / name
            shutil.copyfile(source_path, destination_path)
            destination_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        shutil.copytree(
            source / f"validator-{index}" / "radicle",
            destination / "radicle",
        )
        if include_ocomp:
            for name in ("ocomp-key-v1.hex", "ocomp-registration-v1.ocb1"):
                destination_path = destination / name
                shutil.copyfile(source / f"validator-{index}" / name, destination_path)
                destination_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def verify_founder_material(
    *,
    chain_binary: str,
    validators_path: Path,
    material_dir: Path,
) -> None:
    subprocess.run(
        [
            chain_binary,
            "dkg",
            "verify-identities",
            "--validators",
            str(validators_path),
            "--material-dir",
            str(material_dir),
        ],
        check=True,
    )


def prepare_prefunded_genesis(
    base_genesis: dict[str, Any],
    validators: list[dict[str, Any]],
    *,
    prefund_coen_units: int,
) -> dict[str, Any]:
    genesis = json.loads(json.dumps(base_genesis))
    alloc = genesis.setdefault("alloc", {})
    if not isinstance(alloc, dict):
        raise ValueError("genesis alloc must be an object")
    if prefund_coen_units == 0:
        return genesis
    for validator in validators:
        address, _ = validator_wallet_info(validator)
        key = normalize_hex(address, expected_len=40, field="validator address")
        entry = alloc.setdefault(key, {})
        entry.setdefault("balance", compact_hex_balance(prefund_coen_units))
    return genesis


def run_seed_genesis(
    *,
    repo_root: Path,
    preseed_genesis: Path,
    seed: Path,
    validators: Path,
    output_genesis: Path,
) -> None:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "seed_genesis.py"),
        "--genesis",
        str(preseed_genesis),
        "--seed",
        str(seed),
        "--validators",
        str(validators),
        "--output",
        str(output_genesis),
    ]
    subprocess.run(cmd, check=True)


def run_tee_genesis(
    *,
    chain_binary: str,
    seeded_genesis: Path,
    output_genesis: Path,
    tee_mode: str,
    mrenclave: str | None,
    mrsigner: str | None,
    isv_prod_id: int | None,
    minimum_isv_svn: int | None,
    minimum_tcb_evaluation_data_number: int | None,
) -> None:
    cmd = [
        chain_binary,
        "tee",
        "genesis",
        "--input",
        str(seeded_genesis),
        "--output",
        str(output_genesis),
        "--mode",
        tee_mode,
    ]
    if tee_mode == "dcap-required":
        required = {
            "--mrenclave": mrenclave,
            "--mrsigner": mrsigner,
            "--isv-prod-id": isv_prod_id,
            "--minimum-isv-svn": minimum_isv_svn,
            "--minimum-tcb-evaluation-data-number": minimum_tcb_evaluation_data_number,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise ValueError(
                "dcap-required genesis needs exact release values: " + ", ".join(missing)
            )
        for name, value in required.items():
            cmd.extend([name, str(value)])
    elif any(
        value is not None
        for value in (
            mrenclave,
            mrsigner,
            isv_prod_id,
            minimum_isv_svn,
            minimum_tcb_evaluation_data_number,
        )
    ):
        raise ValueError(
            "gramine-direct-dev forbids DCAP measurement arguments"
        )
    subprocess.run(cmd, check=True)


def run_ocomp_bindings(
    *,
    chain_binary: str,
    seeded_genesis: Path,
    validators: Path,
    output: Path,
) -> dict[str, Any]:
    subprocess.run(
        [
            chain_binary,
            "ocomp",
            "bindings",
            "--input",
            str(seeded_genesis),
            "--validators",
            str(validators),
            "--output",
            str(output),
        ],
        check=True,
    )
    value = load_json(output)
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise ValueError("outbe-chain returned an invalid OCOMP bindings document")
    identities = value.get("validatorIdentityHashes")
    if not isinstance(identities, list) or len(identities) != 4:
        raise ValueError("OCOMP bindings must contain exactly four validator identities")
    return value


def run_ocomp_keygen(
    *,
    keygen_binary: str,
    output_dir: Path,
    bindings: dict[str, Any],
    validators: list[dict[str, Any]],
) -> None:
    identities = bindings["validatorIdentityHashes"]
    if len(validators) != len(identities):
        raise ValueError(
            "OCOMP key generation validator count does not match bindings"
        )
    for index, validator in enumerate(validators):
        address = normalize_hex(
            validator_field(validator, ["address"]) or "",
            expected_len=40,
            field=f"validator {index} address",
        )
        public_key = normalize_hex(
            validator_field(validator, ["public_key"]) or "",
            expected_len=96,
            field=f"validator {index} public_key",
        )
        subprocess.run(
            [
                keygen_binary,
                "ocomp",
                "--output-dir",
                str(output_dir / f"validator-{index}"),
                "--chain-id",
                str(bindings["chainId"]),
                "--genesis-hash",
                str(bindings["genesisHash"]),
                "--validator-address",
                "0x" + address,
                "--consensus-bls-min-pk",
                "0x" + public_key,
            ],
            check=True,
        )


def run_ocomp_genesis(
    *,
    chain_binary: str,
    seeded_genesis: Path,
    validators: Path,
    registrations_dir: Path,
    output_genesis: Path,
    protocol_bundle_output: Path,
) -> None:
    subprocess.run(
        [
            chain_binary,
            "ocomp",
            "genesis",
            "--input",
            str(seeded_genesis),
            "--validators",
            str(validators),
            "--registrations-dir",
            str(registrations_dir),
            "--output",
            str(output_genesis),
            "--protocol-bundle-output",
            str(protocol_bundle_output),
        ],
        check=True,
    )


def generate_dev_sgx_signing_key(path: Path) -> None:
    subprocess.run(
        ["openssl", "genrsa", "-3", "-out", str(path), "3072"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def command_lines(
    *,
    chain_binary: str,
    genesis_runtime_path: str,
    datadir: str,
    rpc_host: str,
    rpc_port: int,
    reth_p2p_port: int,
    discv5_host: str,
    discv5_port: int,
    bootnodes_runtime_path: str,
    p2p_secret_runtime_path: str,
    authrpc_port: int,
    ipc_path: str,
    metrics_host: str,
    metrics_port: int,
    log_dir: str,
    signing_key_path: str,
    evm_key_path: str,
    consensus_listen_host: str,
    consensus_listen_port: int,
    tee_enclave_endpoint: str,
    tee_bootstrap_timeout_secs: int,
    storage_config: str,
    use_local_defaults: bool,
) -> list[str]:
    lines = [
        'export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"',
        "",
        # The p2p key is passed as a FILE (`--p2p-secret-key`), never inline hex
        # in argv: the command line is world-readable via `ps`. reth parses the
        # file contents without trimming, so normalize it in place (idempotent).
        f"printf '%s' \"$(tr -d '[:space:]' < {shell_quote(p2p_secret_runtime_path)})\" > {shell_quote(p2p_secret_runtime_path)}",
        "",
        f"{chain_binary} node \\",
        "  --validator \\",
        f"  --chain {shell_quote(genesis_runtime_path)} \\",
        f"  --datadir {shell_quote(datadir)} \\",
        "  --engine.persistence-threshold 0 \\",
        "  --engine.memory-block-buffer-target 0 \\",
        f"  --http --http.addr {rpc_host} --http.port {rpc_port} \\",
        "  --http.api eth,net,web3,rudis \\",
        f"  --port {reth_p2p_port} \\",
        f"  --discovery.port {reth_p2p_port} \\",
        f"  --discovery.v5.addr {discv5_host} \\",
        f"  --discovery.v5.port {discv5_port} \\",
        f"  --bootnodes \"$(grep -v '^[[:space:]]*#' {shell_quote(bootnodes_runtime_path)} | paste -sd, -)\" \\",
        f"  --p2p-secret-key {shell_quote(p2p_secret_runtime_path)} \\",
        f"  --authrpc.port {authrpc_port} \\",
        f"  --ipcpath {shell_quote(ipc_path)} \\",
        f"  --metrics {metrics_host}:{metrics_port} \\",
        f"  --log.file.directory {shell_quote(log_dir)} \\",
        f"  --consensus.signing-key {shell_quote(signing_key_path)} \\",
        f"  --validator.evm-key {shell_quote(evm_key_path)} \\",
        f"  --projection.storage-config {shell_quote(storage_config)} \\",

        f"  --tee-enclave-socket {shell_quote(tee_enclave_endpoint)} \\",
        f"  --tee-bootstrap-timeout-secs {tee_bootstrap_timeout_secs} \\",
        f"  --consensus.listen-addr {consensus_listen_host}:{consensus_listen_port}",
    ]
    if use_local_defaults:
        lines[-1] += " \\"
        lines.append("  --consensus.use-local-defaults")
    return lines


def enclave_command_lines(
    *,
    tee_mode: str,
    enclave_image: str,
    endpoint: str,
    runtime_validator_dir: str,
    runtime_base_dir: str,
    runtime_enclave_binary: str,
    chain_id: int,
    validator_index: int,
    container_name: str,
) -> list[str]:
    chain_id_hex = f"0x{chain_id:064x}"
    common = [
        f"mkdir -p {shell_quote(runtime_validator_dir + '/tee')}",
        "",
        "docker run --rm \\",
        f"  --name {shell_quote(container_name)} \\",
        "  --network host \\",
        # Bounded, rotated container log: the enclave now emits one stderr line
        # per served request, so the log must never be unbounded or one-shot.
        "  --log-driver local --log-opt max-size=10m --log-opt max-file=3 \\",
    ]
    if tee_mode == "dcap-required":
        common.extend(
            [
                "  --device /dev/sgx_enclave:/dev/sgx_enclave \\",
                "  --device /dev/sgx_provision:/dev/sgx_provision \\",
                f"  -v {shell_quote(runtime_validator_dir + '/tee')}:/var/lib/outbe/tee \\",
                f"  {shell_quote(enclave_image)} \\",
                f"  --socket {shell_quote(endpoint)} \\",
                "  --tee-dir /var/lib/outbe/tee \\",
                f"  --chain-id {chain_id_hex}",
            ]
        )
        return common

    common.extend(
        [
            "  --security-opt seccomp=unconfined \\",
            f"  -v {shell_quote(runtime_enclave_binary)}:/app/outbe-tee-enclave:ro \\",
            f"  -v {shell_quote(runtime_base_dir + '/test-sgx-signing-key.pem')}:/run/secrets/outbe-test-sgx-key.pem:ro \\",
            f"  -v {shell_quote(runtime_validator_dir + '/tee')}:/tee \\",
            f"  {shell_quote(enclave_image)} \\",
            f"  --socket {shell_quote(endpoint)} \\",
            f"  --dkg-seed {validator_index + 1:064x} \\",
            "  --tee-dir /tee \\",
            f"  --chain-id {chain_id_hex}",
        ]
    )
    return common


def write_command_script(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "#!/usr/bin/env bash\nset -euo pipefail\n\n" + "\n".join(lines) + "\n"
    path.write_text(content)
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_secret_hex(path: Path, hex_value: str) -> None:
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(hex_value + "\n")
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def build_network_markdown(
    *,
    validators: list[dict[str, Any]],
    genesis_path: Path,
    copied_validators_path: Path,
    bootnodes_path: Path,
    commands: list[tuple[int, str, list[str]]],
    enclave_commands: list[tuple[int, str, list[str]]],
    reth_rows: list[dict[str, Any]],
    runtime_base_dir: str,
    network_name: str,
    chain_id: int,
    include_private_keys: bool,
    wallet_private_keys: dict[int, str] | None = None,
) -> str:
    wallet_private_keys = wallet_private_keys or {}
    lines: list[str] = []
    lines.append("# Outbe Network Launch Plan")
    lines.append("")
    lines.append("Generated as one chain-bound four-founder deployment bundle.")
    lines.append(f"Canonical network: `{network_name}` (chain ID `{chain_id}`).")
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    lines.append(f"- Genesis: `{genesis_path}`")
    lines.append(f"- Validators input copy: `{copied_validators_path}`")
    lines.append(f"- Reth bootnodes: `{bootnodes_path}`")
    lines.append(f"- Runtime base dir used in commands: `{runtime_base_dir}`")
    lines.append("")
    lines.append("`validators.json` is a genesis/tooling input only. Do not pass it to node runtime; `--consensus.validators` is removed.")
    lines.append("")
    lines.append("## Bootnodes")
    lines.append("")
    lines.append("```text")
    lines.extend(row["enode"] for row in reth_rows)
    lines.append("```")
    lines.append("")
    lines.append("## Validators")
    lines.append("")
    header = "| # | EVM address | BLS public key | Consensus P2P | Reth P2P | RPC | Metrics |"
    sep = "|---:|---|---|---|---|---|---|"
    lines.extend([header, sep])
    for row in reth_rows:
        pk = row["public_key"]
        short_pk = f"`{pk[:12]}...{pk[-12:]}`"
        lines.append(
            f"| {row['index']} | `{row['address']}` | {short_pk} | "
            f"`{row['consensus_p2p']}` | `{row['reth_p2p']}` | "
            f"`http://{row['host']}:{row['rpc_port']}` | `{row['host']}:{row['metrics_port']}` |"
        )
    lines.append("")
    lines.append("## Wallets")
    lines.append("")
    lines.append("| # | Address | Private key |")
    lines.append("|---:|---|---|")
    for index, validator in enumerate(validators):
        address, private_key = validator_wallet_info(validator)
        private_key = private_key or wallet_private_keys.get(index)
        if include_private_keys and private_key:
            key_cell = f"`{private_key}`"
        elif private_key:
            key_cell = "`present in generated/input key material; redacted`"
        else:
            key_cell = "not included; use the operator-owned key for this address"
        lines.append(f"| {index} | `{address}` | {key_cell} |")
    lines.append("")
    lines.append("## Per-Validator Commands")
    lines.append("")
    lines.append("Copy the whole generated bundle to the runtime base directory. Review each `validator-N/offchain-storage.toml` (RocksDB by default), start each enclave command, and only then start all four founder node commands within the configured TEE bootstrap timeout.")
    lines.append("")
    for (index, enclave_script_path, enclave_cmd), (_, script_path, cmd) in zip(
        enclave_commands, commands
    ):
        lines.append(f"### Validator {index}")
        lines.append("")
        lines.append(f"Enclave script: `{enclave_script_path}`")
        lines.append("")
        lines.append("```bash")
        lines.extend(enclave_cmd)
        lines.append("```")
        lines.append("")
        lines.append(f"Node script: `{script_path}`")
        lines.append("")
        lines.append("```bash")
        lines.extend(cmd)
        lines.append("```")
        lines.append("")
    lines.append("## Checks")
    lines.append("")
    lines.append("```bash")
    lines.append("curl -sS -H 'content-type: application/json' \\")
    lines.append("  --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}' \\")
    lines.append("  http://<rpc-host>:<rpc-port>")
    lines.append("")
    lines.append("curl -sS -H 'content-type: application/json' \\")
    lines.append("  --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_peerCount\",\"params\":[]}' \\")
    lines.append("  http://<rpc-host>:<rpc-port>")
    lines.append("")
    lines.append("curl -sS http://<metrics-host>:<metrics-port>/metrics | rg 'outbe_reshares_completed_total|commonware_p2p_tracked_peer_set_size|outbe_consensus_reth_tip_hash_match|outbe_parent_cert_store_size'")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a complete four-founder Outbe network bundle"
    )
    parser.add_argument("--genesis-base", type=Path)
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--validators", type=Path)
    parser.add_argument(
        "--founder-material-dir",
        type=Path,
        help="Required with --validators; contains validator-N/signing-key.hex and evm-key.hex identity files",
    )
    parser.add_argument("--generate-validators", type=int, help="Generate DKG/key material for N validators before preparing the network")
    parser.add_argument("--validator-hosts", help="Comma-separated validator hosts/IPs used with --generate-validators")
    parser.add_argument("--validator-hosts-file", type=Path, help="File with one validator host/IP per line")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--chain-binary", default="outbe-chain")
    parser.add_argument("--keygen-binary", default="outbe-keygen")
    parser.add_argument(
        "--runtime-chain-binary",
        help="outbe-chain path used by generated commands; defaults to --chain-binary",
    )
    parser.add_argument(
        "--tee-mode",
        required=True,
        choices=("dcap-required", "gramine-direct-dev"),
        help="Genesis-fixed mode; testnet never falls back to devnet",
    )
    parser.add_argument(
        "--enclave-image",
        required=True,
        help="Ready Gramine image; use an immutable digest for dcap-required",
    )
    parser.add_argument(
        "--runtime-enclave-binary",
        default="/usr/local/bin/outbe-tee-enclave-mock",
        help="Dev-only enclave binary mounted into the Gramine test image",
    )
    parser.add_argument("--tee-enclave-host", default="127.0.0.1")
    parser.add_argument("--tee-enclave-base-port", type=int, default=17000)
    parser.add_argument("--tee-bootstrap-timeout-secs", type=int, default=300)
    parser.add_argument("--mrenclave", help="Exact release MRENCLAVE for dcap-required")
    parser.add_argument("--mrsigner", help="Exact release MRSIGNER for dcap-required")
    parser.add_argument("--isv-prod-id", type=int)
    parser.add_argument("--minimum-isv-svn", type=int)
    parser.add_argument("--minimum-tcb-evaluation-data-number", type=int)
    parser.add_argument("--runtime-base-dir", help="Path prefix used in generated commands; defaults to output dir")
    parser.add_argument(
        "--prefund-coen-units", type=int, default=DEFAULT_PREFUND_COEN_UNITS
    )
    parser.add_argument("--chain-id", type=int)
    parser.add_argument("--network", choices=tuple(NETWORK_IDENTITIES))
    parser.add_argument("--epoch-length-blocks", type=int, default=DEFAULT_EPOCH_LENGTH_BLOCKS)
    parser.add_argument("--dkg-prepare-window-blocks", type=int, default=DEFAULT_DKG_PREPARE_WINDOW_BLOCKS)
    parser.add_argument("--dkg-activation-grace-blocks", type=int, default=DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS)
    parser.add_argument("--gas-limit", default=DEFAULT_GAS_LIMIT)
    parser.add_argument("--consensus-p2p-base-port", type=int, default=30400)
    parser.add_argument("--reth-p2p-base-port", type=int, default=30303)
    parser.add_argument("--reth-discv5-base-port", type=int, default=31303)
    parser.add_argument("--rpc-base-port", type=int, default=8545)
    parser.add_argument("--authrpc-base-port", type=int, default=8551)
    parser.add_argument("--metrics-base-port", type=int, default=9101)
    parser.add_argument("--http-addr", default="0.0.0.0")
    parser.add_argument("--metrics-addr", default="0.0.0.0")
    parser.add_argument("--discv5-addr", default="0.0.0.0")
    parser.add_argument("--consensus-listen-host", default="0.0.0.0")
    parser.add_argument("--storage-template", type=Path, help="offchain-storage.toml template; Mongo database receives _validator_N suffix; defaults to per-node RocksDB")
    parser.add_argument("--use-local-defaults", action="store_true")
    parser.add_argument("--include-private-keys", action="store_true")
    parser.add_argument("--force-reth-secrets", action="store_true")
    args = parser.parse_args()

    network, args.chain_id, network_name = resolve_network_profile(
        args.network, args.chain_id, args.tee_mode
    )
    if network == "mainnet":
        validate_mainnet_options(args)
    if args.tee_mode == "dcap-required" and re.fullmatch(
        r"[^\s]+@sha256:[0-9a-f]{64}", args.enclave_image
    ) is None:
        raise ValueError(
            "dcap-required needs --enclave-image as an immutable image digest "
            "(name@sha256:<64 lowercase hex>)"
        )

    repo_root = Path(__file__).resolve().parents[1]
    output_dir = args.output_dir
    runtime_base_dir = args.runtime_base_dir or str(output_dir)
    runtime_chain_binary = args.runtime_chain_binary or args.chain_binary
    if args.tee_bootstrap_timeout_secs <= 0:
        raise ValueError("--tee-bootstrap-timeout-secs must be > 0")
    if output_dir.exists():
        raise ValueError(f"refusing to reuse existing output directory: {output_dir}")
    output_dir.mkdir(parents=True)
    projection_scope = secrets.token_hex(8)
    write_secret_hex(output_dir / "projection-scope", projection_scope)
    storage_document = load_storage(args.storage_template) if args.storage_template else storage_settings({}, database="unused", mongo_uri="unused")

    if args.validators and args.generate_validators:
        raise ValueError("use either --validators or --generate-validators, not both")
    if not args.validators and not args.generate_validators:
        raise ValueError("provide --validators or --generate-validators")
    if args.validators and args.founder_material_dir is None:
        raise ValueError("--validators requires --founder-material-dir for runnable founder commands")
    if args.generate_validators and args.founder_material_dir is not None:
        raise ValueError("--founder-material-dir is only valid with --validators")

    wallet_private_keys: dict[int, str] = {}
    validators_path: Path
    if args.generate_validators:
        if args.generate_validators <= 0:
            raise ValueError("--generate-validators must be > 0")
        if args.generate_validators != 4:
            raise ValueError(
                "OCOMP V1 requires exactly 4 founding validators; "
                "--generate-validators must be 4"
            )
        hosts = parse_hosts(args, args.generate_validators)
        run_founder_identity_generation(
            chain_binary=args.chain_binary,
            output_dir=output_dir,
            count=args.generate_validators,
        )
        validators_path = output_dir / "validators.json"
        validators = update_generated_validators(
            validators_path=validators_path,
            hosts=hosts,
            consensus_p2p_base_port=args.consensus_p2p_base_port,
            reth_p2p_base_port=args.reth_p2p_base_port,
        )
        generate_founder_radicle_material(
            keygen_binary=args.keygen_binary,
            output_dir=output_dir,
            validators=validators,
        )
        write_json(validators_path, validators)
        wallet_private_keys = generated_wallet_private_keys(
            output_dir,
            args.generate_validators,
        )
    else:
        validators_path = args.validators
        external_validators = load_json(validators_path)
        if not isinstance(external_validators, list):
            raise ValueError("validators.json must contain a JSON array")
        verify_founder_material(
            chain_binary=args.chain_binary,
            validators_path=validators_path,
            material_dir=args.founder_material_dir,
        )
        if network == "mainnet":
            require_mainnet_ocomp_material(args.founder_material_dir, 4)
        import_founder_material(
            args.founder_material_dir,
            output_dir,
            4,
            external_validators,
            include_ocomp=network == "mainnet",
        )

    validators_raw = load_json(validators_path)
    if not isinstance(validators_raw, list) or not validators_raw:
        raise ValueError("validators.json must contain a non-empty JSON array")
    validators: list[dict[str, Any]] = validators_raw
    if len(validators) != 4:
        raise ValueError(
            f"OCOMP V1 requires exactly 4 founding validators, got {len(validators)}"
        )

    for index, validator in enumerate(validators):
        if not isinstance(validator, dict):
            raise ValueError(f"validator {index} must be an object")
        normalize_hex(validator_field(validator, ["public_key"]) or "", expected_len=96, field=f"validator {index} public_key")
        normalize_hex(validator_field(validator, ["address"]) or "", expected_len=40, field=f"validator {index} address")
        validator_consensus_address(validator, index)

    copied_validators_path = output_dir / "validators.json"
    sanitized_validators = sanitized_validators_for_output(validators)
    if validators_path.resolve() != copied_validators_path.resolve():
        write_json(copied_validators_path, sanitized_validators)
    elif sanitized_validators != validators:
        copied_validators_path = output_dir / "validators.public.json"
        write_json(copied_validators_path, sanitized_validators)

    if args.genesis_base:
        base_genesis = load_json(args.genesis_base)
    else:
        base_genesis = default_base_genesis(
            chain_id=args.chain_id,
            epoch_length_blocks=args.epoch_length_blocks,
            dkg_prepare_window_blocks=args.dkg_prepare_window_blocks,
            dkg_activation_grace_blocks=args.dkg_activation_grace_blocks,
            gas_limit=args.gas_limit,
        )
        write_json(output_dir / "genesis.base.json", base_genesis)
    configured_chain_id = base_genesis.get("config", {}).get("chainId")
    if configured_chain_id != args.chain_id:
        raise ValueError(
            f"genesis chainId {configured_chain_id!r} does not match --chain-id {args.chain_id}"
        )
    preseed_genesis = prepare_prefunded_genesis(
        base_genesis,
        validators,
        prefund_coen_units=args.prefund_coen_units,
    )
    preseed_path = output_dir / "genesis.prefund.json"
    seeded_genesis_path = output_dir / "genesis.seeded.json"
    ocomp_genesis_path = output_dir / "genesis.ocomp.json"
    genesis_path = output_dir / "genesis.json"
    if genesis_path.exists():
        raise ValueError(f"refusing to overwrite existing genesis: {genesis_path}")
    write_json(preseed_path, preseed_genesis)

    run_seed_genesis(
        repo_root=repo_root,
        preseed_genesis=preseed_path,
        seed=args.seed,
        validators=copied_validators_path,
        output_genesis=seeded_genesis_path,
    )
    ocomp_bindings_path = output_dir / "ocomp-bindings-v1.json"
    ocomp_bindings = run_ocomp_bindings(
        chain_binary=args.chain_binary,
        seeded_genesis=seeded_genesis_path,
        validators=copied_validators_path,
        output=ocomp_bindings_path,
    )
    if network != "mainnet":
        run_ocomp_keygen(
            keygen_binary=args.keygen_binary,
            output_dir=output_dir,
            bindings=ocomp_bindings,
            validators=validators,
        )
    protocol_bundle_path = output_dir / "protocol-bundle-v1.ocb1"
    run_ocomp_genesis(
        chain_binary=args.chain_binary,
        seeded_genesis=seeded_genesis_path,
        validators=copied_validators_path,
        registrations_dir=output_dir,
        output_genesis=ocomp_genesis_path,
        protocol_bundle_output=protocol_bundle_path,
    )
    run_tee_genesis(
        chain_binary=args.chain_binary,
        seeded_genesis=ocomp_genesis_path,
        output_genesis=genesis_path,
        tee_mode=args.tee_mode,
        mrenclave=args.mrenclave,
        mrsigner=args.mrsigner,
        isv_prod_id=args.isv_prod_id,
        minimum_isv_svn=args.minimum_isv_svn,
        minimum_tcb_evaluation_data_number=args.minimum_tcb_evaluation_data_number,
    )

    if args.tee_mode == "gramine-direct-dev":
        generate_dev_sgx_signing_key(output_dir / "test-sgx-signing-key.pem")

    bootnodes: list[str] = []
    rows: list[dict[str, Any]] = []
    commands: list[tuple[int, str, list[str]]] = []
    enclave_commands: list[tuple[int, str, list[str]]] = []
    commands_dir = output_dir / "commands"
    claimed_endpoints: dict[tuple[str, int], str] = {}

    for index, validator in enumerate(validators):
        consensus_p2p = validator_consensus_address(validator, index)
        host, consensus_port = parse_host_port(consensus_p2p)
        reth_p2p = validator_reth_address(
            validator,
            index,
            reth_p2p_base_port=args.reth_p2p_base_port,
        )
        reth_host, reth_port = parse_host_port(reth_p2p)
        validator_dir = output_dir / f"validator-{index}"
        validator_dir.mkdir(parents=True, exist_ok=True)
        (validator_dir / "tee").mkdir(exist_ok=True)

        secret_path = validator_dir / "reth-p2p-secret.hex"
        secret_from_json = validator_field(
            validator,
            ["reth_p2p_secret_hex", "reth_p2p_secret"],
        )
        if secret_from_json is not None:
            secret_hex = normalize_hex(secret_from_json, expected_len=64, field=f"validator {index} reth p2p secret")
            write_secret_hex(secret_path, secret_hex)
        elif secret_path.exists() and not args.force_reth_secrets:
            secret_hex = normalize_hex(secret_path.read_text(), expected_len=64, field=f"validator {index} existing reth p2p secret")
            write_secret_hex(secret_path, secret_hex)
        else:
            secret_hex = generate_reth_secret_hex()
            write_secret_hex(secret_path, secret_hex)

        node_id = reth_node_id_from_secret(secret_hex)
        enode = f"enode://{node_id}@{format_enode_host(reth_host)}:{reth_port}"
        bootnodes.append(enode)

        address, private_key = validator_wallet_info(validator)
        evm_key_path = validator_dir / "evm-key.hex"
        if private_key:
            private_key_hex = normalize_hex(private_key, expected_len=64, field=f"validator {index} evm private_key")
            write_secret_hex(evm_key_path, private_key_hex)
        elif evm_key_path.exists():
            private_key_hex = normalize_hex(evm_key_path.read_text(), expected_len=64, field=f"validator {index} existing evm key")
            write_secret_hex(evm_key_path, private_key_hex)
        public_key = normalize_hex(validator["public_key"], expected_len=96, field=f"validator {index} public_key")
        rpc_port = int(validator.get("rpc_port", args.rpc_base_port + index))
        authrpc_port = int(validator.get("authrpc_port", args.authrpc_base_port + index))
        metrics_port = int(validator.get("metrics_port", args.metrics_base_port + index))
        discv5_port = int(
            validator.get("reth_discv5_port", args.reth_discv5_base_port + index)
        )
        signing_key_path = validator_signing_key_path(
            validator,
            index,
            runtime_base_dir=runtime_base_dir,
        )

        node_storage = copy.deepcopy(storage_document)
        if node_storage["backend"] == "mongodb":
            node_storage["mongodb"]["database"] += f"_validator_{index}"
        ensure_storage(validator_dir / "offchain-storage.toml", node_storage)
        runtime_validator_dir = f"{runtime_base_dir}/validator-{index}"
        runtime_secret_path = f"{runtime_validator_dir}/reth-p2p-secret.hex"
        runtime_evm_key_path = f"{runtime_validator_dir}/evm-key.hex"
        runtime_bootnodes_path = f"{runtime_base_dir}/reth-bootnodes.txt"
        runtime_genesis_path = f"{runtime_base_dir}/genesis.json"
        datadir = f"{runtime_validator_dir}/data"
        ipc_path = f"{datadir}/reth.ipc"
        log_dir = f"{runtime_validator_dir}/logs"
        tee_enclave_endpoint = (
            f"{args.tee_enclave_host}:{args.tee_enclave_base_port + index}"
        )
        for endpoint_host, endpoint_port, label in (
            (host, consensus_port, "consensus"),
            (reth_host, reth_port, "reth-p2p"),
            (host, rpc_port, "rpc"),
            (host, authrpc_port, "authrpc"),
            (host, metrics_port, "metrics"),
            (host, discv5_port, "discv5"),
            (host, args.tee_enclave_base_port + index, "tee"),
        ):
            if endpoint_port <= 0 or endpoint_port > 65535:
                raise ValueError(
                    f"validator {index} {label} port is outside 1..65535: {endpoint_port}"
                )
            key = (endpoint_host, endpoint_port)
            previous = claimed_endpoints.get(key)
            if previous is not None:
                raise ValueError(
                    f"endpoint collision at {endpoint_host}:{endpoint_port}: "
                    f"{previous} and validator-{index} {label}"
                )
            claimed_endpoints[key] = f"validator-{index} {label}"

        cmd = command_lines(
            chain_binary=runtime_chain_binary,
            genesis_runtime_path=runtime_genesis_path,
            datadir=datadir,
            rpc_host=args.http_addr,
            rpc_port=rpc_port,
            reth_p2p_port=reth_port,
            discv5_host=args.discv5_addr,
            discv5_port=discv5_port,
            bootnodes_runtime_path=runtime_bootnodes_path,
            p2p_secret_runtime_path=runtime_secret_path,
            authrpc_port=authrpc_port,
            ipc_path=ipc_path,
            metrics_host=args.metrics_addr,
            metrics_port=metrics_port,
            log_dir=log_dir,
            signing_key_path=signing_key_path,
            evm_key_path=runtime_evm_key_path,
            consensus_listen_host=args.consensus_listen_host,
            consensus_listen_port=consensus_port,
            tee_enclave_endpoint=tee_enclave_endpoint,
            tee_bootstrap_timeout_secs=args.tee_bootstrap_timeout_secs,
            storage_config=f"{runtime_validator_dir}/offchain-storage.toml",
            use_local_defaults=args.use_local_defaults,
        )
        script_path = commands_dir / f"validator-{index}.sh"
        write_command_script(script_path, cmd)
        commands.append((index, str(script_path), cmd))

        enclave_cmd = enclave_command_lines(
            tee_mode=args.tee_mode,
            enclave_image=args.enclave_image,
            endpoint=tee_enclave_endpoint,
            runtime_validator_dir=runtime_validator_dir,
            runtime_base_dir=runtime_base_dir,
            runtime_enclave_binary=args.runtime_enclave_binary,
            chain_id=args.chain_id,
            validator_index=index,
            container_name=f"outbe-{projection_scope}-enclave-{index}",
        )
        enclave_script_path = commands_dir / f"enclave-{index}.sh"
        write_command_script(enclave_script_path, enclave_cmd)
        enclave_commands.append((index, str(enclave_script_path), enclave_cmd))

        rows.append(
            {
                "index": index,
                "host": host,
                "address": address,
                "public_key": "0x" + public_key,
                "consensus_p2p": consensus_p2p,
                "reth_p2p": reth_p2p,
                "rpc_port": rpc_port,
                "metrics_port": metrics_port,
                "enode": enode,
            }
        )

    bootnodes_path = output_dir / "reth-bootnodes.txt"
    bootnodes_path.write_text("\n".join(bootnodes) + "\n")

    network_md = build_network_markdown(
        validators=validators,
        genesis_path=genesis_path,
        copied_validators_path=copied_validators_path,
        bootnodes_path=bootnodes_path,
        commands=commands,
        enclave_commands=enclave_commands,
        reth_rows=rows,
        runtime_base_dir=runtime_base_dir,
        network_name=network_name,
        chain_id=args.chain_id,
        include_private_keys=args.include_private_keys,
        wallet_private_keys=wallet_private_keys,
    )
    network_path = output_dir / "network.md"
    network_path.write_text(network_md)
    write_json(
        output_dir / "network-identity.json",
        {"network": network, "chainId": args.chain_id, "chainName": network_name},
    )

    print("Prepared Outbe network:")
    print(f"  genesis:        {genesis_path}")
    print(f"  validators:     {copied_validators_path}")
    print(f"  reth bootnodes: {bootnodes_path}")
    print(f"  network plan:   {network_path}")
    print(f"  commands:       {commands_dir}")


if __name__ == "__main__":
    main()
