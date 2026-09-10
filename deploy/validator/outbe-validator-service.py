#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import NoReturn


OUTBE_ROOT = pathlib.Path("/opt/outbe-chain")
MONGODB_CONTAINER = "outbe-mongodb"
MONGODB_PORT = 27017


def fail(message: str) -> NoReturn:
    raise SystemExit(f"outbe-validator-service: {message}")


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        fail(f"missing environment variable: {name}")
    return value


def exec_role(argv: list[str], *, cwd: pathlib.Path | None = None) -> NoReturn:
    if cwd is not None:
        os.chdir(cwd)
    os.execvpe(argv[0], argv, os.environ.copy())


def mongodb() -> NoReturn:
    image = required_env("OUTBE_MONGODB_IMAGE")
    mongodb_dir = OUTBE_ROOT / "validator-0" / "mongodb"
    mongodb_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    mongodb_dir.chmod(0o700)
    exec_role(
        [
            "/usr/bin/docker",
            "run",
            "--rm",
            "--name",
            MONGODB_CONTAINER,
            "-p",
            f"127.0.0.1:{MONGODB_PORT}:{MONGODB_PORT}",
            "--mount",
            f"type=bind,src={mongodb_dir},dst=/data/db",
            image,
            "--replSet",
            "rs0",
            "--bind_ip_all",
            "--port",
            str(MONGODB_PORT),
        ]
    )


def docker_exec(script: str, *, quiet: bool = False) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/docker",
            "exec",
            MONGODB_CONTAINER,
            "mongosh",
            "--quiet",
            "--port",
            str(MONGODB_PORT),
            "--eval",
            script,
        ],
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
        check=False,
    )


def mongodb_init() -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if docker_exec("db.runCommand({ping:1}).ok", quiet=True).returncode == 0:
            break
        time.sleep(1)
    else:
        fail("MongoDB did not become reachable")

    script = (
        "try { rs.status() } catch (e) { "
        "rs.initiate({_id:'rs0',members:[{_id:0,host:'127.0.0.1:27017'}]}) }"
    )
    if docker_exec(script).returncode != 0:
        fail("MongoDB replica-set initialization failed")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = docker_exec(
            "db.hello().isWritablePrimary ? quit(0) : quit(1)", quiet=True
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    fail("MongoDB replica set did not elect a writable primary")


def mongodb_stop() -> None:
    subprocess.run(
        ["/usr/bin/docker", "stop", "-t", "30", MONGODB_CONTAINER],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def enclave() -> NoReturn:
    runtime = required_env("OUTBE_ENCLAVE_RUNTIME")
    chain_id = required_env("OCOMP_CHAIN_ID")
    try:
        chain_hex = f"0x{int(chain_id):064x}"
    except ValueError:
        fail("OCOMP_CHAIN_ID must be a positive decimal integer")
    arguments = [
        "--socket",
        "127.0.0.1:17000",
        "--tee-dir",
        "/var/lib/outbe/tee" if runtime == "bundled-sgx" else str(OUTBE_ROOT / "tee"),
        "--chain-id",
        chain_hex,
    ]
    if runtime == "system-gramine":
        exec_role(
            ["gramine-sgx", "outbe-tee-enclave", *arguments],
            cwd=OUTBE_ROOT,
        )
    if runtime == "bundled-sgx":
        sgx_dir = OUTBE_ROOT / "sgx"
        exec_role(
            [str(sgx_dir / "bin" / "outbe-tee-enclave-launch"), *arguments],
            cwd=sgx_dir,
        )
    fail("OUTBE_ENCLAVE_RUNTIME must be system-gramine or bundled-sgx")


def feeder() -> NoReturn:
    chain_id = required_env("OCOMP_CHAIN_ID")
    validator = required_env("OUTBE_VALIDATOR_ADDRESS")
    if re.fullmatch(r"[1-9][0-9]*", chain_id) is None:
        fail("OCOMP_CHAIN_ID must be a positive decimal integer")
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", validator) is None:
        fail("OUTBE_VALIDATOR_ADDRESS must be a 20-byte hex address")

    key_path = OUTBE_ROOT / "keys" / "evm-key.hex"
    try:
        key = key_path.read_bytes()
    except OSError as error:
        fail(f"cannot read Validator EVM key: {error}")
    if re.fullmatch(rb"[0-9a-f]{64}", key) is None:
        fail(f"Validator EVM key is not canonical: {key_path}")

    public_path = OUTBE_ROOT / "feeder-public.toml"
    try:
        public = public_path.read_text()
    except OSError as error:
        fail(f"cannot read public feeder configuration: {error}")

    runtime_dir = pathlib.Path(
        os.environ.get("RUNTIME_DIRECTORY", "/run/outbe-feeder")
    )
    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = runtime_dir / "feeder.toml"
    header = f"""[chain]
rpc_endpoint = "http://127.0.0.1:8545"
chain_id = {chain_id}
gasless_oracle_votes = true

[account]
private_key = {json.dumps("0x" + key.decode())}
validator_address = {json.dumps(validator)}

[health]
enabled = true
bind_address = "127.0.0.1:9002"

"""
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(header)
        output.write(public)
        if not public.endswith("\n"):
            output.write("\n")
    exec_role([str(OUTBE_ROOT / "outbe-feeder"), "--config", str(config)])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "role",
        choices=("mongodb", "mongodb-init", "mongodb-stop", "enclave", "feeder"),
    )
    return parser.parse_args()


def main() -> int:
    role = parse_args().role
    if role == "mongodb":
        mongodb()
    if role == "mongodb-init":
        mongodb_init()
        return 0
    if role == "mongodb-stop":
        mongodb_stop()
        return 0
    if role == "enclave":
        enclave()
    if role == "feeder":
        feeder()
    fail(f"unknown role: {role}")


if __name__ == "__main__":
    sys.exit(main())
