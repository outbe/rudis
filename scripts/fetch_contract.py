#!/usr/bin/env python3
"""
Fetch a deployed contract (bytecode + storage) from a JSON-RPC endpoint and
write it to scripts/contracts/ in a form that scripts/seed_genesis.py can
embed into genesis.json via the `contracts` section of seed-testnet.json.

Usage:
  python3 scripts/fetch_contract.py \
    --rpc https://rpc.testnet.outbe.net \
    --address 0x4e59b44847b379578588920cA78FbF26c0B4956C \
    --name create2_deployer

Outputs (under --out-dir, default scripts/contracts/):
  <name>.code.hex    0x-prefixed bytecode
  <name>.state.json  { "<slot 0xhex32>": "<value 0xhex32>", ... }; possibly empty
  <name>.meta.json   provenance: address, rpc, block, balance, nonce, storage_method

Storage is fetched via debug_storageRangeAt (geth/erigon-style). If the RPC
does not expose that method, an empty state file is written and a warning is
logged. eth_getCode returning "0x" is treated as a hard error (not a contract).

Stdlib only - no external dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


ZERO_KEY = "0x" + "00" * 32
PAGE_SIZE = 1024


def rpc_call(rpc_url: str, method: str, params: list, request_id: int = 1) -> dict:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "outbe-fetch-contract/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"RPC HTTP {e.code} for {method}: {e.read().decode('utf-8', 'replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"RPC network error for {method}: {e.reason}")
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        sys.exit(f"RPC malformed JSON for {method}: {e}; body={body!r}")


def rpc_result_or_die(rpc_url: str, method: str, params: list):
    resp = rpc_call(rpc_url, method, params)
    if "error" in resp:
        sys.exit(f"RPC error in {method}: {resp['error']}")
    if "result" not in resp:
        sys.exit(f"RPC missing result in {method}: {resp}")
    return resp["result"]


def normalize_hex32(value: str) -> str:
    """Normalize any 0x-prefixed hex int to 32-byte 0x-prefixed lowercase hex."""
    n = int(value, 16)
    return "0x" + n.to_bytes(32, "big").hex()


def resolve_block(rpc_url: str, block_arg: str) -> tuple[str, int, str]:
    """
    Resolve --block to (block_tag_for_eth_calls, block_number_int, block_hash_hex).
    block_tag_for_eth_calls is a quantity hex like "0x12ab" so all subsequent
    eth_* calls observe the exact same snapshot the storage range was taken at.
    """
    if block_arg == "latest":
        latest = rpc_result_or_die(rpc_url, "eth_blockNumber", [])
        block_tag = latest
    else:
        block_tag = block_arg
    block_obj = rpc_result_or_die(rpc_url, "eth_getBlockByNumber", [block_tag, False])
    if not isinstance(block_obj, dict):
        sys.exit(f"eth_getBlockByNumber({block_tag}) returned {block_obj!r}")
    block_number = int(block_obj["number"], 16)
    block_hash = block_obj["hash"]
    return block_tag, block_number, block_hash


def fetch_storage(rpc_url: str, block_hash: str, address: str) -> tuple[dict, str]:
    """
    Returns (storage_map, method_used). method_used is 'debug_storageRangeAt'
    on success or 'unavailable' if the node refused the method.
    """
    storage: dict = {}
    next_key = ZERO_KEY
    while next_key is not None:
        resp = rpc_call(
            rpc_url,
            "debug_storageRangeAt",
            [block_hash, 0, address, next_key, PAGE_SIZE],
        )
        if "error" in resp:
            err = resp["error"]
            code = err.get("code")
            msg = err.get("message", "")
            if code in (-32601, -32600) or "not found" in msg.lower() or "not supported" in msg.lower():
                print(
                    f"warning: debug_storageRangeAt unavailable on {rpc_url} "
                    f"({code}: {msg}); writing empty state",
                    file=sys.stderr,
                )
                return {}, "unavailable"
            sys.exit(f"RPC error in debug_storageRangeAt: {err}")
        result = resp.get("result") or {}
        page = result.get("storage") or {}
        for entry in page.values():
            if not entry:
                continue
            key = entry.get("key")
            value = entry.get("value")
            if key is None or value is None:
                # Some nodes omit preimages for unknown keys; skip rather than crash.
                continue
            storage[normalize_hex32(key)] = normalize_hex32(value)
        next_key = result.get("nextKey")
    return storage, "debug_storageRangeAt"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch contract code+storage from JSON-RPC into scripts/contracts/"
    )
    parser.add_argument("--rpc", required=True, help="JSON-RPC endpoint URL")
    parser.add_argument("--address", required=True, help="Contract address (0x...)")
    parser.add_argument(
        "--name",
        help="Output basename. Defaults to lowercase address without 0x prefix.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory (default: <repo>/scripts/contracts).",
    )
    parser.add_argument(
        "--block",
        default="latest",
        help="Block to snapshot at (default: latest). Also accepts 0x-prefixed number.",
    )
    args = parser.parse_args()

    addr_lower = args.address.lower()
    if not addr_lower.startswith("0x") or len(addr_lower) != 42:
        sys.exit(f"invalid --address: {args.address}")
    name = args.name or addr_lower[2:]

    if args.out_dir:
        out_dir = args.out_dir
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.join(script_dir, "contracts")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Resolving block {args.block} on {args.rpc}...")
    block_tag, block_number, block_hash = resolve_block(args.rpc, args.block)
    print(f"  block #{block_number}  hash={block_hash}")

    print(f"Fetching code/balance/nonce for {args.address}...")
    code = rpc_result_or_die(args.rpc, "eth_getCode", [args.address, block_tag])
    if not isinstance(code, str) or code in ("0x", "0x0"):
        sys.exit(f"address {args.address} has no contract code at block {block_tag}")
    balance = rpc_result_or_die(args.rpc, "eth_getBalance", [args.address, block_tag])
    nonce = rpc_result_or_die(args.rpc, "eth_getTransactionCount", [args.address, block_tag])

    print(f"Fetching storage via debug_storageRangeAt...")
    storage, storage_method = fetch_storage(args.rpc, block_hash, args.address)
    print(f"  {len(storage)} storage slot(s) ({storage_method})")

    code_path = os.path.join(out_dir, f"{name}.code.hex")
    state_path = os.path.join(out_dir, f"{name}.state.json")
    meta_path = os.path.join(out_dir, f"{name}.meta.json")

    with open(code_path, "w") as f:
        f.write(code.lower() + "\n")
    with open(state_path, "w") as f:
        json.dump(storage, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(meta_path, "w") as f:
        json.dump(
            {
                "address": addr_lower,
                "rpc": args.rpc,
                "block_number": block_number,
                "block_hash": block_hash,
                "balance": balance,
                "nonce": nonce,
                "storage_method": storage_method,
                "fetched_at": int(time.time()),
            },
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")

    code_bytes = (len(code) - 2) // 2
    print(f"Wrote {code_path} ({code_bytes} bytes)")
    print(f"Wrote {state_path}")
    print(f"Wrote {meta_path}")


if __name__ == "__main__":
    main()
