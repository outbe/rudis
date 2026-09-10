#!/usr/bin/env python3
"""
Submit an encrypted tribute offer to the TributeFactory precompile.

Required inputs:
- --wwd
- --private-key
- env TEE_PUBLIC_KEY  (the on-chain offer public key)

The HKDF salt is the fixed protocol constant `outbe_tee::OFFER_HKDF_SALT`; env
TEE_SALT is optional and only overrides it for testing. Everything else is
generated automatically with reasonable defaults.

Dependencies:
- cast (Foundry)
- Python package: cryptography

Example (set PRIVATE_KEY to your funded local test account first):
  export TEE_PUBLIC_KEY=0x...
  python3 scripts/tributefactory/offer_tribute.py \
    --wwd 20260422 \
    --private-key "$PRIVATE_KEY" \
    --rpc-url http://127.0.0.1:8545
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:
    sys.exit(
        "Missing dependency 'cryptography'. Install with: pip install cryptography\n"
        f"Original error: {exc}"
    )

FACTORY = "0x0000000000000000000000000000000000001100"
TRIBUTE = "0x0000000000000000000000000000000000001101"
HKDF_INFO = b"tribute-factory-encryption"


def run_cast(*args: str, expect_json: bool = False) -> str | dict:
    proc = subprocess.run(
        ["cast", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or "cast command failed")
    output = proc.stdout.strip()
    if expect_json:
        return json.loads(output)
    return output


def random_amount_base() -> str:
    return str(random.randint(10, 499))


def canonical_amount_base(value: str) -> str:
    if not value or not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("amount_base must be a canonical unsigned u64")
    parsed = int(value)
    if str(parsed) != value or parsed > 18_446_744_073_709_551_615:
        raise argparse.ArgumentTypeError("amount_base must be a canonical unsigned u64")
    return value


def canonical_amount_atto(value: str) -> str:
    if not value or not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("amount_atto must be a canonical unsigned remainder")
    parsed = int(value)
    if str(parsed) != value or parsed >= 1_000_000:
        raise argparse.ArgumentTypeError("amount_atto must be between 0 and 999999")
    return value


def random_hex32() -> str:
    return "0x" + os.urandom(32).hex()


def load_hex_env(name: str, expected_len: int) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        raise SystemExit(f"Environment variable {name} is required")
    value = raw.removeprefix("0x")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be valid hex") from exc
    if len(data) != expected_len:
        raise SystemExit(f"{name} must be exactly {expected_len} bytes")
    return data


# Fixed, public HKDF salt for the tribute offer encryption key - the canonical
# protocol constant `outbe_tee::OFFER_HKDF_SALT` (ASCII "outbe/tribute/offer-salt/v1",
# zero-padded to 32 bytes). It is the same for every enclave and client (an HKDF
# salt is not secret); clients use this exact value, so TEE_SALT is optional and
# only needed to override it for testing.
OFFER_HKDF_SALT = b"outbe/tribute/offer-salt/v1".ljust(32, b"\0")


def load_tee_config_from_env() -> tuple[bytes, bytes]:
    pubkey = load_hex_env("TEE_PUBLIC_KEY", 32)
    if os.environ.get("TEE_SALT"):
        salt = load_hex_env("TEE_SALT", 32)
    else:
        salt = OFFER_HKDF_SALT
    return pubkey, salt


def sender_from_private_key(private_key: str) -> str:
    return run_cast("wallet", "address", private_key)


def encrypt_payload(tee_pubkey: bytes, tee_salt: bytes, payload: dict) -> tuple[str, str, str]:
    eph_private = X25519PrivateKey.generate()
    eph_public = eph_private.public_key()
    peer = X25519PublicKey.from_public_bytes(tee_pubkey)
    shared_secret = eph_private.exchange(peer)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=tee_salt,
        info=HKDF_INFO,
    )
    encryption_key = hkdf.derive(shared_secret)

    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = ChaCha20Poly1305(encryption_key).encrypt(nonce, plaintext, None)

    return (
        "0x" + ciphertext.hex(),
        "0x" + nonce.hex(),
        "0x"
        + eph_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
    )


def receipt_status(rpc_url: str, tx_hash: str) -> str:
    receipt = run_cast("receipt", tx_hash, "--rpc-url", rpc_url, "--json", expect_json=True)
    return receipt["status"]


def total_supply(rpc_url: str) -> str:
    return run_cast("call", TRIBUTE, "totalSupply()(uint256)", "--rpc-url", rpc_url)


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit an encrypted tribute offer")
    parser.add_argument("--wwd", required=True, type=int, help="Worldwide day (yyyymmdd)")
    parser.add_argument("--private-key", required=True, help="Sender private key")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545", help="RPC URL")
    parser.add_argument(
        "--amount-base",
        default=None,
        help="Canonical unsigned settlement base amount; defaults to a random integer in [10,500)",
    )
    parser.add_argument(
        "--amount-atto",
        default="0",
        help="Six-decimal raw remainder in [0,999999] (legacy field name)",
    )
    parser.add_argument("--currency", default="840", help="ISO currency code")
    parser.add_argument(
        "--gas-limit",
        default=8_000_000,
        type=int,
        help="Explicit gas limit; estimateGas cannot simulate enclave decryption",
    )
    parser.add_argument(
        "--exclude-from-intex-issuance",
        action="store_true",
        help="Exclude the issued Tribute from Intex issuance",
    )
    parser.add_argument(
        "--no-send",
        action="store_true",
        help="Encrypt + print the full ABI calldata, but do not submit (for cast call/send by hand)",
    )
    parser.add_argument(
        "--wallet-address",
        action="append",
        default=[],
        help="Optional agent wallet address (repeatable)",
    )
    parser.add_argument(
        "--sra-address",
        action="append",
        default=[],
        help="Optional agent SRA address (repeatable)",
    )
    args = parser.parse_args()

    amount_base = (
        canonical_amount_base(args.amount_base) if args.amount_base else random_amount_base()
    )
    amount_atto = canonical_amount_atto(args.amount_atto)
    sender = sender_from_private_key(args.private_key)
    tee_pubkey, tee_salt = load_tee_config_from_env()

    if bool(args.wallet_address) != bool(args.sra_address):
        raise SystemExit("wallet-address and sra-address must be provided together or both omitted")

    # worldwide_day + currency are cleartext ABI args, not payload fields.
    payload = {
        "creator": sender,
        "tribute_draft_id": "0x" + os.urandom(32).hex(),
        "amount_base": amount_base,
        "amount_atto": amount_atto,
        "su_hashes": [random_hex32(), random_hex32()],
        "wallet_addresses": args.wallet_address,
        "sra_addresses": args.sra_address,
    }

    cipher_text, nonce, ephemeral_pubkey = encrypt_payload(tee_pubkey, tee_salt, payload)

    print("=== Tribute Offer Input ===")
    print(json.dumps(payload, indent=2))
    print()
    print(f"Sender:        {sender}")
    print(f"TEE pubkey:    0x{tee_pubkey.hex()}")
    print(f"TEE salt:      0x{tee_salt.hex()}")
    print(f"Cipher (pref): {cipher_text[:22]}...")
    print(f"Nonce:         {nonce}")
    print(f"Ephemeral:     {ephemeral_pubkey}")
    print()

    if getattr(args, "no_send", False):
        # Dry run: emit the full ABI calldata so the caller can `cast call`/`cast
        # send` itself (useful when driving the offer from a shell, e.g. tests).
        print("=== Calldata (no-send) ===")
        print(f"CIPHER={cipher_text}")
        print(f"NONCE={nonce}")
        print(f"EPHEMERAL={ephemeral_pubkey}")
        print(f"WORLDWIDE_DAY={int(args.wwd)}")
        print(f"TRIBUTE_CURRENCY={int(args.currency)}")
        print(f"REFERENCE_CURRENCY={int(args.currency)}")
        print(f"EXCLUDE_FROM_INTEX_ISSUANCE={str(args.exclude_from_intex_issuance).lower()}")
        print(f"SENDER={sender}")
        return

    result = run_cast(
        "send",
        FACTORY,
        "offerTribute(bytes,bytes,uint256,uint32,uint16,uint16,bool,bytes,bytes,bytes,bytes,bytes)(bytes)",
        cipher_text,
        nonce,
        ephemeral_pubkey,
        str(args.wwd),
        str(args.currency),
        str(args.currency),
        str(args.exclude_from_intex_issuance).lower(),
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "--rpc-url",
        args.rpc_url,
        "--private-key",
        args.private_key,
        "--gas-limit",
        str(args.gas_limit),
        "--json",
        expect_json=True,
    )

    tx_hash = result["transactionHash"]
    status = receipt_status(args.rpc_url, tx_hash)
    if status not in ("0x1", "1"):
        raise SystemExit(f"Tribute offer transaction failed: {tx_hash} (status={status})")
    print("=== Submitted ===")
    print(f"TX hash:       {tx_hash}")
    print(f"Receipt status:{status}")
    print(f"Total supply:  {total_supply(args.rpc_url)}")


if __name__ == "__main__":
    main()
