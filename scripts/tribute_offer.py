#!/usr/bin/env python3
"""Submit an encrypted Tribute offer to outbe-chain without the Rust CLI.

Byte-for-byte port of `outbe-cli tribute offer`:

  1. read the DKG-derived offer public key from the TeeRegistry (0xEE0A)
  2. (optional) auto-detect the WorldwideDay currently in OFFERING via Metadosis
  3. encrypt the payload to the offer key:
        ephemeral X25519 ECDHE
        -> HKDF-SHA256(salt=OFFER_HKDF_SALT, info="tribute-factory-encryption")
        -> ChaCha20Poly1305 (empty AAD)
     identical to outbe_tee_enclave::crypto::ecdhe_offer_decrypt
  4. ABI-encode + sign (legacy EIP-155) + send `offerTribute` to the
     TributeFactory (0x1100). The enclave decrypts it inside execution.

Deps:  pip install web3 cryptography

Examples:
  # auto-pick the OFFERING day, default amount 100 / currency 840 (USD)
  python3 scripts/tribute_offer.py \
      --rpc https://rpc.testnet.outbe.net \
      --private-key 0x<KEY>

  # explicit day
  python3 scripts/tribute_offer.py --rpc https://rpc.testnet.outbe.net \
      --private-key 0x<KEY> --day 20260601 --amount 100 --currency 840
"""

import argparse
import json
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from web3 import Web3
from eth_account import Account

# --- Protocol addresses (see crates/blockchain/primitives/src/addresses.rs) ---
TEE_REGISTRY_ADDR = Web3.to_checksum_address("0x000000000000000000000000000000000000EE0A")
METADOSIS_ADDR = Web3.to_checksum_address("0x000000000000000000000000000000000000100E")
TRIBUTE_FACTORY_ADDR = Web3.to_checksum_address("0x0000000000000000000000000000000000001100")
TRIBUTE_ADDR = Web3.to_checksum_address("0x0000000000000000000000000000000000001101")

# Fixed enclave offer salt + HKDF info label (must match the enclave).
# Value: outbe_tee::OFFER_HKDF_SALT = ASCII "outbe/tribute/offer-salt/v1",
# zero-padded to 32 bytes (see crates/system/tee/src/lib.rs and
# bin/outbe-tee-enclave/src/keys.rs).
OFFER_SALT = b"outbe/tribute/offer-salt/v1".ljust(32, b"\0")
HKDF_INFO = b"tribute-factory-encryption"

# WorldwideDay status values (crates/core/metadosis/src/schema.rs::status).
STATUS_OFFERING = 2

TEE_REGISTRY_ABI = json.loads(
    """[
      {"type":"function","name":"isBootstrapped","stateMutability":"view",
       "inputs":[],"outputs":[{"type":"bool"}]},
      {"type":"function","name":"tributeOfferPublicKey","stateMutability":"view",
       "inputs":[],"outputs":[{"type":"uint256"}]}
    ]"""
)

METADOSIS_ABI = json.loads(
    """[
      {"type":"function","name":"getWorldwideDaysByStatus","stateMutability":"view",
       "inputs":[{"type":"uint8","name":"status"}],
       "outputs":[{"type":"uint32[]","name":"wwds"}]}
    ]"""
)

TRIBUTE_FACTORY_ABI = json.loads(
    """[
      {"type":"function","name":"offerTribute","stateMutability":"nonpayable",
       "inputs":[
         {"type":"bytes","name":"cipherText"},
         {"type":"bytes","name":"nonce"},
         {"type":"uint256","name":"ephemeralPubkey"},
         {"type":"uint32","name":"worldwideDay"},
         {"type":"uint16","name":"tributeCurrency"},
         {"type":"uint16","name":"referenceCurrency"},
         {"type":"bool","name":"excludeFromIntexIssuance"},
         {"type":"bytes","name":"zkProof"},
         {"type":"bytes","name":"zkVerificationKey"},
         {"type":"bytes","name":"zkPublicKey"},
         {"type":"bytes","name":"zkMerkleRoot"},
         {"type":"bytes","name":"signature"}
       ],
       "outputs":[{"type":"uint256","name":"tributeId"}]}
    ]"""
)

TRIBUTE_ABI = json.loads(
    """[
      {"type":"function","name":"getTributesByOwner","stateMutability":"view",
       "inputs":[{"type":"address","name":"owner"}],
       "outputs":[{"type":"uint256[]"}]}
    ]"""
)


def encrypt_offer(offer_pub: bytes, plaintext: bytes):
    """Ephemeral X25519 ECDHE -> HKDF-SHA256 -> ChaCha20Poly1305 (empty AAD).

    Returns (cipher_text_with_tag, nonce_12, ephemeral_pub_32).
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()  # 32 raw bytes
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(offer_pub))

    key = HKDF(
        algorithm=SHA256(), length=32, salt=OFFER_SALT, info=HKDF_INFO
    ).derive(shared)

    nonce = os.urandom(12)
    cipher_text = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return cipher_text, nonce, eph_pub


def pick_offering_day(w3: Web3) -> int:
    md = w3.eth.contract(address=METADOSIS_ADDR, abi=METADOSIS_ABI)
    days = md.functions.getWorldwideDaysByStatus(STATUS_OFFERING).call()
    if not days:
        sys.exit("no WorldwideDay is currently in OFFERING status")
    if len(days) > 1:
        print(f"multiple OFFERING days {days}; using {days[0]}")
    return int(days[0])


def canonical_amount_base(value: str) -> str:
    if not value or not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("amount_base must be a canonical unsigned u64")
    parsed = int(value)
    if str(parsed) != value or parsed > 18_446_744_073_709_551_615:
        raise argparse.ArgumentTypeError("amount_base must be a canonical unsigned u64")
    return value


def main() -> None:
    ap = argparse.ArgumentParser(description="Submit an encrypted Tribute offer")
    ap.add_argument("--rpc", required=True, help="JSON-RPC endpoint URL")
    ap.add_argument("--private-key", required=True, help="signer private key (hex)")
    ap.add_argument("--day", type=int, default=None,
                    help="WorldwideDay (YYYYMMDD); auto-detect OFFERING if omitted")
    ap.add_argument(
        "--amount",
        default="100",
        help="canonical unsigned amount_base in whole units",
    )
    ap.add_argument("--currency", type=int, default=840, help="ISO 4217 code (840=USD)")
    ap.add_argument("--exclude-from-intex-issuance", action="store_true",
                    help="set the excludeFromIntexIssuance flag")
    ap.add_argument("--gas", type=int, default=8_000_000, help="explicit gas limit")
    ap.add_argument("--wait", action="store_true", help="wait for the receipt")
    args = ap.parse_args()
    amount_base = canonical_amount_base(args.amount)

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    acct = Account.from_key(args.private_key)
    creator = acct.address
    print(f"signer: {creator}")

    # 1. offer key from the TeeRegistry
    reg = w3.eth.contract(address=TEE_REGISTRY_ADDR, abi=TEE_REGISTRY_ABI)
    if not reg.functions.isBootstrapped().call():
        sys.exit("TeeRegistry is not bootstrapped - no offer key to encrypt to")
    offer_pub_u256 = reg.functions.tributeOfferPublicKey().call()
    offer_pub = int(offer_pub_u256).to_bytes(32, "big")
    print(f"offer key (DKG-derived): 0x{offer_pub.hex()}")

    # 2. day
    day = args.day if args.day is not None else pick_offering_day(w3)
    print(f"worldwide_day: {day}")

    # 3. plaintext payload - draft id + su hash must be unique per offer.
    #    worldwide_day + currency travel as cleartext ABI args, not in here.
    payload = {
        "creator": creator,
        "tribute_draft_id": "0x" + os.urandom(32).hex(),
        "amount_base": amount_base,
        "amount_atto": "0",
        "su_hashes": ["0x" + os.urandom(32).hex()],
        "wallet_addresses": [],
        "sra_addresses": [],
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode()

    # 4. encrypt to the offer key
    cipher_text, nonce, eph_pub = encrypt_offer(offer_pub, plaintext)

    # 5. build + sign + send offerTribute (msg.value MUST be 0; zk fields are stubs)
    factory = w3.eth.contract(address=TRIBUTE_FACTORY_ADDR, abi=TRIBUTE_FACTORY_ABI)
    tx = factory.functions.offerTribute(
        cipher_text,
        nonce,
        int.from_bytes(eph_pub, "big"),
        int(day),
        int(args.currency),
        int(args.currency),
        args.exclude_from_intex_issuance,
        b"", b"", b"", b"", b"",
    ).build_transaction(
        {
            "from": creator,
            "value": 0,
            "nonce": w3.eth.get_transaction_count(creator),
            "gas": args.gas,  # estimateGas can't simulate the in-enclave decrypt
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"offerTribute tx: {tx_hash.hex()}")
    print(f"  creator={creator} worldwide_day={day} "
          f"currency={args.currency} amount_base={amount_base}")

    if not args.wait:
        print(f"verify once mined: getTributesByOwner({creator}) on {TRIBUTE_ADDR}")
        return

    print("waiting for receipt...")
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    print(f"status: {rcpt.status} (block {rcpt.blockNumber}, gas {rcpt.gasUsed})")
    if rcpt.status != 1:
        sys.exit("offer reverted - inspect the revert reason via the node")

    time.sleep(1)
    tribute = w3.eth.contract(address=TRIBUTE_ADDR, abi=TRIBUTE_ABI)
    owned = tribute.functions.getTributesByOwner(creator).call()
    print(f"tributes owned by {creator}: {len(owned)}")
    for tid in owned:
        print(f"  - {tid}")


if __name__ == "__main__":
    main()
