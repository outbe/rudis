#!/usr/bin/env python3
"""
Seed genesis.json with precompile storage entries for outbe-chain.

Computes EVM storage slots matching the Rust contract layout
(Solidity-compatible: keccak256(left_pad(key, 32) ++ to_be(slot, 32))).

Usage:
  python3 scripts/seed_genesis.py \
    --genesis /tmp/outbe/genesis.json \
    --seed scripts/seed-testnet.json \
    --validators /tmp/outbe/validators.json \
    --output /tmp/outbe/genesis-seeded.json

Dependencies: pycryptodome (pip install pycryptodome) or pysha3.
Falls back to a small pure-Python Keccak-256 implementation for hermetic
localnet smoke runs when neither optional package is installed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

# --- Keccak256 ---

_MASK64 = (1 << 64) - 1
_KECCAK_RATE_BYTES = 136  # Keccak-256: rate=1088 bits, capacity=512 bits.
_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_KECCAK_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(value: int, shift: int) -> int:
    value &= _MASK64
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    """Apply the Keccak-f[1600] permutation in-place."""
    for rc in _KECCAK_ROUND_CONSTANTS:
        c = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= d[x]

        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROTATION_OFFSETS[x][y]
                )

        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                ) & _MASK64

        state[0] ^= rc


def _pure_python_keccak256(data: bytes) -> bytes:
    """Return Ethereum Keccak-256, not FIPS SHA3-256."""
    state = [0] * 25
    padded = bytearray(data)
    pad_len = _KECCAK_RATE_BYTES - (len(padded) % _KECCAK_RATE_BYTES)
    if pad_len == 1:
        padded.append(0x81)
    else:
        padded.append(0x01)
        padded.extend(b"\x00" * (pad_len - 2))
        padded.append(0x80)

    for offset in range(0, len(padded), _KECCAK_RATE_BYTES):
        block = padded[offset : offset + _KECCAK_RATE_BYTES]
        for lane in range(_KECCAK_RATE_BYTES // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(state)

    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


try:
    from Crypto.Hash import keccak as _keccak_mod  # pyright: ignore[reportMissingImports]

    def keccak256(data: bytes) -> bytes:
        return _keccak_mod.new(data=data, digest_bits=256).digest()
except ImportError:
    try:
        import sha3  # pyright: ignore[reportMissingImports]

        def keccak256(data: bytes) -> bytes:
            return sha3.keccak_256(data).digest()
    except ImportError:

        def keccak256(data: bytes) -> bytes:
            return _pure_python_keccak256(data)


# --- Precompile addresses ---

GRATIS_ADDRESS = "0000000000000000000000000000000000001003"
GRATIS_FACTORY_ADDRESS = "0000000000000000000000000000000000002003"
PROMIS_ADDRESS = "0000000000000000000000000000000000001337"
TRIBUTE_ADDRESS = "0000000000000000000000000000000000001101"
NOD_ADDRESS = "0000000000000000000000000000000000001006"
METADOSIS_ADDRESS = "000000000000000000000000000000000000100e"
TRIBUTE_FACTORY_ADDRESS = "0000000000000000000000000000000000001100"
AGENT_REWARD_ADDRESS = "000000000000000000000000000000000000100b"
FIDELITY_ADDRESS = "000000000000000000000000000000000000100c"
EMISSION_LIMIT_ADDRESS = "000000000000000000000000000000000000100d"
PROMIS_LIMIT_ADDRESS = "000000000000000000000000000000000000100f"
CYCLE_ADDRESS = "0000000000000000000000000000000000001010"
CCA_ADDRESS = "0000000000000000000000000000000000001011"
CREDIS_ADDRESS = "000000000000000000000000000000000000100a"
CREDIS_FACTORY_ADDRESS = "0000000000000000000000000000000000001009"
INTEX_FACTORY_ADDRESS = "0000000000000000000000000000000000001015"
# Factory precompiles seeded as default VaultRouter liquidity sources. Mirror
# the Rust constants in `outbe_primitives::addresses`.
NOD_FACTORY_ADDRESS = "0000000000000000000000000000000000001007"
GEM_FACTORY_ADDRESS = "0000000000000000000000000000000000002013"
# VaultRouter precompile. Genesis seeds the owner (slot 0) and the default
# liquidity source/target registry (see `seed_vault_router`). Mirrors the Rust
# constant `outbe_primitives::addresses::VAULT_ROUTER_ADDRESS`.
VAULT_ROUTER_ADDRESS = "0000000000000000000000000000000000001017"
# PayNote shielded ERC20 note pool. Registered as a VaultRouter liquidity
# source so `deposit` can route pulled ERC20 into the asset's reserve vault.
# Mirrors the Rust constant `outbe_primitives::addresses::PAYNOTE_ADDRESS`.
PAYNOTE_ADDRESS = "0000000000000000000000000000000000001019"
# Gem NFT token precompile. Genesis can seed Settled gems (see `seed_gems`) so a
# demo account has a mineable gem to convert Gem -> Promis -> Gratis; Gratis and
# Promis are TEE-encrypted and can no longer be plaintext-seeded at genesis.
GEM_ADDRESS = "0000000000000000000000000000000000001013"
# Governance precompile. Genesis seeds the authorities set (validator addresses,
# the PoC write-gate) and the canon / meta-canon texts at version 1. Mirrors the
# Rust constant `outbe_primitives::addresses::GOVERNANCE_ADDRESS`.
GOVERNANCE_ADDRESS = "0000000000000000000000000000000000001018"
VALIDATOR_SET_ADDRESS = "000000000000000000000000000000000000ee00"
SLASH_INDICATOR_ADDRESS = "000000000000000000000000000000000000ee01"
STAKING_ADDRESS = "000000000000000000000000000000000000ee02"
REWARDS_ADDRESS = "000000000000000000000000000000000000ee03"
# V2 Phase 1 accounting progress marker. Mirrors the Rust constant
# `outbe_primitives::addresses::ACCOUNTING_PROGRESS_ADDRESS`. The account has
# no precompile dispatch; the executor relies on the `0xef` marker bytecode
# (deployed via `ALL_PRECOMPILE_ADDRESSES` below) to keep slot 0
# (`last_accounted_block_number: u64`) alive across EIP-161 cleanup.
ACCOUNTING_PROGRESS_ADDRESS = "000000000000000000000000000000000000ee04"
ORACLE_ADDRESS = "000000000000000000000000000000000000ee05"
# ZeroFee paymaster precompile at 0xEE09. Holds per-signer EIP-7702
# sponsorship counters; the precompile itself has dispatch logic in
# `outbe-evm/src/precompiles.rs`, so the marker bytecode below is what
# protects its account (and slot 0) from EIP-161 cleanup before the
# first sponsored tx ever lands.
ZEROFEE_ADDRESS = "000000000000000000000000000000000000ee09"
# Compressed-entity EVM schema V3. ADR-011 adds the retirement journal.
# Catalog, so slot 1 is non-zero even though no collection exists at genesis.
COMPRESSED_ENTITIES_ADDRESS = "000000000000000000000000000000000000ee0d"
COMPRESSED_ENTITIES_SCHEMA_VERSION = 4
COMPRESSED_ENTITIES_EMPTY_SEALED_ROOT = int(
    "086cb3c24884752e6453a9d44e15c1f465c0874e5312d18c05feaafec1587802", 16
)
# TEE registry precompile at 0xEE0A. Genesis seeds only slot 2 (`policy_hash`),
# and only when `tee_policy` is present in the seed config; the rest of the
# registry is written by the block-1 `TeeBootstrap` system tx. The account is
# preserved across EIP-161 at runtime by `OUTBE_RUNTIME_MARKER_ADDRESSES`; when a
# policy is seeded it also gets genesis marker bytecode so slot 2 survives to
# block 1. Mirrors `outbe_primitives::addresses::TEE_REGISTRY_ADDRESS`.
TEE_REGISTRY_ADDRESS = "000000000000000000000000000000000000ee0a"
UPDATE_ADDRESS = "0x000000000000000000000000000000000000ee0b"
VOTE_ADDRESS = "0x000000000000000000000000000000000000ee0c"
# Stablecoin Factory/Policy fixed accounts and the dynamic-token address class.
# These mirror outbe_primitives::addresses and are reserved from genesis even
# before production dispatch activates.
STABLECOIN_FACTORY_ADDRESS = "000000000000000000000000000000000000ee0f"
STABLECOIN_POLICY_REGISTRY_ADDRESS = "000000000000000000000000000000000000ee10"
RADICLE_REGISTRY_ADDRESS = "000000000000000000000000000000000000ee11"
# Emit private-note tree precompile. Mirrors the Rust constant
# `outbe_primitives::addresses::EMIT_ADDRESS`. Genesis reserves and marks the
# account only; its chain-specific empty ladder and tree are derived at runtime
# by the first burn, so no Emit field state is ever precomputed here.
EMIT_ADDRESS = "000000000000000000000000000000000000ee13"
STABLECOIN_ADDRESS_PREFIX = "53c0"
OUTBE_SYSTEM_TX_ADDRESS = "ff00000000000000000000000000000000000001"

MIN_STAKE = 100_000 * 10**18
DEFAULT_UNBONDING_PERIOD = 21 * 24 * 3600
DEFAULT_REREGISTRATION_COOLDOWN_BLOCKS = 151_200
# ~1 hour at a ~3s block (40 min at 2s ... 2.7 h at 8s). The epoch is the cadence
# for DKG reshare, active-set rotation, and the per-epoch slash-counter reset, so
# it bounds the felony window: a felony threshold (default 150) must stay below it.
DEFAULT_EPOCH_LENGTH_BLOCKS = 1_200
SECONDS_PER_DAY = 86_400

# Profile selectors. Numbers live in Rust (crates/core/intexfactory/src/config.rs
# and crates/core/gem/src/config.rs); genesis only picks one. The slots are pinned
# by a test in each crate.
PROFILE_SELECTORS = {"auto": 0, "dev": 1, "prod": 2}
INTEX_PROFILE_SLOT = 10
GEM_PROFILE_SLOT = 42

ALL_PRECOMPILE_ADDRESSES = [
    GRATIS_ADDRESS, GRATIS_FACTORY_ADDRESS, PROMIS_ADDRESS, TRIBUTE_ADDRESS,
    NOD_ADDRESS, GEM_ADDRESS, METADOSIS_ADDRESS, TRIBUTE_FACTORY_ADDRESS, AGENT_REWARD_ADDRESS,
    FIDELITY_ADDRESS, EMISSION_LIMIT_ADDRESS, PROMIS_LIMIT_ADDRESS,
    CYCLE_ADDRESS, CREDIS_ADDRESS, CREDIS_FACTORY_ADDRESS, VAULT_ROUTER_ADDRESS,
    GOVERNANCE_ADDRESS, STABLECOIN_FACTORY_ADDRESS,
    STABLECOIN_POLICY_REGISTRY_ADDRESS,
    RADICLE_REGISTRY_ADDRESS,
    UPDATE_ADDRESS, VOTE_ADDRESS,
    EMIT_ADDRESS,
    VALIDATOR_SET_ADDRESS, SLASH_INDICATOR_ADDRESS,
    STAKING_ADDRESS, REWARDS_ADDRESS, ACCOUNTING_PROGRESS_ADDRESS, ORACLE_ADDRESS,
    ZEROFEE_ADDRESS, COMPRESSED_ENTITIES_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS,
]

# Protocol-owned balance accumulators without precompile dispatch. They are
# collision-protected for genesis tooling but do not receive marker bytecode.
PROTOCOL_ACCUMULATOR_ADDRESSES = [
    CCA_ADDRESS,
]
PROTECTED_PROTOCOL_ADDRESSES = set(
    ALL_PRECOMPILE_ADDRESSES
    + PROTOCOL_ACCUMULATOR_ADDRESSES
)

# Marker bytecode for precompile accounts (prevents EIP-161 empty account removal)
MARKER_CODE = "0xef"


# --- Storage slot computation ---

def to_be32(val: int) -> bytes:
    """Encode integer as 32-byte big-endian."""
    return val.to_bytes(32, "big")


def hex32(val: int) -> str:
    """Encode integer as 0x-prefixed 32-byte hex string."""
    return "0x" + val.to_bytes(32, "big").hex()


def mapping_key(key_bytes: bytes, base_slot: int) -> str:
    """
    Compute Solidity-compatible mapping slot.
    slot = keccak256(left_pad(key_bytes, 32) ++ to_be(base_slot, 32))
    """
    padded = key_bytes.rjust(32, b"\x00")
    slot_bytes = to_be32(base_slot)
    h = keccak256(padded + slot_bytes)
    return "0x" + h.hex()


def address_bytes(addr_hex: str) -> bytes:
    """Parse 0x-prefixed address to 20 bytes."""
    addr = addr_hex.lower().replace("0x", "")
    assert len(addr) == 40, f"invalid address length: {addr_hex}"
    return bytes.fromhex(addr)


def validate_stablecoin_namespace_alloc(
    alloc: dict, *, require_reserved_markers: bool
) -> None:
    """Reject genesis state that collides with the Stablecoin V1 namespace.

    The two fixed accounts may contain only the exact marker and zero-valued
    account metadata. Every dynamic-class allocation is forbidden, including a
    balance-only account, because CREATE/CREATE2 reservation starts at genesis.
    """
    normalized = {}
    for raw_address, account in alloc.items():
        normalized_address = address_bytes(raw_address).hex()
        if normalized_address in normalized:
            raise ValueError(
                "duplicate genesis alloc address after normalization: "
                f"{raw_address} and {normalized[normalized_address][0]}"
            )
        if not isinstance(account, dict):
            raise ValueError(f"genesis alloc {raw_address} must be an object")
        normalized[normalized_address] = (raw_address, account)

        if normalized_address.startswith(STABLECOIN_ADDRESS_PREFIX):
            raise ValueError(
                f"genesis alloc {raw_address} collides with reserved stablecoin "
                f"prefix 0x{STABLECOIN_ADDRESS_PREFIX}"
            )

    for address in (
        STABLECOIN_FACTORY_ADDRESS,
        STABLECOIN_POLICY_REGISTRY_ADDRESS,
    ):
        item = normalized.get(address)
        if item is None:
            if require_reserved_markers:
                raise ValueError(f"missing stablecoin reserved account 0x{address}")
            continue
        raw_address, account = item
        code = account.get("code")
        if code is not None and str(code).lower() != MARKER_CODE:
            raise ValueError(
                f"stablecoin reserved account {raw_address} has conflicting code"
            )
        if require_reserved_markers and str(code).lower() != MARKER_CODE:
            raise ValueError(
                f"stablecoin reserved account {raw_address} is missing marker code"
            )
        if account.get("storage"):
            raise ValueError(
                f"stablecoin reserved account {raw_address} has conflicting storage"
            )
        for field in ("balance", "nonce"):
            value = account.get(field, "0x0")
            try:
                nonzero = int(str(value), 0) != 0
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"stablecoin reserved account {raw_address} has invalid {field}"
                ) from error
            if nonzero:
                raise ValueError(
                    f"stablecoin reserved account {raw_address} has nonzero {field}"
                )


def u32_bytes(val: int) -> bytes:
    """Encode u32 as 4-byte big-endian."""
    return val.to_bytes(4, "big")


def wwd_to_day_timestamp(wwd: int) -> int:
    """UTC-midnight unix timestamp for a YYYYMMDD worldwide day. Matches the
    runtime's `worldwide_day_to_utc_timestamp` + `truncate_to_day`."""
    import datetime as _dt

    y, m, d = wwd // 10_000, (wwd // 100) % 100, wwd % 100
    return int(_dt.datetime(y, m, d, tzinfo=_dt.timezone.utc).timestamp())


def u64_bytes(val: int) -> bytes:
    """Encode u64 as 8-byte big-endian."""
    return val.to_bytes(8, "big")


def b256_bytes(hex_str: str) -> bytes:
    """Parse 0x-prefixed B256 to 32 bytes."""
    h = hex_str.lower().replace("0x", "")
    assert len(h) == 64, f"invalid B256 length: {hex_str}"
    return bytes.fromhex(h)


def compute_tee_policy_hash(
    allowed_mrsigner: list, allowed_mrenclave: list, min_isv_svn: int
) -> bytes:
    """Canonical genesis TEE policy hash.

    MUST match `outbe_primitives::tee_bootstrap::TeePolicy::compute_hash`:
    `keccak256(b"outbe/tee/policy/v1" || u16_be(len(mrsigner)) || sorted(mrsigner)
    || u16_be(len(mrenclave)) || sorted(mrenclave) || u16_be(min_isv_svn))`.
    Lists are sorted ascending by their 32 raw bytes (matching Rust's `B256`
    `sort_unstable`), so the hash is independent of allowlist ordering.
    """
    signers = sorted(b256_bytes(s) for s in allowed_mrsigner)
    enclaves = sorted(b256_bytes(e) for e in allowed_mrenclave)
    buf = b"outbe/tee/policy/v1"
    buf += len(signers).to_bytes(2, "big")
    for s in signers:
        buf += s
    buf += len(enclaves).to_bytes(2, "big")
    for e in enclaves:
        buf += e
    buf += int(min_isv_svn).to_bytes(2, "big")
    return keccak256(buf)


def pubkey_bytes(hex_str: str) -> bytes:
    """Parse a 48-byte BLS MinPk public key."""
    h = hex_str.lower().replace("0x", "")
    if len(h) != 96:
        raise ValueError(f"invalid BLS public key length: {hex_str}")
    return bytes.fromhex(h)


def radicle_node_id_bytes(value: object, *, validator_index: int) -> bytes:
    """Parse one founder's required non-zero 32-byte Radicle NodeId."""
    if not isinstance(value, str):
        raise ValueError(f"validator {validator_index} radicle_node_id is required")
    raw = value.removeprefix("0x").removeprefix("0X")
    if len(raw) != 64:
        raise ValueError(
            f"validator {validator_index} radicle_node_id must be 64 hex chars"
        )
    try:
        node_id = bytes.fromhex(raw)
    except ValueError as error:
        raise ValueError(
            f"validator {validator_index} radicle_node_id must be hexadecimal"
        ) from error
    if node_id == bytes(32):
        raise ValueError(f"validator {validator_index} radicle_node_id must not be zero")
    return node_id


def address_as_u256(addr_hex: str) -> int:
    """Convert address to U256 (right-aligned in 32 bytes)."""
    return int(addr_hex, 16)


def parse_int(val) -> int:
    """Parse string or int to Python int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        if val.startswith("0x"):
            return int(val, 16)
        return int(val)
    raise ValueError(f"cannot parse as int: {val}")


def parse_genesis_timestamp(genesis: dict) -> int:
    """Parse ``config.genesisTime`` (ISO 8601 UTC) as a unix timestamp."""
    from datetime import datetime
    config = genesis.get("config", {})
    genesis_time_str = config.get("genesisTime")
    if not genesis_time_str:
        genesis_time_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    dt = datetime.fromisoformat(genesis_time_str.replace("Z", "+00:00"))
    return int(dt.timestamp())


def parse_header_timestamp(genesis: dict) -> int:
    """Parse the consensus header ``timestamp`` as a unix timestamp."""
    if "timestamp" not in genesis:
        raise ValueError("genesis header timestamp is required")
    return parse_int(genesis["timestamp"])


def timestamp_to_utc_date_key(timestamp: int) -> int:
    """Convert a unix timestamp to a UTC yyyymmdd date key."""
    if timestamp < 0:
        raise ValueError(f"genesis timestamp must be non-negative: {timestamp}")
    return civil_date_from_days(timestamp // SECONDS_PER_DAY)


def seed_cycle(storage: "StorageBuilder", genesis_timestamp: int):
    """Seed Cycle slot 2 with the UTC day owned by the genesis block."""
    storage.set_slot(2, timestamp_to_utc_date_key(genesis_timestamp))


def civil_date_from_days(days_since_epoch: int) -> int:
    """Integer UTC calendar conversion matching outbe_primitives::time."""
    z = days_since_epoch + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    if m <= 2:
        y += 1
    return y * 10000 + m * 100 + d


def alloc_balance_hex(amount: int) -> str:
    """Encode an account balance as compact 0x-prefixed hex."""
    return hex(amount)


# --- Storage builder ---

class StorageBuilder:
    """Accumulates storage entries for a contract address."""

    def __init__(self):
        self.entries: dict[str, str] = {}

    def set_slot(self, slot: int, value: int):
        """Set a direct slot value."""
        self.entries[hex32(slot)] = hex32(value)

    def set_raw_slot(self, slot: int | str, value: int):
        """Set a storage slot by integer slot or 0x-prefixed slot key."""
        key = hex32(slot) if isinstance(slot, int) else slot.lower()
        self.entries[key] = hex32(value)

    def set_raw_slot_hex(self, slot: int | str, value_hex: str):
        """Set a storage slot to an already encoded 0x-prefixed 32-byte value."""
        key = hex32(slot) if isinstance(slot, int) else slot.lower()
        value = value_hex.lower()
        assert value.startswith("0x") and len(value) == 66, f"invalid storage word: {value_hex}"
        self.entries[key] = value

    def set_mapping(self, base_slot: int, key_bytes: bytes, value: int):
        """Set a mapping entry."""
        k = mapping_key(key_bytes, base_slot)
        self.entries[k] = hex32(value)

    def set_mapping_b256(self, base_slot: int, key_bytes: bytes, value_bytes: bytes):
        """Set a mapping entry with a B256 value."""
        k = mapping_key(key_bytes, base_slot)
        self.entries[k] = "0x" + value_bytes.hex()

    def set_mapping_pair(self, base_slot: int, key_bytes: bytes, base: str, quote: str):
        """
        Set a two-word `Mapping<K, AddressPair>` entry.

        An oracle pair is 40 bytes and a storage word is 32, so the value spans
        the key's mapping slot and the one after it - base then quote, the same
        layout Solidity gives `mapping(K => struct { address; address; })`.
        Callers pass the pair in its registered orientation; nothing here sorts it.
        """
        slot = int(mapping_key(key_bytes, base_slot), 16)
        self.set_raw_slot(slot, int.from_bytes(asset_address(base), "big"))
        self.set_raw_slot(slot + 1, int.from_bytes(asset_address(quote), "big"))


def data_slot(base_slot: int) -> int:
    """Solidity dynamic bytes/string data slot: keccak256(base_slot)."""
    return int.from_bytes(keccak256(to_be32(base_slot)), "big")


def write_storage_bytes(storage: StorageBuilder, base_slot: int | str, data: bytes):
    """Write Solidity-compatible bytes/string storage at a direct base slot."""
    slot_int = base_slot if isinstance(base_slot, int) else int(base_slot, 16)
    length = len(data)

    if length <= 31:
        word = bytearray(32)
        word[:length] = data
        word[31] = length * 2
        storage.set_raw_slot_hex(base_slot, "0x" + word.hex())
        return

    storage.set_raw_slot(base_slot, length * 2 + 1)
    start = data_slot(slot_int)
    for i in range((length + 31) // 32):
        chunk = data[i * 32:(i + 1) * 32]
        word = bytearray(32)
        word[:len(chunk)] = chunk
        storage.set_raw_slot_hex(start + i, "0x" + word.hex())


def write_mapping_string(storage: StorageBuilder, base_slot: int, key_bytes: bytes, value: str):
    """Write Mapping<K, StorageBytes>::write_string-compatible metadata."""
    write_storage_bytes(storage, mapping_key(key_bytes, base_slot), value.encode())


def write_mapping_bytes(storage: StorageBuilder, base_slot: int, key_bytes: bytes, value: bytes):
    """Write Mapping<K, StorageBytes>::write-compatible metadata."""
    write_storage_bytes(storage, mapping_key(key_bytes, base_slot), value)


P2P_ADDRESS_VERSION_V1 = 1
MAX_P2P_ADDRESS_ENCODED_LEN = 512


def parse_host_port(value: str) -> tuple[str, int]:
    """Parse host:port, including [IPv6]:port."""
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
            raise ValueError(f"invalid socket address: {value}")
        host = value[1:end]
        port_s = value[end + 2:]
    else:
        if ":" not in value:
            raise ValueError(f"invalid socket address: {value}")
        host, port_s = value.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError as exc:
        raise ValueError(f"invalid port in socket address: {value}") from exc
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid port in socket address: {value}")
    return host, port


def validate_hostname(host: str):
    if not host or len(host) > 253:
        raise ValueError(f"invalid DNS hostname: {host}")
    for label in host.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid DNS hostname: {host}")
        if label[0] == "-" or label[-1] == "-":
            raise ValueError(f"invalid DNS hostname: {host}")
        if not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label):
            raise ValueError(f"invalid DNS hostname: {host}")


def encode_p2p_socket(value: str) -> bytes:
    host, port = parse_host_port(value)
    ip = ipaddress.ip_address(host)
    if ip.version == 4:
        return bytes([4]) + ip.packed + port.to_bytes(2, "big")
    if ip.version == 6:
        return bytes([6]) + ip.packed + port.to_bytes(2, "big")
    raise ValueError(f"unsupported ip version in socket address: {value}")


def encode_p2p_ingress(value) -> bytes:
    if isinstance(value, str):
        return bytes([0]) + encode_p2p_socket(value)
    if isinstance(value, dict):
        if "socket" in value:
            return bytes([0]) + encode_p2p_socket(value["socket"])
        if "dns" in value:
            dns = value["dns"]
            host = dns["host"]
            port = parse_int(dns["port"])
            if port <= 0 or port > 65535:
                raise ValueError(f"invalid DNS ingress port: {port}")
            validate_hostname(host)
            encoded_host = host.encode()
            return (
                bytes([1])
                + len(encoded_host).to_bytes(2, "big")
                + encoded_host
                + port.to_bytes(2, "big")
            )
    raise ValueError(f"invalid p2p ingress value: {value}")


def encode_p2p_address_payload(value) -> tuple[int, bytes] | None:
    """Encode a validator p2p address seed into Outbe versioned bytes."""
    if value is None:
        return None
    if isinstance(value, str):
        payload = bytes([0]) + encode_p2p_socket(value)
    elif isinstance(value, dict):
        if "symmetric" in value:
            payload = bytes([0]) + encode_p2p_socket(value["symmetric"])
        elif "asymmetric" in value:
            asymmetric = value["asymmetric"]
            payload = (
                bytes([1])
                + encode_p2p_ingress(asymmetric["ingress"])
                + encode_p2p_socket(asymmetric["egress"])
            )
        else:
            raise ValueError(f"invalid p2p_address object: {value}")
    else:
        raise ValueError(f"invalid p2p_address value: {value}")
    if len(payload) > MAX_P2P_ADDRESS_ENCODED_LEN:
        raise ValueError(
            f"p2p_address payload exceeds {MAX_P2P_ADDRESS_ENCODED_LEN} bytes"
        )
    return P2P_ADDRESS_VERSION_V1, payload


# Marker nibbles every ISO currency address carries, keeping the reserved range
# clear of low-numbered token addresses. Mirrors ISO_MARKER in
# crates/blockchain/primitives/src/asset_type.rs.
ISO_MARKER = 0xCC000


def asset_address(spec: str) -> bytes:
    """
    An oracle asset as its 20-byte address.

    Accepts "COEN"/"native" for the native asset (the zero address), a decimal
    ISO 4217 numeric code, or an explicit 0x-prefixed ERC20 address. Mirrors
    `AssetType` in crates/blockchain/primitives/src/asset_type.rs.
    """
    text = str(spec).strip()
    if text.upper() in ("RUDIS", "COEN", "NATIVE"):
        return bytes(20)
    if text.lower().startswith("0x"):
        return address_bytes(text)
    if text.isdigit():
        code = int(text)
        if not 1 <= code <= 999:
            raise ValueError(f"ISO 4217 code out of range: {text}")
        # One decimal digit per nibble, behind the marker: 840 -> 0x0cc840.
        return (ISO_MARKER | int(f"{code:04d}", 16)).to_bytes(20, "big")
    raise ValueError(
        f"oracle asset must be COEN, an ISO 4217 numeric code or a 0x address: {spec!r}"
    )


def address_pair(base: str, quote: str) -> bytes:
    """
    Oracle pair storage key: both asset addresses concatenated ascending.

    Order-independent, so `COEN/840` and `840/COEN` are one key. `mapping_key`
    needs no special case: it left-pads with `rjust(32)`, which never truncates,
    so a 40-byte key falls through unpadded and yields the same slot as the Rust
    `StorageKey for AddressPair` override.
    """
    low, high = sorted((asset_address(base), asset_address(quote)))
    return low + high


def is_iso_asset_address(address: bytes) -> bool:
    """Mirror `AssetType::IsoCurrency` for an already encoded asset address."""
    raw = int.from_bytes(address, "big")
    if not ISO_MARKER <= raw <= ISO_MARKER | 0x999:
        return False
    bcd = raw - ISO_MARKER
    return all(((bcd >> shift) & 0xF) <= 9 for shift in (0, 4, 8, 12))


# --- Seeders ---

# Gem states (crates/core/gem/src/schema.rs::GemState). Only Settled gems may be
# genesis-seeded - `add_gem` parks Issued gems in a bin-tree index this seeder
# does not reproduce, and `minePromis` requires state == Settled.
GEM_STATE_SETTLED = 3
# Default gem type when unspecified (GemTypes::Wallet). Not validated by
# `minePromis`, so any agent class works.
GEM_TYPE_WALLET = 3


def gem_id_gen(owner: str, promis_load: int, index: int) -> bytes:
    """Genesis gem id = keccak256("gem" ++ owner_20B ++ promis_load_be32 ++ index_be8).

    Mirrors the shape of `GemContract::generate_gem_id` (which uses the issuing
    block number); `index` disambiguates multiple genesis gems for one owner.
    The demo scripts never need to predict this - they discover the id via
    `IGem.tokenOfOwnerByIndex(owner, 0)`.
    """
    buf = b"gem" + address_bytes(owner) + to_be32(promis_load) + u64_bytes(index)
    return keccak256(buf)


def gem_owner_index_key(owner: str, index: int) -> bytes:
    """keccak256(owner_20B ++ index_be4) - matches GemContract::owner_index_key."""
    return keccak256(address_bytes(owner) + u32_bytes(index))


def seed_gems(storage: StorageBuilder, gems: list):
    """Seed Settled gems into the flat `GemContract` storage at GEM_ADDRESS.

    Reproduces exactly what `GemContract::add_gem` writes for a Settled gem, so a
    seeded gem is fully mineable (`minePromis` -> confidential Promis) and
    burns cleanly. Layout pinned by the `gem_storage_layout_matches_genesis_seeder`
    test in `crates/core/gem/src/tests.rs`:

      slot 0:      total_supply (u64)
      slots 1-17:  gem_items Map<U256, GemData> record fields keyed by gem_id:
                     1 owner              2 gem_type           3 promis_load_minor
                     4 entry_price_minor  5 floor_price_minor  6 issuance_currency
                     7 reference_currency 8 state              9 issued_at
                     10 call_price_minor  11 called_at         12 call_notice_period
                     13 call_rate         14 call_window       15 call_threshold
                     16 qualified_at      17 settled_at
      slot 18:     owner_gem_counts Map<Address, u32>
      slot 19:     owner_gem_ids    Map<B256, U256>  (key = owner_index_key)
      slot 20:     all_gem_ids      List<U256>  (len @ slot 20, data @ keccak(20)+i)
      slot 21:     gem_index        Map<U256, u32>

    Settled gems are NOT parked in the unqualified bin-tree index (slots 22+), the
    qualified one, or the called queue, so those slots are intentionally left empty
    (add_gem indexes Issued gems by floor price and Qualified ones by call price).
    """
    owner_counts: dict[str, int] = {}
    for i, gem in enumerate(gems):
        owner = gem["owner"]
        promis_load = parse_int(gem["promis_load"])
        state = parse_int(gem.get("state", GEM_STATE_SETTLED))
        if state != GEM_STATE_SETTLED:
            raise ValueError(
                f"seed_gems only supports Settled gems (state={GEM_STATE_SETTLED}); "
                f"got state={state}"
            )
        gem_id = gem_id_gen(owner, promis_load, i)

        # gem_items record (slots 1-17, keyed by gem_id).
        storage.set_mapping(1, gem_id, address_as_u256(owner))
        storage.set_mapping(2, gem_id, parse_int(gem.get("gem_type", GEM_TYPE_WALLET)))
        storage.set_mapping(3, gem_id, promis_load)
        storage.set_mapping(4, gem_id, parse_int(gem.get("entry_price", "0")))
        storage.set_mapping(5, gem_id, parse_int(gem.get("floor_price", "0")))
        storage.set_mapping(6, gem_id, parse_int(gem.get("issuance_currency", 840)))
        storage.set_mapping(7, gem_id, parse_int(gem.get("reference_currency", 840)))
        storage.set_mapping(8, gem_id, state)
        issued_at = parse_int(gem.get("issued_at", 0))
        storage.set_mapping(9, gem_id, issued_at)
        storage.set_mapping(10, gem_id, parse_int(gem.get("call_price_minor", "0")))
        storage.set_mapping(11, gem_id, parse_int(gem.get("called_at", 0)))
        # call_notice_period: add_gem snapshots CALL_NOTICE_PERIOD (7 days, in seconds).
        storage.set_mapping(12, gem_id, parse_int(gem.get("call_notice_period", 7 * 24 * 3600)))
        # call_rate: the markup above 100%, so call_price = entry x (100 + rate)/100.
        # `add_gem` snapshots CALL_RATE (128), which is the 2.28x the docs quote.
        storage.set_mapping(13, gem_id, parse_int(gem.get("call_rate", 128)))
        # call_window: add_gem snapshots CALL_WINDOW (28 days, in seconds).
        storage.set_mapping(14, gem_id, parse_int(gem.get("call_window", 28 * 24 * 3600)))
        # call_threshold: add_gem snapshots CALL_THRESHOLD (21 days, in seconds).
        storage.set_mapping(15, gem_id, parse_int(gem.get("call_threshold", 21 * 24 * 3600)))
        # qualified_at / settled_at: seeded gems are Settled, so both default to
        # issued_at (the gem reached those states at issuance).
        storage.set_mapping(16, gem_id, parse_int(gem.get("qualified_at", issued_at)))
        storage.set_mapping(17, gem_id, parse_int(gem.get("settled_at", issued_at)))

        # owner_gem_ids index (slot 19) + swap-and-pop counter (slot 18 below).
        oi = owner_counts.get(owner.lower(), 0)
        storage.set_mapping(19, gem_owner_index_key(owner, oi), int.from_bytes(gem_id, "big"))
        owner_counts[owner.lower()] = oi + 1

        # all_gem_ids List element i (slot 20 data region) + gem_index (slot 21).
        storage.set_raw_slot(data_slot(20) + i, int.from_bytes(gem_id, "big"))
        storage.set_mapping(21, gem_id, i)

    for owner, count in owner_counts.items():
        storage.set_mapping(18, address_bytes(owner), count)

    # total_supply (slot 0) and all_gem_ids length (slot 20).
    storage.set_slot(0, len(gems))
    storage.set_slot(20, len(gems))


def seed_coen(alloc: dict, balances: dict):
    """
    native EVM token alloc layout:
      alloc[addr].balance: U256 COEN unit
    """
    for addr, amount_str in balances.items():
        amount = parse_int(amount_str)
        alloc.setdefault(address_bytes(addr).hex(), {})["balance"] = alloc_balance_hex(amount)


def tribute_token_id(owner: str, worldwide_day: int) -> bytes:
    """Generate tribute token_id = keccak256(owner_20B ++ wwd_4B)."""
    buf = address_bytes(owner) + u32_bytes(worldwide_day)
    return keccak256(buf)


def day_index_key(day: int, index: int) -> bytes:
    """keccak256(day_4B ++ index_4B) for tribute day index."""
    buf = u32_bytes(day) + u32_bytes(index)
    return keccak256(buf)


def owner_index_key(owner: str, index: int) -> bytes:
    """keccak256(owner_20B ++ index_4B) for tribute/nod owner index."""
    buf = address_bytes(owner) + u32_bytes(index)
    return keccak256(buf)


def seed_tributes(storage: StorageBuilder, tributes: list):
    """
    Tribute storage layout:
      slot 0: total_supply (u64)
      slot 1: mapping(B256 => Address) owners
      slot 2: mapping(B256 => u32) worldwide_days
      slot 3: mapping(B256 => U256) issuance_amounts
      slot 4: mapping(B256 => u32) settlement_currencies
      slot 5: mapping(B256 => U256) nominal_amounts
      slot 6: mapping(u32 => u32) day_tribute_counts
      slot 7: mapping(u32 => U256) day_nominal_amounts
      slot 8: mapping(u32 => bool) day_blocked
      slot 9: mapping(B256 => B256) day_token_ids
      slot 10: mapping(Address => u32) owner_tribute_counts
      slot 11: mapping(B256 => B256) owner_tribute_ids
    """
    # Track per-day and per-owner counters
    day_counts: dict[int, int] = {}
    day_nominals: dict[int, int] = {}
    owner_counts: dict[str, int] = {}

    for tribute in tributes:
        owner = tribute["owner"]
        wwd = tribute["worldwide_day"]
        settlement = parse_int(tribute["issuance_amount"])
        currency = tribute["issuance_currency"]
        nominal = parse_int(tribute["nominal_amount"])

        # Generate token_id
        token_id = tribute_token_id(owner, wwd)

        # Store tribute fields
        storage.set_mapping(1, token_id, address_as_u256(owner))
        storage.set_mapping(2, token_id, wwd)
        storage.set_mapping(3, token_id, settlement)
        storage.set_mapping(4, token_id, currency)
        storage.set_mapping(5, token_id, nominal)

        # Day index (slot 9)
        day_idx = day_counts.get(wwd, 0)
        di_key = day_index_key(wwd, day_idx)
        storage.set_mapping_b256(9, di_key, token_id)
        day_counts[wwd] = day_idx + 1

        # Day nominal accumulator
        day_nominals[wwd] = day_nominals.get(wwd, 0) + nominal

        # Owner index (slot 11)
        owner_lower = owner.lower()
        oi = owner_counts.get(owner_lower, 0)
        oi_key = owner_index_key(owner, oi)
        storage.set_mapping_b256(11, oi_key, token_id)
        owner_counts[owner_lower] = oi + 1

    # Write day counts and nominals
    for wwd, count in day_counts.items():
        storage.set_mapping(6, u32_bytes(wwd), count)
    for wwd, nominal_total in day_nominals.items():
        storage.set_mapping(7, u32_bytes(wwd), nominal_total)

    # Write owner counts
    for owner, count in owner_counts.items():
        storage.set_mapping(10, address_bytes(owner), count)

    # Total supply
    storage.set_slot(0, len(tributes))


def seed_tribute_day_totals(storage: StorageBuilder, days: list[int]):
    """Initialize the Tribute `day_totals` DSL record for OFFERING days so
    `offerTribute` is accepted: `ensure_day_accepts_tributes` requires
    `initialized == true && !is_sealed`, and a directly-seeded OFFERING worldwide
    day never ran the metadosis `unseal_day` that normally initializes it.

    `day_totals` is `Map<WorldwideDay, DayTotals>` at TributeContract slot 1
    (storage_schema cumulative offsets: `total_supply`@0 = 1 slot, then
    `day_totals` lands at slot 1; Tribute bodies no longer occupy EVM storage).
    Within the `DayTotals` record the
    field offset is the cumulative slot index by `#[attribute(order)]`:
    `initialized`@0, `tribute_count`@1, `tribute_nominal_amount`@2,
    `is_sealed`@3 (its `order = 4` only sorts; the gap at 3 is not reserved).
    So `day_totals[wwd].initialized` is `Mapping(base_slot=1).get(wwd)`; writing
    1 makes the record exist + initialized, with `is_sealed` left at its `false`
    default."""
    for wwd in days:
        storage.set_mapping(1, u32_bytes(wwd), 1)


def seed_nod_materialization_fifo(storage: StorageBuilder):
    """Initialize the canonical NOD materialization FIFO bounds."""
    # Pinned by `materialization_fifo_slots_match_the_genesis_seeder` in
    # `crates/core/nod/src/adr006_tests.rs`.
    storage.set_slot(19, 1)  # head_sequence
    storage.set_slot(20, 1)  # tail_sequence (next-free)


def seed_metadosis(storage: StorageBuilder, config: dict):
    """
    Metadosis storage layout - MUST track `crates/core/metadosis/src/schema.rs`
    (`#[storage_schema] MetadosisContract`). Attributes occupy slots in declared
    order; a `Map<WorldwideDayKey, WorldwideDay>` consumes one base slot per record
    field, a `Value` one slot, and a `Set` two (length + positions base):

      slot 0:      bootstrap_end_time (Value<u64>)
      slots 1-10:  worldwide_days (Map<u32, WorldwideDay>) - one mapping per field:
                     1 status(u8)            2 day_type(u8)
                     3 forming_start(u64)     4 forming_end(u64)
                     5 lookback_end(u64)      6 offering_end(u64)
                     7 scheduled_process_time(u64)
                     8 metadosis_limit_amount(U256)
                     9 previous_vwap(U256)   10 current_vwap(U256)
      slot 11:     active_wwd_count (Value<u16>)
      slots 12-13: active_wwd (Set<WorldwideDayKey>) - OZ enumerable set:
                     12 = length + value array at keccak256(be32(12))+i
                     13 = positions base; position(wwd) = index + 1 (0 = absent)
      slot 14+:    closed_wwd (Deque<WorldwideDayKey>)

    The active_wwd Set is what `get_active_wwd_by_status` (and therefore the tribute
    OFFERING lookup) reads. It MUST be populated in the enumerable-set layout above:
    seeding only the day record (slots 1-10) leaves the day invisible to the active
    scan and every offer reverts "no worldwide day is OFFERING".
    """
    wwds = config.get("worldwide_days", [])

    # active_wwd is a Set at base slot 12 (schema order 3, right after the
    # active_wwd_count Value at slot 11). Its positions mapping lives at base + 1.
    ACTIVE_WWD_BASE = 12

    for idx, entry in enumerate(wwds):
        wwd = entry["wwd"]
        wwd_key = u32_bytes(wwd)

        storage.set_mapping(1, wwd_key, entry.get("status", 0))
        storage.set_mapping(2, wwd_key, entry.get("day_type", 0))
        storage.set_mapping(3, wwd_key, entry.get("forming_start", 0))
        storage.set_mapping(4, wwd_key, entry.get("forming_end", 0))
        storage.set_mapping(5, wwd_key, entry.get("lookback_end", 0))
        storage.set_mapping(6, wwd_key, entry.get("offering_end", 0))
        storage.set_mapping(7, wwd_key, entry.get("scheduled_process_time", 0))

        # slot 8 = metadosis_limit_amount (per-day mint cap), 9 = previous_vwap,
        # 10 = current_vwap - schema field order.
        day_limit = parse_int(entry.get("day_limit", "0"))
        if day_limit > 0:
            storage.set_mapping(8, wwd_key, day_limit)
        storage.set_mapping(9, wwd_key, parse_int(entry.get("previous_vwap", "0")))
        storage.set_mapping(10, wwd_key, parse_int(entry.get("current_vwap", "0")))

        # Insert into the active_wwd Set: value-array entry + 1-indexed position.
        storage.set_slot(data_slot(ACTIVE_WWD_BASE) + idx, wwd)
        storage.set_mapping(ACTIVE_WWD_BASE + 1, u32_bytes(wwd), idx + 1)

    # Set length (slot 12) and the separate active_wwd_count Value (slot 11).
    storage.set_slot(ACTIVE_WWD_BASE, len(wwds))
    storage.set_slot(11, len(wwds))

    # Bootstrap end time
    bootstrap_end = config.get("bootstrap_end_time", 0)
    if bootstrap_end:
        storage.set_slot(0, bootstrap_end)


# VaultRouter default liquidity registry seeded at genesis. The discriminant
# values MUST match the IVaultRouter.StablesSource / StablesTarget enum ordering
# (see contracts/precompiles/src/IVaultRouter.sol).
#   StablesSource: Unknown=0 IntexCostAmount=1 CredisCostAmount=2
#                  GemCostAmount=3 PayNoteDeposit=4
#   StablesTarget: Unknown=0 Credis=1
#
# NodFactory, IntexFactory and GemFactory are deliberately absent: their costs
# are discharged by spending a PayNote, and the underlying assets reached the
# vault through PAYNOTE_ADDRESS when the note was deposited.
VAULT_ROUTER_LIQUIDITY_SOURCES = [
    (CREDIS_FACTORY_ADDRESS, 2),  # CredisCostAmount
    (PAYNOTE_ADDRESS, 4),         # PayNoteDeposit
]
VAULT_ROUTER_LIQUIDITY_TARGETS = [
    (CREDIS_FACTORY_ADDRESS, 1),  # Credis
]


def _seed_address_set_with_types(
    storage: StorageBuilder,
    *,
    set_base: int,
    type_map_slot: int,
    entries: list[tuple[str, int]],
):
    """
    Seed an OZ-style enumerable `Set<Address>` plus its parallel
    `mapping(Address => u8)` type map, matching the Rust `StorageSet` layout:
      set_base       = element count (length)
      set_base       -> value array at keccak256(be32(set_base)) + index
      set_base + 1   = positions mapping (1-indexed; 0 = absent)
      type_map_slot  = mapping(Address => u8) discriminant
    """
    for idx, (addr, type_value) in enumerate(entries):
        addr_bytes = address_bytes(addr)
        # Set: value-array entry (address right-aligned in a 32-byte word) +
        # 1-indexed position.
        storage.set_slot(data_slot(set_base) + idx, address_as_u256(addr))
        storage.set_mapping(set_base + 1, addr_bytes, idx + 1)
        # Parallel discriminant map.
        storage.set_mapping(type_map_slot, addr_bytes, type_value)
    storage.set_slot(set_base, len(entries))


def seed_vault_router(storage: StorageBuilder, owner_address: str):
    """
    VaultRouter storage layout (see crates/core/vaultrouter/src/schema.rs):
      slot 0:      owner (admin)
      slots 1-2:   assets (Set) - written at runtime by addVault
      slot 3:      asset_vaults (Map) - written at runtime by addVault
      slots 4-5:   liquidity_sources (Set<Address>)
      slot 6:      liquidity_source_types (Map<Address, u8>)
      slots 7-8:   liquidity_targets (Set<Address>)
      slot 9:      liquidity_target_types (Map<Address, u8>)

    Genesis sets the owner and pre-registers the default liquidity source/target
    registry for the factory precompiles, so the Solidity deposit / withdraw
    ABI path is gated and configured out of the box. The
    reserve vault itself is still registered post-deploy via `addVault`; the
    in-process api callers bypass this registry and declare their discriminant
    directly. Owner mirrors the ValidatorSet owner pattern (slot 0).
    """
    storage.set_slot(0, address_as_u256(owner_address))

    _seed_address_set_with_types(
        storage,
        set_base=4,
        type_map_slot=6,
        entries=VAULT_ROUTER_LIQUIDITY_SOURCES,
    )
    _seed_address_set_with_types(
        storage,
        set_base=7,
        type_map_slot=9,
        entries=VAULT_ROUTER_LIQUIDITY_TARGETS,
    )


def seed_validator_set(
    storage: StorageBuilder,
    validators: list[dict],
    config: dict,
    *,
    epoch_length_blocks: int,
    epoch_start_timestamp: int,
    min_stake: int,
    validator_stake: int,
):
    """
    ValidatorSet storage layout:
      slots 0-4: config
      slots 5-18: per-validator mappings and reverse indexes
      slot 20: validator_count
      slots 21-26: epoch / consensus-set tracking
      slot 27: re-registration cooldown
      slots 28-29: versioned Commonware P2P address registry
      slots 59-60: Radicle NodeId forward and reverse indexes
    """
    radicle_node_ids = [
        radicle_node_id_bytes(validator.get("radicle_node_id"), validator_index=index)
        for index, validator in enumerate(validators)
    ]
    if len(set(radicle_node_ids)) != len(radicle_node_ids):
        raise ValueError("duplicate Radicle NodeId in founder validators")

    storage.set_slot(0, address_as_u256(config.get("owner", "0x0000000000000000000000000000000000000000")))
    storage.set_slot(1, parse_int(config.get("max_validators", 128)))
    if "epoch_duration" in config:
        raise ValueError("validator_set.epoch_duration is deprecated; use config.epochLengthBlocks")
    if "epoch_length_blocks" in config:
        raise ValueError("validator_set.epoch_length_blocks is deprecated; use config.epochLengthBlocks")
    storage.set_slot(2, epoch_length_blocks)
    storage.set_slot(3, min_stake)
    storage.set_slot(4, 1)
    storage.set_slot(20, len(validators))
    storage.set_slot(21, parse_int(config.get("epoch_number", 0)))
    storage.set_slot(22, parse_int(config.get("epoch_start_timestamp", epoch_start_timestamp)))
    storage.set_slot(23, parse_int(config.get("epoch_start_block", 0)))
    storage.set_slot(25, 0)
    storage.set_slot(26, parse_int(config.get("active_consensus_set_hash", 0)))
    storage.set_slot(27, parse_int(config.get(
        "reregistration_cooldown_blocks",
        DEFAULT_REREGISTRATION_COOLDOWN_BLOCKS,
    )))

    for index, (validator, radicle_node_id) in enumerate(
        zip(validators, radicle_node_ids, strict=True), start=1
    ):
        addr = validator["address"]
        pk = pubkey_bytes(validator["public_key"])
        pk_hi = pk[32:] + (b"\x00" * 16)
        pk_hash = keccak256(pk)

        storage.set_mapping_b256(5, address_bytes(addr), pk[:32])
        storage.set_mapping_b256(6, address_bytes(addr), pk_hi)
        storage.set_mapping(7, address_bytes(addr), validator_stake)
        storage.set_mapping(8, address_bytes(addr), 2)  # ACTIVE
        storage.set_mapping(13, address_bytes(addr), 0)
        storage.set_mapping(16, address_bytes(addr), index)
        storage.set_mapping(17, u64_bytes(index), address_as_u256(addr))
        storage.set_mapping(18, pk_hash, address_as_u256(addr))
        storage.set_mapping(24, address_bytes(addr), 1)
        storage.set_mapping_b256(59, address_bytes(addr), radicle_node_id)
        storage.set_mapping(60, radicle_node_id, address_as_u256(addr))
        p2p_seed = encode_p2p_address_payload(validator.get("p2p_address"))
        if p2p_seed is not None:
            version, payload = p2p_seed
            storage.set_mapping(28, address_bytes(addr), version)
            write_mapping_bytes(storage, 29, address_bytes(addr), payload)


def seed_staking(
    storage: StorageBuilder,
    validators: list[dict],
    config: dict,
    *,
    min_stake: int,
    validator_stake: int,
):
    """
    Staking storage layout:
      slots 0-2: config
      slot 3: mapping(validator => stake_amount)
      slot 4: total_staked
    """
    if validator_stake < min_stake:
        raise ValueError("genesis_validator_stake must be >= min_stake")

    storage.set_slot(0, min_stake)
    unbonding_period = parse_int(config.get("unbonding_period", DEFAULT_UNBONDING_PERIOD))
    storage.set_slot(1, unbonding_period)
    storage.set_slot(2, parse_int(config.get("max_stake_percent", 33)))
    storage.set_slot(
        11,
        parse_int(config.get("slashed_withdrawal_delay", unbonding_period * 2)),
    )

    total_staked = 0
    for validator in validators:
        storage.set_mapping(3, address_bytes(validator["address"]), validator_stake)
        total_staked += validator_stake

    storage.set_slot(4, total_staked)
    return total_staked


def seed_rewards(storage: StorageBuilder, genesis_timestamp: int):
    """
    Rewards storage layout:
      slot 0: genesis_utc_day (uint32 yyyymmdd of genesis timestamp).

    NOTE: `genesis_utc_day` moved from slot 1 to slot 0 when the leading
    `pending_rewards` field was removed (PR #12 / 941c4eb). The runtime also
    lazily anchors this value at block 0 via `rewards::ensure_genesis_anchor`
    (= timestamp_to_date_key(block0.timestamp)); seeding it here keeps genesis
    state explicit and matches that block-0 value.
    """
    storage.set_slot(0, timestamp_to_utc_date_key(genesis_timestamp))


def seed_tee_policy(genesis: dict, alloc: dict, seed: dict):
    """Seed the genesis TEE attestation policy (WS-B), if `tee_policy` is present
    in the seed config.

    Writes two places:
      1. `TeeRegistry` (0xEE0A) slot 2 = `policy_hash` - the consensus-critical,
         deterministic gate the Phase 3b `TeeBootstrap` handler reads from EVM
         state. The account also gets marker bytecode so the slot survives
         EIP-161 cleanup until block 1.
      2. `config.teePolicy` - read by the node at startup to build the host
         structural key/measurement consistency checks at development connect.

    No-op when `tee_policy` is absent: genesis is unchanged and the handler skips
    measurement enforcement (slot 2 == ZERO).
    """
    policy = seed.get("tee_policy")
    if not policy:
        return
    allowed_mrsigner = policy.get("allowed_mrsigner", [])
    allowed_mrenclave = policy.get("allowed_mrenclave", [])
    min_isv_svn = parse_int(policy.get("min_isv_svn", 0))
    policy_hash = compute_tee_policy_hash(allowed_mrsigner, allowed_mrenclave, min_isv_svn)

    storage = StorageBuilder()
    storage.set_raw_slot_hex(2, "0x" + policy_hash.hex())
    entry = alloc.setdefault(TEE_REGISTRY_ADDRESS, {})
    entry["code"] = MARKER_CODE
    entry.setdefault("balance", "0x0")
    entry.setdefault("storage", {}).update(storage.entries)

    genesis.setdefault("config", {})["teePolicy"] = {
        "allowed_mrsigner": allowed_mrsigner,
        "allowed_mrenclave": allowed_mrenclave,
        "min_isv_svn": min_isv_svn,
    }
    print(
        f"  teePolicy: {len(allowed_mrsigner)} mrsigner, {len(allowed_mrenclave)} mrenclave, "
        f"min_isv_svn={min_isv_svn}, policy_hash=0x{policy_hash.hex()}"
    )


def seed_zerofee(storage: StorageBuilder):
    """
    ZeroFee paymaster storage layout:
      slot 0: schema version (uint32) - pinned at 1 for the initial
              `Map<Address, u64> counter` layout. The macro's
              `counter` Map keys are `keccak256(addr || base_slot)` so
              they never collide with slot 0 even though `counter`
              nominally uses slot 0 as the base_slot for keccak.

    The slot-0 schema marker is required by the README rule
    "All precompiles ... storage versioned (slot 0 = version)". A
    future layout migration would bump this value and key off it from
    the runtime.
    """
    storage.set_slot(0, 1)


def seed_accounting_progress(storage: StorageBuilder):
    """
    Accounting progress storage layout (V2):
      slot 0: last_accounted_block_number (u64) - pre-V2 genesis is `0`
              meaning Phase 1 has not yet processed any block. The first
              certified-parent accounting begin-zone system transaction
              advances this slot for block N >= 2.

    Genesis V2 requires this slot to be explicitly written so the resulting
    storage map contains the canonical zero word, matching the Rust schema
    `outbe_accounting::schema::Accounting::last_accounted_block_number`.
    """
    storage.set_slot(0, 0)


def seed_compressed_entities(storage: StorageBuilder):
    """Seed the EVM schema version and ADR-010's authoritative empty sealed root."""
    storage.set_slot(0, COMPRESSED_ENTITIES_SCHEMA_VERSION)
    storage.set_slot(1, COMPRESSED_ENTITIES_EMPTY_SEALED_ROOT)


def seed_governance(storage: StorageBuilder, validators: list, canon_dir: str | None):
    """
    Governance storage layout. All seeded fields are one slot each and precede
    the two record maps in the schema, so their slot indices are stable no matter
    how the Oip/Gip record types grow (a `Map<K, Record>` reserves
    `Record::SLOTS` contiguous base slots). The Rust-side
    `storage_layout_matches_seeder` test pins these indices.

      slot 0:  meta_canon text        (StorageBytes; long data at keccak256(0))
      slot 1:  meta_canon_version     (u64)
      slot 2:  meta_canon_hash        (B256 = keccak256(text))
      slot 3:  meta_canon_revisions   Map<u64, B256>
      slot 4:  canon text             (StorageBytes; long data at keccak256(4))
      slot 5:  canon_version          (u64)
      slot 6:  canon_hash             (B256)
      slot 7:  canon_revisions        Map<u64, B256>
      slot 8:  next_oip_id            (u64, default 0 - not seeded)
      slot 9:  next_gip_id            (u64, default 0 - not seeded)
      slot 10: authorities            Map<Address, bool>  (PoC write-gate)
      slot 11: oips                   Map<U256, Oip>   (not seeded; empty)
      slot 17: gips                   Map<U256, Gip>   (not seeded; empty)

    Authorities are seeded with every genesis validator address - with an empty
    authorities set nobody could ever write the canon, so this is mandatory. The
    canon / meta-canon texts are seeded from `canon_dir/{metacanon.md,canon.md}`
    at version 1 when present; when absent the texts stay empty and any authority
    performs the first `updateCanon` post-genesis (version 0 -> 1).

    Returns `(n_authorities, meta_seeded, canon_seeded)`.
    """
    n_auth = 0
    for v in validators:
        storage.set_mapping(10, address_bytes(v["address"]), 1)  # bool true
        n_auth += 1

    def _seed_text(text_slot: int, version_slot: int, hash_slot: int,
                   revisions_base: int, data: bytes):
        write_storage_bytes(storage, text_slot, data)
        storage.set_slot(version_slot, 1)
        h = keccak256(data)
        storage.set_raw_slot_hex(hash_slot, "0x" + h.hex())
        storage.set_mapping_b256(revisions_base, u64_bytes(1), h)

    meta_seeded = False
    canon_seeded = False
    if canon_dir and os.path.isdir(canon_dir):
        meta_path = os.path.join(canon_dir, "metacanon.md")
        canon_path = os.path.join(canon_dir, "canon.md")
        if os.path.isfile(meta_path):
            with open(meta_path, "rb") as f:
                _seed_text(0, 1, 2, 3, f.read())
            meta_seeded = True
        if os.path.isfile(canon_path):
            with open(canon_path, "rb") as f:
                _seed_text(4, 5, 6, 7, f.read())
            canon_seeded = True

    return n_auth, meta_seeded, canon_seeded


def seed_oracle(storage: StorageBuilder, config: dict):
    """
    Oracle storage layout:
      slots 0-7: config
      slot 8: pair_count
      slot 9: retired hole (was mapping(pair_id => pair_hash))
      slot 10: mapping(pair => ordinal)
      slot 11: mapping(pair => is_vote_target)
      slots 12-14: exchange_rate / block / timestamp, keyed by pair_index
        (the 1-based ordinal from slot 10), not by the pair itself
      slot 15: feeder delegations
      slots 32-33: protected validators
      slot 43: mapping(pair_index => AddressPair), a two-word value and the only
        way to enumerate the registry (40-42, 44, 45 and 46 are retired
        settlement holes; the settlement pair is derived as
        address_pair("COEN", "<iso>"))
      slot 55: reference_currencies (StorageVec<u16>)
      slot 60: retired policy-rate mapping
      slots 74-75: policy_rate_currencies / policy_rate
    """
    pair_keys: dict[tuple[bytes, bytes], bytes] = {}
    pairs = config.get("pairs", [])
    validated_pairs = []

    for idx, pair in enumerate(pairs, start=1):
        base = pair["base"]
        quote = pair["quote"]
        base_address = asset_address(base)
        quote_address = asset_address(quote)
        if base_address == quote_address:
            raise ValueError(
                f"oracle pair must contain two different assets: same asset {base}/{quote}"
            )
        h = address_pair(base, quote)
        key = (asset_address(base), asset_address(quote))
        if key in pair_keys:
            raise ValueError(f"duplicate oracle pair: {base}/{quote}")
        # The key is order-independent, so the inverse is the same pair.
        if h in pair_keys.values():
            raise ValueError(f"oracle pair already registered inverted: {base}/{quote}")
        # This seeder writes slot 43 directly, bypassing `register_pair`, so it
        # owes the same directional invariant: generic markets preserve their
        # configured orientation, while COEN/ISO is always COEN base, ISO quote.
        if is_iso_asset_address(base_address) and quote_address == bytes(20):
            raise ValueError(
                f"oracle COEN/ISO pair must use COEN base and ISO quote: {base}/{quote}"
            )
        pair_keys[key] = h
        validated_pairs.append((idx, pair, base, quote, h))

    # Validate the complete registry before writing any Oracle slot. This keeps
    # direct seeding and create_genesis.py fail-closed on invalid input.
    cfg = config.get("config", {})
    storage.set_slot(0, parse_int(cfg.get("vote_period", 2)))
    storage.set_slot(1, parse_int(cfg.get("reward_band", "20000000000000000")))
    penalties_enabled = cfg.get("penalties_enabled", True)
    if penalties_enabled:
        min_valid_per_window = cfg.get("min_valid_per_window", "50000000000000000")
        slash_fraction = cfg.get("slash_fraction", "0")
    else:
        min_valid_per_window = "0"
        slash_fraction = "0"
    storage.set_slot(2, parse_int(cfg.get("slash_window", 96)))
    storage.set_slot(3, parse_int(min_valid_per_window))
    storage.set_slot(4, parse_int(slash_fraction))
    storage.set_slot(5, parse_int(cfg.get("lookback_duration", 86400)))
    storage.set_slot(6, 1 if cfg.get("enabled", True) else 0)
    storage.set_slot(7, 1 if cfg.get("initialized", True) else 0)
    storage.set_slot(8, len(pairs))

    pair_ids: dict[tuple[bytes, bytes], int] = {}
    for idx, pair, base, quote, h in validated_pairs:
        key = (asset_address(base), asset_address(quote))
        pair_ids[key] = idx

        storage.set_mapping(10, h, idx)
        storage.set_mapping(11, h, 1 if pair.get("vote_target", True) else 0)
        # pair_by_index (macro slot 43), configured orientation.
        storage.set_mapping_pair(43, u32_bytes(idx), base, quote)

        rate = parse_int(pair.get("initial_rate", "0"))
        if rate:
            storage.set_mapping(12, u32_bytes(idx), rate)
            storage.set_mapping(13, u32_bytes(idx), parse_int(pair.get("initial_block", 0)))
            storage.set_mapping(
                14, u32_bytes(idx), parse_int(pair.get("initial_timestamp", 0))
            )

    for rate_entry in config.get("initial_rates", []):
        key = (rate_entry["base"], rate_entry["quote"])
        idx = pair_ids.get((asset_address(key[0]), asset_address(key[1])))
        if idx is None:
            raise ValueError(f"initial rate pair is not registered: {key[0]}/{key[1]}")
        storage.set_mapping(12, u32_bytes(idx), parse_int(rate_entry["rate"]))
        storage.set_mapping(13, u32_bytes(idx), parse_int(rate_entry.get("block", 0)))
        storage.set_mapping(14, u32_bytes(idx), parse_int(rate_entry.get("timestamp", 0)))

    for delegation in config.get("feeder_delegations", []):
        validator = delegation["validator"]
        feeder = delegation["feeder"]
        storage.set_mapping(15, address_bytes(validator), address_as_u256(feeder))

    protected = config.get("protected_validators", [])
    if protected:
        # config_allow_protected (macro slot 33) / protected_validator (slot 32).
        storage.set_slot(33, 1)
        for validator in protected:
            storage.set_mapping(32, address_bytes(validator), 1)

    if config.get("settlement_currencies"):
        raise ValueError(
            "oracle.settlement_currencies was removed: register the COEN/<iso> "
            "pair instead, and list the ISO under oracle.reference_currencies"
        )

    # S-curve genesis seeds (macro slots 34-38). `resolve_tribute_price` reads
    # `max(per-day VWAP, S-curve)`; pre-seeded OFFERING days have no runtime-
    # computed per-day VWAP, so without an S-curve entry the price is 0 and
    # `offerTribute` reverts with `NominalPriceUnavailable`. Each seed gives a
    # pair a peak at a worldwide day so days within the S-curve period resolve.
    scurve_seeds = config.get("scurve_seeds", [])
    if scurve_seeds:
        storage.set_slot(34, len(scurve_seeds))  # scurve_count
        storage.set_slot(38, 0)  # scurve_oldest_idx
        for idx, sc in enumerate(scurve_seeds):
            pair = (sc["pair_base"], sc["pair_quote"])
            if pair_ids.get((asset_address(pair[0]), asset_address(pair[1]))) is None:
                raise ValueError(
                    f"scurve seed pair is not registered: {pair[0]}/{pair[1]}"
                )
            peak_day_ts = wwd_to_day_timestamp(parse_int(sc["peak_day"]))
            # scurve_pair (35): a two-word pair value, base then base+1.
            storage.set_mapping_pair(35, u32_bytes(idx), pair[0], pair[1])
            storage.set_mapping(36, u32_bytes(idx), peak_day_ts)  # scurve_peak_day
            storage.set_mapping(
                37, u32_bytes(idx), parse_int(sc["peak_price"])
            )  # scurve_peak_price

    # Reference currencies and annual policy rates are independent registries.
    # Both lists are canonical ascending ISO order. Slot 60 is retired.
    DEFAULT_USD_CURRENCY_RATE = 36_300  # 3.63% at scale 1e6
    reference_currencies = config.get(
        "reference_currencies",
        [156, 344, 392, 826, 840, 978],
    )
    reference_currencies = [parse_int(iso_code) for iso_code in reference_currencies]
    if len(reference_currencies) > 6:
        raise ValueError("oracle reference currency count exceeds 6")
    if any(iso_code == 0 for iso_code in reference_currencies):
        raise ValueError("oracle reference iso_code must be non-zero")
    if reference_currencies != sorted(set(reference_currencies)):
        raise ValueError("oracle reference currencies must be sorted and unique")
    if 840 not in reference_currencies:
        raise ValueError("oracle reference currencies must include USD 840")
    storage.set_slot(55, len(reference_currencies))
    for i, iso_code in enumerate(reference_currencies):
        storage.set_raw_slot(data_slot(55) + i, iso_code)

    policy_rates = config.get(
        "policy_rates",
        [{"iso_code": 840, "annual_rate_1e6": DEFAULT_USD_CURRENCY_RATE}],
    )
    parsed_policy_rates = [
        (parse_int(entry["iso_code"]), parse_int(entry["annual_rate_1e6"]))
        for entry in policy_rates
    ]
    if any(iso_code == 0 for iso_code, _ in parsed_policy_rates):
        raise ValueError("oracle policy iso_code must be non-zero")
    if any(rate == 0 for _, rate in parsed_policy_rates):
        raise ValueError("oracle policy rate must be non-zero")
    policy_isos = [iso_code for iso_code, _ in parsed_policy_rates]
    if policy_isos != sorted(set(policy_isos)):
        raise ValueError("oracle policy rates must be sorted and unique")
    storage.set_slot(74, len(parsed_policy_rates))
    for i, (iso_code, rate) in enumerate(parsed_policy_rates):
        storage.set_raw_slot(data_slot(74) + i, iso_code)
        storage.set_mapping(75, u32_bytes(iso_code), rate)


# --- External contracts ---

def seed_profile_selector(
    storage: StorageBuilder, config: dict, section: str, slot: int
):
    """Write the profile selector from `profile: "auto"|"dev"|"prod"`; auto is
    the default, seeds nothing, and lets the chain id decide."""
    profile = str(config.get("profile", "auto")).lower()
    if profile not in PROFILE_SELECTORS:
        raise ValueError(
            f"{section}: unknown profile {profile!r}; "
            f"expected one of {sorted(PROFILE_SELECTORS)}"
        )
    selector = PROFILE_SELECTORS[profile]
    if selector == 0:
        return
    storage.set_slot(slot, selector)


def seed_radicle_registry(storage: StorageBuilder, config: dict):
    """Seed immutable RadicleRegistry V1 capacity at slot 5."""
    if not isinstance(config, dict):
        raise ValueError("radicle_registry must be a JSON object")
    configured = parse_int(config.get("max_repositories", 0))
    maximum = 0xFFFFFFFF if configured == -1 else configured
    if maximum <= 0 or maximum >= 0xFFFFFFFF and configured != -1:
        raise ValueError(
            "radicle_registry.max_repositories must be -1 or in 1..=4294967294"
        )
    storage.set_slot(5, maximum)


def seed_external_contracts(alloc, contracts_list, contracts_dir):
    """
    Embed externally-fetched contracts (bytecode + storage) into the genesis
    alloc. Each entry has the form:
        {"address": "0x...", "code": "<file>.code.hex",
         "state": "<file>.state.json"?, "nonce": "0x.."?, "balance": "0x.."?}
    Files are read from contracts_dir. Address keys collide-checked against the
    precompile registry to prevent silently overwriting protocol state.
    """
    for entry in contracts_list:
        addr_norm = address_bytes(entry["address"]).hex()
        if addr_norm in PROTECTED_PROTOCOL_ADDRESSES:
            raise ValueError(
                f"contract {entry['address']} collides with a protocol-reserved address; "
                f"refusing to overwrite protocol state"
            )

        code_path = os.path.join(contracts_dir, entry["code"])
        with open(code_path) as f:
            code_hex = f.read().strip()
        if not code_hex.startswith("0x") or len(code_hex) <= 2:
            raise ValueError(f"{code_path}: empty or non-0x-prefixed bytecode")

        storage = {}
        if entry.get("state"):
            state_path = os.path.join(contracts_dir, entry["state"])
            with open(state_path) as f:
                raw = json.load(f)
            for slot, value in raw.items():
                storage[hex32(int(slot, 16))] = hex32(int(value, 16))

        target = alloc.setdefault(addr_norm, {})
        existing_code = target.get("code")
        if (
            existing_code is not None
            and existing_code != MARKER_CODE
            and existing_code != code_hex
        ):
            raise ValueError(
                f"alloc entry {addr_norm} already has different non-marker code; "
                f"refusing to overwrite"
            )
        target["code"] = code_hex
        target["nonce"] = entry.get("nonce", "0x1")
        target["balance"] = entry.get("balance", "0x0")
        if storage:
            target.setdefault("storage", {}).update(storage)

        print(
            f"  Contract {entry['address']}: code={(len(code_hex) - 2) // 2} bytes, "
            f"{len(storage)} storage entries"
        )


# --- Main ---

def seed_protocol_constants(genesis: dict, seed: dict) -> None:
    """Copy optional protocol timing overrides into genesis config.

    Rust resolves defaults, validates the complete record, and installs it in
    immutable process memory during node startup.
    """
    profile = seed.get("protocol_constants")
    if profile is None:
        return
    if not isinstance(profile, dict):
        raise ValueError("seed protocol_constants must be a JSON object")
    config = genesis.setdefault("config", {})
    if not isinstance(config, dict):
        raise ValueError("genesis config must be a JSON object")
    existing = config.get("outbeProtocol")
    if existing is not None and existing != profile:
        raise ValueError(
            "seed protocol_constants conflicts with genesis config.outbeProtocol"
        )
    config["outbeProtocol"] = json.loads(json.dumps(profile))


def clear_seeded_metadosis_days(seed: dict) -> None:
    """Let block-1 create the first WorldwideDay from protocol timings."""
    metadosis = seed.get("metadosis")
    if metadosis is None:
        return
    if not isinstance(metadosis, dict):
        raise ValueError("seed metadosis must be a JSON object")
    metadosis["worldwide_days"] = []

def override_worldwide_day(seed: dict, day: int) -> None:
    """Retarget every worldwide-day reference in a seed to `day` (YYYYMMDD), in
    place: metadosis worldwide_days[].wwd, oracle scurve_seeds[].peak_day, and
    nods[].worldwide_day.

    A localnet must boot on its genesis (current) date: the metadosis runtime
    derives the active day each block from
    `WorldwideDay::from_timestamp(block.timestamp)`, so a seeded day that differs
    from the genesis wall-clock day leaves two active worldwide days fighting
    (the seeded one + the runtime-created "today") and consensus wedges. Other
    day fields (status, offering window, limits) are left as authored - only the
    calendar key is retargeted, and the OFFERING window the seed declares (forming
    in the past, offering_end far future) keeps the day OFFERING at the new date.
    """
    for w in seed.get("metadosis", {}).get("worldwide_days", []):
        w["wwd"] = day
    for s in seed.get("oracle", {}).get("scurve_seeds", []):
        s["peak_day"] = day


def apply_seed(
    genesis: dict,
    seed: dict,
    validators: list | None = None,
    *,
    contracts_dir: str | None = None,
    canon_dir: str | None = None,
    worldwide_day: int | None = None,
    fresh_metadosis: bool = False,
) -> dict:
    """Compute every derived value a genesis needs and write it into `genesis`.

    This is the calculation half of genesis creation: storage slot layout for
    each precompile, keccak-derived mapping keys, the active WorldwideDay
    resolved against the genesis timestamp, marker bytecode, and balances that
    must match seeded counters. `create_genesis.py` owns the declarative half
    (what the network *is*, from a yaml) and calls this to render it.

    `genesis` is mutated in place and returned.
    """

    seed_protocol_constants(genesis, seed)

    # Retarget the seeded worldwide-day to the genesis (current) date when asked,
    # before any seeder consumes `seed`, so metadosis, the oracle S-curve, the
    # tribute day_totals init, and the NODs all agree on the same active day.
    if worldwide_day is not None:
        override_worldwide_day(seed, worldwide_day)
    if fresh_metadosis:
        clear_seeded_metadosis_days(seed)

    validators = validators or []
    if not isinstance(validators, list):
        raise ValueError("validators must be a list")

    alloc = genesis.setdefault("alloc", {})
    validate_stablecoin_namespace_alloc(alloc, require_reserved_markers=False)

    # Ensure all precompile addresses have marker bytecode
    for addr in ALL_PRECOMPILE_ADDRESSES:
        entry = alloc.setdefault(addr, {})
        entry["code"] = MARKER_CODE
        entry.setdefault("balance", "0x0")

    header_timestamp = parse_header_timestamp(genesis)
    cycle_storage = StorageBuilder()
    seed_cycle(cycle_storage, header_timestamp)
    alloc[CYCLE_ADDRESS].setdefault("storage", {}).update(cycle_storage.entries)
    print(
        "  Cycle: active_utc_day="
        f"{timestamp_to_utc_date_key(header_timestamp)}, slot 2 seeded"
    )

    # Seed native EVM token balances into alloc.
    if "balance" in seed:
        seed_coen(alloc, seed["balance"])
        print(f"  balance: {len(seed['balance'])} entries")

    # Seed ValidatorSet, Staking, and Rewards from validators.json. This makes
    # genesis.json the canonical protocol state; executor no longer backfills it.
    if validators:
        staking_cfg = seed.get("staking", {})
        min_stake = parse_int(staking_cfg.get("min_stake", MIN_STAKE))
        validator_stake = parse_int(staking_cfg.get("genesis_validator_stake", min_stake))
        if validator_stake < min_stake:
            raise ValueError("genesis_validator_stake must be >= min_stake")
        config = genesis.get("config", {})
        if "epochDuration" in config:
            raise ValueError("genesis config uses deprecated epochDuration; use epochLengthBlocks")
        if "dkgRotationIntervalBlocks" in config:
            raise ValueError(
                "genesis config uses deprecated dkgRotationIntervalBlocks; use epochLengthBlocks"
            )
        epoch_length_blocks = parse_int(
            config.get("epochLengthBlocks", DEFAULT_EPOCH_LENGTH_BLOCKS)
        )
        if epoch_length_blocks <= 0:
            raise ValueError("genesis config epochLengthBlocks must be > 0")
        # Pass-through sanity check for the consensus-sync timing trio. The seeder
        # does not author these (they fall back to outbe_consensus::timing
        # defaults); it only rejects an obviously malformed non-positive value so
        # a bad genesis fails early. The full ordering invariant
        # (0 < min < leader <= cert) is enforced by validate_timing at startup.
        for _timing_key in ("minBlockTimeMs", "leaderTimeoutMs", "certificationTimeoutMs"):
            if _timing_key in config and parse_int(config[_timing_key]) <= 0:
                raise ValueError(f"genesis config {_timing_key} must be > 0")
        epoch_start_timestamp = parse_genesis_timestamp(genesis)

        validator_storage = StorageBuilder()
        seed_validator_set(
            validator_storage,
            validators,
            seed.get("validator_set", {}),
            epoch_length_blocks=epoch_length_blocks,
            epoch_start_timestamp=epoch_start_timestamp,
            min_stake=min_stake,
            validator_stake=validator_stake,
        )
        alloc[VALIDATOR_SET_ADDRESS].setdefault("storage", {}).update(validator_storage.entries)

        # VaultRouter owner: validator0 by default (overridable via
        # seed["vault_router"]["owner"]). The owner can later register vaults
        # and liquidity sources/targets on the precompile.
        vault_owner = seed.get("vault_router", {}).get("owner", validators[0]["address"])
        vault_router_storage = StorageBuilder()
        seed_vault_router(vault_router_storage, vault_owner)
        alloc[VAULT_ROUTER_ADDRESS].setdefault("storage", {}).update(
            vault_router_storage.entries
        )
        print(f"  VaultRouter: owner={vault_owner}, slot 0 seeded")

        staking_storage = StorageBuilder()
        total_staked = seed_staking(
            staking_storage,
            validators,
            staking_cfg,
            min_stake=min_stake,
            validator_stake=validator_stake,
        )
        staking_entry = alloc[STAKING_ADDRESS]
        staking_entry.setdefault("storage", {}).update(staking_storage.entries)
        staking_entry["balance"] = alloc_balance_hex(total_staked)

        rewards_storage = StorageBuilder()
        seed_rewards(rewards_storage, epoch_start_timestamp)
        alloc[REWARDS_ADDRESS].setdefault("storage", {}).update(rewards_storage.entries)

        print(
            f"  ValidatorSet: {len(validators)} active validators, "
            f"{len(validator_storage.entries)} storage entries"
        )
        print(
            f"  Staking: total_staked={total_staked}, "
            f"{len(staking_storage.entries)} storage entries"
        )
        print(f"  Rewards: {len(rewards_storage.entries)} storage entries")

    # Governance: seed the authorities write-gate (validator addresses) and the
    # canon / meta-canon texts. Authorities are mandatory - an empty set means no
    # address can ever write the canon. Canon texts default to <script-dir>/canon.
    canon_dir = canon_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "canon"
    )
    governance_storage = StorageBuilder()
    n_auth, meta_seeded, canon_seeded = seed_governance(
        governance_storage, validators, canon_dir
    )
    if governance_storage.entries:
        alloc[GOVERNANCE_ADDRESS].setdefault("storage", {}).update(
            governance_storage.entries
        )
    print(
        f"  Governance: {n_auth} authorities, "
        f"meta-canon={'seeded' if meta_seeded else 'empty'}, "
        f"canon={'seeded' if canon_seeded else 'empty'}, "
        f"{len(governance_storage.entries)} storage entries"
    )

    # V2 Phase 1 accounting progress (slot 0 = 0). Always seeded - independent
    # of validator count - because the executor needs the marker bytecode +
    # an explicit slot 0 = 0 word to record `last_accounted_block_number`
    # under EIP-161-safe storage.
    accounting_storage = StorageBuilder()
    seed_accounting_progress(accounting_storage)
    alloc[ACCOUNTING_PROGRESS_ADDRESS].setdefault("storage", {}).update(
        accounting_storage.entries
    )
    print(
        f"  AccountingProgress: slot 0 = 0, "
        f"{len(accounting_storage.entries)} storage entries"
    )

    compressed_entities_storage = StorageBuilder()
    seed_compressed_entities(compressed_entities_storage)
    alloc[COMPRESSED_ENTITIES_ADDRESS].setdefault("storage", {}).update(
        compressed_entities_storage.entries
    )
    print(
        "  CompressedEntities: slot 0 = 3, "
        "slot 1 = ADR-010 empty sealed Root Catalog root"
    )

    if "radicle_registry" in seed:
        radicle_registry_storage = StorageBuilder()
        seed_radicle_registry(radicle_registry_storage, seed["radicle_registry"])
        alloc[RADICLE_REGISTRY_ADDRESS].setdefault("storage", {}).update(
            radicle_registry_storage.entries
        )
        print(
            "  RadicleRegistry: maxRepositories="
            f"{seed['radicle_registry']['max_repositories']}"
        )

    # ZeroFee paymaster: slot 0 = schema version (1). Honors the README
    # rule "All precompiles storage versioned (slot 0 = version)" and
    # lets a future migration probe slot 0 to decide whether to apply
    # a layout transformation. The `counter` Map keys are keccak-derived
    # and never write to slot 0 directly, so the version marker has no
    # collision risk.
    zerofee_storage = StorageBuilder()
    seed_zerofee(zerofee_storage)
    alloc[ZEROFEE_ADDRESS].setdefault("storage", {}).update(zerofee_storage.entries)
    print(
        f"  ZeroFee: slot 0 = 1 (schema version), "
        f"{len(zerofee_storage.entries)} storage entries"
    )

    # TEE attestation policy (WS-B): seeds TeeRegistry slot 2 (policy_hash) +
    # config.teePolicy, but only when `tee_policy` is present in the seed config.
    seed_tee_policy(genesis, alloc, seed)

    # Gratis and Promis are TEE-encrypted at rest: per-account balances are
    # ciphertext keyed off enclave state keys, so they can NOT be plaintext-seeded
    # at genesis. (The old flat writes were dead - worse, they set total_supply to
    # a non-zero value with no backing encrypted balances.) A demo account instead
    # gets a Settled gem (see below) and mines Gem -> Promis -> Gratis through the
    # enclave. Fail loudly if a stale seed still carries these keys.
    for _encrypted_key in ("gratis_balances", "promis_balances"):
        if _encrypted_key in seed:
            raise ValueError(
                f"{_encrypted_key} is no longer supported: this token is TEE-encrypted "
                f"and cannot be plaintext-seeded at genesis. Seed a `gems` entry instead "
                f"and mine Gem -> Promis -> Gratis "
                f"(see examples/credis-flow/src/0-setup-gratis.ts)."
            )

    # Seed Gems (Settled) so a demo account can mine Gem -> Promis -> Gratis.
    if "gems" in seed:
        gem_storage = StorageBuilder()
        seed_gems(gem_storage, seed["gems"])
        entry = alloc[GEM_ADDRESS]
        entry.setdefault("storage", {}).update(gem_storage.entries)
        print(f"  Gem: {len(seed['gems'])} settled gems, "
              f"{len(gem_storage.entries)} storage entries")

    # Seed Tributes
    if "tributes" in seed:
        tribute_storage = StorageBuilder()
        seed_tributes(tribute_storage, seed["tributes"])
        # Initialize day_totals for OFFERING worldwide days (status 2) so
        # offerTribute is accepted (the directly-seeded OFFERING day never ran
        # the metadosis unseal_day that normally initializes it).
        offering_days = [
            entry_wd["wwd"]
            for entry_wd in seed.get("metadosis", {}).get("worldwide_days", [])
            if entry_wd.get("status", 0) == 2
        ]
        seed_tribute_day_totals(tribute_storage, offering_days)
        entry = alloc[TRIBUTE_ADDRESS]
        entry.setdefault("storage", {}).update(tribute_storage.entries)
        print(f"  Tribute: {len(seed['tributes'])} tributes, "
              f"{len(offering_days)} offering day_totals init, "
              f"{len(tribute_storage.entries)} storage entries")

    # Initialize the canonical materialization FIFO. NOD bodies are stored in
    # compressed-entity storage and are not seeded into EVM slots.
    nod_storage = StorageBuilder()
    seed_nod_materialization_fifo(nod_storage)
    entry = alloc[NOD_ADDRESS]
    entry.setdefault("storage", {}).update(nod_storage.entries)
    print(f"  Nod: {len(nod_storage.entries)} storage entries")

    # Seed Metadosis
    if "metadosis" in seed:
        meta_storage = StorageBuilder()
        seed_metadosis(meta_storage, seed["metadosis"])
        entry = alloc[METADOSIS_ADDRESS]
        entry.setdefault("storage", {}).update(meta_storage.entries)
        wwds = seed["metadosis"].get("worldwide_days", [])
        print(f"  Metadosis: {len(wwds)} worldwide days, "
              f"{len(meta_storage.entries)} storage entries")

    # Seed Oracle
    if "oracle" in seed:
        oracle_storage = StorageBuilder()
        seed_oracle(oracle_storage, seed["oracle"])
        entry = alloc[ORACLE_ADDRESS]
        entry.setdefault("storage", {}).update(oracle_storage.entries)
        pairs = seed["oracle"].get("pairs", [])
        print(f"  Oracle: {len(pairs)} pairs, "
              f"{len(oracle_storage.entries)} storage entries")

    # Seed the profile selectors (prod seeds nothing).
    for section, address, slot, label in (
        ("intex_factory", INTEX_FACTORY_ADDRESS, INTEX_PROFILE_SLOT, "IntexFactory"),
        ("gem_profile", GEM_ADDRESS, GEM_PROFILE_SLOT, "Gem"),
    ):
        if section not in seed:
            continue
        profile_storage = StorageBuilder()
        seed_profile_selector(profile_storage, seed[section], section, slot)
        if profile_storage.entries:
            entry = alloc.setdefault(address, {})
            entry.setdefault("storage", {}).update(profile_storage.entries)
            entry.setdefault("code", MARKER_CODE)
            print(f"  {label}: {len(profile_storage.entries)} storage entries")

    # Seed externally-fetched contracts (e.g. CREATE2 deployer)
    if "contracts" in seed:
        if contracts_dir is None:
            raise ValueError("contracts_dir is required to seed `contracts`")
        seed_external_contracts(alloc, seed["contracts"], contracts_dir)

    # reth v2.2 `GenesisAccount` requires an explicit `balance` on every alloc
    # entry, including code/storage-only marker accounts (the `0xef` markers and
    # system storage accounts) that the seeders above leave balance-less. Default
    # any such account to zero so the chain spec parses; accounts that already
    # carry a real balance keep it (setdefault is a no-op for them).
    for account in alloc.values():
        account.setdefault("balance", "0x0")

    validate_stablecoin_namespace_alloc(alloc, require_reserved_markers=True)

    return genesis


def main():
    parser = argparse.ArgumentParser(description="Seed genesis.json with precompile storage")
    parser.add_argument("--genesis", required=True, help="Path to genesis.json")
    parser.add_argument("--seed", required=True, help="Path to seed config JSON")
    parser.add_argument("--validators", help="Path to validators.json for genesis validator set")
    parser.add_argument("--output", required=True, help="Output path for patched genesis.json")
    parser.add_argument(
        "--contracts-dir",
        help="Directory containing contract code/state files referenced from "
             "seed['contracts']. Defaults to <seed-file-dir>/contracts.",
    )
    parser.add_argument(
        "--canon-dir",
        help="Directory holding metacanon.md and canon.md to seed into the "
             "Governance precompile at version 1. Defaults to <script-dir>/canon. "
             "When absent, the canon texts start empty and an authority sets them "
             "post-genesis.",
    )
    parser.add_argument(
        "--worldwide-day",
        type=int,
        help="Override the seeded active worldwide-day (YYYYMMDD): its S-curve peak "
             "and NOD references too. Localnet bootstrap passes the genesis date so "
             "the seeded OFFERING day tracks the chain's wall-clock; a stale "
             "hardcoded day desyncs from the per-block "
             "WorldwideDay::from_timestamp(block) and wedges metadosis processing.",
    )
    parser.add_argument(
        "--fresh-metadosis",
        action="store_true",
        help="Do not seed an already-OFFERING WorldwideDay; block 1 creates it "
             "from config.outbeProtocol timings in a test-protocol-overrides node. "
             "Intended for production-shaped E2E.",
    )
    args = parser.parse_args()

    with open(args.genesis) as f:
        genesis = json.load(f)
    with open(args.seed) as f:
        seed = json.load(f)
    validators = []
    if args.validators:
        with open(args.validators) as f:
            validators = json.load(f)

    # Build the declarative config this profile describes and hand it to
    # create_genesis, so this CLI used by the localnet scripts creates its
    # genesis through the same path a yaml-driven
    # deployment does. create_genesis calls apply_seed below to render it.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import create_genesis

    genesis = create_genesis.seed_genesis_from_config(
        base_genesis=genesis,
        seed=seed,
        validators=validators,
        contracts_dir=args.contracts_dir
        or os.path.join(os.path.dirname(os.path.abspath(args.seed)), "contracts"),
        canon_dir=args.canon_dir,
        worldwide_day=args.worldwide_day,
        fresh_metadosis=args.fresh_metadosis,
    )

    with open(args.output, "w") as f:
        json.dump(genesis, f, indent=2)

    total_storage = sum(
        len(v.get("storage", {})) for v in genesis["alloc"].values()
    )
    print(f"\nGenesis written to {args.output}")
    print(f"Total storage entries: {total_storage}")


if __name__ == "__main__":
    main()
