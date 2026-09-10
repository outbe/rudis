use alloy_primitives::{Address, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::PROMIS_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot, StorageBytes};

/// EVM storage layout for the confidential Promis token.
///
/// Per-account balances are **ciphertext at rest**: the enclave is the only party
/// that can decrypt them (and the account's view-key holder, client-side). Only
/// the non-attributable `total_supply` aggregate is kept in plaintext.
///
/// Blob layout for the ciphertext balance slot: `version(8, big-endian) || AEAD-ct`
/// (a fixed 56 bytes). The version is produced by the enclave and stored verbatim;
/// it feeds the deterministic nonce so a slot overwrite never reuses a `(key,
/// nonce)` pair.
///
/// **Breaking layout change (genesis-reset):** Promis was previously a plaintext
/// ERC-20 with `balances: Map<Address, U256>` at slot 1. That slot is now reserved
/// (`deprecated_balances`, never read/written) so `balance_ct` lands at a fresh
/// slot and a stale pre-encryption DB can never be misread as ciphertext.
///
/// Storage slots:
///   0: total_supply (U256, plaintext aggregate - feeds `PromisMinted/Burned`)
///   1: deprecated_balances - RESERVED (old plaintext balances; unused)
///   2: mapping(address => bytes) - encrypted balance blob
///   3: mapping(address => u64)   - modify-auth replay counter (monotonic)
#[contract(addr = PROMIS_ADDRESS)]
pub struct Promis {
    pub total_supply: Slot<U256>,
    pub deprecated_balances: Mapping<Address, U256>,
    pub balance_ct: Mapping<Address, StorageBytes>,
    pub op_nonce: Mapping<Address, u64>,
}
