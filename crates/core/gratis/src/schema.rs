use alloy_primitives::{Address, B256, U256};
use outbe_macros::contract;
use outbe_primitives::addresses::GRATIS_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot, StorageBytes};

/// EVM storage layout for the confidential Gratis token.
///
/// Per-account balances and pledged amounts are **ciphertext at rest**: the
/// enclave is the only party that can decrypt them (and the account's view-key
/// holder, client-side). Only two non-attributable aggregates are kept in
/// plaintext.
///
/// Blob layout for every ciphertext slot: `version(8, big-endian) || AEAD-ct`.
/// The version is produced by the enclave and stored verbatim; it feeds the
/// deterministic nonce so a slot overwrite never reuses a `(key, nonce)` pair.
///
/// Pledge model (two-phase, no escrow account): `pledged_total_supply` counts both
/// pending collateral (parked in a `PledgeLockTicket`, debited from `balance` at
/// `pledge`) and active collateral (credited to `pledged_ct` at `consume_pledge`, and
/// drawn back down by `release_to_eoa`/`burn_pledged`). A ticket exists only for the
/// pending window and is deleted when consumed or unpledged; the active credis
/// schedule is tracked on-chain by the Credis position, not here.
///
/// Storage slots:
///   0: total_supply (U256, plaintext aggregate - feeds `GratisMined/Burned`)
///   1: pledged_total_supply (U256, plaintext aggregate - per-account hidden)
///   2: mapping(address => bytes)  - encrypted balance blob
///   3: mapping(address => bytes)  - encrypted pledged-ledger blob
///   4: mapping(address => u64)    - modify-auth replay counter (monotonic)
///   5: mapping(bytes32 => bytes)  - encrypted pledge-lock-tickets keyed by pledge_handle
#[contract(addr = GRATIS_ADDRESS)]
pub struct Gratis {
    pub total_supply: Slot<U256>,
    pub pledged_total_supply: Slot<U256>,
    pub balance_ct: Mapping<Address, StorageBytes>,
    pub pledged_ct: Mapping<Address, StorageBytes>,
    pub op_nonce: Mapping<Address, u64>,
    pub pledge_lock_tickets: Mapping<B256, StorageBytes>,
}
