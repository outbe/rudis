//! Cross-module API for the confidential Gratis token.

use alloy_primitives::{Address, B256, U256};

use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

pub use outbe_tee::protocol::{FidelityOpOutcome, FidelityOpSection, ModifyAuth, PledgeTerms};

use crate::runtime;
use crate::schema::Gratis;

// --- Reads ---

/// Encrypted balance blob for `account`; decrypt client-side with the view key.
pub fn balance_ct(storage: StorageHandle<'_>, account: Address) -> Result<Vec<u8>> {
    Gratis::new(storage).balance_ct_of(account)
}

/// Encrypted pledged-ledger blob for `account`.
pub fn pledged_ct(storage: StorageHandle<'_>, account: Address) -> Result<Vec<u8>> {
    Gratis::new(storage).pledged_ct_of(account)
}

/// The account's current modify-auth replay counter (the value the client's next
/// write authorization must bind).
pub fn op_nonce(storage: StorageHandle<'_>, account: Address) -> Result<u64> {
    Gratis::new(storage).op_nonce_of(account)
}

/// Public total circulating supply (aggregate; per-account balances hidden).
pub fn total_supply(storage: StorageHandle<'_>) -> Result<U256> {
    Gratis::new(storage).total_supply()
}

/// Public aggregate pledged into the credis escrow (per-account amounts hidden).
pub fn pledged_total_supply(storage: StorageHandle<'_>) -> Result<U256> {
    Gratis::new(storage).pledged_total_supply()
}

// --- Owner-authorized mutations ---

/// Mint `amount` gratis to `caller`.
pub fn mint(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    runtime::mint(storage, caller, amount, auth)
}

/// Mint gratis AND apply a co-located fidelity cohort section in ONE enclave
/// round-trip. Returns the fidelity outcome for the caller to persist via
/// `outbe_fidelity::api::apply_fidelity_outcome`.
pub fn mint_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<FidelityOpOutcome> {
    runtime::mint_with_fidelity(storage, caller, amount, auth, fidelity)
}

/// Burn `amount` gratis from `caller`. Returns the remaining total supply.
pub fn burn(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<U256> {
    runtime::burn(storage, caller, amount, auth)
}

/// Burn gratis AND apply a co-located fidelity cohort section in ONE enclave
/// round-trip. Returns the fidelity outcome for the caller to persist.
pub fn burn_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<FidelityOpOutcome> {
    runtime::burn_with_fidelity(storage, caller, amount, auth, fidelity)
}

/// Pledge the gratis that covers `terms.stables_amount` from `caller` into a new
/// pending `PledgeLockTicket`, sealing `terms` alongside it. `amount_stables` is the
/// MAC-bound figure and must equal `terms.stables_amount`. Returns the pledge handle
/// to present at `requestCredis`.
pub fn pledge(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    terms: PledgeTerms,
    auth: ModifyAuth,
) -> Result<B256> {
    runtime::pledge(storage, caller, amount_stables, terms, auth)
}

/// Pledge gratis AND carry a co-located fidelity **probe** in ONE round-trip.
/// Returns `(pledge_handle, fidelity_outcome)`; the outcome's `league` is the
/// caller's current league for the eligibility gate (nothing to persist - a
/// probe never mutates cohorts).
pub fn pledge_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    terms: PledgeTerms,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<(B256, FidelityOpOutcome)> {
    runtime::pledge_with_fidelity(storage, caller, amount_stables, terms, auth, fidelity)
}

/// Directly unpledge an unspent (pending) pledge (`pledge_handle`) back to `caller`.
/// `amount_stables` is the stables figure the pledge was quoted for - the enclave
/// matches it against the ticket. Returns the gratis collateral credited back.
pub fn unpledge(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    pledge_handle: B256,
    auth: ModifyAuth,
) -> Result<U256> {
    runtime::unpledge(storage, caller, amount_stables, pledge_handle, auth)
}

// --- Credis-driven ---

/// requestCredis: consume `pledge_handle`'s ticket for `bundle` (authorized by
/// `spend_auth`), crediting the collateral into the pledger's OWN pledged ledger and
/// deleting the ticket. The pledger EOA is not passed in calldata - the enclave recovers
/// it from the ticket. Returns `(terms, eoa_ct)`: the loan terms quoted when the pledge
/// was made (stables amount, asset, entry rate and the gratis collateral), plus the
/// sealed EOA the caller stores on the Credis position (later opened via
/// [`reveal_owner`]).
pub fn consume_pledge(
    storage: StorageHandle<'_>,
    pledge_handle: B256,
    bundle: Address,
    spend_auth: [u8; 32],
) -> Result<(PledgeTerms, Vec<u8>)> {
    runtime::consume_pledge(storage, pledge_handle, bundle, spend_auth)
}

/// Decrypt a position's stored `eoa_ct` blob back to the pledger EOA (read-only, via the
/// enclave). The caller uses the returned address to key the confidential ledgers at
/// settlement / void without the EOA ever appearing on-chain.
pub fn reveal_owner(storage: StorageHandle<'_>, eoa_ct: &[u8]) -> Result<Address> {
    runtime::reveal_owner(storage, eoa_ct)
}

/// Settlement: release `amount` of collateral from `eoa`'s own pledged ledger back
/// to its balance. Returns the released amount.
pub fn release_to_eoa(storage: StorageHandle<'_>, eoa: Address, amount: U256) -> Result<U256> {
    runtime::release_to_eoa(storage, eoa, amount)
}

/// Credis expiry: burn `amount` of collateral from `eoa`'s own pledged ledger
/// (reduces `total_supply`). Returns the burned amount.
pub fn burn_pledged(storage: StorageHandle<'_>, eoa: Address, amount: U256) -> Result<U256> {
    runtime::burn_pledged(storage, eoa, amount)
}

/// Credis expiry burn AND a co-located fidelity cohort sale for `eoa` in ONE
/// round-trip. Returns `(burned_amount, fidelity_outcome)` for the caller to
/// persist via `outbe_fidelity::api::apply_fidelity_outcome`.
pub fn burn_pledged_with_fidelity(
    storage: StorageHandle<'_>,
    eoa: Address,
    amount: U256,
    fidelity: FidelityOpSection,
) -> Result<(U256, FidelityOpOutcome)> {
    runtime::burn_pledged_with_fidelity(storage, eoa, amount, fidelity)
}
