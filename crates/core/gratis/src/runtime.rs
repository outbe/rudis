//! Business logic for the confidential Gratis token.
//!
//! Each write reads the account's current ciphertext from storage, hands the op
//! to the enclave (which decrypts, enforces invariants, and re-encrypts
//! deterministically), then stores the returned ciphertext verbatim, applies the
//! plaintext aggregate delta, and emits the matching event. These methods are
//! crate-private; other crates reach them through [`crate::api`]. The enclave is
//! the sole party that sees plaintext balances (Enclave Return Rule).
//!
//! Pledge model (two-phase, no escrow account): `pledge` debits `balance` and parks
//! the gratis in an encrypted `PledgeLockTicket` alongside the loan terms it was
//! quoted against; `consume_pledge` (at requestCredis) deletes the ticket, credits the
//! EOA's OWN pledged ledger and hands those terms to credis; `release_to_eoa`
//! (per settlement) and `burn_pledged` (at credis void) draw the collateral back down
//! from that same EOA's pledged ledger. `pledged_total_supply` counts both the
//! pending (in-ticket) and active (in `pledged_ct`) locked gratis.
//!
//! Unit warning: for `pledge`/`unpledge` the MAC-bound `amount` is the STABLECOIN
//! figure the pledger signed, while every balance, aggregate and event here is in
//! GRATIS. The gratis figure comes from the terms (on a pledge) or the ticket (on an
//! unpledge/consume), never from `amount`.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::GRATIS_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_tee::protocol::{
    FidelityOpOutcome, FidelityOpSection, GratisOp, GratisOpRequest, GratisOpResult,
    GratisOpStatus, ModifyAuth, PledgeTerms,
};

use crate::enclave_client::apply_gratis_op;
use crate::precompile::IGratis;
use crate::schema::Gratis;

/// A co-located fidelity section was sent, so the enclave must return its
/// outcome; a missing one is an enclave/transport fault.
fn require_fidelity_outcome(outcome: Option<FidelityOpOutcome>) -> Result<FidelityOpOutcome> {
    outcome.ok_or_else(|| {
        PrecompileError::Fatal("enclave dropped the fidelity section outcome".to_string())
    })
}

/// The chain id the enclave binds a modify-auth to, as a `B256` (host and client
/// must agree on this encoding). The account's modify key is already chain-bound
/// via the DKG state key, so this is defense-in-depth.
fn chain_id_b256(storage: &StorageHandle<'_>) -> Result<B256> {
    Ok(B256::from(U256::from(storage.chain_id()?)))
}

/// A placeholder authorization for the credis-driven ops (`ConsumePledge`,
/// `ReleaseToEoa`, `BurnPledged`), which are gated by the pledge-ticket state /
/// spend-auth binding and the on-chain Credis position schedule rather than a modify
/// key.
fn no_auth() -> ModifyAuth {
    ModifyAuth {
        mac: [0u8; 32],
        op_nonce: 0,
    }
}

/// Build a request with the fields common to every op left at their empty defaults.
fn base_request(op: GratisOp, chain_id: B256, account: Address, amount: U256) -> GratisOpRequest {
    GratisOpRequest {
        op,
        chain_id,
        account,
        amount,
        current_balance: Vec::new(),
        current_pledged: Vec::new(),
        current_pledge_record: Vec::new(),
        modify_auth: no_auth(),
        pledge_handle: None,
        smart_account: None,
        spend_auth: None,
        pledge_terms: None,
        fidelity: None,
    }
}

/// Reject unless the supplied op-nonce equals the account's current on-chain
/// counter - this is what makes a captured modify-auth non-replayable.
fn check_op_nonce(gratis: &Gratis<'_>, account: Address, provided: u64) -> Result<()> {
    let current = gratis.op_nonce_of(account)?;
    if provided != current {
        return Err(PrecompileError::Revert(format!(
            "invalid op nonce: expected {current}, got {provided}"
        )));
    }
    Ok(())
}

/// Turn a business rejection from the enclave into a precompile revert.
fn ensure_applied(result: &GratisOpResult) -> Result<()> {
    match &result.status {
        GratisOpStatus::Applied => Ok(()),
        GratisOpStatus::Rejected { reason } => Err(PrecompileError::Revert(reason.clone())),
    }
}

/// Store the balance / pledged ciphertext blobs the enclave produced (an empty
/// blob means the op did not touch that slot).
fn write_account_blobs(
    gratis: &Gratis<'_>,
    account: Address,
    result: &GratisOpResult,
) -> Result<()> {
    if !result.new_balance.is_empty() {
        gratis.write_balance_ct(account, &result.new_balance)?;
    }
    if !result.new_pledged.is_empty() {
        gratis.write_pledged_ct(account, &result.new_pledged)?;
    }
    Ok(())
}

/// Mint `amount` gratis to `caller` (owner-authorized), optionally carrying a
/// co-located fidelity cohort section applied in the SAME enclave round-trip.
fn mint_impl(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: Option<FidelityOpSection>,
) -> Result<Option<FidelityOpOutcome>> {
    let gratis = Gratis::new(storage.clone());
    check_op_nonce(&gratis, caller, auth.op_nonce)?;
    let mut req = base_request(GratisOp::Mint, chain_id_b256(&storage)?, caller, amount);
    req.current_balance = gratis.balance_ct_of(caller)?;
    req.modify_auth = auth;
    req.fidelity = fidelity;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, caller, &result)?;
    gratis.set_op_nonce(caller, result.next_op_nonce)?;
    let new_supply = gratis
        .total_supply()?
        .checked_add(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis total_supply overflow".to_string()))?;
    gratis.set_total_supply(new_supply)?;
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisMinted {
            account: caller,
            amount: result.event_amount,
            newTotalSupply: new_supply,
        }),
    )?;
    Ok(result.fidelity)
}

/// Mint `amount` gratis to `caller` (owner-authorized).
pub(crate) fn mint(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    mint_impl(storage, caller, amount, auth, None).map(|_| ())
}

/// Mint gratis and apply a co-located fidelity cohort acquisition in one
/// enclave round-trip; returns the fidelity outcome for the caller to persist.
pub(crate) fn mint_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<FidelityOpOutcome> {
    require_fidelity_outcome(mint_impl(storage, caller, amount, auth, Some(fidelity))?)
}

/// Burn `amount` gratis from `caller` (owner-authorized), optionally carrying a
/// co-located fidelity cohort section. Returns remaining supply + the outcome.
fn burn_impl(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: Option<FidelityOpSection>,
) -> Result<(U256, Option<FidelityOpOutcome>)> {
    let gratis = Gratis::new(storage.clone());
    check_op_nonce(&gratis, caller, auth.op_nonce)?;
    let mut req = base_request(GratisOp::Burn, chain_id_b256(&storage)?, caller, amount);
    req.current_balance = gratis.balance_ct_of(caller)?;
    req.modify_auth = auth;
    req.fidelity = fidelity;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, caller, &result)?;
    gratis.set_op_nonce(caller, result.next_op_nonce)?;
    let remaining = gratis
        .total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis total_supply underflow".to_string()))?;
    gratis.set_total_supply(remaining)?;
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisBurned {
            account: caller,
            amount: result.event_amount,
            remainingSupply: remaining,
        }),
    )?;
    Ok((remaining, result.fidelity))
}

/// Burn `amount` gratis from `caller` (owner-authorized). Returns remaining supply.
pub(crate) fn burn(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<U256> {
    Ok(burn_impl(storage, caller, amount, auth, None)?.0)
}

/// Burn gratis and apply a co-located fidelity cohort sale in one enclave
/// round-trip; returns the fidelity outcome for the caller to persist.
pub(crate) fn burn_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<FidelityOpOutcome> {
    require_fidelity_outcome(burn_impl(storage, caller, amount, auth, Some(fidelity))?.1)
}

/// Lock the gratis that covers `terms.stables_amount` into a new pending
/// `PledgeLockTicket`, sealing the loan terms alongside it. The gratis leaves the
/// liquid balance but is NOT yet credited to the pledged ledger (that happens at
/// `consume_pledge`). `amount_stables` is the MAC-bound figure; the gratis actually
/// debited comes from `terms`. Returns the pledge handle the CCA later presents at
/// `requestCredis`.
fn pledge_impl(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    terms: PledgeTerms,
    auth: ModifyAuth,
    fidelity: Option<FidelityOpSection>,
) -> Result<(B256, Option<FidelityOpOutcome>)> {
    let gratis = Gratis::new(storage.clone());
    check_op_nonce(&gratis, caller, auth.op_nonce)?;
    let mut req = base_request(
        GratisOp::Pledge,
        chain_id_b256(&storage)?,
        caller,
        amount_stables,
    );
    req.current_balance = gratis.balance_ct_of(caller)?;
    req.modify_auth = auth;
    req.pledge_terms = Some(terms);
    req.fidelity = fidelity;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, caller, &result)?;
    gratis.write_pledge_ticket_ct(result.pledge_handle, &result.new_pledge_record)?;
    gratis.set_op_nonce(caller, result.next_op_nonce)?;
    let total_pledged = gratis
        .pledged_total_supply()?
        .checked_add(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis pledged_total overflow".to_string()))?;
    gratis.set_pledged_total_supply(total_pledged)?;
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisPledged {
            account: caller,
            amount: result.event_amount,
            totalPledged: total_pledged,
        }),
    )?;
    Ok((result.pledge_handle, result.fidelity))
}

pub(crate) fn pledge(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    terms: PledgeTerms,
    auth: ModifyAuth,
) -> Result<B256> {
    Ok(pledge_impl(storage, caller, amount_stables, terms, auth, None)?.0)
}

/// Pledge and carry a co-located fidelity **probe** (read-only league) in the
/// same round-trip; returns the pledge handle + the caller's league outcome for
/// the eligibility gate.
pub(crate) fn pledge_with_fidelity(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    terms: PledgeTerms,
    auth: ModifyAuth,
    fidelity: FidelityOpSection,
) -> Result<(B256, FidelityOpOutcome)> {
    let (handle, outcome) =
        pledge_impl(storage, caller, amount_stables, terms, auth, Some(fidelity))?;
    Ok((handle, require_fidelity_outcome(outcome)?))
}

/// Return a still-pending pledge (e.g. credis rejected): credit the ticket's gratis
/// back to `caller`'s balance and delete the ticket. `amount_stables` is the stables
/// figure the pledge was quoted for; the enclave cross-checks it against the ticket
/// and returns the matching gratis.
pub(crate) fn unpledge(
    storage: StorageHandle<'_>,
    caller: Address,
    amount_stables: U256,
    pledge_handle: B256,
    auth: ModifyAuth,
) -> Result<U256> {
    let gratis = Gratis::new(storage.clone());
    check_op_nonce(&gratis, caller, auth.op_nonce)?;
    let mut req = base_request(
        GratisOp::Unpledge,
        chain_id_b256(&storage)?,
        caller,
        amount_stables,
    );
    req.current_balance = gratis.balance_ct_of(caller)?;
    req.current_pledge_record = gratis.pledge_ticket_ct_of(pledge_handle)?;
    req.modify_auth = auth;
    req.pledge_handle = Some(pledge_handle);
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, caller, &result)?;
    // `new_pledge_record` is empty -> this clears (deletes) the ticket slot.
    gratis.write_pledge_ticket_ct(pledge_handle, &result.new_pledge_record)?;
    gratis.set_op_nonce(caller, result.next_op_nonce)?;
    let total_pledged = gratis
        .pledged_total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis pledged_total underflow".to_string()))?;
    gratis.set_pledged_total_supply(total_pledged)?;
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisUnpledged {
            account: caller,
            amount: result.event_amount,
            remainingPledged: total_pledged,
        }),
    )?;
    Ok(result.event_amount)
}

/// Recover the plaintext EOA behind a sealed owner blob through the enclave, without
/// touching state. `handle = Some(h)` decrypts a live pledge ticket (at
/// `consume_pledge`, before calldata carries the EOA); `None` decrypts the self-contained
/// `eoa_ct` stored on a Credis position (at settlement / void). The EOA is recovered
/// this way so it never appears in calldata or stored plaintext - only in the (trusted)
/// host to key the confidential ledgers.
fn reveal_owner_inner(
    storage: &StorageHandle<'_>,
    blob: &[u8],
    handle: Option<B256>,
) -> Result<Address> {
    let mut req = base_request(
        GratisOp::RevealOwner,
        chain_id_b256(storage)?,
        Address::ZERO,
        U256::ZERO,
    );
    req.current_pledge_record = blob.to_vec();
    req.pledge_handle = handle;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    Ok(result.revealed_owner)
}

/// Decrypt the `eoa_ct` blob stored on a Credis position back to the pledger EOA
/// (single read-only `RevealOwner` round-trip).
pub(crate) fn reveal_owner(storage: StorageHandle<'_>, eoa_ct: &[u8]) -> Result<Address> {
    reveal_owner_inner(&storage, eoa_ct, None)
}

/// requestCredis: consume `pledge_handle`'s ticket (authorized by `spend_auth`, which
/// binds it to `bundle`), crediting the collateral into the EOA's OWN pledged ledger
/// and deleting the ticket. No escrow account and no aggregate change (it stays
/// pledged, pending -> active). The EOA is not passed in calldata: the enclave carries it
/// in the ticket, so we first `RevealOwner` it (to key its pledged ledger) and the
/// consume result seals it into `eoa_ct` for the caller to store on the position. Returns
/// `(terms, eoa_ct)` - the loan terms quoted when the pledge was made, so credis never
/// re-prices the collateral.
pub(crate) fn consume_pledge(
    storage: StorageHandle<'_>,
    pledge_handle: B256,
    bundle: Address,
    spend_auth: [u8; 32],
) -> Result<(PledgeTerms, Vec<u8>)> {
    let gratis = Gratis::new(storage.clone());
    let ticket_ct = gratis.pledge_ticket_ct_of(pledge_handle)?;
    // Recover the pledger EOA from the ticket so we can read/write its own pledged ledger.
    let eoa = reveal_owner_inner(&storage, &ticket_ct, Some(pledge_handle))?;
    let mut req = base_request(
        GratisOp::ConsumePledge,
        chain_id_b256(&storage)?,
        eoa,
        U256::ZERO,
    );
    req.current_pledged = gratis.pledged_ct_of(eoa)?;
    req.current_pledge_record = ticket_ct;
    req.pledge_handle = Some(pledge_handle);
    req.smart_account = Some(bundle);
    req.spend_auth = Some(spend_auth);
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    // Credit the EOA's own pledged ledger and delete the consumed ticket.
    write_account_blobs(&gratis, eoa, &result)?;
    gratis.write_pledge_ticket_ct(pledge_handle, &result.new_pledge_record)?;
    let terms = result.pledge_terms.ok_or_else(|| {
        PrecompileError::Fatal("enclave dropped the consumed pledge terms".to_string())
    })?;
    Ok((terms, result.eoa_ct))
}

/// Settlement: release `amount` of collateral from `eoa`'s own pledged ledger back
/// to its balance. Amount-based (no ticket): the credis position is the accounting
/// authority. Returns the released amount.
pub(crate) fn release_to_eoa(
    storage: StorageHandle<'_>,
    eoa: Address,
    amount: U256,
) -> Result<U256> {
    let gratis = Gratis::new(storage.clone());
    let mut req = base_request(
        GratisOp::ReleaseToEoa,
        chain_id_b256(&storage)?,
        eoa,
        amount,
    );
    req.current_balance = gratis.balance_ct_of(eoa)?;
    req.current_pledged = gratis.pledged_ct_of(eoa)?;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, eoa, &result)?;
    let total_pledged = gratis
        .pledged_total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis pledged_total underflow".to_string()))?;
    gratis.set_pledged_total_supply(total_pledged)?;
    // Scrub the EOA from the event: this is a credis-driven release tied to a specific
    // position (credis emits the position-scoped `SettlementApplied`), so emitting the
    // pledger address here would re-link EOA<->position on every settlement. The aggregate
    // `remainingPledged` signal is preserved.
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisUnpledged {
            account: Address::ZERO,
            amount: result.event_amount,
            remainingPledged: total_pledged,
        }),
    )?;
    Ok(result.gratis_amount)
}

/// Credis expiry: burn `amount` of collateral from `eoa`'s own pledged ledger,
/// reducing both `total_supply` and `pledged_total_supply`. Amount-based (no ticket):
/// the credis position's outstanding collateral is the authority. Returns the burned
/// amount.
fn burn_pledged_impl(
    storage: StorageHandle<'_>,
    eoa: Address,
    amount: U256,
    fidelity: Option<FidelityOpSection>,
) -> Result<(U256, Option<FidelityOpOutcome>)> {
    let gratis = Gratis::new(storage.clone());
    let mut req = base_request(GratisOp::BurnPledged, chain_id_b256(&storage)?, eoa, amount);
    req.current_pledged = gratis.pledged_ct_of(eoa)?;
    req.fidelity = fidelity;
    let result = apply_gratis_op(req)?;
    ensure_applied(&result)?;
    write_account_blobs(&gratis, eoa, &result)?;
    let remaining = gratis
        .total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis total_supply underflow".to_string()))?;
    gratis.set_total_supply(remaining)?;
    let total_pledged = gratis
        .pledged_total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("gratis pledged_total underflow".to_string()))?;
    gratis.set_pledged_total_supply(total_pledged)?;
    // Scrub the EOA from the event (see `release_to_eoa`): credis emits the position-scoped
    // `CollateralBurned`; the supply signal here stays via `remainingSupply`.
    storage.emit_event(
        GRATIS_ADDRESS,
        SolEvent::encode_log_data(&IGratis::GratisBurned {
            account: Address::ZERO,
            amount: result.event_amount,
            remainingSupply: remaining,
        }),
    )?;
    Ok((result.gratis_amount, result.fidelity))
}

pub(crate) fn burn_pledged(storage: StorageHandle<'_>, eoa: Address, amount: U256) -> Result<U256> {
    Ok(burn_pledged_impl(storage, eoa, amount, None)?.0)
}

/// Burn collateral at credis expiry and apply a co-located fidelity cohort sale
/// for `eoa` in one round-trip; returns the burned amount + the fidelity outcome.
pub(crate) fn burn_pledged_with_fidelity(
    storage: StorageHandle<'_>,
    eoa: Address,
    amount: U256,
    fidelity: FidelityOpSection,
) -> Result<(U256, FidelityOpOutcome)> {
    let (burned, outcome) = burn_pledged_impl(storage, eoa, amount, Some(fidelity))?;
    Ok((burned, require_fidelity_outcome(outcome)?))
}
