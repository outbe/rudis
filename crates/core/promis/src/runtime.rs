//! Business logic for the confidential Promis token.
//!
//! Each write reads the account's current ciphertext from storage, hands the op to
//! the enclave (which decrypts, enforces invariants, and re-encrypts
//! deterministically), then stores the returned ciphertext verbatim, applies the
//! plaintext aggregate delta, and emits the matching event. These methods are
//! crate-private; other crates reach them through [`crate::api`]. The enclave is
//! the sole party that sees plaintext balances (Enclave Return Rule).

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::PROMIS_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_tee::protocol::{ModifyAuth, PromisOp, PromisOpRequest, PromisOpResult, PromisOpStatus};

use crate::enclave_client::apply_promis_op;
use crate::precompile::IPromis;
use crate::schema::Promis;

/// The chain id the enclave binds a modify-auth to, as a `B256` (host and client
/// must agree on this encoding). Defense-in-depth: the modify key is already
/// chain-bound via the DKG state key.
fn chain_id_b256(storage: &StorageHandle<'_>) -> Result<B256> {
    Ok(B256::from(U256::from(storage.chain_id()?)))
}

/// Build a request with the fields common to every op left at their empty defaults.
fn base_request(op: PromisOp, chain_id: B256, account: Address, amount: U256) -> PromisOpRequest {
    PromisOpRequest {
        op,
        chain_id,
        account,
        amount,
        current_balance: Vec::new(),
        modify_auth: ModifyAuth {
            mac: [0u8; 32],
            op_nonce: 0,
        },
    }
}

/// Reject unless the supplied op-nonce equals the account's current on-chain
/// counter - this is what makes a captured modify-auth non-replayable.
fn check_op_nonce(promis: &Promis<'_>, account: Address, provided: u64) -> Result<()> {
    let current = promis.op_nonce_of(account)?;
    if provided != current {
        return Err(PrecompileError::Revert(format!(
            "invalid op nonce: expected {current}, got {provided}"
        )));
    }
    Ok(())
}

/// Turn a business rejection from the enclave into a precompile revert.
fn ensure_applied(result: &PromisOpResult) -> Result<()> {
    match &result.status {
        PromisOpStatus::Applied => Ok(()),
        PromisOpStatus::Rejected { reason } => Err(PrecompileError::Revert(reason.clone())),
    }
}

/// Store the balance ciphertext the enclave produced (an empty blob means the op
/// did not touch the slot).
fn write_balance(promis: &Promis<'_>, account: Address, result: &PromisOpResult) -> Result<()> {
    if !result.new_balance.is_empty() {
        promis.write_balance_ct(account, &result.new_balance)?;
    }
    Ok(())
}

/// Mint `amount` promis to `caller` (owner-authorized).
pub(crate) fn mint(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    let promis = Promis::new(storage.clone());
    check_op_nonce(&promis, caller, auth.op_nonce)?;
    let mut req = base_request(PromisOp::Mint, chain_id_b256(&storage)?, caller, amount);
    req.current_balance = promis.balance_ct_of(caller)?;
    req.modify_auth = auth;
    let result = apply_promis_op(req)?;
    ensure_applied(&result)?;
    write_balance(&promis, caller, &result)?;
    promis.set_op_nonce(caller, result.next_op_nonce)?;
    let new_supply = promis
        .total_supply()?
        .checked_add(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("promis total_supply overflow".to_string()))?;
    promis.set_total_supply(new_supply)?;
    storage.emit_event(
        PROMIS_ADDRESS,
        SolEvent::encode_log_data(&IPromis::PromisMinted {
            account: caller,
            amount: result.event_amount,
            newTotalSupply: new_supply,
        }),
    )?;
    Ok(())
}

/// Burn `amount` promis from `caller` (owner-authorized). Returns remaining supply.
pub(crate) fn burn(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<U256> {
    let promis = Promis::new(storage.clone());
    check_op_nonce(&promis, caller, auth.op_nonce)?;
    let mut req = base_request(PromisOp::Burn, chain_id_b256(&storage)?, caller, amount);
    req.current_balance = promis.balance_ct_of(caller)?;
    req.modify_auth = auth;
    let result = apply_promis_op(req)?;
    ensure_applied(&result)?;
    write_balance(&promis, caller, &result)?;
    promis.set_op_nonce(caller, result.next_op_nonce)?;
    let remaining = promis
        .total_supply()?
        .checked_sub(result.event_amount)
        .ok_or_else(|| PrecompileError::Fatal("promis total_supply underflow".to_string()))?;
    promis.set_total_supply(remaining)?;
    storage.emit_event(
        PROMIS_ADDRESS,
        SolEvent::encode_log_data(&IPromis::PromisBurned {
            account: caller,
            amount: result.event_amount,
            remainingSupply: remaining,
        }),
    )?;
    Ok(remaining)
}
