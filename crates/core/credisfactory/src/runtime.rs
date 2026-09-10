//! Orchestration logic for the credisfactory precompile.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;

use outbe_credis::constants::{BP_DEN, POLICY_RATE_FACTOR_BP};
use outbe_credis::{CredisContract, OpenPositionParams};
use outbe_oracle::api::{fresh_coen_rate_for, get_policy_rate};
use outbe_primitives::addresses::{CREDIS_FACTORY_ADDRESS, VAULT_ROUTER_ADDRESS};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::checked_protocol_to_native;

use crate::errors::CredisFactoryError;
use crate::precompile::ICredisFactory;
use crate::sol_ext::IReferenceCurrency;
use crate::sol_ext::IERC20;

// ---------------------------------------------------------------------------
// request_credis
// ---------------------------------------------------------------------------

/// Consumes a confidential Gratis pledge (identified by `pledge_handle` +
/// `spend_auth`, which binds it to `smart_account`), crediting the collateral into
/// the pledger's own confidential pledged ledger, opens a credis position bound to
/// `smartAccount`, stores the sealed pledger EOA on the position for the later
/// collateral release / void burn, and delivers the stablecoin loan via the
/// vault sub-call.
///
/// The loan is not priced here: the disbursed amount, the asset and the collateral were
/// quoted and sealed into the pledge ticket by `pledgeGratis`, so the borrower gets the
/// terms they accepted rather than whatever the oracle reads now.
///
/// The threshold geometry is priced here, and only it. `reference_currency` is elected at
/// this call and pinned for the position's life; `entry_price` is the COEN quote in that
/// currency and the call price derives from it. Anchoring to the issuance currency reuses
/// the rate sealed into the ticket, so nothing about such a position moves between pledge
/// and origination; a cross-currency anchor has no sealed quote and is read now, which
/// means a delayed `requestCredis` moves its call threshold, though never its loan. The
/// policy rate is pinned here too, off the ISSUANCE currency - it belongs to the debt, not
/// to the threshold.
///
/// The pledger EOA is never in calldata: the enclave recovers it from the ticket and
/// returns it sealed (`eoa_ct`). `caller` is the CCA and is recorded on the position -
/// authorization to spend the pledge is `spend_auth`, verified inside the enclave.
/// Returns `(position_id, amount_stables)`.
pub fn request_credis(
    storage: StorageHandle<'_>,
    caller: Address,
    smart_account: Address,
    pledge_handle: B256,
    spend_auth: [u8; 32],
    reference_currency: u16,
    stake: U256,
) -> Result<(U256, U256)> {
    if smart_account.is_zero() {
        return Err(CredisFactoryError::InvalidSmartAccount.into());
    }

    // Origination is a CCA action, not an open one: the caller must be in good
    // standing at the registry. Today's registry is a stub that reports every address
    // active, so this rejects nothing yet - it is the seam the real one drops into.
    if !outbe_cca::api::is_active(&storage, caller)? {
        return Err(CredisFactoryError::CcaNotActive.into());
    }

    // The loan is delivered by a call into the smart account, and a CALL to a codeless
    // account succeeds returning empty - so an undeployed account would take the loan
    // into a black hole while the position and the consumed pledge stood. Same guard
    // the vault router applies to its own receiver.
    if storage.with_account_info(smart_account, |info| Ok(info.is_empty_code_hash()))? {
        return Err(CredisFactoryError::SmartAccountNotDeployed.into());
    }

    // Block timestamp is read from the execution frame rather than threaded in
    // by the caller.
    let current_time = storage.timestamp()?.to::<u64>();

    // Consume the pledge ticket (the enclave verifies `spend_auth` binds it to
    // `smart_account`, so a mempool copy cannot redirect the loan). The collateral
    // moves into the EOA's OWN pledged ledger and the ticket is deleted. The enclave
    // reads the pledger EOA from the ticket and returns it sealed (`eoa_ct`) so it is
    // stored on the position as ciphertext, never plaintext.
    let (terms, eoa_ct) = outbe_gratis::api::consume_pledge(
        storage.clone(),
        pledge_handle,
        smart_account,
        spend_auth,
    )?;
    let asset = terms.asset;
    if asset.is_zero() {
        return Err(CredisFactoryError::InvalidAsset.into());
    }

    // The CCA matches the borrower's six-decimal GRATIS collateral one for one in
    // value, but msg.value is native 18-decimal COEN. Checked only after
    // `consume_pledge` because the required amount is sealed in the ticket, not in
    // calldata - a caller cannot know it from the call alone, and must read it from the
    // pledge quote. Exact equality, not a floor: matching one for one is the rule, and a
    // floor would let the amount handed to the borrower drift off the collateral.
    let required_stake = checked_protocol_to_native(terms.gratis_amount)
        .ok_or_else(|| PrecompileError::Revert("native rudis stake overflow".into()))?;
    if stake != required_stake {
        return Err(CredisFactoryError::CcaStakeMismatch.into());
    }

    // Derive the issuance currency from the disbursed asset (it self-reports its
    // ISO 4217 code via `IReferenceCurrency.isoCode()`) and pin that currency's
    // official policy rate for the position's life.
    let issuance_currency = read_iso_code(&storage, asset)?;
    let policy_rate = policy_rate_for(storage.clone(), issuance_currency)?;

    outbe_oracle::api::check_reference_currency_with_storage(storage.clone(), reference_currency)?;

    let entry_price = if reference_currency == issuance_currency {
        terms.entry_rate
    } else {
        fresh_coen_rate_for(storage.clone(), reference_currency)?
    };

    // Open the position, storing the sealed pledger EOA so settlement and the void
    // can address the right confidential pledged ledger. The `handle_id`
    // building the position_id is the globally-unique pledge handle.
    let mut credis = CredisContract::new(storage.clone());
    let position_id = credis.open_position(OpenPositionParams {
        handle_id: U256::from_be_bytes(pledge_handle.0),
        smart_account,
        cca: caller,
        eoa_ct,
        asset,
        issuance_currency,
        reference_currency,
        policy_rate,
        principal: terms.stables_amount,
        entry_price,
        collateral: terms.gratis_amount,
        originated_at: current_time,
    })?;

    // The stake is the borrower's from here on: the boundary credited it to this
    // precompile's balance, and it passes straight through to the smart account as
    // ordinary native COEN - no escrow, no claim, nothing to release or burn later.
    if !stake.is_zero() {
        storage.transfer_balance(CREDIS_FACTORY_ADDRESS, smart_account, stake)?;
    }

    // Withdraw the matching stablecoin from the vault to the smart account.
    outbe_vaultrouter::api::withdraw(&storage, asset, terms.stables_amount, smart_account)?;

    storage.emit_event(
        CREDIS_FACTORY_ADDRESS,
        alloy_sol_types::SolEvent::encode_log_data(&ICredisFactory::CredisRequested {
            smartAccount: smart_account,
            cca: caller,
            amount: terms.stables_amount,
        }),
    )?;

    Ok((position_id, terms.stables_amount))
}

/// The currency's official annual policy rate, scaled by the policy-rate factor.
fn policy_rate_for(storage: StorageHandle<'_>, issuance_currency: u16) -> Result<U256> {
    let official = get_policy_rate(storage, issuance_currency)?;
    official
        .checked_mul(U256::from(POLICY_RATE_FACTOR_BP))
        .map(|v| v / U256::from(BP_DEN))
        .ok_or_else(|| PrecompileError::Revert("credis policy rate overflow".into()))
}

// ---------------------------------------------------------------------------
// settle
// ---------------------------------------------------------------------------

/// Applies `amount` to the position - accrued interest first, principal second -
/// and releases the matching share of collateral from the pledger's OWN confidential
/// pledged ledger back to its balance. When `amount` exceeds what the position still
/// needs, only the required part is pulled from the caller.
///
/// ANY caller may settle - a third party can settle someone else's position. That is
/// safe by construction rather than by an access check: the debt is pulled from
/// `caller`'s own balance, while the freed collateral goes to the pledger EOA stored
/// sealed on the position and recovered here through the enclave (`reveal_owner`). The
/// payer can therefore never redirect value to themselves, and the EOA never appears
/// on-chain. The payment (the ERC20 -> vault deposit below) is the authorization for
/// the release - no separate proof is required. Returns the stablecoin actually pulled.
/// Settles `amount` against a position and returns `(principal, interest)` - the
/// principal this payment covered and the interest it collected. Their sum is what
/// was pulled from the caller.
pub fn settle(
    storage: StorageHandle<'_>,
    caller: Address,
    position_id: U256,
    amount: U256,
) -> Result<(U256, U256)> {
    if amount.is_zero() {
        return Err(CredisFactoryError::InvalidAmount.into());
    }

    // Read-only validation pass before any mutation; recover the pledger EOA from the
    // position's sealed `eoa_ct` via a RevealOwner enclave round-trip.
    let eoa_account = {
        let credis_ro = CredisContract::new(storage.clone());
        let position = credis_ro.get_position(position_id)?;
        if position.asset.is_zero() {
            return Err(CredisFactoryError::InvalidAsset.into());
        }
        outbe_gratis::api::reveal_owner(storage.clone(), &position.eoa_ct)?
    };

    let current_time = storage.timestamp()?.to::<u64>();
    let mut credis = CredisContract::new(storage.clone());
    let settlement = credis.settle(position_id, amount, current_time)?;

    // ERC20 + vault sequence, moving only what the position consumed. Sub-call reverts
    // propagate out and unwind the bookkeeping via the surrounding precompile frame.
    let paid = settlement.total_paid;
    let asset = settlement.asset;

    if !paid.is_zero() {
        // 1) Pull stablecoin from caller into the credisfactory precompile address.
        let transfer = IERC20::transferFromCall {
            from: caller,
            to: CREDIS_FACTORY_ADDRESS,
            amount: paid,
        }
        .abi_encode();
        storage.call(asset, U256::ZERO, transfer.into())?;

        // 2) Approve the vault to spend that exact amount.
        let approve = IERC20::approveCall {
            spender: VAULT_ROUTER_ADDRESS,
            amount: paid,
        }
        .abi_encode();
        storage.call(asset, U256::ZERO, approve.into())?;

        // 3) Vault pulls and deposits into the reserve vault via its Solidity ABI.
        outbe_vaultrouter::api::deposit(&storage, asset, paid)?;
    }

    // 4) Release the collateral share freed by this settlement from the pledger's own
    //    pledged ledger back to its liquid Gratis balance.
    if !settlement.gratis_released.is_zero() {
        outbe_gratis::api::release_to_eoa(
            storage.clone(),
            eoa_account,
            settlement.gratis_released,
        )?;
    }

    Ok((settlement.principal_paid, settlement.interest))
}

// ---------------------------------------------------------------------------
// void
// ---------------------------------------------------------------------------

/// Voids the remainder of a called position whose settlement window has lapsed:
/// burns the unpaid share of the pledged collateral, drops the pledger's fidelity
/// cohort by that amount, and deposits the equivalent value into the Promis Reserve.
///
/// Nothing is market-sold and nothing is collected - the written-off principal and its
/// accrued interest simply cease to exist, and the burned collateral becomes invest-side
/// capacity instead.
pub fn void_position(storage: StorageHandle<'_>, position_id: U256) -> Result<()> {
    let now = storage.timestamp()?.to::<u64>();
    let void = CredisContract::new(storage.clone()).void_position(position_id, now)?;

    // Recover the pledger EOA from the position's sealed `eoa_ct` through the enclave so
    // the burn / fidelity drop address the right confidential ledgers (reveal once, use
    // for both).
    let eoa = outbe_gratis::api::reveal_owner(storage.clone(), &void.eoa_ct)?;

    // Burn the still-locked collateral from the pledger's own pledged ledger,
    // folding the Fidelity sale cohort into the SAME enclave round-trip (no extra
    // trip); persist the returned fidelity blob.
    let section = outbe_fidelity::api::cohort_section(
        storage.clone(),
        eoa,
        outbe_fidelity::api::FidelityCohortOp::Out,
        now,
    )?;
    let (_, outcome) = outbe_gratis::api::burn_pledged_with_fidelity(
        storage.clone(),
        eoa,
        void.gratis_burned,
        section,
    )?;
    outbe_fidelity::api::apply_fidelity_outcome(storage.clone(), eoa, &outcome)?;

    // The equivalent value is deposited 1:1 into the Promis Reserve.
    outbe_promislimit::PromisLimitContract::new(storage.clone())
        .add_to_total_unallocated(void.gratis_burned)?;

    Ok(())
}

/// Reads the disbursed asset's ISO 4217 currency code via a static
/// `IReferenceCurrency.isoCode()` sub-call. Mirrors the `staticcall` +
/// `abi_decode_returns` pattern used by intexfactory's ERC20 reads.
fn read_iso_code(storage: &StorageHandle<'_>, asset: Address) -> Result<u16> {
    let ret = storage.staticcall(
        asset,
        IReferenceCurrency::isoCodeCall {}.abi_encode().into(),
    )?;
    IReferenceCurrency::isoCodeCall::abi_decode_returns(&ret)
        .map_err(|_| CredisFactoryError::AssetIsoUndecodable.into())
}
