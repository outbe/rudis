use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolEvent};
use outbe_gem::{api as gem_api, GemAddParams, GemState};
use outbe_intex::SeriesId;
use outbe_oracle::api::fresh_coen_rate_for;
use outbe_primitives::addresses::{
    GEM_FACTORY_ADDRESS, INTEX_NFT1155_ADDRESS, VAULT_ROUTER_ADDRESS,
};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::SCALE_1E6_U256;

use outbe_common::pow;

use crate::constants::SRA_RATE;
use crate::errors::GemFactoryError;
use crate::precompile::IGemFactory::{GemIssued, GemMined, GemSettled};
use crate::schema::{GemFactoryContract, GemPosition, GemTypes};
use crate::sol_ext::{IIntexNFT1155, IReferenceCurrency, IERC20};
use outbe_vaultrouter::api::IVaultRouter;

/// Issues one agent-class gem priced at `entry_price`, the COEN rate in
/// `reference_currency` that the caller resolved for the gem's own day.
pub fn issue_gem(
    storage: &StorageHandle<'_>,
    owner: Address,
    gem_type: GemTypes,
    promis_load: U256,
    issuance_currency: u16,
    reference_currency: u16,
    entry_price: U256,
) -> Result<U256> {
    if owner.is_zero() {
        return Err(GemFactoryError::InvalidOwner.into());
    }
    if entry_price.is_zero() {
        return Err(GemFactoryError::OracleUnavailable.into());
    }
    // A zero load makes the cost zero, and a PayNote cannot spend zero.
    if promis_load.is_zero() {
        return Err(GemFactoryError::ZeroPromisLoad.into());
    }

    // The holder's own label: only its range is checked, as the auction checks a bid's.
    if issuance_currency == 0 || issuance_currency > 999 {
        return Err(GemFactoryError::InvalidCurrency {
            currency: issuance_currency,
        }
        .into());
    }
    outbe_oracle::api::check_reference_currency_with_storage(storage.clone(), reference_currency)?;

    // The caller resolves the price: it knows which day the gem belongs to.
    let issued_at = storage.timestamp()?.to::<u64>();
    let terms = outbe_gem::config::read(storage)?;
    let (floor_price, initial_state) = compute_params(gem_type, promis_load, entry_price, &terms)?;
    let call_price = derived_call_price(entry_price, terms.call_rate)?;

    let params = GemAddParams {
        owner,
        gem_type: gem_type as u8,
        promis_load_minor: promis_load,
        entry_price_minor: entry_price,
        floor_price_minor: floor_price,
        call_price_minor: call_price,
        call_rate: terms.call_rate,
        issuance_currency,
        reference_currency,
        initial_state,
        issued_at,
    };
    let gem_id = gem_api::add_gem(storage, params)?;

    let factory = GemFactoryContract::new(storage.clone());
    let prev_total = factory.total_gems_issued.read()?;
    let new_total = prev_total
        .checked_add(U256::from(1))
        .ok_or(GemFactoryError::Overflow)?;
    factory.total_gems_issued.write(new_total)?;

    emit_event(
        storage,
        GemIssued {
            gemId: gem_id,
            gemType: gem_type as u8,
            owner,
            promisLoad: promis_load,
            entryPrice: entry_price,
            floorPrice: floor_price,
            issuanceCurrency: issuance_currency,
            referenceCurrency: reference_currency,
            issuedAt: issued_at,
        },
    )?;

    Ok(gem_id)
}

/// Park a merchant's whole Intex series and issue a GemPosition NFT. Burns the
/// merchant's entire Issued holding on IntexNFT1155 (`parkIntex`, GEM_ROLE)
/// and records the position with a snapshot of the source entry/floor and the
/// resulting Promis capacity. Returns the issued `position_id`.
pub fn issue_gem_position(
    storage: &StorageHandle<'_>,
    caller: Address,
    source_intex_id: SeriesId,
    amount: U256,
) -> Result<U256> {
    if caller.is_zero() {
        return Err(GemFactoryError::InvalidOwner.into());
    }

    let series = outbe_intex::api::get_series(storage, source_intex_id)?
        .ok_or(GemFactoryError::SourceIntexNotFound)?;

    // A currency no qualification scan walks would leave every gem stuck in Issued.
    outbe_oracle::api::check_reference_currency_with_storage(
        storage.clone(),
        series.reference_currency,
    )?;

    // Burn `amount` of the merchant's Intex units; `parkIntex` returns the
    // burned count (and reverts on a non-parkable state or a zero amount).
    let units = burn_parked_intex(storage, caller, source_intex_id, amount)?;
    let capacity = series
        .promis_load_minor
        .checked_mul(units)
        .ok_or(GemFactoryError::Overflow)?;

    // Their load moved into the position, so the source series cannot forfeit them.
    let parked_units = u32::try_from(units).map_err(|_| GemFactoryError::Overflow)?;
    outbe_intex::api::record_parked_units(storage, source_intex_id, parked_units)?;

    let parked_at = storage.timestamp()?.to::<u64>();
    let position_id =
        GemFactoryContract::generate_position_id(source_intex_id, storage.block_number()?);

    let mut factory = GemFactoryContract::new(storage.clone());
    factory.add_position(&GemPosition {
        position_id,
        merchant: caller,
        source_intex_id,
        remaining_capacity: capacity,
        source_entry_price: series.entry_price_minor,
        source_floor_price: series.floor_price_minor,
        issuance_currency: series.issuance_currency,
        reference_currency: series.reference_currency,
        parked_at,
        expires_at: parked_at.saturating_add(outbe_gem::config::read(storage)?.position_validity),
    })?;

    factory.push_live_position(position_id)?;

    let prev_parked = factory.total_intex_parked.read()?;
    let new_parked = prev_parked
        .checked_add(capacity)
        .ok_or(GemFactoryError::Overflow)?;
    factory.total_intex_parked.write(new_parked)?;

    Ok(position_id)
}

/// Burn `amount` of the merchant's Issued Intex units via `parkIntex`
/// (GEM_ROLE) and return the burned count. Reverts if the series is in a
/// non-parkable (non-Issued/Qualified) state or `amount` is zero.
fn burn_parked_intex(
    storage: &StorageHandle<'_>,
    holder: Address,
    series_id: SeriesId,
    amount: U256,
) -> Result<U256> {
    let ret = storage.call(
        INTEX_NFT1155_ADDRESS,
        U256::ZERO,
        IIntexNFT1155::parkIntexCall {
            holder,
            seriesId: series_id.into(),
            amount,
        }
        .abi_encode()
        .into(),
    )?;
    IIntexNFT1155::parkIntexCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("parkIntex return undecodable".into()))
}

/// Issue one Merchant gem to a customer, draining the position's capacity.
pub fn issue_merchant_gem(
    storage: &StorageHandle<'_>,
    caller: Address,
    position_id: U256,
    owner: Address,
    promis_load: U256,
) -> Result<U256> {
    if owner.is_zero() {
        return Err(GemFactoryError::InvalidOwner.into());
    }
    // A zero load makes the cost zero, and a PayNote cannot spend zero.
    if promis_load.is_zero() {
        return Err(GemFactoryError::ZeroPromisLoad.into());
    }

    let mut factory = GemFactoryContract::new(storage.clone());
    let mut record = factory
        .positions
        .get(position_id)?
        .ok_or(GemFactoryError::PositionNotFound)?;
    if record.merchant != caller {
        return Err(GemFactoryError::NotPositionOwner.into());
    }

    let now = storage.timestamp()?.to::<u64>();
    if now >= record.expires_at {
        return Err(GemFactoryError::PositionExpired.into());
    }
    let remaining = record
        .remaining_capacity
        .checked_sub(promis_load)
        .ok_or(GemFactoryError::InsufficientCapacity)?;

    // Both maxima are an anti-dilution floor, not a price: never below the source Intex.
    let coen_rate = read_reference_oracle_rate(storage, record.reference_currency)?;
    let entry_price = coen_rate.max(record.source_entry_price);
    compute_cost(entry_price, promis_load, 100)?;
    let terms = outbe_gem::config::read(storage)?;
    let floor_price = derived_floor(entry_price, terms.floor_rate)?.max(record.source_floor_price);
    let call_price = derived_call_price(entry_price, terms.call_rate)?;

    let gem_id = gem_api::add_gem(
        storage,
        GemAddParams {
            owner,
            gem_type: GemTypes::Merchant as u8,
            promis_load_minor: promis_load,
            entry_price_minor: entry_price,
            floor_price_minor: floor_price,
            call_price_minor: call_price,
            call_rate: terms.call_rate,
            issuance_currency: record.issuance_currency,
            reference_currency: record.reference_currency,
            initial_state: GemState::Issued,
            issued_at: now,
        },
    )?;

    record.remaining_capacity = remaining;
    factory.positions.update(&record)?;
    // Nothing left to return: it leaves the queue instead of sitting at the head.
    if remaining.is_zero() {
        factory.remove_live_position(position_id)?;
    }

    let prev_total = factory.total_gems_issued.read()?;
    let new_total = prev_total
        .checked_add(U256::from(1))
        .ok_or(GemFactoryError::Overflow)?;
    factory.total_gems_issued.write(new_total)?;

    emit_event(
        storage,
        GemIssued {
            gemId: gem_id,
            gemType: GemTypes::Merchant as u8,
            owner,
            promisLoad: promis_load,
            entryPrice: entry_price,
            floorPrice: floor_price,
            issuanceCurrency: record.issuance_currency,
            referenceCurrency: record.reference_currency,
            issuedAt: now,
        },
    )?;

    Ok(gem_id)
}

/// The cost is discharged by spending a PayNote, so no tokens move here.
pub fn settle_gem(
    storage: &StorageHandle<'_>,
    caller: Address,
    gem_id: U256,
    paynote_proof: &[u8],
) -> Result<()> {
    let item = gem_api::get_gem(storage, gem_id)?.ok_or(GemFactoryError::GemNotFound)?;
    if item.owner != caller {
        return Err(GemFactoryError::NotGemOwner.into());
    }
    // Settlement is allowed from Qualified (voluntary) or Called (forced). A
    // Called gem must settle before its notice period lapses.
    match item.state {
        s if s == GemState::Qualified as u8 => {}
        s if s == GemState::Called as u8 => {
            let now = storage.timestamp()?.to::<u64>();
            let deadline = item.called_at + u64::from(item.call_notice_period);
            if now > deadline {
                return Err(GemFactoryError::DeadlineExpired.into());
            }
        }
        _ => return Err(GemFactoryError::InvalidState.into()),
    }

    // Last, so a doomed settle never pays for proof verification.
    let claim = outbe_paynote::api::consume(storage, paynote_proof)?;

    // Notes are bearer: anyone can relay a proof, so bind its spender to the caller.
    if claim.spender != caller {
        return Err(GemFactoryError::PayNoteSpenderMismatch {
            expected: caller,
            actual: claim.spender,
        }
        .into());
    }

    let currency = accept_payment_asset(storage, claim.asset, &item)?;
    let expected = match currency {
        PaymentCurrency::Reference => item.reference_currency,
        PaymentCurrency::Issuance => item.issuance_currency,
    };
    let amount_paid = cost_in_token(storage, &item, claim.asset, currency)?;
    if claim.spend_amount < amount_paid {
        return Err(GemFactoryError::PayNoteUndercoversCost {
            covered: claim.spend_amount,
            required: amount_paid,
        }
        .into());
    }

    gem_api::set_state(storage, gem_id, GemState::Settled)?;

    emit_event(
        storage,
        GemSettled {
            gemId: gem_id,
            owner: caller,
            amountPaid: amount_paid,
            settlementCurrency: expected,
        },
    )?;

    Ok(())
}

/// Reads the settlement asset's `decimals()` via a static sub-call.
fn read_decimals(storage: &StorageHandle<'_>, asset: Address) -> Result<u8> {
    let ret = storage.staticcall(asset, IERC20::decimalsCall {}.abi_encode().into())?;
    IERC20::decimalsCall::abi_decode_returns(&ret).map_err(|_| GemFactoryError::InvalidAsset.into())
}

/// Which of a gem's two currencies a payment asset is denominated in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaymentCurrency {
    Reference,
    Issuance,
}

/// Which of the gem's two currencies `asset` is denominated in. Registration is
/// checked first, so an unregistered asset need not implement `isoCode()` at all;
/// reference is matched first, so a single-currency gem takes the no-rate branch.
fn accept_payment_asset(
    storage: &StorageHandle<'_>,
    asset: Address,
    item: &outbe_gem::GemData,
) -> Result<PaymentCurrency> {
    let ret = storage.staticcall(
        VAULT_ROUTER_ADDRESS,
        IVaultRouter::assetVaultsCountCall { asset }
            .abi_encode()
            .into(),
    )?;
    let vaults = IVaultRouter::assetVaultsCountCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("assetVaultsCount undecodable".into()))?;
    if vaults.is_zero() {
        return Err(GemFactoryError::SettlementAssetNotRegistered { asset }.into());
    }

    let iso = asset_iso_code(storage, asset)?;
    if iso == item.reference_currency {
        return Ok(PaymentCurrency::Reference);
    }
    if iso == item.issuance_currency {
        return Ok(PaymentCurrency::Issuance);
    }
    Err(GemFactoryError::SettlementCurrencyMismatch { iso_code: iso }.into())
}

/// Cost of one gem in `asset`'s minor units. The reference rail needs no rate; the
/// issuance rail converts through COEN, decimals folded into the same division so
/// it rounds once. The rates cancel only because both legs are `COEN/<iso>` markets,
/// which the oracle quotes at six decimals and every other market at eighteen.
fn cost_in_token(
    storage: &StorageHandle<'_>,
    item: &outbe_gem::GemData,
    asset: Address,
    currency: PaymentCurrency,
) -> Result<U256> {
    let asset_decimals = read_decimals(storage, asset)?;
    let cost = gem_cost_minor(item)?;
    if currency == PaymentCurrency::Reference {
        return cost_to_payment_units(cost, U256::ONE, U256::ONE, asset_decimals);
    }

    let rate_issuance = fresh_coen_rate_for(storage.clone(), item.issuance_currency)?;
    let rate_reference = fresh_coen_rate_for(storage.clone(), item.reference_currency)?;
    cost_to_payment_units(cost, rate_issuance, rate_reference, asset_decimals)
}

/// The gem's cost in its reference currency, derived from the record: the same
/// `entry x load x rate` the issuance path computed, off the same stored inputs.
pub(crate) fn gem_cost_minor(item: &outbe_gem::GemData) -> Result<U256> {
    compute_cost(
        item.entry_price_minor,
        item.promis_load_minor,
        cost_rate(item.gem_type),
    )
}

/// Share of the full agent cost this gem type pays, in percent.
fn cost_rate(gem_type: u8) -> u64 {
    if gem_type == GemTypes::Sra as u8 {
        SRA_RATE
    } else {
        100
    }
}

/// Six-decimal cost into payment-token minor units, rounded up exactly once.
fn cost_to_payment_units(
    cost: U256,
    rate_numerator: U256,
    rate_denominator: U256,
    payment_decimals: u8,
) -> Result<U256> {
    const COST_DECIMALS: u32 = 6;
    const MAX_PAYMENT_DECIMALS: u8 = 18;

    if payment_decimals > MAX_PAYMENT_DECIMALS {
        return Err(GemFactoryError::UnsupportedPaymentDecimals(payment_decimals).into());
    }
    if rate_denominator.is_zero() {
        return Err(PrecompileError::Revert(
            "settlement rate denominator is zero".into(),
        ));
    }

    let mut numerator = cost
        .checked_mul(rate_numerator)
        .ok_or_else(|| PrecompileError::Revert("settlement conversion overflow".into()))?;
    let mut denominator = rate_denominator;
    let payment_decimals = u32::from(payment_decimals);
    if payment_decimals < COST_DECIMALS {
        denominator = denominator
            .checked_mul(U256::from(10u64).pow(U256::from(COST_DECIMALS - payment_decimals)))
            .ok_or_else(|| PrecompileError::Revert("settlement conversion overflow".into()))?;
    } else if payment_decimals > COST_DECIMALS {
        numerator = numerator
            .checked_mul(U256::from(10u64).pow(U256::from(payment_decimals - COST_DECIMALS)))
            .ok_or_else(|| PrecompileError::Revert("settlement conversion overflow".into()))?;
    }

    Ok(numerator.div_ceil(denominator))
}

/// Reads the settlement asset's ISO 4217 code via a static sub-call.
fn asset_iso_code(storage: &StorageHandle<'_>, asset: Address) -> Result<u16> {
    let ret = storage.staticcall(
        asset,
        IReferenceCurrency::isoCodeCall {}.abi_encode().into(),
    )?;
    IReferenceCurrency::isoCodeCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("isoCode undecodable".into()))
}

/// What settling `gem_id` with `asset` costs, and in which currency.
pub fn quote_settlement(
    storage: &StorageHandle<'_>,
    gem_id: U256,
    asset: Address,
) -> Result<(u16, U256)> {
    let item = gem_api::get_gem(storage, gem_id)?.ok_or(GemFactoryError::GemNotFound)?;
    let currency = accept_payment_asset(storage, asset, &item)?;
    let settlement_currency = match currency {
        PaymentCurrency::Reference => item.reference_currency,
        PaymentCurrency::Issuance => item.issuance_currency,
    };
    Ok((
        settlement_currency,
        cost_in_token(storage, &item, asset, currency)?,
    ))
}

/// The full terms of a parked position.
pub fn position_data(
    storage: &StorageHandle<'_>,
    position_id: U256,
) -> Result<crate::precompile::IGemFactory::PositionData> {
    let record = GemFactoryContract::new(storage.clone())
        .positions
        .get(position_id)?
        .ok_or(GemFactoryError::PositionNotFound)?;
    Ok(crate::precompile::IGemFactory::PositionData {
        positionId: record.position_id,
        merchant: record.merchant,
        sourceIntexId: record.source_intex_id.into(),
        remainingCapacity: record.remaining_capacity,
        sourceEntryPrice: record.source_entry_price,
        sourceFloorPrice: record.source_floor_price,
        issuanceCurrency: record.issuance_currency,
        referenceCurrency: record.reference_currency,
        parkedAt: record.parked_at,
        expiresAt: record.expires_at,
    })
}

pub fn mine_promis(
    storage: &StorageHandle<'_>,
    caller: Address,
    gem_id: U256,
    nonce: u64,
    auth: outbe_promisfactory::api::ModifyAuth,
) -> Result<U256> {
    let item = gem_api::get_gem(storage, gem_id)?.ok_or(GemFactoryError::GemNotFound)?;
    if item.owner != caller {
        return Err(GemFactoryError::NotGemOwner.into());
    }
    if item.state != GemState::Settled as u8 {
        return Err(GemFactoryError::InvalidState.into());
    }

    validate_pow(gem_id, nonce)?;

    gem_api::burn(storage, gem_id)?;

    // The Promis is confidential: the mint runs inside the enclave, authorized by
    // the gem owner's Promis modify key. The client's `mac`/`opNonce` must bind the
    // minted amount (`item.promis_load_minor`), so the client precomputes it.
    outbe_promisfactory::api::mint(storage.clone(), caller, item.promis_load_minor, auth)?;

    emit_event(
        storage,
        GemMined {
            gemId: gem_id,
            owner: caller,
            promisLoad: item.promis_load_minor,
        },
    )?;

    Ok(item.promis_load_minor)
}

/// Looks up the COEN/`reference_currency` rate via Oracle's derived pair
/// lookup. Propagates Oracle's typed missing/stale errors and maps an unusable
/// zero rate to `OracleUnavailable`.
fn read_reference_oracle_rate(
    storage: &StorageHandle<'_>,
    reference_currency: u16,
) -> Result<U256> {
    let rate = fresh_coen_rate_for(storage.clone(), reference_currency)?;
    if rate.is_zero() {
        return Err(GemFactoryError::OracleUnavailable.into());
    }
    Ok(rate)
}

fn compute_params(
    gem_type: GemTypes,
    promis_load: U256,
    coen_rate: U256,
    terms: &outbe_gem::GemParams,
) -> Result<(U256, GemState)> {
    // The cost is derived from the record on demand; it is computed here only to
    // reject a load whose cost rounds to zero.
    let (floor_price, initial_state) = match gem_type {
        // Genesis: validator gem during the genesis window - born Qualified
        // (no maturity wait), but validators pay like every other agent
        // class: cost = entry x load, floor = rate x 1.08. settleGem moves
        // the cost into the Reserve vault just like Wallet/Cca/Sra.
        GemTypes::Genesis => {
            compute_cost(coen_rate, promis_load, 100)?;
            (
                derived_floor(coen_rate, terms.floor_rate)?,
                GemState::Qualified,
            )
        }
        GemTypes::Sra => {
            compute_cost(coen_rate, promis_load, SRA_RATE)?;
            (
                derived_floor(coen_rate, terms.floor_rate)?,
                GemState::Issued,
            )
        }
        // Validator (post-genesis), Wallet, Cca - standard agent-class flow:
        // cost = entry x load, floor = rate x 1.08, born Issued.
        GemTypes::Validator | GemTypes::Wallet | GemTypes::Cca => {
            compute_cost(coen_rate, promis_load, 100)?;
            (
                derived_floor(coen_rate, terms.floor_rate)?,
                GemState::Issued,
            )
        }
        // Merchant gems are issued via `issue_merchant_gem` against a GemPosition,
        // not through this agent-class path.
        GemTypes::Merchant => return Err(GemFactoryError::UnsupportedGemType.into()),
    };
    Ok((floor_price, initial_state))
}

/// `floor(entry x load x percent / (100 x SCALE_1E6_U256))`. Entry, load and
/// result are six-decimal monetary values; the calculation rounds only once.
fn compute_cost(entry: U256, load: U256, cost_num: u64) -> Result<U256> {
    let numerator = entry
        .checked_mul(load)
        .ok_or(GemFactoryError::Overflow)?
        .checked_mul(U256::from(cost_num))
        .ok_or(GemFactoryError::Overflow)?;
    let denominator = SCALE_1E6_U256
        .checked_mul(U256::from(100u64))
        .ok_or(GemFactoryError::Overflow)?;
    let cost = numerator / denominator;
    if !entry.is_zero() && !load.is_zero() && cost.is_zero() {
        return Err(PrecompileError::Revert(
            "gem cost rounds to zero".to_owned(),
        ));
    }
    Ok(cost)
}

/// Floor price = `entry x (100 + FLOOR_RATE) / 100` (8% markup => 1.08x).
fn derived_floor(entry_price: U256, floor_rate: u16) -> Result<U256> {
    let acc = entry_price
        .checked_mul(U256::from(100 + u64::from(floor_rate)))
        .ok_or(GemFactoryError::Overflow)?;
    Ok(acc / U256::from(100u64))
}

/// Call price = `entry x (100 + CALL_RATE) / 100` (128% markup => 2.28x).
/// Entry equals the issuance-time coen rate in the single-currency case.
fn derived_call_price(entry_price: U256, call_rate: u16) -> Result<U256> {
    let acc = entry_price
        .checked_mul(U256::from(100 + u64::from(call_rate)))
        .ok_or(GemFactoryError::Overflow)?;
    Ok(acc / U256::from(100u64))
}

pub(crate) fn emit_event<E: SolEvent>(storage: &StorageHandle<'_>, event: E) -> Result<()> {
    storage.emit_event(GEM_FACTORY_ADDRESS, event.encode_log_data())
}

/// PoW gate for `mine_promis`, delegating to the shared
/// [`outbe_common::pow`] scheme and mapping failures onto [`GemFactoryError`].
pub fn validate_pow(gem_id: U256, nonce: u64) -> Result<()> {
    pow::validate_pow(gem_id, nonce).map_err(|e| GemFactoryError::from(e).into())
}
