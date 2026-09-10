//! NodFactory runtime: issuance, PoW-gated mining, event emission.
//!
//! All persistent Nod state lives in the entity store at
//! [`outbe_primitives::addresses::NOD_ADDRESS`]. NodFactory mutates that
//! state exclusively through [`outbe_nod::api`] and emits its own events at
//! [`NOD_FACTORY_ADDRESS`].

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::NOD_FACTORY_ADDRESS;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use outbe_common::pow;
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_nod::api as nod_api;
use outbe_nod::api::{LoadedNodBucket, LoadedNodItem};
use outbe_nod::constants::CALL_NOTICE_PERIOD;
use outbe_nod::schema::{NodContract, NodIssueParams, NodItemState};

use crate::errors::NodFactoryError;
use crate::precompile::INodFactory;

/// Issues a Nod through the block-scoped compressed-body lifecycle.
pub fn issue_nod(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    params: &NodIssueParams,
) -> Result<WwdEntityId> {
    if params.owner.is_zero() {
        return Err(NodFactoryError::InvalidOwner.into());
    }

    let nod_id = NodContract::generate_nod_id(params.owner, params.worldwide_day)?;
    if nod_api::get_item(storage, scope, parent, nod_id)?.is_some() {
        return Err(NodFactoryError::NodAlreadyExists.into());
    }

    issue_nod_inner(storage, params, |item| {
        nod_api::add_nod(storage, scope, parent, item, params.entry_price_minor)
    })
}

fn issue_nod_inner(
    storage: &StorageHandle<'_>,
    params: &NodIssueParams,
    add: impl FnOnce(&NodItemState) -> Result<()>,
) -> Result<WwdEntityId> {
    let nod_id = NodContract::generate_nod_id(params.owner, params.worldwide_day)?;

    let bucket_key = NodContract::bucket_key(
        params.worldwide_day,
        params.floor_price_minor,
        params.reference_currency,
    );

    let issued_at = storage.timestamp()?.to::<u64>();

    let item = NodItemState {
        nod_id,
        owner: params.owner,
        gratis_load_minor: params.gratis_load_minor,
        worldwide_day: params.worldwide_day,
        league_id: params.league_id,
        floor_price_minor: params.floor_price_minor,
        bucket_key,
        issuance_currency: params.issuance_currency,
        reference_currency: params.reference_currency,
        issued_at,
    };
    add(&item)?;

    emit_event(
        storage,
        INodFactory::NodIssued {
            owner: params.owner,
            nodId: nod_id.to_u256(),
            worldwideDay: U256::from(u32::from(params.worldwide_day)),
            leagueId: U256::from(params.league_id),
            floorPriceMinor: params.floor_price_minor,
            gratisLoadMinor: params.gratis_load_minor,
            entryPriceMinor: params.entry_price_minor,
            costAmountMinor: nod_api::cost_amount_minor(
                params.entry_price_minor,
                params.gratis_load_minor,
            )?,
        },
    )?;

    Ok(nod_id)
}

/// One `mineGratis` command. Grouped rather than passed positionally because
/// `caller`, `nod_id`, and `nonce` are otherwise three adjacent opaque scalars.
pub struct MineGratisRequest<'proof> {
    pub caller: Address,
    pub nod_id: WwdEntityId,
    pub nonce: u64,
    pub auth: outbe_gratisfactory::api::ModifyAuth,
    /// Spend proof for the note discharging the Nod's cost.
    pub paynote_proof: &'proof [u8],
}

/// Atomic mine-gratis path: validate ownership + PoW + bucket qualification,
/// discharge the Nod's cost by spending a PayNote, burn the Nod (emitting
/// `NodBurned`), then delegate the matching gratis mint to `gratisfactory`
/// (which mints to the owner and records the Fidelity cohort; the
/// `GratisMinted` event is emitted by the Gratis token). Returns the minted
/// amount.
///
/// This path moves no value. The cost's underlying assets already reached the
/// reserve vault when the note was deposited through `IPayNote.deposit`, which
/// routes them under `StablesSource::PayNoteDeposit`. What happens here is the
/// proof obligation: `paynote_proof` must name `caller` as its spender, carry
/// the asset registered for the Nod's `reference_currency`, and cover the Nod's
/// cost.
pub fn mine_gratis(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    request: MineGratisRequest<'_>,
) -> Result<U256> {
    let MineGratisRequest {
        caller,
        nod_id,
        nonce,
        auth,
        paynote_proof,
    } = request;
    let item =
        nod_api::load_item(storage, scope, parent, nod_id)?.ok_or(NodFactoryError::NodNotFound)?;
    if NodContract::new(storage.clone())
        .ocomp_certified_generation(item.body().worldwide_day)?
        .is_some_and(|generation| generation.next_nod_ordinal < generation.nod_count)
    {
        return Err(NodFactoryError::NodGenerationNotMaterialized.into());
    }
    let bucket_id =
        WwdEntityId::from_day_and_digest(item.body().worldwide_day, item.body().bucket_key.0);
    let bucket = nod_api::load_bucket(storage, scope, parent, bucket_id)?
        .ok_or(NodFactoryError::NodNotQualified)?;
    storage.clone().with_checkpoint(|| {
        mine_gratis_inner(
            storage,
            MineGratisInput {
                caller,
                nod_id,
                nonce,
                item,
                bucket,
                auth,
                paynote_proof,
            },
            scope,
        )
    })
}

struct MineGratisInput<'proof> {
    caller: Address,
    nod_id: WwdEntityId,
    nonce: u64,
    item: LoadedNodItem,
    bucket: LoadedNodBucket,
    auth: outbe_gratisfactory::api::ModifyAuth,
    paynote_proof: &'proof [u8],
}

fn mine_gratis_inner(
    storage: &StorageHandle<'_>,
    input: MineGratisInput<'_>,
    scope: &ExecutionScope,
) -> Result<U256> {
    let MineGratisInput {
        caller,
        nod_id,
        nonce,
        item,
        bucket,
        auth,
        paynote_proof,
    } = input;
    if caller != item.body().owner {
        return Err(NodFactoryError::NotOwner.into());
    }

    validate_pow(nod_id, nonce)?;

    if !bucket.body().is_qualified {
        return Err(NodFactoryError::NodNotQualified.into());
    }

    // Mining stays open during the notice period - that is what the notice is
    // for. Past it the Nod is forfeit, and this check closes the gap before the
    // daily sweep reaches it.
    let called_at = NodContract::new(storage.clone())
        .bucket_called_at
        .read(&item.body().bucket_key)?;
    let now = storage.timestamp()?.to::<u64>();
    if called_at != 0 && now > called_at.saturating_add(CALL_NOTICE_PERIOD) {
        return Err(NodFactoryError::CallDeadlineExpired.into());
    }

    let paid = discharge_cost(
        storage,
        item.body(),
        bucket.body().entry_price_minor,
        caller,
        paynote_proof,
    )?;

    let owner = item.body().owner;
    let gratis_load_minor = item.body().gratis_load_minor;
    nod_api::remove_nod(storage, scope, item, bucket)?;

    emit_event(
        storage,
        INodFactory::NodPaid {
            owner,
            nodId: nod_id.to_u256(),
            asset: paid.asset,
            nullifier: paid.nullifier,
            amountCovered: paid.spend_amount,
        },
    )?;

    emit_event(
        storage,
        INodFactory::NodBurned {
            owner: caller,
            nodId: nod_id.to_u256(),
            gratisLoadMinor: gratis_load_minor,
        },
    )?;

    outbe_gratisfactory::api::mint(storage.clone(), owner, gratis_load_minor, auth)?;

    Ok(gratis_load_minor)
}

/// One discharged Nod cost, as it is reported by `NodPaid`.
struct PaidCost {
    asset: Address,
    nullifier: B256,
    spend_amount: U256,
}

/// Discharges `item`'s cost by spending one PayNote.
///
/// The proof is the payment. `consume` books its nullifier before returning, so
/// the note cannot be spent twice; running inside the caller's checkpoint means
/// a later failure un-books it. It is called last, after the cheap
/// owner/PoW/qualification guards, so a doomed mine never pays for
/// verification.
fn discharge_cost(
    storage: &StorageHandle<'_>,
    item: &NodItemState,
    entry_price_minor: U256,
    caller: Address,
    paynote_proof: &[u8],
) -> Result<PaidCost> {
    let cost = nod_api::cost_amount_minor(entry_price_minor, item.gratis_load_minor)?;

    let claim = outbe_paynote::api::consume(storage, paynote_proof)?;

    // PayNote notes are bearer instruments: the proof names its own spender and
    // anyone can relay it. Binding that spender to the caller is what stops an
    // observer from lifting a broadcast proof to pay for their own Nod.
    if claim.spender != caller {
        return Err(NodFactoryError::PayNoteSpenderMismatch {
            expected: caller,
            actual: claim.spender,
        }
        .into());
    }
    check_settlement_asset(storage, item.reference_currency, claim.asset)?;
    if claim.spend_amount != cost {
        return Err(NodFactoryError::PayNoteCostMismatch {
            covered: claim.spend_amount,
            required: cost,
        }
        .into());
    }

    Ok(PaidCost {
        asset: claim.asset,
        nullifier: claim.nullifier,
        spend_amount: claim.spend_amount,
    })
}

/// Rejects a note whose asset the vault router does not register under
/// `reference_currency`.
///
/// The cost is denominated in the Nod's own reference currency, so any asset
/// registered under it settles the Nod: the registry lists interchangeable
/// alternatives, not a preference, and the payer picks which one their note
/// carries. An empty registry is a configuration error, not a payer one.
fn check_settlement_asset(
    storage: &StorageHandle<'_>,
    reference_currency: u16,
    asset: Address,
) -> Result<()> {
    let registered =
        outbe_vaultrouter::api::reference_currency_assets(storage, reference_currency)?;
    if !registered.contains(&asset) {
        return Err(NodFactoryError::PayNoteAssetMismatch {
            asset,
            reference_currency,
        }
        .into());
    }
    Ok(())
}

/// PoW gate for `mine_gratis`, delegating to the shared [`outbe_common::pow`]
/// scheme and mapping failures onto [`NodFactoryError`].
pub fn validate_pow(nod_id: WwdEntityId, nonce: u64) -> Result<()> {
    pow::validate_pow(nod_id.to_u256(), nonce).map_err(|e| NodFactoryError::from(e).into())
}

/// Shared PoW hash over `nod_id.to_be_bytes::<32>() || nonce.to_be_bytes()`.
pub fn compute_pow_hash(nod_id: WwdEntityId, nonce: u64) -> [u8; 32] {
    pow::compute_pow_hash(nod_id.to_u256(), nonce)
}

fn emit_event<E: SolEvent>(storage: &StorageHandle<'_>, event: E) -> Result<()> {
    storage.emit_event(NOD_FACTORY_ADDRESS, event.encode_log_data())
}
