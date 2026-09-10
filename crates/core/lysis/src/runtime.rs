use crate::program_v1::{self, ProgramErrorV1, TributeInputV1};
use alloy_primitives::U256;
use outbe_compressed_entities::{
    list, ExecutionScope, IdPageRequest, ParentBodySource, QueryRef, WwdEntityId, MAX_ID_PAGE_LIMIT,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::StorageHandle,
};

/// Result of a lysis execution.
pub struct LysisResult {
    pub nod_ids: Vec<WwdEntityId>,
    pub tribute_ids: Vec<WwdEntityId>,
    pub remaining_gratis: U256,
}

/// Executes lysis for a given worldwide day with the specified gratis allocation.
///
/// All arithmetic uses integer fixed-point math (no f32/f64).
///
/// 1. Loads all tributes for the day
/// 2. Groups by fidelity index
/// 3. Runs the distribution algorithm (fixed-point)
/// 4. Creates NODs for each tribute
/// 5. Leaves gratis unminted until a later NOD mine step
/// 6. Deletes processed tributes and clears the day index
pub fn lysis(
    storage: StorageHandle,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    wwd: WorldwideDay,
    gratis_allocation: U256,
) -> Result<LysisResult> {
    storage
        .clone()
        .with_checkpoint(|| lysis_inner(storage, scope, parent, wwd, gratis_allocation))
}

fn lysis_inner(
    storage: StorageHandle,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    wwd: WorldwideDay,
    gratis_allocation: U256,
) -> Result<LysisResult> {
    let mut tribute_contract = outbe_tribute::TributeContract::new(storage.clone());
    let mut tributes = load_day_tributes(storage.clone(), scope, parent, wwd)?;
    if tributes.is_empty() {
        return Ok(LysisResult {
            nod_ids: vec![],
            tribute_ids: vec![],
            remaining_gratis: gratis_allocation,
        });
    }

    tributes.sort_by_key(|loaded| loaded.body().tribute_id);

    let mut tribute_inputs = Vec::with_capacity(tributes.len());
    let mut first_leagues = Vec::with_capacity(tributes.len());
    let mut observed_total = U256::ZERO;
    for (ordinal, loaded) in tributes.iter().enumerate() {
        let tribute = loaded.body();
        first_leagues.push(outbe_fidelity::api::league(storage.clone(), tribute.owner)?);
        observed_total =
            program_v1::checked_nominal_step(observed_total, tribute.nominal_amount_minor, ordinal)
                .map_err(program_error)?;
        tribute_inputs.push(TributeInputV1 {
            tribute_id: tribute.tribute_id,
            owner: tribute.owner,
            worldwide_day: tribute.worldwide_day,
            issuance_currency: tribute.issuance_currency,
            nominal_amount_minor: tribute.nominal_amount_minor,
            reference_currency: tribute.reference_currency,
            tribute_price_minor: tribute.tribute_price_minor,
            exclude_from_intex_issuance: tribute.exclude_from_intex_issuance,
        });
    }
    let prepared = program_v1::prepare(
        wwd,
        tribute_inputs,
        first_leagues,
        gratis_allocation,
        storage.timestamp()?.to::<u64>(),
    )
    .map_err(program_error)?;
    let entry_price_minor_840 = resolve_entry_price_minor(storage.clone(), wwd, 840)?;
    let mut execution = prepared
        .start(entry_price_minor_840)
        .map_err(program_error)?;

    let mut nod_ids = Vec::with_capacity(tributes.len());
    for loaded in &tributes {
        let tribute = loaded.body();
        let pending = execution.quote_next().map_err(program_error)?;

        let entry_price_minor = match tribute.reference_currency {
            840 => entry_price_minor_840,
            currency => resolve_entry_price_minor(storage.clone(), wwd, currency)?,
        };
        let league_id = outbe_fidelity::api::league(storage.clone(), tribute.owner)?;
        let action = execution
            .commit_next(pending, entry_price_minor, league_id, true)
            .map_err(program_error)?;
        let nod_id = outbe_nodfactory::api::issue_nod(
            &storage,
            scope,
            parent,
            &outbe_nod::NodIssueParams {
                owner: action.owner,
                worldwide_day: action.worldwide_day,
                league_id: action.league_id,
                floor_price_minor: action.floor_price_minor,
                gratis_load_minor: action.gratis_load_minor,
                entry_price_minor: action.entry_price_minor,
                issuance_currency: action.issuance_currency,
                reference_currency: action.reference_currency,
            },
        )?;
        if nod_id != action.nod_id {
            return Err(PrecompileError::BodyReadCorruption(
                "Lysis V1 Nod identity differs from the semantic action".into(),
            ));
        }
        nod_ids.push(nod_id);
    }

    let result = execution.finish().map_err(program_error)?;
    if result.total_nominal != observed_total {
        return Err(PrecompileError::BodyReadCorruption(
            "Lysis V1 adapter observed total differs from the semantic result".into(),
        ));
    }
    let list = result
        .contributors
        .iter()
        .map(|contributor| (contributor.owner, contributor.nominal_amount_minor))
        .collect::<Vec<_>>();
    outbe_intex::api::record_contributors(&storage, wwd, &list)?;
    tribute_contract.consume_lysis_partition(
        wwd,
        u32::try_from(tributes.len()).map_err(|_| {
            PrecompileError::BodyReadCorruption("Tribute count exceeds u32 during Lysis".into())
        })?,
        result.total_nominal,
    )?;

    Ok(LysisResult {
        nod_ids,
        tribute_ids: result.tribute_ids,
        remaining_gratis: result.remaining_gratis,
    })
}

#[cfg(test)]
pub(crate) fn consume_required_gratis(remaining: &mut U256, gratis_load: U256) -> Result<()> {
    *remaining =
        program_v1::validate_required_gratis(*remaining, gratis_load, 0).map_err(program_error)?;
    Ok(())
}

fn load_day_tributes(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    wwd: WorldwideDay,
) -> Result<Vec<outbe_tribute::LoadedTribute>> {
    let mut records = Vec::new();
    let mut after = None;
    loop {
        let page = list(
            storage.clone(),
            scope,
            parent,
            QueryRef::TributeByDay(wwd),
            IdPageRequest {
                after,
                limit: MAX_ID_PAGE_LIMIT,
            },
        )?;
        let next_after = page.next_after();
        let bodies = page.into_bodies();
        records.extend(
            bodies
                .into_iter()
                .map(outbe_tribute::LoadedTribute::from_verified)
                .collect::<Result<Vec<_>>>()?,
        );
        let Some(next) = next_after else {
            return Ok(records);
        };
        after = Some(next);
    }
}

/// Computes the FI -> gratis-fraction map (fixed-point, SCALE = 10^6) from each
/// tribute's nominal amount and fidelity index. Pure integer math; deterministic
/// across nodes.
///
/// `nominal_amounts` and `tribute_fis` are index-aligned: entry `i` is the
/// nominal interest and fidelity index of the same tribute. `total_interest` is
/// the sum of all `nominal_amounts` (precomputed by the caller).
#[cfg(test)]
pub(crate) fn compute_fi_fraction_map(
    nominal_amounts: &[U256],
    tribute_fis: &[u16],
    total_interest: U256,
    gratis_allocation: U256,
) -> Result<std::collections::HashMap<u16, U256>> {
    program_v1::compute_fraction_hash_map(
        nominal_amounts,
        tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .map_err(program_error)
}

fn program_error(error: ProgramErrorV1) -> PrecompileError {
    PrecompileError::BodyReadCorruption(error.to_string())
}

fn resolve_entry_price_minor(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
    iso_code: u16,
) -> Result<U256> {
    let (_, index) = outbe_oracle::api::require_coen_pair(storage.clone(), iso_code)?;
    let vwap = outbe_oracle::api::get_worldwide_day_vwap_for_pair(storage, worldwide_day, index)?
        .unwrap_or(U256::ZERO);
    if vwap.is_zero() {
        return Err(PrecompileError::Revert(
            "Lysis WWD VWAP is missing or zero for this reference currency".into(),
        ));
    }
    Ok(vwap)
}

#[cfg(test)]
pub(crate) fn resolve_entry_price_minor_for_test(
    storage: StorageHandle,
    worldwide_day: WorldwideDay,
    iso_code: u16,
) -> Result<U256> {
    resolve_entry_price_minor(storage, worldwide_day, iso_code)
}
