use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::{
    aggregate::{ValidatedWwdAggregate, WwdMembership, WwdProjection, WwdStatus},
    ocomp::schema::poc_schema_limits,
    schema::MetadosisContract,
};

pub use crate::aggregate::{WwdDayType, WwdStatus as WorldwideDayStatus};
pub use crate::ocomp::activation::{OcompFinalityAuthorityError, OcompFinalizedIntentAuthority};
pub use crate::pre_admission::MetadosisPreAdmissionProjection;
pub use crate::state::DayLimitFormationReceipt;
pub use crate::terminal::{CapacityForfeitureReceipt, MissedOfferingReceipt};

/// Reads one typed WWD projection without exposing its storage facade.
pub fn worldwide_day(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<Option<WwdProjection>> {
    let contract = MetadosisContract::new(storage);
    let Some(record) = contract.worldwide_days.get(wwd)? else {
        return Ok(None);
    };
    let active = contract.active_wwd.read_all()?.contains(&wwd);
    let closed = contract.closed_wwd.read_all()?.contains(&wwd);
    let membership = match (active, closed) {
        (true, false) => WwdMembership::Active,
        (false, true) => WwdMembership::Closed,
        _ => {
            return Err(crate::errors::storage_corruption(
                "Metadosis WWD membership is not exactly one of active/closed".into(),
            ))
        }
    };
    let status = WwdStatus::try_from(record.status)?;
    let day_type = record.day_type.try_into()?;
    Ok(Some(WwdProjection::from_record(
        wwd, status, day_type, membership, &record,
    )))
}

/// Reads the complete bounded typed WWD aggregate without exposing indexes or
/// storage entries. The result is sorted by WorldwideDay.
pub fn worldwide_days(storage: StorageHandle<'_>) -> Result<Vec<WwdProjection>> {
    Ok(ValidatedWwdAggregate::load_and_validate(storage)?
        .records()
        .copied()
        .collect())
}

/// Typed query used by TributeFactory instead of a raw status byte read.
pub fn is_offering_day(storage: StorageHandle<'_>, wwd: WorldwideDay) -> Result<bool> {
    Ok(worldwide_day(storage, wwd)?
        .is_some_and(|projection| projection.status == WwdStatus::Offering))
}

/// Returns indexed OFFERING days as typed keys without exposing status bytes or
/// the storage facade.
pub fn offering_worldwide_days(storage: StorageHandle<'_>) -> Result<Vec<WorldwideDay>> {
    let contract = MetadosisContract::new(storage);
    let mut result = Vec::new();
    for wwd in contract.active_wwd.read_all()? {
        let record = contract.worldwide_days.get(wwd)?.ok_or_else(|| {
            crate::errors::storage_corruption(
                "Metadosis active index points to a missing WWD".into(),
            )
        })?;
        if WwdStatus::try_from(record.status)? == WwdStatus::Offering {
            result.push(wwd);
        }
    }
    result.sort();
    Ok(result)
}

/// True only when a canonical active OCOMP request profile is persisted.
pub fn has_active_ocomp_profile(storage: StorageHandle<'_>) -> Result<bool> {
    MetadosisContract::new(storage)
        .read_ocomp_request_profile(&poc_schema_limits())
        .map(|profile| profile.is_some())
}

/// True only when the complete immutable fork installation matches `install`.
/// This semantic predicate keeps callers away from the storage facade while
/// still allowing production-route persistence checks to verify both halves of
/// the authority atomically.
pub fn is_active_ocomp_fork_install(
    storage: StorageHandle<'_>,
    install: &crate::config::OcompForkInstallV1,
) -> Result<bool> {
    let contract = MetadosisContract::new(storage);
    let limits = poc_schema_limits();
    let profile = contract.read_ocomp_request_profile(&limits)?;
    let authority = contract.read_ocomp_activation_authority(&limits)?;
    Ok(profile.as_ref() == Some(&install.request_profile)
        && authority.is_some_and(|authority| authority.bundle == install.protocol_bundle))
}

/// Reads the durable Metadosis-owned semantic result for one Cycle day-limit
/// formation slot.
pub fn day_limit_formation_receipt(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<Option<DayLimitFormationReceipt>> {
    MetadosisContract::new(storage).day_limit_formation_receipt(wwd)
}

/// Reads the typed durable missed-offering result for one terminal WWD.
pub fn missed_offering_receipt(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<Option<MissedOfferingReceipt>> {
    MetadosisContract::new(storage).read_missed_offering_receipt(wwd)
}

/// Reads the typed durable capacity-forfeiture result for one terminal WWD.
pub fn capacity_forfeiture_receipt(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<Option<CapacityForfeitureReceipt>> {
    MetadosisContract::new(storage).read_capacity_forfeiture_receipt(wwd)
}

pub fn pre_admission_projection(
    storage: StorageHandle<'_>,
    wwd: WorldwideDay,
) -> Result<MetadosisPreAdmissionProjection> {
    MetadosisContract::new(storage).ocomp_pre_admission_projection(wwd)
}

pub use crate::ocomp::views::{
    get_active_lysis_generation, get_lysis_terminal_receipt, get_offchain_job,
    get_offchain_vote_accountability,
};
