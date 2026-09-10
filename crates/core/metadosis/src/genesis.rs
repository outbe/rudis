//! Typed fresh-devnet genesis adaptation for cross-crate test harnesses.
//!
//! The builder is feature-gated, accepts only invariant-valid named operations,
//! and refuses to run after block 1. It exposes no schema entry, slot, provider,
//! mutation permit, or arbitrary callback.

use alloy_primitives::U256;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::{
    aggregate::{ValidatedWwdAggregate, WwdDayType, WwdStatus},
    errors::storage_corruption_message,
    schema::{status, MetadosisContract, WorldwideDay as WorldwideDayRecord},
};

/// One invariant-valid active WWD included in a fresh-devnet genesis artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisWorldwideDay {
    pub worldwide_day: WorldwideDay,
    pub status: WwdStatus,
    pub day_type: WwdDayType,
    pub forming_start: u64,
    pub forming_end: u64,
    pub lookback_end: u64,
    pub offering_end: u64,
    pub scheduled_process_time: u64,
    pub metadosis_limit_amount: U256,
    pub previous_vwap: U256,
    pub current_vwap: U256,
}

impl GenesisWorldwideDay {
    fn validate(self) -> Result<Self> {
        if !self.worldwide_day.is_valid() {
            return Err(storage_corruption_message(
                "fresh-devnet genesis WWD is not a valid calendar day",
            ));
        }
        if !matches!(self.status, WwdStatus::Offering | WwdStatus::Ready) {
            return Err(storage_corruption_message(
                "fresh-devnet genesis builder only accepts OFFERING or READY predecessors",
            ));
        }
        if self.day_type == WwdDayType::Unknown {
            return Err(storage_corruption_message(
                "fresh-devnet genesis WWD requires a known day type",
            ));
        }
        if !(self.forming_start <= self.forming_end
            && self.forming_end <= self.lookback_end
            && self.lookback_end <= self.offering_end
            && self.offering_end <= self.scheduled_process_time)
        {
            return Err(storage_corruption_message(
                "fresh-devnet genesis WWD phase order is invalid",
            ));
        }
        Ok(self)
    }
}

enum GenesisOperation {
    SeedActive(GenesisWorldwideDay),
    RetimeOffering {
        worldwide_day: WorldwideDay,
        offering_end: u64,
    },
    ClearSingleOffering {
        expected_worldwide_day: WorldwideDay,
    },
}

/// Ordered typed mutations applied while constructing a fresh-devnet genesis.
#[derive(Default)]
pub struct FreshDevnetGenesisBuilder {
    operations: Vec<GenesisOperation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshDevnetGenesisReport {
    pub changed: bool,
}

impl FreshDevnetGenesisBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn seed_active_worldwide_day(mut self, day: GenesisWorldwideDay) -> Self {
        self.operations.push(GenesisOperation::SeedActive(day));
        self
    }

    #[must_use]
    pub fn retime_offering_day(mut self, worldwide_day: WorldwideDay, offering_end: u64) -> Self {
        self.operations.push(GenesisOperation::RetimeOffering {
            worldwide_day,
            offering_end,
        });
        self
    }

    #[must_use]
    pub fn clear_single_offering_day(mut self, expected_worldwide_day: WorldwideDay) -> Self {
        self.operations.push(GenesisOperation::ClearSingleOffering {
            expected_worldwide_day,
        });
        self
    }

    pub fn apply(self, storage: StorageHandle<'_>) -> Result<FreshDevnetGenesisReport> {
        if storage.block_number()? > 1 {
            return Err(storage_corruption_message(
                "fresh-devnet genesis builder cannot run after the pre-launch boundary",
            ));
        }
        let mut changed = false;
        let contract = MetadosisContract::new(storage.clone());
        for operation in self.operations {
            match operation {
                GenesisOperation::SeedActive(day) => {
                    let day = day.validate()?;
                    if contract.worldwide_days.get(day.worldwide_day)?.is_some() {
                        return Err(storage_corruption_message(
                            "fresh-devnet genesis WWD already exists",
                        ));
                    }
                    contract.worldwide_days.create(&WorldwideDayRecord {
                        wwd: day.worldwide_day,
                        status: status_tag(day.status),
                        day_type: day.day_type.as_u8(),
                        forming_start: day.forming_start,
                        forming_end: day.forming_end,
                        lookback_end: day.lookback_end,
                        offering_end: day.offering_end,
                        scheduled_process_time: day.scheduled_process_time,
                        metadosis_limit_amount: day.metadosis_limit_amount,
                        previous_vwap: day.previous_vwap,
                        current_vwap: day.current_vwap,
                    })?;
                    contract.active_wwd.insert(day.worldwide_day)?;
                    changed = true;
                }
                GenesisOperation::RetimeOffering {
                    worldwide_day,
                    offering_end,
                } => {
                    let mut day = contract.worldwide_days.get(worldwide_day)?.ok_or_else(|| {
                        storage_corruption_message("fresh-devnet offering WWD is missing")
                    })?;
                    if WwdStatus::try_from(day.status)? != WwdStatus::Offering {
                        return Err(storage_corruption_message(
                            "fresh-devnet WWD is not in OFFERING",
                        ));
                    }
                    if day.forming_end > offering_end || day.lookback_end > offering_end {
                        return Err(storage_corruption_message(
                            "fresh-devnet WWD phases end after the requested offering deadline",
                        ));
                    }
                    let operation_changed = day.offering_end != offering_end
                        || day.scheduled_process_time != offering_end;
                    day.offering_end = offering_end;
                    day.scheduled_process_time = offering_end;
                    contract.worldwide_days.update(&day)?;
                    changed |= operation_changed;
                }
                GenesisOperation::ClearSingleOffering {
                    expected_worldwide_day,
                } => {
                    let active = contract.active_wwd.read_all()?;
                    if active.len() > 1
                        || active
                            .first()
                            .is_some_and(|day| *day != expected_worldwide_day)
                    {
                        return Err(storage_corruption_message(
                            "fresh-devnet genesis contains an unexpected active WWD",
                        ));
                    }
                    let Some(day) = contract.worldwide_days.get(expected_worldwide_day)? else {
                        if active.is_empty() {
                            continue;
                        }
                        return Err(storage_corruption_message(
                            "fresh-devnet active WWD record is missing",
                        ));
                    };
                    if WwdStatus::try_from(day.status)? != WwdStatus::Offering {
                        return Err(storage_corruption_message(
                            "fresh-devnet seeded WWD is not in OFFERING",
                        ));
                    }
                    if !active.is_empty() {
                        contract.active_wwd.remove(&expected_worldwide_day)?;
                    }
                    contract.worldwide_days.delete(expected_worldwide_day)?;
                    changed = true;
                }
            }
            ValidatedWwdAggregate::load_and_validate(storage.clone())?;
        }
        Ok(FreshDevnetGenesisReport { changed })
    }
}

const fn status_tag(value: WwdStatus) -> u8 {
    match value {
        WwdStatus::Forming => status::FORMING,
        WwdStatus::LookbackDelay => status::LOOKBACK_DELAY,
        WwdStatus::Offering => status::OFFERING,
        WwdStatus::Waiting => status::WAITING,
        WwdStatus::Ready => status::READY,
        WwdStatus::OffchainPending => status::OFFCHAIN_PENDING,
        WwdStatus::Completed => status::COMPLETED,
        WwdStatus::Failed => status::FAILED,
    }
}

#[cfg(test)]
mod tests {
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

    use super::*;
    use crate::{aggregate::WwdMembership, api};

    const DAY: WorldwideDay = WorldwideDay::new(20_260_731);

    fn offering_day() -> GenesisWorldwideDay {
        GenesisWorldwideDay {
            worldwide_day: DAY,
            status: WwdStatus::Offering,
            day_type: WwdDayType::Green,
            forming_start: 10,
            forming_end: 20,
            lookback_end: 30,
            offering_end: 40,
            scheduled_process_time: 40,
            metadosis_limit_amount: U256::from(100),
            previous_vwap: U256::from(8),
            current_vwap: U256::from(9),
        }
    }

    #[test]
    fn seed_retime_and_clear_preserve_the_typed_aggregate() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.set_block_number(1);

        StorageHandle::enter(&mut provider, |storage| {
            let report = FreshDevnetGenesisBuilder::new()
                .seed_active_worldwide_day(offering_day())
                .retime_offering_day(DAY, 35)
                .apply(storage.clone())
                .unwrap();
            assert!(report.changed);

            let projection = api::worldwide_day(storage.clone(), DAY).unwrap().unwrap();
            assert_eq!(projection.status, WwdStatus::Offering);
            assert_eq!(projection.membership, WwdMembership::Active);
            assert_eq!(projection.offering_end, 35);
            assert_eq!(projection.scheduled_process_time, 35);

            let report = FreshDevnetGenesisBuilder::new()
                .clear_single_offering_day(DAY)
                .apply(storage.clone())
                .unwrap();
            assert!(report.changed);
            assert!(api::worldwide_days(storage).unwrap().is_empty());
        });
    }

    #[test]
    fn rejects_post_launch_and_invalid_predecessors() {
        let mut post_launch = HashMapStorageProvider::new(1);
        post_launch.set_block_number(2);
        let error = StorageHandle::enter(&mut post_launch, |storage| {
            FreshDevnetGenesisBuilder::new()
                .seed_active_worldwide_day(offering_day())
                .apply(storage)
                .unwrap_err()
        });
        assert!(matches!(
            error,
            outbe_primitives::error::PrecompileError::Fatal(_)
        ));
        assert!(post_launch.storage.is_empty());

        let mut invalid = offering_day();
        invalid.status = WwdStatus::Completed;
        let mut provider = HashMapStorageProvider::new(1);
        let error = StorageHandle::enter(&mut provider, |storage| {
            FreshDevnetGenesisBuilder::new()
                .seed_active_worldwide_day(invalid)
                .apply(storage)
                .unwrap_err()
        });
        assert!(matches!(
            error,
            outbe_primitives::error::PrecompileError::Fatal(_)
        ));
        assert!(provider.storage.is_empty());
    }

    #[test]
    fn clear_refuses_an_unexpected_active_day() {
        let unexpected = WorldwideDay::new(20_260_730);
        let mut day = offering_day();
        day.worldwide_day = unexpected;
        let mut provider = HashMapStorageProvider::new(1);

        StorageHandle::enter(&mut provider, |storage| {
            FreshDevnetGenesisBuilder::new()
                .seed_active_worldwide_day(day)
                .apply(storage.clone())
                .unwrap();
            let error = FreshDevnetGenesisBuilder::new()
                .clear_single_offering_day(DAY)
                .apply(storage.clone())
                .unwrap_err();
            assert!(matches!(
                error,
                outbe_primitives::error::PrecompileError::Fatal(_)
            ));
            assert_eq!(api::worldwide_days(storage).unwrap().len(), 1);
        });
    }
}
