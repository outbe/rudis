//! Finalized, read-only lifecycle schedule exposed to host operator tooling.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Exact finalized chain facts used for renewal scheduling and freeze-relative
/// alerts. This is an operator view, not a new consensus object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeeRenewalScheduleV1 {
    pub finalized_height: u64,
    pub finalized_hash: B256,
    pub finalized_timestamp: u64,
    pub epoch_number: u64,
    pub epoch_start_height: u64,
    pub epoch_length_blocks: u32,
    pub next_freeze_height: u64,
    pub planned_activation_height: u64,
    pub dkg_prepare_window_blocks: u64,
    pub minimum_block_time_millis: u64,
}

impl TeeRenewalScheduleV1 {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.finalized_hash.is_zero()
            || self.epoch_length_blocks == 0
            || self.minimum_block_time_millis == 0
        {
            return Err("renewal schedule contains a zero mandatory field");
        }
        let expected_activation = self
            .epoch_start_height
            .checked_add(u64::from(self.epoch_length_blocks))
            .ok_or("renewal schedule activation height overflow")?;
        if self.planned_activation_height != expected_activation {
            return Err("renewal schedule activation height is inconsistent");
        }
        let expected_freeze = expected_activation.saturating_sub(
            self.dkg_prepare_window_blocks
                .min(u64::from(self.epoch_length_blocks)),
        );
        if self.next_freeze_height != expected_freeze {
            return Err("renewal schedule freeze height is inconsistent");
        }
        Ok(self)
    }

    #[must_use]
    pub fn blocks_until_freeze(self) -> u64 {
        self.next_freeze_height
            .saturating_sub(self.finalized_height)
    }

    #[must_use]
    pub fn forecast_freeze_timestamp(self) -> u64 {
        let millis = self
            .blocks_until_freeze()
            .saturating_mul(self.minimum_block_time_millis);
        self.finalized_timestamp
            .saturating_add(millis.div_ceil(1_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_pins_activation_freeze_and_forecast() {
        let schedule = TeeRenewalScheduleV1 {
            finalized_height: 120,
            finalized_hash: B256::repeat_byte(1),
            finalized_timestamp: 1_000,
            epoch_number: 2,
            epoch_start_height: 100,
            epoch_length_blocks: 100,
            next_freeze_height: 180,
            planned_activation_height: 200,
            dkg_prepare_window_blocks: 20,
            minimum_block_time_millis: 2_000,
        }
        .validate()
        .unwrap();
        assert_eq!(schedule.blocks_until_freeze(), 60);
        assert_eq!(schedule.forecast_freeze_timestamp(), 1_120);
    }

    #[test]
    fn inconsistent_schedule_is_rejected() {
        let schedule = TeeRenewalScheduleV1 {
            finalized_height: 1,
            finalized_hash: B256::repeat_byte(1),
            finalized_timestamp: 1,
            epoch_number: 0,
            epoch_start_height: 1,
            epoch_length_blocks: 10,
            next_freeze_height: 8,
            planned_activation_height: 12,
            dkg_prepare_window_blocks: 3,
            minimum_block_time_millis: 1,
        };
        assert!(schedule.validate().is_err());
    }
}
