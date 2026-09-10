//! Read-only, freeze-relative TEE lease renewal status.

use std::path::Path;

use eyre::Result;
use outbe_primitives::tee_attestation_v1::AttestationMode;
use serde::Serialize;

use crate::rpc::RenewalRpc;

use super::{
    registry::{read_finalized_bound_renewal_view_v1, NodeBindingSelectorV1},
    renewal_journal::inspect_journal,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RenewalAlertLevelV1 {
    Healthy,
    Warning,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalStatusV1 {
    pub alert: RenewalAlertLevelV1,
    pub finalized_height: u64,
    pub finalized_timestamp: u64,
    pub next_freeze_height: u64,
    pub forecast_freeze_timestamp: u64,
    pub blocks_until_freeze: u64,
    pub valid_until: u64,
    pub collateral_valid_until: Option<u64>,
    pub safe_for_next_freeze: bool,
    pub journal_state: Option<String>,
    pub journal_generation: Option<u64>,
}

/// Inspect status without creating the journal directory, lock or scratch file.
pub async fn read_renewal_status_v1(
    rpc: &(impl RenewalRpc + Sync),
    node_data_dir: &Path,
    selector: &NodeBindingSelectorV1,
    warning_blocks: u64,
    critical_blocks: u64,
) -> Result<RenewalStatusV1> {
    if critical_blocks > warning_blocks {
        eyre::bail!("critical renewal margin cannot exceed warning margin");
    }
    let view = read_finalized_bound_renewal_view_v1(rpc, selector).await?;
    let journal = inspect_journal(node_data_dir)?;
    let forecast_freeze_timestamp = view.schedule.forecast_freeze_timestamp();
    let blocks_until_freeze = view.schedule.blocks_until_freeze();
    let collateral_valid_until = match view.policy.attestation_mode {
        AttestationMode::DcapRequired => Some(view.binding.collateral_valid_until),
        AttestationMode::GramineDirectDev => None,
    };
    let safe_for_next_freeze = lease_is_safe_for_next_freeze(
        view.binding.valid_until,
        collateral_valid_until,
        forecast_freeze_timestamp,
    );
    let alert = classify_alert(
        safe_for_next_freeze,
        blocks_until_freeze,
        warning_blocks,
        critical_blocks,
    );
    Ok(RenewalStatusV1 {
        alert,
        finalized_height: view.schedule.finalized_height,
        finalized_timestamp: view.schedule.finalized_timestamp,
        next_freeze_height: view.schedule.next_freeze_height,
        forecast_freeze_timestamp,
        blocks_until_freeze,
        valid_until: view.binding.valid_until,
        collateral_valid_until,
        safe_for_next_freeze,
        journal_state: journal
            .as_ref()
            .map(|snapshot| snapshot.lifecycle.label().to_owned()),
        journal_generation: journal.map(|snapshot| snapshot.generation),
    })
}

fn lease_is_safe_for_next_freeze(
    valid_until: u64,
    collateral_valid_until: Option<u64>,
    forecast_freeze_timestamp: u64,
) -> bool {
    valid_until > forecast_freeze_timestamp
        && collateral_valid_until.is_none_or(|deadline| deadline > forecast_freeze_timestamp)
}

fn classify_alert(
    safe_for_next_freeze: bool,
    blocks_until_freeze: u64,
    warning_blocks: u64,
    critical_blocks: u64,
) -> RenewalAlertLevelV1 {
    if safe_for_next_freeze {
        RenewalAlertLevelV1::Healthy
    } else if blocks_until_freeze <= critical_blocks {
        RenewalAlertLevelV1::Critical
    } else if blocks_until_freeze <= warning_blocks {
        RenewalAlertLevelV1::Warning
    } else {
        RenewalAlertLevelV1::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_are_unsafe_and_freeze_relative() {
        assert_eq!(
            classify_alert(true, 0, 600, 120),
            RenewalAlertLevelV1::Healthy
        );
        assert_eq!(
            classify_alert(false, 601, 600, 120),
            RenewalAlertLevelV1::Healthy
        );
        assert_eq!(
            classify_alert(false, 600, 600, 120),
            RenewalAlertLevelV1::Warning
        );
        assert_eq!(
            classify_alert(false, 120, 600, 120),
            RenewalAlertLevelV1::Critical
        );
    }

    #[test]
    fn direct_dev_safety_has_no_fake_intel_collateral_deadline() {
        assert!(lease_is_safe_for_next_freeze(201, None, 200));
        assert!(!lease_is_safe_for_next_freeze(200, None, 200));
        assert!(lease_is_safe_for_next_freeze(201, Some(201), 200));
        assert!(!lease_is_safe_for_next_freeze(201, Some(200), 200));
    }
}
