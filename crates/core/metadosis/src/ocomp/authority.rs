use alloy_primitives::B256;
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::{errors::storage_corruption_message, schema::MetadosisContract};

use super::{
    activation::validate_activation_authority,
    profile::{poc_schema_limits, OcompRequestProfile},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OcompAttemptSnapshotBinding {
    pub(crate) validator_set_epoch: u64,
    pub(crate) committee_set_hash: B256,
    pub(crate) ocomp_binding_hash: B256,
    pub(crate) member_count: u16,
    pub(crate) quorum_threshold: u16,
}

pub(crate) fn current_ocomp_attempt_snapshot(
    storage: StorageHandle<'_>,
) -> Result<OcompAttemptSnapshotBinding> {
    let validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
    let validator_set_epoch = validators.current_epoch_u64()?;
    let (_, extension) =
        outbe_validatorset::read_ocomp_snapshot_extension_at_epoch(storage, validator_set_epoch)?
            .ok_or_else(|| {
            storage_corruption_message(
                "current ValidatorSet OCOMP snapshot is missing or inconsistent",
            )
        })?;
    if extension.member_count == 0 {
        return Err(storage_corruption_message(
            "current ValidatorSet OCOMP snapshot is empty",
        ));
    }
    let quorum_threshold =
        outbe_consensus::proof::simplex_n3f1_quorum(usize::from(extension.member_count))
            .try_into()
            .map_err(|_| storage_corruption_message("current ValidatorSet quorum exceeds u16"))?;
    Ok(OcompAttemptSnapshotBinding {
        validator_set_epoch,
        committee_set_hash: extension.committee_set_hash,
        ocomp_binding_hash: extension.ocomp_binding_hash,
        member_count: extension.member_count,
        quorum_threshold,
    })
}

pub(crate) fn require_current_ocomp_attempt_snapshot(
    storage: StorageHandle<'_>,
    intent: &outbe_ocomp_protocol::intent::JobIntentV1,
) -> Result<()> {
    let expected = current_ocomp_attempt_snapshot(storage)?;
    if intent.result_validator_set_epoch != expected.validator_set_epoch
        || intent.result_committee_set_hash != expected.committee_set_hash
        || intent.result_ocomp_binding_hash != expected.ocomp_binding_hash
        || intent.result_member_count != expected.member_count
        || intent.result_quorum_threshold != expected.quorum_threshold
    {
        return Err(storage_corruption_message(
            "OCOMP intent membership differs from the current ValidatorSet snapshot",
        ));
    }
    Ok(())
}

pub(crate) fn require_active_ocomp_profile(
    metadosis: &MetadosisContract<'_>,
) -> Result<OcompRequestProfile> {
    let limits = poc_schema_limits();
    let profile = metadosis
        .read_ocomp_request_profile(&limits)?
        .ok_or_else(|| {
            storage_corruption_message(
                "fresh-devnet Metadosis requires a genesis-active OCOMP profile",
            )
        })?;
    let authority = metadosis
        .read_ocomp_activation_authority(&limits)?
        .ok_or_else(|| {
            storage_corruption_message(
                "fresh-devnet Metadosis requires complete OCOMP activation authority",
            )
        })?;
    validate_activation_authority(&profile, &authority.bundle, &limits)?;
    Ok(profile)
}
