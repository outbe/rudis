//! DKG boundary-resolution tests for `Mailbox::resolve_boundary`.
//!
//! These exercise the parent-ancestry scan and its process-local
//! boundary-status cache. They moved here with the production logic (previously
//! `resolve_boundary_requirement` in `application::handler`). As a descendant
//! module of `dkg_manager`, they can drive the private cache methods directly.

use alloy_primitives::B256;
use commonware_consensus::types::Epoch;
use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact;

use crate::dkg_manager::{self, BoundaryRequirement, Mailbox as DkgManagerMailbox};
use crate::test_fixtures::{
    block_with_header_artifact, block_with_number_and_parent,
    block_with_number_parent_and_header_artifact, dkg_runtime_artifacts, validator_set_from_keys,
    TestAncestryReader,
};

#[tokio::test]
async fn boundary_requirement_is_derived_from_parent_snapshot_not_local_served_flag() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(0),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: true,
        dkg_cycle: 0,
        freeze_height: 0,
        planned_activation_height: 0,
        vrf_material_version: 0,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let parent =
        block_with_header_artifact(&ConsensusHeaderArtifact::BoundaryOutcome(artifact.clone()));
    let manager = DkgManagerMailbox::new();
    let ancestry = TestAncestryReader::ready();

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
            .await
            .expect("parent ancestry should decode"),
        BoundaryRequirement::AlreadyCommitted
    );
}

#[tokio::test]
async fn boundary_requirement_no_pending_does_not_read_ancestry() {
    let parent = block_with_number_and_parent(120, B256::from([0x44; 32]));
    let manager = DkgManagerMailbox::new();
    let ancestry = TestAncestryReader::ready();

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), None, &ancestry)
            .await
            .expect("no pending boundary is a normal requirement state"),
        BoundaryRequirement::NoPending
    );
    assert_eq!(ancestry.lookup_count(), 0);
}

#[tokio::test]
async fn boundary_requirement_uses_marshal_ancestry_after_block_cache_eviction() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let mut parent_hash = B256::ZERO;
    let mut ancestry = TestAncestryReader::ready();
    let mut parent = None;
    for number in 90..=120 {
        let block = block_with_number_and_parent(number, parent_hash);
        parent_hash = block.block_hash();
        if number == 120 {
            parent = Some(block.clone());
        }
        ancestry = ancestry.with_block(block);
    }
    let parent = parent.expect("parent block exists");
    let manager = DkgManagerMailbox::new();

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
            .await
            .expect("marshal ancestry should resolve"),
        BoundaryRequirement::MustEmit
    );
}

#[tokio::test]
async fn boundary_requirement_finds_deep_committed_boundary() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let mut parent_hash = B256::ZERO;
    let mut ancestry = TestAncestryReader::ready();
    let mut parent = None;
    for number in 90..=120 {
        let block = if number == 90 {
            block_with_number_parent_and_header_artifact(
                number,
                parent_hash,
                &ConsensusHeaderArtifact::BoundaryOutcome(artifact.clone()),
            )
        } else {
            block_with_number_and_parent(number, parent_hash)
        };
        parent_hash = block.block_hash();
        if number == 120 {
            parent = Some(block.clone());
        }
        ancestry = ancestry.with_block(block);
    }
    let parent = parent.expect("parent block exists");
    let manager = DkgManagerMailbox::new();

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
            .await
            .expect("marshal ancestry should resolve"),
        BoundaryRequirement::AlreadyCommitted
    );

    let not_ready = TestAncestryReader::not_ready();
    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &not_ready)
            .await
            .expect("cached boundary status should avoid cold ancestry reads"),
        BoundaryRequirement::AlreadyCommitted
    );
}

#[tokio::test]
async fn boundary_requirement_finds_boundary_committed_at_late_activation_height() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let planned_activation_height: u64 = 120;
    let late_activation_height = planned_activation_height
        .saturating_add(crate::config::DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let mut parent_hash = B256::ZERO;
    let mut ancestry = TestAncestryReader::ready();
    let mut parent = None;
    for number in 90..=late_activation_height {
        let block = if number == late_activation_height {
            block_with_number_parent_and_header_artifact(
                number,
                parent_hash,
                &ConsensusHeaderArtifact::BoundaryOutcome(artifact.clone()),
            )
        } else {
            block_with_number_and_parent(number, parent_hash)
        };
        parent_hash = block.block_hash();
        if number == late_activation_height {
            parent = Some(block.clone());
        }
        ancestry = ancestry.with_block(block);
    }
    let parent = parent.expect("late activation parent exists");
    let manager = DkgManagerMailbox::new();

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
            .await
            .expect("late activation boundary should resolve"),
        BoundaryRequirement::AlreadyCommitted
    );
}

#[tokio::test]
async fn boundary_requirement_uses_hash_lookup_when_height_lookup_is_stale() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 119,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let stale_parent = block_with_number_and_parent(119, B256::from([0x11; 32]));
    let stale_hash = stale_parent.block_hash();
    let canonical_parent = block_with_number_and_parent(119, B256::from([0x22; 32]));
    let parent = block_with_number_and_parent(120, canonical_parent.block_hash());
    let ancestry = TestAncestryReader::ready()
        .with_block(stale_parent)
        .with_hash_block(canonical_parent);
    let manager = DkgManagerMailbox::new();
    let pending_hash = DkgManagerMailbox::boundary_artifact_hash(&artifact).unwrap();
    manager.record_boundary_status(
        stale_hash,
        pending_hash,
        crate::dkg_manager::BoundaryStatus::NoBoundarySeen,
    );
    assert!(manager
        .cached_boundary_status(stale_hash, pending_hash)
        .is_some());

    assert_eq!(
        manager
            .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
            .await
            .expect("hash lookup should recover canonical ancestry after stale height hit"),
        BoundaryRequirement::MustEmit
    );
    assert!(
        manager
            .cached_boundary_status(stale_hash, pending_hash)
            .is_none(),
        "stale parent status must be explicitly evicted when height lookup returns a non-canonical block"
    );
}

#[tokio::test]
async fn boundary_requirement_rejects_missing_canonical_parent_after_stale_height_hit() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 119,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let stale_parent = block_with_number_and_parent(119, B256::from([0x11; 32]));
    let canonical_parent = block_with_number_and_parent(119, B256::from([0x22; 32]));
    let parent = block_with_number_and_parent(120, canonical_parent.block_hash());
    let ancestry = TestAncestryReader::ready().with_block(stale_parent);
    let manager = DkgManagerMailbox::new();

    let error = manager
        .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing parent"));
}

#[tokio::test]
async fn boundary_requirement_reports_backfill_not_ready() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let parent = block_with_number_and_parent(120, B256::from([0x33; 32]));
    let manager = DkgManagerMailbox::new();
    let ancestry = TestAncestryReader::not_ready();

    let error = manager
        .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not ready"));
    assert_eq!(ancestry.lookup_count(), 0);
}

#[tokio::test]
async fn boundary_requirement_rejects_same_epoch_conflict() {
    let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
    let validator_set = validator_set_from_keys(&keys);
    let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: false,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let mut conflicting = artifact.clone();
    conflicting.vrf_material_version = conflicting.vrf_material_version.saturating_add(1);
    let parent = block_with_number_parent_and_header_artifact(
        120,
        B256::ZERO,
        &ConsensusHeaderArtifact::BoundaryOutcome(conflicting),
    );
    let manager = DkgManagerMailbox::new();
    let ancestry = TestAncestryReader::ready();

    let error = manager
        .resolve_boundary(Some(&parent), Some(&artifact), &ancestry)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("conflicting DKG BoundaryOutcome"));
}
