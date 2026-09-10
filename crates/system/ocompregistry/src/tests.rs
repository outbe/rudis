use alloy_primitives::{B256, U256};
use alloy_sol_types::SolCall;
use outbe_ocomp_protocol::{
    generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1,
    profile::{CapacityProfileV1, ProtocolBundleV1},
};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;

use crate::{
    poc_schema_limits,
    precompile::{dispatch, IOcompRegistry},
    OcompProtocolAuthorityV1, OcompRegistry, OcompRequestProfile,
};

const CHAIN_ID: u64 = 42;
const ACTIVATION_HEIGHT: u64 = 32;

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn capacity() -> CapacityProfileV1 {
    let generated = OCOMP_POC_CANDIDATE_LIMITS_V1;
    CapacityProfileV1 {
        profile_id: hash(13),
        max_tributes_per_work_shard: u32::try_from(generated.max_tributes_per_work_shard).unwrap(),
        max_workers_per_domain: 4,
        max_intents_per_block: 1,
        max_activations_per_block: 1,
        max_ready_inspections_per_block: 1,
        max_expirations_per_block: 1,
        ready_backoff_blocks: 1,
        max_reference_currencies: 1,
        max_oracle_wwd_pair_entries: 1,
        max_active_scurve_entries: 1,
        result_deadline_blocks: 10,
        source_retention_after_terminal_blocks: generated.source_retention_after_terminal_blocks,
        generated_limits_manifest_hash: hash(30),
    }
}

fn bundle() -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(21),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: outbe_ocomp_protocol::registry::TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: outbe_ocomp_protocol::registry::FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: outbe_ocomp_protocol::registry::ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(22),
        release_approval_policy_hash: hash(24),
        release_validator_command_artifact_hash: hash(25),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(26),
        required_upgrade_handler_set_hash: hash(27),
    }
}

fn authority(genesis_hash: B256) -> OcompProtocolAuthorityV1 {
    let protocol_bundle = bundle();
    let limits = poc_schema_limits();
    let bundle_hash = protocol_bundle.protocol_bundle_hash(&limits).unwrap();
    OcompProtocolAuthorityV1 {
        request_profile: OcompRequestProfile {
            chain_id: CHAIN_ID,
            genesis_hash,
            fork_id: protocol_bundle.fork_id,
            protocol_bundle_hash: bundle_hash,
            correctness_profile_id: protocol_bundle.correctness_profile_id,
            capacity_profile: capacity(),
            source_availability_policy_id: hash(44),
        },
        protocol_bundle,
    }
}

fn successor(genesis_hash: B256, activation_height: u64) -> crate::OcompSuccessorV1 {
    let predecessor = authority(genesis_hash);
    let mut protocol_bundle = predecessor.protocol_bundle.clone();
    protocol_bundle.protocol_version += 1;
    protocol_bundle.fork_id = hash(61);
    protocol_bundle.request_semantics_version += 1;
    protocol_bundle.lysis_program_semantics_hash = hash(62);
    let limits = poc_schema_limits();
    let protocol_bundle_hash = protocol_bundle.protocol_bundle_hash(&limits).unwrap();
    crate::OcompSuccessorV1 {
        activation_height,
        predecessor_protocol_bundle_hash: predecessor.request_profile.protocol_bundle_hash,
        authority: OcompProtocolAuthorityV1 {
            request_profile: OcompRequestProfile {
                fork_id: protocol_bundle.fork_id,
                protocol_bundle_hash,
                correctness_profile_id: protocol_bundle.correctness_profile_id,
                ..predecessor.request_profile
            },
            protocol_bundle,
        },
    }
}

#[test]
fn fresh_genesis_install_is_visible_and_exact_replay_is_a_noop() {
    let genesis_hash = hash(42);
    let expected = authority(genesis_hash);
    let install_hash = hash(99);
    let limits = poc_schema_limits();
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(ACTIVATION_HEIGHT);

    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            registry.initialize_genesis_authority(
                &expected,
                install_hash,
                ACTIVATION_HEIGHT,
                ACTIVATION_HEIGHT,
                &limits,
            )?;
            assert_eq!(registry.active_authority(&limits)?, Some(expected.clone()));
            assert_eq!(registry.install_hash.read()?, install_hash);
            assert_eq!(registry.activation_height.read()?, ACTIVATION_HEIGHT);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();

    provider
        .enter(|storage| {
            OcompRegistry::new(storage).initialize_genesis_authority(
                &expected,
                install_hash,
                ACTIVATION_HEIGHT,
                ACTIVATION_HEIGHT,
                &limits,
            )
        })
        .unwrap();

    assert_eq!(
        provider
            .get_events(outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS)
            .len(),
        1
    );
}

#[test]
fn successor_activation_keeps_pinned_predecessor_until_retention_expires() {
    let genesis_hash = hash(42);
    let initial = authority(genesis_hash);
    let activation_height = 100;
    let next = successor(genesis_hash, activation_height);
    let proposal_id = U256::from(7);
    let old_lineage = hash(71);
    let new_lineage = hash(72);
    let retry_lineage = hash(73);
    let limits = poc_schema_limits();
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(ACTIVATION_HEIGHT);
    provider
        .enter(|storage| {
            OcompRegistry::new(storage).initialize_genesis_authority(
                &initial,
                hash(99),
                ACTIVATION_HEIGHT,
                ACTIVATION_HEIGHT,
                &limits,
            )
        })
        .unwrap();

    provider.set_block_number(50);
    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            assert_eq!(
                registry.pin_lineage(old_lineage, &limits)?,
                initial.request_profile.protocol_bundle_hash
            );
            registry.stage_successor(proposal_id, &next, &limits)
        })
        .unwrap();

    provider.set_block_number(activation_height);
    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            registry.promote_staged_successor(proposal_id, activation_height, &limits)?;
            assert_eq!(
                registry.pin_lineage(new_lineage, &limits)?,
                next.authority.request_profile.protocol_bundle_hash
            );
            assert_eq!(
                registry.pin_inherited_lineage(retry_lineage, old_lineage, &limits)?,
                initial.request_profile.protocol_bundle_hash
            );
            assert_eq!(
                registry.resolve_lineage(old_lineage)?,
                Some(initial.request_profile.protocol_bundle_hash)
            );
            assert_eq!(
                registry.authority_by_bundle_hash(
                    initial.request_profile.protocol_bundle_hash,
                    &limits,
                )?,
                Some(initial.clone())
            );
            assert!(!registry.try_retire_predecessor(activation_height, &limits)?);
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();

    provider.set_block_number(activation_height + 1);
    let retire_at = provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            registry.release_lineage(old_lineage, activation_height + 1, &limits)?;
            assert_eq!(
                registry
                    .retention_until
                    .read(&initial.request_profile.protocol_bundle_hash)?,
                0
            );
            registry.release_lineage(retry_lineage, activation_height + 1, &limits)?;
            registry
                .retention_until
                .read(&initial.request_profile.protocol_bundle_hash)
        })
        .unwrap();
    assert!(retire_at > activation_height + 1);

    provider.set_block_number(retire_at);
    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            assert!(registry.try_retire_predecessor(retire_at, &limits)?);
            assert_eq!(
                registry.authority_by_bundle_hash(
                    initial.request_profile.protocol_bundle_hash,
                    &limits,
                )?,
                None
            );
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();
}

#[test]
fn precompile_exposes_active_staged_retiring_and_lineage_state() {
    let genesis_hash = hash(42);
    let initial = authority(genesis_hash);
    let activation_height = 100;
    let next = successor(genesis_hash, activation_height);
    let proposal_id = U256::from(8);
    let lineage = hash(81);
    let limits = poc_schema_limits();
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(ACTIVATION_HEIGHT);
    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage.clone());
            registry.initialize_genesis_authority(
                &initial,
                hash(99),
                ACTIVATION_HEIGHT,
                ACTIVATION_HEIGHT,
                &limits,
            )?;
            registry.pin_lineage(lineage, &limits)?;
            registry.stage_successor(proposal_id, &next, &limits)?;

            let staged = dispatch(
                storage.clone(),
                &IOcompRegistry::stagedSuccessorCall {}.abi_encode(),
                alloy_primitives::Address::ZERO,
                U256::ZERO,
            )?;
            let staged = IOcompRegistry::stagedSuccessorCall::abi_decode_returns(&staged)
                .map_err(|error| crate::errors::corruption(error.to_string()))?;
            assert_eq!(staged.proposalId, proposal_id);
            assert_eq!(
                staged.canonicalSuccessor.as_ref(),
                next.encode_canonical(&limits)?.as_slice()
            );

            let lineage_hash = dispatch(
                storage,
                &IOcompRegistry::lineageProtocolBundleHashCall { lineage }.abi_encode(),
                alloy_primitives::Address::ZERO,
                U256::ZERO,
            )?;
            assert_eq!(
                IOcompRegistry::lineageProtocolBundleHashCall::abi_decode_returns(&lineage_hash)
                    .map_err(|error| crate::errors::corruption(error.to_string()))?,
                initial.request_profile.protocol_bundle_hash
            );
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();

    provider.set_block_number(activation_height);
    provider
        .enter(|storage| {
            OcompRegistry::new(storage.clone()).promote_staged_successor(
                proposal_id,
                activation_height,
                &limits,
            )?;
            let retiring = dispatch(
                storage,
                &IOcompRegistry::retiringProtocolBundleHashCall {}.abi_encode(),
                alloy_primitives::Address::ZERO,
                U256::ZERO,
            )?;
            assert_eq!(
                IOcompRegistry::retiringProtocolBundleHashCall::abi_decode_returns(&retiring)
                    .map_err(|error| crate::errors::corruption(error.to_string()))?,
                initial.request_profile.protocol_bundle_hash
            );
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();
}

#[test]
fn conflicting_genesis_replay_and_unavailable_inherited_lineage_fail_closed() {
    let genesis_hash = hash(42);
    let initial = authority(genesis_hash);
    let limits = poc_schema_limits();
    let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    provider.set_block_number(ACTIVATION_HEIGHT);
    provider
        .enter(|storage| {
            let mut registry = OcompRegistry::new(storage);
            registry.initialize_genesis_authority(
                &initial,
                hash(99),
                ACTIVATION_HEIGHT,
                ACTIVATION_HEIGHT,
                &limits,
            )?;
            let mut changed = initial.clone();
            changed.request_profile.source_availability_policy_id = hash(45);
            assert!(registry
                .initialize_genesis_authority(
                    &changed,
                    hash(99),
                    ACTIVATION_HEIGHT,
                    ACTIVATION_HEIGHT,
                    &limits,
                )
                .is_err());
            assert!(registry
                .pin_inherited_lineage(hash(91), hash(92), &limits)
                .is_err());
            Ok::<_, outbe_primitives::error::PrecompileError>(())
        })
        .unwrap();
}
