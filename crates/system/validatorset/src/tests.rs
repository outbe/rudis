use alloy_primitives::{address, keccak256, Address, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationCoreV1, OcompKeyRegistrationV1,
        POC_KEY_EPOCH, RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    profile::poc_schema_limits,
};
use outbe_primitives::consensus_p2p::{
    encode_v1, P2pAddress, P2pIngress, MAX_P2P_ADDRESS_ENCODED_LEN, P2P_ADDRESS_VERSION_V1,
};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::validators::{validator_registration_message, VALIDATOR_REGISTRATION_DST};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::runtime::status;
use crate::schema::ValidatorSet;
use crate::state_machine::{StakeProjection, ValidatorLifecycle};

const CHAIN_ID: u64 = 1;

/// Owner address used across tests.
const OWNER: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

/// Convenience: set config_owner and config_max_validators, then run test.
fn with_vs_configured<R>(max: u32, f: impl FnOnce(&mut ValidatorSet) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // Height zero is the storage sentinel for an absent lifecycle height. Keep
    // semantic transition fixtures at a real block so EXITING/INACTIVE decode
    // through the same path as production records.
    storage.set_block_number(1);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(max).unwrap();
        vs.config_epoch_length_blocks.write(10).unwrap();
        f(&mut vs)
    })
}

/// Move a registered validator through the canonical committee-entry path.
fn activate_for_test(vs: &mut ValidatorSet, addr: Address) {
    vs.activate_validator(addr).unwrap();
}

/// Activate through the complete stake/readiness/boundary type-state path.
fn activate_staked_for_test(vs: &mut ValidatorSet, addr: Address) {
    let minimum = U256::from(1_000u64);
    vs.test_activate_validator_canonically(addr, StakeProjection::new(minimum, None), minimum)
        .unwrap();
}

/// Move a registered validator through a complete canonical economic exit.
fn make_inactive_for_test(vs: &mut ValidatorSet, addr: Address) {
    activate_for_test(vs, addr);
    vs.deactivate_validator(OWNER, addr).unwrap();
    vs.activate_reshared_set(&[], B256::ZERO).unwrap();
    vs.complete_unbonding(addr).unwrap();
}

/// Generate a dummy 48-byte consensus pubkey with a unique seed byte.
fn dummy_consensus_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn test_radicle_node_id(validator: Address) -> B256 {
    keccak256(validator.as_slice())
}

fn ocomp_registration(
    validator: Address,
    consensus_pubkey: &[u8; 48],
    key_seed: u8,
) -> (OcompKeyRegistrationV1, Vec<u8>) {
    let signing_key =
        SigningKey::from_bytes((&outbe_primitives::test_keys::secret((key_seed) as u64)).into())
            .unwrap();
    let ocomp_public_key_sec1 = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id: CHAIN_ID,
            genesis_hash: B256::ZERO,
            validator_identity_hash: validator_identity_hash_v1(validator, consensus_pubkey)
                .unwrap(),
            ocomp_public_key_sec1,
            key_epoch: POC_KEY_EPOCH,
            allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
        },
        proof_of_possession: [0; 64],
    };
    let limits = poc_schema_limits();
    let digest = registration.proof_of_possession_digest(&limits).unwrap();
    let signature: Signature = signing_key.sign_prehash(digest.as_slice()).unwrap();
    registration.proof_of_possession = signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into();
    let encoded = registration.encode_canonical(&limits).unwrap();
    (registration, encoded)
}

fn confirm_ready(vs: &mut ValidatorSet<'_>, validator: Address, key_seed: u8) {
    let consensus_pubkey = vs
        .get_validator(validator)
        .unwrap()
        .unwrap()
        .consensus_pubkey;
    let (_, encoded) = ocomp_registration(validator, &consensus_pubkey, key_seed);
    vs.confirm_validator_ready(validator, &encoded).unwrap();
}

#[test]
fn founder_key_bootstrap_imports_exact_active_order_and_replays_idempotently() {
    let validators = [Address::repeat_byte(0x61), Address::repeat_byte(0x62)];
    let consensus_keys = [dummy_consensus_pubkey(0x31), dummy_consensus_pubkey(0x32)];

    with_vs_configured(2, |vs| {
        let mut registrations = Vec::new();
        for (index, (validator, consensus_key)) in
            validators.into_iter().zip(consensus_keys).enumerate()
        {
            vs.register_validator(OWNER, validator, &consensus_key)
                .unwrap();
            vs.mark_pending(validator).unwrap();
            let (registration, encoded) = ocomp_registration(
                validator,
                &consensus_key,
                u8::try_from(index).unwrap().saturating_add(0x71),
            );
            vs.confirm_validator_ready(validator, &encoded).unwrap();
            vs.activate_validator_via_boundary_for_test(validator)
                .unwrap();
            registrations.push(registration);
        }

        for (validator, registration) in validators.into_iter().zip(&registrations) {
            let key_hash = keccak256(registration.core.ocomp_public_key_sec1);
            vs.val_ocomp_registration
                .get_bytes(&validator)
                .clear()
                .unwrap();
            vs.ocomp_key_hash_to_validator
                .write(&key_hash, Address::ZERO)
                .unwrap();
            vs.val_join_confirmed.write(&validator, false).unwrap();
        }

        vs.initialize_founder_ocomp_registrations(&registrations)
            .unwrap();
        for (validator, registration) in validators.into_iter().zip(&registrations) {
            assert_eq!(
                vs.ocomp_registration(validator).unwrap().as_ref(),
                Some(registration)
            );
            assert_eq!(
                vs.ocomp_key_hash_to_validator
                    .read(&keccak256(registration.core.ocomp_public_key_sec1))
                    .unwrap(),
                validator
            );
            assert!(
                !vs.val_join_confirmed.read(&validator).unwrap(),
                "founder key bootstrap must not mutate ACTIVE admission readiness"
            );
        }

        vs.initialize_founder_ocomp_registrations(&registrations)
            .unwrap();
        let mut reordered = registrations;
        reordered.swap(0, 1);
        assert!(matches!(
            vs.initialize_founder_ocomp_registrations(&reordered),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

fn admit_pending(vs: &mut ValidatorSet<'_>, validator: Address, key_seed: u8) {
    vs.mark_pending(validator).unwrap();
    confirm_ready(vs, validator, key_seed);
}

fn symmetric_p2p(port: u16) -> Vec<u8> {
    encode_v1(&P2pAddress::Symmetric(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
    )))
}

// ---------------------------------------------------------------------------
// 1. test_register_validator
// ---------------------------------------------------------------------------
#[test]
fn test_register_validator() {
    let val_addr = address!("0x1111111111111111111111111111111111111111");
    let pk = dummy_consensus_pubkey(1);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();

        // Index must be 1
        assert_eq!(vs.address_to_index.read(&val_addr).unwrap(), 1);
        assert_eq!(vs.index_to_address.read(&1u64).unwrap(), val_addr);

        // Status must be REGISTERED after registration
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::REGISTERED);

        // Consensus pubkey stored correctly (read back via get_validator)
        let record = vs.get_validator(val_addr).unwrap().unwrap();
        assert_eq!(record.consensus_pubkey, pk);

        // Reverse lookup by pubkey hash
        let pk_hash = ValidatorSet::consensus_pubkey_hash(&pk);
        assert_eq!(
            vs.consensus_pubkey_hash_to_address.read(&pk_hash).unwrap(),
            val_addr
        );

        // Count incremented
        assert_eq!(vs.validator_count.read().unwrap(), 1);

        // pending_set_change should be set
        assert!(vs.pending_set_change.read().unwrap());
    });
}

#[test]
fn test_activate_missing_validator_returns_revert() {
    let val_addr = address!("0x1111111111111111111111111111111111111111");

    with_vs_configured(10, |vs| {
        let err = vs
            .activate_validator_via_boundary_for_test(val_addr)
            .unwrap_err();
        assert!(
            matches!(err, PrecompileError::Revert(message) if message == "test validator is not registered")
        );
    });
}

// ---------------------------------------------------------------------------
// 2. test_register_self - self-registration now requires BLS proof
// ---------------------------------------------------------------------------
#[test]
fn test_register_self_without_sig_rejected() {
    let val_addr = address!("0x2222222222222222222222222222222222222222");
    let pk = dummy_consensus_pubkey(2);

    with_vs_configured(10, |vs| {
        // Self-registration without BLS signature must fail
        let result = vs.register_validator_with_sig(
            val_addr,
            val_addr,
            &pk,
            test_radicle_node_id(val_addr),
            None,
        );
        assert!(
            result.is_err(),
            "self-registration without BLS sig must be rejected"
        );
    });
}

#[test]
fn test_register_via_owner() {
    let val_addr = address!("0x2222222222222222222222222222222222222222");
    let pk = dummy_consensus_pubkey(2);

    with_vs_configured(10, |vs| {
        // Owner registration path - no BLS sig required
        vs.register_validator(OWNER, val_addr, &pk).unwrap();
        assert!(vs.is_validator(val_addr).unwrap());
    });
}

#[test]
fn test_set_p2p_address_owner_or_self_and_get() {
    let val_addr = address!("0x2222222222222222222222222222222222222223");
    let pk = dummy_consensus_pubkey(23);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();

        let encoded = symmetric_p2p(30400);
        vs.set_p2p_address(OWNER, val_addr, P2P_ADDRESS_VERSION_V1, &encoded)
            .unwrap();
        assert_eq!(
            vs.get_p2p_address(val_addr).unwrap(),
            Some((P2P_ADDRESS_VERSION_V1, encoded.clone()))
        );

        let replacement = symmetric_p2p(30401);
        vs.set_p2p_address(val_addr, val_addr, P2P_ADDRESS_VERSION_V1, &replacement)
            .unwrap();
        assert_eq!(
            vs.get_p2p_address(val_addr).unwrap(),
            Some((P2P_ADDRESS_VERSION_V1, replacement))
        );
    });
}

#[test]
fn test_set_p2p_address_rejects_unauthorized_and_malformed() {
    let val_addr = address!("0x2222222222222222222222222222222222222224");
    let stranger = address!("0x9999999999999999999999999999999999999999");
    let pk = dummy_consensus_pubkey(24);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();
        let encoded = symmetric_p2p(30400);

        let err = vs
            .set_p2p_address(stranger, val_addr, P2P_ADDRESS_VERSION_V1, &encoded)
            .unwrap_err();
        assert!(
            matches!(err, PrecompileError::Revert(message) if message.contains("unauthorized"))
        );

        let err = vs
            .set_p2p_address(OWNER, val_addr, 2, &encoded)
            .unwrap_err();
        assert!(
            matches!(err, PrecompileError::Revert(message) if message.contains("unsupported p2p address version"))
        );

        let malformed = [0u8; 3];
        let err = vs
            .set_p2p_address(OWNER, val_addr, P2P_ADDRESS_VERSION_V1, &malformed)
            .unwrap_err();
        assert!(
            matches!(err, PrecompileError::Revert(message) if message.contains("invalid p2p address"))
        );
    });
}

#[test]
fn test_set_p2p_address_rejects_oversized_and_accepts_asymmetric() {
    let val_addr = address!("0x2222222222222222222222222222222222222225");
    let pk = dummy_consensus_pubkey(25);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();

        let oversized = vec![0u8; MAX_P2P_ADDRESS_ENCODED_LEN + 1];
        let err = vs
            .set_p2p_address(OWNER, val_addr, P2P_ADDRESS_VERSION_V1, &oversized)
            .unwrap_err();
        assert!(
            matches!(err, PrecompileError::Revert(message) if message.contains("exceeds max length"))
        );

        let asymmetric = encode_v1(&P2pAddress::Asymmetric {
            ingress: P2pIngress::Dns {
                host: "validator-1.example.com".to_owned(),
                port: 30400,
            },
            egress: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30401),
        });
        vs.set_p2p_address(OWNER, val_addr, P2P_ADDRESS_VERSION_V1, &asymmetric)
            .unwrap();
        assert_eq!(
            vs.get_p2p_address(val_addr).unwrap(),
            Some((P2P_ADDRESS_VERSION_V1, asymmetric))
        );
    });
}

#[test]
fn malformed_p2p_fails_all_complete_record_projections_closed() {
    let val_addr = address!("0x2222222222222222222222222222222222222226");
    let pk = dummy_consensus_pubkey(6);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();
        vs.val_p2p_address_version
            .write(&val_addr, P2P_ADDRESS_VERSION_V1)
            .unwrap();
        vs.val_p2p_address_payload
            .get_bytes(&val_addr)
            .write(&[0xFF])
            .unwrap();

        // Every complete projection now passes through the canonical aggregate;
        // malformed coupled P2P fields therefore fail closed consistently.
        assert!(matches!(
            vs.get_validator(val_addr),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            vs.get_all_validators(),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            vs.validator_state(val_addr),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn typed_storage_adapter_rejects_pre_registration_stake_and_fails_closed() {
    let addr = address!("0x2222222222222222222222222222222222222227");

    with_vs_configured(10, |vs| {
        vs.val_stake.write(&addr, U256::from(900)).unwrap();
        vs.val_unbonding_end.write(&addr, 55).unwrap();

        assert!(matches!(
            vs.validator_state(addr),
            Err(PrecompileError::Fatal(_))
        ));

        vs.val_stake.write(&addr, U256::ZERO).unwrap();
        vs.val_unbonding_end.write(&addr, 0).unwrap();
        assert_eq!(
            vs.validator_state(addr).unwrap().lifecycle(),
            &crate::ValidatorLifecycle::Absent
        );

        vs.val_join_confirmed.write(&addr, true).unwrap();
        assert!(matches!(
            vs.validator_state(addr),
            Err(PrecompileError::Fatal(_))
        ));

        vs.val_join_confirmed.write(&addr, false).unwrap();
        vs.val_status.write(&addr, 7).unwrap();
        assert!(matches!(
            vs.validator_state(addr),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn full_and_hot_lifecycle_reads_both_reject_combined_residue() {
    let addr = address!("0x2222222222222222222222222222222222222228");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, addr, &dummy_consensus_pubkey(28))
            .unwrap();
        vs.val_status.write(&addr, status::UNBONDING).unwrap();
        vs.val_join_confirmed.write(&addr, true).unwrap();
        vs.val_has_bls_share.write(&addr, true).unwrap();
        vs.val_jailed_at_height.write(&addr, 99).unwrap();

        assert!(matches!(
            vs.validator_state(addr),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            vs.validator_lifecycle(addr),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

// ---------------------------------------------------------------------------
// 3. test_register_duplicate_fails
// ---------------------------------------------------------------------------
#[test]
fn test_register_duplicate_fails() {
    let val_addr = address!("0x3333333333333333333333333333333333333333");
    let pk = dummy_consensus_pubkey(3);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();
        let result = vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(30));
        assert!(result.is_err(), "duplicate registration must fail");
    });
}

// ---------------------------------------------------------------------------
// 4. test_register_max_validators
// ---------------------------------------------------------------------------
#[test]
fn test_register_max_validators() {
    with_vs_configured(2, |vs| {
        let addr1 = address!("0x0000000000000000000000000000000000000011");
        let addr2 = address!("0x0000000000000000000000000000000000000022");
        let addr3 = address!("0x0000000000000000000000000000000000000033");

        vs.register_validator(OWNER, addr1, &dummy_consensus_pubkey(11))
            .unwrap();
        vs.register_validator(OWNER, addr2, &dummy_consensus_pubkey(22))
            .unwrap();

        let result = vs.register_validator(OWNER, addr3, &dummy_consensus_pubkey(33));
        assert!(result.is_err(), "should fail when max validators reached");
    });
}

// ---------------------------------------------------------------------------
// 5. test_activate_deactivate
// ---------------------------------------------------------------------------
#[test]
fn test_activate_deactivate() {
    let val_addr = address!("0x4444444444444444444444444444444444444444");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(4))
            .unwrap();

        // Initially REGISTERED
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::REGISTERED);

        vs.activate_validator_via_boundary_for_test(val_addr)
            .unwrap();
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::ACTIVE);

        vs.deactivate_validator(OWNER, val_addr).unwrap();
        // In the new lifecycle, deactivation transitions to EXITING (not INACTIVE)
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::EXITING);

        // pending_set_change should be set after deactivation
        assert!(vs.pending_set_change.read().unwrap());
    });
}

#[test]
fn deactivation_rejection_reasons_preserve_validator_state() {
    let validator = address!("0x4444444444444444444444444444444444444444");
    let outsider = address!("0x9999999999999999999999999999999999999999");
    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, validator, &dummy_consensus_pubkey(4))
            .unwrap();
        activate_staked_for_test(vs, validator);
        let active = vs.validator_state(validator).unwrap();
        let pending = vs.pending_set_change.read().unwrap();
        assert!(matches!(
            vs.deactivate_validator(outsider, validator),
            Err(PrecompileError::Revert(reason))
                if reason == "unauthorized: caller must be owner or validator itself"
        ));
        assert_eq!(vs.validator_state(validator).unwrap(), active);
        assert_eq!(vs.pending_set_change.read().unwrap(), pending);

        vs.deactivate_validator(validator, validator).unwrap();
        let exiting = vs.validator_state(validator).unwrap();
        let pending = vs.pending_set_change.read().unwrap();
        assert!(matches!(
            vs.deactivate_validator(validator, validator),
            Err(PrecompileError::Revert(reason))
                if reason == "can only deactivate an active validator"
        ));
        assert_eq!(vs.validator_state(validator).unwrap(), exiting);
        assert_eq!(vs.pending_set_change.read().unwrap(), pending);
    });
}

// ---------------------------------------------------------------------------
// 6. test_force_exit
// ---------------------------------------------------------------------------
#[test]
fn test_force_exit() {
    let val_addr = address!("0x5555555555555555555555555555555555555555");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(5))
            .unwrap();
        activate_for_test(vs, val_addr);

        vs.force_exit_validator(val_addr).unwrap();
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::EXITING);
        assert_eq!(vs.val_slash_count.read(&val_addr).unwrap(), 1);
        assert!(vs.pending_set_change.read().unwrap());
    });
}

// ---------------------------------------------------------------------------
// 7. test_record_proposer
// ---------------------------------------------------------------------------
#[test]
fn test_record_proposer() {
    let val_addr = address!("0x6666666666666666666666666666666666666666");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(6))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val_addr)
            .unwrap();
        vs.val_has_bls_share.write(&val_addr, true).unwrap();

        assert_eq!(vs.val_blocks_proposed.read(&val_addr).unwrap(), 0);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 0);

        vs.record_proposer(val_addr).unwrap();
        assert_eq!(vs.val_blocks_proposed.read(&val_addr).unwrap(), 1);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 0);

        vs.record_proposer(val_addr).unwrap();
        assert_eq!(vs.val_blocks_proposed.read(&val_addr).unwrap(), 2);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 0);
    });
}

// ---------------------------------------------------------------------------
// 8. test_record_participation
// ---------------------------------------------------------------------------
#[test]
fn test_record_participation() {
    let val1 = address!("0x0000000000000000000000000000000000000071");
    let val2 = address!("0x0000000000000000000000000000000000000072");
    let val3 = address!("0x0000000000000000000000000000000000000073");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(71))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(72))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(73))
            .unwrap();
        for val in [val1, val2, val3] {
            vs.activate_validator_via_boundary_for_test(val).unwrap();
            vs.val_has_bls_share.write(&val, true).unwrap();
        }

        // val3 is absent
        let voters = vec![val1, val2];
        let absent = vec![val3];
        vs.record_participation(&voters, &absent).unwrap();

        assert_eq!(vs.val_missed_votes.read(&val1).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&val2).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&val3).unwrap(), 1);

        // Record again - val2 also absent this time
        let voters2 = vec![val1];
        let absent2 = vec![val2, val3];
        vs.record_participation(&voters2, &absent2).unwrap();

        assert_eq!(vs.val_missed_votes.read(&val2).unwrap(), 1);
        assert_eq!(vs.val_missed_votes.read(&val3).unwrap(), 2);
    });
}

// ---------------------------------------------------------------------------
// 8b. test_record_finalized_participation
// ---------------------------------------------------------------------------
#[test]
fn test_record_finalized_participation_accepts_historical_validators() {
    let val_active = address!("0x0000000000000000000000000000000000000081");
    let val_unbonding = address!("0x0000000000000000000000000000000000000082");

    with_vs_configured(10, |vs| {
        // Active current participant.
        vs.register_validator(OWNER, val_active, &dummy_consensus_pubkey(81))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val_active)
            .unwrap();
        vs.val_has_bls_share.write(&val_active, true).unwrap();

        // Registered historical participant: canonically exit the live set to
        // UNBONDING. record_participation rejects it, while finalized-parent
        // accounting still accepts its retained registry/history record.
        vs.register_validator(OWNER, val_unbonding, &dummy_consensus_pubkey(82))
            .unwrap();
        activate_for_test(vs, val_unbonding);
        vs.deactivate_validator(OWNER, val_unbonding).unwrap();
        vs.activate_reshared_set(&[val_active], B256::ZERO).unwrap();

        // Sanity: record_participation rejects historical val_unbonding.
        // Participation/registration checks revert (not Fatal) so the error
        // message propagates instead of being masked as OutOfGas (see commit
        // c879d4e: Fatal -> Revert for system/core checks).
        let err = vs
            .record_participation(&[val_active], &[val_unbonding])
            .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(_)));

        // record_finalized_participation accepts both, increments missed_votes for absent.
        vs.record_finalized_participation(&[val_active], &[val_unbonding])
            .unwrap();
        assert_eq!(vs.val_missed_votes.read(&val_active).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&val_unbonding).unwrap(), 1);
    });
}

#[test]
fn test_record_finalized_participation_rejects_unregistered() {
    let val = address!("0x0000000000000000000000000000000000000091");
    let stranger = address!("0x9999999999999999999999999999999999999999");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val, &dummy_consensus_pubkey(91))
            .unwrap();

        let err = vs
            .record_finalized_participation(&[val], &[stranger])
            .unwrap_err();
        // Registration check reverts (not Fatal) so the message propagates
        // cleanly instead of being masked as OutOfGas (see commit c879d4e).
        match err {
            PrecompileError::Revert(msg) => {
                assert!(
                    msg.contains("not a registered validator"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected Revert, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// 9. test_update_epoch
// ---------------------------------------------------------------------------
#[test]
fn test_update_epoch() {
    let val_addr = address!("0x0000000000000000000000000000000000000091");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(91))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val_addr)
            .unwrap();
        vs.val_has_bls_share.write(&val_addr, true).unwrap();

        // Accumulate some stats
        vs.record_proposer(val_addr).unwrap();
        vs.record_missed_block(val_addr).unwrap();
        vs.record_participation(&[], &[val_addr]).unwrap();

        assert_eq!(vs.val_blocks_proposed.read(&val_addr).unwrap(), 1);
        assert_eq!(vs.val_missed_blocks.read(&val_addr).unwrap(), 1);
        assert_eq!(vs.val_missed_votes.read(&val_addr).unwrap(), 1);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 0);
        assert_eq!(vs.epoch_number.read().unwrap(), 0);

        vs.update_epoch(5000, 77).unwrap();

        // Counters reset
        assert_eq!(vs.val_blocks_proposed.read(&val_addr).unwrap(), 0);
        assert_eq!(vs.val_missed_blocks.read(&val_addr).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&val_addr).unwrap(), 0);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 77);

        // Epoch number incremented, timestamp and start block updated.
        assert_eq!(vs.epoch_number.read().unwrap(), 1);
        assert_eq!(vs.epoch_start_timestamp.read().unwrap(), 5000);
    });
}

#[test]
fn test_epoch_boundary_uses_block_height_not_timestamp() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage.clone());
        vs.config_epoch_length_blocks.write(100).unwrap();
        vs.epoch_start_block.write(25).unwrap();
        vs.epoch_start_timestamp.write(1_000).unwrap();

        assert!(
            !crate::hooks::is_epoch_boundary(storage.clone(), 124).unwrap(),
            "block before start+length must not transition even if wall-clock advanced"
        );
        assert!(
            crate::hooks::is_epoch_boundary(storage.clone(), 125).unwrap(),
            "block at start+length must transition"
        );
    });
}

#[test]
fn test_transition_epoch_updates_start_block_and_timestamp() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage.clone());
        vs.config_epoch_length_blocks.write(100).unwrap();

        crate::hooks::transition_epoch(storage.clone(), 1_234, 456).unwrap();

        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.epoch_number.read().unwrap(), 1);
        assert_eq!(vs.epoch_start_timestamp.read().unwrap(), 1_234);
        assert_eq!(vs.epoch_start_block.read().unwrap(), 456);
    });
}

// ---------------------------------------------------------------------------
// 10. test_get_active_validators
// ---------------------------------------------------------------------------
#[test]
fn test_get_active_validators() {
    let val1 = address!("0x00000000000000000000000000000000000000A1");
    let val2 = address!("0x00000000000000000000000000000000000000A2");
    let val3 = address!("0x00000000000000000000000000000000000000A3");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xA1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xA2))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(0xA3))
            .unwrap();

        // Activate only val1 and val3
        vs.activate_validator_via_boundary_for_test(val1).unwrap();
        vs.activate_validator_via_boundary_for_test(val3).unwrap();

        let active = vs.get_active_validators().unwrap();
        let active_addrs: Vec<Address> = active.iter().map(|v| v.validator_address).collect();

        assert_eq!(active.len(), 2);
        assert!(active_addrs.contains(&val1));
        assert!(!active_addrs.contains(&val2));
        assert!(active_addrs.contains(&val3));
    });
}

// ---------------------------------------------------------------------------
// 11. test_is_validator
// ---------------------------------------------------------------------------
#[test]
fn test_is_validator() {
    let registered = address!("0x00000000000000000000000000000000000000B1");
    let stranger = address!("0x00000000000000000000000000000000000000B2");

    with_vs_configured(10, |vs| {
        assert!(!vs.is_validator(registered).unwrap());
        assert!(!vs.is_validator(stranger).unwrap());

        vs.register_validator(OWNER, registered, &dummy_consensus_pubkey(0xB1))
            .unwrap();

        assert!(vs.is_validator(registered).unwrap());
        assert!(!vs.is_validator(stranger).unwrap());
    });
}

#[test]
fn config_max_validators_cannot_exceed_consensus_bound() {
    with_vs_configured(10, |vs| {
        let consensus_bound = outbe_consensus::bls::MAX_VALIDATORS;
        vs.set_config_max_validators(consensus_bound).unwrap();
        assert_eq!(vs.config_max_validators.read().unwrap(), consensus_bound);

        assert!(vs
            .set_config_max_validators(consensus_bound.saturating_add(1))
            .is_err());
        assert_eq!(
            vs.config_max_validators.read().unwrap(),
            consensus_bound,
            "rejected bound must not mutate config",
        );
    });
}

#[test]
fn production_validator_set_selector_allow_list_is_exact() {
    // Explicit public signatures pin the security boundary independently of
    // the generated ABI enum; adding any entry requires reviewing this list.
    let signatures = [
        "getValidators()",
        "getActiveValidators()",
        "getActiveConsensusSet()",
        "validatorByAddress(address)",
        "validatorByIndex(uint64)",
        "validatorCount()",
        "activeValidatorCount()",
        "activeConsensusCount()",
        "isValidator(address)",
        "isConsensusParticipant(address)",
        "hasPendingSetChange()",
        "getEpochNumber()",
        "getEpochStartTimestamp()",
        "getEpochStartBlock()",
        "setDelegate(uint8,address)",
        "revokeDelegate(uint8)",
        "getDelegate(address,uint8)",
        "resolveValidator(uint8,address)",
        "registerValidator(address,bytes,bytes32,bytes)",
        "getRadicleNodeId(address)",
        "validatorByRadicleNodeId(bytes32)",
        "setP2pAddress(address,uint8,bytes)",
        "getP2pAddress(address)",
        "deactivateValidator(address)",
        "confirmValidatorReady(bytes)",
    ];
    let mut expected = signatures.map(|signature| {
        let digest = keccak256(signature);
        <[u8; 4]>::try_from(&digest[..4]).unwrap()
    });
    expected.sort_unstable();
    assert!(
        expected.windows(2).all(|pair| pair[0] != pair[1]),
        "selector collision in allow-list"
    );
    let mut actual = crate::precompile::IValidatorSet::IValidatorSetCalls::SELECTORS.to_vec();
    actual.sort_unstable();
    assert_eq!(actual, expected, "public ValidatorSet selectors changed");
}

#[test]
fn owner_manual_reshare_selector_is_not_exposed() {
    let digest = keccak256("activateResharedSet(address[],bytes32)");
    let selector: [u8; 4] = digest[..4].try_into().unwrap();
    assert!(
        !crate::precompile::IValidatorSet::IValidatorSetCalls::SELECTORS.contains(&selector),
        "owner/manual activation must not be reachable through ValidatorSet ABI",
    );
}

// ---------------------------------------------------------------------------
// 12. test_consensus_set
// ---------------------------------------------------------------------------
#[test]
fn test_consensus_set() {
    let val1 = address!("0x00000000000000000000000000000000000000C1");
    let val2 = address!("0x00000000000000000000000000000000000000C2");
    let val3 = address!("0x00000000000000000000000000000000000000C3");
    let group_key = B256::with_last_byte(0xFF);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xC1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xC2))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(0xC3))
            .unwrap();

        // All start as REGISTERED
        assert_eq!(vs.val_status.read(&val1).unwrap(), status::REGISTERED);
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::REGISTERED);

        // Stake/readiness fixtures make val1 and val2 eligible for boundary
        // inclusion. val3 deliberately remains WaitingForStake.
        activate_for_test(vs, val1);
        activate_for_test(vs, val2);

        // Commit a same-member reshared set with val1 and val2 (not val3).
        vs.activate_reshared_set(&[val1, val2], group_key).unwrap();

        // val1 and val2 should be ACTIVE with has_bls_share
        assert_eq!(vs.val_status.read(&val1).unwrap(), status::ACTIVE);
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::ACTIVE);
        assert!(vs.val_has_bls_share.read(&val1).unwrap());
        assert!(vs.val_has_bls_share.read(&val2).unwrap());

        // val3 remains REGISTERED, no BLS share
        assert_eq!(vs.val_status.read(&val3).unwrap(), status::REGISTERED);
        assert!(!vs.val_has_bls_share.read(&val3).unwrap());

        // Consensus set contains only val1 and val2
        let consensus_set = vs.get_active_consensus_set().unwrap();
        assert_eq!(consensus_set.len(), 2);
        assert_eq!(vs.active_consensus_count().unwrap(), 2);

        // pending_set_change should be cleared
        assert!(!vs.pending_set_change.read().unwrap());

        // is_consensus_participant checks
        assert!(vs.is_consensus_participant(val1).unwrap());
        assert!(vs.is_consensus_participant(val2).unwrap());
        assert!(!vs.is_consensus_participant(val3).unwrap());
    });
}

// ---------------------------------------------------------------------------
// 13. test_exiting_to_unbonding_via_reshare
// ---------------------------------------------------------------------------
#[test]
fn test_exiting_to_unbonding_via_reshare() {
    let val1 = address!("0x00000000000000000000000000000000000000D1");
    let val2 = address!("0x00000000000000000000000000000000000000D2");
    let group_key = B256::with_last_byte(0xFE);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xD1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xD2))
            .unwrap();
        admit_pending(vs, val1, 0xD1);
        admit_pending(vs, val2, 0xD2);

        activate_for_test(vs, val1);
        activate_for_test(vs, val2);

        // First reshare: both remain active.
        vs.activate_reshared_set(&[val1, val2], group_key).unwrap();
        assert_eq!(vs.val_status.read(&val1).unwrap(), status::ACTIVE);
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::ACTIVE);

        // val2 requests deactivation -> EXITING
        vs.deactivate_validator(OWNER, val2).unwrap();
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::EXITING);

        // Second reshare: only val1 in new set
        let group_key2 = B256::with_last_byte(0xFD);
        vs.activate_reshared_set(&[val1], group_key2).unwrap();

        // val1 still ACTIVE with BLS share
        assert_eq!(vs.val_status.read(&val1).unwrap(), status::ACTIVE);
        assert!(vs.val_has_bls_share.read(&val1).unwrap());

        // val2 transitioned from EXITING -> UNBONDING, no BLS share
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::UNBONDING);
        assert!(!vs.val_has_bls_share.read(&val2).unwrap());
    });
}

#[test]
fn test_deactivated_validator_stays_current_consensus_participant_until_reshare() {
    let val1 = address!("0x0000000000000000000000000000000000000CD1");
    let val2 = address!("0x0000000000000000000000000000000000000CD2");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xD1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xD2))
            .unwrap();
        activate_for_test(vs, val1);
        activate_for_test(vs, val2);
        vs.activate_reshared_set(&[val1, val2], B256::with_last_byte(0xD1))
            .unwrap();

        vs.deactivate_validator(OWNER, val2).unwrap();

        assert_eq!(vs.val_status.read(&val2).unwrap(), status::EXITING);
        assert!(vs.val_has_bls_share.read(&val2).unwrap());
        assert!(vs.is_consensus_participant(val2).unwrap());
        assert_eq!(vs.active_consensus_count().unwrap(), 2);

        let current_set = vs.get_active_consensus_set().unwrap();
        let current_addrs: Vec<_> = current_set.iter().map(|v| v.validator_address).collect();
        assert!(current_addrs.contains(&val1));
        assert!(current_addrs.contains(&val2));

        vs.record_proposer(val2).unwrap();
        vs.record_participation(&[val1], &[val2]).unwrap();
        assert_eq!(vs.val_blocks_proposed.read(&val2).unwrap(), 1);
        assert_eq!(vs.val_missed_votes.read(&val2).unwrap(), 1);

        vs.activate_reshared_set(&[val1], B256::with_last_byte(0xD2))
            .unwrap();
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::UNBONDING);
        assert!(!vs.val_has_bls_share.read(&val2).unwrap());
        assert!(!vs.is_consensus_participant(val2).unwrap());
    });
}

#[test]
fn test_force_exited_validator_stays_current_consensus_participant_until_reshare() {
    let val1 = address!("0x0000000000000000000000000000000000000CF1");
    let val2 = address!("0x0000000000000000000000000000000000000CF2");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xF1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xF2))
            .unwrap();
        activate_for_test(vs, val1);
        activate_for_test(vs, val2);
        vs.activate_reshared_set(&[val1, val2], B256::with_last_byte(0xF1))
            .unwrap();

        vs.force_exit_validator(val2).unwrap();

        assert_eq!(vs.val_status.read(&val2).unwrap(), status::EXITING);
        assert!(vs.val_has_bls_share.read(&val2).unwrap());
        assert!(vs.is_consensus_participant(val2).unwrap());
        assert_eq!(vs.val_slash_count.read(&val2).unwrap(), 1);

        vs.record_proposer(val2).unwrap();
        vs.record_participation(&[val1], &[val2]).unwrap();

        vs.force_exit_validator(val2).unwrap();
        assert!(vs.val_has_bls_share.read(&val2).unwrap());
        assert!(vs.is_consensus_participant(val2).unwrap());
        assert_eq!(vs.val_slash_count.read(&val2).unwrap(), 1);

        vs.activate_reshared_set(&[val1], B256::with_last_byte(0xF2))
            .unwrap();
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::UNBONDING);
        assert!(!vs.is_consensus_participant(val2).unwrap());
    });
}

#[test]
fn post_freeze_exit_is_retained_then_excluded_at_a_later_boundary() {
    let survivor = address!("0x0000000000000000000000000000000000000E11");
    let exiting = address!("0x0000000000000000000000000000000000000E12");
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // The target was frozen at height 10; the exit request lands afterwards.
    storage.set_block_number(11);

    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage);
        vs.config_owner.write(OWNER).unwrap();
        vs.config_max_validators.write(10).unwrap();
        vs.register_validator(OWNER, survivor, &dummy_consensus_pubkey(0xE1))
            .unwrap();
        vs.register_validator(OWNER, exiting, &dummy_consensus_pubkey(0xE2))
            .unwrap();
        activate_staked_for_test(&mut vs, survivor);
        activate_staked_for_test(&mut vs, exiting);

        vs.deactivate_validator(OWNER, exiting).unwrap();
        assert!(matches!(
            vs.validator_lifecycle(exiting).unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));

        // The height-10 frozen target still contains the validator. Retaining it
        // is required: excluding it here would apply post-freeze state to a
        // historical target and make honest nodes disagree about the boundary.
        let retained_hash = B256::with_last_byte(0xE1);
        vs.test_activate_validated_boundary_set(&[survivor, exiting], retained_hash, 10)
            .unwrap();
        assert!(matches!(
            vs.validator_lifecycle(exiting).unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));
        assert!(vs.is_consensus_participant(exiting).unwrap());
        assert!(vs.has_pending_set_change().unwrap());

        // Once the exit is visible at the freeze height, retaining it is an
        // invalid artifact. Verify the failed plan leaves every observed field
        // unchanged before applying the correct exclusion boundary.
        let survivor_before = vs.validator_lifecycle(survivor).unwrap();
        let exiting_before = vs.validator_lifecycle(exiting).unwrap();
        let pending_before = vs.has_pending_set_change().unwrap();
        let hash_before = vs.active_consensus_set_hash().unwrap();
        let err = vs
            .test_activate_validated_boundary_set(
                &[survivor, exiting],
                B256::with_last_byte(0xEE),
                11,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Fatal(message)
                if message.contains("retained validator")
                    && message.contains("exited at 11 before freeze 11")
        ));
        assert_eq!(vs.validator_lifecycle(survivor).unwrap(), survivor_before);
        assert_eq!(vs.validator_lifecycle(exiting).unwrap(), exiting_before);
        assert_eq!(vs.has_pending_set_change().unwrap(), pending_before);
        assert_eq!(vs.active_consensus_set_hash().unwrap(), hash_before);

        let excluded_hash = B256::with_last_byte(0xE2);
        vs.test_activate_validated_boundary_set(&[survivor], excluded_hash, 12)
            .unwrap();
        assert!(matches!(
            vs.validator_lifecycle(exiting).unwrap(),
            ValidatorLifecycle::Unbonding(_)
        ));
        assert!(!vs.is_consensus_participant(exiting).unwrap());
        assert!(!vs.has_pending_set_change().unwrap());
        assert_eq!(vs.active_consensus_set_hash().unwrap(), excluded_hash);
    });
}

#[test]
fn post_freeze_jail_is_retained_then_excluded_at_a_later_boundary() {
    let survivor = address!("0x0000000000000000000000000000000000000A11");
    let jailed = address!("0x0000000000000000000000000000000000000A12");
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // The target was frozen at height 10; punishment lands afterwards.
    storage.set_block_number(11);

    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage);
        vs.config_owner.write(OWNER).unwrap();
        vs.config_max_validators.write(10).unwrap();
        vs.register_validator(OWNER, survivor, &dummy_consensus_pubkey(0xA1))
            .unwrap();
        vs.register_validator(OWNER, jailed, &dummy_consensus_pubkey(0xA2))
            .unwrap();
        activate_staked_for_test(&mut vs, survivor);
        activate_staked_for_test(&mut vs, jailed);

        vs.jail_validator(jailed).unwrap();
        assert!(matches!(
            vs.validator_lifecycle(jailed).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
        assert_eq!(vs.val_jailed_at_height.read(&jailed).unwrap(), 11);

        // The historical height-10 target still contains the newly jailed
        // validator, so this boundary retains its live-share accountability.
        let retained_hash = B256::with_last_byte(0xA1);
        vs.test_activate_validated_boundary_set(&[survivor, jailed], retained_hash, 10)
            .unwrap();
        assert!(matches!(
            vs.validator_lifecycle(jailed).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
        assert!(vs.is_consensus_participant(jailed).unwrap());
        assert!(vs.has_pending_set_change().unwrap());

        // At a freeze that can see the jail, retaining it must fail without
        // committing lifecycle/hash/signal changes.
        let survivor_before = vs.validator_lifecycle(survivor).unwrap();
        let jailed_before = vs.validator_lifecycle(jailed).unwrap();
        let pending_before = vs.has_pending_set_change().unwrap();
        let hash_before = vs.active_consensus_set_hash().unwrap();
        let err = vs
            .test_activate_validated_boundary_set(
                &[survivor, jailed],
                B256::with_last_byte(0xAA),
                11,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PrecompileError::Fatal(message)
                if message.contains("retained validator")
                    && message.contains("jailed at 11 before freeze 11")
        ));
        assert_eq!(vs.validator_lifecycle(survivor).unwrap(), survivor_before);
        assert_eq!(vs.validator_lifecycle(jailed).unwrap(), jailed_before);
        assert_eq!(vs.has_pending_set_change().unwrap(), pending_before);
        assert_eq!(vs.active_consensus_set_hash().unwrap(), hash_before);

        let excluded_hash = B256::with_last_byte(0xA2);
        vs.test_activate_validated_boundary_set(&[survivor], excluded_hash, 12)
            .unwrap();
        assert!(matches!(
            vs.validator_lifecycle(jailed).unwrap(),
            ValidatorLifecycle::Jail(_)
        ));
        assert!(!vs.is_consensus_participant(jailed).unwrap());
        assert!(!vs.has_pending_set_change().unwrap());
        assert_eq!(vs.active_consensus_set_hash().unwrap(), excluded_hash);
    });
}

#[test]
fn tee_expiry_jail_is_non_slashing_and_idempotent() {
    let validator = address!("0x0000000000000000000000000000000000000A13");
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(17);

    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage);
        vs.config_owner.write(OWNER).unwrap();
        vs.config_max_validators.write(10).unwrap();
        vs.register_validator(OWNER, validator, &dummy_consensus_pubkey(0xA3))
            .unwrap();
        activate_staked_for_test(&mut vs, validator);

        let before = vs.get_validator(validator).unwrap().unwrap();
        let before_stake = before.stake;
        let before_slash_count = before.slash_count;

        assert!(vs.jail_validator_for_tee_expiry(validator).unwrap());
        let jailed = vs.get_validator(validator).unwrap().unwrap();
        assert_eq!(jailed.status, status::JAILED);
        assert_eq!(jailed.stake, before_stake);
        assert_eq!(jailed.slash_count, before_slash_count);
        assert_eq!(vs.val_jailed_at_height.read(&validator).unwrap(), 17);
        assert!(vs.has_pending_set_change().unwrap());

        assert!(!vs.jail_validator_for_tee_expiry(validator).unwrap());
        let replayed = vs.get_validator(validator).unwrap().unwrap();
        assert_eq!(replayed, jailed);
        assert_eq!(replayed.stake, before_stake);
        assert_eq!(replayed.slash_count, before_slash_count);

        vs.test_activate_validated_boundary_set(&[], B256::ZERO, 17)
            .unwrap();
        let excluded = vs.get_validator(validator).unwrap().unwrap();
        assert_eq!(excluded.status, status::JAILED);
        assert!(!excluded.has_bls_share);
        assert_eq!(excluded.stake, before_stake);
        assert_eq!(excluded.slash_count, before_slash_count);
        assert!(!vs.is_consensus_participant(validator).unwrap());
    });
}

// ---------------------------------------------------------------------------
// 14. test_pending_set_change
// ---------------------------------------------------------------------------
#[test]
fn test_pending_set_change() {
    let val_addr = address!("0x00000000000000000000000000000000000000E1");

    with_vs_configured(10, |vs| {
        // Initially no pending change
        assert!(!vs.has_pending_set_change().unwrap());

        // Registration triggers pending_set_change
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(0xE1))
            .unwrap();
        assert!(vs.has_pending_set_change().unwrap());

        activate_for_test(vs, val_addr);

        // A valid same-member boundary clears it.
        let group_key = B256::with_last_byte(0xEE);
        vs.activate_reshared_set(&[val_addr], group_key).unwrap();
        assert!(!vs.has_pending_set_change().unwrap());

        // Forced exit triggers pending_set_change
        vs.force_exit_validator(val_addr).unwrap();
        assert!(vs.has_pending_set_change().unwrap());
    });
}

// ---------------------------------------------------------------------------
// 14b. test_pending_set_change_missed_validator
// ---------------------------------------------------------------------------
#[test]
fn test_boundary_rejects_missed_active_validator_atomically() {
    let val1 = address!("0x00000000000000000000000000000000000000A1");
    let val2 = address!("0x00000000000000000000000000000000000000A2");
    let val3 = address!("0x00000000000000000000000000000000000000A3");
    let group_key1 = B256::with_last_byte(0xAA);
    let group_key2 = B256::with_last_byte(0xBB);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xA1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xA2))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(0xA3))
            .unwrap();
        admit_pending(vs, val1, 0xA1);
        admit_pending(vs, val2, 0xA2);
        admit_pending(vs, val3, 0xA3);

        for val in [val1, val2, val3] {
            activate_for_test(vs, val);
        }

        // First reshare: all 3 validators participate -> all ACTIVE.
        vs.activate_reshared_set(&[val1, val2, val3], group_key1)
            .unwrap();
        assert_eq!(vs.val_status.read(&val1).unwrap(), status::ACTIVE);
        assert_eq!(vs.val_status.read(&val2).unwrap(), status::ACTIVE);
        assert_eq!(vs.val_status.read(&val3).unwrap(), status::ACTIVE);
        // All covered -> pending cleared
        assert!(!vs.has_pending_set_change().unwrap());

        // A purported validated boundary may not silently omit an existing
        // ACTIVE participant. The planner rejects it before writing anything.
        assert!(matches!(
            vs.activate_reshared_set(&[val1, val2], group_key2),
            Err(PrecompileError::Fatal(_))
        ));

        // The complete prior committee, hash, and repair signal are unchanged.
        assert!(vs.val_has_bls_share.read(&val1).unwrap());
        assert!(vs.val_has_bls_share.read(&val2).unwrap());
        assert_eq!(vs.val_status.read(&val3).unwrap(), status::ACTIVE);
        assert!(vs.val_has_bls_share.read(&val3).unwrap());
        assert_eq!(vs.active_consensus_set_hash.read().unwrap(), group_key1);
        assert!(!vs.has_pending_set_change().unwrap());
    });
}

// ---------------------------------------------------------------------------
// 15. test_consensus_pubkey_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn test_consensus_pubkey_roundtrip() {
    let val_addr = address!("0x00000000000000000000000000000000000000F1");
    // Build a non-trivial 48-byte key
    let mut pk = [0u8; 48];
    for (i, byte) in pk.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(0x10);
    }

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();
        let record = vs.get_validator(val_addr).unwrap().unwrap();
        assert_eq!(record.consensus_pubkey, pk);
    });
}

// ---------------------------------------------------------------------------
// 16. test_pubkey_hash_lookup
// ---------------------------------------------------------------------------
#[test]
fn test_pubkey_hash_lookup() {
    let val_addr = address!("0x00000000000000000000000000000000000000F2");
    let pk = dummy_consensus_pubkey(0xF2);

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &pk).unwrap();

        let pk_hash = ValidatorSet::consensus_pubkey_hash(&pk);
        let looked_up = vs.lookup_by_pubkey_hash(pk_hash).unwrap();
        assert_eq!(looked_up, val_addr);
    });
}

// ---------------------------------------------------------------------------
// 17. test_reregister_inactive_validator
// ---------------------------------------------------------------------------
#[test]
fn test_reregister_inactive_validator() {
    let val_addr = address!("0x1111111111111111111111111111111111111111");
    let pk_old = dummy_consensus_pubkey(0x11);
    let pk_new = dummy_consensus_pubkey(0x22);

    with_vs_configured(10, |vs| {
        // Register and transition to INACTIVE
        vs.register_validator(OWNER, val_addr, &pk_old).unwrap();
        make_inactive_for_test(vs, val_addr);

        // Re-register with a new pubkey
        vs.register_validator(OWNER, val_addr, &pk_new).unwrap();

        // Status reset to REGISTERED
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::REGISTERED);

        // New pubkey stored
        let record = vs.get_validator(val_addr).unwrap().unwrap();
        assert_eq!(record.consensus_pubkey, pk_new);

        // Old pubkey hash cleared
        let old_hash = ValidatorSet::consensus_pubkey_hash(&pk_old);
        assert_eq!(
            vs.consensus_pubkey_hash_to_address.read(&old_hash).unwrap(),
            Address::ZERO
        );

        // New pubkey hash set
        let new_hash = ValidatorSet::consensus_pubkey_hash(&pk_new);
        assert_eq!(
            vs.consensus_pubkey_hash_to_address.read(&new_hash).unwrap(),
            val_addr
        );

        // Count unchanged (reused existing index)
        assert_eq!(vs.validator_count.read().unwrap(), 1);

        // Counters reset
        assert_eq!(record.slash_count, 0);
        assert_eq!(record.missed_blocks, 0);
        assert!(record.stake.is_zero());
        assert!(!vs.val_join_confirmed.read(&val_addr).unwrap());
        assert_eq!(vs.val_jailed_at_height.read(&val_addr).unwrap(), 0);
    });
}

// ---------------------------------------------------------------------------
// 18. test_reregister_active_fails
// ---------------------------------------------------------------------------
#[test]
fn test_reregister_active_fails() {
    let val_addr = address!("0x2222222222222222222222222222222222222222");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(0x21))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val_addr)
            .unwrap();

        // Re-registration of ACTIVE validator must fail
        let result = vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(0x22));
        assert!(result.is_err());
    });
}

// ---------------------------------------------------------------------------
// 19. test_forced_exit_preserves_staking_lifecycle
// ---------------------------------------------------------------------------
#[test]
fn test_forced_exit_preserves_staking_lifecycle() {
    use alloy_primitives::U256;
    let val_addr = address!("0x3333333333333333333333333333333333333333");

    with_vs_configured(10, |vs| {
        vs.config_min_stake.write(U256::from(1000u64)).unwrap();

        vs.register_validator(OWNER, val_addr, &dummy_consensus_pubkey(0x33))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val_addr)
            .unwrap();

        // Set stake above min then force exit.
        vs.val_stake.write(&val_addr, U256::from(1000u64)).unwrap();
        vs.force_exit_validator(val_addr).unwrap();
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::EXITING);

        // Simulate slash reducing stake below min_stake
        vs.val_stake.write(&val_addr, U256::from(500u64)).unwrap();

        // Forced exit never returns through REGISTERED. Staking moves
        // UNBONDING validators to INACTIVE after withdrawability completes.
        assert_eq!(vs.val_status.read(&val_addr).unwrap(), status::EXITING);
    });
}

// ---------------------------------------------------------------------------
// 20. test_cleanup_inactive_validators
// ---------------------------------------------------------------------------
#[test]
fn test_cleanup_inactive_validators() {
    let val1 = address!("0x00000000000000000000000000000000000000A1");
    let val2 = address!("0x00000000000000000000000000000000000000A2");
    let val3 = address!("0x00000000000000000000000000000000000000A3");
    let val4 = address!("0x00000000000000000000000000000000000000A4");
    let val5 = address!("0x00000000000000000000000000000000000000A5");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xA1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xA2))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(0xA3))
            .unwrap();
        vs.register_validator(OWNER, val4, &dummy_consensus_pubkey(0xA4))
            .unwrap();
        vs.register_validator(OWNER, val5, &dummy_consensus_pubkey(0xA5))
            .unwrap();
        assert_eq!(vs.validator_count.read().unwrap(), 5);

        // Move val2 and val4 through the canonical exit and claim-completion
        // transitions before cleaning their registry slots.
        make_inactive_for_test(vs, val2);
        make_inactive_for_test(vs, val4);

        // Cleanup all INACTIVE entries
        let removed = vs.cleanup_inactive_validators(0).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(vs.validator_count.read().unwrap(), 3);

        // Cleaned-up validators have index 0
        assert_eq!(vs.address_to_index.read(&val2).unwrap(), 0);
        assert_eq!(vs.address_to_index.read(&val4).unwrap(), 0);

        // Remaining validators are still accessible
        assert!(vs.address_to_index.read(&val1).unwrap() > 0);
        assert!(vs.address_to_index.read(&val3).unwrap() > 0);
        assert!(vs.address_to_index.read(&val5).unwrap() > 0);
    });
}

// ---------------------------------------------------------------------------
// 21. test_cleanup_capped
// ---------------------------------------------------------------------------
#[test]
fn test_cleanup_capped() {
    let val1 = address!("0x00000000000000000000000000000000000000B1");
    let val2 = address!("0x00000000000000000000000000000000000000B2");
    let val3 = address!("0x00000000000000000000000000000000000000B3");

    with_vs_configured(10, |vs| {
        vs.register_validator(OWNER, val1, &dummy_consensus_pubkey(0xB1))
            .unwrap();
        vs.register_validator(OWNER, val2, &dummy_consensus_pubkey(0xB2))
            .unwrap();
        vs.register_validator(OWNER, val3, &dummy_consensus_pubkey(0xB3))
            .unwrap();

        // Move all three through canonical INACTIVE records.
        make_inactive_for_test(vs, val1);
        make_inactive_for_test(vs, val2);
        make_inactive_for_test(vs, val3);

        // Cap at 2
        let removed = vs.cleanup_inactive_validators(2).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(vs.validator_count.read().unwrap(), 1);

        // Second call gets the remaining one
        let removed2 = vs.cleanup_inactive_validators(2).unwrap();
        assert_eq!(removed2, 1);
        assert_eq!(vs.validator_count.read().unwrap(), 0);
    });
}

// ---------------------------------------------------------------------------
// P2-3: Re-registration cooldown tests
// ---------------------------------------------------------------------------

#[test]
fn test_reregistration_cooldown_gates_then_allows() {
    // Re-registration is rejected until `config_reregistration_cooldown` blocks
    // pass after deactivation, then allowed. Deactivated at h100, cooldown 1000:
    // rejected at h500 (400 elapsed), allowed at h1100 (1000 elapsed).
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    let val = address!("0x1111111111111111111111111111111111111111");

    storage.set_block_number(100);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(128).unwrap();
        vs.config_reregistration_cooldown.write(1000).unwrap();
        vs.register_validator(OWNER, val, &dummy_consensus_pubkey(0xCC))
            .unwrap();
        make_inactive_for_test(&mut vs, val);
    });

    // h500: only 400 blocks elapsed -> rejected with a cooldown error.
    storage.set_block_number(500);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        let err = vs
            .register_validator(OWNER, val, &dummy_consensus_pubkey(0xDD))
            .unwrap_err();
        assert!(
            err.to_string().contains("cooldown"),
            "error should mention cooldown"
        );
    });

    // h1100: 1000 blocks elapsed -> allowed.
    storage.set_block_number(1100);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.register_validator(OWNER, val, &dummy_consensus_pubkey(0xFF))
            .unwrap();
        assert_eq!(vs.val_status.read(&val).unwrap(), status::REGISTERED);
    });
}

#[test]
fn test_reregistration_no_cooldown_configured() {
    with_vs_configured(128, |vs| {
        let val = address!("0x3333333333333333333333333333333333333333");
        let pk = dummy_consensus_pubkey(0xAA);

        // cooldown = 0 (default)
        assert_eq!(vs.config_reregistration_cooldown.read().unwrap(), 0);

        vs.register_validator(OWNER, val, &pk).unwrap();
        make_inactive_for_test(vs, val);

        // Re-register immediately - should succeed (no cooldown)
        let pk_new = dummy_consensus_pubkey(0xBB);
        vs.register_validator(OWNER, val, &pk_new).unwrap();
        assert_eq!(vs.val_status.read(&val).unwrap(), status::REGISTERED);
    });
}

// ---------------------------------------------------------------------------
// Task 04: validator join race tests
// ---------------------------------------------------------------------------

#[test]
fn test_confirm_ready_signals_pending_until_certified_boundary() {
    with_vs_configured(128, |vs| {
        let val = address!("0x1111111111111111111111111111111111111111");
        let pk = dummy_consensus_pubkey(0x01);

        // Register -> REGISTERED, pending_set_change = true
        vs.register_validator(OWNER, val, &pk).unwrap();
        assert!(vs.has_pending_set_change().unwrap());

        // Simulate reshare completed (without this validator, they had no stake).
        // activate_reshared_set with empty set -> clears pending.
        vs.activate_reshared_set(&[], B256::with_last_byte(0x01))
            .unwrap();
        assert!(!vs.has_pending_set_change().unwrap());

        // Staking and confirm-ready signal that a new certified boundary is due.
        vs.mark_pending(val).unwrap();
        confirm_ready(vs, val, 0x01);
        assert!(vs.has_pending_set_change().unwrap());

        // The shared helper drives the certified boundary and clears the signal
        // once the admitted validator is part of the complete ACTIVE set.
        vs.activate_validator_via_boundary_for_test(val).unwrap();
        assert_eq!(vs.val_status.read(&val).unwrap(), status::ACTIVE);
        assert!(
            !vs.has_pending_set_change().unwrap(),
            "certified boundary must clear the covered set-change signal"
        );
    });
}

#[test]
fn test_activate_reshared_set_clears_pending_after_join() {
    // After a new validator is activated and reshare includes them,
    // pending_set_change should be cleared.
    with_vs_configured(128, |vs| {
        let val = address!("0x1111111111111111111111111111111111111111");
        let pk = dummy_consensus_pubkey(0x01);

        vs.register_validator(OWNER, val, &pk).unwrap();
        vs.mark_pending(val).unwrap();
        confirm_ready(vs, val, 0x02);
        assert!(vs.has_pending_set_change().unwrap());

        // The production boundary path now includes the admitted validator.
        vs.activate_validator_via_boundary_for_test(val).unwrap();
        assert!(
            !vs.has_pending_set_change().unwrap(),
            "pending should be cleared after reshare includes all active validators"
        );
    });
}

#[test]
fn test_admitted_non_consensus_includes_registered_and_pending_not_active() {
    // TEE full-node admission: the secondary-tier P2P set must
    // contain REGISTERED (full-node, not staked) + PENDING (staked joiner), but NOT
    // ACTIVE (already a primary peer). The reshare target is the mirror image
    // ({ACTIVE, PENDING}) - REGISTERED must never be a reshare player (no stake).
    with_vs_configured(128, |vs| {
        let reg = address!("0x1111111111111111111111111111111111111111");
        let pend = address!("0x2222222222222222222222222222222222222222");
        let act = address!("0x3333333333333333333333333333333333333333");

        vs.register_validator(OWNER, reg, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.register_validator(OWNER, pend, &dummy_consensus_pubkey(0x02))
            .unwrap();
        vs.mark_pending(pend).unwrap();
        vs.register_validator(OWNER, act, &dummy_consensus_pubkey(0x03))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(act).unwrap();

        let admitted: Vec<_> = vs
            .get_admitted_non_consensus_validators()
            .unwrap()
            .into_iter()
            .map(|v| v.validator_address)
            .collect();
        assert!(
            admitted.contains(&reg),
            "REGISTERED full-node must be admitted"
        );
        assert!(admitted.contains(&pend), "PENDING joiner must be admitted");
        assert!(
            !admitted.contains(&act),
            "ACTIVE validator is a primary peer, not secondary"
        );

        // Stale-join guard: a freshly-PENDING joiner is NOT yet in the reshare
        // target until it confirms readiness; ACTIVE is always in.
        let reshare_before: Vec<_> = vs
            .get_reshare_target_set()
            .unwrap()
            .into_iter()
            .map(|v| v.validator_address)
            .collect();
        assert!(
            !reshare_before.contains(&reg),
            "REGISTERED (unstaked) must NOT be a reshare player"
        );
        assert!(
            !reshare_before.contains(&pend),
            "unconfirmed PENDING joiner must NOT be a reshare player (stale-join guard)"
        );
        assert!(reshare_before.contains(&act));

        // After confirming readiness the PENDING joiner enters the target.
        confirm_ready(vs, pend, 0x12);
        let reshare_after: Vec<_> = vs
            .get_reshare_target_set()
            .unwrap()
            .into_iter()
            .map(|v| v.validator_address)
            .collect();
        assert!(
            reshare_after.contains(&pend) && reshare_after.contains(&act),
            "confirmed PENDING joiner + ACTIVE must both be reshare players"
        );
    });
}

#[test]
fn test_confirm_validator_ready_requires_pending() {
    // confirmValidatorReady is only valid from PENDING; REGISTERED and ACTIVE revert.
    with_vs_configured(128, |vs| {
        let reg = address!("0x1111111111111111111111111111111111111111");
        let act = address!("0x3333333333333333333333333333333333333333");
        vs.register_validator(OWNER, reg, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.register_validator(OWNER, act, &dummy_consensus_pubkey(0x03))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(act).unwrap();

        assert!(
            vs.confirm_validator_ready(reg, &[]).is_err(),
            "REGISTERED cannot confirm readiness"
        );
        assert!(
            vs.confirm_validator_ready(act, &[]).is_err(),
            "ACTIVE cannot confirm readiness"
        );
        let unregistered = address!("0x9999999999999999999999999999999999999999");
        assert!(
            vs.confirm_validator_ready(unregistered, &[]).is_err(),
            "unregistered address cannot confirm readiness"
        );
    });
}

#[test]
fn confirm_ready_persists_valid_ocomp_registration_before_readiness() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5555555555555555555555555555555555555555");
        let consensus_pubkey = dummy_consensus_pubkey(0x55);
        vs.register_validator(OWNER, validator, &consensus_pubkey)
            .unwrap();
        vs.mark_pending(validator).unwrap();
        let (registration, encoded) = ocomp_registration(validator, &consensus_pubkey, 0x56);

        vs.confirm_validator_ready(validator, &encoded).unwrap();

        assert_eq!(
            vs.ocomp_registration(validator).unwrap(),
            Some(registration.clone())
        );
        let key_hash = keccak256(registration.core.ocomp_public_key_sec1);
        assert_eq!(
            vs.ocomp_key_hash_to_validator.read(&key_hash).unwrap(),
            validator
        );
        assert!(vs.val_join_confirmed.read(&validator).unwrap());
    });
}

#[test]
fn confirm_ready_exact_replay_rejects_ocomp_key_replacement_atomically() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5656565656565656565656565656565656565656");
        let consensus_pubkey = dummy_consensus_pubkey(0x56);
        vs.register_validator(OWNER, validator, &consensus_pubkey)
            .unwrap();
        vs.mark_pending(validator).unwrap();
        let (first, first_encoded) = ocomp_registration(validator, &consensus_pubkey, 0x57);
        vs.confirm_validator_ready(validator, &first_encoded)
            .unwrap();

        vs.confirm_validator_ready(validator, &first_encoded)
            .expect("byte-identical registration replay");

        let (replacement, replacement_encoded) =
            ocomp_registration(validator, &consensus_pubkey, 0x58);
        let error = vs
            .confirm_validator_ready(validator, &replacement_encoded)
            .expect_err("V1 OCOMP key is immutable after first admission");
        assert!(error.to_string().contains("OCOMP public key is immutable"));

        assert_eq!(
            vs.ocomp_registration(validator).unwrap(),
            Some(first.clone()),
            "failed replacement preserves the original registration"
        );
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&keccak256(first.core.ocomp_public_key_sec1))
                .unwrap(),
            validator
        );
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&keccak256(replacement.core.ocomp_public_key_sec1))
                .unwrap(),
            Address::ZERO
        );
        assert!(vs.val_join_confirmed.read(&validator).unwrap());
    });
}

#[test]
fn reshare_target_requires_registration_even_if_readiness_flag_is_set() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5757575757575757575757575757575757575757");
        vs.register_validator(OWNER, validator, &dummy_consensus_pubkey(0x57))
            .unwrap();
        vs.mark_pending(validator).unwrap();

        // Model a stale/legacy/corrupt flag without the registration whose
        // admission must now be authoritative.
        vs.val_join_confirmed.write(&validator, true).unwrap();

        assert!(
            !vs.get_reshare_target_set()
                .unwrap()
                .iter()
                .any(|record| record.validator_address == validator),
            "readiness without a canonical OCOMP registration must fail closed"
        );
    });
}

#[test]
fn bls_key_change_preserves_ocomp_pin_and_requires_same_key_identity_refresh() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5858585858585858585858585858585858585858");
        let first_consensus_pubkey = dummy_consensus_pubkey(0x58);
        vs.register_validator(OWNER, validator, &first_consensus_pubkey)
            .unwrap();
        vs.mark_pending(validator).unwrap();
        let (registration, encoded) = ocomp_registration(validator, &first_consensus_pubkey, 0x59);
        vs.confirm_validator_ready(validator, &encoded).unwrap();
        let old_ocomp_key_hash = keccak256(registration.core.ocomp_public_key_sec1);

        make_inactive_for_test(vs, validator);
        let replacement_consensus_pubkey = dummy_consensus_pubkey(0x5A);
        vs.register_validator(OWNER, validator, &replacement_consensus_pubkey)
            .unwrap();

        assert_eq!(
            vs.ocomp_registration(validator).unwrap(),
            Some(registration.clone())
        );
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&old_ocomp_key_hash)
                .unwrap(),
            validator
        );
        assert!(!vs.val_join_confirmed.read(&validator).unwrap());
        assert_eq!(vs.val_status.read(&validator).unwrap(), status::REGISTERED);

        vs.mark_pending(validator).unwrap();
        let (refreshed, refreshed_encoded) =
            ocomp_registration(validator, &replacement_consensus_pubkey, 0x59);
        vs.confirm_validator_ready(validator, &refreshed_encoded)
            .expect("new BLS identity may refresh PoP only with the pinned OCOMP key");
        assert_eq!(
            refreshed.core.ocomp_public_key_sec1,
            registration.core.ocomp_public_key_sec1
        );
        assert_eq!(vs.ocomp_registration(validator).unwrap(), Some(refreshed));
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&old_ocomp_key_hash)
                .unwrap(),
            validator
        );
        assert!(vs.val_join_confirmed.read(&validator).unwrap());
    });
}

#[test]
fn full_validator_cleanup_preserves_immutable_ocomp_registration_and_key_pin() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5959595959595959595959595959595959595959");
        let consensus_pubkey = dummy_consensus_pubkey(0x59);
        vs.register_validator(OWNER, validator, &consensus_pubkey)
            .unwrap();
        vs.mark_pending(validator).unwrap();
        let (registration, encoded) = ocomp_registration(validator, &consensus_pubkey, 0x5A);
        vs.confirm_validator_ready(validator, &encoded).unwrap();
        let ocomp_key_hash = keccak256(registration.core.ocomp_public_key_sec1);
        make_inactive_for_test(vs, validator);

        assert_eq!(vs.cleanup_inactive_validators(1).unwrap(), 1);

        assert_eq!(
            vs.ocomp_registration(validator).unwrap(),
            Some(registration)
        );
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&ocomp_key_hash)
                .unwrap(),
            validator
        );
        assert_eq!(vs.address_to_index.read(&validator).unwrap(), 0);

        let squatter = Address::repeat_byte(0x5A);
        let squatter_consensus_pubkey = dummy_consensus_pubkey(0x5B);
        vs.register_validator(OWNER, squatter, &squatter_consensus_pubkey)
            .unwrap();
        vs.mark_pending(squatter).unwrap();
        let (_, squatter_registration) =
            ocomp_registration(squatter, &squatter_consensus_pubkey, 0x5A);
        let error = vs
            .confirm_validator_ready(squatter, &squatter_registration)
            .expect_err("cleanup must not make the pinned OCOMP key squattable");
        assert!(error
            .to_string()
            .contains("already registered by another validator"));
        assert_eq!(
            vs.ocomp_key_hash_to_validator
                .read(&ocomp_key_hash)
                .unwrap(),
            validator
        );
    });
}

#[test]
fn certified_activation_rejects_registered_and_keyless_pending_members() {
    let registered = Address::repeat_byte(0x5A);
    with_vs_configured(128, |vs| {
        vs.register_validator(OWNER, registered, &dummy_consensus_pubkey(0x5A))
            .unwrap();
        let error = vs
            .activate_reshared_set(&[registered], B256::repeat_byte(0xA1))
            .unwrap_err();
        assert!(matches!(error, PrecompileError::Fatal(_)));
        assert_eq!(vs.val_status.read(&registered).unwrap(), status::REGISTERED);
    });

    let pending = Address::repeat_byte(0x5B);
    with_vs_configured(128, |vs| {
        vs.register_validator(OWNER, pending, &dummy_consensus_pubkey(0x5B))
            .unwrap();
        vs.mark_pending(pending).unwrap();
        vs.val_join_confirmed.write(&pending, true).unwrap();
        let error = vs
            .activate_reshared_set(&[pending], B256::repeat_byte(0xA2))
            .unwrap_err();
        assert!(matches!(error, PrecompileError::Fatal(_)));
        assert_eq!(vs.val_status.read(&pending).unwrap(), status::PENDING);
        assert!(!vs.val_has_bls_share.read(&pending).unwrap());
    });
}

#[test]
fn test_stale_join_guard_resets_on_restake() {
    // A re-staked validator (PENDING->...->PENDING) must re-confirm: mark_pending
    // clears the confirmed flag so a stale prior confirmation cannot leak through.
    with_vs_configured(128, |vs| {
        let pend = address!("0x2222222222222222222222222222222222222222");
        vs.register_validator(OWNER, pend, &dummy_consensus_pubkey(0x02))
            .unwrap();
        vs.mark_pending(pend).unwrap();
        confirm_ready(vs, pend, 0x22);
        let in_target = |vs: &mut crate::schema::ValidatorSet, addr| {
            vs.get_reshare_target_set()
                .unwrap()
                .into_iter()
                .any(|v| v.validator_address == addr)
        };
        assert!(in_target(vs, pend), "confirmed PENDING is in the target");

        // Promotion clears the flag; demote back to REGISTERED then re-PENDING.
        vs.activate_reshared_set(&[pend], B256::ZERO).unwrap();
        // Force back to REGISTERED to simulate a churn that returns it to PENDING.
        vs.deactivate_validator(OWNER, pend).unwrap();
        vs.activate_reshared_set(&[], B256::ZERO).unwrap(); // EXITING->UNBONDING
                                                            // A fresh registration+stake cycle starts unconfirmed.
        let pend2 = address!("0x4444444444444444444444444444444444444444");
        vs.register_validator(OWNER, pend2, &dummy_consensus_pubkey(0x04))
            .unwrap();
        vs.mark_pending(pend2).unwrap();
        assert!(
            !in_target(vs, pend2),
            "freshly re-PENDING joiner must NOT be in the target without re-confirming"
        );
    });
}

#[test]
fn inactive_reentry_with_same_bls_requires_fresh_ocomp_confirmation() {
    with_vs_configured(128, |vs| {
        let validator = address!("0x5555555555555555555555555555555555555555");
        let consensus_pubkey = dummy_consensus_pubkey(0x55);
        let (_, encoded_registration) = ocomp_registration(validator, &consensus_pubkey, 0x55);

        vs.register_validator(OWNER, validator, &consensus_pubkey)
            .unwrap();
        vs.mark_pending(validator).unwrap();
        vs.confirm_validator_ready(validator, &encoded_registration)
            .unwrap();
        vs.activate_validator_via_boundary_for_test(validator)
            .unwrap();

        make_inactive_for_test(vs, validator);
        vs.register_validator(OWNER, validator, &consensus_pubkey)
            .unwrap();
        assert_eq!(vs.val_status.read(&validator).unwrap(), status::REGISTERED);
        assert!(!vs.val_join_confirmed.read(&validator).unwrap());
        assert_eq!(
            vs.ocomp_registration(validator).unwrap().unwrap(),
            OcompKeyRegistrationV1::decode_canonical(&encoded_registration, &poc_schema_limits())
                .unwrap(),
            "same-BLS re-entry retains the identity-bound registration for exact replay"
        );

        vs.mark_pending(validator).unwrap();
        assert!(
            vs.get_reshare_target_set().unwrap().is_empty(),
            "re-entry must remain outside DKG until readiness is confirmed again"
        );

        vs.confirm_validator_ready(validator, &encoded_registration)
            .unwrap();
        assert_eq!(
            vs.get_reshare_target_set()
                .unwrap()
                .into_iter()
                .map(|record| record.validator_address)
                .collect::<Vec<_>>(),
            vec![validator]
        );
    });
}

#[test]
fn certified_tee_expiry_demotes_active_and_clears_pending_readiness() {
    with_vs_configured(128, |vs| {
        let active = address!("0x1111111111111111111111111111111111111111");
        let pending = address!("0x2222222222222222222222222222222222222222");
        vs.register_validator(OWNER, active, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator(active).unwrap();
        vs.register_validator(OWNER, pending, &dummy_consensus_pubkey(0x02))
            .unwrap();
        vs.mark_pending(pending).unwrap();
        confirm_ready(vs, pending, 0x32);

        vs.test_activate_validated_boundary_set_with_expiry_exclusions(
            &[],
            B256::with_last_byte(0xA2),
            u64::MAX,
            &[active, pending],
        )
        .unwrap();

        for validator in [active, pending] {
            assert_eq!(vs.val_status.read(&validator).unwrap(), status::PENDING);
            assert!(!vs.val_has_bls_share.read(&validator).unwrap());
            assert!(!vs.val_join_confirmed.read(&validator).unwrap());
        }
        assert!(vs.get_reshare_target_set().unwrap().is_empty());

        // Renewal alone does not touch ValidatorSet readiness. Explicit operator
        // confirmation is required before either validator can return to target.
        confirm_ready(vs, active, 0x31);
        confirm_ready(vs, pending, 0x32);
        let target: Vec<_> = vs
            .get_reshare_target_set()
            .unwrap()
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
        assert_eq!(target, vec![active, pending]);
    });
}

#[test]
fn ordinary_dkg_omission_without_expiry_proof_is_rejected_atomically() {
    with_vs_configured(128, |vs| {
        let active = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, active, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator(active).unwrap();
        let hash_before = vs.active_consensus_set_hash().unwrap();
        assert!(vs
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &[],
                B256::with_last_byte(0xB2),
                u64::MAX,
                &[],
            )
            .is_err());

        assert_eq!(vs.val_status.read(&active).unwrap(), status::ACTIVE);
        assert!(vs.val_has_bls_share.read(&active).unwrap());
        assert_eq!(vs.active_consensus_set_hash().unwrap(), hash_before);
    });
}

#[test]
fn expiry_branch_rejects_contradictory_duplicate_and_unknown_authority() {
    with_vs_configured(128, |vs| {
        let active = address!("0x1111111111111111111111111111111111111111");
        let unknown = address!("0x9999999999999999999999999999999999999999");
        vs.register_validator(OWNER, active, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator(active).unwrap();

        assert!(vs
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &[active],
                B256::with_last_byte(0xC2),
                u64::MAX,
                &[active],
            )
            .is_err());
        assert!(vs
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &[],
                B256::with_last_byte(0xC2),
                u64::MAX,
                &[active, active],
            )
            .is_err());
        assert!(vs
            .test_activate_validated_boundary_set_with_expiry_exclusions(
                &[],
                B256::with_last_byte(0xC2),
                u64::MAX,
                &[unknown],
            )
            .is_err());

        assert_eq!(vs.val_status.read(&active).unwrap(), status::ACTIVE);
        assert!(vs.val_has_bls_share.read(&active).unwrap());
    });
}

#[test]
fn test_jail_validator_from_active() {
    with_vs_configured(128, |vs| {
        let v = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(v).unwrap();
        vs.val_has_bls_share.write(&v, true).unwrap();
        assert!(vs.is_consensus_participant(v).unwrap());

        vs.jail_validator(v).unwrap();
        assert_eq!(vs.val_status.read(&v).unwrap(), status::JAILED);
        assert_eq!(vs.val_slash_count.read(&v).unwrap(), 1);
        assert!(vs.has_pending_set_change().unwrap());
        // Still accountable in the live committee until the next reshare clears the
        // share (same as EXITING) - so current-epoch metadata does not Fatal.
        assert!(vs.is_consensus_participant(v).unwrap());
        // Excluded from the NEXT reshare target.
        assert!(!vs
            .get_reshare_target_set()
            .unwrap()
            .iter()
            .any(|r| r.validator_address == v));
        // Still admitted to P2P as a non-voting follower so it keeps syncing.
        assert!(vs
            .get_admitted_non_consensus_validators()
            .unwrap()
            .iter()
            .any(|r| r.validator_address == v));
    });
}

#[test]
fn test_jailed_loses_share_at_reshare() {
    with_vs_configured(128, |vs| {
        let v = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(v).unwrap();
        vs.val_has_bls_share.write(&v, true).unwrap();
        vs.jail_validator(v).unwrap();

        // A reshare that does not include the jailed validator clears its share
        // (clear-all loop) and it stops being a participant - but stays JAILED.
        vs.activate_reshared_set(&[], B256::ZERO).unwrap();
        assert!(!vs.val_has_bls_share.read(&v).unwrap());
        assert!(!vs.is_consensus_participant(v).unwrap());
        assert_eq!(vs.val_status.read(&v).unwrap(), status::JAILED);
    });
}

#[test]
fn test_unjail_after_exclusion_returns_to_unconfirmed_pending() {
    with_vs_configured(128, |vs| {
        let v = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(v).unwrap();
        vs.val_has_bls_share.write(&v, true).unwrap();
        vs.val_missed_blocks.write(&v, 7).unwrap();
        vs.val_missed_votes.write(&v, 9).unwrap();
        vs.jail_validator(v).unwrap();

        // A retained jailed member cannot be unjailed before the committee
        // boundary has removed its old share.
        assert!(vs.unjail_to_pending(v).is_err());
        vs.activate_reshared_set(&[], B256::ZERO).unwrap();
        vs.unjail_to_pending(v).unwrap();
        assert_eq!(vs.val_status.read(&v).unwrap(), status::PENDING);
        assert_eq!(vs.val_jailed_at_height.read(&v).unwrap(), 0);
        assert_eq!(vs.val_missed_blocks.read(&v).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&v).unwrap(), 0);
        // Must re-confirm readiness before re-entering the reshare target.
        assert!(!vs.val_join_confirmed.read(&v).unwrap());
        assert!(!vs
            .get_reshare_target_set()
            .unwrap()
            .iter()
            .any(|r| r.validator_address == v));
        vs.admit_validator_for_boundary_for_test(v)
            .expect("unjail replays the pinned OCOMP registration");
        assert!(vs
            .get_reshare_target_set()
            .unwrap()
            .iter()
            .any(|r| r.validator_address == v));
    });
}

#[test]
fn excluded_jail_accepts_late_finalized_participation_then_unjail_clears_it() {
    with_vs_configured(128, |vs| {
        let v = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator(v).unwrap();
        vs.val_has_bls_share.write(&v, true).unwrap();
        vs.val_missed_blocks.write(&v, 7).unwrap();
        vs.val_missed_votes.write(&v, 9).unwrap();
        vs.jail_validator(v).unwrap();

        vs.activate_reshared_set(&[], B256::ZERO).unwrap();
        assert_eq!(vs.val_missed_blocks.read(&v).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&v).unwrap(), 0);

        // A late certificate for the historical committee may arrive after the
        // exclusion boundary. The excluded Jail state must remain decodable.
        vs.record_finalized_participation(&[], &[v]).unwrap();
        assert_eq!(vs.val_missed_votes.read(&v).unwrap(), 1);
        let jailed = vs.validator_state(v).unwrap();
        assert!(matches!(jailed.lifecycle(), ValidatorLifecycle::Jail(_)));
        assert_eq!(jailed.history().unwrap().missed_votes(), 1);

        // Rejoining always starts from a clean per-epoch miss slate, including
        // late historical misses recorded after exclusion.
        vs.unjail_to_pending(v).unwrap();
        assert_eq!(vs.val_missed_blocks.read(&v).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&v).unwrap(), 0);
    });
}

#[test]
fn test_unjail_requires_jailed_status() {
    with_vs_configured(128, |vs| {
        let active = address!("0x1111111111111111111111111111111111111111");
        vs.register_validator(OWNER, active, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(active).unwrap();
        assert!(
            vs.unjail_to_pending(active).is_err(),
            "cannot unjail an ACTIVE validator"
        );
        let reg = address!("0x2222222222222222222222222222222222222222");
        vs.register_validator(OWNER, reg, &dummy_consensus_pubkey(0x02))
            .unwrap();
        assert!(
            vs.unjail_to_pending(reg).is_err(),
            "cannot unjail a REGISTERED validator"
        );
    });
}

#[test]
fn test_unjail_cooldown_blocks() {
    use outbe_primitives::storage::StorageHandle;
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    let v = address!("0x1111111111111111111111111111111111111111");
    storage.set_block_number(100);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(128).unwrap();
        vs.config_unjail_cooldown_blocks.write(50).unwrap();
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(v).unwrap();
        vs.val_has_bls_share.write(&v, true).unwrap();
        vs.jail_validator(v).unwrap();
        assert_eq!(vs.val_jailed_at_height.read(&v).unwrap(), 100);
        vs.activate_reshared_set(&[], B256::ZERO).unwrap();
        // 100 < 100 + 50 -> still in cooldown.
        assert!(
            vs.unjail_to_pending(v).is_err(),
            "unjail must fail before the cooldown elapses"
        );
    });
    storage.set_block_number(150);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        // 150 >= 100 + 50 -> cooldown elapsed.
        vs.unjail_to_pending(v).unwrap();
        assert_eq!(vs.val_status.read(&v).unwrap(), status::PENDING);
    });
}

#[test]
fn test_already_active_validator_does_not_raise_pending() {
    // Calling activate_validator on an already-ACTIVE validator is a no-op.
    with_vs_configured(128, |vs| {
        let val = address!("0x1111111111111111111111111111111111111111");
        let pk = dummy_consensus_pubkey(0x01);

        vs.register_validator(OWNER, val, &pk).unwrap();
        vs.activate_validator_via_boundary_for_test(val).unwrap();

        // Clear pending by completing reshare.
        vs.activate_reshared_set(&[val], B256::with_last_byte(0x01))
            .unwrap();
        assert!(!vs.has_pending_set_change().unwrap());

        // Calling activate_validator again should NOT re-raise pending.
        vs.activate_validator_via_boundary_for_test(val).unwrap();
        assert!(
            !vs.has_pending_set_change().unwrap(),
            "already-active validator should not trigger spurious pending_set_change"
        );
    });
}

#[test]
fn ocomp_miss_opens_one_fixed_recovery_window_and_repeats_do_not_extend_it() {
    let validator = address!("0x9191919191919191919191919191919191919191");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(100);

    StorageHandle::enter(&mut provider, |storage| {
        let mut validators = ValidatorSet::new(storage.clone());
        validators.config_owner.write(OWNER).unwrap();
        validators.set_config_max_validators(1).unwrap();
        validators
            .register_validator(OWNER, validator, &dummy_consensus_pubkey(0x91))
            .unwrap();
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();

        let first = validators.record_ocomp_miss(validator).unwrap();
        assert_eq!(
            first,
            crate::runtime::OcompMissRecord::Opened {
                miss_count: 1,
                recovery_deadline: 43_300,
            }
        );
        assert_eq!(
            validators
                .val_ocomp_recovery_deadline
                .read(&validator)
                .unwrap(),
            43_300
        );
    });

    provider.set_block_number(101);
    StorageHandle::enter(&mut provider, |storage| {
        let mut validators = ValidatorSet::new(storage);
        let repeated = validators.record_ocomp_miss(validator).unwrap();
        assert_eq!(
            repeated,
            crate::runtime::OcompMissRecord::Repeated {
                miss_count: 2,
                recovery_deadline: 43_300,
            }
        );
        assert_eq!(
            validators
                .val_ocomp_recovery_deadline
                .read(&validator)
                .unwrap(),
            43_300
        );
    });
}

#[test]
fn validator_reregistration_cannot_erase_an_open_ocomp_recovery_window() {
    with_vs_configured(1, |validators| {
        let validator = address!("0x9292929292929292929292929292929292929292");
        let public_key = dummy_consensus_pubkey(0x92);
        validators
            .register_validator(OWNER, validator, &public_key)
            .unwrap();
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        validators.record_ocomp_miss(validator).unwrap();
        make_inactive_for_test(validators, validator);
        assert!(validators
            .ocomp_recovery_window(validator)
            .unwrap()
            .is_some());

        assert!(matches!(
            validators.register_validator(OWNER, validator, &public_key),
            Err(PrecompileError::Revert(message))
                if message.contains("OCOMP recovery window is open")
        ));
        assert!(validators
            .ocomp_recovery_window(validator)
            .unwrap()
            .is_some());
        assert_eq!(validators.val_ocomp_miss_count.read(&validator).unwrap(), 1);
        assert_eq!(validators.cleanup_inactive_validators(1).unwrap(), 0);
        assert!(validators.get_validator(validator).unwrap().is_some());
    });
}

// ===========================================================================
// Forced-exit validator status guard tests
// ===========================================================================

#[test]
fn force_exit_from_each_status() {
    // force_exit_validator across every starting status: ACTIVE->EXITING, an
    // already-EXITING idempotent call, the UNBONDING/INACTIVE idempotent no-ops,
    // and the REGISTERED rejection.
    let val = address!("0x0909090909090909090909090909090909090909");
    #[derive(Clone, Copy)]
    enum Setup {
        Active,
        Exiting,
        Unbonding,
        Inactive,
        Registered,
    }
    let cases: &[(&str, Setup, bool, u8)] = &[
        ("ACTIVE -> EXITING", Setup::Active, true, status::EXITING),
        ("EXITING idempotent", Setup::Exiting, true, status::EXITING),
        (
            "UNBONDING idempotent",
            Setup::Unbonding,
            true,
            status::UNBONDING,
        ),
        (
            "INACTIVE idempotent",
            Setup::Inactive,
            true,
            status::INACTIVE,
        ),
        (
            "REGISTERED rejected",
            Setup::Registered,
            false,
            status::REGISTERED,
        ),
    ];
    for (i, (label, setup, expect_ok, final_status)) in cases.iter().enumerate() {
        with_vs_configured(10, |vs| {
            vs.register_validator(OWNER, val, &dummy_consensus_pubkey(90 + i as u8))
                .unwrap();
            match setup {
                Setup::Active => activate_for_test(vs, val),
                Setup::Exiting => {
                    activate_for_test(vs, val);
                    vs.force_exit_validator(val).unwrap();
                }
                Setup::Unbonding => {
                    activate_for_test(vs, val);
                    vs.deactivate_validator(OWNER, val).unwrap();
                    vs.activate_reshared_set(&[], B256::ZERO).unwrap();
                }
                Setup::Inactive => make_inactive_for_test(vs, val),
                Setup::Registered => {}
            }
            assert_eq!(
                vs.force_exit_validator(val).is_ok(),
                *expect_ok,
                "case '{label}': result mismatch"
            );
            if *expect_ok {
                assert_eq!(
                    vs.val_status.read(&val).unwrap(),
                    *final_status,
                    "case '{label}': final status"
                );
            }
        });
    }
}

#[test]
fn test_repeated_force_exit_remains_exiting() {
    with_vs_configured(10, |vs| {
        let val = address!("0x0909090909090909090909090909090909090909");
        vs.register_validator(OWNER, val, &dummy_consensus_pubkey(92))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val).unwrap();
        vs.force_exit_validator(val).unwrap();
        vs.force_exit_validator(val).unwrap();
        assert_eq!(vs.val_status.read(&val).unwrap(), status::EXITING);
        assert_eq!(vs.val_slash_count.read(&val).unwrap(), 1);
    });
}

// ===========================================================================
// BLS pubkey uniqueness tests
// ===========================================================================

#[test]
fn test_duplicate_pubkey_rejected() {
    with_vs_configured(10, |vs| {
        let val_a = address!("0x1818181818181818181818181818181818181818");
        let val_b = address!("0x1919191919191919191919191919191919191919");
        let pk = dummy_consensus_pubkey(18);

        vs.register_validator(OWNER, val_a, &pk).unwrap();
        // Same pubkey for different validator must fail
        let result = vs.register_validator(OWNER, val_b, &pk);
        assert!(result.is_err(), "duplicate BLS pubkey must be rejected");
    });
}

// ===========================================================================
// Activate validator status guard tests
// ===========================================================================

#[test]
fn activate_rejected_from_non_promotable_status() {
    // activate_validator only promotes REGISTERED/PENDING. EXITING (reached either
    // via force_exit or written directly), UNBONDING, and INACTIVE are all rejected.
    let val = address!("0x2121212121212121212121212121212121212121");
    let cases: &[(&str, u8)] = &[
        ("EXITING", status::EXITING),
        ("UNBONDING", status::UNBONDING),
        ("INACTIVE", status::INACTIVE),
    ];
    for (i, (label, s)) in cases.iter().enumerate() {
        with_vs_configured(10, |vs| {
            vs.register_validator(OWNER, val, &dummy_consensus_pubkey(21 + i as u8))
                .unwrap();
            vs.val_status.write(&val, *s).unwrap();
            assert!(
                vs.activate_validator_via_boundary_for_test(val).is_err(),
                "case '{label}': activate must be rejected"
            );
        });
    }
}

// ===========================================================================
// EXITING validators get per-epoch counters reset
// ===========================================================================

#[test]
fn test_epoch_reset_includes_exiting() {
    with_vs_configured(10, |vs| {
        let val = address!("0x4444444444444444444444444444444444444444");
        vs.register_validator(OWNER, val, &dummy_consensus_pubkey(44))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(val).unwrap();

        // Accumulate counters then transition to EXITING
        vs.val_missed_blocks.write(&val, 10).unwrap();
        vs.val_missed_votes.write(&val, 5).unwrap();
        vs.val_blocks_proposed.write(&val, 3).unwrap();
        vs.deactivate_validator(OWNER, val).unwrap();

        // Epoch transition should reset counters even for EXITING
        vs.update_epoch(1000, 42).unwrap();

        assert_eq!(vs.val_missed_blocks.read(&val).unwrap(), 0);
        assert_eq!(vs.val_missed_votes.read(&val).unwrap(), 0);
        assert_eq!(vs.val_blocks_proposed.read(&val).unwrap(), 0);
    });
}

// ===========================================================================
// Invalid BLS signature rejected for self-registration
// ===========================================================================

#[test]
fn test_register_self_invalid_sig_rejected() {
    with_vs_configured(10, |vs| {
        let val = address!("0x4545454545454545454545454545454545454545");
        let pk = dummy_consensus_pubkey(45);
        let bad_sig = [0xFFu8; 96]; // garbage signature

        let result = vs.register_validator_with_sig(
            val,
            val,
            &pk,
            test_radicle_node_id(val),
            Some(&bad_sig),
        );
        assert!(result.is_err(), "invalid BLS sig must be rejected");
    });
}

/// Valid self-registration with correct BLS signature succeeds.
// the free, permissionless self-registration surface is capped at
// MAX_SELF_REGISTERED_UNSTAKED; owner registrations bypass the cap.
#[test]
fn m27_self_registration_capped_owner_bypasses() {
    use crate::runtime::MAX_SELF_REGISTERED_UNSTAKED;
    use blst::min_pk::SecretKey;

    fn self_reg_inputs(i: u32) -> (Address, [u8; 48], [u8; 96]) {
        let mut ikm = [7u8; 32];
        ikm[28..].copy_from_slice(&i.to_be_bytes());
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let mut ab = [0u8; 20];
        ab[16..].copy_from_slice(&i.to_be_bytes());
        // avoid the zero address (index 0 sentinel) by setting a high byte.
        ab[0] = 0x5a;
        let val = Address::from(ab);
        let pk: [u8; 48] = sk.sk_to_pk().to_bytes();
        let node_id = test_radicle_node_id(val);
        let message = validator_registration_message(CHAIN_ID, val, node_id);
        let sig: [u8; 96] = sk
            .sign(&message, VALIDATOR_REGISTRATION_DST, &[])
            .to_bytes();
        (val, pk, sig)
    }

    // max_validators well above the self-registration cap so the cap, not the
    // global capacity, is what bites.
    with_vs_configured(200, |vs| {
        for i in 0..MAX_SELF_REGISTERED_UNSTAKED {
            let (val, pk, sig) = self_reg_inputs(i);
            vs.register_validator_with_sig(val, val, &pk, test_radicle_node_id(val), Some(&sig))
                .unwrap_or_else(|e| panic!("self-registration {i} within cap must succeed: {e}"));
        }
        assert_eq!(
            vs.registered_count().unwrap(),
            MAX_SELF_REGISTERED_UNSTAKED,
            "exactly the cap of self-registrations should be REGISTERED"
        );

        // The next self-registration is rejected before consuming a slot.
        let (val, pk, sig) = self_reg_inputs(MAX_SELF_REGISTERED_UNSTAKED);
        let err = vs
            .register_validator_with_sig(val, val, &pk, test_radicle_node_id(val), Some(&sig))
            .unwrap_err();
        assert!(
            err.to_string().contains("self-registration limit reached"),
            "over-cap self-registration must be rejected, got: {err}"
        );

        // The owner can still register validators directly, bypassing the cap.
        let owner_val = address!("0x000000000000000000000000000000000000beef");
        let mut ikm = [9u8; 32];
        ikm[28..].copy_from_slice(&(MAX_SELF_REGISTERED_UNSTAKED + 1).to_be_bytes());
        let owner_sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let owner_pk: [u8; 48] = owner_sk.sk_to_pk().to_bytes();
        let owner_node_id = test_radicle_node_id(owner_val);
        let owner_message = validator_registration_message(CHAIN_ID, owner_val, owner_node_id);
        let owner_sig: [u8; 96] = owner_sk
            .sign(&owner_message, VALIDATOR_REGISTRATION_DST, &[])
            .to_bytes();
        vs.register_validator_with_sig(
            OWNER,
            owner_val,
            &owner_pk,
            owner_node_id,
            Some(&owner_sig),
        )
        .expect("owner registration must bypass the self-registration cap");
        assert!(vs.is_validator(owner_val).unwrap());
    });
}

#[test]
fn test_register_self_valid_sig_accepted() {
    use blst::min_pk::SecretKey;

    with_vs_configured(10, |vs| {
        let val = address!("0x4646464646464646464646464646464646464646");
        let ikm = [46u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        let pk_bytes: [u8; 48] = pk.to_bytes();

        let node_id = test_radicle_node_id(val);
        let message = validator_registration_message(CHAIN_ID, val, node_id);
        let sig = sk.sign(&message, VALIDATOR_REGISTRATION_DST, &[]);
        let sig_bytes: [u8; 96] = sig.to_bytes();

        vs.register_validator_with_sig(val, val, &pk_bytes, node_id, Some(&sig_bytes))
            .unwrap();
        assert!(vs.is_validator(val).unwrap());
    });
}

#[test]
fn registration_pop_cannot_be_replayed_on_another_chain() {
    use blst::min_pk::SecretKey;

    let val = address!("0x4747474747474747474747474747474747474747");
    let sk = SecretKey::key_gen(&[47u8; 32], &[]).unwrap();
    let pk: [u8; 48] = sk.sk_to_pk().to_bytes();
    let node_id = test_radicle_node_id(val);
    let message = validator_registration_message(1, val, node_id);
    let sig: [u8; 96] = sk
        .sign(&message, VALIDATOR_REGISTRATION_DST, &[])
        .to_bytes();

    let register_on_chain = |chain_id| {
        let mut storage = HashMapStorageProvider::new(chain_id);
        StorageHandle::enter(&mut storage, |storage| {
            let mut vs = ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(10).unwrap();
            vs.register_validator_with_sig(val, val, &pk, node_id, Some(&sig))
        })
    };

    register_on_chain(1).expect("proof must be valid on the chain it was created for");
    assert!(
        register_on_chain(2).is_err(),
        "registration proof from chain 1 must be rejected on chain 2"
    );
}

fn signed_radicle_registration(
    seed: u8,
    chain_id: u64,
    validator: Address,
    node_id: B256,
) -> ([u8; 48], [u8; 96]) {
    use blst::min_pk::SecretKey;

    let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    let public_key = sk.sk_to_pk().to_bytes();
    let message = validator_registration_message(chain_id, validator, node_id);
    let signature = sk
        .sign(&message, VALIDATOR_REGISTRATION_DST, &[])
        .to_bytes();
    (public_key, signature)
}

#[test]
fn radicle_node_id_registration_is_bidirectional_and_signature_bound() {
    let validator = Address::repeat_byte(0x71);
    let node_id = B256::repeat_byte(0x81);
    let other_node_id = B256::repeat_byte(0x82);
    let (public_key, signature) = signed_radicle_registration(0x31, CHAIN_ID, validator, node_id);

    with_vs_configured(10, |vs| {
        vs.register_validator_with_sig(
            validator,
            validator,
            &public_key,
            node_id,
            Some(&signature),
        )
        .unwrap();

        assert_eq!(vs.get_radicle_node_id(validator).unwrap(), node_id);
        assert_eq!(vs.validator_by_radicle_node_id(node_id).unwrap(), validator);
        assert!(vs
            .validator_by_radicle_node_id(other_node_id)
            .unwrap()
            .is_zero());
    });

    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut vs = ValidatorSet::new(storage);
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(10).unwrap();
        let err = vs
            .register_validator_with_sig(
                validator,
                validator,
                &public_key,
                other_node_id,
                Some(&signature),
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid BLS registration signature"));
    });
}

#[test]
fn radicle_node_id_rejects_zero_and_duplicate_without_partial_state() {
    let first = Address::repeat_byte(0x72);
    let second = Address::repeat_byte(0x73);
    let node_id = B256::repeat_byte(0x83);
    let (first_key, first_signature) = signed_radicle_registration(0x32, CHAIN_ID, first, node_id);
    let (second_key, second_signature) =
        signed_radicle_registration(0x33, CHAIN_ID, second, node_id);
    let (zero_key, zero_signature) =
        signed_radicle_registration(0x34, CHAIN_ID, second, B256::ZERO);

    with_vs_configured(10, |vs| {
        let zero = vs
            .register_validator_with_sig(
                second,
                second,
                &zero_key,
                B256::ZERO,
                Some(&zero_signature),
            )
            .unwrap_err();
        assert!(zero.to_string().contains("Radicle NodeId must not be zero"));
        assert_eq!(vs.validator_count().unwrap(), 0);

        vs.register_validator_with_sig(first, first, &first_key, node_id, Some(&first_signature))
            .unwrap();
        let duplicate = vs
            .register_validator_with_sig(
                second,
                second,
                &second_key,
                node_id,
                Some(&second_signature),
            )
            .unwrap_err();
        assert!(duplicate
            .to_string()
            .contains("Radicle NodeId already registered"));
        assert_eq!(vs.validator_count().unwrap(), 1);
        assert!(vs.get_radicle_node_id(second).unwrap().is_zero());
        assert_eq!(vs.validator_by_radicle_node_id(node_id).unwrap(), first);
    });
}

#[test]
fn inactive_reregistration_preserves_node_id_until_final_cleanup() {
    let validator = Address::repeat_byte(0x74);
    let first_node_id = B256::repeat_byte(0x84);
    let second_node_id = B256::repeat_byte(0x85);
    let (first_key, first_signature) =
        signed_radicle_registration(0x35, CHAIN_ID, validator, first_node_id);
    let (second_key, first_node_signature) =
        signed_radicle_registration(0x36, CHAIN_ID, validator, first_node_id);
    let (_, second_node_signature) =
        signed_radicle_registration(0x36, CHAIN_ID, validator, second_node_id);

    with_vs_configured(10, |vs| {
        vs.register_validator_with_sig(
            validator,
            validator,
            &first_key,
            first_node_id,
            Some(&first_signature),
        )
        .unwrap();
        make_inactive_for_test(vs, validator);

        let changed = vs
            .register_validator_with_sig(
                validator,
                validator,
                &second_key,
                second_node_id,
                Some(&second_node_signature),
            )
            .unwrap_err();
        assert!(changed
            .to_string()
            .contains("inactive validator must keep its Radicle NodeId"));

        vs.register_validator_with_sig(
            validator,
            validator,
            &second_key,
            first_node_id,
            Some(&first_node_signature),
        )
        .unwrap();
        assert_eq!(vs.get_radicle_node_id(validator).unwrap(), first_node_id);

        make_inactive_for_test(vs, validator);
        assert_eq!(vs.cleanup_inactive_validators(0).unwrap(), 1);
        assert!(vs.get_radicle_node_id(validator).unwrap().is_zero());
        assert!(vs
            .validator_by_radicle_node_id(first_node_id)
            .unwrap()
            .is_zero());

        vs.register_validator_with_sig(
            validator,
            validator,
            &second_key,
            second_node_id,
            Some(&second_node_signature),
        )
        .unwrap();
        assert_eq!(vs.get_radicle_node_id(validator).unwrap(), second_node_id);
    });
}

#[test]
fn every_radicle_registration_mutation_rolls_back_atomically() {
    let validator = Address::repeat_byte(0x75);
    let node_id = B256::repeat_byte(0x86);
    let (public_key, signature) = signed_radicle_registration(0x37, CHAIN_ID, validator, node_id);

    let configured_provider = || {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.set_block_number(1);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = ValidatorSet::new(storage);
            vs.config_owner.write(OWNER).unwrap();
            vs.config_max_validators.write(10).unwrap();
        });
        provider
    };

    let mut measured = configured_provider();
    measured.fail_after_mutation_at(usize::MAX);
    StorageHandle::enter(&mut measured, |storage| {
        ValidatorSet::new(storage)
            .register_validator_with_sig(
                validator,
                validator,
                &public_key,
                node_id,
                Some(&signature),
            )
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count > 2);

    for failure_at in 0..operation_count {
        let mut provider = configured_provider();
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(ValidatorSet::new(storage)
                .register_validator_with_sig(
                    validator,
                    validator,
                    &public_key,
                    node_id,
                    Some(&signature),
                )
                .is_err());
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let vs = ValidatorSet::new(storage);
            assert_eq!(vs.validator_count().unwrap(), 0);
            assert!(vs.get_radicle_node_id(validator).unwrap().is_zero());
            assert!(vs.validator_by_radicle_node_id(node_id).unwrap().is_zero());
            assert!(!vs.is_validator(validator).unwrap());
        });
        assert!(provider
            .get_events(outbe_primitives::addresses::VALIDATOR_SET_ADDRESS)
            .is_empty());
    }
}

// ---- Step 8: idempotent record_finalized_participation hook tests --------

mod record_finalized_participation_idempotency {
    use super::*;
    use crate::hooks;
    use alloy_primitives::b256;

    const FB_HASH_A: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const FB_HASH_B: B256 =
        b256!("0x2222222222222222222222222222222222222222222222222222222222222222");

    fn dummy_consensus_pubkey_local(seed: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = seed;
        pk
    }

    fn register_active(vs: &mut ValidatorSet, addr: Address, seed: u8) {
        vs.register_validator(OWNER, addr, &dummy_consensus_pubkey_local(seed))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(addr).unwrap();
        vs.val_has_bls_share.write(&addr, true).unwrap();
    }

    #[test]
    fn replay_for_same_fb_hash_is_noop() {
        let val_a = address!("0x00000000000000000000000000000000000000A1");
        let val_b = address!("0x00000000000000000000000000000000000000B2");
        with_vs_configured(10, |vs| {
            register_active(vs, val_a, 1);
            register_active(vs, val_b, 2);

            let storage = vs.storage.clone();
            // First call: increments missed_votes for absent val_b.
            hooks::record_finalized_participation(storage.clone(), FB_HASH_A, &[val_a], &[val_b])
                .unwrap();
            assert_eq!(vs.val_missed_votes.read(&val_b).unwrap(), 1);

            // Replay same fb_hash: must not bump again.
            hooks::record_finalized_participation(storage.clone(), FB_HASH_A, &[val_a], &[val_b])
                .unwrap();
            assert_eq!(vs.val_missed_votes.read(&val_b).unwrap(), 1);

            // Triple replay: still 1.
            hooks::record_finalized_participation(storage.clone(), FB_HASH_A, &[val_a], &[val_b])
                .unwrap();
            assert_eq!(vs.val_missed_votes.read(&val_b).unwrap(), 1);
        });
    }

    #[test]
    fn different_fb_hash_increments_independently() {
        let val_a = address!("0x00000000000000000000000000000000000000A1");
        let val_b = address!("0x00000000000000000000000000000000000000B2");
        with_vs_configured(10, |vs| {
            register_active(vs, val_a, 1);
            register_active(vs, val_b, 2);
            let storage = vs.storage.clone();

            hooks::record_finalized_participation(storage.clone(), FB_HASH_A, &[val_a], &[val_b])
                .unwrap();
            hooks::record_finalized_participation(storage.clone(), FB_HASH_B, &[val_a], &[val_b])
                .unwrap();

            assert_eq!(
                vs.val_missed_votes.read(&val_b).unwrap(),
                2,
                "two distinct finalized blocks count independently"
            );
        });
    }

    #[test]
    fn empty_voters_and_absent_is_noop() {
        with_vs_configured(10, |vs| {
            let storage = vs.storage.clone();
            hooks::record_finalized_participation(storage, FB_HASH_A, &[], &[]).unwrap();
            assert!(!vs
                .finalized_participation_recorded
                .read(&FB_HASH_A)
                .unwrap());
        });
    }
}

#[test]
fn finalized_participation_guard_prune_ring_bounds_growth() {
    use outbe_primitives::storage::StorageHandle;
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(128).unwrap();
        let v = address!("0x0101010101010101010101010101010101010101");
        vs.register_validator(OWNER, v, &dummy_consensus_pubkey(0x01))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(v).unwrap();

        let retain = crate::hooks::FINALIZED_PARTICIPATION_RETAIN;
        let total = retain + 3;
        let hashes: Vec<B256> = (0..total)
            .map(|i| B256::with_last_byte((i + 1) as u8))
            .collect();
        for h in &hashes {
            crate::hooks::record_finalized_participation(storage.clone(), *h, &[v], &[]).unwrap();
        }
        // The oldest (total - retain) guard flags are evicted (slots reclaimed);
        // the last `retain` finalized blocks are still guarded against replay.
        for i in 0..(total - retain) {
            assert!(
                !vs.finalized_participation_recorded
                    .read(&hashes[i as usize])
                    .unwrap(),
                "guard entry {i} must be pruned"
            );
        }
        for i in (total - retain)..total {
            assert!(
                vs.finalized_participation_recorded
                    .read(&hashes[i as usize])
                    .unwrap(),
                "guard entry {i} must be retained"
            );
        }
    });
}

mod operational_key_delegation {
    use super::*;
    use crate::delegation::ValidatorDelegateRole;

    const VALIDATOR_A: Address = address!("0x00000000000000000000000000000000000000A1");
    const VALIDATOR_B: Address = address!("0x00000000000000000000000000000000000000B2");
    const DELEGATE: Address = address!("0x00000000000000000000000000000000000000D1");
    const ROTATED: Address = address!("0x00000000000000000000000000000000000000D2");

    fn register_active(vs: &mut ValidatorSet, validator: Address, seed: u8) {
        vs.register_validator(OWNER, validator, &dummy_consensus_pubkey(seed))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(validator)
            .unwrap();
        vs.val_has_bls_share.write(&validator, true).unwrap();
    }

    #[test]
    fn delegated_key_resolves_only_for_its_assigned_role() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);

            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Oracle, DELEGATE)
                .unwrap();

            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Oracle)
                    .unwrap(),
                Some(VALIDATOR_A)
            );
            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn rotation_and_revoke_remove_the_previous_capability() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp, DELEGATE)
                .unwrap();
            assert_eq!(
                vs.resolve_validator_for_role(VALIDATOR_A, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                None,
                "explicit delegation disables validator-address fallback for that role"
            );
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp, ROTATED)
                .unwrap();

            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                None
            );
            assert_eq!(
                vs.resolve_validator_for_role(ROTATED, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                Some(VALIDATOR_A)
            );

            vs.revoke_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp)
                .unwrap();
            assert_eq!(
                vs.resolve_validator_for_role(ROTATED, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                None
            );
            assert_eq!(
                vs.resolve_validator_for_role(VALIDATOR_A, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                Some(VALIDATOR_A),
                "revocation restores validator-address fallback"
            );
        });
    }

    #[test]
    fn delegate_cannot_be_claimed_by_two_validators_for_the_same_role() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);
            register_active(vs, VALIDATOR_B, 2);
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Oracle, DELEGATE)
                .unwrap();

            let err = vs
                .set_delegate(VALIDATOR_B, ValidatorDelegateRole::Oracle, DELEGATE)
                .unwrap_err();
            assert!(
                matches!(err, PrecompileError::Revert(message) if message == "delegate already assigned for role")
            );
        });
    }

    #[test]
    fn registered_validator_address_cannot_be_used_as_another_validators_delegate() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);
            register_active(vs, VALIDATOR_B, 2);

            let err = vs
                .set_delegate(VALIDATOR_A, ValidatorDelegateRole::Oracle, VALIDATOR_B)
                .unwrap_err();
            assert!(
                matches!(err, PrecompileError::Revert(message) if message == "delegate must not be a registered validator")
            );
        });
    }

    #[test]
    fn operational_delegate_cannot_later_register_as_a_validator() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp, DELEGATE)
                .unwrap();

            let err = vs
                .register_validator(OWNER, DELEGATE, &dummy_consensus_pubkey(2))
                .unwrap_err();
            assert!(
                matches!(err, PrecompileError::Revert(message) if message == "validator address is already assigned as an operational delegate")
            );
            assert!(!vs.is_validator(DELEGATE).unwrap());
            assert_eq!(
                vs.get_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                DELEGATE
            );
            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                Some(VALIDATOR_A)
            );
        });
    }

    #[test]
    fn inactive_validator_can_configure_but_cannot_use_an_operational_key() {
        with_vs_configured(10, |vs| {
            vs.register_validator(OWNER, VALIDATOR_A, &dummy_consensus_pubkey(1))
                .unwrap();
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Oracle, DELEGATE)
                .unwrap();

            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Oracle)
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn one_address_can_hold_independent_roles_for_the_same_validator() {
        with_vs_configured(10, |vs| {
            register_active(vs, VALIDATOR_A, 1);
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Oracle, DELEGATE)
                .unwrap();
            vs.set_delegate(VALIDATOR_A, ValidatorDelegateRole::Ocomp, DELEGATE)
                .unwrap();

            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Oracle)
                    .unwrap(),
                Some(VALIDATOR_A)
            );
            assert_eq!(
                vs.resolve_validator_for_role(DELEGATE, ValidatorDelegateRole::Ocomp)
                    .unwrap(),
                Some(VALIDATOR_A)
            );
        });
    }

    #[test]
    fn unknown_role_ids_fail_closed() {
        assert!(ValidatorDelegateRole::try_from(0).is_err());
        assert!(ValidatorDelegateRole::try_from(3).is_err());
        assert_eq!(
            ValidatorDelegateRole::try_from(1).unwrap(),
            ValidatorDelegateRole::Oracle
        );
        assert_eq!(
            ValidatorDelegateRole::try_from(2).unwrap(),
            ValidatorDelegateRole::Ocomp
        );
    }
}
