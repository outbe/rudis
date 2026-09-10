//! End-to-end tests for `submitSeedPartialEquivocationEvidence` (Offense B).
//!
//! A validator that identity-signs two DIFFERENT VRF seed partials for the same
//! `(round, vrf_material_version)` is jailed + slashed. The evidence is
//! self-authenticating from the two MinPk identity signatures, so no committee
//! polynomial is needed and an honest validator cannot be framed.

use alloy_primitives::{address, Address, U256};
use commonware_codec::Encode;
use commonware_cryptography::{bls12381, Signer as _};
use outbe_consensus::proof::{seed_attest_namespace, seed_partial_attest_message};
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_slashindicator::schema::SlashIndicator;
use outbe_staking::contract::Staking;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::{StakeProjection, ValidatorLifecycle};

const CHAIN_ID: u64 = 1;
const OWNER: Address = address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const SUBMITTER: Address = address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");
const ACCUSED: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
const STAKE_AMOUNT: u64 = 1_000_000_000_000u64;
const ROUND_EPOCH: u64 = 3;
const ROUND_VIEW: u64 = 100;
const VRF_VERSION: u64 = 5;

fn accused_key() -> bls12381::PrivateKey {
    bls12381::PrivateKey::from_seed(0xA11CE)
}

fn pubkey_bytes(key: &bls12381::PrivateKey) -> [u8; 48] {
    bls12381::PublicKey::from(key.clone())
        .encode()
        .as_ref()
        .try_into()
        .expect("MinPk pubkey is 48 bytes")
}

fn identity_sig(key: &bls12381::PrivateKey, partial: &[u8; 48]) -> [u8; 96] {
    let msg = seed_partial_attest_message(ROUND_EPOCH, ROUND_VIEW, VRF_VERSION, partial);
    key.sign(&seed_attest_namespace(), &msg)
        .encode()
        .as_ref()
        .try_into()
        .expect("MinPk signature is 96 bytes")
}

/// Build SPE1 evidence with the two partials each identity-signed by `key`.
fn build_evidence(
    key: &bls12381::PrivateKey,
    pubkey: &[u8; 48],
    partial_1: &[u8; 48],
    partial_2: &[u8; 48],
) -> Vec<u8> {
    let sig_1 = identity_sig(key, partial_1);
    let sig_2 = identity_sig(key, partial_2);
    let mut d = Vec::with_capacity(365);
    d.extend_from_slice(b"SPE1");
    d.push(0x01);
    d.extend_from_slice(&ROUND_EPOCH.to_be_bytes());
    d.extend_from_slice(&ROUND_VIEW.to_be_bytes());
    d.extend_from_slice(&VRF_VERSION.to_be_bytes());
    d.extend_from_slice(pubkey);
    d.extend_from_slice(partial_1);
    d.extend_from_slice(&sig_1);
    d.extend_from_slice(partial_2);
    d.extend_from_slice(&sig_2);
    d
}

/// Register ACCUSED (with `pubkey`) as an active, staked validator and SUBMITTER
/// as an active validator; set the epoch counter so epoch-lag passes.
fn setup(storage: StorageHandle, accused_pubkey: &[u8; 48]) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(OWNER).unwrap();
    vs.set_config_max_validators(100).unwrap();
    let mut epoch = vs.epoch_snapshot().unwrap();
    epoch.number = U256::from(ROUND_EPOCH);
    vs.test_set_epoch_snapshot(epoch).unwrap();

    vs.test_register_validator_without_pop(ACCUSED, accused_pubkey)
        .unwrap();
    let staking = Staking::new(storage.clone());
    let stake = U256::from(STAKE_AMOUNT);
    staking.stake_amount.write(&ACCUSED, stake).unwrap();
    staking.total_staked.write(stake).unwrap();
    staking
        .storage
        .increase_balance(STAKING_ADDRESS, stake)
        .unwrap();
    vs.test_set_stake_projection(ACCUSED, StakeProjection::new(stake, None))
        .unwrap();
    vs.activate_validator_via_boundary_for_test(ACCUSED)
        .unwrap();

    let mut submitter_pk = [0u8; 48];
    submitter_pk[0] = 0x77;
    vs.test_register_validator_without_pop(SUBMITTER, &submitter_pk)
        .unwrap();
    vs.activate_validator_via_boundary_for_test(SUBMITTER)
        .unwrap();
}

fn with_storage<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(1);
    storage.enter(f)
}

#[test]
fn equivocation_jails_and_slashes_then_dedups() {
    with_storage(|storage| {
        let key = accused_key();
        let pubkey = pubkey_bytes(&key);
        setup(storage.clone(), &pubkey);

        let p1 = [0x11u8; 48];
        let p2 = [0x22u8; 48];
        let evidence = build_evidence(&key, &pubkey, &p1, &p2);

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .expect("valid equivocation evidence must slash");

        let vs = ValidatorSet::new(storage.clone());
        assert!(
            matches!(
                vs.validator_lifecycle(ACCUSED).unwrap(),
                ValidatorLifecycle::JailRetained(_)
            ),
            "accused must be JAILED"
        );
        let si = SlashIndicator::new(storage.clone());
        assert_eq!(si.felony_count.read(&ACCUSED).unwrap(), 1);

        // Replaying the same evidence (either partial order) is idempotent-revert.
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(format!("{err:?}").contains("already processed"));
        let swapped = build_evidence(&key, &pubkey, &p2, &p1);
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &swapped)
            .unwrap_err();
        assert!(format!("{err:?}").contains("already processed"));
    });
}

#[test]
fn identical_partials_are_not_equivocation() {
    with_storage(|storage| {
        let key = accused_key();
        let pubkey = pubkey_bytes(&key);
        setup(storage.clone(), &pubkey);
        let p = [0x33u8; 48];
        let evidence = build_evidence(&key, &pubkey, &p, &p);
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(format!("{err:?}").contains("identical"));
    });
}

#[test]
fn corrupt_identity_sig_is_rejected() {
    with_storage(|storage| {
        let key = accused_key();
        let pubkey = pubkey_bytes(&key);
        setup(storage.clone(), &pubkey);
        let mut evidence = build_evidence(&key, &pubkey, &[0x11; 48], &[0x22; 48]);
        // identity_sig_1 sits at offset 5+24+48+48 = 125; flip a byte.
        evidence[125] ^= 0xFF;
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(format!("{err:?}").contains("identity signature"));
    });
}

#[test]
fn unregistered_signer_is_rejected() {
    with_storage(|storage| {
        // Do NOT register the accused; only the submitter.
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(100).unwrap();
        let mut epoch = vs.epoch_snapshot().unwrap();
        epoch.number = U256::from(ROUND_EPOCH);
        vs.test_set_epoch_snapshot(epoch).unwrap();
        let mut submitter_pk = [0u8; 48];
        submitter_pk[0] = 0x77;
        vs.test_register_validator_without_pop(SUBMITTER, &submitter_pk)
            .unwrap();
        vs.activate_validator_via_boundary_for_test(SUBMITTER)
            .unwrap();

        let key = accused_key();
        let pubkey = pubkey_bytes(&key);
        let evidence = build_evidence(&key, &pubkey, &[0x11; 48], &[0x22; 48]);
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(format!("{err:?}").contains("not a registered validator"));
    });
}

#[test]
fn non_active_submitter_is_rejected() {
    with_storage(|storage| {
        let key = accused_key();
        let pubkey = pubkey_bytes(&key);
        // Register accused but NOT the submitter (submitter status = 0).
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(OWNER).unwrap();
        vs.set_config_max_validators(100).unwrap();
        let mut epoch = vs.epoch_snapshot().unwrap();
        epoch.number = U256::from(ROUND_EPOCH);
        vs.test_set_epoch_snapshot(epoch).unwrap();
        vs.test_register_validator_without_pop(ACCUSED, &pubkey)
            .unwrap();
        vs.test_set_stake_projection(ACCUSED, StakeProjection::new(U256::from(1), None))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(ACCUSED)
            .unwrap();

        let evidence = build_evidence(&key, &pubkey, &[0x11; 48], &[0x22; 48]);
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_seed_partial_equivocation_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(format!("{err:?}").contains("not an ACTIVE validator"));
    });
}
