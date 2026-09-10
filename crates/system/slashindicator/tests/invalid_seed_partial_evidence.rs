//! End-to-end tests for `submitInvalidSeedPartialEvidence` (Offense A): slashing
//! a single VRF seed partial that fails verification against the committee's
//! full public polynomial. Uses a real DKG so a genuinely-valid partial is NOT
//! slashable and a genuinely-invalid one is.

use alloy_primitives::{address, keccak256, Address, U256};
use commonware_codec::Encode;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381;
use commonware_cryptography::bls12381::primitives::{ops::threshold, variant::MinSig};
use commonware_cryptography::Signer as _;
use outbe_consensus::bls::bootstrap_dkg;
use outbe_consensus::dkg_manager::public_polynomial_hash;
use outbe_consensus::proof::{hybrid_seed_namespace, seed_partial_attest_message};
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_slashindicator::schema::SlashIndicator;
use outbe_staking::contract::Staking;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::state::write_committee_snapshot;
use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot, StakeProjection, ValidatorLifecycle};

const CHAIN_ID: u64 = 1;
const OWNER: Address = address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const SUBMITTER: Address = address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");
const ROUND_EPOCH: u64 = 3;
const ROUND_VIEW: u64 = 100;
const VRF_VERSION: u64 = 0;
const N: u32 = 4;

fn validator_addr(i: u32) -> Address {
    let mut b = [0u8; 20];
    b[0] = 0xA0 | (i as u8);
    Address::from(b)
}

struct Fixture {
    keys: Vec<bls12381::PrivateKey>,
    pubkeys: Vec<[u8; 48]>,
    shares: Vec<commonware_cryptography::bls12381::primitives::group::Share>,
    commitment: Vec<u8>,
    committee_set_hash: alloy_primitives::B256,
}

/// Build a real DKG, register the committee, write the snapshot with the
/// authentic polynomial hash, and register SUBMITTER as ACTIVE.
fn setup(storage: StorageHandle) -> Fixture {
    let dkg = bootstrap_dkg(N).unwrap();
    let keys: Vec<bls12381::PrivateKey> = (0..N)
        .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
        .collect();
    let pubkeys: Vec<[u8; 48]> = keys
        .iter()
        .map(|k| {
            bls12381::PublicKey::from(k.clone())
                .encode()
                .as_ref()
                .try_into()
                .unwrap()
        })
        .collect();

    let mut vs = ValidatorSet::new(storage.clone());
    vs.config_owner.write(OWNER).unwrap();
    vs.set_config_max_validators(100).unwrap();
    let mut epoch = vs.epoch_snapshot().unwrap();
    epoch.number = U256::from(ROUND_EPOCH);
    vs.test_set_epoch_snapshot(epoch).unwrap();

    let mut committee = Vec::new();
    for i in 0..N {
        let addr = validator_addr(i);
        vs.test_register_validator_without_pop(addr, &pubkeys[i as usize])
            .unwrap();
        let stake = U256::from(1_000_000u64);
        let staking = Staking::new(storage.clone());
        staking.stake_amount.write(&addr, stake).unwrap();
        vs.test_set_stake_projection(addr, StakeProjection::new(stake, None))
            .unwrap();
        vs.activate_validator_via_boundary_for_test(addr).unwrap();
        committee.push(CommitteeEntry {
            address: addr,
            consensus_pubkey: pubkeys[i as usize],
        });
    }
    let staking = Staking::new(storage.clone());
    staking
        .total_staked
        .write(U256::from(4_000_000u64))
        .unwrap();
    staking
        .storage
        .increase_balance(STAKING_ADDRESS, U256::from(4_000_000u64))
        .unwrap();

    // SUBMITTER active.
    let mut sub_pk = [0u8; 48];
    sub_pk[0] = 0x77;
    vs.test_register_validator_without_pop(SUBMITTER, &sub_pk)
        .unwrap();
    vs.test_set_stake_projection(SUBMITTER, StakeProjection::new(U256::from(1), None))
        .unwrap();
    vs.activate_validator_via_boundary_for_test(SUBMITTER)
        .unwrap();

    let commitment = dkg.polynomial.encode().to_vec();
    let poly_hash = public_polynomial_hash(&dkg.polynomial);
    assert_eq!(poly_hash, keccak256(&commitment));

    let snapshot = CommitteeSnapshot {
        committee,
        vrf_material_version: VRF_VERSION,
        vrf_group_public_key_bytes: dkg.polynomial.public().encode().to_vec(),
        vrf_public_polynomial_hash: poly_hash,
    };
    let (committee_set_hash, _key) =
        write_committee_snapshot(storage.clone(), ROUND_EPOCH, &snapshot).unwrap();

    Fixture {
        keys,
        pubkeys,
        shares: dkg.shares,
        commitment,
        committee_set_hash,
    }
}

/// Threshold-sign a seed partial for `signer` over `(epoch, view)`; return the
/// 48-byte partial.
fn sign_partial(fx: &Fixture, signer: usize, epoch: u64, view: u64) -> [u8; 48] {
    let msg = Round::new(Epoch::new(epoch), View::new(view)).encode();
    let partial = threshold::sign_message::<MinSig>(
        &fx.shares[signer],
        &hybrid_seed_namespace(),
        msg.as_ref(),
    )
    .value;
    partial.encode().as_ref().try_into().unwrap()
}

fn identity_sign(fx: &Fixture, signer: usize, partial: &[u8; 48]) -> [u8; 96] {
    let msg = seed_partial_attest_message(ROUND_EPOCH, ROUND_VIEW, VRF_VERSION, partial);
    fx.keys[signer]
        .sign(&outbe_consensus::proof::seed_attest_namespace(), &msg)
        .encode()
        .as_ref()
        .try_into()
        .unwrap()
}

fn build_ipe1(
    fx: &Fixture,
    signer_index: u32,
    partial: &[u8; 48],
    identity_sig: &[u8; 96],
    commitment: &[u8],
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(b"IPE1");
    d.push(0x01);
    d.extend_from_slice(fx.committee_set_hash.as_slice());
    d.extend_from_slice(&ROUND_EPOCH.to_be_bytes());
    d.extend_from_slice(&ROUND_VIEW.to_be_bytes());
    d.extend_from_slice(&VRF_VERSION.to_be_bytes());
    d.extend_from_slice(&signer_index.to_be_bytes());
    d.extend_from_slice(&fx.pubkeys[signer_index as usize]);
    d.extend_from_slice(partial);
    d.extend_from_slice(identity_sig);
    d.extend_from_slice(&(commitment.len() as u32).to_be_bytes());
    d.extend_from_slice(commitment);
    d
}

fn with_storage<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(1);
    storage.enter(f)
}

#[test]
fn invalid_partial_jails_and_slashes_then_dedups() {
    with_storage(|storage| {
        let fx = setup(storage.clone());
        let signer = 1usize;
        // Invalid partial: signed over a DIFFERENT view, so it fails at ROUND_VIEW.
        let bad = sign_partial(&fx, signer, ROUND_EPOCH, ROUND_VIEW + 1);
        let id_sig = identity_sign(&fx, signer, &bad);
        let evidence = build_ipe1(&fx, signer as u32, &bad, &id_sig, &fx.commitment);

        let mut si = SlashIndicator::new(storage.clone());
        si.submit_invalid_seed_partial_evidence(SUBMITTER, &evidence)
            .expect("an invalid identity-signed partial must slash");

        let vs = ValidatorSet::new(storage.clone());
        assert!(matches!(
            vs.validator_lifecycle(validator_addr(signer as u32))
                .unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
        let si = SlashIndicator::new(storage.clone());
        assert_eq!(
            si.felony_count
                .read(&validator_addr(signer as u32))
                .unwrap(),
            1
        );

        // Replay rejected.
        let mut si = SlashIndicator::new(storage.clone());
        assert!(si
            .submit_invalid_seed_partial_evidence(SUBMITTER, &evidence)
            .unwrap_err()
            .to_string()
            .contains("already processed"));
    });
}

#[test]
fn valid_partial_is_not_slashable() {
    with_storage(|storage| {
        let fx = setup(storage.clone());
        let signer = 2usize;
        // A genuinely valid partial for ROUND must NOT slash.
        let good = sign_partial(&fx, signer, ROUND_EPOCH, ROUND_VIEW);
        let id_sig = identity_sign(&fx, signer, &good);
        let evidence = build_ipe1(&fx, signer as u32, &good, &id_sig, &fx.commitment);

        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_invalid_seed_partial_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(
            err.to_string().contains("valid; nothing to slash"),
            "got: {err:?}"
        );
    });
}

#[test]
fn forged_commitment_is_rejected() {
    with_storage(|storage| {
        let fx = setup(storage.clone());
        let signer = 1usize;
        let bad = sign_partial(&fx, signer, ROUND_EPOCH, ROUND_VIEW + 1);
        let id_sig = identity_sign(&fx, signer, &bad);
        // Tamper the commitment so its hash no longer matches the snapshot.
        let mut forged = fx.commitment.clone();
        forged[0] ^= 0xFF;
        let evidence = build_ipe1(&fx, signer as u32, &bad, &id_sig, &forged);
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_invalid_seed_partial_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match committee snapshot polynomial hash")
                || err.to_string().contains("malformed"),
            "got: {err:?}"
        );
    });
}

#[test]
fn wrong_signer_index_pubkey_mismatch_rejected() {
    with_storage(|storage| {
        let fx = setup(storage.clone());
        let signer = 1usize;
        let bad = sign_partial(&fx, signer, ROUND_EPOCH, ROUND_VIEW + 1);
        let id_sig = identity_sign(&fx, signer, &bad);
        // Claim signer_index 0 but carry signer 1's pubkey -> committee[0] != pubkey.
        let mut evidence = build_ipe1(&fx, signer as u32, &bad, &id_sig, &fx.commitment);
        // overwrite signer_index (bytes [45..49]) with 0
        let idx_off = 4 + 1 + 32 + 8 + 8 + 8;
        evidence[idx_off..idx_off + 4].copy_from_slice(&0u32.to_be_bytes());
        let mut si = SlashIndicator::new(storage.clone());
        let err = si
            .submit_invalid_seed_partial_evidence(SUBMITTER, &evidence)
            .unwrap_err();
        assert!(
            err.to_string().contains("does not match committee entry"),
            "got: {err:?}"
        );
    });
}
