//! Integration tests for the V2 `CommitteeSnapshotStore`.
//!
//! Layout tests pin the schema slot indices for slot 30 and slots 31..40 so
//! schema drift is caught as a wire-format-breaking change. Hash and key
//! formula tests pin the byte layout. The atomicity tests use
//! the V2 atomic boundary hook (`activate_boundary_atomic`) to verify that
//! a failure in the middle of activation never leaves a partial snapshot
//! visible to readers.

use alloy_primitives::{address, b256, Address, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationCoreV1, OcompKeyRegistrationV1,
        POC_KEY_EPOCH, RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    profile::poc_schema_limits,
};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::hooks::{activate_boundary_atomic, BoundaryActivationInputs};
use outbe_validatorset::test_support::activate_validator_via_boundary;
use outbe_validatorset::{
    clear_committee_snapshot, committee_set_hash_v2, committee_snapshot_key,
    read_committee_snapshot, read_committee_snapshot_for_epoch, read_ocomp_snapshot_extension,
    read_ocomp_snapshot_extension_for_binding, read_ocomp_snapshot_member_at, snapshot_identity,
    write_committee_snapshot, CommitteeEntry, CommitteeSnapshot,
};

const CHAIN_ID: u64 = 1;

fn pubkey_filled(byte: u8) -> [u8; 48] {
    [byte; 48]
}

fn admit_ocomp_key(
    vs: &mut ValidatorSet<'_>,
    validator: Address,
    consensus_pubkey: &[u8; 48],
    key_seed: u8,
) -> OcompKeyRegistrationV1 {
    let owner = vs.config_owner.read().unwrap();
    vs.register_validator(owner, validator, consensus_pubkey)
        .unwrap();
    vs.mark_pending(validator).unwrap();
    let (registration, encoded) = ocomp_registration(validator, consensus_pubkey, key_seed);
    vs.confirm_validator_ready(validator, &encoded).unwrap();
    registration
}

fn ocomp_registration(
    validator: Address,
    consensus_pubkey: &[u8; 48],
    key_seed: u8,
) -> (OcompKeyRegistrationV1, Vec<u8>) {
    let signing_key =
        SigningKey::from_bytes((&outbe_primitives::test_keys::secret((key_seed) as u64)).into())
            .unwrap();
    let mut registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id: CHAIN_ID,
            genesis_hash: B256::ZERO,
            validator_identity_hash: validator_identity_hash_v1(validator, consensus_pubkey)
                .unwrap(),
            ocomp_public_key_sec1: signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
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

/// Hand-rolled legacy `hash_active_set` (addresses-only) - kept verbatim from
/// `crates/blockchain/consensus/src/dkg_manager.rs::hash_active_set` so the
/// distinctness assertion in
/// `committee_set_hash_v2_never_equals_legacy_active_set_hash_for_same_addresses`
/// is a true comparison against the legacy formula.
fn legacy_active_set_hash(addresses: &[Address]) -> B256 {
    let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
    bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
    for addr in addresses {
        bytes.extend_from_slice(addr.as_slice());
    }
    alloy_primitives::keccak256(bytes)
}

// ---------------------------------------------------------------------------
// 1. Slot stability: slots 31..40 are at the expected indices.
// ---------------------------------------------------------------------------

#[test]
fn committee_snapshot_storage_slots_31_to_40_are_stable() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);

        assert_eq!(vs.committee_snapshot_exists.base_slot(), U256::from(31u64));
        assert_eq!(vs.committee_snapshot_len.base_slot(), U256::from(32u64));
        assert_eq!(
            vs.committee_snapshot_address_at.base_slot(),
            U256::from(33u64)
        );
        assert_eq!(
            vs.committee_snapshot_pubkey_lo_at.base_slot(),
            U256::from(34u64)
        );
        assert_eq!(
            vs.committee_snapshot_pubkey_hi_at.base_slot(),
            U256::from(35u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_material_version.base_slot(),
            U256::from(36u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_hash.base_slot(),
            U256::from(37u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_len.base_slot(),
            U256::from(38u64)
        );
        assert_eq!(
            vs.committee_snapshot_vrf_group_public_key_chunk_at
                .base_slot(),
            U256::from(39u64)
        );
        assert_eq!(
            vs._reserved_committee_snapshot_slot_40.slot(),
            U256::from(40u64),
        );
    });
}

// ---------------------------------------------------------------------------
// 2. Slot 30 (`finalized_participation_recorded`) does not move.
// ---------------------------------------------------------------------------

#[test]
fn validator_set_slot30_finalized_participation_recorded_does_not_move() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);
        assert_eq!(
            vs.finalized_participation_recorded.base_slot(),
            U256::from(30u64),
            "slot 30 (finalized_participation_recorded) must not move; \
             V2 snapshot extension starts at slot 31"
        );
    });
}

#[test]
fn validator_operational_key_slots_48_and_49_are_append_only() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.delegate_by_validator_role.base_slot(), U256::from(48u64));
        assert_eq!(vs.validator_by_role_delegate.base_slot(), U256::from(49u64));
    });
}

#[test]
fn radicle_node_id_slots_59_and_60_are_append_only() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.val_radicle_node_id.base_slot(), U256::from(59u64));
        assert_eq!(
            vs.radicle_node_id_to_validator.base_slot(),
            U256::from(60u64)
        );
    });
}

#[test]
fn ocomp_recovery_slots_61_and_62_are_append_only() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.val_ocomp_miss_count.base_slot(), U256::from(61u64));
        assert_eq!(
            vs.val_ocomp_recovery_deadline.base_slot(),
            U256::from(62u64)
        );
    });
}

#[test]
fn committee_snapshot_persists_separate_strict_ocomp_extension() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let first = Address::repeat_byte(0x61);
        let second = Address::repeat_byte(0x62);
        let first_bls = pubkey_filled(0x71);
        let second_bls = pubkey_filled(0x72);
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        let first_registration = admit_ocomp_key(&mut vs, first, &first_bls, 0x11);
        let second_registration = admit_ocomp_key(&mut vs, second, &second_bls, 0x12);
        let snapshot = CommitteeSnapshot {
            committee: vec![
                CommitteeEntry {
                    address: first,
                    consensus_pubkey: first_bls,
                },
                CommitteeEntry {
                    address: second,
                    consensus_pubkey: second_bls,
                },
            ],
            vrf_material_version: 3,
            vrf_group_public_key_bytes: vec![0x73; 96],
            vrf_public_polynomial_hash: B256::repeat_byte(0x74),
        };
        let epoch = 9;
        let expected_consensus_hash = committee_set_hash_v2(epoch, &snapshot);

        let (consensus_hash, snapshot_key) =
            write_committee_snapshot(storage.clone(), epoch, &snapshot).unwrap();

        assert_eq!(consensus_hash, expected_consensus_hash);
        let extension = read_ocomp_snapshot_extension(storage.clone(), snapshot_key)
            .unwrap()
            .expect("OCOMP extension");
        assert_eq!(extension.epoch, epoch);
        assert_eq!(extension.committee_set_hash, consensus_hash);
        assert_eq!(extension.member_count, 2);
        assert_ne!(extension.ocomp_binding_hash, B256::ZERO);
        assert_eq!(
            read_ocomp_snapshot_member_at(storage.clone(), snapshot_key, 0)
                .unwrap()
                .unwrap()
                .ocomp_public_key_sec1,
            first_registration.core.ocomp_public_key_sec1
        );
        assert_eq!(
            read_ocomp_snapshot_member_at(storage.clone(), snapshot_key, 1)
                .unwrap()
                .unwrap()
                .ocomp_public_key_sec1,
            second_registration.core.ocomp_public_key_sec1
        );
        assert_eq!(
            read_ocomp_snapshot_extension_for_binding(
                storage,
                epoch,
                consensus_hash,
                extension.ocomp_binding_hash,
            )
            .unwrap(),
            Some(extension)
        );
    });
}

#[test]
fn committee_snapshot_exact_replay_survives_rejected_ocomp_key_replacement() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let validator = Address::repeat_byte(0x63);
        let consensus_pubkey = pubkey_filled(0x73);
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        admit_ocomp_key(&mut vs, validator, &consensus_pubkey, 0x13);
        let snapshot = CommitteeSnapshot {
            committee: vec![CommitteeEntry {
                address: validator,
                consensus_pubkey,
            }],
            vrf_material_version: 4,
            vrf_group_public_key_bytes: vec![0x75; 96],
            vrf_public_polynomial_hash: B256::repeat_byte(0x76),
        };
        let epoch = 10;

        let identity = write_committee_snapshot(storage.clone(), epoch, &snapshot).unwrap();
        let original_extension = read_ocomp_snapshot_extension(storage.clone(), identity.1)
            .unwrap()
            .unwrap();

        assert_eq!(
            write_committee_snapshot(storage.clone(), epoch, &snapshot).unwrap(),
            identity,
            "byte-identical replay must be idempotent",
        );

        let (_, replacement) = ocomp_registration(validator, &consensus_pubkey, 0x14);
        let error = vs
            .confirm_validator_ready(validator, &replacement)
            .expect_err("key_epoch 1 cannot replace the pinned OCOMP key");
        assert!(error.to_string().contains("OCOMP public key is immutable"));
        drop(vs);

        assert_eq!(
            write_committee_snapshot(storage.clone(), epoch, &snapshot).unwrap(),
            identity,
            "rejected key replacement cannot introduce snapshot binding drift",
        );
        assert_eq!(
            read_ocomp_snapshot_extension(storage, identity.1)
                .unwrap()
                .unwrap(),
            original_extension,
            "rejected key replacement must not mutate the committed extension",
        );
    });
}

#[test]
fn clear_committee_snapshot_zeroes_consensus_and_ocomp_extension() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let validator = Address::repeat_byte(0x64);
        let consensus_pubkey = pubkey_filled(0x74);
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        admit_ocomp_key(&mut vs, validator, &consensus_pubkey, 0x15);
        drop(vs);
        let snapshot = CommitteeSnapshot {
            committee: vec![CommitteeEntry {
                address: validator,
                consensus_pubkey,
            }],
            vrf_material_version: 5,
            vrf_group_public_key_bytes: vec![0x77; 96],
            vrf_public_polynomial_hash: B256::repeat_byte(0x78),
        };
        let (_, key) = write_committee_snapshot(storage.clone(), 11, &snapshot).unwrap();

        clear_committee_snapshot(storage.clone(), key).unwrap();

        assert_eq!(read_committee_snapshot(storage.clone(), key).unwrap(), None);
        assert_eq!(
            read_ocomp_snapshot_extension(storage.clone(), key).unwrap(),
            None
        );
        assert_eq!(
            read_ocomp_snapshot_member_at(storage.clone(), key, 0).unwrap(),
            None
        );
        let vs = ValidatorSet::new(storage);
        assert_eq!(vs.committee_snapshot_ocomp_epoch.read(&key).unwrap(), 0);
        assert_eq!(
            vs.committee_snapshot_ocomp_consensus_hash
                .read(&key)
                .unwrap(),
            B256::ZERO
        );
        assert_eq!(
            vs.committee_snapshot_ocomp_binding_hash.read(&key).unwrap(),
            B256::ZERO
        );
        assert_eq!(
            vs.committee_snapshot_ocomp_member_count.read(&key).unwrap(),
            0
        );
        assert_eq!(
            vs.committee_snapshot_ocomp_key_lo_at
                .get_nested(&key)
                .read(&0)
                .unwrap(),
            B256::ZERO
        );
        assert_eq!(
            vs.committee_snapshot_ocomp_key_hi_at
                .get_nested(&key)
                .read(&0)
                .unwrap(),
            B256::ZERO
        );
        assert_eq!(
            vs.committee_snapshot_ocomp_key_epoch_at
                .get_nested(&key)
                .read(&0)
                .unwrap(),
            0
        );
        assert_eq!(
            vs._reserved_committee_snapshot_slot_40.read().unwrap(),
            B256::ZERO
        );
    });
}

#[test]
fn shared_test_activation_helper_drives_production_boundary_hook() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let validator = Address::repeat_byte(0x65);
        let consensus_pubkey = pubkey_filled(0x75);
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        vs.register_validator(Address::ZERO, validator, &consensus_pubkey)
            .unwrap();

        let snapshot_key = activate_validator_via_boundary(&mut vs, validator).unwrap();

        let state = vs.validator_state(validator).unwrap();
        assert!(state.lifecycle().is_active_status());
        assert!(state.has_bls_share());
        drop(vs);
        assert_eq!(
            read_committee_snapshot(storage.clone(), snapshot_key)
                .unwrap()
                .unwrap()
                .committee,
            vec![CommitteeEntry {
                address: validator,
                consensus_pubkey,
            }]
        );
        assert_eq!(
            read_ocomp_snapshot_extension(storage, snapshot_key)
                .unwrap()
                .unwrap()
                .member_count,
            1
        );
    });
}

// ---------------------------------------------------------------------------
// 3. test vector for committee_set_hash + snapshot_key.
// ---------------------------------------------------------------------------

#[test]
fn committee_snapshot_storage_key_test_vector_matches_plan() {
    // line 332:
    //   epoch = 0
    //   committee = [{ 0x..01, [0x11; 48] }]
    //   vrf_material_version = 0
    //   vrf_group_public_key_bytes = [0x22; 96]
    // expected committee_set_hash =
    //   0x61e5cd9eb3bd1a53545d83ce8462b9f8476dbf95312152b69468d2d34c0032d7
    // expected snapshot_key =
    //   0x33d4a585f916d6562b8560f407abeb1e10366e02d290ffdd9b0ad49778ab8a4d
    let snapshot = CommitteeSnapshot {
        committee: vec![CommitteeEntry {
            address: address!("0x0000000000000000000000000000000000000001"),
            consensus_pubkey: pubkey_filled(0x11),
        }],
        vrf_material_version: 0,
        vrf_group_public_key_bytes: vec![0x22u8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let hash = committee_set_hash_v2(0, &snapshot);
    let key = committee_snapshot_key(0, hash);

    assert_eq!(
        hash,
        b256!("61e5cd9eb3bd1a53545d83ce8462b9f8476dbf95312152b69468d2d34c0032d7"),
        "committee_set_hash test vector drift",
    );
    assert_eq!(
        key,
        b256!("33d4a585f916d6562b8560f407abeb1e10366e02d290ffdd9b0ad49778ab8a4d"),
        "snapshot_key test vector drift",
    );
}

// ---------------------------------------------------------------------------
// 4. Formula coverage - domain + epoch + len + addresses + pubkeys + vrf_material.
// ---------------------------------------------------------------------------

#[test]
fn committee_set_hash_formula_includes_domain_epoch_len_addresses_pubkeys_and_vrf_material() {
    let base = CommitteeSnapshot {
        committee: vec![
            CommitteeEntry {
                address: address!("0x1111111111111111111111111111111111111111"),
                consensus_pubkey: pubkey_filled(0x11),
            },
            CommitteeEntry {
                address: address!("0x2222222222222222222222222222222222222222"),
                consensus_pubkey: pubkey_filled(0x22),
            },
        ],
        vrf_material_version: 7,
        vrf_group_public_key_bytes: vec![0x33u8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let base_hash = committee_set_hash_v2(5, &base);

    // Domain: changing the domain string changes the hash. We exercise this by
    // hashing a synthetic input that mirrors `committee_set_hash_v2` but with
    // an alternate domain; if the function didn't include the domain prefix,
    // it would equal the recomputed value below - and we assert it does NOT.
    let mut alt_domain_buf = Vec::new();
    alt_domain_buf.extend_from_slice(b"DIFFERENT_DOMAIN_V2");
    alt_domain_buf.extend_from_slice(&5u64.to_be_bytes());
    alt_domain_buf.extend_from_slice(&2u64.to_be_bytes());
    for entry in &base.committee {
        alt_domain_buf.extend_from_slice(entry.address.as_slice());
        alt_domain_buf.extend_from_slice(&entry.consensus_pubkey);
    }
    alt_domain_buf.extend_from_slice(&7u64.to_be_bytes());
    alt_domain_buf.extend_from_slice(&96u64.to_be_bytes());
    alt_domain_buf.extend_from_slice(&[0x33u8; 96]);
    let alt_domain_hash = alloy_primitives::keccak256(&alt_domain_buf);
    assert_ne!(base_hash, alt_domain_hash, "domain prefix is included");

    // Epoch is included.
    assert_ne!(
        base_hash,
        committee_set_hash_v2(6, &base),
        "epoch is included"
    );

    // Length (and therefore order/count) is included - drop one entry.
    let shorter = CommitteeSnapshot {
        committee: vec![base.committee[0].clone()],
        ..base.clone()
    };
    assert_ne!(
        base_hash,
        committee_set_hash_v2(5, &shorter),
        "committee length is included"
    );

    // Addresses are included - flip one address.
    let mut altered = base.clone();
    altered.committee[0].address = address!("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF");
    assert_ne!(
        base_hash,
        committee_set_hash_v2(5, &altered),
        "validator addresses are included"
    );

    // Pubkeys are included - flip one pubkey while keeping addresses.
    let mut altered = base.clone();
    altered.committee[0].consensus_pubkey = pubkey_filled(0x99);
    assert_ne!(
        base_hash,
        committee_set_hash_v2(5, &altered),
        "validator consensus pubkeys are included"
    );

    // vrf_material_version is included.
    let mut altered = base.clone();
    altered.vrf_material_version = 8;
    assert_ne!(
        base_hash,
        committee_set_hash_v2(5, &altered),
        "vrf_material_version is included"
    );

    // vrf_group_public_key_bytes is included.
    let mut altered = base.clone();
    altered.vrf_group_public_key_bytes = vec![0x44u8; 96];
    assert_ne!(
        base_hash,
        committee_set_hash_v2(5, &altered),
        "vrf_group_public_key_bytes is included"
    );
}

// ---------------------------------------------------------------------------
// 5. V2 hash is never equal to the legacy address-only hash.
// ---------------------------------------------------------------------------

#[test]
fn committee_set_hash_v2_never_equals_legacy_active_set_hash_for_same_addresses() {
    let addresses = vec![
        address!("0x1111111111111111111111111111111111111111"),
        address!("0x2222222222222222222222222222222222222222"),
        address!("0x3333333333333333333333333333333333333333"),
    ];
    let snapshot = CommitteeSnapshot {
        committee: addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| CommitteeEntry {
                address: *addr,
                consensus_pubkey: pubkey_filled(0x10 + i as u8),
            })
            .collect(),
        vrf_material_version: 1,
        vrf_group_public_key_bytes: vec![0xAAu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };

    let v2 = committee_set_hash_v2(42, &snapshot);
    let legacy = legacy_active_set_hash(&addresses);
    assert_ne!(
        v2, legacy,
        "V2 committee hash must differ from legacy address-only hash; \
         shared collisions would break the V2 binding contract"
    );

    // Also: the V2 hash for an empty-pubkeys / version=0 / empty-vrf snapshot
    // must still differ from the legacy hash because of the domain prefix.
    let zeroed = CommitteeSnapshot {
        committee: addresses
            .iter()
            .map(|addr| CommitteeEntry {
                address: *addr,
                consensus_pubkey: [0u8; 48],
            })
            .collect(),
        vrf_material_version: 0,
        vrf_group_public_key_bytes: Vec::new(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    assert_ne!(
        committee_set_hash_v2(0, &zeroed),
        legacy_active_set_hash(&addresses),
        "domain prefix must keep V2 distinct even with cleared fields"
    );
}

// ---------------------------------------------------------------------------
// 6. Order matches Commonware public-key order, not address order.
// ---------------------------------------------------------------------------

#[test]
fn committee_snapshot_order_matches_commonware_public_key_order_not_address_order() {
    // Pick addresses and pubkeys whose Commonware (lexicographic on raw
    // pubkey bytes) order is the inverse of the address order: addresses
    // sort 0x11.. < 0x22.. but pubkeys sort 0xFF.. > 0xAA...
    let entry_a = CommitteeEntry {
        address: address!("0x1111111111111111111111111111111111111111"),
        consensus_pubkey: pubkey_filled(0xFF),
    };
    let entry_b = CommitteeEntry {
        address: address!("0x2222222222222222222222222222222222222222"),
        consensus_pubkey: pubkey_filled(0xAA),
    };

    // order is Commonware participant-index order
    // (sorted by encoded pubkey bytes), so 0xAA.. comes first.
    let address_order = CommitteeSnapshot {
        committee: vec![entry_a.clone(), entry_b.clone()],
        vrf_material_version: 0,
        vrf_group_public_key_bytes: Vec::new(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let pubkey_order = CommitteeSnapshot {
        committee: vec![entry_b.clone(), entry_a.clone()],
        vrf_material_version: 0,
        vrf_group_public_key_bytes: Vec::new(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    assert_ne!(
        committee_set_hash_v2(0, &address_order),
        committee_set_hash_v2(0, &pubkey_order),
        "ordering enters the hash and is not commutative"
    );

    // Sanity: simulate the Commonware sort and confirm pubkey_order matches.
    let mut entries = vec![entry_a.clone(), entry_b.clone()];
    entries.sort_by_key(|x| x.consensus_pubkey);
    assert_eq!(
        entries, pubkey_order.committee,
        "pubkey-order vector must reflect ascending pubkey bytes"
    );
}

// ---------------------------------------------------------------------------
// 7. Boundary atomicity - both outgoing and incoming snapshots are written.
// ---------------------------------------------------------------------------

#[test]
fn boundary_block_writes_both_outgoing_and_incoming_snapshots_atomically() {
    let outgoing_addr = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let incoming_addr = address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

    let outgoing_snapshot = CommitteeSnapshot {
        committee: vec![CommitteeEntry {
            address: outgoing_addr,
            consensus_pubkey: pubkey_filled(0xAA),
        }],
        vrf_material_version: 4,
        vrf_group_public_key_bytes: vec![0xEEu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let incoming_snapshot = CommitteeSnapshot {
        committee: vec![CommitteeEntry {
            address: incoming_addr,
            consensus_pubkey: pubkey_filled(0xBB),
        }],
        vrf_material_version: 5,
        vrf_group_public_key_bytes: vec![0xFFu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let outgoing_epoch = 9u64;
    let incoming_epoch = 10u64;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(1);
    StorageHandle::enter(&mut storage, |storage| {
        // Admit OCOMP material for both validators before either one can be
        // represented by a production committee snapshot, then recreate the
        // real outgoing-exit/incoming-join rotation shape.
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner
            .write(address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"))
            .unwrap();
        vs.set_config_max_validators(10).unwrap();
        admit_ocomp_key(&mut vs, outgoing_addr, &pubkey_filled(0xAA), 0x21);
        admit_ocomp_key(&mut vs, incoming_addr, &pubkey_filled(0xBB), 0x22);
        vs.activate_validator(outgoing_addr).unwrap();
        let owner = vs.config_owner.read().unwrap();
        vs.deactivate_validator(owner, outgoing_addr)
            .expect("outgoing validator requests exit before freeze");
        drop(vs);

        let inputs = BoundaryActivationInputs {
            outgoing: Some((outgoing_epoch, outgoing_snapshot.clone())),
            incoming_epoch,
            incoming: incoming_snapshot.clone(),
            freeze_height: 1,
            new_active_set: vec![incoming_addr],
            active_set_hash: b256!(
                "00000000000000000000000000000000000000000000000000000000000000A1"
            ),
            tee_expired_target_exclusions: Vec::new(),
        };

        let (out_key, in_key) =
            activate_boundary_atomic(storage.clone(), &inputs).expect("atomic activation");

        // Outgoing snapshot is readable.
        let out_read = read_committee_snapshot(storage.clone(), out_key)
            .unwrap()
            .expect("outgoing snapshot must be present");
        assert_eq!(out_read.committee, outgoing_snapshot.committee);
        assert_eq!(out_read.vrf_material_version, 4);
        assert_eq!(out_read.vrf_group_public_key_bytes, vec![0xEEu8; 96]);

        // Incoming snapshot is readable.
        let in_read = read_committee_snapshot(storage.clone(), in_key)
            .unwrap()
            .expect("incoming snapshot must be present");
        assert_eq!(in_read.committee, incoming_snapshot.committee);
        assert_eq!(in_read.vrf_material_version, 5);
        assert_eq!(in_read.vrf_group_public_key_bytes, vec![0xFFu8; 96]);

        // active_consensus_set_hash advanced to the boundary's hash.
        let vs_after = ValidatorSet::new(storage.clone());
        assert_eq!(
            vs_after.active_consensus_set_hash().unwrap(),
            b256!("00000000000000000000000000000000000000000000000000000000000000A1")
        );
    });
}

// ---------------------------------------------------------------------------
// 8. Outgoing snapshot remains available forever (no pruning in genesis V2).
// ---------------------------------------------------------------------------

#[test]
fn outgoing_epoch_snapshot_remains_available_after_reshare_activation() {
    let val_a = address!("0x1111111111111111111111111111111111111111");
    let val_b = address!("0x2222222222222222222222222222222222222222");
    let val_c = address!("0x3333333333333333333333333333333333333333");

    let outgoing_snapshot = CommitteeSnapshot {
        committee: vec![
            CommitteeEntry {
                address: val_a,
                consensus_pubkey: pubkey_filled(0x11),
            },
            CommitteeEntry {
                address: val_b,
                consensus_pubkey: pubkey_filled(0x22),
            },
        ],
        vrf_material_version: 1,
        vrf_group_public_key_bytes: vec![0xAAu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let incoming_snapshot = CommitteeSnapshot {
        committee: vec![
            CommitteeEntry {
                address: val_b,
                consensus_pubkey: pubkey_filled(0x22),
            },
            CommitteeEntry {
                address: val_c,
                consensus_pubkey: pubkey_filled(0x33),
            },
        ],
        vrf_material_version: 2,
        vrf_group_public_key_bytes: vec![0xBBu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let outgoing_epoch = 17u64;
    let incoming_epoch = 18u64;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(1);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner
            .write(address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"))
            .unwrap();
        vs.set_config_max_validators(10).unwrap();
        admit_ocomp_key(&mut vs, val_a, &pubkey_filled(0x11), 0x31);
        admit_ocomp_key(&mut vs, val_b, &pubkey_filled(0x22), 0x32);
        admit_ocomp_key(&mut vs, val_c, &pubkey_filled(0x33), 0x33);
        let owner = vs.config_owner.read().unwrap();
        vs.activate_validator(val_a).unwrap();
        vs.activate_validator(val_b).unwrap();
        vs.deactivate_validator(owner, val_a)
            .expect("val_a requests exit before the first freeze");
        drop(vs);

        let inputs = BoundaryActivationInputs {
            outgoing: Some((outgoing_epoch, outgoing_snapshot.clone())),
            incoming_epoch,
            incoming: incoming_snapshot.clone(),
            freeze_height: 1,
            new_active_set: vec![val_b, val_c],
            active_set_hash: B256::with_last_byte(0xC1),
            tee_expired_target_exclusions: Vec::new(),
        };
        let (out_key, _) =
            activate_boundary_atomic(storage.clone(), &inputs).expect("first activation");

        // val_b is still active after the first rotation. Its exit request is
        // visible at the next freeze, so the second boundary may exclude it.
        let mut vs = ValidatorSet::new(storage.clone());
        vs.deactivate_validator(owner, val_b)
            .expect("val_b requests exit before the second freeze");
        drop(vs);

        // A second (later) reshare from epoch 18 -> 19 that rotates validators.
        let next_outgoing = incoming_snapshot.clone();
        let next_incoming = CommitteeSnapshot {
            committee: vec![CommitteeEntry {
                address: val_c,
                consensus_pubkey: pubkey_filled(0x33),
            }],
            vrf_material_version: 3,
            vrf_group_public_key_bytes: vec![0xCCu8; 96],
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        let next = BoundaryActivationInputs {
            outgoing: Some((incoming_epoch, next_outgoing)),
            incoming_epoch: incoming_epoch + 1,
            incoming: next_incoming,
            freeze_height: 1,
            new_active_set: vec![val_c],
            active_set_hash: B256::with_last_byte(0xC2),
            tee_expired_target_exclusions: Vec::new(),
        };
        activate_boundary_atomic(storage.clone(), &next).expect("second activation");

        // The epoch-17 outgoing snapshot must still be readable.
        let still_there = read_committee_snapshot(storage.clone(), out_key)
            .unwrap()
            .expect("genesis-V2 must not prune outgoing snapshots");
        assert_eq!(still_there.committee, outgoing_snapshot.committee);
        assert_eq!(still_there.vrf_material_version, 1);
        assert_eq!(still_there.vrf_group_public_key_bytes, vec![0xAAu8; 96]);
    });
}

// ---------------------------------------------------------------------------
// 9. Slot-39 bytes match real `commonware_codec::Encode(polynomial.public())`.
// ---------------------------------------------------------------------------

#[test]
fn committee_snapshot_slot39_bytes_match_commonware_encode_of_real_polynomial() {
    use commonware_cryptography::bls12381::dkg::feldman_desmedt::{Dealer, Info, Player};
    use commonware_cryptography::bls12381::primitives::sharing::Mode;
    use commonware_cryptography::bls12381::primitives::variant::MinSig;
    use commonware_cryptography::bls12381::{self, PrivateKey, PublicKey};
    use commonware_cryptography::Signer as _;
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered, N3f1, TryCollect as _};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Use a stable arbitrary seed so the DKG fixture is deterministic.
    let mut rng = ChaCha20Rng::seed_from_u64(277_u64);
    let mut keys: Vec<bls12381::PrivateKey> = (0..3)
        .map(|_| <PrivateKey as Random>::random(&mut rng))
        .collect();
    keys.sort_by(|a, b| {
        commonware_codec::Encode::encode(&a.public_key())
            .cmp(&commonware_codec::Encode::encode(&b.public_key()))
    });
    let participants: ordered::Set<PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();

    let info = Info::<MinSig, PublicKey>::new::<N3f1>(
        b"snapshot-store-test",
        0,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants.clone(),
    )
    .unwrap();

    let mut dealers = Vec::new();
    let mut pub_msgs = Vec::new();
    let mut all_priv_msgs = Vec::new();
    for key in &keys {
        let (dealer, pub_msg, priv_msgs) =
            Dealer::<MinSig, PrivateKey>::start::<N3f1>(&mut rng, info.clone(), key.clone(), None)
                .unwrap();
        dealers.push(dealer);
        pub_msgs.push(pub_msg);
        all_priv_msgs.push(priv_msgs);
    }
    let mut players: Vec<Player<MinSig, PrivateKey>> = keys
        .iter()
        .map(|k| Player::new(info.clone(), k.clone()).unwrap())
        .collect();
    for (dealer_idx, (pub_msg, priv_msgs)) in pub_msgs.iter().zip(all_priv_msgs.iter()).enumerate()
    {
        let dealer_pk = keys[dealer_idx].public_key();
        for (player_pk, priv_msg) in priv_msgs {
            let player_idx = keys
                .iter()
                .position(|k| &k.public_key() == player_pk)
                .unwrap();
            if let Some(ack) = players[player_idx].dealer_message::<N3f1>(
                dealer_pk.clone(),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealers[dealer_idx]
                    .receive_player_ack(player_pk.clone(), ack)
                    .unwrap();
            }
        }
    }
    let mut logs = std::collections::BTreeMap::new();
    for dealer in dealers {
        let signed_log = dealer.finalize::<N3f1>();
        if let Some((pk, log)) = signed_log.check(&info) {
            logs.insert(pk, log);
        }
    }
    let mut dkg_logs = commonware_cryptography::bls12381::dkg::feldman_desmedt::Logs::<
        MinSig,
        PublicKey,
        N3f1,
    >::new(info.clone());
    for (dealer_pk, log) in logs {
        dkg_logs.record(dealer_pk, log);
    }
    let (output, _share) = players
        .remove(0)
        .finalize::<N3f1, commonware_cryptography::bls12381::Batch>(&mut rng, dkg_logs, &Sequential)
        .unwrap();

    let encoded_group_pk = commonware_codec::Encode::encode(output.public()).to_vec();
    assert!(
        !encoded_group_pk.is_empty(),
        "polynomial.public() must encode to non-empty bytes",
    );

    // Build a snapshot from the real DKG output and write it.
    let committee: Vec<CommitteeEntry> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let encoded = commonware_codec::Encode::encode(&k.public_key()).to_vec();
            let pubkey: [u8; 48] = encoded.as_slice().try_into().expect("MinPk pubkey = 48");
            CommitteeEntry {
                address: Address::from_slice(&[i as u8 + 1; 20]),
                consensus_pubkey: pubkey,
            }
        })
        .collect();
    let snapshot = CommitteeSnapshot {
        committee,
        vrf_material_version: 0,
        vrf_group_public_key_bytes: encoded_group_pk.clone(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        for (index, entry) in snapshot.committee.iter().enumerate() {
            admit_ocomp_key(
                &mut vs,
                entry.address,
                &entry.consensus_pubkey,
                0x41 + index as u8,
            );
        }
        drop(vs);
        let (_hash, key) = write_committee_snapshot(storage.clone(), 0, &snapshot).unwrap();
        let read_back = read_committee_snapshot(storage.clone(), key)
            .unwrap()
            .expect("snapshot must be present after write");
        assert_eq!(
            read_back.vrf_group_public_key_bytes, encoded_group_pk,
            "slot 39 chunks must round-trip the exact commonware_codec::Encode bytes"
        );

        // Sanity: slot-38 length equals the actual encoded length.
        let vs = ValidatorSet::new(storage.clone());
        let stored_len = vs
            .committee_snapshot_vrf_group_public_key_len
            .read(&key)
            .unwrap();
        assert_eq!(stored_len as usize, encoded_group_pk.len());
    });
}

// ---------------------------------------------------------------------------
// 12. Boundary activation rolls back snapshots on artifact rejection.
//
// Behavioural test for the AC: drive `activate_boundary_atomic` through the
// fail-closed membership check with an unregistered artifact participant, then
// prove that the journal is reverted end-to-end - neither outgoing nor incoming
// snapshot is reachable, and `active_consensus_set_hash` is unchanged. This
// turns the previously mechanism-only argument (CheckpointGuard::Drop semantics
// + exists-last write ordering) into a runtime assertion.
// ---------------------------------------------------------------------------

#[test]
fn boundary_activation_rolls_back_snapshots_on_failure() {
    let known_addr = address!("0x1111111111111111111111111111111111111111");
    let unknown_addr = address!("0x9999999999999999999999999999999999999999");

    let outgoing_snapshot = CommitteeSnapshot {
        committee: vec![CommitteeEntry {
            address: known_addr,
            consensus_pubkey: pubkey_filled(0x11),
        }],
        vrf_material_version: 1,
        vrf_group_public_key_bytes: vec![0xAAu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let incoming_snapshot = CommitteeSnapshot {
        committee: vec![
            CommitteeEntry {
                address: known_addr,
                consensus_pubkey: pubkey_filled(0x11),
            },
            CommitteeEntry {
                address: unknown_addr,
                consensus_pubkey: pubkey_filled(0x99),
            },
        ],
        vrf_material_version: 2,
        vrf_group_public_key_bytes: vec![0xBBu8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    let outgoing_epoch = 11u64;
    let incoming_epoch = 12u64;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        // Admit only the "known" validator. The incoming `new_active_set`
        // intentionally contains `unknown_addr` which is NOT registered, so
        // the validated boundary fails closed before any write commits.
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner
            .write(address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"))
            .unwrap();
        vs.set_config_max_validators(10).unwrap();
        admit_ocomp_key(&mut vs, known_addr, &pubkey_filled(0x11), 0x51);
        vs.activate_validator(known_addr).unwrap();
        let before_lifecycle = vs.validator_lifecycle(known_addr).unwrap();
        let before_active_set_hash = vs.active_consensus_set_hash().unwrap();
        drop(vs);

        // Pre-compute the canonical snapshot keys so we can probe them
        // after the (expected) failure without depending on the helper's
        // own return value.
        let (_, outgoing_key) = snapshot_identity(outgoing_epoch, &outgoing_snapshot);
        let (_, incoming_key) = snapshot_identity(incoming_epoch, &incoming_snapshot);

        let inputs = BoundaryActivationInputs {
            outgoing: Some((outgoing_epoch, outgoing_snapshot.clone())),
            incoming_epoch,
            incoming: incoming_snapshot.clone(),
            freeze_height: 0,
            new_active_set: vec![known_addr, unknown_addr],
            active_set_hash: B256::with_last_byte(0xF1),
            tee_expired_target_exclusions: Vec::new(),
        };

        let err = activate_boundary_atomic(storage.clone(), &inputs).expect_err(
            "activation must reject an artifact with an unregistered extra participant",
        );
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("validated boundary participant membership mismatch"),
            "unexpected error kind: {err_msg}",
        );

        // the outgoing snapshot was the FIRST thing written, and the
        // `exists` flag for it would normally be set by the time the failure
        // happens. The CheckpointGuard drop path must revert that write -
        // reading the snapshot back through the public API returns None.
        assert!(
            read_committee_snapshot(storage.clone(), outgoing_key)
                .unwrap()
                .is_none(),
            "outgoing snapshot must NOT be reachable after rollback",
        );
        // Same for the incoming snapshot - that path never executes because
        // the activation step fails first, but we check it anyway to lock
        // the invariant.
        assert!(
            read_committee_snapshot(storage.clone(), incoming_key)
                .unwrap()
                .is_none(),
            "incoming snapshot must NOT be reachable after rollback",
        );

        // ValidatorSet membership/hash state remains byte-for-byte equivalent
        // to the canonical pre-boundary fixture.
        let vs_after = ValidatorSet::new(storage.clone());
        assert_eq!(
            vs_after.active_consensus_set_hash().unwrap(),
            before_active_set_hash,
            "active_consensus_set_hash must remain unchanged on rollback",
        );

        assert_eq!(
            vs_after.validator_lifecycle(known_addr).unwrap(),
            before_lifecycle,
            "pre-existing validator lifecycle must not be affected by the failed activation",
        );
    });
}

// ---------------------------------------------------------------------------
// Prune ring: state-growth bound - only the last RETAIN epochs stay live.
// ---------------------------------------------------------------------------

#[test]
fn committee_snapshot_prune_ring_retains_recent_and_clears_old_epochs() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let snap = CommitteeSnapshot {
            committee: vec![CommitteeEntry {
                address: address!("0x0000000000000000000000000000000000000001"),
                consensus_pubkey: pubkey_filled(0x11),
            }],
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vec![0x22u8; 96],
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        admit_ocomp_key(
            &mut vs,
            snap.committee[0].address,
            &snap.committee[0].consensus_pubkey,
            0x61,
        );
        drop(vs);
        let retain = outbe_validatorset::COMMITTEE_SNAPSHOT_RETAIN_EPOCHS;
        let total = retain + 2;
        let keys: Vec<B256> = (0..total)
            .map(|epoch| {
                write_committee_snapshot(storage.clone(), epoch, &snap)
                    .unwrap()
                    .1
            })
            .collect();

        // The oldest (total - retain) epochs are evicted: snapshot gone, exists
        // flag cleared, length zeroed - their slots are reclaimed.
        for epoch in 0..(total - retain) {
            let key = keys[epoch as usize];
            assert!(
                read_committee_snapshot(storage.clone(), key)
                    .unwrap()
                    .is_none(),
                "epoch {epoch} snapshot must be pruned"
            );
            let vs = ValidatorSet::new(storage.clone());
            assert!(
                !vs.committee_snapshot_exists.read(&key).unwrap(),
                "epoch {epoch} exists flag must be cleared"
            );
            assert_eq!(
                vs.committee_snapshot_len.read(&key).unwrap(),
                0,
                "epoch {epoch} len must be zeroed"
            );
        }
        // The last `retain` epochs remain fully readable.
        for epoch in (total - retain)..total {
            let read = read_committee_snapshot(storage.clone(), keys[epoch as usize]).unwrap();
            assert!(read.is_some(), "epoch {epoch} snapshot must be retained");
            assert_eq!(read.unwrap().committee.len(), 1, "epoch {epoch} intact");
        }
    });
}

#[test]
fn committee_snapshot_epoch_lookup_rejects_a_newer_colliding_ring_entry() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let validator = address!("0x0000000000000000000000000000000000000001");
        let consensus_pubkey = pubkey_filled(0x11);
        let mut vs = ValidatorSet::new(storage.clone());
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.set_config_max_validators(128).unwrap();
        admit_ocomp_key(&mut vs, validator, &consensus_pubkey, 0x61);
        drop(vs);

        let snapshot = CommitteeSnapshot {
            committee: vec![CommitteeEntry {
                address: validator,
                consensus_pubkey,
            }],
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vec![0x22u8; 96],
            vrf_public_polynomial_hash: B256::ZERO,
        };
        let retained_epoch = 7;
        let colliding_epoch = retained_epoch + outbe_validatorset::COMMITTEE_SNAPSHOT_RETAIN_EPOCHS;

        write_committee_snapshot(storage.clone(), retained_epoch, &snapshot).unwrap();
        write_committee_snapshot(storage.clone(), colliding_epoch, &snapshot).unwrap();

        assert!(
            read_committee_snapshot_for_epoch(storage.clone(), retained_epoch)
                .unwrap()
                .is_none(),
            "an evicted epoch must not resolve to the newer snapshot in the same ring slot"
        );
        assert_eq!(
            read_committee_snapshot_for_epoch(storage.clone(), colliding_epoch).unwrap(),
            Some(snapshot),
            "the actual retained epoch must remain readable"
        );
    });
}
